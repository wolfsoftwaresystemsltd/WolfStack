#!/bin/bash
# audit-outbound.sh — list outbound connections from this Proxmox host,
# flag anything going to a public IP that isn't on the known-good list,
# optionally drop those sockets.
#
# Usage:
#   sudo bash audit-outbound.sh          # audit only (default)
#   sudo bash audit-outbound.sh kill     # drop suspicious sockets after confirm
#
# "Bad" = outbound to a non-private, non-cluster-peer, non-DNS, non-NTP
# destination that isn't a reply to an inbound session we're listening on.
# This is a heuristic — review the list before killing.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

MODE="${1:-audit}"
case "$MODE" in audit|kill) ;; *) echo "Usage: $0 [audit|kill]" >&2; exit 1;; esac

# ─── Build whitelist of legitimate public destinations ────────────────────────
WHITELIST_IPS=()

if [[ -r /etc/pve/corosync.conf ]]; then
  while read -r entry; do
    entry=$(echo "$entry" | tr -d '"')
    if [[ "$entry" =~ ^[0-9.]+$ ]] || [[ "$entry" == *:* ]]; then
      WHITELIST_IPS+=("$entry")
    else
      while read -r ip; do WHITELIST_IPS+=("$ip"); done \
        < <(getent ahosts "$entry" 2>/dev/null | awk '{print $1}' | sort -u)
    fi
  done < <(awk '/ring[0-9]+_addr:/ {print $2}' /etc/pve/corosync.conf)
fi

while read -r ns; do WHITELIST_IPS+=("$ns"); done \
  < <(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null)

for conf in /etc/chrony/chrony.conf /etc/ntp.conf /etc/systemd/timesyncd.conf; do
  [[ -r "$conf" ]] || continue
  while read -r host; do
    [[ -z "$host" ]] && continue
    if [[ "$host" =~ ^[0-9.]+$ ]]; then
      WHITELIST_IPS+=("$host")
    else
      while read -r ip; do WHITELIST_IPS+=("$ip"); done \
        < <(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
    fi
  done < <(grep -E '^(server|pool|NTP=|FallbackNTP=)' "$conf" 2>/dev/null \
           | sed 's/[=,]/ /g' | awk '{for(i=2;i<=NF;i++) print $i}' \
           | grep -Ev '^(iburst|prefer|minpoll|maxpoll|[0-9]+)$')
done

LISTEN_PORTS=$( (ss -ltnH; ss -lunH) | awk '{print $4}' \
                | awk -F: '{print $NF}' | sort -u | grep -v '^$' || true)

# ─── Classification helpers ───────────────────────────────────────────────────
is_private() {
  local ip="$1"
  [[ "$ip" =~ ^127\. ]] && return 0
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
  [[ "$ip" =~ ^169\.254\. ]] && return 0
  [[ "$ip" =~ ^(22[4-9]|23[0-9])\. ]] && return 0
  [[ "$ip" == "::1" || "$ip" =~ ^fe80: || "$ip" =~ ^f[cd] ]] && return 0
  return 1
}
is_whitelisted() {
  local ip="$1"
  for w in "${WHITELIST_IPS[@]:-}"; do [[ "$ip" == "$w" ]] && return 0; done
  return 1
}
is_listen_port() { echo "$LISTEN_PORTS" | grep -qx "$1"; }

# ─── Print whitelist summary ──────────────────────────────────────────────────
echo "===================================================================="
echo "Auto-allowed:  loopback, RFC1918, link-local, multicast, ULA"
echo "Whitelisted public destinations:"
for ip in "${WHITELIST_IPS[@]:-}"; do
  is_private "$ip" || echo "  $ip"
done
echo "Local listening ports (replies excluded): $(echo "$LISTEN_PORTS" | tr '\n' ' ')"
echo "===================================================================="

# ─── Scan ESTABLISHED outbound connections ────────────────────────────────────
printf '\n%-5s %-23s %-23s %-30s %s\n' "PROTO" "LOCAL" "PEER" "PROCESS(PID)" "VERDICT"
printf '%-5s %-23s %-23s %-30s %s\n'   "-----" "-----" "----" "------------" "-------"

SUSPICIOUS=()
while read -r line; do
  [[ -z "$line" ]] && continue
  proto=$(echo "$line" | awk '{print $1}')
  local_addr=$(echo "$line" | awk '{print $5}')
  peer_addr=$(echo "$line" | awk '{print $6}')
  procinfo=$(echo "$line" | awk '{print $7}')

  peer_ip="${peer_addr%:*}"; peer_ip="${peer_ip#[}"; peer_ip="${peer_ip%]}"
  local_port="${local_addr##*:}"

  [[ -z "$peer_ip" || "$peer_ip" == "*" ]] && continue
  is_private "$peer_ip" && continue
  is_whitelisted "$peer_ip" && continue
  is_listen_port "$local_port" && continue

  pid=$(echo "$procinfo" | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  proc=$(echo "$procinfo" | grep -oP '\("\K[^"]+' | head -1 || echo "?")

  printf '%-5s %-23s %-23s %-30s %s\n' "$proto" "$local_addr" "$peer_addr" "${proc}(${pid:-?})" "SUSPICIOUS"
  SUSPICIOUS+=("$proto|$peer_ip|${peer_addr##*:}|${pid:-}|${proc}")
done < <(ss -tunpH state established 2>/dev/null)

echo ""
echo "Suspicious outbound connections: ${#SUSPICIOUS[@]}"

if [[ ${#SUSPICIOUS[@]} -eq 0 ]]; then
  echo "Nothing to act on."
  exit 0
fi

# Show owning process detail
echo ""
echo "Process details for owning PIDs:"
seen_pids=""
for entry in "${SUSPICIOUS[@]}"; do
  IFS='|' read -r _ _ _ pid _ <<<"$entry"
  [[ -z "$pid" ]] && continue
  [[ "$seen_pids" == *" $pid "* ]] && continue
  seen_pids+=" $pid "
  if [[ -r /proc/$pid/exe ]]; then
    exe=$(readlink -f /proc/$pid/exe 2>/dev/null || echo "?")
    cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
    deleted=""
    [[ "$exe" == *" (deleted)"* ]] && deleted=" ⚠ DELETED BINARY"
    printf '  pid=%-6s exe=%s%s\n           cmd=%s\n' "$pid" "$exe" "$deleted" "$cmd"
  fi
done

if [[ "$MODE" == "audit" ]]; then
  echo ""
  echo "To drop these sockets:  sudo bash $0 kill"
  echo "(kills the socket via 'ss -K'; process is left running so you can investigate it)"
  exit 0
fi

# ─── Kill mode ────────────────────────────────────────────────────────────────
echo ""
read -r -p "Type YES to drop the suspicious sockets above: " confirm
[[ "$confirm" == "YES" ]] || { echo "Aborted."; exit 1; }

for entry in "${SUSPICIOUS[@]}"; do
  IFS='|' read -r proto peer_ip peer_port pid proc <<<"$entry"
  echo "Dropping $proto -> $peer_ip:$peer_port ($proc/$pid)"
  if [[ "$proto" == "tcp" ]]; then
    if ! ss -K dst "$peer_ip" dport "= $peer_port" 2>&1; then
      echo "  ss -K failed — kernel may lack CONFIG_INET_DIAG_DESTROY"
    fi
  else
    if [[ -n "$pid" ]]; then
      echo "  UDP socket — killing process $pid"
      kill -9 "$pid" 2>/dev/null || echo "  kill failed"
    else
      echo "  UDP socket with no PID — cannot drop"
    fi
  fi
done

echo ""
echo "Done. Re-run 'sudo bash $0 audit' to verify."
echo "If sockets reappear, the owning process is reconnecting — investigate the PID's exe path"
echo "and consider 'kill -9 <pid>' or 'systemctl stop <unit>' on the parent service."
