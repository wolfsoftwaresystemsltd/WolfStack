#!/bin/bash
# allow-updates.sh — temporarily whitelist apt/proxmox update traffic on a host
# that's been locked down by block-outbound.sh. Run again with 'remove' when done.
#
# Usage:
#   sudo bash allow-updates.sh add      # open DNS + http/https to apt sources
#   sudo bash allow-updates.sh remove   # revoke the temporary whitelist
#   sudo bash allow-updates.sh status   # show currently-active whitelist rules
#
# Rules are tagged 'IR-allow-updates:' so they're identifiable and removable
# without touching the rest of the block-outbound ruleset.

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

ACTION="${1:-}"
case "$ACTION" in add|remove|status) ;;
  *) echo "Usage: $0 {add|remove|status}" >&2; exit 1 ;;
esac

TAG="IR-allow-updates"

# ─── status ───────────────────────────────────────────────────────────────────
if [[ "$ACTION" == "status" ]]; then
  echo "=== IPv4 OUTPUT rules tagged '$TAG' ==="
  iptables -L OUTPUT -n -v --line-numbers | grep -E "(Chain|$TAG)" || echo "  none"
  echo ""
  echo "=== IPv6 OUTPUT rules tagged '$TAG' ==="
  ip6tables -L OUTPUT -n -v --line-numbers | grep -E "(Chain|$TAG)" || echo "  none"
  exit 0
fi

# ─── remove ───────────────────────────────────────────────────────────────────
if [[ "$ACTION" == "remove" ]]; then
  echo "==> Removing all rules tagged '$TAG'"
  removed=0
  # Delete by spec, not by line number, so renumbering can't bite us
  while iptables-save | grep -q -- "--comment \"$TAG"; do
    rule=$(iptables-save | grep -m1 -- "--comment \"$TAG" | sed 's/^-A /-D /')
    iptables $rule && removed=$((removed+1))
  done
  while ip6tables-save | grep -q -- "--comment \"$TAG"; do
    rule=$(ip6tables-save | grep -m1 -- "--comment \"$TAG" | sed 's/^-A /-D /')
    ip6tables $rule && removed=$((removed+1))
  done
  echo "    removed $removed rule(s)"
  echo "==> Outbound is locked down again. Verify with: iptables -L OUTPUT -n -v"
  exit 0
fi

# ─── add ──────────────────────────────────────────────────────────────────────
# Sanity check: refuse to add if block-outbound never ran (no point in this script)
if ! iptables-save | grep -q "IR-block: default deny"; then
  echo "WARNING: no IR-block ruleset detected. This script is meant to whitelist holes"
  echo "         in the block-outbound.sh lockdown. Continuing anyway..."
  echo ""
fi

# 1. DNS to configured resolvers — needed to resolve apt source hostnames
echo "==> Opening DNS to configured resolvers"
NAMESERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)
if [[ -z "$NAMESERVERS" ]]; then
  echo "ERROR: no nameservers in /etc/resolv.conf — cannot resolve mirrors" >&2
  exit 1
fi
for ns in $NAMESERVERS; do
  if [[ "$ns" == *:* ]]; then
    ip6tables -I OUTPUT 1 -d "$ns" -p udp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
    ip6tables -I OUTPUT 1 -d "$ns" -p tcp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
    echo "    allowed DNS to $ns (v6)"
  else
    iptables -I OUTPUT 1 -d "$ns" -p udp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
    iptables -I OUTPUT 1 -d "$ns" -p tcp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
    echo "    allowed DNS to $ns (v4)"
  fi
done

# 2. Extract apt source hostnames from sources.list + sources.list.d/*
echo ""
echo "==> Parsing apt sources for mirror hostnames"
HOSTS=$(
  {
    [[ -r /etc/apt/sources.list ]] && cat /etc/apt/sources.list
    find /etc/apt/sources.list.d -type f \( -name '*.list' -o -name '*.sources' \) 2>/dev/null -exec cat {} +
  } | grep -vE '^\s*(#|$)' \
    | grep -oE 'https?://[^/[:space:]]+' \
    | sed 's|^https\?://||' \
    | sed 's|:.*||' \
    | sort -u
)

# Add Proxmox subscription/no-sub host even if not in sources (some helpers fetch from it)
HOSTS=$(printf '%s\ndownload.proxmox.com\nenterprise.proxmox.com\n' "$HOSTS" | sort -u | grep -v '^$')

if [[ -z "$HOSTS" ]]; then
  echo "ERROR: no apt mirrors found in /etc/apt/sources.list*" >&2
  exit 1
fi
echo "    mirrors found:"
for h in $HOSTS; do echo "      $h"; done

# 3. Resolve each hostname and open port 80 + 443
echo ""
echo "==> Opening HTTP/HTTPS to mirror IPs"
total_ips=0
for host in $HOSTS; do
  ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
  if [[ -z "$ips" ]]; then
    echo "    [!] could not resolve $host — skipping (check DNS rule)"
    continue
  fi
  for ip in $ips; do
    if [[ "$ip" == *:* ]]; then
      ip6tables -I OUTPUT 1 -d "$ip" -p tcp --dport 443 -j ACCEPT -m comment --comment "$TAG: $host:443"
      ip6tables -I OUTPUT 1 -d "$ip" -p tcp --dport 80  -j ACCEPT -m comment --comment "$TAG: $host:80"
    else
      iptables -I OUTPUT 1 -d "$ip" -p tcp --dport 443 -j ACCEPT -m comment --comment "$TAG: $host:443"
      iptables -I OUTPUT 1 -d "$ip" -p tcp --dport 80  -j ACCEPT -m comment --comment "$TAG: $host:80"
    fi
    echo "    $host -> $ip"
    total_ips=$((total_ips+1))
  done
done

echo ""
echo "==> DONE. Opened DNS + $total_ips mirror IPs."
echo ""
echo "Now run your updates:"
echo "  apt update && apt upgrade -y"
echo ""
echo "When finished, revoke the whitelist:"
echo "  sudo bash $0 remove"
echo ""
echo "Show currently-open holes:"
echo "  sudo bash $0 status"
echo ""
echo "NOTE: mirror IPs can rotate (CDN). If apt fails part-way through, re-run"
echo "      'add' to refresh the resolved IPs, then continue the upgrade."
