#!/bin/bash
# allow-pbs.sh — temporarily whitelist outbound to Proxmox Backup Server
# (and remote NFS/CIFS backup targets) so a pre-reboot backup can run while
# block-outbound.sh is in effect.
#
# Usage:
#   sudo bash allow-pbs.sh add      # open required outbound to PBS/NFS/CIFS targets
#   sudo bash allow-pbs.sh remove   # revoke the temporary whitelist
#   sudo bash allow-pbs.sh status   # show currently-active whitelist rules
#
# Rules are tagged 'IR-allow-pbs:' so they can be cleanly removed without
# touching the rest of the block-outbound ruleset.

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

ACTION="${1:-}"
case "$ACTION" in add|remove|status) ;;
  *) echo "Usage: $0 {add|remove|status}" >&2; exit 1 ;;
esac

TAG="IR-allow-pbs"
STORAGE_CFG="/etc/pve/storage.cfg"

# ── status ────────────────────────────────────────────────────────────────────
if [[ "$ACTION" == "status" ]]; then
  echo "=== IPv4 OUTPUT rules tagged '$TAG' ==="
  iptables -L OUTPUT -n -v --line-numbers | grep -E "(Chain|$TAG)" || echo "  none"
  echo ""
  echo "=== IPv6 OUTPUT rules tagged '$TAG' ==="
  ip6tables -L OUTPUT -n -v --line-numbers | grep -E "(Chain|$TAG)" || echo "  none"
  exit 0
fi

# ── remove ────────────────────────────────────────────────────────────────────
if [[ "$ACTION" == "remove" ]]; then
  echo "==> Removing all rules tagged '$TAG'"
  removed=0
  while iptables-save | grep -q -- "--comment \"$TAG"; do
    rule=$(iptables-save | grep -m1 -- "--comment \"$TAG" | sed 's/^-A /-D /')
    iptables $rule && removed=$((removed+1))
  done
  while ip6tables-save | grep -q -- "--comment \"$TAG"; do
    rule=$(ip6tables-save | grep -m1 -- "--comment \"$TAG" | sed 's/^-A /-D /')
    ip6tables $rule && removed=$((removed+1))
  done
  echo "    removed $removed rule(s)"
  echo "==> Backup paths are closed again."
  exit 0
fi

# ── add ───────────────────────────────────────────────────────────────────────
if [[ ! -r "$STORAGE_CFG" ]]; then
  echo "ERROR: cannot read $STORAGE_CFG — is this a Proxmox node?" >&2
  exit 1
fi

if ! iptables-save | grep -q "IR-block: default deny"; then
  echo "WARNING: no IR-block ruleset detected. Continuing anyway..."
  echo ""
fi

# Parse storage.cfg — for each PBS/NFS/CIFS entry, extract the server address.
# Format:
#   pbs: name
#           server 1.2.3.4
#           ...
#   nfs: name
#           server 1.2.3.4
#           export /foo
#   cifs: name
#           server 1.2.3.4
#           share foo
#
# We emit one "type|name|host" line per storage entry that has a server field.
ENTRIES=$(awk '
  /^[a-z]+:[[:space:]]/ { type=$1; sub(":","",type); name=$2; host=""; next }
  /^[[:space:]]+server[[:space:]]/ { host=$2 }
  /^$/ {
    if (host != "" && (type == "pbs" || type == "nfs" || type == "cifs"))
      print type "|" name "|" host
    type=""; name=""; host=""
  }
  END {
    if (host != "" && (type == "pbs" || type == "nfs" || type == "cifs"))
      print type "|" name "|" host
  }
' "$STORAGE_CFG")

if [[ -z "$ENTRIES" ]]; then
  echo "ERROR: no pbs/nfs/cifs storage entries with a 'server' line found in $STORAGE_CFG" >&2
  echo "       (local-only storage doesn't need outbound rules)" >&2
  exit 1
fi

echo "==> Found backup-capable remote storage:"
echo "$ENTRIES" | while IFS='|' read -r type name host; do
  printf '    %-5s %-20s -> %s\n' "$type" "$name" "$host"
done

# If any hostname isn't an IP, we need DNS. Open DNS to resolvers (idempotent — re-running is fine).
need_dns=0
while IFS='|' read -r _ _ host; do
  if ! [[ "$host" =~ ^[0-9.]+$ ]] && ! [[ "$host" == *:*:* ]]; then
    need_dns=1; break
  fi
done <<<"$ENTRIES"

if [[ "$need_dns" == "1" ]]; then
  echo ""
  echo "==> Opening DNS to configured resolvers (needed to resolve hostnames)"
  NAMESERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)
  if [[ -z "$NAMESERVERS" ]]; then
    echo "ERROR: no nameservers in /etc/resolv.conf — cannot resolve backup hostnames" >&2
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
fi

# Open ports per storage type:
#   pbs  : tcp/8007
#   nfs  : tcp+udp/2049, tcp/111 (rpcbind), tcp/20048 (mountd) — pinning mountd avoids guessing portmap
#   cifs : tcp/445, tcp/139
open_port_v4() {  # ip proto port label
  iptables -I OUTPUT 1 -d "$1" -p "$2" --dport "$3" -j ACCEPT -m comment --comment "$TAG: $4"
}
open_port_v6() {
  ip6tables -I OUTPUT 1 -d "$1" -p "$2" --dport "$3" -j ACCEPT -m comment --comment "$TAG: $4"
}

emit_rules() {  # type name host
  local type="$1" name="$2" host="$3"
  local ips
  if [[ "$host" =~ ^[0-9.]+$ ]] || [[ "$host" == *:* ]]; then
    ips="$host"
  else
    ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
    if [[ -z "$ips" ]]; then
      echo "    [!] could not resolve $host — skipping"
      return
    fi
  fi
  for ip in $ips; do
    case "$type" in
      pbs)
        if [[ "$ip" == *:* ]]; then open_port_v6 "$ip" tcp 8007 "$name (pbs)"
        else                         open_port_v4 "$ip" tcp 8007 "$name (pbs)"; fi
        echo "    pbs  $name  $host -> $ip:8007"
        ;;
      nfs)
        if [[ "$ip" == *:* ]]; then
          open_port_v6 "$ip" tcp 2049  "$name (nfs)"
          open_port_v6 "$ip" udp 2049  "$name (nfs)"
          open_port_v6 "$ip" tcp 111   "$name (rpcbind)"
          open_port_v6 "$ip" udp 111   "$name (rpcbind)"
          open_port_v6 "$ip" tcp 20048 "$name (mountd)"
          open_port_v6 "$ip" udp 20048 "$name (mountd)"
        else
          open_port_v4 "$ip" tcp 2049  "$name (nfs)"
          open_port_v4 "$ip" udp 2049  "$name (nfs)"
          open_port_v4 "$ip" tcp 111   "$name (rpcbind)"
          open_port_v4 "$ip" udp 111   "$name (rpcbind)"
          open_port_v4 "$ip" tcp 20048 "$name (mountd)"
          open_port_v4 "$ip" udp 20048 "$name (mountd)"
        fi
        echo "    nfs  $name  $host -> $ip:{2049,111,20048}"
        ;;
      cifs)
        if [[ "$ip" == *:* ]]; then
          open_port_v6 "$ip" tcp 445 "$name (cifs)"
          open_port_v6 "$ip" tcp 139 "$name (cifs)"
        else
          open_port_v4 "$ip" tcp 445 "$name (cifs)"
          open_port_v4 "$ip" tcp 139 "$name (cifs)"
        fi
        echo "    cifs $name  $host -> $ip:{445,139}"
        ;;
    esac
  done
}

echo ""
echo "==> Opening per-storage outbound ports"
while IFS='|' read -r type name host; do
  emit_rules "$type" "$name" "$host"
done <<<"$ENTRIES"

echo ""
echo "==> DONE."
echo ""
echo "Now run your backups, e.g.:"
echo "  vzdump <vmid> --storage <pbs-storage-name> --mode snapshot"
echo "  # or trigger from the PVE web UI / scheduled job"
echo ""
echo "When the backup completes and you're about to reboot, revoke:"
echo "  sudo bash $0 remove"
echo ""
echo "NOTE: NFS sometimes uses random ports for mountd unless you've pinned it."
echo "      If mounts fail, on the NFS *server* set:"
echo "        echo 'MOUNTD_PORT=20048' >> /etc/default/nfs-kernel-server && systemctl restart nfs-server"
