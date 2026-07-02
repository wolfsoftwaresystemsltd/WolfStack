#!/bin/bash
# allow-rclone.sh — open the outbound ports rclone needs to reach cloud storage.
# rclone backends (S3, B2, Drive, Dropbox, OneDrive, pCloud, Mega, WebDAV, etc.)
# all use HTTPS on TCP/443. SFTP backend uses TCP/22. Some legacy/redirect
# traffic uses HTTP/80. Cloud-provider IPs rotate constantly so we open by
# port, not by destination IP — tagged so it's cleanly revocable.
#
# Usage:
#   sudo bash allow-rclone.sh add
#   sudo bash allow-rclone.sh remove
#   sudo bash allow-rclone.sh status

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

ACTION="${1:-}"
case "$ACTION" in add|remove|status) ;;
  *) echo "Usage: $0 {add|remove|status}" >&2; exit 1 ;;
esac

TAG="IR-allow-rclone"

if [[ "$ACTION" == "status" ]]; then
  echo "=== IPv4 OUTPUT rules tagged '$TAG' ==="
  iptables -L OUTPUT -n -v --line-numbers | grep -E "(Chain|$TAG)" || echo "  none"
  echo ""
  echo "=== IPv6 OUTPUT rules tagged '$TAG' ==="
  ip6tables -L OUTPUT -n -v --line-numbers | grep -E "(Chain|$TAG)" || echo "  none"
  exit 0
fi

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
  exit 0
fi

# ── add ───────────────────────────────────────────────────────────────────────
echo "==> Opening DNS to configured resolvers"
NAMESERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)
[[ -n "$NAMESERVERS" ]] || { echo "ERROR: no nameservers in /etc/resolv.conf" >&2; exit 1; }
for ns in $NAMESERVERS; do
  if [[ "$ns" == *:* ]]; then
    ip6tables -I OUTPUT 1 -d "$ns" -p udp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
    ip6tables -I OUTPUT 1 -d "$ns" -p tcp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
  else
    iptables  -I OUTPUT 1 -d "$ns" -p udp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
    iptables  -I OUTPUT 1 -d "$ns" -p tcp --dport 53 -j ACCEPT -m comment --comment "$TAG: DNS"
  fi
  echo "    allowed DNS to $ns"
done

echo ""
echo "==> Opening TCP/443 (HTTPS), TCP/80 (HTTP redirects), TCP/22 (SFTP) outbound"
for port in 443 80 22; do
  iptables  -I OUTPUT 1 -p tcp --dport "$port" -j ACCEPT -m comment --comment "$TAG: tcp/$port"
  ip6tables -I OUTPUT 1 -p tcp --dport "$port" -j ACCEPT -m comment --comment "$TAG: tcp/$port"
  echo "    allowed tcp/$port (v4 + v6)"
done

echo ""
echo "==> DONE. rclone can now reach any HTTPS/HTTP/SFTP endpoint."
echo ""
echo "Run your sync, then close it back up with:"
echo "  sudo bash $0 remove"
echo ""
echo "NOTE: this is broader than allow-updates.sh / allow-pbs.sh because cloud"
echo "      providers (S3/B2/Drive/Dropbox/OneDrive/etc.) use rotating CDN IPs"
echo "      that can't be pre-resolved. Outbound 443 is the standard pragmatic"
echo "      whitelist for any cloud-sync tool."
