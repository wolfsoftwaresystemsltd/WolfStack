#!/bin/bash
# allow-kernelcare.sh — temporarily whitelist KernelCare / TuxCare CDN
# endpoints so `kcarectl --update` can fetch live patches and licence
# under the block-outbound.sh lockdown.
#
# The .list file at /etc/apt/sources.list.d/kcare.list is handled by
# allow-updates.sh (it parses sources.list.d). This script covers the
# SEPARATE traffic that the KernelCare daemon makes outside of apt.
#
# Usage:
#   sudo bash allow-kernelcare.sh add
#   sudo bash allow-kernelcare.sh remove
#   sudo bash allow-kernelcare.sh status

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

ACTION="${1:-}"
case "$ACTION" in add|remove|status) ;;
  *) echo "Usage: $0 {add|remove|status}" >&2; exit 1 ;;
esac

TAG="IR-allow-kernelcare"

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

# ─── add ──────────────────────────────────────────────────────────────────────
if ! command -v kcarectl >/dev/null 2>&1; then
  echo "ERROR: kcarectl not found — KernelCare doesn't appear to be installed on this host." >&2
  echo "       (If you have it under a different path, run with PATH including /usr/bin/kcarectl.)" >&2
  exit 1
fi

if ! iptables-save | grep -q "IR-block: default deny"; then
  echo "WARNING: no IR-block ruleset detected. This script is meant to whitelist holes"
  echo "         in the block-outbound.sh lockdown. Continuing anyway..."
  echo ""
fi

# KernelCare / TuxCare CDN endpoints. These are the hosts kcarectl
# reaches outside of apt — live patch downloads, licence, registration.
# As of 2025 the list below covers stock kernelcare-free, kernelcare,
# tuxcare, and CloudLinux LB instances. Adding extras costs nothing.
KCARE_HOSTS=(
  patches.kernelcare.com
  repo.tuxcare.com
  downloads.kernelcare.com
  cln.cloudlinux.com
  rhn.cloudlinux.com
)

# Pick up any custom host configured in /etc/sysconfig/kcare/kcare.conf
# (some installs point at a private mirror).
if [[ -r /etc/sysconfig/kcare/kcare.conf ]]; then
  while read -r host; do
    [[ -z "$host" ]] && continue
    # Skip if already in the array.
    skip=0
    for existing in "${KCARE_HOSTS[@]}"; do
      [[ "$existing" == "$host" ]] && { skip=1; break; }
    done
    [[ $skip -eq 0 ]] && KCARE_HOSTS+=("$host")
  done < <(grep -oE 'https?://[^/[:space:]]+' /etc/sysconfig/kcare/kcare.conf 2>/dev/null \
           | sed 's|^https\?://||' | sed 's|:.*||' | sort -u)
fi

# Open DNS first — needed to resolve the hostnames above.
echo "==> Opening DNS to configured resolvers"
NAMESERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)
if [[ -z "$NAMESERVERS" ]]; then
  echo "ERROR: no nameservers in /etc/resolv.conf — cannot resolve KernelCare hosts" >&2
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

echo ""
echo "==> Opening HTTPS to KernelCare endpoints"
total_ips=0
for host in "${KCARE_HOSTS[@]}"; do
  ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
  if [[ -z "$ips" ]]; then
    echo "    [!] could not resolve $host — skipping"
    continue
  fi
  for ip in $ips; do
    if [[ "$ip" == *:* ]]; then
      ip6tables -I OUTPUT 1 -d "$ip" -p tcp --dport 443 -j ACCEPT -m comment --comment "$TAG: $host:443"
    else
      iptables -I OUTPUT 1 -d "$ip" -p tcp --dport 443 -j ACCEPT -m comment --comment "$TAG: $host:443"
    fi
    echo "    $host -> $ip"
    total_ips=$((total_ips+1))
  done
done

echo ""
echo "==> DONE. Opened DNS + $total_ips KernelCare endpoint IP(s)."
echo ""
echo "Now run:    kcarectl --update"
echo "When done:  sudo bash $0 remove"
echo ""
echo "NOTE: KernelCare CDNs may rotate IPs. If kcarectl fails part-way,"
echo "      re-run 'add' to refresh the resolved IPs."
