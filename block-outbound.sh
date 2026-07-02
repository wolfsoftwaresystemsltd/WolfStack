#!/bin/bash
# block-outbound.sh — incident response: block all outbound from a Proxmox host
# while preserving the current SSH session, loopback, and inter-node cluster traffic.
#
# Usage:  scp this file to each Proxmox node, then:  sudo bash block-outbound.sh
# Rollback path is printed at the end.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root" >&2
  exit 1
fi

COROSYNC_CONF="/etc/pve/corosync.conf"
if [[ ! -r "$COROSYNC_CONF" ]]; then
  echo "ERROR: cannot read $COROSYNC_CONF — is this a Proxmox node?" >&2
  exit 1
fi

TS=$(date +%Y%m%d-%H%M%S)
BACKUP4="/root/iptables-before-block-${TS}.rules"
BACKUP6="/root/ip6tables-before-block-${TS}.rules"

echo "==> Snapshotting current firewall rules"
iptables-save  > "$BACKUP4"
ip6tables-save > "$BACKUP6"
echo "    saved: $BACKUP4"
echo "    saved: $BACKUP6"

echo "==> Discovering cluster peers from $COROSYNC_CONF"
RAW_PEERS=$(awk '/ring[0-9]+_addr:/ {print $2}' "$COROSYNC_CONF" | tr -d '"' | sort -u)
if [[ -z "$RAW_PEERS" ]]; then
  echo "ERROR: no ringX_addr entries found in corosync.conf — refusing to proceed" >&2
  echo "       (running without peer whitelist would break the cluster)" >&2
  exit 1
fi

PEER_IPS=()
for entry in $RAW_PEERS; do
  if [[ "$entry" =~ ^[0-9a-fA-F:.]+$ ]] && [[ "$entry" == *.* || "$entry" == *:* ]]; then
    PEER_IPS+=("$entry")
  else
    # Hostname — resolve it
    resolved=$(getent ahosts "$entry" | awk '{print $1}' | sort -u)
    if [[ -z "$resolved" ]]; then
      echo "ERROR: could not resolve peer hostname '$entry' — refusing to proceed" >&2
      exit 1
    fi
    for ip in $resolved; do
      PEER_IPS+=("$ip")
    done
  fi
done

echo "    peers to whitelist:"
for ip in "${PEER_IPS[@]}"; do echo "      $ip"; done

apply_v4() {
  echo "==> Applying IPv4 OUTPUT rules"
  # ESTABLISHED first so your live SSH session survives
  iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "IR-block: keep existing sessions"
  iptables -I OUTPUT 2 -o lo -j ACCEPT -m comment --comment "IR-block: loopback"
  local idx=3
  for ip in "${PEER_IPS[@]}"; do
    if [[ "$ip" == *:* ]]; then continue; fi  # v6 handled separately
    iptables -I OUTPUT $idx -d "$ip" -j ACCEPT -m comment --comment "IR-block: cluster peer"
    idx=$((idx+1))
  done
  iptables -A OUTPUT -j DROP -m comment --comment "IR-block: default deny"
}

apply_v6() {
  echo "==> Applying IPv6 OUTPUT rules"
  ip6tables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "IR-block: keep existing sessions"
  ip6tables -I OUTPUT 2 -o lo -j ACCEPT -m comment --comment "IR-block: loopback"
  local idx=3
  for ip in "${PEER_IPS[@]}"; do
    if [[ "$ip" != *:* ]]; then continue; fi
    ip6tables -I OUTPUT $idx -d "$ip" -j ACCEPT -m comment --comment "IR-block: cluster peer"
    idx=$((idx+1))
  done
  ip6tables -A OUTPUT -j DROP -m comment --comment "IR-block: default deny"
}

apply_v4
apply_v6

echo ""
echo "==> DONE. Outbound is blocked except: established sessions, loopback, cluster peers."
echo ""
echo "Verify with:"
echo "  iptables  -L OUTPUT -n -v --line-numbers"
echo "  ip6tables -L OUTPUT -n -v --line-numbers"
echo ""
echo "Test (should FAIL):  curl -sS --max-time 5 https://1.1.1.1"
echo "Test (should PASS):  ping -c1 ${PEER_IPS[0]}"
echo ""
echo "ROLLBACK when ready:"
echo "  iptables-restore  < $BACKUP4"
echo "  ip6tables-restore < $BACKUP6"
