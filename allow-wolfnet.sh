#!/bin/bash
# allow-wolfnet.sh — re-open the outbound traffic the WolfNet overlay needs on
# a host that's been locked down by block-outbound.sh.
#
# WHY THIS IS NEEDED
#   block-outbound.sh appends a default-DROP to the OUTPUT chain and only
#   whitelists established sessions, loopback, and corosync cluster-ring peers.
#   WolfNet's tunnel must *initiate* outbound UDP to every peer — including
#   peers on other clusters and peers learned at runtime via PEX — so any peer
#   whose endpoint isn't a corosync ring IP gets dropped and the mesh dies.
#
# WHAT IT OPENS
#   1. Tunnel transport — outbound UDP whose SOURCE port is WolfNet's
#      listen_port. WolfNet binds one UDP socket to <bind_address>:<listen_port>
#      (see wolfnet src/main.rs UdpSocket::bind, src/transport.rs send paths);
#      every handshake / keepalive / data / peer-exchange packet is sent from
#      that socket, so they all share that source port. Matching --sport is
#      therefore precise (one port, not "all UDP") yet covers every peer and
#      every PEX-learned endpoint without enumerating IPs that can rotate.
#   2. LAN discovery broadcast — outbound UDP to 255.255.255.255:9601
#      (wolfnet src/transport.rs DISCOVERY_PORT). Only matters for same-subnet
#      auto-discovery; harmless to include.
#
#   It does NOT whitelist traffic that a WolfNet *gateway* node NATs on behalf
#   of other nodes (their internet egress) — that stays blocked on purpose
#   during incident response.
#
# Usage:
#   sudo bash allow-wolfnet.sh add      # open WolfNet tunnel + discovery outbound
#   sudo bash allow-wolfnet.sh remove   # revoke the temporary whitelist
#   sudo bash allow-wolfnet.sh status   # show currently-active whitelist rules
#
# Rules are tagged 'IR-allow-wolfnet:' so they're identifiable and removable
# without touching the rest of the block-outbound ruleset.

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

ACTION="${1:-}"
case "$ACTION" in add|remove|status) ;;
  *) echo "Usage: $0 {add|remove|status}" >&2; exit 1 ;;
esac

TAG="IR-allow-wolfnet"
WOLFNET_CONF="/etc/wolfnet/config.toml"
DISCOVERY_PORT=9601   # wolfnet src/transport.rs: pub const DISCOVERY_PORT: u16 = 9601

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
  echo "==> WolfNet outbound is locked down again. The mesh will stop after"
  echo "    the last keepalive ages out (~120s)."
  exit 0
fi

# ─── add ──────────────────────────────────────────────────────────────────────
# Sanity check: warn if block-outbound never ran (this script is only useful
# when there's a lockdown to poke a hole in).
if ! iptables-save | grep -q "IR-block: default deny"; then
  echo "WARNING: no IR-block ruleset detected. This script is meant to whitelist"
  echo "         holes in the block-outbound.sh lockdown. Continuing anyway..."
  echo ""
fi

# Determine WolfNet's UDP listen port from its config (default 9600 if the
# config is missing or has no explicit listen_port — matches wolfnet
# src/config.rs default_port()).
LISTEN_PORT=""
if [[ -r "$WOLFNET_CONF" ]]; then
  LISTEN_PORT=$(awk -F= '
    /^[[:space:]]*listen_port[[:space:]]*=/ { gsub(/[^0-9]/,"",$2); print $2; exit }
  ' "$WOLFNET_CONF" 2>/dev/null)
fi
if [[ -z "${LISTEN_PORT}" ]]; then
  LISTEN_PORT=9600
  echo "==> WolfNet listen_port not found in $WOLFNET_CONF — using default $LISTEN_PORT"
else
  echo "==> WolfNet listen_port = $LISTEN_PORT (from $WOLFNET_CONF)"
fi

# 1. Tunnel transport — outbound UDP from WolfNet's listen_port to any peer.
echo ""
echo "==> Opening WolfNet tunnel transport (outbound udp --sport $LISTEN_PORT)"
iptables  -I OUTPUT 1 -p udp --sport "$LISTEN_PORT" -j ACCEPT \
  -m comment --comment "$TAG: tunnel udp/$LISTEN_PORT"
ip6tables -I OUTPUT 1 -p udp --sport "$LISTEN_PORT" -j ACCEPT \
  -m comment --comment "$TAG: tunnel udp/$LISTEN_PORT"
echo "    allowed udp/$LISTEN_PORT outbound (v4 + v6)"

# 2. LAN discovery broadcast — outbound UDP to 255.255.255.255:9601.
#    The broadcaster binds an ephemeral source port, so this is matched on the
#    broadcast destination + discovery port. IPv4 broadcast only — WolfNet's
#    discovery has no IPv6 equivalent.
echo ""
echo "==> Opening WolfNet LAN discovery broadcast (udp -> 255.255.255.255:$DISCOVERY_PORT)"
iptables -I OUTPUT 1 -p udp -d 255.255.255.255 --dport "$DISCOVERY_PORT" -j ACCEPT \
  -m comment --comment "$TAG: discovery broadcast"
echo "    allowed udp/$DISCOVERY_PORT broadcast outbound (v4)"

echo ""
echo "==> DONE. WolfNet can reach all peers (configured + PEX-learned) again."
echo ""
echo "Verify on this node:"
echo "  wolfnetctl status      # peers should reach 'data_flowing' within ~30s"
echo "  iptables -L OUTPUT -n -v --line-numbers | grep -E 'Chain|$TAG'"
echo ""
echo "When the incident lockdown is lifted entirely, prefer restoring the"
echo "pre-incident ruleset over piecemeal removal:"
echo "  iptables-restore  < /root/iptables-before-block-<timestamp>.rules"
echo "  ip6tables-restore < /root/ip6tables-before-block-<timestamp>.rules"
echo ""
echo "Or revoke just this whitelist:  sudo bash $0 remove"
echo ""
echo "NOTE: like block-outbound.sh, these are runtime rules — a reboot clears"
echo "      both the block and this whitelist."
