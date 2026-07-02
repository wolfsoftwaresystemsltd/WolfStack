#!/bin/bash
# Deploy the freshly-built wolfstack release binary over the running one.
# Idempotent: re-running it just re-installs the same binary.
# Designed to be foolproof — no multi-line shell quoting to mangle.

set -e

SRC="/home/paulc/NetBeansProjects/wolfscale/wolfstack/target/release/wolfstack"
DST="/usr/local/bin/wolfstack"
BAK="/usr/local/bin/wolfstack.bak"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (try: su -c '/home/paulc/NetBeansProjects/wolfscale/wolfstack/deploy-new.sh')" >&2
  exit 1
fi

if [[ ! -f "$SRC" ]]; then
  echo "ERROR: release binary not found at $SRC" >&2
  exit 1
fi

# Make sure we have SOME backup. If a previous attempt left a bak file,
# keep it (it's the original v23.12.4). Otherwise capture the current
# binary right now.
if [[ ! -f "$BAK" ]]; then
  echo "==> No existing backup — snapshotting current $DST to $BAK"
  cp "$DST" "$BAK"
fi

echo "==> Stopping wolfstack.service (idempotent)"
systemctl stop wolfstack.service || true

echo "==> Installing new binary"
install -m 0755 -o root -g root "$SRC" "$DST"

echo "==> Starting wolfstack.service"
systemctl start wolfstack.service

sleep 2

if systemctl is-active --quiet wolfstack.service; then
  echo "==> OK — wolfstack.service is active"
  systemctl status wolfstack.service --no-pager -l | head -8
else
  echo "==> FAILED — service is not active. Showing journal:"
  journalctl -u wolfstack.service --no-pager -l -n 30
  exit 1
fi
