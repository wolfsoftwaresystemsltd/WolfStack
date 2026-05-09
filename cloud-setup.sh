#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack Cloud Setup
# A cloud-init-friendly wrapper around setup.sh that adds hostname
# configuration. Designed to be the entry point for the per-cloud
# bootstrap scripts (Hetzner, AWS, GCP, Azure, DigitalOcean, Vultr,
# Linode, Scaleway, etc.) so every fresh cloud VM ends up with a
# meaningful hostname AND a running WolfStack node, without prompting
# (cloud-init has no TTY).
#
# Usage from cloud-init runcmd:
#   curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/cloud-setup.sh \
#     | sudo bash -s -- --hostname mynode-01
#
# Usage interactively on a fresh VM (will prompt for hostname):
#   curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/cloud-setup.sh \
#     | sudo bash
#
# Behaviour:
#   * --hostname <name>  set the system hostname before installing
#                        (hostnamectl + /etc/hosts patched)
#   * If --hostname omitted AND a TTY is available, prompts for it
#   * If --hostname omitted AND no TTY (cloud-init), keeps the existing
#     hostname (e.g. cloud-provider auto-generated like ip-10-0-1-23)
#   * Always passes --yes to setup.sh so the install runs unattended;
#     cloud-init never has a TTY and would otherwise hang
#   * Other flags (--beta, --agent, --skip-pbs-build, etc.) are forwarded
#     to setup.sh verbatim
#
# Each node still generates its own join token at /etc/wolfstack/join-token.
# After this script finishes you'll see the token in setup.sh's completion
# banner; SSH into the new node later to retrieve it
# (`sudo cat /etc/wolfstack/join-token`) and paste into the master server's
# Cluster → Add Node form.

# `set -u` catches unset variables (typo defence). `set -o pipefail` makes
# the curl|bash hand-off below fail loudly if curl 404s — without it, bash
# would receive empty stdin, exit 0, and we'd "succeed" with nothing
# installed. `set -e` aborts on the first unhandled error.
set -euo pipefail

# ─── Constants ──────────────────────────────────────────────────────────────
# Pinned at file scope so they're easy to find/audit.
SETUP_REPO="wolfsoftwaresystemsltd/WolfStack"
HOSTNAME_REGEX='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'

# ─── Help text (rendered the same whether the script is run from a file ─────
#                or piped from curl — sed-on-self breaks when piped because
#                $0 is `bash`, so we keep the help inline as a heredoc) ─────
print_help() {
    cat <<'HELP'
WolfStack Cloud Setup — cloud-init wrapper around setup.sh

Usage:
  cloud-setup.sh [--hostname <name>] [setup.sh flags...]

Flags:
  --hostname <name>   Set the system hostname before installing WolfStack.
                      RFC 1123 (letters, digits, hyphens). Persisted via
                      hostnamectl + /etc/hosts.
  --beta              Forward to setup.sh — install from the beta branch.
  --agent             Forward to setup.sh — install in agent mode (cluster
                      API only, no SPA).
  --help, -h          Show this message.

Any flag not recognised here is passed through to setup.sh untouched.
--yes is always passed to setup.sh so the install runs unattended.

Examples:
  # From cloud-init runcmd (non-interactive):
  curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/cloud-setup.sh \
    | sudo bash -s -- --hostname web-01

  # Interactive on a fresh VM (prompts for hostname):
  curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/cloud-setup.sh \
    | sudo bash

After install, retrieve the cluster join token with:
  sudo cat /etc/wolfstack/join-token
HELP
}

# ─── Parse arguments ─────────────────────────────────────────────────────────
NEW_HOSTNAME=""
BRANCH="master"
# Always include --yes so setup.sh runs unattended. Cloud-init has no TTY,
# and the prompt_read() in setup.sh would silently fall through to empty
# defaults; --yes makes the unattended path explicit and consistent.
SETUP_ARGS=("--yes")

while [ $# -gt 0 ]; do
    case "$1" in
        --hostname)
            if [ "${2:-}" != "" ] && [ "${2#-}" = "${2:-}" ]; then
                shift
                NEW_HOSTNAME="$1"
            else
                echo "✗ --hostname requires a name argument" >&2
                exit 2
            fi
            ;;
        --beta)
            BRANCH="beta"
            SETUP_ARGS+=("--beta")
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            # Forward anything else to setup.sh — keeps cloud-setup.sh
            # transparent to setup.sh's flags without re-listing them here.
            SETUP_ARGS+=("$1")
            ;;
    esac
    shift
done

# ─── Sanity: root + Linux + tools ────────────────────────────────────────────
if [ "$(id -u 2>/dev/null)" != "0" ]; then
    echo "✗ cloud-setup.sh must be run as root (use sudo)" >&2
    exit 2
fi

# Catch the obvious "wrong OS" case before we waste time downloading setup.sh
case "$(uname -s 2>/dev/null)" in
    Linux) ;;
    *)
        echo "✗ cloud-setup.sh requires a Linux host (uname=$(uname -s))" >&2
        echo "  WolfStack is Linux-only. Spin up a Linux VM and re-run." >&2
        exit 2
        ;;
esac

# curl is the only tool we need before handing off to setup.sh. Most cloud
# base images ship it, but the very minimal Alpine / Debian-cloud variants
# sometimes don't — surface a clean error rather than `command not found`.
if ! command -v curl >/dev/null 2>&1; then
    echo "✗ curl is required by cloud-setup.sh (and by setup.sh)" >&2
    echo "  Install: 'apt-get install -y curl' / 'dnf install -y curl' / 'apk add curl'" >&2
    exit 2
fi

# ─── Hostname prompt (only when interactive AND no --hostname given) ─────────
# /dev/tty is the canonical "is there a human at the other end" check. Cloud-
# init runcmd never has /dev/tty, so this block is skipped automatically in
# that context — perfect, because we don't want to block waiting on input.
if [ -z "$NEW_HOSTNAME" ] && [ -e /dev/tty ] && : < /dev/tty 2>/dev/null; then
    CURRENT_HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
    echo ""
    echo "  Set the hostname for this WolfStack node."
    echo "  (Press Enter to keep the current one: '$CURRENT_HOSTNAME')"
    echo -n "  Hostname: "
    read -r NEW_HOSTNAME < /dev/tty 2>/dev/null || NEW_HOSTNAME=""
    echo ""
fi

# ─── Apply hostname change ───────────────────────────────────────────────────
if [ -n "$NEW_HOSTNAME" ]; then
    # RFC 1123: each label is letters/digits/hyphens, no leading/trailing
    # hyphen, max 63 chars per label, dots between labels.
    if ! echo "$NEW_HOSTNAME" | grep -qE "$HOSTNAME_REGEX"; then
        echo "✗ Invalid hostname: '$NEW_HOSTNAME'" >&2
        echo "  Hostnames must follow RFC 1123 (letters, digits, hyphens; max 63 per label)." >&2
        exit 2
    fi

    OLD_HOSTNAME="$(hostname 2>/dev/null || echo '')"
    if [ "$NEW_HOSTNAME" != "$OLD_HOSTNAME" ]; then
        echo "→ Setting hostname: $OLD_HOSTNAME → $NEW_HOSTNAME"

        # Persist (survives reboot) — works on systemd, falls back to
        # writing /etc/hostname directly for non-systemd Linux (rare on
        # cloud, but Alpine is non-systemd by default).
        if command -v hostnamectl >/dev/null 2>&1; then
            hostnamectl set-hostname "$NEW_HOSTNAME"
        elif [ -w /etc/hostname ]; then
            echo "$NEW_HOSTNAME" > /etc/hostname
        else
            echo "  ⚠ Neither hostnamectl nor writable /etc/hostname found — hostname will not persist across reboot" >&2
        fi

        # Apply now so subsequent commands see the new hostname.
        # Some Alpine/musl systems lack the `hostname` BSD command;
        # writing /proc/sys/kernel/hostname is the universal fallback.
        if command -v hostname >/dev/null 2>&1; then
            hostname "$NEW_HOSTNAME" 2>/dev/null || echo "$NEW_HOSTNAME" > /proc/sys/kernel/hostname 2>/dev/null || true
        else
            echo "$NEW_HOSTNAME" > /proc/sys/kernel/hostname 2>/dev/null || true
        fi

        # Patch /etc/hosts so `sudo` and other tools that resolve the local
        # hostname don't complain. By Debian convention the 127.0.1.1 line
        # maps to the system hostname; we keep 127.0.0.1 localhost
        # untouched. RHEL-family hosts often don't ship a 127.0.1.1 line —
        # we add one so the same logic works everywhere.
        if [ -w /etc/hosts ]; then
            if grep -qE '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
                sed -i "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
            else
                printf '127.0.1.1\t%s\n' "$NEW_HOSTNAME" >> /etc/hosts
            fi
        else
            echo "  ⚠ /etc/hosts not writable — hostname change applied but not reflected in /etc/hosts" >&2
        fi
    fi
fi

# ─── Hand off to setup.sh ────────────────────────────────────────────────────
SETUP_URL="https://raw.githubusercontent.com/${SETUP_REPO}/${BRANCH}/setup.sh"
echo "→ Fetching setup.sh from ${BRANCH} branch..."
echo ""

# `--proto '=https'` ensures curl refuses any non-HTTPS redirect target —
# defensive against a compromised intermediate adding an http:// hop. The
# `set -o pipefail` at the top of the script propagates curl failures
# through the pipe into bash, so a 404 or DNS failure here aborts loudly
# rather than silently running an empty pipeline as success.
if ! curl --proto '=https' -fsSL --connect-timeout 15 --max-time 600 --retry 2 "$SETUP_URL" \
    | bash -s -- "${SETUP_ARGS[@]}"; then
    echo "" >&2
    echo "✗ setup.sh failed (or could not be downloaded). See output above for details." >&2
    echo "  Common causes:" >&2
    echo "    • Network: this VM cannot reach raw.githubusercontent.com" >&2
    echo "    • Branch: --beta given but the beta branch is currently broken" >&2
    echo "    • Distro: this Linux distribution is not yet supported by setup.sh" >&2
    exit 1
fi

# setup.sh prints its own completion banner with the join token. We don't
# repeat it here — the operator only wants to see one. cloud-setup.sh's
# job is done at this point.
