#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack Uninstall Script
# Removes WolfStack server management dashboard and optionally WolfNet
#
# Usage: sudo bash uninstall.sh
#        sudo bash uninstall.sh --purge          # Also remove config and data
#        sudo bash uninstall.sh --purge --wolfnet # Also remove WolfNet
#

set -e

# ─── Parse arguments ─────────────────────────────────────────────────────────
PURGE=false
REMOVE_WOLFNET=false
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --purge)   PURGE=true ;;
        --wolfnet) REMOVE_WOLFNET=true ;;
        --force)   FORCE=true ;;
    esac
done

echo ""
echo "  🐺 WolfStack Uninstaller"
echo "  ─────────────────────────────────────"
if [ "$PURGE" = true ]; then
    echo "  Mode: Full purge (config + data will be removed)"
else
    echo "  Mode: Standard (config + data preserved)"
fi
if [ "$REMOVE_WOLFNET" = true ]; then
    echo "  WolfNet: Will also be removed"
fi
echo ""

# ─── Must run as root ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "✗ This script must be run as root."
    echo "  Usage: sudo bash uninstall.sh"
    exit 1
fi

# ─── Confirm ─────────────────────────────────────────────────────────────────
if [ "$FORCE" != true ]; then
    echo "This will remove WolfStack from your system."
    if [ "$PURGE" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --purge will delete ALL configuration and data:"
        echo "     • /etc/wolfstack/ (config files, S3/PBS credentials)"
        echo "     • /opt/wolfstack/ (web UI)"
        echo "     • /opt/wolfstack-src/ (source code)"
        echo "     • /mnt/wolfstack/ (storage mounts)"
        echo "     • /var/cache/wolfstack/ (S3 cache)"
    fi
    if [ "$REMOVE_WOLFNET" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --wolfnet will also remove WolfNet:"
        echo "     • wolfnet binary and systemd service"
        if [ "$PURGE" = true ]; then
            echo "     • /etc/wolfnet/ (config and keys)"
            echo "     • /opt/wolfnet-src/ (source code)"
        fi
    fi
    echo ""
    echo -n "Are you sure you want to continue? [y/N]: "
    read CONFIRM < /dev/tty
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled."
        exit 0
    fi
    echo ""
fi

# ─── Stop and disable WolfStack service ─────────────────────────────────────
echo "Stopping WolfStack..."
if systemctl is-active --quiet wolfstack 2>/dev/null; then
    systemctl stop wolfstack 2>/dev/null || true
    echo "✓ WolfStack service stopped"
else
    echo "  WolfStack service not running"
fi

if systemctl is-enabled --quiet wolfstack 2>/dev/null; then
    systemctl disable wolfstack 2>/dev/null || true
    echo "✓ WolfStack service disabled"
fi

# ─── Remove systemd service file ────────────────────────────────────────────
if [ -f "/etc/systemd/system/wolfstack.service" ]; then
    rm -f /etc/systemd/system/wolfstack.service
    systemctl daemon-reload
    echo "✓ WolfStack systemd service removed"
else
    echo "  No systemd service file found"
fi

# ─── Remove binary ──────────────────────────────────────────────────────────
if [ -f "/usr/local/bin/wolfstack" ]; then
    rm -f /usr/local/bin/wolfstack
    echo "✓ Removed /usr/local/bin/wolfstack"
else
    echo "  Binary not found at /usr/local/bin/wolfstack"
fi

# ─── Remove web UI ──────────────────────────────────────────────────────────
if [ -d "/opt/wolfstack/web" ]; then
    rm -rf /opt/wolfstack/web
    # Remove /opt/wolfstack if now empty
    rmdir /opt/wolfstack 2>/dev/null || true
    echo "✓ Removed web UI from /opt/wolfstack/web"
else
    echo "  Web UI directory not found"
fi

# ─── Remove firewall rules ──────────────────────────────────────────────────
# Read port from config if it exists
WS_PORT=$(grep "port" /etc/wolfstack/config.toml 2>/dev/null | head -1 | awk '{print $3}' || echo "8553")

if command -v ufw &> /dev/null; then
    ufw delete allow "$WS_PORT/tcp" 2>/dev/null && echo "✓ Firewall: Closed port $WS_PORT/tcp (ufw)" || true
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --remove-port="$WS_PORT/tcp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    echo "✓ Firewall: Closed port $WS_PORT/tcp (firewalld)" || true
fi

# ─── Purge config and data (optional) ───────────────────────────────────────
if [ "$PURGE" = true ]; then
    echo ""
    echo "Purging configuration and data..."

    if [ -d "/etc/wolfstack" ]; then
        rm -rf /etc/wolfstack
        echo "✓ Removed /etc/wolfstack/"
    fi

    if [ -d "/opt/wolfstack-src" ]; then
        rm -rf /opt/wolfstack-src
        echo "✓ Removed /opt/wolfstack-src/"
    fi

    if [ -d "/opt/wolfstack" ]; then
        rm -rf /opt/wolfstack
        echo "✓ Removed /opt/wolfstack/"
    fi

    if [ -d "/mnt/wolfstack" ]; then
        # Unmount any active mounts first
        for mnt in /mnt/wolfstack/*/; do
            if mountpoint -q "$mnt" 2>/dev/null; then
                umount -l "$mnt" 2>/dev/null || true
            fi
        done
        rm -rf /mnt/wolfstack
        echo "✓ Removed /mnt/wolfstack/"
    fi

    if [ -d "/var/cache/wolfstack" ]; then
        rm -rf /var/cache/wolfstack
        echo "✓ Removed /var/cache/wolfstack/"
    fi
else
    echo ""
    echo "  ℹ  Config preserved at /etc/wolfstack/"
    echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge"
fi

# ─── Remove WolfNet (optional) ──────────────────────────────────────────────
if [ "$REMOVE_WOLFNET" = true ]; then
    echo ""
    echo "Removing WolfNet..."

    # Stop and disable service
    if systemctl is-active --quiet wolfnet 2>/dev/null; then
        systemctl stop wolfnet 2>/dev/null || true
        echo "✓ WolfNet service stopped"
    fi

    if systemctl is-enabled --quiet wolfnet 2>/dev/null; then
        systemctl disable wolfnet 2>/dev/null || true
        echo "✓ WolfNet service disabled"
    fi

    # Remove systemd service
    if [ -f "/etc/systemd/system/wolfnet.service" ]; then
        rm -f /etc/systemd/system/wolfnet.service
        systemctl daemon-reload
        echo "✓ WolfNet systemd service removed"
    fi

    # Remove binaries
    if [ -f "/usr/local/bin/wolfnet" ]; then
        rm -f /usr/local/bin/wolfnet
        echo "✓ Removed /usr/local/bin/wolfnet"
    fi
    if [ -f "/usr/local/bin/wolfnetctl" ]; then
        rm -f /usr/local/bin/wolfnetctl
        echo "✓ Removed /usr/local/bin/wolfnetctl"
    fi

    # Remove wolfnet0 interface
    if ip link show wolfnet0 &>/dev/null; then
        ip link set wolfnet0 down 2>/dev/null || true
        ip link delete wolfnet0 2>/dev/null || true
        echo "✓ Removed wolfnet0 network interface"
    fi

    # Remove firewall rules for WolfNet
    if command -v ufw &> /dev/null; then
        ufw delete allow 9600/udp 2>/dev/null && echo "✓ Firewall: Closed port 9600/udp (ufw)" || true
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-port="9600/udp" 2>/dev/null && \
        firewall-cmd --reload 2>/dev/null && \
        echo "✓ Firewall: Closed port 9600/udp (firewalld)" || true
    fi

    # Purge WolfNet config and source
    if [ "$PURGE" = true ]; then
        if [ -d "/etc/wolfnet" ]; then
            rm -rf /etc/wolfnet
            echo "✓ Removed /etc/wolfnet/"
        fi

        if [ -d "/var/run/wolfnet" ]; then
            rm -rf /var/run/wolfnet
            echo "✓ Removed /var/run/wolfnet/"
        fi

        if [ -d "/opt/wolfnet-src" ]; then
            rm -rf /opt/wolfnet-src
            echo "✓ Removed /opt/wolfnet-src/"
        fi
    else
        echo "  ℹ  WolfNet config preserved at /etc/wolfnet/"
        echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge --wolfnet"
    fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "  🐺 Uninstall Complete!"
echo "  ─────────────────────────────────────"
if [ "$PURGE" != true ]; then
    echo "  Config files preserved — reinstall with setup.sh to restore."
fi
if [ "$REMOVE_WOLFNET" != true ] && command -v wolfnet &>/dev/null; then
    echo "  WolfNet was NOT removed. To remove it:"
    echo "    sudo bash uninstall.sh --wolfnet"
fi
echo ""
echo "  Note: System packages installed by setup.sh (git, curl, Docker,"
echo "  LXC, QEMU, etc.) were NOT removed. Remove them manually if needed."
echo ""
