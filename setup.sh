#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack Quick Install Script
# Installs WolfStack server management dashboard
# Supported: Ubuntu/Debian, Fedora/RHEL/CentOS, SLES/openSUSE, IBM Power (ppc64le)
#
# Usage: curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash
#        curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/beta/setup.sh | sudo bash -s -- --beta
#        sudo bash setup.sh --install-dir /mnt/usb      # build & install from external drive
#

set -e

# Helper: read from /dev/tty if available, otherwise return empty (use defaults)
prompt_read() {
    if [ -e /dev/tty ] && : < /dev/tty 2>/dev/null; then
        read "$1" < /dev/tty 2>/dev/null || eval "$1="
    else
        eval "$1="
    fi
}

# ─── Parse arguments ─────────────────────────────────────────────────────────
BRANCH="master"
CUSTOM_INSTALL_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --beta) BRANCH="beta" ;;
        --install-dir|--install)
            if [ -n "$2" ]; then
                shift
                CUSTOM_INSTALL_DIR="$1"
            else
                echo "✗ --install-dir requires a path argument"
                exit 1
            fi
            ;;
    esac
    shift
done

# Allow git to operate on repos owned by other users (setup.sh runs as root
# but repos may have been cloned by a regular user)
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="*"

# ─── Custom install directory (for low-disk devices like Raspberry Pi) ───────
if [ -n "$CUSTOM_INSTALL_DIR" ]; then
    # If given a block device, mount it
    if [ -b "$CUSTOM_INSTALL_DIR" ]; then
        MOUNT_DEV="$CUSTOM_INSTALL_DIR"
        CUSTOM_INSTALL_DIR="/mnt/wolfstack-build"
        mkdir -p "$CUSTOM_INSTALL_DIR"
        if ! mountpoint -q "$CUSTOM_INSTALL_DIR" 2>/dev/null; then
            echo "Mounting $MOUNT_DEV at $CUSTOM_INSTALL_DIR..."
            mount "$MOUNT_DEV" "$CUSTOM_INSTALL_DIR"
        fi
    fi
    mkdir -p "$CUSTOM_INSTALL_DIR"

    # Redirect EVERYTHING to external drive: Rust toolchain, build cache, temp files
    export RUSTUP_HOME="$CUSTOM_INSTALL_DIR/.rustup"
    export CARGO_HOME="$CUSTOM_INSTALL_DIR/.cargo"
    export TMPDIR="$CUSTOM_INSTALL_DIR/tmp"
    export PATH="$CARGO_HOME/bin:$PATH"
    mkdir -p "$TMPDIR"
fi

echo ""
echo "  🐺 WolfStack Installer"
echo "  ─────────────────────────────────────"
echo "  Server Management Platform"
if [ "$BRANCH" != "master" ]; then
    echo "  Branch: $BRANCH"
fi
if [ -n "$CUSTOM_INSTALL_DIR" ]; then
    echo "  Install dir: $CUSTOM_INSTALL_DIR"
fi
echo ""

# ─── Must run as root ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "✗ This script must be run as root."
    echo "  Usage: sudo bash setup.sh"
    echo "     or: curl -sSL <url> | sudo bash"
    exit 1
fi

# Detect the real user (for Rust install) when running under sudo
REAL_USER="${SUDO_USER:-root}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ─── Detect package manager ─────────────────────────────────────────────────
echo "Checking system requirements..."

if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    echo "✓ Detected Debian/Ubuntu (apt)"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    echo "✓ Detected Fedora/RHEL (dnf)"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    echo "✓ Detected RHEL/CentOS (yum)"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
    echo "✓ Detected SLES/openSUSE (zypper)"
else
    echo "✗ Could not detect package manager (apt/dnf/yum/zypper)"
    echo "  Please install dependencies manually."
    exit 1
fi

# ─── Detect Proxmox VE host ─────────────────────────────────────────────────
IS_PROXMOX=false
if command -v pveversion &> /dev/null || [ -f /etc/pve/.version ] || dpkg -l proxmox-ve &> /dev/null 2>&1; then
    IS_PROXMOX=true
    PVE_VER=$(pveversion 2>/dev/null || echo "unknown")
    echo "✓ Detected Proxmox VE host ($PVE_VER)"
    echo "  Skipping packages already provided by Proxmox (QEMU, LXC)"
fi

# ─── Install system dependencies ────────────────────────────────────────────
echo ""
echo "Installing system dependencies..."

if [ "$PKG_MANAGER" = "apt" ]; then
    apt update -qq
    # On Proxmox hosts, QEMU and LXC are already provided by pve-qemu-kvm and lxc-pve.
    # Many Debian packages conflict with PVE equivalents, causing APT to try removing
    # the proxmox-ve metapackage. We must be very conservative on PVE hosts.
    if [ "$IS_PROXMOX" = true ]; then
        # Only install build dependencies needed for compiling Rust/WolfStack.
        # Proxmox already provides QEMU, LXC, socat, bridge-utils, etc.
        apt install -y --no-install-recommends git curl build-essential pkg-config libssl-dev libcrypt-dev || {
            echo "⚠ Some build dependencies failed to install. Trying individually..."
            for pkg in git curl build-essential pkg-config libssl-dev libcrypt-dev; do
                dpkg -s "$pkg" &>/dev/null || apt install -y --no-install-recommends "$pkg" 2>/dev/null || true
            done
        }
        # Install optional runtime deps one-by-one — skip if already provided by PVE
        for pkg in dnsmasq-base bridge-utils socat s3fs nfs-common fuse3; do
            if dpkg -s "$pkg" &>/dev/null; then
                echo "  ✓ $pkg already installed"
            else
                echo "  Installing $pkg..."
                apt install -y --no-install-recommends "$pkg" 2>/dev/null || \
                    echo "  ⚠ Could not install $pkg (may conflict with PVE) — skipping"
            fi
        done
    else
        # Select architecture-appropriate QEMU package
        ARCH=$(uname -m)
        if [ "$ARCH" = "ppc64le" ] || [ "$ARCH" = "ppc64" ]; then
            QEMU_PKG="qemu-system-ppc qemu-utils"
        elif [ "$ARCH" = "aarch64" ]; then
            QEMU_PKG="qemu-system-arm qemu-utils qemu-efi-aarch64"
        else
            QEMU_PKG="qemu-system-x86 qemu-utils"
        fi
        apt install -y git curl build-essential pkg-config libssl-dev libcrypt-dev lxc lxc-templates dnsmasq-base bridge-utils $QEMU_PKG socat s3fs nfs-common fuse3
    fi
elif [ "$PKG_MANAGER" = "dnf" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_DNF="qemu-system-aarch64 qemu-img edk2-aarch64"
    else
        QEMU_DNF="qemu-kvm qemu-img"
    fi
    dnf install -y git curl gcc gcc-c++ make openssl-devel pkg-config libxcrypt-devel lxc lxc-templates lxc-extra dnsmasq bridge-utils $QEMU_DNF socat s3fs-fuse nfs-utils fuse3
elif [ "$PKG_MANAGER" = "yum" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_YUM="qemu-system-aarch64 qemu-img"
    else
        QEMU_YUM="qemu-kvm qemu-img"
    fi
    yum install -y git curl gcc gcc-c++ make openssl-devel pkgconfig lxc lxc-templates lxc-extra dnsmasq bridge-utils $QEMU_YUM socat s3fs-fuse nfs-utils fuse
elif [ "$PKG_MANAGER" = "zypper" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_ZYPP="qemu-arm qemu-tools qemu-uefi-aarch64"
    else
        QEMU_ZYPP="qemu-kvm qemu-tools"
    fi
    zypper install -y git curl gcc gcc-c++ make libopenssl-devel pkg-config lxc dnsmasq bridge-utils $QEMU_ZYPP socat s3fs nfs-client fuse3
fi

echo "✓ System dependencies installed"

# ─── Install Proxmox Backup Client (optional, for PBS integration) ──────────
echo ""
echo "Installing Proxmox Backup Client..."

if command -v proxmox-backup-client &> /dev/null; then
    echo "✓ proxmox-backup-client already installed"
elif [ "$PKG_MANAGER" = "apt" ]; then
    # Add Proxmox PBS repo for Debian/Ubuntu
    PBS_REPO_FILE="/etc/apt/sources.list.d/pbs-client.list"
    if [ ! -f "$PBS_REPO_FILE" ]; then
        CODENAME="bookworm"
        echo "deb http://download.proxmox.com/debian/pbs $CODENAME pbs-no-subscription" > "$PBS_REPO_FILE"
        curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-${CODENAME}.gpg" \
            -o /etc/apt/trusted.gpg.d/proxmox-release-${CODENAME}.gpg 2>/dev/null || true
        apt update -qq 2>/dev/null || true
    fi
    apt install -y proxmox-backup-client 2>/dev/null || \
    apt install -y --allow-unauthenticated proxmox-backup-client 2>/dev/null || {
        echo "⚠ Could not install proxmox-backup-client from repo."
        echo "  You can install it manually later: apt install proxmox-backup-client"
    }
else
    # For Fedora, RHEL, Arch, etc: download the .deb from Proxmox and extract the binary
    # The proxmox-backup-client binary is statically linked and works on any Linux
    echo "  Non-Debian system detected — extracting proxmox-backup-client from Proxmox .deb..."
    PBS_TMP=$(mktemp -d)
    ARCH=$(dpkg --print-architecture 2>/dev/null || (uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'))

    # Find the latest proxmox-backup-client .deb URL from the Proxmox repo
    PBS_PKG_URL="http://download.proxmox.com/debian/pbs/dists/bookworm/pbs-no-subscription/binary-${ARCH}/"
    PBS_DEB=$(curl -fsSL "$PBS_PKG_URL" 2>/dev/null | grep -oP 'proxmox-backup-client_[^"]+\.deb' | sort -V | tail -1)

    if [ -n "$PBS_DEB" ]; then
        echo "  Downloading $PBS_DEB..."
        if curl -fsSL "${PBS_PKG_URL}${PBS_DEB}" -o "${PBS_TMP}/${PBS_DEB}" 2>/dev/null; then
            # Extract .deb: ar extracts data.tar, then we pull the binary out
            cd "$PBS_TMP"
            ar x "$PBS_DEB" 2>/dev/null
            # data.tar may be .zst, .xz, or .gz compressed
            DATA_TAR=$(ls data.tar.* 2>/dev/null | head -1)
            if [ -n "$DATA_TAR" ]; then
                case "$DATA_TAR" in
                    *.zst) zstd -d "$DATA_TAR" -o data.tar 2>/dev/null || true ;;
                    *.xz)  xz -d "$DATA_TAR" 2>/dev/null || true ;;
                    *.gz)  gzip -d "$DATA_TAR" 2>/dev/null || true ;;
                esac
                if [ -f data.tar ]; then
                    tar xf data.tar ./usr/bin/proxmox-backup-client 2>/dev/null && \
                        cp -f usr/bin/proxmox-backup-client /usr/local/bin/proxmox-backup-client && \
                        chmod +x /usr/local/bin/proxmox-backup-client && \
                        echo "✓ proxmox-backup-client installed to /usr/local/bin/"
                else
                    echo "⚠ Failed to decompress PBS package data."
                fi
            else
                echo "⚠ Could not find data archive in PBS .deb package."
            fi
            cd - > /dev/null
        else
            echo "⚠ Failed to download PBS package."
        fi
    else
        echo "⚠ Could not find proxmox-backup-client .deb for architecture: $ARCH"
        echo "  PBS integration will not be available. Install manually if needed."
    fi
    rm -rf "$PBS_TMP"
fi

# ─── Configure FUSE for storage mounts ──────────────────────────────────────
# Enable allow_other in FUSE (needed for s3fs mounts accessible by containers)
if [ -f /etc/fuse.conf ]; then
    if ! grep -q "^user_allow_other" /etc/fuse.conf; then
        echo "user_allow_other" >> /etc/fuse.conf
    fi
fi

# Create storage directories
# rust-s3 syncs bucket contents to /var/cache/wolfstack/s3/<mount-id>/
mkdir -p /etc/wolfstack/s3 /etc/wolfstack/pbs /mnt/wolfstack /var/cache/wolfstack/s3
echo "✓ Storage directories configured"

# ─── Install Docker if missing ──────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    echo ""
    echo "Installing Docker..."
    if curl -fsSL https://get.docker.com | sh; then
        systemctl enable docker 2>/dev/null || true
        systemctl start docker 2>/dev/null || true
        echo "✓ Docker installed"
    else
        echo "⚠ Failed to install Docker automatically. Please install manually."
    fi
else
    echo "✓ Docker already installed"
fi

# ─── Install WolfNet (cluster network layer) ────────────────────────────────
echo ""
echo "Checking WolfNet (cluster networking)..."

if command -v wolfnet &> /dev/null && systemctl is-active --quiet wolfnet 2>/dev/null; then
    # Already installed and running — check for upgrades
    echo "✓ WolfNet already installed and running"
    WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "")
    if [ -n "$WOLFNET_IP" ]; then
        echo "  WolfNet IP: $WOLFNET_IP"
    fi

    # Always update WolfNet when WolfStack updates
    WOLFNET_SRC_DIR="${CUSTOM_INSTALL_DIR:-/opt}/wolfnet-src"
    if [ ! -d "$WOLFNET_SRC_DIR" ]; then
        echo "  WolfNet source not found — cloning..."
        git clone https://github.com/wolfsoftwaresystemsltd/WolfNet.git "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
    fi

    echo "  Updating WolfNet..."
    cd "$WOLFNET_SRC_DIR"
    git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
    git fetch origin 2>&1 || true
    git reset --hard origin/main 2>&1 || true

    # If the existing source dir is a WolfScale clone (old layout), replace it
    if [ -f "$WOLFNET_SRC_DIR/Cargo.toml" ] && ! grep -q 'name = "wolfnet"' "$WOLFNET_SRC_DIR/Cargo.toml"; then
        echo "  Replacing old WolfScale clone with standalone WolfNet repo..."
        rm -rf "$WOLFNET_SRC_DIR"
        git clone https://github.com/wolfsoftwaresystemsltd/WolfNet.git "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
    fi

    # Rebuild
    export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:/usr/local/bin:/usr/bin:$PATH"
    if command -v cargo &> /dev/null; then
        cd "$WOLFNET_SRC_DIR"
        if [ -n "$CUSTOM_INSTALL_DIR" ]; then
            chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR" "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" 2>/dev/null || true
            if [ "$REAL_USER" != "root" ]; then
                su - "$REAL_USER" -c "export CARGO_HOME='$CARGO_HOME' RUSTUP_HOME='$RUSTUP_HOME' TMPDIR='$TMPDIR' PATH='$CARGO_HOME/bin:/usr/local/bin:/usr/bin:\$PATH' && cd $WOLFNET_SRC_DIR && cargo build --release"
            else
                cargo build --release
            fi
        elif [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
            chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR"
            su - "$REAL_USER" -c "cd $WOLFNET_SRC_DIR && $REAL_HOME/.cargo/bin/cargo build --release"
        else
            cargo build --release
        fi

        # Install updated binaries
        systemctl stop wolfnet 2>/dev/null || true
        cp "$WOLFNET_SRC_DIR/target/release/wolfnet" /usr/local/bin/wolfnet
        chmod +x /usr/local/bin/wolfnet
        if [ -f "$WOLFNET_SRC_DIR/target/release/wolfnetctl" ]; then
            cp "$WOLFNET_SRC_DIR/target/release/wolfnetctl" /usr/local/bin/wolfnetctl
            chmod +x /usr/local/bin/wolfnetctl
        fi
        systemctl start wolfnet 2>/dev/null || true
        echo "  ✓ WolfNet updated and restarted"
    else
        echo "  ⚠ Cargo not found — skipping WolfNet rebuild"
    fi

elif command -v wolfnet &> /dev/null && [ -f "/etc/systemd/system/wolfnet.service" ]; then
    # Installed but not running — check for upgrades, then start
    echo "✓ WolfNet installed (not running)"

    # Always update WolfNet when WolfStack updates
    WOLFNET_SRC_DIR="${CUSTOM_INSTALL_DIR:-/opt}/wolfnet-src"
    if [ ! -d "$WOLFNET_SRC_DIR" ]; then
        echo "  WolfNet source not found — cloning..."
        git clone https://github.com/wolfsoftwaresystemsltd/WolfNet.git "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
    fi

    echo "  Updating WolfNet..."
    cd "$WOLFNET_SRC_DIR"
    git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
    git fetch origin 2>&1 || true
    git reset --hard origin/main 2>&1 || true

    # If the existing source dir is a WolfScale clone (old layout), replace it
    if [ -f "$WOLFNET_SRC_DIR/Cargo.toml" ] && ! grep -q 'name = "wolfnet"' "$WOLFNET_SRC_DIR/Cargo.toml"; then
        echo "  Replacing old WolfScale clone with standalone WolfNet repo..."
        rm -rf "$WOLFNET_SRC_DIR"
        git clone https://github.com/wolfsoftwaresystemsltd/WolfNet.git "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
    fi

    export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:/usr/local/bin:/usr/bin:$PATH"
    if command -v cargo &> /dev/null; then
        cd "$WOLFNET_SRC_DIR"
        if [ -n "$CUSTOM_INSTALL_DIR" ]; then
            chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR" "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" 2>/dev/null || true
            if [ "$REAL_USER" != "root" ]; then
                su - "$REAL_USER" -c "export CARGO_HOME='$CARGO_HOME' RUSTUP_HOME='$RUSTUP_HOME' TMPDIR='$TMPDIR' PATH='$CARGO_HOME/bin:/usr/local/bin:/usr/bin:\$PATH' && cd $WOLFNET_SRC_DIR && cargo build --release"
            else
                cargo build --release
            fi
        elif [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
            chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR"
            su - "$REAL_USER" -c "cd $WOLFNET_SRC_DIR && $REAL_HOME/.cargo/bin/cargo build --release"
        else
            cargo build --release
        fi
        cp "$WOLFNET_SRC_DIR/target/release/wolfnet" /usr/local/bin/wolfnet
        chmod +x /usr/local/bin/wolfnet
        if [ -f "$WOLFNET_SRC_DIR/target/release/wolfnetctl" ]; then
            cp "$WOLFNET_SRC_DIR/target/release/wolfnetctl" /usr/local/bin/wolfnetctl
            chmod +x /usr/local/bin/wolfnetctl
        fi
        echo "  ✓ WolfNet updated"
    else
        echo "  ⚠ Cargo not found — skipping WolfNet rebuild"
    fi

    echo "  Starting WolfNet..."
    systemctl start wolfnet 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet wolfnet; then
        WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "")
        echo "  ✓ WolfNet started. IP: ${WOLFNET_IP:-unknown}"
    else
        echo "  ⚠ WolfNet failed to start. Check: journalctl -u wolfnet -n 20"
    fi

else
    # WolfNet NOT installed — must install it
    echo "  WolfNet not found — installing for cluster networking..."
    echo ""

    # WolfNet needs /dev/net/tun
    SKIP_WOLFNET=false
    if [ ! -e /dev/net/tun ]; then
        echo ""
        echo "  ⚠  /dev/net/tun is NOT available!"
        echo "  ─────────────────────────────────────"
        echo ""
        echo "  This is almost certainly a Proxmox LXC container."
        echo "  WolfNet needs TUN/TAP to create its network overlay."
        echo ""
        echo "  To fix this, run the following on the Proxmox HOST (not inside the container):"
        echo ""
        echo "  1. Edit the container config:"
        echo "     nano /etc/pve/lxc/<CTID>.conf"
        echo ""
        echo "  2. Add these lines:"
        echo "     lxc.cgroup2.devices.allow: c 10:200 rwm"
        echo "     lxc.mount.entry: /dev/net dev/net none bind,create=dir"
        echo ""
        echo "  3. Restart the container:"
        echo "     pct restart <CTID>"
        echo ""
        echo "  4. Inside the container, create the device if needed:"
        echo "     mkdir -p /dev/net"
        echo "     mknod /dev/net/tun c 10 200"
        echo "     chmod 666 /dev/net/tun"
        echo ""
        echo "  Then re-run this installer."
        echo ""
        echo "  ✗ Cannot continue without WolfNet. Fix /dev/net/tun and re-run."
        exit 1
    fi

    # Download WolfNet source
    echo "  Downloading WolfNet..."
    WOLFNET_SRC_DIR="${CUSTOM_INSTALL_DIR:-/opt}/wolfnet-src"
    if [ -d "$WOLFNET_SRC_DIR" ]; then
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
        cd "$WOLFNET_SRC_DIR" && git fetch origin && git reset --hard origin/main
    else
        git clone https://github.com/wolfsoftwaresystemsltd/WolfNet.git "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
        cd "$WOLFNET_SRC_DIR"
    fi

    # Ensure Rust is available for building WolfNet
    export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:/usr/local/bin:/usr/bin:$PATH"

    if ! command -v cargo &> /dev/null; then
        echo "  Installing Rust first..."
        if [ -n "$CUSTOM_INSTALL_DIR" ] || [ "$REAL_USER" = "root" ]; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        else
            su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        fi
        export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:$PATH"
    fi

    # Build WolfNet
    echo "  Building WolfNet..."
    cd "$WOLFNET_SRC_DIR"
    if [ -n "$CUSTOM_INSTALL_DIR" ]; then
        chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR" "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" 2>/dev/null || true
        if [ "$REAL_USER" != "root" ]; then
            su - "$REAL_USER" -c "export CARGO_HOME='$CARGO_HOME' RUSTUP_HOME='$RUSTUP_HOME' TMPDIR='$TMPDIR' PATH='$CARGO_HOME/bin:/usr/local/bin:/usr/bin:\$PATH' && cd $WOLFNET_SRC_DIR && cargo build --release"
        else
            cargo build --release
        fi
    elif [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
        chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR"
        su - "$REAL_USER" -c "cd $WOLFNET_SRC_DIR && $REAL_HOME/.cargo/bin/cargo build --release"
    else
        cargo build --release
    fi

    # Install binaries
    cp "$WOLFNET_SRC_DIR/target/release/wolfnet" /usr/local/bin/wolfnet
    chmod +x /usr/local/bin/wolfnet
    if [ -f "$WOLFNET_SRC_DIR/target/release/wolfnetctl" ]; then
        cp "$WOLFNET_SRC_DIR/target/release/wolfnetctl" /usr/local/bin/wolfnetctl
        chmod +x /usr/local/bin/wolfnetctl
    fi
    echo "  ✓ WolfNet binary installed"

    # Configure WolfNet for cluster use
    mkdir -p /etc/wolfnet /var/run/wolfnet

    if [ ! -f "/etc/wolfnet/config.toml" ]; then
        # Auto-assign a cluster IP based on the last octet of the host IP
        HOST_IP=$(hostname -I | awk '{print $1}')
        LAST_OCTET=$(echo "$HOST_IP" | awk -F. '{print $4}')
        # Ensure last octet is valid (1-254); default to 1 if detection fails
        if [ -z "$LAST_OCTET" ] || [ "$LAST_OCTET" -lt 1 ] 2>/dev/null || [ "$LAST_OCTET" -gt 254 ] 2>/dev/null; then
            LAST_OCTET=1
        fi

        # Find a /24 subnet that doesn't conflict with existing networks
        # Preferred: 10.10.10.0/24, fallback: 10.10.20.0/24, 10.10.30.0/24, etc.
        WOLFNET_SUBNET=""
        for THIRD_OCTET in 10 20 30 40 50 60 70 80 90; do
            CANDIDATE="10.10.${THIRD_OCTET}.0/24"
            # Check if this subnet is already routed or has addresses assigned
            if ! ip route show 2>/dev/null | grep -q "10.10.${THIRD_OCTET}\." && \
               ! ip addr show 2>/dev/null | grep -q "10.10.${THIRD_OCTET}\."; then
                WOLFNET_SUBNET="10.10.${THIRD_OCTET}"
                break
            fi
            echo "  ⚠ Subnet $CANDIDATE already in use, trying next..."
        done

        if [ -z "$WOLFNET_SUBNET" ]; then
            echo "  ✗ Could not find a free 10.10.x.0/24 subnet!"
            echo "  Please configure WolfNet manually: /etc/wolfnet/config.toml"
            WOLFNET_SUBNET="10.10.10"  # fallback anyway
        fi

        # Check the candidate IP isn't already taken by another node
        # (e.g. two servers with the same last octet on different subnets)
        WOLFNET_IP="${WOLFNET_SUBNET}.${LAST_OCTET}"
        TRIES=0
        while [ $TRIES -lt 253 ]; do
            # Quick ping check — if nobody responds, it's free
            if ! ping -c 1 -W 1 "$WOLFNET_IP" &>/dev/null; then
                break
            fi
            echo "  ⚠ ${WOLFNET_IP} already in use, trying next..."
            LAST_OCTET=$(( (LAST_OCTET % 254) + 1 ))
            WOLFNET_IP="${WOLFNET_SUBNET}.${LAST_OCTET}"
            TRIES=$((TRIES + 1))
        done

        # Ask about LAN auto-discovery
        echo ""
        echo "  ──────────────────────────────────────────────────"
        echo "  LAN Auto-Discovery"
        echo "  ──────────────────────────────────────────────────"
        echo ""
        echo "  WolfNet can broadcast discovery packets on your local"
        echo "  network to automatically find other WolfNet nodes."
        echo ""
        echo "  ⚠  Do NOT enable on public/datacenter networks!"
        echo "     (Proxmox VLANs, Hetzner, OVH, etc.)"
        echo "     Only enable on private LANs (home, office)."
        echo ""
        echo -n "Enable LAN auto-discovery? [y/N]: "
        prompt_read ENABLE_DISCOVERY
        if [ "$ENABLE_DISCOVERY" = "y" ] || [ "$ENABLE_DISCOVERY" = "Y" ]; then
            WOLFNET_DISCOVERY="true"
        else
            WOLFNET_DISCOVERY="false"
        fi

        # Generate keys
        KEY_FILE="/etc/wolfnet/private.key"
        /usr/local/bin/wolfnet genkey --output "$KEY_FILE" 2>/dev/null || true

        cat <<EOF > /etc/wolfnet/config.toml
# WolfNet Configuration
# Auto-generated by WolfStack installer
# Provides cluster overlay network

[network]
interface = "wolfnet0"
address = "$WOLFNET_IP"
subnet = 24
listen_port = 9600
gateway = false
discovery = $WOLFNET_DISCOVERY
mtu = 1400

[security]
private_key_file = "$KEY_FILE"

# Peers will be added automatically when you add servers to WolfStack
EOF
        echo "  ✓ WolfNet configured: $WOLFNET_IP/24 (subnet: ${WOLFNET_SUBNET}.0/24)"
        if [ "$WOLFNET_DISCOVERY" = "false" ]; then
            echo "  ℹ  Discovery disabled. You can enable it later in WolfStack → WolfNet → Network Settings."
        fi
    fi

    # Create systemd service
    if [ ! -f "/etc/systemd/system/wolfnet.service" ]; then
        cat > /etc/systemd/system/wolfnet.service <<EOF
[Unit]
Description=WolfNet - Secure Private Mesh Networking
Before=wolfstack.service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wolfnet --config /etc/wolfnet/config.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
DeviceAllow=/dev/net/tun rw
RuntimeDirectory=wolfnet
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi

    systemctl enable wolfnet 2>/dev/null || true
    systemctl start wolfnet 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet wolfnet; then
        WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "${WOLFNET_IP:-unknown}")
        echo "  ✓ WolfNet running! Cluster IP: $WOLFNET_IP"
    else
        echo "  ⚠ WolfNet may not have started. Check: journalctl -u wolfnet -n 20"
    fi
fi


# ─── Install Rust if not present ────────────────────────────────────────────
CARGO_BIN="${CARGO_HOME:-$REAL_HOME/.cargo}/bin/cargo"

if [ -f "$CARGO_BIN" ]; then
    echo "✓ Rust already installed"
elif command -v cargo &> /dev/null; then
    CARGO_BIN="$(command -v cargo)"
    echo "✓ Rust already installed (system-wide)"
else
    echo ""
    if [ -n "$CUSTOM_INSTALL_DIR" ]; then
        echo "Installing Rust to $CUSTOM_INSTALL_DIR..."
    else
        echo "Installing Rust for user '$REAL_USER'..."
    fi
    if [ -n "$CUSTOM_INSTALL_DIR" ] || [ "$REAL_USER" = "root" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    else
        su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    fi
    echo "✓ Rust installed"
fi

# Ensure cargo is found
export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:/usr/local/bin:/usr/bin:$PATH"

if ! command -v cargo &> /dev/null; then
    echo "✗ cargo not found after installation. Check Rust install."
    exit 1
fi

echo "✓ Using cargo: $(command -v cargo)"

# ─── Clone or update repository ─────────────────────────────────────────────
INSTALL_DIR="${CUSTOM_INSTALL_DIR:-/opt}/wolfstack-src"
if [ -n "$CUSTOM_INSTALL_DIR" ]; then
    export CARGO_TARGET_DIR="$CUSTOM_INSTALL_DIR/wolfstack-target"
    mkdir -p "$CARGO_TARGET_DIR"
    chown -R "$REAL_USER:$REAL_USER" "$CARGO_TARGET_DIR" 2>/dev/null || true
    echo ""
    echo "  External drive build paths:"
    echo "    Source:    $INSTALL_DIR"
    echo "    Target:    $CARGO_TARGET_DIR"
    echo "    Cargo:     $CARGO_HOME"
    echo "    Rustup:    $RUSTUP_HOME"
    echo "    Tmpdir:    $TMPDIR"
fi
echo ""
echo "Cloning WolfStack repository..."

if [ -d "$INSTALL_DIR" ]; then
    echo "  Updating existing installation..."
    cd "$INSTALL_DIR"
    git fetch origin
    git checkout -B $BRANCH origin/$BRANCH
    git reset --hard origin/$BRANCH
else
    git clone -b $BRANCH https://github.com/wolfsoftwaresystemsltd/WolfStack.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Show what we're building
BUILT_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "✓ Repository ready ($INSTALL_DIR)"
echo "  Branch: $BRANCH | Version: $BUILT_VERSION"

# Force full rebuild to ensure the new version takes effect
echo "  Cleaning previous build..."
CLEAN_TARGET="${CARGO_TARGET_DIR:-$INSTALL_DIR/target}"
rm -rf "$CLEAN_TARGET/release/wolfstack" "$CLEAN_TARGET/release/.fingerprint/wolfstack-"*

# ─── Build WolfStack ────────────────────────────────────────────────────────
echo ""
echo "Building WolfStack (this may take a few minutes)..."

# Low-memory systems (< 4GB): create swap and limit parallelism to avoid OOM
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
TOTAL_AVAILABLE_KB=$((TOTAL_MEM_KB + TOTAL_SWAP_KB))
CARGO_JOBS=""
CREATED_SWAP=""

if [ "$TOTAL_AVAILABLE_KB" -lt 4000000 ]; then
    echo "  Low memory detected ($(( TOTAL_MEM_KB / 1024 ))MB RAM + $(( TOTAL_SWAP_KB / 1024 ))MB swap)"
    CARGO_JOBS="-j 1"

    # Create a temporary swap file if total memory + swap < 4GB
    SWAP_DIR="${CUSTOM_INSTALL_DIR:-/var}"
    SWAP_FILE="$SWAP_DIR/.wolfstack-build-swap"
    NEEDED_SWAP_MB=$(( (4000000 - TOTAL_AVAILABLE_KB) / 1024 + 512 ))
    if [ "$NEEDED_SWAP_MB" -gt 4096 ]; then
        NEEDED_SWAP_MB=4096
    fi

    echo "  Creating ${NEEDED_SWAP_MB}MB temporary swap file for build..."
    dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$NEEDED_SWAP_MB" status=none 2>/dev/null && \
    chmod 600 "$SWAP_FILE" && \
    mkswap "$SWAP_FILE" >/dev/null 2>&1 && \
    swapon "$SWAP_FILE" 2>/dev/null && \
    CREATED_SWAP="$SWAP_FILE" && \
    echo "  ✓ Temporary swap enabled" || \
    echo "  ⚠ Could not create swap file (build may be slow or fail)"
fi

if [ -n "$CUSTOM_INSTALL_DIR" ]; then
    # Custom install dir — all build I/O goes to external drive
    chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR" "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" "$CARGO_TARGET_DIR" 2>/dev/null || true
    if [ "$REAL_USER" != "root" ]; then
        su - "$REAL_USER" -c "export CARGO_HOME='$CARGO_HOME' RUSTUP_HOME='$RUSTUP_HOME' TMPDIR='$TMPDIR' CARGO_TARGET_DIR='$CARGO_TARGET_DIR' PATH='$CARGO_HOME/bin:/usr/local/bin:/usr/bin:\$PATH' && cd $INSTALL_DIR && cargo build --release $CARGO_JOBS"
    else
        cargo build --release $CARGO_JOBS
    fi
elif [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
    chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR"
    su - "$REAL_USER" -c "cd $INSTALL_DIR && $REAL_HOME/.cargo/bin/cargo build --release $CARGO_JOBS"
else
    cargo build --release $CARGO_JOBS
fi

# Clean up temporary swap file
if [ -n "$CREATED_SWAP" ]; then
    swapoff "$CREATED_SWAP" 2>/dev/null
    rm -f "$CREATED_SWAP"
    echo "  ✓ Temporary swap removed"
fi

echo "✓ Build complete"

# ─── Flag restart if service is running (for upgrades) ───────────────────────
if systemctl is-active --quiet wolfstack 2>/dev/null; then
    echo ""
    echo "WolfStack service is running — will restart after upgrade."
    RESTART_SERVICE=true
else
    RESTART_SERVICE=false
fi

# ─── Install binary ─────────────────────────────────────────────────────────
echo ""
if [ -f "/usr/local/bin/wolfstack" ]; then
    echo "Upgrading WolfStack..."
    rm -f /usr/local/bin/wolfstack
else
    echo "Installing WolfStack..."
fi

BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-$INSTALL_DIR/target}"
cp "$BUILD_TARGET_DIR/release/wolfstack" /usr/local/bin/wolfstack
chmod +x /usr/local/bin/wolfstack
echo "✓ wolfstack installed to /usr/local/bin/wolfstack"

# ─── Install web UI ─────────────────────────────────────────────────────────
echo ""
echo "Installing web UI..."
mkdir -p /opt/wolfstack/web
cp -r "$INSTALL_DIR/web/"* /opt/wolfstack/web/
echo "✓ Web UI installed to /opt/wolfstack/web"

# ─── Configuration ──────────────────────────────────────────────────────────
if [ ! -f "/etc/wolfstack/config.toml" ]; then
    echo ""
    echo "  ──────────────────────────────────────────────────"
    echo "  WolfStack Configuration"
    echo "  ──────────────────────────────────────────────────"
    echo ""

    # Prompt for port
    echo -n "Dashboard port [8553]: "
    prompt_read WS_PORT
    WS_PORT=${WS_PORT:-8553}

    # Prompt for bind address
    echo -n "Bind address [0.0.0.0]: "
    prompt_read WS_BIND
    WS_BIND=${WS_BIND:-0.0.0.0}

    # Write config
    mkdir -p /etc/wolfstack
    cat <<EOF > /etc/wolfstack/config.toml
# WolfStack Configuration
# Generated by setup.sh

[server]
port = $WS_PORT
bind = "$WS_BIND"
web_dir = "/opt/wolfstack/web"
EOF
    echo "✓ Config created at /etc/wolfstack/config.toml"
    echo ""
    echo "  Dashboard: http://$WS_BIND:$WS_PORT"
else
    echo ""
    echo "✓ Config already exists at /etc/wolfstack/config.toml"
    echo "  (Upgrade mode - skipping configuration prompts)"
    # Read port from existing config
    WS_PORT=$(grep "port" /etc/wolfstack/config.toml 2>/dev/null | head -1 | awk '{print $3}' || echo "8553")
fi

# ─── Create systemd service ─────────────────────────────────────────────────
if [ ! -f "/etc/systemd/system/wolfstack.service" ]; then
    echo ""
    echo "  ──────────────────────────────────────────────────"
    echo "  Creating systemd service..."
    echo "  ──────────────────────────────────────────────────"
    echo ""

    cat > /etc/systemd/system/wolfstack.service <<EOF
[Unit]
Description=WolfStack - Server Management Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wolfstack --port $WS_PORT --bind $WS_BIND
WorkingDirectory=/opt/wolfstack
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Must run as root for Linux auth and service management
User=root
Group=root

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wolfstack

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "✓ Systemd service created"

    # Enable and optionally start
    echo ""
    echo -n "Start WolfStack now? [Y/n]: "
    prompt_read start_now
    if [ "$start_now" != "n" ] && [ "$start_now" != "N" ]; then
        systemctl enable wolfstack
        systemctl start wolfstack
        sleep 2
        if systemctl is-active --quiet wolfstack; then
            echo "✓ WolfStack is running!"
        else
            echo "⚠ WolfStack may have failed to start. Check: journalctl -u wolfstack -n 20"
        fi
    else
        systemctl enable wolfstack
        echo "✓ WolfStack enabled (will start on boot)"
    fi
else
    echo ""
    echo "✓ Service already installed - reloading systemd"
    systemctl daemon-reload
fi

# ─── Firewall ───────────────────────────────────────────────────────────────
echo ""
if command -v ufw &> /dev/null; then
    ufw allow "$WS_PORT/tcp" 2>/dev/null && echo "✓ Firewall: Opened port $WS_PORT/tcp (ufw)" || true
    ufw allow 9600/udp 2>/dev/null && echo "✓ Firewall: Opened port 9600/udp for WolfNet (ufw)" || true
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port="$WS_PORT/tcp" 2>/dev/null && \
    firewall-cmd --permanent --add-port="9600/udp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    echo "✓ Firewall: Opened port $WS_PORT/tcp and 9600/udp (firewalld)" || true
fi

# ─── Set up lxcbr0 bridge for LXC containers ────────────────────────────────
if command -v lxc-ls &> /dev/null; then
    # Only configure lxc-net on fresh installs — restarting lxc-net on upgrades
    # destroys lxcbr0 and all container kernel routes, breaking WolfNet routing.
    # WolfStack's reapply_wolfnet_routes() handles route restoration on startup.
    if ip link show lxcbr0 &>/dev/null && ip -4 addr show lxcbr0 2>/dev/null | grep -q "inet "; then
        echo "✓ LXC networking already active (lxcbr0 up)"
    else
        echo ""
        echo "Configuring LXC networking (lxc-net)..."
        
        # Ensure USE_LXC_BRIDGE="true" in /etc/default/lxc-net
        if [ -f "/etc/default/lxc-net" ]; then
            if grep -q "USE_LXC_BRIDGE" /etc/default/lxc-net; then
                sed -i 's/^#\?USE_LXC_BRIDGE=.*/USE_LXC_BRIDGE="true"/' /etc/default/lxc-net
            else
                echo 'USE_LXC_BRIDGE="true"' >> /etc/default/lxc-net
            fi
        else
            echo 'USE_LXC_BRIDGE="true"' > /etc/default/lxc-net
        fi

        # Enable and start lxc-net service
        systemctl enable lxc-net 2>/dev/null || true
        systemctl restart lxc-net 2>/dev/null || true
        
        # Check if dnsmasq is running on lxcbr0
        sleep 2
        if pgrep -f "dnsmasq.*lxcbr0" > /dev/null; then
            echo "✓ LXC networking active (lxcbr0 + dnsmasq)"
        else
            echo "⚠ LXC networking service started but dnsmasq not detected on lxcbr0."
            echo "  Attempting manual fallback..."
            systemctl stop lxc-net 2>/dev/null || true
            
            ip link add lxcbr0 type bridge 2>/dev/null || true
            ip addr add 10.0.3.1/24 dev lxcbr0 2>/dev/null || true
            ip link set lxcbr0 up 2>/dev/null || true
            
            # NAT
            echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
            iptables -t nat -A POSTROUTING -s 10.0.3.0/24 ! -d 10.0.3.0/24 -j MASQUERADE 2>/dev/null || true
            iptables -A FORWARD -i lxcbr0 -j ACCEPT 2>/dev/null || true
            iptables -A FORWARD -o lxcbr0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
            
            # DNSMasq
            mkdir -p /run/lxc
            dnsmasq --strict-order --bind-interfaces --pid-file=/run/lxc/dnsmasq.pid \
                --listen-address 10.0.3.1 --dhcp-range 10.0.3.2,10.0.3.254 \
                --dhcp-lease-max=253 --dhcp-no-override --except-interface=lo \
                --interface=lxcbr0 --conf-file= 2>/dev/null || true
                
            echo "✓ Manually configured lxcbr0 and dnsmasq"
        fi
    fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "  🐺 Installation Complete!"
echo "  ─────────────────────────────────────"
echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):${WS_PORT}"
echo "  Login:      Use your Linux system username and password"
echo ""
echo "  Manage:"
echo "  Status:     sudo systemctl status wolfstack"
echo "  Logs:       sudo journalctl -u wolfstack -f"
echo "  Restart:    sudo systemctl restart wolfstack"
echo "  Config:     /etc/wolfstack/config.toml"
echo ""
echo "**** UPGRADE COMPLETE ****"
echo ""
echo "Please Refresh your browser if upgrading..."

# ─── Restart service if upgrading (must be last!) ────────────────────────────
if [ "$RESTART_SERVICE" = "true" ]; then
    nohup bash -c "sleep 3 && systemctl restart wolfstack" &>/dev/null &
fi
