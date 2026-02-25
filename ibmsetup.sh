#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack IBM Power (ppc64le) Complete Installer
# Full standalone installer for IBM POWER9/POWER10 servers running RHEL.
# This replaces setup.sh on IBM Power — handles everything:
#   - System dependencies (with correct ppc64le / RHEL 10 package names)
#   - IBM Power hardware tools, diagnostics & firmware checks
#   - Performance tuning (SMT, NUMA, sysctl, tuned)
#   - Container runtime (Docker/Podman)
#   - WolfNet cluster networking
#   - Rust toolchain
#   - WolfStack build, install & systemd service
#
# Usage: curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/ibmsetup.sh | sudo bash
#        sudo bash ibmsetup.sh
#        sudo bash ibmsetup.sh --beta
#        sudo bash ibmsetup.sh --skip-tuning
#        sudo bash ibmsetup.sh --skip-firmware
#

set -e

# ─── Parse arguments ─────────────────────────────────────────────────────────
BRANCH="master"
SKIP_TUNING=false
SKIP_FIRMWARE=false
for arg in "$@"; do
    case "$arg" in
        --beta)          BRANCH="beta" ;;
        --skip-tuning)   SKIP_TUNING=true ;;
        --skip-firmware) SKIP_FIRMWARE=true ;;
        --help|-h)
            echo "Usage: sudo bash ibmsetup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --beta           Install from beta branch"
            echo "  --skip-tuning    Skip performance tuning (SMT, sysctl, tuned)"
            echo "  --skip-firmware  Skip firmware version checks"
            echo "  --help, -h       Show this help"
            exit 0
            ;;
    esac
done

# Allow git to operate on repos owned by other users
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="*"

echo ""
echo "  WolfStack IBM Power Installer"
echo "  ─────────────────────────────────────"
echo "  Complete installer for POWER9/POWER10"
echo "  RHEL (ppc64le)"
if [ "$BRANCH" != "master" ]; then
    echo "  Branch: $BRANCH"
fi
echo ""

# ─── Must run as root ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    echo "  Usage: sudo bash ibmsetup.sh"
    exit 1
fi

# Detect the real user (for Rust install) when running under sudo
REAL_USER="${SUDO_USER:-root}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ─── Architecture check ─────────────────────────────────────────────────────
ARCH=$(uname -m)
if [ "$ARCH" != "ppc64le" ] && [ "$ARCH" != "ppc64" ]; then
    echo "This script is for IBM Power (ppc64le) systems only."
    echo "  Detected architecture: $ARCH"
    echo "  Use setup.sh for x86_64/aarch64 systems."
    exit 1
fi
echo "Architecture: $ARCH"

# ─── Detect OS ───────────────────────────────────────────────────────────────
if [ -f /etc/redhat-release ]; then
    RHEL_VER=$(grep -oP '\d+' /etc/redhat-release | head -1)
    echo "OS: $(cat /etc/redhat-release)"
else
    RHEL_VER=""
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
fi

# ─── Detect package manager ─────────────────────────────────────────────────
if command -v dnf &> /dev/null; then
    PKG="dnf"
elif command -v yum &> /dev/null; then
    PKG="yum"
else
    echo "Could not detect dnf or yum. This script requires RHEL/CentOS/Fedora."
    exit 1
fi
echo "Package manager: $PKG"

# ─── Detect LPAR vs bare-metal ──────────────────────────────────────────────
IS_LPAR=false
LPAR_NAME=""
PROC_MODE=""
if [ -f /proc/ppc64/lparcfg ]; then
    IS_LPAR=true
    LPAR_NAME=$(grep "partition_name" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "unknown")
    SHARED_PROC=$(grep "shared_processor_mode" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")
    if [ "$SHARED_PROC" = "1" ]; then
        PROC_MODE="shared"
    else
        PROC_MODE="dedicated"
    fi
    echo "LPAR: $LPAR_NAME (${PROC_MODE} processors)"
else
    echo "Mode: bare-metal / PowerNV"
fi

echo ""

# ─── Enable RHEL repos for ppc64le ──────────────────────────────────────────
echo "Checking RHEL repositories..."

if command -v subscription-manager &> /dev/null; then
    if subscription-manager identity &>/dev/null; then
        if [ -n "$RHEL_VER" ]; then
            subscription-manager repos \
                --enable="rhel-${RHEL_VER}-for-ppc64le-baseos-rpms" \
                --enable="rhel-${RHEL_VER}-for-ppc64le-appstream-rpms" 2>/dev/null || true
            echo "  Enabled RHEL ${RHEL_VER} ppc64le repos"
        fi
    else
        echo "  System not registered with subscription-manager — skipping repo config"
    fi
else
    echo "  subscription-manager not found — using existing repos"
fi

echo ""

# ─── Install system dependencies (ppc64le / RHEL 10) ────────────────────────
# Many packages that setup.sh expects don't exist on RHEL 10 ppc64le:
#   lxc, lxc-templates, lxc-extra  — not packaged for RHEL ppc64le
#   bridge-utils                   — deprecated in RHEL 10 (iproute2 replaces brctl)
#   qemu-kvm                       — named differently on ppc64le
#   s3fs-fuse                      — not in standard RHEL repos
#   libxcrypt-devel                — may be libcrypt-devel on some versions
echo "Installing system dependencies for ppc64le..."

# Build toolchain (needed to compile WolfStack and WolfNet from source)
$PKG install -y \
    git \
    curl \
    gcc \
    gcc-c++ \
    make \
    openssl-devel \
    pkg-config \
    2>/dev/null || true

# libxcrypt-devel — try both names
if ! rpm -q libxcrypt-devel &>/dev/null && ! rpm -q libcrypt-devel &>/dev/null; then
    $PKG install -y libxcrypt-devel 2>/dev/null || \
    $PKG install -y libcrypt-devel 2>/dev/null || true
fi

# QEMU for ppc64le (package name differs from x86_64)
for qemu_pkg in qemu-system-ppc qemu-system-ppc-core qemu-kvm-core qemu-kvm; do
    if $PKG install -y "$qemu_pkg" 2>/dev/null; then
        echo "  Installed $qemu_pkg"
        break
    fi
done
$PKG install -y qemu-img 2>/dev/null || true

# Networking — bridge-utils is gone in RHEL 10, iproute2 handles bridges natively
for net_pkg in dnsmasq socat nftables firewalld iproute; do
    if ! rpm -q "$net_pkg" &>/dev/null; then
        $PKG install -y "$net_pkg" 2>/dev/null || true
    fi
done

# NFS and FUSE
$PKG install -y nfs-utils fuse3 fuse3-libs 2>/dev/null || true

# s3fs-fuse — try to install, often not in RHEL repos
if ! rpm -q s3fs-fuse &>/dev/null; then
    if ! $PKG install -y s3fs-fuse 2>/dev/null; then
        if ! rpm -q epel-release &>/dev/null; then
            $PKG install -y epel-release 2>/dev/null || true
        fi
        $PKG install -y s3fs-fuse 2>/dev/null || \
            echo "  s3fs-fuse not available — S3 mounts will use WolfStack's built-in rust-s3 sync"
    fi
fi

# LXC — not available on RHEL ppc64le
if ! command -v lxc-ls &> /dev/null; then
    echo "  LXC not available on RHEL ppc64le — Docker/Podman containers fully supported"
fi

echo "  System dependencies installed"
echo ""

# ─── Install IBM Power hardware tools ───────────────────────────────────────
echo "Installing IBM Power hardware tools..."

POWER_PKGS=(
    powerpc-utils
    ppc64-diag
    lsvpd
    librtas
    servicelog
    servicelog-notify
    iprutils
    src
)

INSTALLED=0
SKIPPED=0
for pkg in "${POWER_PKGS[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
        INSTALLED=$((INSTALLED + 1))
    else
        if $PKG install -y "$pkg" &>/dev/null; then
            INSTALLED=$((INSTALLED + 1))
        else
            SKIPPED=$((SKIPPED + 1))
            echo "  Could not install $pkg — skipping"
        fi
    fi
done
echo "  ${INSTALLED} Power packages installed, ${SKIPPED} skipped"

# RSCT (Reliable Scalable Cluster Technology) — needed for DLPAR operations
$PKG install -y rsct.core rsct.basic 2>/dev/null && \
    echo "  RSCT installed" || \
    echo "  RSCT not available — DLPAR operations may be limited"

echo ""

# ─── Install server management tools ────────────────────────────────────────
echo "Installing server management tools..."

$PKG install -y \
    numactl \
    tuned \
    sysstat \
    perf \
    net-tools \
    bind-utils \
    ethtool \
    lvm2 \
    device-mapper-multipath \
    sg3_utils \
    nvme-cli \
    chrony \
    tpm2-tools \
    irqbalance \
    2>/dev/null || true

echo "  Server tools installed"
echo ""

# ─── Enable Power-specific services ─────────────────────────────────────────
echo "Enabling IBM Power services..."

if [ -f /usr/sbin/rtas_errd ] || systemctl list-unit-files rtas_errd.service &>/dev/null; then
    systemctl enable rtas_errd 2>/dev/null && systemctl start rtas_errd 2>/dev/null && \
        echo "  rtas_errd (hardware error daemon) — running" || \
        echo "  rtas_errd — could not start"
fi

for svc in iprinit iprupdate iprdump; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null; then
        systemctl enable "$svc" 2>/dev/null && systemctl start "$svc" 2>/dev/null && \
            echo "  $svc — running" || true
    fi
done

if systemctl list-unit-files ctrmc.service &>/dev/null; then
    systemctl enable ctrmc 2>/dev/null && systemctl start ctrmc 2>/dev/null && \
        echo "  ctrmc (RSCT resource manager) — running" || true
fi

systemctl enable irqbalance 2>/dev/null && systemctl start irqbalance 2>/dev/null && \
    echo "  irqbalance — running" || true

echo ""

# ─── Rebuild VPD database ───────────────────────────────────────────────────
if command -v vpdupdate &> /dev/null; then
    echo "Rebuilding Vital Product Data database..."
    vpdupdate 2>/dev/null && echo "  VPD database updated" || echo "  VPD update skipped"
    echo ""
fi

# ─── Performance tuning ─────────────────────────────────────────────────────
if [ "$SKIP_TUNING" = false ]; then
    echo "Applying IBM Power performance tuning..."

    # SMT — default to SMT=4 (good balance of throughput vs per-thread performance)
    if command -v ppc64_cpu &> /dev/null; then
        CURRENT_SMT=$(ppc64_cpu --smt 2>/dev/null | grep -oP '\d+' || echo "?")
        echo "  Current SMT level: $CURRENT_SMT"

        if [ "$CURRENT_SMT" != "4" ] && [ "$CURRENT_SMT" != "8" ]; then
            ppc64_cpu --smt=4 2>/dev/null && \
                echo "  SMT set to 4 (balanced mode)" || \
                echo "  Could not set SMT level"
        else
            echo "  SMT level OK — no change needed"
        fi

        CORES=$(ppc64_cpu --cores-present 2>/dev/null | grep -oP '\d+' || echo "?")
        THREADS=$(ppc64_cpu --threads-per-core 2>/dev/null | grep -oP '\d+' || echo "?")
        echo "  Cores: $CORES, Threads/core: $THREADS"
    fi

    # tuned profile
    if command -v tuned-adm &> /dev/null; then
        systemctl enable tuned 2>/dev/null || true
        systemctl start tuned 2>/dev/null || true

        CURRENT_PROFILE=$(tuned-adm active 2>/dev/null | awk -F': ' '{print $2}' || echo "none")
        if [ "$CURRENT_PROFILE" != "throughput-performance" ]; then
            tuned-adm profile throughput-performance 2>/dev/null && \
                echo "  tuned profile: throughput-performance (was: $CURRENT_PROFILE)" || true
        else
            echo "  tuned profile: $CURRENT_PROFILE (OK)"
        fi
    fi

    # Sysctl tuning for Power
    SYSCTL_FILE="/etc/sysctl.d/99-wolfstack-power.conf"
    if [ ! -f "$SYSCTL_FILE" ]; then
        cat > "$SYSCTL_FILE" << 'EOF'
# WolfStack IBM Power performance tuning
# Generated by ibmsetup.sh

# Memory
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10

# NUMA balancing (important for multi-socket Power)
kernel.numa_balancing = 1

# Scheduler tuning for high core counts with SMT
kernel.sched_migration_cost_ns = 5000000
kernel.sched_min_granularity_ns = 10000000
kernel.sched_wakeup_granularity_ns = 15000000

# Network
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_forward = 1

# File descriptors
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
EOF
        sysctl --system &>/dev/null
        echo "  Sysctl tuning applied ($SYSCTL_FILE)"
    else
        echo "  Sysctl tuning already configured ($SYSCTL_FILE)"
    fi

    # Transparent huge pages (Power default page size is 64KB, THP uses 16MB)
    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
        echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
        echo "  Transparent huge pages: enabled"
    fi

    echo ""
fi

# ─── Multipath configuration ────────────────────────────────────────────────
echo "Checking multipath storage..."

if command -v multipathd &> /dev/null; then
    if multipath -ll 2>/dev/null | grep -q "mpath"; then
        systemctl enable multipathd 2>/dev/null || true
        systemctl start multipathd 2>/dev/null || true
        MPATH_COUNT=$(multipath -ll 2>/dev/null | grep -c "mpath" || echo "0")
        echo "  multipathd running — $MPATH_COUNT multipath device(s)"
    else
        echo "  No multipath devices detected — skipping multipathd"
    fi
else
    echo "  multipathd not installed — skipping"
fi
echo ""

# ─── Configure FUSE for storage mounts ───────────────────────────────────────
if [ -f /etc/fuse.conf ]; then
    if ! grep -q "^user_allow_other" /etc/fuse.conf; then
        echo "user_allow_other" >> /etc/fuse.conf
    fi
fi

# Create storage directories
mkdir -p /etc/wolfstack/s3 /etc/wolfstack/pbs /mnt/wolfstack /var/cache/wolfstack/s3
echo "  Storage directories configured"

# ─── Install Docker ──────────────────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    echo ""
    echo "Installing Docker..."
    if curl -fsSL https://get.docker.com | sh; then
        systemctl enable docker 2>/dev/null || true
        systemctl start docker 2>/dev/null || true
        echo "  Docker installed"
    else
        # Fallback to Podman with Docker compatibility
        echo "  Docker installer failed — installing Podman instead..."
        $PKG install -y podman podman-docker buildah skopeo containernetworking-plugins 2>/dev/null || true
        if command -v podman &> /dev/null; then
            systemctl enable podman.socket 2>/dev/null || true
            systemctl start podman.socket 2>/dev/null || true
            echo "  Podman installed with Docker compatibility"
        else
            echo "  Could not install container runtime — install Docker or Podman manually"
        fi
    fi
else
    echo "  Docker already installed"
fi

echo ""
echo "  NOTE: On ppc64le, container images must be built for ppc64le or"
echo "  be multi-arch. Red Hat UBI images (registry.access.redhat.com/ubi9/*)"
echo "  are recommended as they provide full ppc64le support."
echo ""

# ─── Install WolfNet (cluster network layer) ────────────────────────────────
echo "Checking WolfNet (cluster networking)..."

if command -v wolfnet &> /dev/null && systemctl is-active --quiet wolfnet 2>/dev/null; then
    echo "  WolfNet already installed and running"
    WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "")
    if [ -n "$WOLFNET_IP" ]; then
        echo "  WolfNet IP: $WOLFNET_IP"
    fi

    # Update WolfNet
    WOLFNET_SRC_DIR="/opt/wolfnet-src"
    if [ -d "$WOLFNET_SRC_DIR" ]; then
        echo "  Updating WolfNet..."
        cd "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
        git fetch origin 2>&1 || true
        git reset --hard origin/main 2>&1 || true

        if [ ! -d "$WOLFNET_SRC_DIR/wolfnet" ]; then
            echo "  wolfnet subdirectory missing — re-cloning..."
            cd /tmp
            rm -rf "$WOLFNET_SRC_DIR"
            git clone https://github.com/wolfsoftwaresystemsltd/WolfScale.git "$WOLFNET_SRC_DIR"
            git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
            cd "$WOLFNET_SRC_DIR"
        fi

        export PATH="$REAL_HOME/.cargo/bin:/usr/local/bin:/usr/bin:$PATH"
        if command -v cargo &> /dev/null; then
            cd "$WOLFNET_SRC_DIR/wolfnet"
            if [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
                chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR"
                su - "$REAL_USER" -c "cd $WOLFNET_SRC_DIR/wolfnet && $REAL_HOME/.cargo/bin/cargo build --release"
            else
                cargo build --release
            fi

            systemctl stop wolfnet 2>/dev/null || true
            cp "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnet" /usr/local/bin/wolfnet
            chmod +x /usr/local/bin/wolfnet
            if [ -f "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnetctl" ]; then
                cp "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnetctl" /usr/local/bin/wolfnetctl
                chmod +x /usr/local/bin/wolfnetctl
            fi
            systemctl start wolfnet 2>/dev/null || true
            echo "  WolfNet updated and restarted"
        else
            echo "  Cargo not found — skipping WolfNet rebuild"
        fi
    fi

elif command -v wolfnet &> /dev/null; then
    echo "  WolfNet installed (not running)"

    WOLFNET_SRC_DIR="/opt/wolfnet-src"
    if [ -d "$WOLFNET_SRC_DIR" ]; then
        echo "  Updating WolfNet..."
        cd "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
        git fetch origin 2>&1 || true
        git reset --hard origin/main 2>&1 || true

        if [ ! -d "$WOLFNET_SRC_DIR/wolfnet" ]; then
            cd /tmp
            rm -rf "$WOLFNET_SRC_DIR"
            git clone https://github.com/wolfsoftwaresystemsltd/WolfScale.git "$WOLFNET_SRC_DIR"
            git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
            cd "$WOLFNET_SRC_DIR"
        fi

        export PATH="$REAL_HOME/.cargo/bin:/usr/local/bin:/usr/bin:$PATH"
        if command -v cargo &> /dev/null; then
            cd "$WOLFNET_SRC_DIR/wolfnet"
            if [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
                chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR"
                su - "$REAL_USER" -c "cd $WOLFNET_SRC_DIR/wolfnet && $REAL_HOME/.cargo/bin/cargo build --release"
            else
                cargo build --release
            fi
            cp "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnet" /usr/local/bin/wolfnet
            chmod +x /usr/local/bin/wolfnet
            if [ -f "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnetctl" ]; then
                cp "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnetctl" /usr/local/bin/wolfnetctl
                chmod +x /usr/local/bin/wolfnetctl
            fi
            echo "  WolfNet updated"
        fi
    fi

    echo "  Starting WolfNet..."
    systemctl start wolfnet 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet wolfnet; then
        WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "")
        echo "  WolfNet started. IP: ${WOLFNET_IP:-unknown}"
    else
        echo "  WolfNet failed to start. Check: journalctl -u wolfnet -n 20"
    fi

else
    # WolfNet NOT installed — must install it
    echo "  WolfNet not found — installing for cluster networking..."
    echo ""

    # WolfNet needs /dev/net/tun
    if [ ! -e /dev/net/tun ]; then
        echo ""
        echo "  /dev/net/tun is NOT available!"
        echo "  ─────────────────────────────────────"
        echo ""
        echo "  WolfNet needs TUN/TAP to create its network overlay."
        echo "  If this is an LPAR, ensure the VIO server provides TUN/TAP."
        echo ""
        echo "  To create the device manually:"
        echo "     mkdir -p /dev/net"
        echo "     mknod /dev/net/tun c 10 200"
        echo "     chmod 666 /dev/net/tun"
        echo ""
        echo "  Then re-run this installer."
        echo ""
        echo "  Cannot continue without WolfNet. Fix /dev/net/tun and re-run."
        exit 1
    fi

    # Download WolfNet source
    echo "  Downloading WolfNet..."
    WOLFNET_SRC_DIR="/opt/wolfnet-src"
    if [ -d "$WOLFNET_SRC_DIR" ]; then
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
        cd "$WOLFNET_SRC_DIR" && git fetch origin && git reset --hard origin/main
    else
        git clone https://github.com/wolfsoftwaresystemsltd/WolfScale.git "$WOLFNET_SRC_DIR"
        git config --global --add safe.directory "$WOLFNET_SRC_DIR" 2>/dev/null || true
        cd "$WOLFNET_SRC_DIR"
    fi

    # Ensure Rust is available for building WolfNet
    export PATH="$REAL_HOME/.cargo/bin:/usr/local/bin:/usr/bin:$PATH"

    if ! command -v cargo &> /dev/null; then
        echo "  Installing Rust first..."
        if [ "$REAL_USER" = "root" ]; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        else
            su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        fi
        export PATH="$REAL_HOME/.cargo/bin:$PATH"
    fi

    # Build WolfNet
    echo "  Building WolfNet..."
    cd "$WOLFNET_SRC_DIR/wolfnet"
    if [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
        chown -R "$REAL_USER:$REAL_USER" "$WOLFNET_SRC_DIR"
        su - "$REAL_USER" -c "cd $WOLFNET_SRC_DIR/wolfnet && $REAL_HOME/.cargo/bin/cargo build --release"
    else
        cargo build --release
    fi

    # Install binaries
    cp "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnet" /usr/local/bin/wolfnet
    chmod +x /usr/local/bin/wolfnet
    if [ -f "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnetctl" ]; then
        cp "$WOLFNET_SRC_DIR/wolfnet/target/release/wolfnetctl" /usr/local/bin/wolfnetctl
        chmod +x /usr/local/bin/wolfnetctl
    fi
    echo "  WolfNet binary installed"

    # Configure WolfNet
    mkdir -p /etc/wolfnet /var/run/wolfnet

    if [ ! -f "/etc/wolfnet/config.toml" ]; then
        HOST_IP=$(hostname -I | awk '{print $1}')
        LAST_OCTET=$(echo "$HOST_IP" | awk -F. '{print $4}')
        if [ -z "$LAST_OCTET" ] || [ "$LAST_OCTET" -lt 1 ] 2>/dev/null || [ "$LAST_OCTET" -gt 254 ] 2>/dev/null; then
            LAST_OCTET=1
        fi

        WOLFNET_SUBNET=""
        for THIRD_OCTET in 10 20 30 40 50 60 70 80 90; do
            CANDIDATE="10.10.${THIRD_OCTET}.0/24"
            if ! ip route show 2>/dev/null | grep -q "10.10.${THIRD_OCTET}\." && \
               ! ip addr show 2>/dev/null | grep -q "10.10.${THIRD_OCTET}\."; then
                WOLFNET_SUBNET="10.10.${THIRD_OCTET}"
                break
            fi
            echo "  Subnet $CANDIDATE already in use, trying next..."
        done

        if [ -z "$WOLFNET_SUBNET" ]; then
            echo "  Could not find a free 10.10.x.0/24 subnet!"
            echo "  Please configure WolfNet manually: /etc/wolfnet/config.toml"
            WOLFNET_SUBNET="10.10.10"
        fi

        WOLFNET_IP="${WOLFNET_SUBNET}.${LAST_OCTET}"
        TRIES=0
        while [ $TRIES -lt 253 ]; do
            if ! ping -c 1 -W 1 "$WOLFNET_IP" &>/dev/null; then
                break
            fi
            echo "  ${WOLFNET_IP} already in use, trying next..."
            LAST_OCTET=$(( (LAST_OCTET % 254) + 1 ))
            WOLFNET_IP="${WOLFNET_SUBNET}.${LAST_OCTET}"
            TRIES=$((TRIES + 1))
        done

        echo ""
        echo "  ──────────────────────────────────────────────────"
        echo "  LAN Auto-Discovery"
        echo "  ──────────────────────────────────────────────────"
        echo ""
        echo "  WolfNet can broadcast discovery packets on your local"
        echo "  network to automatically find other WolfNet nodes."
        echo ""
        echo "  Do NOT enable on public/datacenter networks!"
        echo "  Only enable on private LANs (home, office)."
        echo ""
        echo -n "Enable LAN auto-discovery? [y/N]: "
        read ENABLE_DISCOVERY < /dev/tty
        if [ "$ENABLE_DISCOVERY" = "y" ] || [ "$ENABLE_DISCOVERY" = "Y" ]; then
            WOLFNET_DISCOVERY="true"
        else
            WOLFNET_DISCOVERY="false"
        fi

        KEY_FILE="/etc/wolfnet/private.key"
        /usr/local/bin/wolfnet genkey --output "$KEY_FILE" 2>/dev/null || true

        cat <<WOLFCFG > /etc/wolfnet/config.toml
# WolfNet Configuration
# Auto-generated by ibmsetup.sh (IBM Power)
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
WOLFCFG
        echo "  WolfNet configured: $WOLFNET_IP/24 (subnet: ${WOLFNET_SUBNET}.0/24)"
        if [ "$WOLFNET_DISCOVERY" = "false" ]; then
            echo "  Discovery disabled. You can enable it later in WolfStack settings."
        fi
    fi

    # Create systemd service
    if [ ! -f "/etc/systemd/system/wolfnet.service" ]; then
        cat > /etc/systemd/system/wolfnet.service <<WNETSVC
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
WNETSVC
        systemctl daemon-reload
    fi

    systemctl enable wolfnet 2>/dev/null || true
    systemctl start wolfnet 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet wolfnet; then
        WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "${WOLFNET_IP:-unknown}")
        echo "  WolfNet running! Cluster IP: $WOLFNET_IP"
    else
        echo "  WolfNet may not have started. Check: journalctl -u wolfnet -n 20"
    fi
fi

echo ""

# ─── Install Rust if not present ────────────────────────────────────────────
CARGO_BIN="$REAL_HOME/.cargo/bin/cargo"

if [ -f "$CARGO_BIN" ]; then
    echo "  Rust already installed"
elif command -v cargo &> /dev/null; then
    CARGO_BIN="$(command -v cargo)"
    echo "  Rust already installed (system-wide)"
else
    echo ""
    echo "Installing Rust for user '$REAL_USER'..."
    if [ "$REAL_USER" = "root" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    else
        su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    fi
    echo "  Rust installed"
fi

export PATH="$REAL_HOME/.cargo/bin:/usr/local/bin:/usr/bin:$PATH"

if ! command -v cargo &> /dev/null; then
    echo "cargo not found after installation. Check Rust install."
    exit 1
fi

echo "  Using cargo: $(command -v cargo)"

# ─── Clone or update repository ─────────────────────────────────────────────
INSTALL_DIR="/opt/wolfstack-src"
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

BUILT_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "  Repository ready ($INSTALL_DIR)"
echo "  Branch: $BRANCH | Version: $BUILT_VERSION"

# Force full rebuild
echo "  Cleaning previous build..."
rm -rf target/release/wolfstack target/release/.fingerprint/wolfstack-*

# ─── Build WolfStack ────────────────────────────────────────────────────────
echo ""
echo "Building WolfStack (this may take a few minutes)..."

if [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
    chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR"
    su - "$REAL_USER" -c "cd $INSTALL_DIR && $REAL_HOME/.cargo/bin/cargo build --release"
else
    cargo build --release
fi

echo "  Build complete"

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

cp "$INSTALL_DIR/target/release/wolfstack" /usr/local/bin/wolfstack
chmod +x /usr/local/bin/wolfstack
echo "  wolfstack installed to /usr/local/bin/wolfstack"

# ─── Install web UI ─────────────────────────────────────────────────────────
echo ""
echo "Installing web UI..."
mkdir -p /opt/wolfstack/web
cp -r "$INSTALL_DIR/web/"* /opt/wolfstack/web/
echo "  Web UI installed to /opt/wolfstack/web"

# ─── Configuration ──────────────────────────────────────────────────────────
if [ ! -f "/etc/wolfstack/config.toml" ]; then
    echo ""
    echo "  ──────────────────────────────────────────────────"
    echo "  WolfStack Configuration"
    echo "  ──────────────────────────────────────────────────"
    echo ""

    echo -n "Dashboard port [8553]: "
    read WS_PORT < /dev/tty
    WS_PORT=${WS_PORT:-8553}

    echo -n "Bind address [0.0.0.0]: "
    read WS_BIND < /dev/tty
    WS_BIND=${WS_BIND:-0.0.0.0}

    mkdir -p /etc/wolfstack
    cat <<WSCFG > /etc/wolfstack/config.toml
# WolfStack Configuration
# Generated by ibmsetup.sh (IBM Power)

[server]
port = $WS_PORT
bind = "$WS_BIND"
web_dir = "/opt/wolfstack/web"
WSCFG
    echo "  Config created at /etc/wolfstack/config.toml"
    echo ""
    echo "  Dashboard: http://$WS_BIND:$WS_PORT"
else
    echo ""
    echo "  Config already exists at /etc/wolfstack/config.toml"
    echo "  (Upgrade mode - skipping configuration prompts)"
    WS_PORT=$(grep "port" /etc/wolfstack/config.toml 2>/dev/null | head -1 | awk '{print $3}' || echo "8553")
    WS_BIND=$(grep "bind" /etc/wolfstack/config.toml 2>/dev/null | head -1 | awk '{print $3}' | tr -d '"' || echo "0.0.0.0")
fi

# ─── Create systemd service ─────────────────────────────────────────────────
if [ ! -f "/etc/systemd/system/wolfstack.service" ]; then
    echo ""
    echo "  ──────────────────────────────────────────────────"
    echo "  Creating systemd service..."
    echo "  ──────────────────────────────────────────────────"
    echo ""

    cat > /etc/systemd/system/wolfstack.service <<WSSVC
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
WSSVC

    systemctl daemon-reload
    echo "  Systemd service created"

    echo ""
    echo -n "Start WolfStack now? [Y/n]: "
    read start_now < /dev/tty
    if [ "$start_now" != "n" ] && [ "$start_now" != "N" ]; then
        systemctl enable wolfstack
        systemctl start wolfstack
        sleep 2
        if systemctl is-active --quiet wolfstack; then
            echo "  WolfStack is running!"
        else
            echo "  WolfStack may have failed to start. Check: journalctl -u wolfstack -n 20"
        fi
    else
        systemctl enable wolfstack
        echo "  WolfStack enabled (will start on boot)"
    fi
else
    echo ""
    echo "  Service already installed - reloading systemd"
    systemctl daemon-reload
fi

# ─── Firewall ───────────────────────────────────────────────────────────────
echo ""
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port="$WS_PORT/tcp" 2>/dev/null && \
    firewall-cmd --permanent --add-port="9600/udp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    echo "  Firewall: Opened port $WS_PORT/tcp and 9600/udp (firewalld)" || true
elif command -v ufw &> /dev/null; then
    ufw allow "$WS_PORT/tcp" 2>/dev/null && echo "  Firewall: Opened port $WS_PORT/tcp (ufw)" || true
    ufw allow 9600/udp 2>/dev/null && echo "  Firewall: Opened port 9600/udp for WolfNet (ufw)" || true
fi

# ─── Firmware information ────────────────────────────────────────────────────
if [ "$SKIP_FIRMWARE" = false ]; then
    echo ""
    echo "─── Firmware & Hardware Information ─────────────────"
    echo ""

    if command -v lsmcode &> /dev/null; then
        FW_LEVEL=$(lsmcode -r 2>/dev/null || echo "N/A")
        echo "  System firmware: $FW_LEVEL"
    fi

    if command -v lsmcode &> /dev/null; then
        echo ""
        echo "  Adapter firmware levels:"
        lsmcode -A 2>/dev/null | head -20 | while IFS= read -r line; do
            echo "    $line"
        done
        echo ""
    fi

    if command -v lscfg &> /dev/null; then
        echo "  Hardware summary:"
        PROC_INFO=$(lscfg -vpl proc0 2>/dev/null | grep "Model" | head -1 || echo "")
        if [ -n "$PROC_INFO" ]; then
            echo "    Processor: $PROC_INFO"
        fi
        MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{printf "%.0f GB", $2/1024/1024}')
        echo "    Memory: $MEM_TOTAL"
        PAGE_SIZE=$(getconf PAGESIZE)
        echo "    Page size: $((PAGE_SIZE / 1024)) KB"
    fi

    if [ "$IS_LPAR" = true ] && [ -f /proc/ppc64/lparcfg ]; then
        echo ""
        echo "  LPAR configuration:"
        ENTITLED=$(grep "partition_entitled_capacity" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")
        VCPUS=$(grep "partition_active_processors" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")
        CAPPED=$(grep "^capped" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")

        if [ "$ENTITLED" != "?" ]; then
            ENT_PROCS=$(echo "scale=2; $ENTITLED / 100" | bc 2>/dev/null || echo "$ENTITLED/100")
            echo "    Entitled capacity: $ENT_PROCS processors"
        fi
        echo "    Virtual CPUs: $VCPUS"
        if [ "$CAPPED" = "0" ]; then
            echo "    Mode: uncapped (can burst beyond entitlement)"
        elif [ "$CAPPED" = "1" ]; then
            echo "    Mode: capped (limited to entitlement)"
        fi
    fi
    echo ""
fi

# ─── Create Power hardware diagnostics script ───────────────────────────────
MONITOR_SCRIPT="/usr/local/bin/wolfstack-power-diag"
cat > "$MONITOR_SCRIPT" << 'DIAG'
#!/bin/bash
# WolfStack IBM Power Diagnostics
# Quick hardware health check for IBM Power servers

echo "=== WolfStack IBM Power Diagnostics ==="
echo "Date: $(date)"
echo ""

echo "--- System ---"
uname -m
echo "Kernel: $(uname -r)"
lsmcode -r 2>/dev/null || echo "Firmware: N/A"
echo ""

echo "--- LPAR ---"
if [ -f /proc/ppc64/lparcfg ]; then
    grep -E "partition_name|partition_entitled|partition_active|shared_processor|capped" /proc/ppc64/lparcfg 2>/dev/null
else
    echo "Not running in an LPAR (bare-metal/PowerNV)"
fi
echo ""

echo "--- CPU ---"
ppc64_cpu --smt 2>/dev/null || true
ppc64_cpu --cores-present 2>/dev/null || true
ppc64_cpu --frequency 2>/dev/null || true
lparstat 1 1 2>/dev/null || true
echo ""

echo "--- Memory ---"
free -h
echo ""

echo "--- Storage ---"
multipath -ll 2>/dev/null | head -20 || echo "No multipath"
echo ""

echo "--- Hardware Errors ---"
servicelog --query 2>/dev/null | tail -10 || echo "No servicelog entries"
echo ""

echo "--- Attention LEDs ---"
usysattn 2>/dev/null || echo "LED status not available"
echo ""

echo "--- Network Adapters ---"
ip -br link show 2>/dev/null || ip link show
echo ""

echo "=== End Diagnostics ==="
DIAG
chmod +x "$MONITOR_SCRIPT"
echo "Installed diagnostics tool: wolfstack-power-diag"

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "  Installation Complete! (IBM Power)"
echo "  ─────────────────────────────────────"
echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):${WS_PORT}"
echo "  Login:      Use your Linux system username and password"
echo ""
echo "  Architecture:    $ARCH"
if [ "$IS_LPAR" = true ]; then
    echo "  LPAR:            $LPAR_NAME ($PROC_MODE)"
fi
if command -v ppc64_cpu &> /dev/null; then
    echo "  SMT:             $(ppc64_cpu --smt 2>/dev/null | grep -oP 'SMT=\d+' || echo 'N/A')"
fi
echo "  Page size:       $(($(getconf PAGESIZE) / 1024)) KB"
echo ""
echo "  Manage:"
echo "  Status:     sudo systemctl status wolfstack"
echo "  Logs:       sudo journalctl -u wolfstack -f"
echo "  Restart:    sudo systemctl restart wolfstack"
echo "  Config:     /etc/wolfstack/config.toml"
echo "  Diagnostics: wolfstack-power-diag"
echo ""
echo "**** UPGRADE COMPLETE ****"
echo ""
echo "Please Refresh your browser if upgrading..."

# ─── Restart service if upgrading (must be last!) ────────────────────────────
if [ "$RESTART_SERVICE" = "true" ]; then
    nohup bash -c "sleep 3 && systemctl restart wolfstack" &>/dev/null &
fi
