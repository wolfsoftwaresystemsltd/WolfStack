#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack IBM Power (ppc64le) Setup Script
# Installs IBM Power-specific hardware tools, performance tuning,
# and RHEL configuration for IBM POWER servers (POWER9/POWER10)
#
# Run this BEFORE or AFTER setup.sh on IBM Power servers.
# This script handles Power-specific packages and tuning that
# the main installer does not cover.
#
# Usage: sudo bash ibmsetup.sh
#        sudo bash ibmsetup.sh --skip-tuning    # skip performance tuning
#        sudo bash ibmsetup.sh --skip-firmware   # skip firmware checks
#

set -e

# ─── Parse arguments ─────────────────────────────────────────────────────────
SKIP_TUNING=false
SKIP_FIRMWARE=false
for arg in "$@"; do
    case "$arg" in
        --skip-tuning)   SKIP_TUNING=true ;;
        --skip-firmware) SKIP_FIRMWARE=true ;;
        --help|-h)
            echo "Usage: sudo bash ibmsetup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-tuning    Skip performance tuning (SMT, sysctl, tuned)"
            echo "  --skip-firmware  Skip firmware version checks"
            echo "  --help, -h       Show this help"
            exit 0
            ;;
    esac
done

echo ""
echo "  WolfStack IBM Power Setup"
echo "  ─────────────────────────────────────"
echo "  Hardware tools, tuning & diagnostics"
echo "  for IBM POWER9/POWER10 (ppc64le) RHEL"
echo ""

# ─── Must run as root ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    echo "  Usage: sudo bash ibmsetup.sh"
    exit 1
fi

# ─── Architecture check ─────────────────────────────────────────────────────
ARCH=$(uname -m)
if [ "$ARCH" != "ppc64le" ] && [ "$ARCH" != "ppc64" ]; then
    echo "This script is for IBM Power (ppc64le) systems only."
    echo "  Detected architecture: $ARCH"
    echo "  Use setup.sh for x86_64/aarch64 systems."
    exit 1
fi
echo "Architecture: $ARCH"

# ─── Detect RHEL version ────────────────────────────────────────────────────
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
    # Only attempt repo enable if the system is registered
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

# ─── Install IBM Power hardware management tools ────────────────────────────
echo "Installing IBM Power hardware tools..."

# Core Power packages — install individually so failures don't block others
POWER_PKGS=(
    powerpc-utils       # lscfg, lparstat, ppc64_cpu, drmgr, nvram
    ppc64-diag          # rtas_errd, diag_encl, usysident (hardware diagnostics)
    lsvpd               # lsvpd, lscfg VPD, lsmcode (firmware levels)
    librtas             # Runtime Abstraction Services library
    servicelog          # Hardware error logging
    servicelog-notify   # Error notification hooks
    iprutils            # IBM SAS/SCSI RAID adapter management
    src                 # System Resource Controller
)

INSTALLED=0
SKIPPED=0
for pkg in "${POWER_PKGS[@]}"; do
    # Strip inline comments
    pkg_name="${pkg%% *}"
    if rpm -q "$pkg_name" &>/dev/null; then
        INSTALLED=$((INSTALLED + 1))
    else
        if $PKG install -y "$pkg_name" &>/dev/null; then
            INSTALLED=$((INSTALLED + 1))
        else
            SKIPPED=$((SKIPPED + 1))
            echo "  Could not install $pkg_name — skipping"
        fi
    fi
done

echo "  ${INSTALLED} packages installed, ${SKIPPED} skipped"

# RSCT (Reliable Scalable Cluster Technology) — needed for DLPAR operations
echo ""
echo "Installing RSCT (cluster technology for DLPAR)..."
$PKG install -y rsct.core rsct.basic 2>/dev/null && \
    echo "  RSCT installed" || \
    echo "  RSCT not available — DLPAR operations may be limited"

echo ""

# ─── Install general server management tools ────────────────────────────────
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

# rtas_errd — monitors hardware errors from firmware
if [ -f /usr/sbin/rtas_errd ] || systemctl list-unit-files rtas_errd.service &>/dev/null; then
    systemctl enable rtas_errd 2>/dev/null && systemctl start rtas_errd 2>/dev/null && \
        echo "  rtas_errd (hardware error daemon) — running" || \
        echo "  rtas_errd — could not start"
fi

# IPR RAID services (for IBM SAS adapters)
for svc in iprinit iprupdate iprdump; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null; then
        systemctl enable "$svc" 2>/dev/null && systemctl start "$svc" 2>/dev/null && \
            echo "  $svc — running" || true
    fi
done

# RSCT resource manager
if systemctl list-unit-files ctrmc.service &>/dev/null; then
    systemctl enable ctrmc 2>/dev/null && systemctl start ctrmc 2>/dev/null && \
        echo "  ctrmc (RSCT resource manager) — running" || true
fi

# irqbalance — important for multi-socket Power with many queues
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

        # Only change SMT if not already set to a reasonable value
        if [ "$CURRENT_SMT" != "4" ] && [ "$CURRENT_SMT" != "8" ]; then
            ppc64_cpu --smt=4 2>/dev/null && \
                echo "  SMT set to 4 (balanced mode)" || \
                echo "  Could not set SMT level"
        else
            echo "  SMT level OK — no change needed"
        fi

        # Show core/thread info
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

    # Sysctl tuning for Power servers
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
    # Only configure if there are actual multipath-capable devices
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

# ─── Container runtime check ────────────────────────────────────────────────
echo "Checking container runtime for ppc64le..."

if command -v podman &> /dev/null; then
    echo "  podman: $(podman --version 2>/dev/null || echo 'installed')"
elif command -v docker &> /dev/null; then
    echo "  docker: $(docker --version 2>/dev/null || echo 'installed')"
else
    echo "  No container runtime found — setup.sh will install Docker"
fi

echo ""
echo "  NOTE: On ppc64le, container images must be built for ppc64le"
echo "  or be multi-arch. Many Docker Hub images are x86_64-only."
echo "  Red Hat UBI images (registry.access.redhat.com/ubi9/*) are"
echo "  recommended as they provide full ppc64le support."
echo ""

# ─── Firmware information ────────────────────────────────────────────────────
if [ "$SKIP_FIRMWARE" = false ]; then
    echo "─── Firmware & Hardware Information ─────────────────"
    echo ""

    # System firmware level
    if command -v lsmcode &> /dev/null; then
        FW_LEVEL=$(lsmcode -r 2>/dev/null || echo "N/A")
        echo "  System firmware: $FW_LEVEL"
    fi

    # Adapter firmware
    if command -v lsmcode &> /dev/null; then
        echo ""
        echo "  Adapter firmware levels:"
        lsmcode -A 2>/dev/null | head -20 | while IFS= read -r line; do
            echo "    $line"
        done
        echo ""
    fi

    # Hardware configuration summary
    if command -v lscfg &> /dev/null; then
        echo "  Hardware summary:"
        # Processor
        PROC_INFO=$(lscfg -vpl proc0 2>/dev/null | grep "Model" | head -1 || echo "")
        if [ -n "$PROC_INFO" ]; then
            echo "    Processor: $PROC_INFO"
        fi

        # Memory
        MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{printf "%.0f GB", $2/1024/1024}')
        echo "    Memory: $MEM_TOTAL"

        # Page size (Power uses 64KB vs x86 4KB)
        PAGE_SIZE=$(getconf PAGESIZE)
        echo "    Page size: $((PAGE_SIZE / 1024)) KB"
    fi

    # LPAR details
    if [ "$IS_LPAR" = true ] && [ -f /proc/ppc64/lparcfg ]; then
        echo ""
        echo "  LPAR configuration:"
        ENTITLED=$(grep "partition_entitled_capacity" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")
        VCPUS=$(grep "partition_active_processors" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")
        CAPPED=$(grep "^capped" /proc/ppc64/lparcfg 2>/dev/null | cut -d= -f2 || echo "?")

        if [ "$ENTITLED" != "?" ]; then
            # Entitled capacity is in hundredths of a processor
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

# ─── Create Power hardware monitoring script ────────────────────────────────
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
echo "Installed diagnostics tool: $MONITOR_SCRIPT"
echo "  Run: wolfstack-power-diag"
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────
echo "  IBM Power Setup Complete!"
echo "  ─────────────────────────────────────"
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
echo "  Key commands:"
echo "    lparstat -i              LPAR configuration"
echo "    ppc64_cpu --smt          SMT threading status"
echo "    lsmcode -A               Firmware levels"
echo "    lscfg -vpl               Hardware configuration"
echo "    servicelog --query       Hardware error log"
echo "    iprconfig                RAID adapter management"
echo "    wolfstack-power-diag     Quick health check"
echo ""
echo "  Next: Run setup.sh to install WolfStack itself."
echo ""
