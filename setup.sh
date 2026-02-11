#!/bin/bash
#
# WolfStack Quick Install Script
# Installs WolfStack server management dashboard
# Supported: Ubuntu/Debian, Fedora/RHEL/CentOS, SLES/openSUSE, IBM Power (ppc64le)
#
# Usage: curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash
#

set -e

echo ""
echo "  🐺 WolfStack Installer"
echo "  ─────────────────────────────────────"
echo "  Server Management Platform"
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

# ─── Install system dependencies ────────────────────────────────────────────
echo ""
echo "Installing system dependencies..."

if [ "$PKG_MANAGER" = "apt" ]; then
    apt update -qq
    # Select architecture-appropriate QEMU package
    ARCH=$(uname -m)
    if [ "$ARCH" = "ppc64le" ] || [ "$ARCH" = "ppc64" ]; then
        QEMU_PKG="qemu-system-ppc"
    elif [ "$ARCH" = "aarch64" ]; then
        QEMU_PKG="qemu-system-arm"
    else
        QEMU_PKG="qemu-system-x86"
    fi
    apt install -y git curl build-essential pkg-config libssl-dev libcrypt-dev lxc lxc-templates dnsmasq-base bridge-utils $QEMU_PKG qemu-utils socat s3fs nfs-common fuse3
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install -y git curl gcc gcc-c++ make openssl-devel pkg-config libxcrypt-devel lxc lxc-templates lxc-extra dnsmasq bridge-utils qemu-kvm qemu-img socat s3fs-fuse nfs-utils fuse3
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y git curl gcc gcc-c++ make openssl-devel pkgconfig lxc lxc-templates lxc-extra dnsmasq bridge-utils qemu-kvm qemu-img socat s3fs-fuse nfs-utils fuse
elif [ "$PKG_MANAGER" = "zypper" ]; then
    zypper install -y git curl gcc gcc-c++ make libopenssl-devel pkg-config lxc dnsmasq bridge-utils qemu-kvm qemu-tools socat s3fs nfs-client fuse3
fi

echo "✓ System dependencies installed"

# ─── Install Proxmox Backup Client (optional, for PBS integration) ──────────
echo ""
echo "Installing Proxmox Backup Client..."

if command -v proxmox-backup-client &> /dev/null; then
    echo "✓ proxmox-backup-client already installed"
elif [ "$PKG_MANAGER" = "apt" ]; then
    # Add Proxmox PBS client repo (works on any Debian/Ubuntu)
    PBS_REPO_FILE="/etc/apt/sources.list.d/pbs-client.list"
    if [ ! -f "$PBS_REPO_FILE" ]; then
        # Detect Debian codename — PBS builds against bookworm
        CODENAME="bookworm"
        echo "deb http://download.proxmox.com/debian/pbs $CODENAME pbs-no-subscription" > "$PBS_REPO_FILE"
        # Add Proxmox repo key
        curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-${CODENAME}.gpg" \
            -o /etc/apt/trusted.gpg.d/proxmox-release-${CODENAME}.gpg 2>/dev/null || true
        apt update -qq 2>/dev/null || true
    fi
    apt install -y proxmox-backup-client 2>/dev/null || \
    apt install -y --allow-unauthenticated proxmox-backup-client 2>/dev/null || {
        echo "⚠ Could not install proxmox-backup-client from repo."
        echo "  PBS backup/restore will not be available."
        echo "  You can install it manually later: apt install proxmox-backup-client"
    }
else
    # For non-Debian: try downloading the static binary
    echo "  Attempting to download static proxmox-backup-client..."
    ARCH=$(uname -m)
    PBS_URL="https://enterprise.proxmox.com/debian/pbs-client/proxmox-backup-client-static-${ARCH}.bin"
    if curl -fsSL "$PBS_URL" -o /usr/local/bin/proxmox-backup-client 2>/dev/null; then
        chmod +x /usr/local/bin/proxmox-backup-client
        echo "✓ proxmox-backup-client (static) installed"
    else
        echo "⚠ Could not download proxmox-backup-client for $ARCH."
        echo "  PBS integration will not be available. Install manually if needed."
    fi
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
    # Already installed and running — nothing to do
    echo "✓ WolfNet already installed and running"
    WOLFNET_IP=$(ip -4 addr show wolfnet0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' || echo "")
    if [ -n "$WOLFNET_IP" ]; then
        echo "  WolfNet IP: $WOLFNET_IP"
    fi

elif command -v wolfnet &> /dev/null; then
    # Installed but not running — just start it
    echo "✓ WolfNet installed (not running)"
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
    WOLFNET_SRC_DIR="/opt/wolfnet-src"
    if [ -d "$WOLFNET_SRC_DIR" ]; then
        cd "$WOLFNET_SRC_DIR" && git fetch origin && git reset --hard origin/main
    else
        git clone https://github.com/wolfsoftwaresystemsltd/WolfScale.git "$WOLFNET_SRC_DIR"
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
discovery = true
mtu = 1400

[security]
private_key_file = "$KEY_FILE"

# Peers will be added automatically when you add servers to WolfStack
EOF
        echo "  ✓ WolfNet configured: $WOLFNET_IP/24 (subnet: ${WOLFNET_SUBNET}.0/24)"
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
CARGO_BIN="$REAL_HOME/.cargo/bin/cargo"

if [ -f "$CARGO_BIN" ]; then
    echo "✓ Rust already installed"
elif command -v cargo &> /dev/null; then
    CARGO_BIN="$(command -v cargo)"
    echo "✓ Rust already installed (system-wide)"
else
    echo ""
    echo "Installing Rust for user '$REAL_USER'..."
    if [ "$REAL_USER" = "root" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    else
        su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    fi
    echo "✓ Rust installed"
fi

# Ensure cargo is found
export PATH="$REAL_HOME/.cargo/bin:/usr/local/bin:/usr/bin:$PATH"

if ! command -v cargo &> /dev/null; then
    echo "✗ cargo not found after installation. Check Rust install."
    exit 1
fi

echo "✓ Using cargo: $(command -v cargo)"

# ─── Clone or update repository ─────────────────────────────────────────────
INSTALL_DIR="/opt/wolfstack-src"
echo ""
echo "Cloning WolfStack repository..."

if [ -d "$INSTALL_DIR" ]; then
    echo "  Updating existing installation..."
    cd "$INSTALL_DIR"
    git fetch origin
    git reset --hard origin/master
else
    git clone https://github.com/wolfsoftwaresystemsltd/WolfStack.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo "✓ Repository cloned to $INSTALL_DIR"

# ─── Build WolfStack ────────────────────────────────────────────────────────
echo ""
echo "Building WolfStack (this may take a few minutes)..."

if [ "$REAL_USER" != "root" ] && [ -f "$REAL_HOME/.cargo/bin/cargo" ]; then
    chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR"
    su - "$REAL_USER" -c "cd $INSTALL_DIR && $REAL_HOME/.cargo/bin/cargo build --release"
else
    cargo build --release
fi

echo "✓ Build complete"

# ─── Stop service if running (for upgrades) ─────────────────────────────────
if systemctl is-active --quiet wolfstack 2>/dev/null; then
    echo ""
    echo "Stopping WolfStack service for upgrade..."
    systemctl stop wolfstack
    sleep 2
    echo "✓ Service stopped"
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
    read WS_PORT < /dev/tty
    WS_PORT=${WS_PORT:-8553}

    # Prompt for bind address
    echo -n "Bind address [0.0.0.0]: "
    read WS_BIND < /dev/tty
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
    read start_now < /dev/tty
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

# ─── Restart if upgrading ───────────────────────────────────────────────────
if [ "$RESTART_SERVICE" = "true" ]; then
    echo ""
    echo "Restarting WolfStack service..."
    systemctl start wolfstack
    echo "✓ Service restarted"
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
