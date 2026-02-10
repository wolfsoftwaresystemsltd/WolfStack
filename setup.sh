#!/bin/bash
#
# WolfStack Quick Install Script
# Installs WolfStack server management dashboard on Ubuntu/Debian or Fedora/RHEL
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
else
    echo "✗ Could not detect package manager (apt/dnf/yum)"
    echo "  Please install dependencies manually."
    exit 1
fi

# ─── Install system dependencies ────────────────────────────────────────────
echo ""
echo "Installing system dependencies..."

if [ "$PKG_MANAGER" = "apt" ]; then
    apt update -qq
    apt install -y git curl build-essential pkg-config libssl-dev libcrypt-dev
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install -y git curl gcc gcc-c++ make openssl-devel pkg-config libxcrypt-devel
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y git curl gcc gcc-c++ make openssl-devel pkgconfig
fi

echo "✓ System dependencies installed"

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
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port="$WS_PORT/tcp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    echo "✓ Firewall: Opened port $WS_PORT/tcp (firewalld)" || true
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
