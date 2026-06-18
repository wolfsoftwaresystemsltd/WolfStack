#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
#
# build-iso.sh — Build a WolfStack Live USB ISO based on Debian Live XFCE
#
# This remaster a Debian Live XFCE ISO to create a bootable live USB that:
#   1. Boots straight into an XFCE desktop with WiFi support
#   2. WolfStack starts automatically as a background service
#   3. Firefox opens the WolfStack dashboard (http://127.0.0.1:8553)
#   4. Desktop shortcut lets the user install to disk (with confirmation)
#
# Usage:
#   sudo ./tools/build-iso.sh                    # Build with latest release binary
#   sudo ./tools/build-iso.sh --from-source      # Build binary from local source
#   sudo ./tools/build-iso.sh --binary /path/to  # Use a specific binary
#
# Requirements: xorriso, squashfs-tools, wget
# Must run as root (for squashfs operations).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/.iso-build"
DEBIAN_LIVE_URL="https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-13.4.0-amd64-xfce.iso"
DEBIAN_LIVE_FILE="$BUILD_DIR/debian-live-xfce.iso"

# Get version from Cargo.toml
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
OUTPUT_ISO="$PROJECT_DIR/wolfstack-${VERSION}-amd64.iso"

# Parse arguments
BINARY_PATH=""
FROM_SOURCE=false
for arg in "$@"; do
    case "$arg" in
        --from-source) FROM_SOURCE=true ;;
        --binary) shift; BINARY_PATH="$1" ;;
    esac
done

echo ""
echo "  ======================================"
echo "  WolfStack Live USB Builder v${VERSION}"
echo "  ======================================"
echo ""

# ── Check root ──
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (for squashfs operations)."
    echo "Usage: sudo $0 $*"
    exit 1
fi

# ── Check dependencies ──
for cmd in xorriso unsquashfs mksquashfs wget; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Missing dependency: $cmd"
        echo "Install with: sudo pacman -S xorriso squashfs-tools wget"
        exit 1
    fi
done

# ── Clean up stale mounts from any previous failed build ──
cleanup_mounts() {
    local FS="$BUILD_DIR/squashfs-root"
    umount "$FS/tmp" 2>/dev/null || true
    umount "$FS/sys" 2>/dev/null || true
    umount "$FS/proc" 2>/dev/null || true
    umount "$FS/dev/pts" 2>/dev/null || true
    umount "$FS/dev" 2>/dev/null || true
}
trap cleanup_mounts EXIT
cleanup_mounts

# ── Prepare build directory ──
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# ── Download Debian Live XFCE ISO ──
if [ -f "$DEBIAN_LIVE_FILE" ]; then
    echo "[1/7] Using cached Debian Live XFCE ISO"
else
    echo "[1/7] Downloading Debian Live XFCE ISO (~3 GB)..."
    wget -q --show-progress -O "$DEBIAN_LIVE_FILE" "$DEBIAN_LIVE_URL"
fi

# ── Extract ISO ──
echo "[2/7] Extracting ISO..."
xorriso -osirrox on -indev "$DEBIAN_LIVE_FILE" -extract / "$BUILD_DIR/iso" 2>/dev/null
chmod -R u+w "$BUILD_DIR/iso"

# ── Extract squashfs filesystem ──
echo "[3/7] Extracting live filesystem (this takes a minute)..."
SQUASHFS_FILE=$(find "$BUILD_DIR/iso" -name "filesystem.squashfs" | head -1)
if [ -z "$SQUASHFS_FILE" ]; then
    echo "ERROR: Could not find filesystem.squashfs in ISO"
    exit 1
fi
unsquashfs -d "$BUILD_DIR/squashfs-root" "$SQUASHFS_FILE"

# ── Prepare WolfStack binary ──
echo "[4/7] Preparing WolfStack binary..."
if [ -n "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" "$BUILD_DIR/squashfs-root/usr/local/bin/wolfstack"
elif [ "$FROM_SOURCE" = true ]; then
    echo "  Building from source (this takes a few minutes)..."
    cd "$PROJECT_DIR"
    # Build as the original user, not root
    ORIG_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-root}")
    if [ "$ORIG_USER" != "root" ]; then
        su - "$ORIG_USER" -c "cd '$PROJECT_DIR' && cargo build --release" 2>&1 | tail -3
    else
        cargo build --release 2>&1 | tail -3
    fi
    cp "$PROJECT_DIR/target/release/wolfstack" "$BUILD_DIR/squashfs-root/usr/local/bin/wolfstack"
else
    echo "  Downloading latest release binary..."
    RELEASE_URL="https://github.com/wolfsoftwaresystemsltd/WolfStack/releases/latest/download/wolfstack-linux-amd64"
    if ! wget -q --show-progress -O "$BUILD_DIR/squashfs-root/usr/local/bin/wolfstack" "$RELEASE_URL" 2>/dev/null; then
        echo "  No release binary found. Building from source..."
        cd "$PROJECT_DIR"
        ORIG_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-root}")
        if [ "$ORIG_USER" != "root" ]; then
            su - "$ORIG_USER" -c "cd '$PROJECT_DIR' && cargo build --release" 2>&1 | tail -3
        else
            cargo build --release 2>&1 | tail -3
        fi
        cp "$PROJECT_DIR/target/release/wolfstack" "$BUILD_DIR/squashfs-root/usr/local/bin/wolfstack"
    fi
fi
chmod +x "$BUILD_DIR/squashfs-root/usr/local/bin/wolfstack"

# Copy web UI
echo "  Bundling web UI..."
if [ -d "$PROJECT_DIR/web" ]; then
    mkdir -p "$BUILD_DIR/squashfs-root/opt/wolfstack"
    cp -r "$PROJECT_DIR/web" "$BUILD_DIR/squashfs-root/opt/wolfstack/web"
fi

# Copy setup script (for install-to-disk, not used during live boot)
cp "$PROJECT_DIR/setup.sh" "$BUILD_DIR/squashfs-root/opt/wolfstack/setup.sh" 2>/dev/null || true

# ── Build and bundle WolfNet binary ──
echo "  Building WolfNet..."
WOLFNET_SRC="$PROJECT_DIR/../wolfnet"
if [ -d "$WOLFNET_SRC" ] && [ -f "$WOLFNET_SRC/Cargo.toml" ]; then
    ORIG_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-root}")
    if [ "$ORIG_USER" != "root" ]; then
        su - "$ORIG_USER" -c "cd '$WOLFNET_SRC' && cargo build --release" 2>&1 | tail -3
    else
        cd "$WOLFNET_SRC" && cargo build --release 2>&1 | tail -3
    fi
    cp "$WOLFNET_SRC/target/release/wolfnet" "$BUILD_DIR/squashfs-root/usr/local/bin/wolfnet"
    chmod +x "$BUILD_DIR/squashfs-root/usr/local/bin/wolfnet"
    if [ -f "$WOLFNET_SRC/target/release/wolfnetctl" ]; then
        cp "$WOLFNET_SRC/target/release/wolfnetctl" "$BUILD_DIR/squashfs-root/usr/local/bin/wolfnetctl"
        chmod +x "$BUILD_DIR/squashfs-root/usr/local/bin/wolfnetctl"
    fi
    echo "  ✓ WolfNet binary bundled"
else
    echo "  ⚠ WolfNet source not found at $WOLFNET_SRC — WolfNet will not be pre-installed"
fi

# ── Configure the live system ──
echo "[5/7] Configuring live system..."
FS="$BUILD_DIR/squashfs-root"

# --- Install all runtime dependencies into the squashfs via chroot ---
# This means the ISO boots ready-to-go with NO internet required.
echo "  Installing runtime packages into squashfs (chroot)..."
mount --bind /dev "$FS/dev"
mount --bind /dev/pts "$FS/dev/pts"
mount -t proc proc "$FS/proc"
mount -t sysfs sysfs "$FS/sys"
mount -t tmpfs tmpfs "$FS/tmp"
cp /etc/resolv.conf "$FS/etc/resolv.conf" 2>/dev/null || true

chroot "$FS" bash -c '
export DEBIAN_FRONTEND=noninteractive

# Ensure working NETWORK apt sources in the squashfs. install-to-disk rsyncs
# this filesystem onto the target, so whatever sources.list lives here is what
# the INSTALLED system gets. Debian Live images commonly ship only a `cdrom:`
# entry (or none), which left a fresh install unable to apt-update/upgrade or
# install anything until the user hand-added repos (SponiX 2026-06-18). Write
# canonical deb.debian.org sources for THIS image codename (deb822 form — the
# Debian 13/trixie default) and neutralise any cdrom entry so post-install
# `apt update` does not fail on an absent CD.
CODENAME="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-stable}")"
sed -i "s|^deb cdrom:|# deb cdrom:|g" /etc/apt/sources.list 2>/dev/null || true
rm -f /etc/apt/sources.list.d/*cdrom*.sources /etc/apt/sources.list.d/*cdrom*.list 2>/dev/null || true
mkdir -p /etc/apt/sources.list.d
cat > /etc/apt/sources.list.d/wolfstack-debian.sources <<SRC
Types: deb
URIs: http://deb.debian.org/debian
Suites: ${CODENAME} ${CODENAME}-updates
Components: main contrib non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: ${CODENAME}-security
Components: main contrib non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
SRC

apt update -qq 2>/dev/null || true

# Runtime dependencies — NO build tools, NO Rust
apt install -y --no-install-recommends \
    docker.io docker-compose \
    lxc lxc-templates dnsmasq-base bridge-utils socat \
    nfs-common fuse3 qemu-system-x86 qemu-utils \
    curl ca-certificates 2>/dev/null || true

apt install -y --no-install-recommends s3fs-fuse 2>/dev/null || \
    apt install -y --no-install-recommends s3fs 2>/dev/null || true

# Clean apt cache to save ISO space
apt clean
rm -rf /var/lib/apt/lists/*

' 2>&1 | tail -20

umount "$FS/tmp"
umount "$FS/sys"
umount "$FS/proc"
umount "$FS/dev/pts"
umount "$FS/dev"
echo "  ✓ Runtime packages installed"

# User creation handled by wolfstack-live-setup at boot (step 1/7)

# --- WolfNet configuration ---
mkdir -p "$FS/etc/wolfnet" "$FS/var/run/wolfnet"
cat > "$FS/etc/wolfnet/config.toml" << 'WNCONF'
# WolfNet Configuration — auto-generated by WolfStack Live USB
[network]
interface = "wolfnet0"
address = "10.10.10.1"
subnet = 24
listen_port = 9600
gateway = false
discovery = false
mtu = 1400

[security]
private_key_file = "/etc/wolfnet/private.key"
WNCONF

# --- WolfNet systemd service ---
cat > "$FS/etc/systemd/system/wolfnet.service" << 'EOF'
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

# --- WolfStack configuration ---
mkdir -p "$FS/etc/wolfstack"
cat > "$FS/etc/wolfstack/config.toml" << 'WSCONF'
# WolfStack Configuration — auto-generated by WolfStack Live USB
[server]
port = 8553
bind = "0.0.0.0"
web_dir = "/opt/wolfstack/web"
WSCONF

# --- WolfStack systemd service ---
cat > "$FS/etc/systemd/system/wolfstack.service" << 'EOF'
[Unit]
Description=WolfStack - Server Management Platform
After=network-online.target wolfnet.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wolfstack --port 8553 --bind 0.0.0.0
WorkingDirectory=/opt/wolfstack
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wolfstack

[Install]
WantedBy=multi-user.target
EOF

# --- LXC networking ---
if [ -f "$FS/etc/default/lxc-net" ]; then
    sed -i 's/^#\?USE_LXC_BRIDGE=.*/USE_LXC_BRIDGE="true"/' "$FS/etc/default/lxc-net"
else
    echo 'USE_LXC_BRIDGE="true"' > "$FS/etc/default/lxc-net"
fi

# --- Enable all services to start on boot ---
mkdir -p "$FS/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/wolfnet.service "$FS/etc/systemd/system/multi-user.target.wants/wolfnet.service"
ln -sf /etc/systemd/system/wolfstack.service "$FS/etc/systemd/system/multi-user.target.wants/wolfstack.service"
ln -sf /lib/systemd/system/docker.service "$FS/etc/systemd/system/multi-user.target.wants/docker.service" 2>/dev/null || true
ln -sf /lib/systemd/system/lxc-net.service "$FS/etc/systemd/system/multi-user.target.wants/lxc-net.service" 2>/dev/null || true

# --- Boot-time init script (minimal: just TUN device + WolfNet key gen) ---
cat > "$FS/usr/local/bin/wolfstack-live-setup" << 'SETUPEOF'
#!/bin/bash
# WolfStack Live USB — boot-time init

SETUP_DONE="/var/run/wolfstack-setup-done"
[ -f "$SETUP_DONE" ] && exit 0

echo ""
echo "  ======================================"
echo "  WolfStack Live USB — Starting up"
echo "  ======================================"
echo ""

# Create the wolfstack login user
echo "  [1/7] Creating wolfstack user..."
if ! id wolfstack &>/dev/null; then
    adduser --disabled-password --gecos "WolfStack" wolfstack 2>/dev/null
    echo "wolfstack:wolfstack" | chpasswd -c SHA512
fi
echo "         Done."

# Ensure /dev/net/tun
echo "  [2/7] Setting up TUN device..."
if [ ! -e /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 666 /dev/net/tun 2>/dev/null || true
fi
modprobe tun 2>/dev/null || true
echo "         Done."

# Generate WolfNet key if not present
echo "  [3/7] Generating WolfNet encryption key..."
if [ ! -f /etc/wolfnet/private.key ]; then
    mkdir -p /etc/wolfnet
    if command -v wolfnet >/dev/null 2>&1; then
        wolfnet genkey --output /etc/wolfnet/private.key 2>/dev/null || true
    fi
fi
echo "         Done."

# Auto-assign WolfNet IP based on host network
echo "  [4/7] Detecting network configuration..."
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
LAST_OCTET=$(echo "$HOST_IP" | awk -F. '{print $4}')
if [ -n "$LAST_OCTET" ] && [ "$LAST_OCTET" -ge 1 ] 2>/dev/null && [ "$LAST_OCTET" -le 254 ] 2>/dev/null; then
    sed -i "s/address = \"10.10.10.1\"/address = \"10.10.10.${LAST_OCTET}\"/" /etc/wolfnet/config.toml 2>/dev/null || true
    echo "         IP address: $HOST_IP — WolfNet: 10.10.10.${LAST_OCTET}"
else
    echo "         No network detected — using default WolfNet IP"
fi

# Start Docker
echo "  [5/7] Starting Docker..."
systemctl daemon-reload
systemctl start docker 2>/dev/null || true
echo "         Done."

# Start WolfNet
echo "  [6/7] Starting WolfNet..."
systemctl start wolfnet 2>/dev/null || true
sleep 2
echo "         Done."

# Start WolfStack
echo "  [7/7] Starting WolfStack dashboard..."
systemctl start wolfstack 2>/dev/null || true

# Wait for WolfStack to respond (up to 30 seconds)
for i in $(seq 1 30); do
    if curl -sSf http://127.0.0.1:8553/api/settings/login-disabled >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
echo "         Done."

touch "$SETUP_DONE"
echo ""
echo "  ======================================"
echo "  WolfStack is ready!"
echo "  ======================================"
echo ""
echo "  Dashboard: http://127.0.0.1:8553"
echo ""
echo "  Login credentials:"
echo "    Username: wolfstack"
echo "    Password: wolfstack"
echo ""
echo "  Change your password after first login!"
echo ""
SETUPEOF
chmod +x "$FS/usr/local/bin/wolfstack-live-setup"

# --- Boot-time systemd service (runs the minimal init script) ---
cat > "$FS/etc/systemd/system/wolfstack-setup.service" << 'EOF'
[Unit]
Description=WolfStack Live USB Init
After=network-online.target
Wants=network-online.target
Before=wolfnet.service wolfstack.service
ConditionPathExists=!/var/run/wolfstack-setup-done

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wolfstack-live-setup
RemainAfterExit=yes
TimeoutStartSec=120
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
mkdir -p "$FS/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/wolfstack-setup.service "$FS/etc/systemd/system/multi-user.target.wants/wolfstack-setup.service"

# --- Landing page (static HTML — no API calls, no CORS issues) ---
mkdir -p "$FS/opt/wolfstack/landing"
cat > "$FS/opt/wolfstack/landing/index.html" << 'LANDING'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WolfStack — Getting Ready</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0a0e17; color: #c9d1d9;
    display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh;
  }
  .card {
    background: rgba(17,24,43,0.85); border: 1px solid rgba(220,38,38,0.15);
    border-radius: 16px; padding: 48px 40px; max-width: 480px; width: 90vw;
    box-shadow: 0 25px 50px rgba(0,0,0,0.4); text-align: center;
  }
  h1 { font-size: 22px; color: #f87171; margin: 12px 0 4px; }
  .sub { color: #64748b; font-size: 14px; margin-bottom: 28px; }

  .steps {
    text-align: left; background: rgba(15,23,42,0.6);
    border: 1px solid rgba(220,38,38,0.15); border-radius: 10px;
    padding: 20px 24px; margin-bottom: 24px;
  }
  .steps h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-bottom: 14px; }
  .step { display: flex; gap: 10px; padding: 6px 0; font-size: 14px; color: #94a3b8; }
  .step-num { color: #f87171; font-weight: 600; min-width: 18px; }

  .creds {
    text-align: left; background: rgba(15,23,42,0.6);
    border: 1px solid rgba(220,38,38,0.15); border-radius: 10px;
    padding: 16px 24px; margin-bottom: 24px;
  }
  .creds h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-bottom: 10px; }
  .cred-row { display: flex; justify-content: space-between; padding: 4px 0; font-size: 14px; }
  .cred-label { color: #94a3b8; }
  .cred-value {
    font-family: 'Courier New', monospace; font-weight: 600;
    color: #e2e8f0; background: rgba(220,38,38,0.1);
    padding: 2px 10px; border-radius: 6px;
  }
  .cred-warn { font-size: 12px; color: #f59e0b; margin-top: 8px; }

  .go-btn {
    display: block; width: 100%; padding: 14px; text-align: center;
    background: linear-gradient(135deg, #dc2626, #b91c1c);
    border: none; border-radius: 10px; color: white;
    font-size: 15px; font-weight: 600; cursor: pointer;
    text-decoration: none; transition: all 0.25s;
  }
  .go-btn:hover { transform: translateY(-1px); box-shadow: 0 8px 25px rgba(220,38,38,0.35); }

  .hint { font-size: 12px; color: #64748b; margin-top: 16px; line-height: 1.5; }

  .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #64748b; }
  .footer a { color: #f87171; text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <img src="http://127.0.0.1:8553/images/wolfstack-logo.png" alt="" style="height:40px;" onerror="this.style.display='none'">
  <h1>WolfStack Live USB</h1>
  <p class="sub">Server Management Platform</p>

  <div class="steps">
    <h2>What's happening</h2>
    <div class="step"><span class="step-num">1.</span> WolfStack is setting up services in the background</div>
    <div class="step"><span class="step-num">2.</span> You can watch the progress in the terminal window behind this page</div>
    <div class="step"><span class="step-num">3.</span> When the terminal says "WolfStack is ready!", click the button below</div>
  </div>

  <div class="creds">
    <h2>Login Credentials</h2>
    <div class="cred-row"><span class="cred-label">Username</span><span class="cred-value">wolfstack</span></div>
    <div class="cred-row"><span class="cred-label">Password</span><span class="cred-value">wolfstack</span></div>
    <p class="cred-warn">Change your password after first login.</p>
  </div>

  <a href="http://127.0.0.1:8553" class="go-btn">Open Dashboard</a>

  <p class="hint">
    If the dashboard doesn't load yet, just wait a moment and try again.<br>
    Services typically take 30-60 seconds to start.
  </p>
</div>
<div class="footer">&copy; 2026 <a href="https://wolf.uk.com/">Wolf Software Systems Ltd</a></div>
</body>
</html>
LANDING

# --- Firefox ESR homepage policy ---
mkdir -p "$FS/usr/lib/firefox-esr/distribution"
cat > "$FS/usr/lib/firefox-esr/distribution/policies.json" << 'EOF'
{
  "policies": {
    "Homepage": {
      "URL": "file:///opt/wolfstack/landing/index.html",
      "Locked": false,
      "StartPage": "homepage"
    },
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": ""
  }
}
EOF

# --- Auto-open service log terminal on desktop login ---
mkdir -p "$FS/etc/xdg/autostart"
cat > "$FS/etc/xdg/autostart/wolfstack-setup-terminal.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=WolfStack Services
Exec=bash -c 'sleep 3 && xfce4-terminal --title="WolfStack — Starting Up" -e "sudo journalctl -u wolfstack-setup -u wolfstack -u wolfnet -u docker -f --no-hostname -o cat"'
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
Comment=Shows WolfStack service logs
EOF

# --- Auto-open Firefox on desktop login (landing page works immediately) ---
cat > "$FS/etc/xdg/autostart/wolfstack-browser.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=WolfStack Dashboard
Exec=bash -c 'sleep 5 && firefox-esr file:///opt/wolfstack/landing/index.html'
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
Comment=Opens WolfStack setup landing page
EOF

# --- Install to Disk script ---
cat > "$FS/usr/local/bin/wolfstack-install-to-disk" << 'INSTALLER'
#!/bin/bash
# WolfStack — Install to Disk
# Copies the live system to a hard drive with user confirmation.

export DISPLAY="${DISPLAY:-:0}"

# Require root
if [ "$EUID" -ne 0 ]; then
    pkexec "$0" "$@"
    exit $?
fi

# ── Welcome & confirmation ──
zenity --question \
    --title="Install WolfStack to Disk" \
    --text="This will install WolfStack to your hard drive.\n\nThe live USB system, including WolfStack and the XFCE desktop,\nwill be copied to the disk you select.\n\n<b>WARNING: The selected disk will be COMPLETELY ERASED.</b>\n\nDo you want to continue?" \
    --width=450 --ok-label="Continue" --cancel-label="Cancel" 2>/dev/null || exit 0

# ── Find available disks (exclude live media and loops) ──
LIVE_SOURCE=$(findmnt -no SOURCE /run/live/medium 2>/dev/null || findmnt -no SOURCE /lib/live/mount/medium 2>/dev/null || echo "")
LIVE_DISK=$(echo "$LIVE_SOURCE" | sed 's/[0-9]*$//' | sed 's/p[0-9]*$//')

DISK_LIST=""
while IFS= read -r line; do
    DNAME=$(echo "$line" | awk '{print $1}')
    DSIZE=$(echo "$line" | awk '{print $2}')
    DMODEL=$(echo "$line" | awk '{$1=$2=""; print $0}' | xargs)
    # Skip the live USB, loop devices, and optical drives
    [[ "$DNAME" == "$LIVE_DISK" ]] && continue
    [[ "$DNAME" == *loop* ]] && continue
    [[ "$DNAME" == *sr* ]] && continue
    DISK_LIST+="${DNAME}\n${DSIZE}\n${DMODEL:-Unknown}\n"
done < <(lsblk -dpno NAME,SIZE,MODEL 2>/dev/null)

if [ -z "$DISK_LIST" ]; then
    zenity --error --title="No Disks Found" \
        --text="No suitable disks found for installation.\nMake sure a hard drive is connected." \
        --width=350 2>/dev/null
    exit 1
fi

# ── Select disk ──
SELECTED=$(echo -e "$DISK_LIST" | zenity --list \
    --title="Select Installation Disk" \
    --text="Choose the disk to install WolfStack on.\nAll data on the selected disk will be erased." \
    --column="Disk" --column="Size" --column="Model" \
    --width=550 --height=350 2>/dev/null)

if [ -z "$SELECTED" ]; then
    exit 0
fi

# ── Final confirmation ──
DISK_SIZE=$(lsblk -dpno SIZE "$SELECTED" 2>/dev/null | xargs)
zenity --question \
    --title="Confirm Installation" \
    --text="<b>FINAL WARNING</b>\n\nYou are about to ERASE ALL DATA on:\n\n  Disk: <b>${SELECTED}</b>\n  Size: <b>${DISK_SIZE}</b>\n\nThis cannot be undone. Are you absolutely sure?" \
    --width=400 --ok-label="Erase and Install" --cancel-label="Cancel" 2>/dev/null || exit 0

# ── Set root password ──
while true; do
    PASS1=$(zenity --entry --title="Set Root Password" \
        --text="Enter a root password for the installed system:" \
        --hide-text --width=400 2>/dev/null) || exit 0
    if [ -z "$PASS1" ]; then
        zenity --warning --text="Password cannot be empty." --width=300 2>/dev/null
        continue
    fi
    PASS2=$(zenity --entry --title="Confirm Root Password" \
        --text="Confirm the root password:" \
        --hide-text --width=400 2>/dev/null) || exit 0
    if [ "$PASS1" = "$PASS2" ]; then
        break
    fi
    zenity --warning --text="Passwords do not match. Try again." --width=300 2>/dev/null
done

# ── Install (with progress) ──
(
echo "5"
echo "# Partitioning disk..."

# Detect UEFI vs BIOS
if [ -d /sys/firmware/efi ]; then
    UEFI=true
    parted -s "$SELECTED" mklabel gpt
    parted -s "$SELECTED" mkpart ESP fat32 1MiB 513MiB
    parted -s "$SELECTED" set 1 esp on
    parted -s "$SELECTED" mkpart primary ext4 513MiB 100%
    sleep 1
    # Determine partition naming (nvme vs sd)
    if [[ "$SELECTED" == *nvme* ]] || [[ "$SELECTED" == *mmcblk* ]]; then
        EFI_PART="${SELECTED}p1"
        ROOT_PART="${SELECTED}p2"
    else
        EFI_PART="${SELECTED}1"
        ROOT_PART="${SELECTED}2"
    fi
    mkfs.fat -F32 "$EFI_PART" >/dev/null 2>&1
    mkfs.ext4 -F -q "$ROOT_PART" >/dev/null 2>&1
else
    UEFI=false
    parted -s "$SELECTED" mklabel msdos
    parted -s "$SELECTED" mkpart primary ext4 1MiB 100%
    parted -s "$SELECTED" set 1 boot on
    sleep 1
    if [[ "$SELECTED" == *nvme* ]] || [[ "$SELECTED" == *mmcblk* ]]; then
        ROOT_PART="${SELECTED}p1"
    else
        ROOT_PART="${SELECTED}1"
    fi
    mkfs.ext4 -F -q "$ROOT_PART" >/dev/null 2>&1
fi

echo "15"
echo "# Mounting target disk..."
mkdir -p /mnt/wolfstack-target
mount "$ROOT_PART" /mnt/wolfstack-target
if [ "$UEFI" = true ]; then
    mkdir -p /mnt/wolfstack-target/boot/efi
    mount "$EFI_PART" /mnt/wolfstack-target/boot/efi
fi

echo "20"
echo "# Copying system files (this takes several minutes)..."
rsync -aHAX --info=progress2 \
    --exclude='/proc/*' \
    --exclude='/sys/*' \
    --exclude='/dev/*' \
    --exclude='/run/*' \
    --exclude='/tmp/*' \
    --exclude='/mnt/*' \
    --exclude='/media/*' \
    --exclude='/live' \
    --exclude='/cdrom' \
    --exclude='/run/live' \
    --exclude='/lib/live' \
    / /mnt/wolfstack-target/ 2>/dev/null

echo "75"
echo "# Setting up system directories..."
mkdir -p /mnt/wolfstack-target/{proc,sys,dev,run,tmp,mnt,media}
chmod 1777 /mnt/wolfstack-target/tmp

echo "80"
echo "# Generating fstab..."
ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
echo "UUID=$ROOT_UUID / ext4 errors=remount-ro 0 1" > /mnt/wolfstack-target/etc/fstab
if [ "$UEFI" = true ]; then
    EFI_UUID=$(blkid -s UUID -o value "$EFI_PART")
    echo "UUID=$EFI_UUID /boot/efi vfat umask=0077 0 1" >> /mnt/wolfstack-target/etc/fstab
fi
echo "tmpfs /tmp tmpfs defaults,noatime,mode=1777 0 0" >> /mnt/wolfstack-target/etc/fstab

echo "82"
echo "# Setting hostname..."
echo "wolfstack" > /mnt/wolfstack-target/etc/hostname
cat > /mnt/wolfstack-target/etc/hosts << HOSTS
127.0.0.1   localhost
127.0.1.1   wolfstack
HOSTS

echo "85"
echo "# Setting root password..."
echo "root:${PASS1}" | chroot /mnt/wolfstack-target chpasswd -c SHA512 2>/dev/null

echo "87"
echo "# Binding filesystems for grub install..."
mount --bind /dev /mnt/wolfstack-target/dev
mount --bind /proc /mnt/wolfstack-target/proc
mount --bind /sys /mnt/wolfstack-target/sys
mount -t efivarfs efivarfs /mnt/wolfstack-target/sys/firmware/efi/efivars 2>/dev/null || true

echo "90"
echo "# Installing bootloader..."
if [ "$UEFI" = true ]; then
    chroot /mnt/wolfstack-target grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=WolfStack --recheck 2>/dev/null
else
    chroot /mnt/wolfstack-target grub-install --target=i386-pc "$SELECTED" --recheck 2>/dev/null
fi
chroot /mnt/wolfstack-target update-grub 2>/dev/null

echo "93"
echo "# Removing live-boot packages..."
chroot /mnt/wolfstack-target apt-get remove -y --purge live-boot live-config live-tools 2>/dev/null || true
chroot /mnt/wolfstack-target update-initramfs -u 2>/dev/null || true

echo "95"
echo "# Enabling services..."
chroot /mnt/wolfstack-target systemctl enable wolfnet 2>/dev/null
chroot /mnt/wolfstack-target systemctl enable wolfstack 2>/dev/null
chroot /mnt/wolfstack-target systemctl enable docker 2>/dev/null
chroot /mnt/wolfstack-target systemctl enable NetworkManager 2>/dev/null

# Remove the install desktop shortcut from the installed system
rm -f /mnt/wolfstack-target/usr/share/applications/wolfstack-install.desktop
rm -f /mnt/wolfstack-target/home/*/Desktop/wolfstack-install.desktop 2>/dev/null

echo "98"
echo "# Cleaning up..."
umount /mnt/wolfstack-target/sys/firmware/efi/efivars 2>/dev/null || true
umount /mnt/wolfstack-target/dev
umount /mnt/wolfstack-target/proc
umount /mnt/wolfstack-target/sys
if [ "$UEFI" = true ]; then
    umount /mnt/wolfstack-target/boot/efi
fi
umount /mnt/wolfstack-target
rmdir /mnt/wolfstack-target 2>/dev/null || true

echo "100"
echo "# Installation complete!"
) | zenity --progress \
    --title="Installing WolfStack" \
    --text="Preparing..." \
    --percentage=0 --auto-close --no-cancel \
    --width=450 2>/dev/null

zenity --info \
    --title="Installation Complete" \
    --text="WolfStack has been installed to <b>${SELECTED}</b> successfully!\n\nYou can now reboot and remove the USB drive.\nWolfStack will start automatically on port 8553.\n\nSystem login: root (with the password you set)\nDashboard login: wolfstack / wolfstack\n\nChange the dashboard password after first login!" \
    --width=400 2>/dev/null
INSTALLER
chmod +x "$FS/usr/local/bin/wolfstack-install-to-disk"

# --- Desktop shortcut for installer ---
cat > "$FS/usr/share/applications/wolfstack-install.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=Install WolfStack to Disk
Comment=Install WolfStack to your hard drive
Exec=wolfstack-install-to-disk
Icon=drive-harddisk
Terminal=false
Categories=System;
Keywords=install;disk;wolfstack;
EOF

# Place shortcut on live user's desktop
mkdir -p "$FS/etc/skel/Desktop"
cp "$FS/usr/share/applications/wolfstack-install.desktop" "$FS/etc/skel/Desktop/"
chmod +x "$FS/etc/skel/Desktop/wolfstack-install.desktop"

# Also put it directly in /home/user/Desktop for Debian Live's default user
mkdir -p "$FS/home/user/Desktop"
cp "$FS/usr/share/applications/wolfstack-install.desktop" "$FS/home/user/Desktop/"
chmod +x "$FS/home/user/Desktop/wolfstack-install.desktop"
chown -R 1000:1000 "$FS/home/user" 2>/dev/null || true

# --- Custom /etc/issue for console login ---
cat > "$FS/etc/issue" << 'EOF'

  WolfStack Live USB
  ──────────────────────────────
  Dashboard: http://127.0.0.1:8553
  Login:     wolfstack / wolfstack

  Everything is pre-installed — no internet needed.
  WolfStack starts automatically on boot.

  Service logs:    sudo journalctl -u wolfstack -u wolfnet -f
  Install to disk: sudo wolfstack-install-to-disk

EOF

# ── Rebuild squashfs ──
echo "[6/7] Rebuilding live filesystem (this takes a few minutes)..."
rm -f "$SQUASHFS_FILE"
mksquashfs "$BUILD_DIR/squashfs-root" "$SQUASHFS_FILE" -comp xz -Xbcj x86 -b 1M -no-duplicates

# Update filesystem.size
du -sx --block-size=1 "$BUILD_DIR/squashfs-root" | cut -f1 > "$(dirname "$SQUASHFS_FILE")/filesystem.size" 2>/dev/null || true

# ── Customize boot menu ──
echo "[7/7] Building ISO..."

# Find kernel and initrd filenames from the live directory
LIVE_VMLINUZ=$(basename "$(ls "$BUILD_DIR/iso/live/vmlinuz"* 2>/dev/null | head -1)" 2>/dev/null)
LIVE_INITRD=$(basename "$(ls "$BUILD_DIR/iso/live/initrd"* 2>/dev/null | head -1)" 2>/dev/null)
LIVE_VMLINUZ="${LIVE_VMLINUZ:-vmlinuz}"
LIVE_INITRD="${LIVE_INITRD:-initrd.img}"

# Rewrite GRUB config (UEFI boot)
if [ -f "$BUILD_DIR/iso/boot/grub/grub.cfg" ]; then
    cat > "$BUILD_DIR/iso/boot/grub/grub.cfg" << GRUBEOF
if loadfont /boot/grub/font.pf2 ; then
    set gfxmode=auto
    insmod efi_gop
    insmod efi_uga
    insmod vbe
    insmod vga
    insmod gfxterm
    terminal_output gfxterm
fi

set default=0
set timeout=10
set menu_color_normal=cyan/blue
set menu_color_highlight=white/blue

menuentry "WolfStack Live" {
    linux /live/${LIVE_VMLINUZ} boot=live components nomodeset splash quiet
    initrd /live/${LIVE_INITRD}
}

menuentry "WolfStack Live (Safe Graphics)" {
    linux /live/${LIVE_VMLINUZ} boot=live components nomodeset noapic noapm vga=normal quiet
    initrd /live/${LIVE_INITRD}
}

menuentry "WolfStack Live (Text Mode)" {
    linux /live/${LIVE_VMLINUZ} boot=live components nomodeset 3
    initrd /live/${LIVE_INITRD}
}
GRUBEOF
fi

# Rewrite isolinux live config (BIOS boot)
# Debian Live splits config across files — live.cfg has the boot entries
ISOLINUX_LIVE_CFG=$(find "$BUILD_DIR/iso/isolinux" -name "live*.cfg" 2>/dev/null | head -1)
if [ -n "$ISOLINUX_LIVE_CFG" ]; then
    cat > "$ISOLINUX_LIVE_CFG" << ISOLEOF
label live-amd64
    menu label ^WolfStack Live
    menu default
    linux /live/${LIVE_VMLINUZ}
    initrd /live/${LIVE_INITRD}
    append boot=live components nomodeset splash quiet

label live-amd64-safe
    menu label WolfStack Live (^Safe Graphics)
    linux /live/${LIVE_VMLINUZ}
    initrd /live/${LIVE_INITRD}
    append boot=live components nomodeset noapic noapm vga=normal quiet

label live-amd64-text
    menu label WolfStack Live (^Text Mode)
    linux /live/${LIVE_VMLINUZ}
    initrd /live/${LIVE_INITRD}
    append boot=live components nomodeset 3
ISOLEOF
elif [ -f "$BUILD_DIR/iso/isolinux/isolinux.cfg" ]; then
    # Monolithic config — add nomodeset to all boot entries
    sed -i 's/\(append.*boot=live.*\)/\1 nomodeset/' "$BUILD_DIR/iso/isolinux/isolinux.cfg" 2>/dev/null || true
    sed -i 's/menu label.*/menu label ^WolfStack Live/' "$BUILD_DIR/iso/isolinux/isolinux.cfg" 2>/dev/null || true
fi

# Update menu title
MENU_CFG=$(find "$BUILD_DIR/iso/isolinux" -name "menu.cfg" 2>/dev/null | head -1)
if [ -n "$MENU_CFG" ]; then
    sed -i 's/menu title.*/menu title WolfStack Live USB/' "$MENU_CFG" 2>/dev/null || true
fi

# Regenerate md5sum
cd "$BUILD_DIR/iso"
find . -type f ! -name md5sum.txt ! -path './isolinux/*' -exec md5sum {} \; > md5sum.txt 2>/dev/null || true

# Build ISO with xorriso (supports both BIOS and UEFI)
MBR_BIN=$(find /usr/lib -name isohdpfx.bin 2>/dev/null | head -1)
if [ -z "$MBR_BIN" ]; then
    # Try to extract from the original ISO
    MBR_BIN="$BUILD_DIR/isohdpfx.bin"
    dd if="$DEBIAN_LIVE_FILE" bs=1 count=432 of="$MBR_BIN" 2>/dev/null
fi

xorriso -as mkisofs \
    -o "$OUTPUT_ISO" \
    -isohybrid-mbr "$MBR_BIN" \
    -c isolinux/boot.cat \
    -b isolinux/isolinux.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot -isohybrid-gpt-basdat \
    -V "WOLFSTACK_${VERSION}" \
    "$BUILD_DIR/iso" 2>/dev/null

# ── Cleanup ──
rm -rf "$BUILD_DIR/iso" "$BUILD_DIR/squashfs-root"

ISO_SIZE=$(du -h "$OUTPUT_ISO" | cut -f1)

# Copy ISO to ../web (website directory) for upload
WEBSITE_DIR="$PROJECT_DIR/../web"
if [ -d "$WEBSITE_DIR" ]; then
    cp "$OUTPUT_ISO" "$WEBSITE_DIR/"
    echo "  ISO copied to ../web/ for website upload"
else
    echo "  WARNING: ../web/ directory not found — ISO not copied"
fi

echo ""
echo "  ======================================"
echo "  WolfStack Live USB Built Successfully!"
echo "  ======================================"
echo ""
echo "  Output:  $OUTPUT_ISO"
echo "  Web:     $WEBSITE_DIR/$(basename "$OUTPUT_ISO")"
echo "  Size:    $ISO_SIZE"
echo "  Version: $VERSION"
echo ""
echo "  Write to USB:"
echo "    sudo dd if=$OUTPUT_ISO of=/dev/sdX bs=4M status=progress"
echo ""
echo "  Or use Ventoy — just copy the ISO onto a Ventoy USB drive."
echo ""
echo "  The live USB boots straight into WolfStack — no internet needed."
echo "  Dashboard: http://127.0.0.1:8553  Login: wolfstack / wolfstack"
echo "  Use the 'Install WolfStack to Disk' shortcut to install permanently."
echo ""
