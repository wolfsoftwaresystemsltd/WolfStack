#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack Quick Install Script
# Installs WolfStack server management dashboard
# Supported: Ubuntu/Debian, Fedora/RHEL/CentOS, SLES/openSUSE, Arch Linux, IBM Power (ppc64le),
#            Unraid (auto-detected — installs the static-binary agent, no package manager needed)
#
# Usage (as root — Proxmox root login):
#        curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | bash
#        curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/beta/setup.sh | bash -s -- --beta
#        bash setup.sh --install-dir /mnt/usb           # build & install from external drive
# Usage (sudoer — Ubuntu/Debian):
#        curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash
#        sudo bash setup.sh
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
ASSUME_YES=false
AGENT_MODE=false
SKIP_PBS_BUILD=false
FORCE_PBS_BUILD=false
while [ $# -gt 0 ]; do
    case "$1" in
        --beta) BRANCH="beta" ;;
        --yes|-y|--assume-yes) ASSUME_YES=true ;;
        --agent) AGENT_MODE=true ;;
        --skip-pbs-build|--no-pbs-build) SKIP_PBS_BUILD=true ;;
        --build-pbs|--pbs-from-source) FORCE_PBS_BUILD=true ;;
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

# Existing install = upgrade. The /api/upgrade endpoint in older WolfStack
# binaries spawns this script via `curl|bash` without --yes, with stdin nulled
# out, so any interactive prompt would block the upgrade forever. If
# /etc/wolfstack exists this is an upgrade, not a fresh install — force
# unattended mode so the in-app "Upgrade" button actually completes.
if [ -d /etc/wolfstack ]; then
    ASSUME_YES=true
fi

# Allow git to operate on repos owned by other users (setup.sh runs as root
# but repos may have been cloned by a regular user)
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="*"

# ─── Architecture detection for prebuilt binaries ──────────────────────────
HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
    x86_64)  BINARY_ARCH="x86_64" ;;
    aarch64) BINARY_ARCH="aarch64" ;;
    *)       BINARY_ARCH="" ;;  # unsupported — will build from source
esac

# Download a prebuilt binary from GitHub Releases.
# Usage: download_prebuilt <repo> <binary_name> <dest_path>
# Returns 0 on success, 1 on failure (caller should fall back to source build)
download_prebuilt() {
    local repo="$1" binary="$2" dest="$3"
    if [ -z "$BINARY_ARCH" ]; then
        return 1
    fi
    local url="https://github.com/${repo}/releases/latest/download/${binary}-${BINARY_ARCH}"
    echo "  Downloading prebuilt ${binary} for ${BINARY_ARCH}..."
    local tmpfile="${dest}.download"
    if curl -fSL --connect-timeout 15 --max-time 300 --retry 2 -o "$tmpfile" "$url" 2>&1; then
        mv "$tmpfile" "$dest"
        chmod +x "$dest"
        echo "  ✓ Downloaded prebuilt ${binary} (${BINARY_ARCH})"
        return 0
    else
        echo "  ⚠ Prebuilt binary not available — will build from source"
        rm -f "$tmpfile"
        return 1
    fi
}

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
if [ "$AGENT_MODE" = true ]; then
    echo "  Mode: Agent (cluster API only — no management UI)"
    echo "  Manage this node from your master server's UI after install."
else
    echo "  Server Management Platform"
fi
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
    if command -v sudo >/dev/null 2>&1; then
        echo "  Usage: sudo bash setup.sh"
        echo "     or: curl -sSL <url> | sudo bash"
    else
        # Proxmox / minimal installs without sudo — operator is expected
        # to log in as root and run the script directly.
        echo "  sudo is not installed on this system. Log in as root and run:"
        echo "    bash setup.sh"
        echo "    curl -sSL <url> | bash"
    fi
    exit 1
fi

# Detect the real user (for Rust install) when running under sudo
REAL_USER="${SUDO_USER:-root}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ─── Unraid (Slackware, no package manager, no systemd, RAM-based OS) ────────
# Unraid boots from USB into RAM: /etc, /usr and /usr/local/bin are recreated
# on every boot, and there is no apt/dnf/etc. and no systemd — so the normal
# install path below cannot run (it dies at "Could not detect package manager").
# Instead we install the prebuilt static-musl binary onto the array
# (/mnt/user/appdata, which persists), symlink the config dir, and wire startup
# into /boot/config/go (Unraid's boot script). The node runs in --agent mode and
# is managed from a master node; agent mode serves an inline page and needs no
# on-disk web/ assets, so the single binary is self-sufficient. This must run
# BEFORE the package-manager check. See docs: "Installing WolfStack Agent on
# Unraid".
if [ -f /etc/unraid-version ]; then
    UNRAID_VER=$(tr -d '"' < /etc/unraid-version 2>/dev/null | sed -n 's/^version=//p')
    echo "✓ Detected Unraid ${UNRAID_VER:-(unknown version)} — using the static-binary agent install"
    echo ""

    # Unraid is always a managed AGENT node: there's no package manager to build
    # a full UI host, and full mode needs on-disk web/ assets we don't ship.
    AGENT_MODE=true

    if [ -z "$BINARY_ARCH" ]; then
        echo "✗ Unsupported CPU architecture '$HOST_ARCH' for Unraid."
        echo "  WolfStack ships prebuilt static binaries for x86_64 and aarch64 only,"
        echo "  and Unraid has no toolchain to build from source. Cannot continue."
        exit 1
    fi

    # Persistent storage MUST be the array — /usr/local/bin and /tmp are RAM and
    # vanish on reboot. Require /mnt/user (the array) to be started.
    WS_APPDATA="/mnt/user/appdata/wolfstack"
    if [ ! -d /mnt/user ]; then
        echo "✗ /mnt/user not found — the Unraid array doesn't appear to be started."
        echo "  Start the array (so /mnt/user/appdata is available), then re-run this script."
        exit 1
    fi
    mkdir -p "$WS_APPDATA/etc"

    # Stop any agent we previously started (upgrade / re-run) so the new binary
    # takes over the port cleanly.
    #
    # Match on "wolfstack --agent" only — NOT the absolute "$WS_APPDATA/..." path.
    # We start the agent with `cd "$WS_APPDATA" && ./wolfstack --agent`, so its
    # /proc/<pid>/cmdline is the RELATIVE `./wolfstack --agent`. The old absolute
    # pattern never matched it, so on every update the running agent was never
    # stopped: the new binary landed on disk but the old agent kept holding the
    # port, the freshly-started one couldn't bind, and the node "updated"
    # without errors yet stayed on the old version (klasSponsor, Unraid,
    # 2026-06-22). "wolfstack --agent" matches both the relative and absolute
    # forms; on an Unraid agent node it's the only such process.
    if pgrep -f "wolfstack --agent" >/dev/null 2>&1; then
        echo "  Stopping running WolfStack agent for upgrade..."
        pkill -f "wolfstack --agent" 2>/dev/null || true
        sleep 2
    fi

    # Download the static musl binary (the same release artifact the normal path
    # uses). Unraid can't build from source, so a failure here is fatal.
    if ! download_prebuilt "wolfsoftwaresystemsltd/WolfStack" "wolfstack" "$WS_APPDATA/wolfstack"; then
        echo "✗ Could not download the prebuilt WolfStack binary for $BINARY_ARCH."
        echo "  Check this server's internet access to github.com and re-run."
        exit 1
    fi

    # /etc is RAM-fresh each boot, so /etc/wolfstack must be a symlink onto the
    # array. -n replaces an existing symlink instead of descending into it.
    ln -sfn "$WS_APPDATA/etc" /etc/wolfstack
    ln -sf "$WS_APPDATA/wolfstack" /usr/local/bin/wolfstack

    # Wire startup into /boot/config/go (persists on the USB). Append an
    # idempotent, marker-delimited block — never clobber the rest of go, which
    # carries emhttp (Unraid's own UI) and any user customisations.
    GO_FILE="/boot/config/go"
    GO_START="# >>> WolfStack agent (managed by setup.sh) >>>"
    GO_END="# <<< WolfStack agent (managed by setup.sh) <<<"
    if [ ! -d /boot/config ]; then
        echo "  ⚠ /boot/config not found — cannot persist startup across reboots."
        echo "    The agent will run now but won't auto-start after a reboot."
    else
        if [ ! -f "$GO_FILE" ]; then
            # Very unusual on a real Unraid, but be safe: a fresh go still needs
            # the shebang and emhttp so the Unraid UI starts.
            printf '%s\n%s\n%s\n' '#!/bin/bash' '# Start the Management Utilities' '/usr/local/sbin/emhttp &' > "$GO_FILE"
            chmod +x "$GO_FILE" 2>/dev/null || true
        fi
        # Strip any previous WolfStack block (exact-line match, no regex
        # escaping), then append a fresh one.
        WS_GO_APPEND=true
        if grep -qF "$GO_START" "$GO_FILE"; then
            if awk -v s="$GO_START" -v e="$GO_END" \
                '$0==s{skip=1} skip&&$0==e{skip=0;next} !skip{print}' \
                "$GO_FILE" > "$GO_FILE.tmp"; then
                mv "$GO_FILE.tmp" "$GO_FILE"
            else
                rm -f "$GO_FILE.tmp"
                echo "  ⚠ Could not rewrite $GO_FILE cleanly — leaving the existing block in place."
                WS_GO_APPEND=false
            fi
        fi
        if [ "$WS_GO_APPEND" = true ]; then
            # Drop trailing blank lines first so repeated re-runs don't slowly
            # accumulate them above the block; then append with one separator.
            if awk 'NF{last=NR} {line[NR]=$0} END{for(i=1;i<=last;i++) print line[i]}' \
                "$GO_FILE" > "$GO_FILE.tmp"; then
                mv "$GO_FILE.tmp" "$GO_FILE"
            else
                rm -f "$GO_FILE.tmp"
            fi
            {
                printf '\n%s\n' "$GO_START"
                # /boot/config/go runs at boot BEFORE the Unraid array is
                # started, so /mnt/user/appdata (where the binary + config
                # live) does NOT exist yet. Starting the agent directly here
                # fails the `cd` and the node never comes back after a reboot —
                # this is the "node did not survive an Unraid update" bug.
                # Instead wait (in a backgrounded subshell, so `go` never
                # blocks boot / emhttp) for the binary to appear once the array
                # mounts, then symlink + launch. 180×5s = up to 15 min.
                printf '%s\n' "("
                printf '%s\n' "  for _i in \$(seq 1 180); do [ -x \"$WS_APPDATA/wolfstack\" ] && break; sleep 5; done"
                printf '%s\n' "  [ -x \"$WS_APPDATA/wolfstack\" ] || exit 0"
                printf '%s\n' "  ln -sfn \"$WS_APPDATA/etc\" /etc/wolfstack"
                printf '%s\n' "  ln -sf \"$WS_APPDATA/wolfstack\" /usr/local/bin/wolfstack"
                printf '%s\n' "  cd \"$WS_APPDATA\" && ./wolfstack --agent </dev/null >> \"$WS_APPDATA/wolfstack.log\" 2>&1"
                printf '%s\n' ") &"
                printf '%s\n' "$GO_END"
            } >> "$GO_FILE"
            echo "  ✓ Startup wired into $GO_FILE (survives reboots)"
        fi
    fi

    # Start the agent now (no reboot needed). nohup + background so it keeps
    # running after this script (often curl|bash) exits.
    echo "  Starting WolfStack agent..."
    # </dev/null so the backgrounded agent never holds the curl|bash pipe open.
    ( cd "$WS_APPDATA" && nohup ./wolfstack --agent </dev/null >> "$WS_APPDATA/wolfstack.log" 2>&1 & )
    sleep 3

    # awk (not grep -PoP) so it works on busybox grep too: pull the token after "src".
    WS_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
    [ -z "$WS_IP" ] && WS_IP="<this-unraid-ip>"

    echo ""
    echo "  ✅ WolfStack agent installed on Unraid"
    echo "  ─────────────────────────────────────"
    echo "  Binary:  $WS_APPDATA/wolfstack ($BINARY_ARCH static musl)"
    echo "  Config:  $WS_APPDATA/etc  (→ /etc/wolfstack)"
    echo "  Log:     $WS_APPDATA/wolfstack.log"
    echo "  Startup: $GO_FILE"
    echo ""
    echo "  This node runs in AGENT mode — manage it from your master node's UI:"
    echo "    master UI → + (bottom of the sidebar) → host $WS_IP, port 8554"
    if [ -s /etc/wolfstack/join-token ]; then
        echo "    join token: $(tr -d '\n\r' < /etc/wolfstack/join-token 2>/dev/null)"
    else
        echo "    join token: cat /etc/wolfstack/join-token   (once the agent has finished starting)"
    fi
    echo ""
    echo "  Verify:  tail -f $WS_APPDATA/wolfstack.log"
    echo ""
    # This Unraid branch is self-contained and exits before the rest of the
    # script. When run via `curl ... | bash`, exiting while curl still has the
    # remaining ~1500 lines to send breaks the pipe and curl dies with
    # "curl: (23) Failure writing output to destination" — alarming the user
    # even though the install succeeded. Drain the rest of the piped script
    # first so curl finishes cleanly. Guarded on a non-tty stdin so a direct
    # `bash setup.sh` (tty) never blocks waiting on the terminal.
    [ -t 0 ] || cat >/dev/null 2>&1 || true
    exit 0
fi

# ─── Detect package manager ─────────────────────────────────────────────────
echo "Checking system requirements..."

if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    echo "✓ Detected Debian/Ubuntu (apt)"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    echo "✓ Detected Fedora/RHEL (dnf)"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    echo "✓ Detected RHEL/CentOS (yum)"
elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
    echo "✓ Detected SLES/openSUSE (zypper)"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    echo "✓ Detected Arch Linux (pacman)"
else
    echo "✗ Could not detect package manager (apt/dnf/yum/zypper/pacman)"
    echo "  Please install dependencies manually."
    exit 1
fi

# ─── Pre-flight: warn about services we know will collide ──────────────────
# Adam Cogswell's feedback: WolfStack installs dnsmasq for LXC's bridge.
# On a host that already runs an authoritative resolver (Technitium,
# Pi-hole, AdGuard, bind, unbound), or a reverse proxy that owns :80/:443,
# the install can break the user's existing setup. We don't fail — we
# warn loudly and require explicit confirmation. Skip the prompt with
# --yes for unattended installs.
echo ""
echo "Pre-flight checks..."

WS_CONFLICT_FOUND=false
ws_warn() {
    WS_CONFLICT_FOUND=true
    echo "  ⚠ $1"
}

# Helper: is a port held by a non-wolfstack process?
ws_port_holder() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tnlp 2>/dev/null | awk -v p=":$port$" '$4 ~ p { for(i=1;i<=NF;i++) if($i ~ /users:/) print $i; exit }'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tnlp 2>/dev/null | awk -v p=":$port$" '$4 ~ p {print $7; exit}'
    fi
}

# DNS-on-:53 conflicts
DNS_HOLDER=$(ws_port_holder 53)
if [ -n "$DNS_HOLDER" ]; then
    case "$DNS_HOLDER" in
        *Technitium*|*technitium*)
            ws_warn "Technitium DNS Server is bound to :53. WolfStack installs dnsmasq for LXC; the global dnsmasq.service will be left disabled but the package install may still affect Technitium. Consider running WolfStack on a different host." ;;
        *pihole*|*pihole-FTL*)
            ws_warn "Pi-hole is bound to :53. Same caveat as Technitium — installing dnsmasq alongside Pi-hole's FTL can collide." ;;
        *AdGuardHome*|*AdGuard*)
            ws_warn "AdGuard Home is bound to :53. Installing dnsmasq alongside AdGuard can collide." ;;
        *systemd-resolve*)
            echo "  ℹ systemd-resolved is bound to :53 (stub listener). WolfStack handles this case automatically — leaving it alone." ;;
        *named*|*bind*)
            ws_warn "BIND (named) is bound to :53. Installing dnsmasq alongside BIND can collide." ;;
        *unbound*)
            ws_warn "Unbound is bound to :53. Installing dnsmasq alongside Unbound can collide." ;;
        *dnsmasq*)
            : ;; # already dnsmasq — fine
        *)
            ws_warn "Something is already bound to :53 ($DNS_HOLDER). Installing dnsmasq may collide." ;;
    esac
fi

# 8553 / 8554 / 8550 — the three ports WolfStack actually binds. 8553 is the
# management UI / API, 8554 is the inter-node HTTP listener (cluster proxy),
# 8550 is the dedicated public status-page listener. Calling all three out
# matters for firewall planning — users open just :8553 and wonder why
# inter-node sync or status pages don't work.
for port in 8553 8554 8550; do
    HOLDER=$(ws_port_holder "$port")
    if [ -n "$HOLDER" ] && [ "$HOLDER" != "${HOLDER#*wolfstack}" ]; then
        : # our own previous instance — fine on upgrade
    elif [ -n "$HOLDER" ]; then
        case "$port" in
            8553) ROLE="management UI / API" ;;
            8554) ROLE="inter-node cluster API" ;;
            8550) ROLE="public status pages" ;;
        esac
        ws_warn "Port $port ($ROLE) is already bound by $HOLDER. WolfStack will fail to bind it until that service is stopped or the port is moved in /etc/wolfstack/config.toml."
    fi
done

# Reverse proxies on 80/443 (we don't install one by default but WolfProxy
# component does — flag so the user knows).
for port in 80 443; do
    HOLDER=$(ws_port_holder "$port")
    if [ -n "$HOLDER" ]; then
        case "$HOLDER" in
            *nginx*|*apache*|*httpd*|*caddy*|*traefik*|*haproxy*)
                echo "  ℹ Reverse proxy detected on :$port ($HOLDER). WolfStack core will not touch :$port — only relevant if you install WolfProxy later." ;;
        esac
    fi
done

# Existing /etc/wolfstack/ from a prior install. The risk: re-running setup
# preserves the OLD join-token, cluster secret, and nodes.json, which on a
# fresh box looks like an upgrade but on a moved-disk-to-new-host can mean
# the new node ends up trying to join its old cluster with stale state.
IS_UPGRADE=false
if [ -d /etc/wolfstack ] && [ "$(ls -A /etc/wolfstack 2>/dev/null)" ]; then
    IS_UPGRADE=true
    echo "  ℹ /etc/wolfstack already exists with content — treating this as an upgrade. Existing config, cluster secret, and join token will be preserved."
    if [ -f /etc/wolfstack/custom-cluster-secret ]; then
        echo "    • Custom cluster secret is set on this node. If joining a NEW cluster, delete /etc/wolfstack/custom-cluster-secret and /etc/wolfstack/nodes.json before adding this node from the master."
    fi
fi

# Detect whether this upgrade is crossing the v23.11 boundary (when
# WolfStack started serving HTTPS by default on the main port). Only
# matters for upgraders who were running with NO TLS configured —
# they're about to switch from HTTP to HTTPS and their old http://
# URLs will stop working. We can't know the prior version reliably
# (the upgrade script might be running before the new binary lands),
# so we detect "was running HTTP-only" by absence of any TLS cert.
WAS_HTTP_ONLY=false
if [ "$IS_UPGRADE" = true ]; then
    if [ ! -f /etc/wolfstack/tls/cert.pem ] \
        && [ ! -f /etc/wolfstack/cert.pem ] \
        && [ ! -d /etc/letsencrypt/live ] \
        && ! grep -q '^[[:space:]]*tls_cert' /etc/wolfstack/config.toml 2>/dev/null \
        && ! grep -q '\-\-no-tls' /etc/systemd/system/wolfstack.service 2>/dev/null \
        && ! grep -q '\-\-tls-cert' /etc/systemd/system/wolfstack.service 2>/dev/null
    then
        WAS_HTTP_ONLY=true
    fi
fi

# Active firewall blocking 8553? Most homelab installs don't bother, but
# enterprise images ship with firewalld/ufw on. Surface it now so the user
# isn't troubleshooting "can't reach :8553" after install.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -qE "8553(/tcp)?\s+ALLOW"; then
        echo "  ℹ ufw is active and does not allow :8553. After install run: sudo ufw allow 8553/tcp 8554/tcp 8550/tcp"
    fi
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    if ! firewall-cmd --list-ports 2>/dev/null | grep -q "8553/tcp"; then
        echo "  ℹ firewalld is running and does not allow :8553. After install run: sudo firewall-cmd --permanent --add-port=8553/tcp --add-port=8554/tcp --add-port=8550/tcp && sudo firewall-cmd --reload"
    fi
fi

# Architecture: prebuilt binaries only ship for x86_64 / aarch64. Anything
# else falls through to source build, which is slow and can fail. Tell the
# user upfront so they can either accept the source-build path or bail.
case "$HOST_ARCH" in
    x86_64|aarch64) ;;
    *)
        echo "  ⚠ Architecture $HOST_ARCH has no prebuilt binary — WolfStack will be compiled from source (~10–30 min, ~3 GB free disk required in /tmp and \$HOME)."
        ;;
esac

# Summarise what's about to happen
echo ""
echo "  This will install / update on this host:"
echo "    • The wolfstack binary at /usr/local/bin/wolfstack"
echo "    • A systemd unit (wolfstack.service)"
echo "    • Listeners bound: :8553 (management UI), :8554 (inter-node), :8550 (status pages)"
echo "    • Build dependencies: git, curl, build tools, openssl headers"
echo "    • Runtime dependencies: lxc, dnsmasq (binary), bridge-utils, qemu, socat, nfs-client, fuse3, s3fs"
if [ "$AGENT_MODE" = true ]; then
    echo "    • Agent mode: SPA disabled, but ALL runtime deps above still installed —"
    echo "      every node has to be able to actually run containers/VMs/storage."
fi
echo "    • A cluster join token at /etc/wolfstack/join-token"
echo "    • A package manifest log at /var/log/wolfstack/install-<timestamp>.log"
echo "    • The uninstaller at /usr/local/bin/wolfstack-uninstall"

if [ "$WS_CONFLICT_FOUND" = true ]; then
    echo ""
    echo "  ⚠ Conflicts above were detected. Read them carefully before continuing."
fi

# Prompt unless --yes was passed or stdin isn't a tty (curl|bash case)
if [ "$ASSUME_YES" != true ]; then
    if [ -t 0 ] || [ -r /dev/tty ]; then
        echo ""
        printf "  Proceed with install? [y/N] "
        WS_REPLY=""
        if [ -t 0 ]; then
            read -r WS_REPLY
        else
            # stdin is a pipe (curl|bash) — read from /dev/tty if we have one
            read -r WS_REPLY < /dev/tty 2>/dev/null || WS_REPLY=""
        fi
        case "$WS_REPLY" in
            y|Y|yes|YES) ;;
            *)
                echo "  Aborted. Re-run with --yes to skip this prompt for unattended installs."
                exit 0
                ;;
        esac
    else
        # No tty available at all (e.g. CI without --yes). Be conservative — abort.
        if [ "$WS_CONFLICT_FOUND" = true ]; then
            echo ""
            echo "  ✗ Conflicts detected and no terminal to confirm interactively."
            echo "    Re-run with --yes to acknowledge and proceed:"
            echo "      curl -sSL <url> | sudo bash -s -- --yes"
            exit 1
        fi
    fi
fi
echo ""

# ─── Update system packages first ─────────────────────────────────────────
# Ensures package index is in sync and avoids dependency mismatches
# Refresh package index (needed to install dependencies) but do NOT upgrade existing packages.
# A full system upgrade can break things, takes ages, and the user didn't ask for it.
echo ""
echo "Refreshing package index..."
if [ "$PKG_MANAGER" = "apt" ]; then
    if ! apt update -qq 2>/dev/null; then
        echo "  ⚠ Some repositories failed to update."
        echo "    This is usually caused by a third-party repo (e.g. Docker) that doesn't"
        echo "    support your distro version. WolfStack will still install, but you may"
        echo "    need to fix the broken repo afterwards:"
        echo "      sudo apt update    (to see which repo is failing)"
        echo "      Check /etc/apt/sources.list.d/ for the problematic .list file"
        echo "    Continuing installation..."
    fi
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf makecache -q 2>/dev/null || true
elif [ "$PKG_MANAGER" = "zypper" ]; then
    zypper refresh -q 2>/dev/null || true
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy --noconfirm 2>/dev/null || true
fi
echo "✓ Package index refreshed"

# ─── Detect Proxmox VE host ─────────────────────────────────────────────────
IS_PROXMOX=false
if command -v pveversion >/dev/null 2>&1 || [ -f /etc/pve/.version ] || dpkg -l proxmox-ve >/dev/null 2>&1 2>&1; then
    IS_PROXMOX=true
    PVE_VER=$(pveversion 2>/dev/null || echo "unknown")
    echo "✓ Detected Proxmox VE host ($PVE_VER)"
    echo "  Skipping packages already provided by Proxmox (QEMU, LXC)"
fi

# ─── Install manifest: snapshot package state BEFORE we install anything ───
# Goal: produce a record at /var/log/wolfstack/install-<timestamp>.log of
# every package that was added or upgraded by this run, so a user who needs
# to roll back has a precise list of what changed. We snapshot here (before
# any install commands run) and again right before the completion banner;
# the diff is the manifest. This catches every package-manager call in the
# script without having to wrap each one individually.
WS_MANIFEST_DIR="/var/log/wolfstack"
WS_MANIFEST_TS="$(date +%Y%m%d-%H%M%S)"
WS_MANIFEST_FILE="$WS_MANIFEST_DIR/install-$WS_MANIFEST_TS.log"
WS_PKG_BEFORE="$WS_MANIFEST_DIR/.pkg-before-$$"
WS_PKG_AFTER="$WS_MANIFEST_DIR/.pkg-after-$$"
mkdir -p "$WS_MANIFEST_DIR" 2>/dev/null || true
chmod 750 "$WS_MANIFEST_DIR" 2>/dev/null || true

ws_snapshot_packages() {
    local out="$1"
    : > "$out" 2>/dev/null || return 0
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | sort > "$out"
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort > "$out"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Q 2>/dev/null | tr ' ' '\t' | sort > "$out"
    fi
}
ws_snapshot_packages "$WS_PKG_BEFORE"

# ─── Install system dependencies ────────────────────────────────────────────
echo ""
echo "Installing system dependencies..."

# Snapshot dnsmasq.service state BEFORE we run the package install.
# Several distros (Fedora/RHEL/CentOS/openSUSE/Arch) ship the full
# dnsmasq package with a systemd unit that auto-starts and binds
# 0.0.0.0:53 — which collides with systemd-resolved's stub listener
# on 127.0.0.53:53 and breaks host DNS resolution. We need the dnsmasq
# BINARY for LXC's lxcbr0 (lxc-net launches its own scoped dnsmasq),
# but we don't want the global service stomping on port 53.
#
# We only auto-disable the service when WE caused it to exist — i.e.
# when the unit wasn't on disk at all before we started. If the user
# had already installed and configured dnsmasq as their system
# resolver before running setup.sh, that state is recorded here and
# we leave it strictly alone.
DNSMASQ_PRE_STATE=""
if systemctl list-unit-files dnsmasq.service >/dev/null 2>&1; then
    if systemctl is-enabled --quiet dnsmasq.service 2>/dev/null; then
        DNSMASQ_PRE_STATE="enabled"
    elif systemctl is-active --quiet dnsmasq.service 2>/dev/null; then
        DNSMASQ_PRE_STATE="active"
    else
        DNSMASQ_PRE_STATE="installed-disabled"
    fi
fi

# Install packages resiliently — NEVER abort setup if some are unavailable.
# set -e is active, so an unguarded `apt/dnf/... install` of a long list dies
# entirely when one package is renamed/missing or a mirror/third-party repo is
# flaky, taking the whole installer down with it. We try a bulk install first
# (fast, co-resolves deps); on failure we retry each package alone so one bad
# name doesn't block the rest, warn about what's left, and carry on. A package
# that's genuinely required but still missing fails loudly later at build time.
ws_install_pkgs() {
    local cmd
    case "$PKG_MANAGER" in
        apt)    cmd="apt install -y" ;;
        # skip_if_unavailable: a leftover broken docker-ce.repo (a prior
        # failed install whose $releasever 404s) must not abort the whole
        # dependency install — skip the dead repo instead of wedging dnf,
        # which is how a WolfStack update "killed Docker" on Oracle Linux.
        dnf)    cmd="dnf install -y --setopt=*.skip_if_unavailable=True" ;;
        yum)    cmd="yum install -y --setopt=*.skip_if_unavailable=True" ;;
        zypper) cmd="zypper install -y" ;;
        pacman) cmd="pacman -Sy --noconfirm --needed" ;;
        *) echo "  ⚠ Unknown package manager '$PKG_MANAGER' — skipping install of: $*"; return 0 ;;
    esac
    if $cmd "$@"; then
        return 0
    fi
    echo "  ⚠ Bulk package install failed — retrying individually so one bad package doesn't stop the rest..."
    local pkg failed=""
    for pkg in "$@"; do
        $cmd "$pkg" >/dev/null 2>&1 || failed="$failed $pkg"
    done
    if [ -n "$failed" ]; then
        echo "  ⚠ Could not install:$failed"
        echo "    Continuing anyway — install these by hand if a feature turns out to be missing."
    fi
    return 0
}

if [ "$PKG_MANAGER" = "apt" ]; then
    apt update -qq 2>/dev/null || true
    # On Proxmox hosts, QEMU and LXC are already provided by pve-qemu-kvm and lxc-pve.
    # Many Debian packages conflict with PVE equivalents, causing APT to try removing
    # the proxmox-ve metapackage. We must be very conservative on PVE hosts.
    if [ "$IS_PROXMOX" = true ]; then
        # Only install build dependencies needed for compiling Rust/WolfStack.
        # Proxmox already provides QEMU, LXC, socat, bridge-utils, etc.
        apt install -y --no-install-recommends git curl build-essential pkg-config libssl-dev libcrypt-dev || {
            echo "⚠ Some build dependencies failed to install. Trying individually..."
            for pkg in git curl build-essential pkg-config libssl-dev libcrypt-dev; do
                dpkg -s "$pkg" >/dev/null 2>&1 || apt install -y --no-install-recommends "$pkg" 2>/dev/null || true
            done
        }
        # Install optional runtime deps one-by-one — skip if already provided by PVE
        for pkg in dnsmasq-base bridge-utils socat nfs-common fuse3; do
            if dpkg -s "$pkg" >/dev/null 2>&1; then
                echo "  ✓ $pkg already installed"
            else
                echo "  Installing $pkg..."
                apt install -y --no-install-recommends "$pkg" 2>/dev/null || \
                    echo "  ⚠ Could not install $pkg (may conflict with PVE) — skipping"
            fi
        done
        # s3fs — try both package names (s3fs-fuse on Kali/some Debian, s3fs on Ubuntu/Proxmox)
        if ! dpkg -s s3fs-fuse >/dev/null 2>&1 && ! dpkg -s s3fs >/dev/null 2>&1; then
            apt install -y --no-install-recommends s3fs-fuse 2>/dev/null || \
                apt install -y --no-install-recommends s3fs 2>/dev/null || \
                echo "  ⚠ s3fs not available — S3 mounts will use built-in sync"
        fi
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
        # apparmor + apparmor-utils are Recommends (not Depends) of lxc on
        # Debian/Ubuntu — minimal cloud images skip them with -y, then the
        # first `lxc-start` fails with "apparmor_parser not available".
        # Pin them explicitly so containers actually start out of the box.
        ws_install_pkgs git curl build-essential pkg-config libssl-dev libcrypt-dev lxc lxc-templates apparmor apparmor-utils dnsmasq-base bridge-utils $QEMU_PKG socat nfs-common fuse3
        apt install -y s3fs-fuse 2>/dev/null || apt install -y s3fs 2>/dev/null || echo "  ⚠ s3fs not available — S3 mounts will use built-in sync"
    fi
elif [ "$PKG_MANAGER" = "dnf" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_DNF="qemu-system-aarch64 qemu-img edk2-aarch64"
    else
        QEMU_DNF="qemu-kvm qemu-img"
    fi
    ws_install_pkgs git curl gcc gcc-c++ make openssl-devel pkg-config libxcrypt-devel lxc lxc-templates lxc-extra dnsmasq bridge-utils $QEMU_DNF socat s3fs-fuse nfs-utils fuse3
elif [ "$PKG_MANAGER" = "yum" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_YUM="qemu-system-aarch64 qemu-img"
    else
        QEMU_YUM="qemu-kvm qemu-img"
    fi
    ws_install_pkgs git curl gcc gcc-c++ make openssl-devel pkgconfig lxc lxc-templates lxc-extra dnsmasq bridge-utils $QEMU_YUM socat s3fs-fuse nfs-utils fuse
elif [ "$PKG_MANAGER" = "zypper" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_ZYPP="qemu-arm qemu-tools qemu-uefi-aarch64"
    else
        QEMU_ZYPP="qemu-kvm qemu-tools"
    fi
    # SUSE uses AppArmor by default — same Recommends-not-Depends trap.
    ws_install_pkgs git curl gcc gcc-c++ make libopenssl-devel pkg-config lxc apparmor-parser apparmor-utils dnsmasq bridge-utils $QEMU_ZYPP socat s3fs nfs-client fuse3
elif [ "$PKG_MANAGER" = "pacman" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_PAC="qemu-system-aarch64 qemu-img edk2-aarch64"
    else
        QEMU_PAC="qemu-full"
    fi
    ws_install_pkgs git curl base-devel openssl pkg-config lxc dnsmasq $QEMU_PAC socat s3fs-fuse nfs-utils fuse3 rustup
fi

# Decide whether to disable the freshly-installed dnsmasq.service.
# We act only when ALL of these are true:
#   1. The unit didn't exist before we ran (DNSMASQ_PRE_STATE empty)
#      — i.e. we caused it to come into existence. If the user had
#      dnsmasq pre-installed/configured as their system resolver, we
#      leave it alone.
#   2. The unit exists now (the package install actually placed it).
#   3. systemd-resolved is active. Without it, there's no port-53
#      conflict to worry about — the user may be relying on dnsmasq
#      or another resolver and we shouldn't second-guess.
#   4. The unit is now active (auto-started by the install).
# When all four hold, the install just created a port-53 collision
# that breaks host DNS — disable the service to clear it. The dnsmasq
# binary stays installed so LXC's lxcbr0 can launch its own scoped
# dnsmasq via lxc-net (--bind-interfaces --interface=lxcbr0).
if [ -z "$DNSMASQ_PRE_STATE" ] \
   && systemctl list-unit-files dnsmasq.service >/dev/null 2>&1 \
   && systemctl is-active --quiet systemd-resolved 2>/dev/null \
   && systemctl is-active --quiet dnsmasq.service 2>/dev/null; then
    echo "  Package install auto-started dnsmasq.service (binds 0.0.0.0:53)"
    echo "  systemd-resolved is also active (binds 127.0.0.53:53) — these will conflict and break host DNS."
    echo "  Disabling dnsmasq.service. LXC's lxcbr0 gets its own scoped dnsmasq via lxc-net (unaffected)."
    echo "  If you intended to use dnsmasq as your system resolver, run:"
    echo "    sudo systemctl disable --now systemd-resolved"
    echo "    sudo systemctl enable --now dnsmasq"
    systemctl disable --now dnsmasq.service 2>/dev/null || true
fi

echo "✓ System dependencies installed"

# ─── Install Proxmox Backup Client (optional, for PBS integration) ──────────
echo ""
echo "Installing Proxmox Backup Client..."

# Helper: detect the best PBS codename to use based on current OS
pbs_detect_codename() {
    local codename=""
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        codename="${VERSION_CODENAME:-}"
    fi
    [ -z "$codename" ] && codename=$(lsb_release -sc 2>/dev/null || echo "")
    case "$codename" in
        # Debian — use as-is (proxmox publishes for these)
        trixie|bookworm|bullseye) echo "$codename" ;;
        # Ubuntu codenames mapped to closest Debian
        noble|oracular|plucky) echo "trixie" ;;       # 24.04+/25.04 → Debian 13
        jammy|lunar|mantic)    echo "bookworm" ;;     # 22.04–23.10 → Debian 12
        focal|impish)          echo "bullseye" ;;     # 20.04–21.10 → Debian 11
        # Unknown/everything else — trixie is newest; extraction will fallback
        *) echo "trixie" ;;
    esac
}

# Helper: extract proxmox-backup-client binary from Debian .deb
# Used on non-Debian systems (Fedora, Arch fallback, openSUSE)
pbs_extract_from_deb() {
    local codename="$1"
    local arch="${2:-amd64}"
    local tmp
    tmp=$(mktemp -d)
    local base_url="http://download.proxmox.com/debian/pbs/dists/${codename}/pbs-no-subscription/binary-${arch}/"
    local deb_name
    deb_name=$(curl -fsSL "$base_url" 2>/dev/null | grep -oP 'proxmox-backup-client_[^"]+\.deb' | grep -v dbgsym | sort -V | tail -1)
    if [ -z "$deb_name" ]; then
        rm -rf "$tmp"
        return 1
    fi
    echo "  Downloading $deb_name (${codename}/${arch})..." >&2
    if ! curl -fsSL "${base_url}${deb_name}" -o "${tmp}/${deb_name}" 2>/dev/null; then
        rm -rf "$tmp"; return 1
    fi
    ( cd "$tmp" && ar x "$deb_name" 2>/dev/null ) || { rm -rf "$tmp"; return 1; }
    local data_tar
    data_tar=$(ls "$tmp"/data.tar.* 2>/dev/null | head -1)
    [ -z "$data_tar" ] && { rm -rf "$tmp"; return 1; }
    case "$data_tar" in
        *.zst) zstd -d -q "$data_tar" -o "$tmp/data.tar" 2>/dev/null || { rm -rf "$tmp"; return 1; } ;;
        *.xz)  xz -d -k "$data_tar" 2>/dev/null || { rm -rf "$tmp"; return 1; } ;;
        *.gz)  gzip -dk "$data_tar" 2>/dev/null || { rm -rf "$tmp"; return 1; } ;;
    esac
    if ! tar -C "$tmp" -xf "$tmp/data.tar" ./usr/bin/proxmox-backup-client 2>/dev/null; then
        rm -rf "$tmp"; return 1
    fi
    install -m 0755 "$tmp/usr/bin/proxmox-backup-client" /usr/local/bin/proxmox-backup-client
    rm -rf "$tmp"
    return 0
}

pbs_install_success=false

if command -v proxmox-backup-client >/dev/null 2>&1; then
    echo "✓ proxmox-backup-client already installed ($(proxmox-backup-client --version 2>&1 | head -1))"
    pbs_install_success=true

elif command -v apt-get >/dev/null 2>&1; then
    # ─── Debian / Ubuntu / Proxmox VE ──────────────────────────────────────
    CODENAME=$(pbs_detect_codename)
    echo "  Using Proxmox PBS repo for: $CODENAME"
    mkdir -p /etc/apt/sources.list.d /etc/apt/trusted.gpg.d
    echo "deb http://download.proxmox.com/debian/pbs $CODENAME pbs-no-subscription" > /etc/apt/sources.list.d/pbs-client.list
    curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-${CODENAME}.gpg" \
        -o "/etc/apt/trusted.gpg.d/proxmox-release-${CODENAME}.gpg" 2>/dev/null || true

    if apt-get update -qq 2>/dev/null && apt-get install -y proxmox-backup-client 2>/dev/null; then
        echo "✓ proxmox-backup-client installed from $CODENAME repo"
        pbs_install_success=true
    elif [ "$CODENAME" != "bookworm" ]; then
        echo "  ⚠ $CODENAME install failed — trying bookworm repo"
        echo "deb http://download.proxmox.com/debian/pbs bookworm pbs-no-subscription" > /etc/apt/sources.list.d/pbs-client.list
        curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg" \
            -o "/etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg" 2>/dev/null || true
        if apt-get update -qq 2>/dev/null && apt-get install -y proxmox-backup-client 2>/dev/null; then
            echo "✓ proxmox-backup-client installed from bookworm repo"
            pbs_install_success=true
        fi
    fi

elif command -v pacman >/dev/null 2>&1; then
    # ─── Arch / CachyOS / Manjaro ──────────────────────────────────────────
    # Required libraries for the binary: libfuse3, openssl 3, acl, zstd
    pacman -S --needed --noconfirm fuse3 openssl acl zstd 2>/dev/null || true

    # Try AUR helper first (paru or yay) — builds clean Arch package
    AUR_HELPER=""
    for h in paru yay; do
        if command -v "$h" >/dev/null 2>&1; then AUR_HELPER="$h"; break; fi
    done
    if [ -n "$AUR_HELPER" ] && [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        echo "  Using $AUR_HELPER to build proxmox-backup-client-bin from AUR..."
        if su - "$SUDO_USER" -c "$AUR_HELPER -S --needed --noconfirm proxmox-backup-client-bin" 2>/dev/null; then
            pbs_install_success=true
        fi
    fi
    if [ "$pbs_install_success" != "true" ]; then
        echo "  Falling back to Debian .deb extraction..."
        if pbs_extract_from_deb trixie amd64 || pbs_extract_from_deb bookworm amd64; then
            echo "✓ proxmox-backup-client installed to /usr/local/bin/"
            pbs_install_success=true
        fi
    fi

elif command -v dnf >/dev/null 2>&1; then
    # ─── Fedora / RHEL / Rocky / AlmaLinux ─────────────────────────────────
    dnf install -y fuse3 openssl libacl zstd 2>/dev/null || true
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    if pbs_extract_from_deb trixie "$ARCH" || pbs_extract_from_deb bookworm "$ARCH"; then
        echo "✓ proxmox-backup-client installed to /usr/local/bin/"
        pbs_install_success=true
    fi

elif command -v zypper >/dev/null 2>&1; then
    # ─── openSUSE ──────────────────────────────────────────────────────────
    zypper install -y fuse3 openssl libacl1 libzstd1 2>/dev/null || true
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    if pbs_extract_from_deb trixie "$ARCH" || pbs_extract_from_deb bookworm "$ARCH"; then
        echo "✓ proxmox-backup-client installed to /usr/local/bin/"
        pbs_install_success=true
    fi

else
    # ─── Unknown distro — try generic .deb extract ─────────────────────────
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    if pbs_extract_from_deb trixie "$ARCH" || pbs_extract_from_deb bookworm "$ARCH"; then
        echo "✓ proxmox-backup-client installed to /usr/local/bin/"
        pbs_install_success=true
    fi
fi

# ─── Source-build fallback for architectures Proxmox doesn't ship binaries for ─
# Proxmox publishes proxmox-backup-client ONLY for amd64
# (http://download.proxmox.com/debian/pbs/dists/{bookworm,trixie}/pbs-no-subscription/
# only has binary-amd64/). Every other architecture — Raspberry Pi (aarch64),
# Apple Silicon Linux (aarch64), ARM servers (aarch64), armv7l Pis — silently
# fails the .deb extraction path above. This block builds the client crate from
# source via cargo so PBS backup destinations work on ARM hosts.
#
# Skip with --skip-pbs-build if you don't need PBS and don't want to wait
# 20-30 min on a Pi. Force a rebuild attempt with --build-pbs even on amd64.
pbs_build_from_source() {
    local target_arch="${HOST_ARCH:-$(uname -m)}"
    echo ""
    echo "  Building proxmox-backup-client from source for $target_arch..."
    echo "  This takes ~20-30 minutes on a Raspberry Pi 4. Re-run setup.sh"
    echo "  with --skip-pbs-build to skip on next upgrade if you don't need PBS."

    if ! command -v cargo >/dev/null 2>&1; then
        echo "  ✗ Cargo (Rust toolchain) not found — cannot build from source."
        echo "    Install Rust first: https://rustup.rs/  then re-run setup.sh"
        return 1
    fi

    # Build dependencies. The proxmox-backup-client crate links libssl, libacl,
    # libfuse3 (for fuse-mount of pxar archives), and libsystemd. Names vary
    # by distro — best-effort install, build will fail loudly if any are missing.
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y --no-install-recommends \
            git build-essential pkg-config clang \
            libssl-dev libacl1-dev libfuse3-dev libsystemd-dev uuid-dev 2>/dev/null \
            || echo "  ⚠ Some build deps may be missing — continuing anyway"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y git gcc gcc-c++ make pkgconf-pkg-config clang \
            openssl-devel libacl-devel fuse3-devel systemd-devel libuuid-devel 2>/dev/null \
            || echo "  ⚠ Some build deps may be missing — continuing anyway"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --needed --noconfirm git base-devel pkg-config clang \
            openssl acl fuse3 systemd-libs util-linux 2>/dev/null \
            || echo "  ⚠ Some build deps may be missing — continuing anyway"
    elif command -v zypper >/dev/null 2>&1; then
        zypper install -y git gcc gcc-c++ make pkg-config clang \
            libopenssl-devel libacl-devel fuse3-devel systemd-devel libuuid-devel 2>/dev/null \
            || echo "  ⚠ Some build deps may be missing — continuing anyway"
    fi

    local src="${CUSTOM_INSTALL_DIR:-/var/cache/wolfstack}/proxmox-backup-src"
    rm -rf "$src"
    mkdir -p "$(dirname "$src")"

    if ! git clone --depth 1 https://git.proxmox.com/git/proxmox-backup.git "$src" 2>&1 | tail -3; then
        echo "  ✗ Could not clone proxmox-backup source from git.proxmox.com"
        rm -rf "$src"
        return 1
    fi

    # Build only the client crate. The wider workspace pulls in PBS-server
    # crates (proxmox-backup-server, daemons, web UI assets) that need
    # extra build infrastructure we don't want to drag in for the client.
    # Re-use the swap created earlier in the wolfstack source-build block
    # if memory is tight (1GB Pi 3, 2GB Pi 4).
    local cargo_jobs=""
    local total_kb
    total_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
    if [ -n "$total_kb" ] && [ "$total_kb" -lt 4000000 ]; then
        cargo_jobs="-j 1"
        echo "  Low memory detected — limiting build to one job"
    fi

    if ! ( cd "$src" && cargo build --release $cargo_jobs --bin proxmox-backup-client ) 2>&1 | tail -15; then
        echo "  ✗ cargo build failed — see output above"
        echo "    The proxmox-backup workspace can be sensitive to system library"
        echo "    versions. If openssl-sys, libfuse-sys, or proxmox-* crates"
        echo "    failed, install the matching -devel/-dev packages and re-run."
        rm -rf "$src"
        return 1
    fi

    if [ -x "$src/target/release/proxmox-backup-client" ]; then
        install -m 0755 "$src/target/release/proxmox-backup-client" /usr/local/bin/proxmox-backup-client
        echo "  ✓ proxmox-backup-client built and installed to /usr/local/bin/"
        rm -rf "$src"
        return 0
    fi
    rm -rf "$src"
    return 1
}

if [ "$pbs_install_success" != "true" ] && [ "$SKIP_PBS_BUILD" != "true" ]; then
    # Tell the user WHY the install failed (most likely: arch mismatch).
    case "$HOST_ARCH" in
        x86_64)
            echo "  ⚠ proxmox-backup-client install failed on x86_64 — unusual."
            echo "    Network or repo issue likely. Skipping source build (the apt"
            echo "    path should have worked). Re-run with --build-pbs to force"
            echo "    a from-source attempt anyway."
            ;;
        aarch64|arm64|armv7l|armv6l)
            echo ""
            echo "  ℹ Proxmox doesn't publish proxmox-backup-client binaries for $HOST_ARCH."
            echo "    The Debian PBS repo at download.proxmox.com only has binary-amd64/."
            echo "    Falling back to source build so PBS backup destinations work here."
            pbs_build_from_source && pbs_install_success=true
            ;;
        *)
            echo "  ℹ No upstream proxmox-backup-client binary for $HOST_ARCH."
            echo "    Attempting source build via cargo..."
            pbs_build_from_source && pbs_install_success=true
            ;;
    esac
fi

# Allow `--build-pbs` to force a source build on amd64 too (useful for users
# who want to track upstream master rather than the published bookworm/trixie
# .deb releases).
if [ "$pbs_install_success" = "true" ] && [ "$FORCE_PBS_BUILD" = "true" ]; then
    echo "  --build-pbs requested — replacing installed binary with source build"
    pbs_build_from_source || true
fi
if [ "$pbs_install_success" != "true" ] && [ "$FORCE_PBS_BUILD" = "true" ]; then
    pbs_build_from_source && pbs_install_success=true
fi

if [ "$pbs_install_success" != "true" ]; then
    echo ""
    echo "  ⚠ proxmox-backup-client is NOT installed on this host."
    echo "    Impact: PBS backup destinations in WolfStack will not work."
    echo "    Workarounds — these backup destinations all work without PBS client:"
    echo "      • Local filesystem"
    echo "      • S3 / S3-compatible (Backblaze B2, MinIO, etc.)"
    echo "      • NFS mount"
    echo "      • SMB / CIFS share"
    echo "      • SSHFS to a remote WolfStack node"
    echo "      • WolfDisk replication"
    echo "    Manual install (if you really need PBS): https://pbs.proxmox.com/docs/backup-client.html"
fi

# Fix libfuse3 soname: proxmox-backup-client links against libfuse3.so.3
# but some distros (CachyOS, rolling Arch) have soname 4 (libfuse3.so.4)
if command -v proxmox-backup-client >/dev/null 2>&1; then
    for libdir in /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do
        if [ ! -e "$libdir/libfuse3.so.3" ] && [ -e "$libdir/libfuse3.so.4" ]; then
            FUSE3_REAL=$(readlink -f "$libdir/libfuse3.so.4")
            ln -sf "$FUSE3_REAL" "$libdir/libfuse3.so.3"
            echo "  ✓ Created $libdir/libfuse3.so.3 symlink (soname compat)"
        fi
    done
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

# Lock down /etc/wolfstack — it holds the cluster secret, PVE API
# tokens inside nodes.json, the join-token, and license.key. Before
# v18.7.27 these files were world-readable (inherited process umask),
# which let any unprivileged local user impersonate a cluster member
# or siphon PVE credentials. The running binary also enforces this
# on startup (paths::harden_existing); tightening here too closes
# the window on very first install before wolfstack has started.
chmod 700 /etc/wolfstack 2>/dev/null || true
for f in /etc/wolfstack/custom-cluster-secret \
         /etc/wolfstack/cluster-secret \
         /etc/wolfstack/nodes.json \
         /etc/wolfstack/join-token \
         /etc/wolfstack/license.key \
         /etc/wolfstack/key.pem; do
    if [ -e "$f" ]; then
        chmod 600 "$f" 2>/dev/null || true
    fi
done

# ─── Install Docker if missing ──────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    echo ""
    echo "Installing Docker..."
    DOCKER_INSTALLED=false

    # Try the official convenience script first (works for Ubuntu, Debian, Fedora, CentOS, RHEL)
    if curl -fsSL https://get.docker.com | sh 2>/dev/null; then
        DOCKER_INSTALLED=true
    else
        # Convenience script failed — likely a derivative distro (Nobara, Rocky, Alma, etc.)
        # Detect the distro family from /etc/os-release and set up Docker repo manually
        echo "  Convenience script failed — trying manual Docker repo setup..."
        DISTRO_ID=$(. /etc/os-release 2>/dev/null && echo "$ID")
        DISTRO_LIKE=$(. /etc/os-release 2>/dev/null && echo "$ID_LIKE")
        DISTRO_VERSION=$(. /etc/os-release 2>/dev/null && echo "$VERSION_ID")

        if echo "$DISTRO_ID" | grep -qiE '^(ol|rhel|centos|rocky|almalinux|alma|scientific|oracle|virtuozzo)$' \
            || echo "$DISTRO_LIKE" | grep -qiE 'rhel|centos'; then
            # RHEL/CentOS family — INCLUDING Oracle Linux. Checked BEFORE Fedora
            # on purpose: Oracle Linux 10 / RHEL 10 set ID_LIKE="fedora", so a
            # plain `grep fedora` (the old first branch) wrongly sent them to the
            # Fedora repo, which seds $releasever to e.g. "10.1" and 404s on
            # download.docker.com/linux/fedora/10.1/. The leftover broken repo
            # then makes EVERY later dnf/yum run fail — which is how a failed
            # WolfStack install "killed Docker" on Oracle Linux and persisted
            # after uninstall (wabil 2026-06-14).
            echo "  Detected RHEL/CentOS family (${DISTRO_ID}) — using the CentOS Docker repo"
            # Heal a box left broken by a PRIOR failed install: an earlier
            # WolfStack version mis-added a Fedora docker-ce.repo with a bogus
            # $releasever, and that 404'ing repo makes every dnf/yum run fail.
            # Clear it before any dnf op so re-running setup.sh recovers the box.
            rm -f /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
            dnf -y install dnf-plugins-core 2>/dev/null || yum install -y yum-utils 2>/dev/null || true
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || \
                dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || \
                dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || true
            if yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || \
               dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null; then
                DOCKER_INSTALLED=true
            else
                # Docker may not publish a repo for a brand-new EL major yet.
                # Remove the repo we just added so a 404'ing repo can't break
                # every subsequent dnf/yum run (the root of the OL breakage).
                rm -f /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
            fi
        elif echo "$DISTRO_ID $DISTRO_LIKE" | grep -qiE "fedora"; then
            # Genuine Fedora family (Nobara, Ultramarine, etc.) — Fedora repo.
            # Use the major Fedora version the derivative is based on.
            FEDORA_VER="$DISTRO_VERSION"
            if [ "$DISTRO_ID" != "fedora" ]; then
                PLATFORM_ID=$(. /etc/os-release 2>/dev/null && echo "$PLATFORM_ID")
                if echo "$PLATFORM_ID" | grep -q "fedora"; then
                    FEDORA_VER=$(echo "$PLATFORM_ID" | grep -oP 'f\K[0-9]+' || echo "$DISTRO_VERSION")
                fi
            fi
            echo "  Detected Fedora family (${DISTRO_ID} based on Fedora ${FEDORA_VER})"
            dnf -y install dnf-plugins-core 2>/dev/null || true
            dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo 2>/dev/null || \
                dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo 2>/dev/null || true
            # Override $releasever with actual Fedora version for derivatives
            if [ "$DISTRO_ID" != "fedora" ] && [ -n "$FEDORA_VER" ]; then
                sed -i "s/\$releasever/${FEDORA_VER}/g" /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
            fi
            if dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
                DOCKER_INSTALLED=true
            else
                # Don't leave a broken repo behind — it would break later dnf runs.
                rm -f /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
            fi
        elif echo "$DISTRO_ID $DISTRO_LIKE" | grep -qiE "suse|sles"; then
            # openSUSE/SLES — use distro docker packages
            echo "  Detected SUSE family (${DISTRO_ID})"
            if zypper install -y docker docker-compose 2>/dev/null; then
                DOCKER_INSTALLED=true
            fi
        elif echo "$DISTRO_ID $DISTRO_LIKE" | grep -qiE "debian|ubuntu"; then
            # Debian derivatives (Mint, Pop!_OS, etc.) — use Debian/Ubuntu Docker repo
            UPSTREAM="debian"
            CODENAME=$(. /etc/os-release 2>/dev/null && echo "$UBUNTU_CODENAME")
            if [ -n "$CODENAME" ]; then
                UPSTREAM="ubuntu"
            else
                CODENAME=$(. /etc/os-release 2>/dev/null && echo "$VERSION_CODENAME")
                # For rolling/derivative distros (Kali, Parrot, etc.), Docker has no matching repo
                # Fall back to a known Debian stable codename
                if [ -z "$CODENAME" ] || echo "$CODENAME" | grep -qiE "rolling|sid|unstable"; then
                    CODENAME="bookworm"
                fi
            fi
            echo "  Detected Debian family (${DISTRO_ID}, using ${UPSTREAM}/${CODENAME})"
            # Try distro's own docker package first (works on Kali, Parrot, ARM, etc.)
            if apt install -y docker.io 2>/dev/null; then
                echo "  ✓ Installed docker.io from distro repos"
                DOCKER_INSTALLED=true
            else
                # Fall back to Docker's official repo. Docker is optional, so
                # every step here is best-effort — a failed key fetch or apt
                # update must not abort the whole installer (set -e). If any
                # step fails the final `docker-ce` install simply won't flip
                # DOCKER_INSTALLED and setup carries on without Docker.
                apt install -y ca-certificates curl gnupg 2>/dev/null || true
                install -m 0755 -d /etc/apt/keyrings || true
                curl -fsSL "https://download.docker.com/linux/${UPSTREAM}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
                chmod a+r /etc/apt/keyrings/docker.gpg 2>/dev/null || true
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${UPSTREAM} ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list || true
                apt update -qq 2>/dev/null || true
                if apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null; then
                    DOCKER_INSTALLED=true
                fi
            fi
        elif echo "$DISTRO_ID $DISTRO_LIKE" | grep -qiE "arch|manjaro"; then
            # Arch family
            echo "  Detected Arch family (${DISTRO_ID})"
            if pacman -Sy --noconfirm docker docker-compose 2>/dev/null; then
                DOCKER_INSTALLED=true
            fi
        fi
    fi

    if [ "$DOCKER_INSTALLED" = true ]; then
        systemctl enable docker 2>/dev/null || true
        systemctl start docker 2>/dev/null || true
        echo "✓ Docker installed"

        # ─── Configure Docker DNS ────────────────────────────────────
        # systemd-resolved puts 127.0.0.53 in /etc/resolv.conf which
        # is unreachable from inside Docker containers (their own
        # loopback). Detect the real upstream nameservers and write
        # them to daemon.json so containers get working DNS.
        WS_DOCKER_DNS=""
        if command -v resolvectl >/dev/null 2>&1; then
            WS_DOCKER_DNS=$(resolvectl status 2>/dev/null \
                | grep -E 'DNS Servers?:' | head -3 \
                | sed 's/.*: *//' | tr ' ' '\n' \
                | grep -vE '^127\.' | head -3 | tr '\n' ' ')
        fi
        if [ -z "$(echo "$WS_DOCKER_DNS" | xargs)" ]; then
            WS_DOCKER_DNS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null \
                | awk '{print $2}' | grep -vE '^127\.' | head -3 | tr '\n' ' ')
        fi
        WS_DOCKER_DNS=$(echo "$WS_DOCKER_DNS" | xargs)  # trim
        [ -z "$WS_DOCKER_DNS" ] && WS_DOCKER_DNS="8.8.8.8 1.1.1.1"

        # Build JSON array: "8.8.8.8 1.1.1.1" → ["8.8.8.8","1.1.1.1"]
        WS_DNS_JSON=$(echo "$WS_DOCKER_DNS" | tr ' ' '\n' | grep -v '^$' \
            | sed 's/.*/"&"/' | paste -sd, | sed 's/.*/[&]/')

        DAEMON_JSON="/etc/docker/daemon.json"
        mkdir -p /etc/docker
        if [ -f "$DAEMON_JSON" ] && command -v python3 >/dev/null 2>&1 \
            && python3 -c "import json; json.load(open('$DAEMON_JSON'))" 2>/dev/null; then
            # Merge into existing daemon.json — preserve other keys
            python3 -c "
import json, sys
try:
    with open('$DAEMON_JSON') as f: cfg = json.load(f)
    cfg['dns'] = json.loads('$WS_DNS_JSON')
    with open('$DAEMON_JSON', 'w') as f: json.dump(cfg, f, indent=2)
except Exception:
    sys.exit(1)
" 2>/dev/null || echo "{\"dns\": $WS_DNS_JSON}" > "$DAEMON_JSON"
        else
            echo "{\"dns\": $WS_DNS_JSON}" > "$DAEMON_JSON"
        fi
        systemctl restart docker 2>/dev/null || true
        echo "  ✓ Docker DNS configured ($WS_DOCKER_DNS)"
    else
        echo ""
        echo "  ⚠ Docker could not be installed automatically."
        echo "    Your distro may not be directly supported by Docker's official repos."
        echo "    WolfStack will still work for LXC containers, VMs, and server management."
        echo "    To add Docker support, install it manually:"
        echo "      https://docs.docker.com/engine/install/"
        if [ "$PKG_MANAGER" = "apt" ]; then
            echo "    Or try: sudo apt install docker.io  (community package, may be older)"
        elif [ "$PKG_MANAGER" = "dnf" ]; then
            echo "    Or try: sudo dnf install docker  (community package)"
        elif [ "$PKG_MANAGER" = "pacman" ]; then
            echo "    Or try: sudo pacman -S docker  (community package)"
        elif [ "$PKG_MANAGER" = "zypper" ]; then
            echo "    Or try: sudo zypper install docker  (community package)"
        fi
        echo ""
    fi
else
    echo "✓ Docker already installed"
fi

# ─── Install WolfNet (cluster network layer) ────────────────────────────────

# Helper: download prebuilt WolfNet binaries or build from source.
# Sets WOLFNET_BUILT=true on success.
# Requires WOLFNET_SRC_DIR to be set if building from source.
build_or_download_wolfnet() {
    # Try prebuilt first
    if download_prebuilt "wolfsoftwaresystemsltd/WolfNet" "wolfnet" "/usr/local/bin/wolfnet"; then
        download_prebuilt "wolfsoftwaresystemsltd/WolfNet" "wolfnetctl" "/usr/local/bin/wolfnetctl" || true
        WOLFNET_BUILT=true
        return 0
    fi

    # Fall back to source build
    if [ -z "$WOLFNET_SRC_DIR" ] || [ ! -d "$WOLFNET_SRC_DIR" ]; then
        echo "  ✗ WolfNet source not available and no prebuilt binary — skipping"
        WOLFNET_BUILT=false
        return 1
    fi

    export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:/usr/local/bin:/usr/bin:$PATH"
    if ! command -v cargo >/dev/null 2>&1; then
        echo "  ⚠ Cargo not found — skipping WolfNet rebuild"
        WOLFNET_BUILT=false
        return 1
    fi

    echo "  Building WolfNet from source..."
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
    WOLFNET_BUILT=true
    return 0
}

echo ""
echo "Checking WolfNet (cluster networking)..."

if command -v wolfnet >/dev/null 2>&1 && systemctl is-active --quiet wolfnet 2>/dev/null; then
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

    # Update binaries (prebuilt or source)
    systemctl stop wolfnet 2>/dev/null || true
    if build_or_download_wolfnet; then
        systemctl start wolfnet 2>/dev/null || true
        echo "  ✓ WolfNet updated and restarted"
    else
        systemctl start wolfnet 2>/dev/null || true
    fi

elif command -v wolfnet >/dev/null 2>&1 && [ -f "/etc/systemd/system/wolfnet.service" ]; then
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

    if build_or_download_wolfnet; then
        echo "  ✓ WolfNet updated"
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

    # Try prebuilt binary first, fall back to source build
    WOLFNET_SRC_DIR="${CUSTOM_INSTALL_DIR:-/opt}/wolfnet-src"
    if ! build_or_download_wolfnet; then
        # Prebuilt failed and source wasn't available yet — clone and retry
        echo "  Downloading WolfNet source..."
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

        if ! command -v cargo >/dev/null 2>&1; then
            echo "  Installing Rust first..."
            if [ -n "$CUSTOM_INSTALL_DIR" ] || [ "$REAL_USER" = "root" ]; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            else
                su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
            fi
            export PATH="${CARGO_HOME:-$REAL_HOME/.cargo}/bin:$PATH"
        fi

        build_or_download_wolfnet
    fi
    echo "  ✓ WolfNet binary installed"

    # Configure WolfNet for cluster use
    mkdir -p /etc/wolfnet /var/run/wolfnet

    if [ ! -f "/etc/wolfnet/config.toml" ]; then
        # Auto-assign a cluster IP based on the last octet of the host IP
        HOST_IP=$(ip -4 route show default 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
        [ -z "$HOST_IP" ] && HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
        [ -z "$HOST_IP" ] && HOST_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}')
        [ -z "$HOST_IP" ] && HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        [ -z "$HOST_IP" ] && HOST_IP=$(hostname -i 2>/dev/null | awk '{print $1}')
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
            if ! ping -c 1 -W 1 "$WOLFNET_IP" >/dev/null 2>&1; then
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


# ─── Upgrade WolfProxy if installed and outdated ─────────────────────────────
# WolfProxy is an optional companion (the reverse proxy) installed separately,
# but when WolfStack updates we pull any newer WolfProxy too so unit/binary
# fixes reach existing installs without a separate step — notably the
# orphan-reaping ExecStartPre that resolves the "ports 80/443 in use" loop.
# WolfProxy's own setup.sh downloads the latest prebuilt binary AND rewrites the
# systemd unit, so re-running it upgrades both. Best-effort — never block the
# WolfStack install on it, and never trigger an upgrade when the version probe
# is inconclusive (empty WP_LATEST).
echo ""
echo "Checking WolfProxy (reverse proxy)..."
if command -v wolfproxy >/dev/null 2>&1 || [ -f /etc/systemd/system/wolfproxy.service ]; then
    WP_INSTALLED="$(wolfproxy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")"
    WP_LATEST="$(curl -fsSL https://api.github.com/repos/wolfsoftwaresystemsltd/wolfproxy/releases/latest 2>/dev/null \
        | grep -oE '"tag_name"[^"]*"v?[0-9]+\.[0-9]+\.[0-9]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")"
    if [ -n "$WP_LATEST" ] && [ "$WP_INSTALLED" != "$WP_LATEST" ]; then
        echo "  WolfProxy ${WP_INSTALLED:-unknown} → ${WP_LATEST} available — upgrading..."
        if curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | bash; then
            echo "  ✓ WolfProxy upgraded to ${WP_LATEST}"
        else
            echo "  ⚠ WolfProxy upgrade failed — re-run manually: curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash"
        fi
    elif [ -n "$WP_INSTALLED" ]; then
        echo "  ✓ WolfProxy up to date (${WP_INSTALLED})"
    else
        echo "  ✓ WolfProxy present"
    fi
else
    echo "  WolfProxy not installed — skipping (install it from the WolfStack Configurator if you want a reverse proxy)."
fi


# ─── Install Rust if not present ────────────────────────────────────────────
CARGO_BIN="${CARGO_HOME:-$REAL_HOME/.cargo}/bin/cargo"

if [ -f "$CARGO_BIN" ]; then
    echo "✓ Rust already installed"
elif command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
    echo "✓ Rust already installed (system-wide)"
elif command -v rustup >/dev/null 2>&1; then
    # rustup installed (e.g. via pacman on Arch) but no toolchain set yet
    echo "  Setting default Rust toolchain via rustup..."
    rustup default stable
    echo "✓ Rust installed via rustup"
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

if ! command -v cargo >/dev/null 2>&1; then
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
    if ! git fetch origin 2>/dev/null; then
        echo "  ⚠ Git repo corrupted — re-cloning..."
        cd /
        rm -rf "$INSTALL_DIR"
        git clone -b $BRANCH https://github.com/wolfsoftwaresystemsltd/WolfStack.git "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    else
        git checkout -B $BRANCH origin/$BRANCH
        git reset --hard origin/$BRANCH
    fi
else
    git clone -b $BRANCH https://github.com/wolfsoftwaresystemsltd/WolfStack.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Show what we're building
BUILT_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "✓ Repository ready ($INSTALL_DIR)"
echo "  Branch: $BRANCH | Version: $BUILT_VERSION"

# ─── Build or download WolfStack ───────────────────────────────────────────
echo ""

# Flag restart if service is running (for upgrades)
if systemctl is-active --quiet wolfstack 2>/dev/null; then
    echo "WolfStack service is running — will restart after upgrade."
    RESTART_SERVICE=true
else
    RESTART_SERVICE=false
fi

echo ""
if [ -f "/usr/local/bin/wolfstack" ]; then
    echo "Upgrading WolfStack..."
else
    echo "Installing WolfStack..."
fi

# Try prebuilt binary first — saves disk space, memory, and build time
WOLFSTACK_PREBUILT=false
if download_prebuilt "wolfsoftwaresystemsltd/WolfStack" "wolfstack" "/usr/local/bin/wolfstack"; then
    WOLFSTACK_PREBUILT=true
else
    # Fall back to building from source
    echo "Building WolfStack from source (this may take a few minutes)..."

    # Source build needs serious disk space — Cargo's target/ regularly hits
    # 2-4 GB for a release build, plus the rust toolchain in $CARGO_HOME.
    # Bail loudly here rather than letting the user discover an out-of-space
    # error 15 minutes into a `cargo build`. Skip when the user pointed
    # CARGO_TARGET_DIR at a custom mount (they've already planned space).
    BUILD_DIR="${CARGO_TARGET_DIR:-${CUSTOM_INSTALL_DIR:-$INSTALL_DIR}}"
    BUILD_FREE_KB=$(df -Pk "$BUILD_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$BUILD_FREE_KB" ] && [ "$BUILD_FREE_KB" -lt 3145728 ]; then
        FREE_GB=$(( BUILD_FREE_KB / 1024 / 1024 ))
        echo "  ⚠ Only ${FREE_GB} GB free at $BUILD_DIR. Source build needs ~3 GB."
        echo "    Free up space, or pass --install-dir /path/to/larger/disk to redirect"
        echo "    Cargo's target directory and toolchain to an external mount."
        if [ "$ASSUME_YES" != true ]; then
            if [ -t 0 ] || [ -r /dev/tty ]; then
                printf "  Continue anyway and risk an out-of-space failure mid-build? [y/N] "
                WS_REPLY=""
                if [ -t 0 ]; then read -r WS_REPLY
                else read -r WS_REPLY < /dev/tty 2>/dev/null || WS_REPLY=""; fi
                case "$WS_REPLY" in y|Y|yes|YES) ;; *) echo "  Aborted."; exit 1 ;; esac
            else
                echo "  Aborting — re-run with --yes to override."
                exit 1
            fi
        fi
    fi

    # Force full rebuild to ensure the new version takes effect
    echo "  Cleaning previous build..."
    CLEAN_TARGET="${CARGO_TARGET_DIR:-$INSTALL_DIR/target}"
    rm -rf "$CLEAN_TARGET/release/wolfstack" "$CLEAN_TARGET/release/.fingerprint/wolfstack-"*

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

    BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-$INSTALL_DIR/target}"
    cp "$BUILD_TARGET_DIR/release/wolfstack" /usr/local/bin/wolfstack
    chmod +x /usr/local/bin/wolfstack
fi

echo "✓ wolfstack installed to /usr/local/bin/wolfstack"

# ─── Drop a local copy of uninstall.sh ──────────────────────────────────────
# Adam Cogswell's feedback: when DNS or networking gets broken (e.g. dnsmasq
# vs Technitium collision) the user can't curl uninstall.sh to recover.
# Stash a copy at /usr/local/bin/wolfstack-uninstall so it's reachable
# offline. We fetch from the same branch this setup.sh came from. If the
# fetch fails we still write a minimal stub so the user has *something*.
WS_UNINSTALL_DEST="/usr/local/bin/wolfstack-uninstall"
WS_UNINSTALL_URL="https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/${BRANCH}/uninstall.sh"
WS_UNINSTALL_FETCHED=false
if command -v curl >/dev/null 2>&1; then
    if curl -fsSL --connect-timeout 10 --max-time 60 -o "${WS_UNINSTALL_DEST}.new" "$WS_UNINSTALL_URL" 2>/dev/null; then
        if head -1 "${WS_UNINSTALL_DEST}.new" 2>/dev/null | grep -q '^#!'; then
            mv "${WS_UNINSTALL_DEST}.new" "$WS_UNINSTALL_DEST"
            chmod 0755 "$WS_UNINSTALL_DEST"
            WS_UNINSTALL_FETCHED=true
            echo "✓ Uninstall script saved to $WS_UNINSTALL_DEST"
        else
            rm -f "${WS_UNINSTALL_DEST}.new"
        fi
    fi
fi
if [ "$WS_UNINSTALL_FETCHED" != true ]; then
    # Fallback stub — covers the 90% case (stop the service + remove the
    # binary + the systemd unit). Anything beyond this needs the full
    # uninstall.sh from the repo, but at least the user gets back to a
    # bootable state without internet.
    cat > "$WS_UNINSTALL_DEST" <<'WSUNINSTALL_STUB'
#!/bin/bash
# WolfStack offline-uninstall stub. The full uninstaller could not be
# fetched at install time. This stub does the minimum needed to recover:
# stop the service, remove the binary, remove the systemd unit. Run
# without arguments. Add --purge to also wipe /etc/wolfstack and the
# install manifest log directory.
set -e
PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "wolfstack-uninstall must be run as root (use: sudo wolfstack-uninstall)." >&2
    else
        echo "wolfstack-uninstall must be run as root (log in as root, then re-run)." >&2
    fi
    exit 1
fi
echo "Stopping wolfstack…"
systemctl stop wolfstack 2>/dev/null || true
systemctl disable wolfstack 2>/dev/null || true
rm -f /etc/systemd/system/wolfstack.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/wolfstack
if [ "$PURGE" = true ]; then
    rm -rf /etc/wolfstack /var/log/wolfstack
    echo "Purged /etc/wolfstack and /var/log/wolfstack."
fi
echo "Stub uninstall complete. For a full uninstall (WolfNet/WolfProxy/etc.)"
echo "fetch the full script: curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/uninstall.sh | sudo bash"
WSUNINSTALL_STUB
    chmod 0755 "$WS_UNINSTALL_DEST"
    echo "⚠ Could not fetch full uninstall.sh — wrote offline stub to $WS_UNINSTALL_DEST"
fi

# AI knowledge base is now compiled into the binary — no separate install needed
echo "✓ AI knowledge base embedded in binary"

# ─── Install WolfUSB ────────────────────────────────────────────────────────
echo ""
echo "Installing WolfUSB..."

# Install libusb (required by wolfusb)
if command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm libusb 2>/dev/null || true
elif command -v apt-get >/dev/null 2>&1; then
    apt-get install -y libusb-1.0-0 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y libusbx 2>/dev/null || dnf install -y libusb1 2>/dev/null || true
elif command -v zypper >/dev/null 2>&1; then
    zypper install -y libusb-1_0-0 2>/dev/null || true
fi

# Stop service for upgrade
systemctl stop wolfusb 2>/dev/null || true

# Install/update wolfusb binary via its official setup.sh (handles platform detection)
if curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfusb/main/setup.sh | bash; then
    echo "  ✓ WolfUSB binary installed"
else
    echo "  ⚠ WolfUSB install failed (non-critical)"
fi

# Configure WolfUSB with the cluster secret as its auth key
mkdir -p /etc/wolfusb
CLUSTER_SECRET_FILE="/etc/wolfstack/custom-cluster-secret"
if [ -f "$CLUSTER_SECRET_FILE" ] && [ -s "$CLUSTER_SECRET_FILE" ]; then
    WOLFUSB_KEY_VALUE=$(cat "$CLUSTER_SECRET_FILE" | tr -d '\n\r')
else
    # Use the compiled-in default (wolfstack will use this as well)
    WOLFUSB_KEY_VALUE="wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3"
fi
cat > /etc/wolfusb/wolfusb.env << ENV
WOLFUSB_BIND=0.0.0.0
WOLFUSB_PORT=3240
WOLFUSB_KEY=${WOLFUSB_KEY_VALUE}
ENV
chmod 600 /etc/wolfusb/wolfusb.env

# Install systemd unit
cat > /etc/systemd/system/wolfusb.service << 'UNIT'
[Unit]
Description=WolfUSB Server
After=network.target

[Service]
Type=simple
Environment=WOLFUSB_BIND=0.0.0.0
Environment=WOLFUSB_PORT=3240
EnvironmentFile=-/etc/wolfusb/wolfusb.env
ExecStart=/usr/local/bin/wolfusb server --bind ${WOLFUSB_BIND} --port ${WOLFUSB_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Udev rules for USB device access
mkdir -p /etc/udev/rules.d
echo 'SUBSYSTEM=="usb", MODE="0666", GROUP="plugdev"' > /etc/udev/rules.d/99-wolfusb.rules
udevadm control --reload-rules 2>/dev/null || true

# USB/IP kernel module setup.
# Each wolfstack node is both a potential client (needs vhci-hcd) AND server
# (needs usbip-host). On most distros these live in a "kernel-modules-extra"
# style package that ISN'T installed by default. First try loading; if that
# fails, install the right package for the distro, then try again.
wolfusb_try_modprobe() {
    modprobe vhci-hcd 2>/dev/null || modprobe vhci_hcd 2>/dev/null || true
    modprobe usbip-host 2>/dev/null || modprobe usbip_host 2>/dev/null || true
    [ -d /sys/devices/platform/vhci_hcd.0 ] && \
        [ -d /sys/bus/usb/drivers/usbip-host ]
}

wolfusb_install_modules_pkg() {
    # Read distro once
    local ID="" LIKE=""
    if [ -r /etc/os-release ]; then
        ID=$(. /etc/os-release && echo "${ID:-}")
        LIKE=$(. /etc/os-release && echo "${ID_LIKE:-}")
    fi
    case "$ID $LIKE" in
        *arch*|*manjaro*|*cachyos*|*endeavouros*)
            # Arch: modules come with the kernel package; nothing extra needed.
            return 1
            ;;
        *fedora*|*rhel*|*centos*|*rocky*|*alma*)
            # Fedora/RHEL family: kernel-modules-extra
            dnf install -y kernel-modules-extra 2>/dev/null || \
                yum install -y kernel-modules-extra 2>/dev/null || return 1
            ;;
        *debian*|*ubuntu*|*pop*|*linuxmint*|*elementary*|*raspbian*)
            # Debian/Ubuntu family: linux-modules-extra-$(uname -r)
            # Fall back to the meta-package when the exact kernel build isn't
            # available (common with third-party/self-built kernels).
            apt-get update 2>/dev/null || true
            apt-get install -y "linux-modules-extra-$(uname -r)" 2>/dev/null || \
                apt-get install -y linux-modules-extra-generic 2>/dev/null || \
                apt-get install -y linux-image-extra-"$(uname -r)" 2>/dev/null || \
                return 1
            ;;
        *suse*|*sles*|*opensuse*)
            zypper install -y kernel-default-extra 2>/dev/null || return 1
            ;;
        *alpine*)
            # Alpine's default kernel (linux-lts/linux-virt) has usbip built in
            # for some image variants, missing on others. Try the modules pkg.
            apk add --no-cache linux-lts 2>/dev/null || return 1
            ;;
        *)
            # Unknown distro — can't guess the package name
            return 1
            ;;
    esac
    return 0
}

mkdir -p /etc/modules-load.d
printf 'vhci-hcd\nusbip-core\nusbip-host\n' > /etc/modules-load.d/wolfusb.conf

if ! wolfusb_try_modprobe; then
    echo "  USB/IP kernel modules not available — installing modules package..."
    if wolfusb_install_modules_pkg && wolfusb_try_modprobe; then
        :  # success
    fi
fi

if [ -d /sys/devices/platform/vhci_hcd.0 ] && \
   [ -d /sys/bus/usb/drivers/usbip-host ]; then
    echo "  ✓ USB/IP kernel modules loaded (vhci-hcd + usbip-host)"
    echo "    Node can both share local USB devices and mount remote ones."
else
    echo "  ⚠ USB/IP kernel modules unavailable on this kernel."
    echo "    Remote USB device passthrough will not work until these are"
    echo "    installed. Try:"
    echo "      Fedora/RHEL:   dnf install kernel-modules-extra && reboot"
    echo "      Debian/Ubuntu: apt install linux-modules-extra-\$(uname -r)"
    echo "      openSUSE:      zypper install kernel-default-extra && reboot"
    echo "      Arch:          usually already present; ensure stock linux kernel"
    echo "    Container/cloud-optimised kernels (GCP COS, Bottlerocket, etc.)"
    echo "    generally cannot run usbip-host and are not supported."
fi

systemctl daemon-reload
systemctl enable wolfusb 2>/dev/null || true
systemctl restart wolfusb 2>/dev/null || systemctl start wolfusb 2>/dev/null || true

if systemctl is-active --quiet wolfusb 2>/dev/null; then
    echo "  ✓ WolfUSB service running on port 3240"
else
    echo "  ⚠ WolfUSB service not running — check: journalctl -u wolfusb -n 20"
fi

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
    WS_PORT=$(echo "$WS_PORT" | tr -d '[:space:][:cntrl:]')
    WS_PORT=${WS_PORT:-8553}
    # Validate port is a number between 1-65535, fallback to default
    if ! echo "$WS_PORT" | grep -qE '^[0-9]+$' || [ "$WS_PORT" -lt 1 ] 2>/dev/null || [ "$WS_PORT" -gt 65535 ] 2>/dev/null; then
        echo "  ⚠ Invalid port '$WS_PORT' — using default 8553"
        WS_PORT=8553
    fi

    # Prompt for bind address
    echo -n "Bind address [0.0.0.0]: "
    prompt_read WS_BIND
    WS_BIND=$(echo "$WS_BIND" | tr -d '[:cntrl:]' | xargs)
    WS_BIND=${WS_BIND:-0.0.0.0}
    # Validate bind is a valid IP pattern, fallback to default
    if ! echo "$WS_BIND" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "  ⚠ Invalid bind address '$WS_BIND' — using default 0.0.0.0"
        WS_BIND="0.0.0.0"
    fi

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
    echo "  Dashboard: https://$WS_BIND:$WS_PORT"
else
    echo ""
    echo "✓ Config already exists at /etc/wolfstack/config.toml"
    echo "  (Upgrade mode - skipping configuration prompts)"
    # Read port and bind from existing config
    WS_PORT=$(grep "^port" /etc/wolfstack/config.toml 2>/dev/null | head -1 | awk '{print $3}' | tr -d '[:space:][:cntrl:]' || echo "8553")
    WS_PORT=${WS_PORT:-8553}
    WS_BIND=$(grep "^bind" /etc/wolfstack/config.toml 2>/dev/null | head -1 | sed 's/.*"\(.*\)"/\1/' | tr -d '[:space:][:cntrl:]' || echo "0.0.0.0")
    WS_BIND=${WS_BIND:-0.0.0.0}
fi

# ─── Create systemd service ─────────────────────────────────────────────────
if [ ! -f "/etc/systemd/system/wolfstack.service" ]; then
    echo ""
    echo "  ──────────────────────────────────────────────────"
    echo "  Creating systemd service..."
    echo "  ──────────────────────────────────────────────────"
    echo ""

    # In agent mode, the binary is run with --agent which disables the
    # management SPA but keeps the cluster API. The flag is part of the
    # ExecStart line so a manual edit + daemon-reload is enough to flip
    # an agent into a full server later (or vice versa).
    AGENT_FLAG=""
    [ "$AGENT_MODE" = true ] && AGENT_FLAG=" --agent"

    cat > /etc/systemd/system/wolfstack.service <<EOF
[Unit]
Description=WolfStack - Server Management Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wolfstack --port $WS_PORT --bind $WS_BIND${AGENT_FLAG}
WorkingDirectory=/opt/wolfstack
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Only signal the main WolfStack process on stop/restart — never the whole
# control group. WolfStack daemonizes native QEMU VMs (qemu -daemonize) and
# spawns other long-lived children; with the systemd default of
# KillMode=control-group a routine WolfStack restart/upgrade would SIGTERM
# those guests too, taking running VMs down with the management plane.
# KillMode=process leaves them running so "restart WolfStack" updates only
# WolfStack — guests survive (PapaSchlumpf 2026-06: Home Assistant VM killed
# by an in-app upgrade on a raw/native WolfStack host).
KillMode=process

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
    # Server↔agent flip handling. We only modify the ExecStart= line on a
    # rerun and only when the user explicitly asked for the OTHER mode —
    # so a plain `setup.sh` with no flag never alters an existing unit's
    # mode. The original unit is backed up to .pre-agent-flip so the user
    # can recover any custom edits we may have stomped.
    UNIT_FILE="/etc/systemd/system/wolfstack.service"
    EXISTING_AGENT=false
    if grep -qE '^ExecStart=.* --agent( |$)' "$UNIT_FILE" 2>/dev/null; then
        EXISTING_AGENT=true
    fi
    if [ "$AGENT_MODE" = true ] && [ "$EXISTING_AGENT" = false ]; then
        echo "  → Flipping unit from SERVER to AGENT mode (--agent appended to ExecStart=)"
        cp "$UNIT_FILE" "${UNIT_FILE}.pre-agent-flip"
        # Append " --agent" to any ExecStart line that targets our binary
        # and doesn't already have the flag. Anchor to /usr/local/bin/wolfstack
        # so we don't touch unrelated ExecStartPre/Post lines.
        sed -i -E 's|^(ExecStart=/usr/local/bin/wolfstack[^\n]*?)(\s*)$|\1 --agent\2|' "$UNIT_FILE"
        echo "    Backup saved at ${UNIT_FILE}.pre-agent-flip"
    elif [ "$AGENT_MODE" = false ] && [ "$EXISTING_AGENT" = true ]; then
        # User reran without --agent; assume they want server mode back.
        # If they want to keep agent mode, they should not rerun without
        # the flag — make this clear AFTER the change so the rerun is
        # idempotent (rerun with --agent → still agent; rerun without
        # → server).
        echo "  → Flipping unit from AGENT to SERVER mode (removing --agent from ExecStart=)"
        cp "$UNIT_FILE" "${UNIT_FILE}.pre-agent-flip"
        sed -i -E 's|^(ExecStart=/usr/local/bin/wolfstack[^\n]*?)\s+--agent(\s.*)?$|\1\2|' "$UNIT_FILE"
        echo "    Backup saved at ${UNIT_FILE}.pre-agent-flip"
        echo "    Pass --agent on the next rerun to flip back."
    fi
    # Ensure KillMode=process on existing units. Installs created before this
    # change have no KillMode= line and therefore inherit systemd's
    # control-group default, so a restart/upgrade SIGTERMs daemonized QEMU VMs
    # and other children along with WolfStack (PapaSchlumpf 2026-06). Patch
    # idempotently and BEFORE the daemon-reload below so the upgrade restart at
    # the end of this script already runs with KillMode=process — the guest
    # survives even the very upgrade that introduces the fix. (Golden Rule:
    # this only narrows what a WolfStack restart kills; nothing else changes.)
    if ! grep -qE '^[[:space:]]*KillMode=' "$UNIT_FILE" 2>/dev/null; then
        echo "  → Adding KillMode=process (WolfStack restarts no longer stop VMs/containers)"
        sed -i '/^\[Service\]/a KillMode=process' "$UNIT_FILE"
    fi
    systemctl daemon-reload
    # Restart only if we actually changed the unit, otherwise leave
    # whatever the user has running alone.
    if [ -f "${UNIT_FILE}.pre-agent-flip" ]; then
        # Only restart if the flip was JUST done (file is fresh).
        if [ "$(find "${UNIT_FILE}.pre-agent-flip" -mmin -1 2>/dev/null)" ]; then
            echo "  → Restarting wolfstack to apply mode change..."
            systemctl restart wolfstack 2>/dev/null || true
        fi
    fi
fi

# ─── Firewall ───────────────────────────────────────────────────────────────
echo ""
if command -v ufw >/dev/null 2>&1; then
    ufw allow "$WS_PORT/tcp" 2>/dev/null && echo "✓ Firewall: Opened port $WS_PORT/tcp (ufw)" || true
    ufw allow 9600/udp 2>/dev/null && echo "✓ Firewall: Opened port 9600/udp for WolfNet (ufw)" || true
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$WS_PORT/tcp" 2>/dev/null && \
    firewall-cmd --permanent --add-port="9600/udp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    echo "✓ Firewall: Opened port $WS_PORT/tcp and 9600/udp (firewalld)" || true
fi

# ─── Set up lxcbr0 bridge for LXC containers ────────────────────────────────
if command -v lxc-ls >/dev/null 2>&1; then
    # Only configure lxc-net on fresh installs — restarting lxc-net on upgrades
    # destroys lxcbr0 and all container kernel routes, breaking WolfNet routing.
    # WolfStack's reapply_wolfnet_routes() handles route restoration on startup.
    if ip link show lxcbr0 >/dev/null 2>&1 && ip -4 addr show lxcbr0 2>/dev/null | grep -q "inet "; then
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
# Portable IP detection — `hostname -I` is GNU-only; Arch/BSD use `hostname -i`
# `ip` is the most reliable fallback on modern Linux.
get_primary_ip() {
    local ip=""
    # Default route src (works without internet connectivity)
    ip=$(ip -4 route show default 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    if [ -n "$ip" ]; then echo "$ip"; return; fi
    # Route to public IP (needs connectivity, but works everywhere)
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [ -n "$ip" ]; then echo "$ip"; return; fi
    # First global IPv4 (may be VPN/tailscale, but beats nothing)
    ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}')
    if [ -n "$ip" ]; then echo "$ip"; return; fi
    # GNU hostname -I
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$ip" ]; then echo "$ip"; return; fi
    # Non-GNU hostname -i
    ip=$(hostname -i 2>/dev/null | awk '{print $1}')
    if [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ]; then echo "$ip"; return; fi
    echo "localhost"
}

# ─── Install manifest: snapshot package state AFTER and write the diff ─────
ws_snapshot_packages "$WS_PKG_AFTER"
{
    echo "# WolfStack install manifest"
    echo "# Generated: $(date -Iseconds 2>/dev/null || date)"
    echo "# Host:      $(hostname 2>/dev/null || echo unknown)"
    echo "# Distro:    ${DISTRO:-unknown}"
    echo "# Pkg mgr:   ${PKG_MANAGER:-unknown}"
    echo "# Proxmox:   ${IS_PROXMOX:-false}"
    echo ""
    echo "# This file lists every package whose installed version changed during"
    echo "# the WolfStack install. Lines starting '+' were added or upgraded."
    echo "# Lines starting '-' were removed (should be empty in normal runs)."
    echo "# To uninstall, run /usr/local/bin/wolfstack-uninstall (or uninstall.sh"
    echo "# from the source tree) — it reads the most recent manifest."
    echo ""
    echo "## Packages added or upgraded"
    if [ -s "$WS_PKG_BEFORE" ] && [ -s "$WS_PKG_AFTER" ]; then
        # comm -13 = lines only in AFTER → packages added or version-bumped
        comm -13 "$WS_PKG_BEFORE" "$WS_PKG_AFTER" | sed 's/^/+ /'
    else
        echo "  (no package snapshot available — unsupported package manager)"
    fi
    echo ""
    echo "## Packages removed"
    if [ -s "$WS_PKG_BEFORE" ] && [ -s "$WS_PKG_AFTER" ]; then
        comm -23 "$WS_PKG_BEFORE" "$WS_PKG_AFTER" | sed 's/^/- /'
    fi
    echo ""
    echo "## Services touched by setup.sh"
    echo "  systemd unit: wolfstack.service (enabled + started)"
    if [ -n "$DNSMASQ_PRE_STATE" ]; then
        echo "  dnsmasq.service: prior state = $DNSMASQ_PRE_STATE"
    fi
    echo ""
    echo "## Files written"
    echo "  /etc/wolfstack/                 — config, secrets, license"
    echo "  /usr/local/bin/wolfstack        — main binary"
    echo "  /etc/systemd/system/wolfstack.service — systemd unit"
    echo "  /etc/wolfstack/join-token       — cluster join token (mode 0600)"
    echo "  $WS_MANIFEST_FILE  — this manifest"
} > "$WS_MANIFEST_FILE" 2>/dev/null || true
chmod 640 "$WS_MANIFEST_FILE" 2>/dev/null || true
rm -f "$WS_PKG_BEFORE" "$WS_PKG_AFTER" 2>/dev/null || true

# ─── Pre-generate join token so we can show it in the banner ────────────────
# wolfstack normally generates this on first run via load_join_token() in
# src/api/mod.rs. We pre-create it here using the same format (64 hex chars
# from /dev/urandom) so the banner can show it immediately and the user
# can paste it into another node's UI before this service finishes booting.
JOIN_TOKEN_FILE="/etc/wolfstack/join-token"
if [ ! -s "$JOIN_TOKEN_FILE" ]; then
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32 > "$JOIN_TOKEN_FILE" 2>/dev/null || true
    elif [ -r /dev/urandom ]; then
        # POSIX-portable fallback: od + tr produces 64 lowercase hex chars
        od -An -vtx1 -N32 /dev/urandom 2>/dev/null | tr -d ' \n' > "$JOIN_TOKEN_FILE" || true
        echo >> "$JOIN_TOKEN_FILE"
    fi
    chmod 600 "$JOIN_TOKEN_FILE" 2>/dev/null || true
fi
JOIN_TOKEN="$(tr -d '\n\r' < "$JOIN_TOKEN_FILE" 2>/dev/null || echo '')"

echo "  🐺 Installation Complete!"
echo "  ─────────────────────────────────────"
if [ "$AGENT_MODE" = true ]; then
    echo "  Mode:       Agent-only (no management UI on this node)"
    echo "  This node:  https://$(get_primary_ip):${WS_PORT}  (cluster API, HTTPS)"
    echo "  Manage:     Open your master server's UI and add this node"
    echo "              via Cluster → Add Node using the join token below."
    echo ""
    echo "  ⚠ Cluster secret note:"
    echo "    If you rotated the cluster secret on the master server"
    echo "    (Settings → Security), copy /etc/wolfstack/custom-cluster-secret"
    echo "    from the master to THIS node before the first connection — otherwise"
    echo "    inter-node calls will fail X-WolfStack-Secret authentication."
else
    echo "  Dashboard:  https://$(get_primary_ip):${WS_PORT}"
    echo "  Login:      Use your Linux system username and password"
fi
echo ""
if [ "$WAS_HTTP_ONLY" = true ]; then
    echo "  ⚠ UPGRADER NOTICE — HTTPS-by-default is new in v23.11"
    echo "  ─────────────────────────────────────"
    echo "  This server was previously running on HTTP (no TLS cert configured)."
    echo "  v23.11 now auto-generates a self-signed cert and serves HTTPS on"
    echo "  port ${WS_PORT}. **Your old http://${WS_BIND:-host}:${WS_PORT}/ URLs will stop working.**"
    echo ""
    echo "  Action needed:"
    echo "    1. Update browser bookmarks: http://  →  https://"
    echo "    2. Update any scripts hitting the API to use https:// (and -k"
    echo "       if they don't already accept self-signed certs)"
    echo "    3. Browser will warn 'connection not private' once — click"
    echo "       through, or import /etc/wolfstack/tls/cert.pem as trusted"
    echo ""
    echo "  Want to keep HTTP-only? Edit /etc/systemd/system/wolfstack.service"
    echo "  and add --no-tls to the ExecStart line, then 'systemctl daemon-reload"
    echo "  && systemctl restart wolfstack'. Strongly NOT recommended — your"
    echo "  login credentials currently travel in cleartext over the network."
    echo ""
fi
echo "  TLS:"
echo "    WolfStack auto-generates a self-signed cert at"
echo "    /etc/wolfstack/tls/cert.pem on first start (valid 10 years)."
echo "    Your browser will warn 'connection not private' the first"
echo "    time — that's expected for self-signed certs. Either:"
echo "      • click through the warning (one-time, per browser), OR"
echo "      • download the cert from the Dashboard and import it as a trust anchor, OR"
echo "      • request a real CA cert from the Settings → Certificates"
echo "        page (Let's Encrypt is supported if this host has a public domain)."
echo "    The cluster secret authenticates every API call — the cert"
echo "    just encrypts the transport. Self-signed is fine for"
echo "    everything except 'no browser warnings'."
echo ""
echo "  Manage:"
echo "  Status:     sudo systemctl status wolfstack"
echo "  Logs:       sudo journalctl -u wolfstack -f"
echo "  Restart:    sudo systemctl restart wolfstack"
echo "  Config:     /etc/wolfstack/config.toml"
echo "  Uninstall:  sudo wolfstack-uninstall              (preserves config)"
echo "              sudo wolfstack-uninstall --purge      (full wipe of WolfStack)"
echo "              sudo wolfstack-uninstall --all --purge (also remove WolfNet/Proxy/Serve/Disk/Scale)"
if [ -s "$WS_MANIFEST_FILE" ]; then
    echo "  Manifest:   $WS_MANIFEST_FILE"
    echo "              (records every package added/upgraded — kept for rollback)"
fi
echo ""
if [ -n "$JOIN_TOKEN" ]; then
    echo "  ─── Add this node to a cluster ──────"
    echo "  This node's join token (paste into the master server's"
    echo "  \"Add Node\" form to link this server to an existing cluster):"
    echo ""
    echo "    $JOIN_TOKEN"
    echo ""
    echo "  Token file:  $JOIN_TOKEN_FILE  (mode 0600, root only)"
    echo "  Retrieve later:  sudo cat $JOIN_TOKEN_FILE"
    echo ""
fi
echo "**** UPGRADE COMPLETE ****"
echo ""
echo "Please Refresh your browser if upgrading..."

# ─── Restart service if upgrading (must be last!) ────────────────────────────
#
# Detach properly. PapaSchlumpf 2026-05-25: upgrading from 24.7.7 to
# 24.7.9 via the in-app console, closing the browser tab before the
# 3-second sleep elapsed killed the pending restart along with the
# pty session — the new binary was installed but the service kept
# running the old one, so the dashboard kept showing 24.7.7.
#
# `nohup ... &` is NOT enough. The console session is a pty spawned
# by wolfstack itself; when the browser closes, wolfstack tears down
# the pty and every child in its session/cgroup is signalled. `nohup`
# only ignores SIGHUP, not SIGTERM/SIGKILL that come from cgroup
# cleanup. Schedule via a transient systemd timer so the restart is
# owned by PID 1 and cannot be killed by the pty closing.
#
# Fallback (no systemd-run) uses `setsid` to start a new session
# detached from the pty plus full stdio redirection — the best a
# plain shell can do.
if [ "$RESTART_SERVICE" = "true" ]; then
    if command -v systemd-run >/dev/null 2>&1; then
        # Transient one-shot timer owned by systemd; survives the pty
        # closing because its parent is PID 1, not our shell.
        systemd-run --quiet --no-block \
            --on-active=3s \
            --unit="wolfstack-self-restart-$$.timer" \
            /bin/systemctl restart wolfstack >/dev/null 2>&1 || \
        setsid bash -c "sleep 3 && systemctl restart wolfstack" \
            </dev/null >/dev/null 2>&1 &
    else
        setsid bash -c "sleep 3 && systemctl restart wolfstack" \
            </dev/null >/dev/null 2>&1 &
    fi
fi
