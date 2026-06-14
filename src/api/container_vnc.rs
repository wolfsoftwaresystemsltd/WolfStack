// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! VNC desktop access into LXC / Proxmox-LXC / Docker containers.
//!
//! Users may not have a VNC server inside their containers — we offer to
//! install TigerVNC + XFCE4 on detected OSes (Debian/Ubuntu, Alpine,
//! RHEL/Rocky/Fedora). Once installed, a WebSocket bridge spawns
//! `<runtime exec> -- socat STDIO TCP:127.0.0.1:5901` and shuttles the
//! stdio bytes ↔ noVNC binary frames in the browser. No port publishing,
//! no per-container firewall rules — works the same in any network mode.
//!
//! Cross-node access reuses the existing
//! /ws/remote-console/{node_id}/{ctype}/{name} bridge with ctype values
//! `lxc-vnc` / `docker-vnc` / `pct-vnc` (see console.rs).

use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};

use super::AppState;

const VNC_CONFIG_PATH: &str = "/etc/wolfstack/container-vnc.json";

/// One entry per container that has been set up for VNC.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VncEntry {
    runtime: String,       // "lxc" | "docker" | "pct"
    name: String,          // container name (or numeric VMID for pct)
    password: String,      // 8-char alphanum (TigerVNC VncAuth truncates >8)
    installed_at: String,  // RFC3339
}

fn config_key(runtime: &str, name: &str) -> String {
    format!("{}:{}", runtime, name)
}

fn load_config() -> HashMap<String, VncEntry> {
    std::fs::read_to_string(VNC_CONFIG_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(map: &HashMap<String, VncEntry>) -> Result<(), String> {
    std::fs::create_dir_all("/etc/wolfstack")
        .map_err(|e| format!("create_dir /etc/wolfstack: {}", e))?;
    let s = serde_json::to_string_pretty(map)
        .map_err(|e| format!("serialise vnc config: {}", e))?;
    crate::paths::write_secure(VNC_CONFIG_PATH, &s)
        .map_err(|e| format!("write {}: {}", VNC_CONFIG_PATH, e))
}


/// 8-char alphanumeric password (avoiding visually-ambiguous chars).
/// TigerVNC VncAuth truncates passwords to 8 bytes anyway.
fn generate_password() -> String {
    use std::io::Read;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    let mut out = String::with_capacity(8);
    for b in &buf {
        out.push(CHARSET[(*b as usize) % CHARSET.len()] as char);
    }
    out
}

/// Validate the (runtime, name) pair to avoid command-injection through
/// the container name. Returns Err(HttpResponse) if invalid.
fn validate_target(runtime: &str, name: &str) -> Result<(), HttpResponse> {
    match runtime {
        "docker" | "lxc" => {
            if !crate::auth::is_safe_name(name) {
                return Err(HttpResponse::BadRequest()
                    .json(serde_json::json!({ "error": "Invalid container name" })));
            }
        }
        "pct" => {
            // Proxmox LXC — name is the numeric VMID
            if name.parse::<u64>().is_err() {
                return Err(HttpResponse::BadRequest()
                    .json(serde_json::json!({ "error": "Invalid VMID" })));
            }
        }
        _ => {
            return Err(HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Unknown runtime" })));
        }
    }
    Ok(())
}

/// Build argv for `<runtime exec> sh -c '<shell_cmd>'`.
/// Caller must have already passed validate_target — we re-check anyway
/// (defence in depth).
fn build_exec_argv(runtime: &str, name: &str, shell_cmd: &str) -> Result<Vec<String>, String> {
    match runtime {
        "docker" => {
            if !crate::auth::is_safe_name(name) {
                return Err("invalid container name".into());
            }
            Ok(vec![
                "docker".into(), "exec".into(), "-i".into(),
                name.into(),
                "sh".into(), "-c".into(), shell_cmd.into(),
            ])
        }
        "lxc" => {
            if !crate::auth::is_safe_name(name) {
                return Err("invalid container name".into());
            }
            let base = crate::containers::lxc_base_dir(name);
            let mut a: Vec<String> = vec!["lxc-attach".into()];
            if base != crate::containers::LXC_DEFAULT_PATH {
                a.push("-P".into());
                a.push(base);
            }
            a.extend([
                "-n".into(), name.into(),
                "--".into(),
                "sh".into(), "-c".into(), shell_cmd.into(),
            ]);
            Ok(a)
        }
        "pct" => {
            if name.parse::<u64>().is_err() {
                return Err("invalid VMID".into());
            }
            Ok(vec![
                "pct".into(), "exec".into(), name.into(),
                "--".into(),
                "sh".into(), "-c".into(), shell_cmd.into(),
            ])
        }
        _ => Err(format!("Unknown runtime: {}", runtime)),
    }
}

/// Run a one-shot command inside the container and capture
/// (exit_code, stdout, stderr). Used for OS detection + state probes.
fn container_exec(runtime: &str, name: &str, shell_cmd: &str) -> Result<(i32, String, String), String> {
    let argv = build_exec_argv(runtime, name, shell_cmd)?;
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn {}: {}", argv[0], e))?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// One desktop environment offering for the install-modal dropdown.
#[derive(Debug, Clone, Serialize)]
pub struct DesktopChoice {
    pub id: String,             // "xfce", "mate", "lxqt", "kde", "gnome", "cinnamon"
    pub label: String,          // human-friendly name shown in the dropdown
    pub size_mb: u32,           // rough on-disk install footprint
    pub session_binary: String, // command run by xstartup
    pub packages: Vec<String>,  // packages installed on top of the VNC base
}

/// Detected OS family and the package manager / install commands we'll use.
#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub id: String,            // e.g. "debian", "ubuntu", "alpine", "rocky"
    pub id_like: String,       // /etc/os-release ID_LIKE
    pub version_id: String,    // /etc/os-release VERSION_ID
    pub family: String,        // "debian" | "alpine" | "rhel" | "unknown"
    pub supported: bool,
    pub packages: Vec<String>, // packages we'd install (default = XFCE full-desktop)
    pub size_estimate_mb: u32, // full-desktop install size, rough (XFCE)
    /// Existing desktop session detected inside the container — drives the
    /// modal's recommendation (VNC-only when present). Value is the session
    /// binary command, e.g. "cinnamon-session", or "xfce4-session".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_desktop: Option<String>,
    /// Friendly label for `detected_desktop` (e.g. "Cinnamon").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_desktop_label: Option<String>,
    /// Packages we'd install on the VNC-only path (no DE).
    pub packages_vnc_only: Vec<String>,
    /// VNC-only install size.
    pub size_estimate_mb_vnc_only: u32,
    /// Per-OS-family desktop catalogue for the install modal dropdown.
    /// First entry is the default (XFCE — lightest, most reliable in LXC).
    pub available_desktops: Vec<DesktopChoice>,
}

/// Catalogue of desktop options per OS family. First entry is the default.
/// Sizes are rough — actual install size depends on what's already there.
fn available_desktops(family: &str) -> Vec<DesktopChoice> {
    match family {
        "debian" => vec![
            DesktopChoice {
                id: "xfce".into(), label: "XFCE 4 (lightweight, recommended)".into(),
                size_mb: 450, session_binary: "startxfce4".into(),
                packages: vec!["xfce4".into(), "xfce4-terminal".into()],
            },
            DesktopChoice {
                id: "mate".into(), label: "MATE".into(),
                size_mb: 600, session_binary: "mate-session".into(),
                packages: vec!["mate-desktop-environment-core".into(), "mate-terminal".into()],
            },
            DesktopChoice {
                id: "lxqt".into(), label: "LXQt (very lightweight)".into(),
                size_mb: 350, session_binary: "startlxqt".into(),
                packages: vec!["lxqt-core".into(), "qterminal".into()],
            },
            DesktopChoice {
                id: "cinnamon".into(), label: "Cinnamon".into(),
                size_mb: 700, session_binary: "cinnamon-session".into(),
                packages: vec!["cinnamon-desktop-environment".into()],
            },
            DesktopChoice {
                id: "kde".into(), label: "KDE Plasma".into(),
                size_mb: 1500, session_binary: "startplasma-x11".into(),
                packages: vec!["kde-plasma-desktop".into(), "konsole".into()],
            },
            DesktopChoice {
                id: "gnome".into(), label: "GNOME".into(),
                size_mb: 1800, session_binary: "gnome-session".into(),
                packages: vec!["gnome-session".into(), "gnome-terminal".into()],
            },
        ],
        "alpine" => vec![
            DesktopChoice {
                id: "xfce".into(), label: "XFCE 4 (lightweight, recommended)".into(),
                size_mb: 250, session_binary: "startxfce4".into(),
                packages: vec!["xfce4".into(), "xfce4-terminal".into()],
            },
            DesktopChoice {
                id: "mate".into(), label: "MATE".into(),
                size_mb: 400, session_binary: "mate-session".into(),
                packages: vec!["mate-desktop".into(), "mate-terminal".into()],
            },
            DesktopChoice {
                id: "lxqt".into(), label: "LXQt (very lightweight)".into(),
                size_mb: 300, session_binary: "startlxqt".into(),
                packages: vec!["lxqt".into()],
            },
            DesktopChoice {
                id: "kde".into(), label: "KDE Plasma".into(),
                size_mb: 1000, session_binary: "startplasma-x11".into(),
                packages: vec!["plasma-desktop".into()],
            },
        ],
        "rhel" => vec![
            DesktopChoice {
                id: "xfce".into(), label: "XFCE 4 (lightweight, recommended)".into(),
                size_mb: 500, session_binary: "startxfce4".into(),
                packages: vec![
                    "xfce4-session".into(), "xfwm4".into(), "xfce4-panel".into(),
                    "xfce4-terminal".into(), "thunar".into(),
                ],
            },
            DesktopChoice {
                id: "mate".into(), label: "MATE".into(),
                size_mb: 700, session_binary: "mate-session".into(),
                packages: vec!["mate-session-manager".into(), "mate-panel".into(), "mate-terminal".into(), "caja".into()],
            },
            DesktopChoice {
                id: "kde".into(), label: "KDE Plasma".into(),
                size_mb: 1200, session_binary: "startplasma-x11".into(),
                packages: vec!["plasma-workspace".into(), "konsole".into()],
            },
            DesktopChoice {
                id: "gnome".into(), label: "GNOME".into(),
                size_mb: 2000, session_binary: "gnome-session".into(),
                packages: vec!["gnome-session".into(), "gnome-terminal".into()],
            },
        ],
        _ => Vec::new(),
    }
}

fn lookup_desktop(family: &str, id: &str) -> Option<DesktopChoice> {
    available_desktops(family).into_iter().find(|d| d.id == id)
}

/// Probe binaries — order matters (Mint defaults first, then Ubuntu, then KDE/etc).
/// Each tuple is (binary on PATH, friendly label, optional override for the
/// xstartup exec line — falls back to the binary itself when None).
const DE_PROBES: &[(&str, &str, Option<&str>)] = &[
    ("cinnamon-session",   "Cinnamon",  None),
    ("mate-session",       "MATE",      None),
    ("gnome-session",      "GNOME",     None),
    ("startplasma-x11",    "KDE Plasma", None),
    ("startkde",           "KDE",       None),
    ("startxfce4",         "XFCE",      None),
    ("startlxqt",          "LXQt",      None),
    ("lxsession",          "LXDE",      None),
    ("openbox-session",    "Openbox",   None),
    ("fluxbox",            "Fluxbox",   None),
    ("icewm-session",      "IceWM",     None),
    ("i3",                 "i3",        Some("i3 --shmlog-size 0")),
];

/// Inside-container probe — for each candidate session binary, ask `command -v`
/// and return the first hit with its friendly label.
fn detect_desktop(runtime: &str, name: &str) -> (Option<String>, Option<String>) {
    let probe = DE_PROBES.iter()
        .map(|(bin, _, _)| format!("if command -v {bin} >/dev/null 2>&1; then echo {bin}; exit 0; fi"))
        .collect::<Vec<_>>()
        .join("; ");
    match container_exec(runtime, name, &probe) {
        Ok((_, stdout, _)) => {
            let bin = stdout.trim().to_string();
            if bin.is_empty() {
                (None, None)
            } else {
                let label = DE_PROBES.iter()
                    .find(|(b, _, _)| *b == bin.as_str())
                    .map(|(_, l, _)| l.to_string());
                (Some(bin), label)
            }
        }
        Err(_) => (None, None),
    }
}

/// Returns (family, supported, full_desktop_packages, full_size_mb,
/// vnc_only_packages, vnc_only_size_mb).
fn classify_os(id: &str, id_like: &str) -> (String, bool, Vec<String>, u32, Vec<String>, u32) {
    let id_l = id.to_lowercase();
    let like_l = id_like.to_lowercase();
    let in_like = |needle: &str| like_l.split_whitespace().any(|w| w == needle);

    if id_l == "debian" || id_l == "ubuntu" || in_like("debian") || in_like("ubuntu") {
        (
            "debian".into(),
            true,
            vec![
                "tigervnc-standalone-server".into(),
                "tigervnc-common".into(),
                "tigervnc-tools".into(), // provides vncpasswd
                "xfce4".into(),
                "xfce4-terminal".into(),
                "dbus-x11".into(),
                "socat".into(),
                "fonts-dejavu".into(),
            ],
            450,
            vec![
                "tigervnc-standalone-server".into(),
                "tigervnc-common".into(),
                "tigervnc-tools".into(), // provides vncpasswd
                "dbus-x11".into(),
                "socat".into(),
                "xterm".into(),
            ],
            40,
        )
    } else if id_l == "alpine" || in_like("alpine") {
        (
            "alpine".into(),
            true,
            vec![
                "tigervnc".into(),
                "xfce4".into(),
                "xfce4-terminal".into(),
                "dbus-x11".into(),
                "socat".into(),
                "ttf-dejavu".into(),
                // Alpine ships pgrep via busybox — no separate procps package needed.
            ],
            250,
            vec![
                "tigervnc".into(),
                "dbus-x11".into(),
                "socat".into(),
                "xterm".into(),
            ],
            30,
        )
    } else if id_l == "rocky" || id_l == "almalinux" || id_l == "rhel"
        || id_l == "centos" || id_l == "fedora"
        || in_like("rhel") || in_like("fedora") || in_like("centos")
    {
        (
            "rhel".into(),
            true,
            vec![
                "tigervnc-server".into(),
                "tigervnc".into(), // provides vncpasswd
                "xfce4-session".into(),
                "xfwm4".into(),
                "xfce4-panel".into(),
                "xfce4-terminal".into(),
                "thunar".into(),
                "dbus-x11".into(),
                "socat".into(),
                "dejavu-sans-fonts".into(),
            ],
            500,
            vec![
                "tigervnc-server".into(),
                "tigervnc".into(), // provides vncpasswd
                "dbus-x11".into(),
                "socat".into(),
                "xterm".into(),
            ],
            45,
        )
    } else {
        ("unknown".into(), false, Vec::new(), 0, Vec::new(), 0)
    }
}

fn detect_os(runtime: &str, name: &str) -> Result<OsInfo, String> {
    // Use printf+separators rather than `echo` so newlines in values can't fake out parsing.
    // Variables come from /etc/os-release; if missing we fall back to /usr/lib/os-release.
    let cmd = ". /etc/os-release 2>/dev/null || . /usr/lib/os-release 2>/dev/null; \
               printf '%s\\n%s\\n%s\\n' \"${ID:-unknown}\" \"${ID_LIKE:-}\" \"${VERSION_ID:-}\"";
    let (code, stdout, stderr) = container_exec(runtime, name, cmd)?;
    if code != 0 {
        return Err(format!("OS detection failed (exit {}): {}", code, stderr.trim()));
    }
    let mut lines = stdout.lines();
    let id = lines.next().unwrap_or("unknown").trim().to_string();
    let id_like = lines.next().unwrap_or("").trim().to_string();
    let version_id = lines.next().unwrap_or("").trim().to_string();
    let (family, supported, packages, size_estimate_mb, packages_vnc_only, size_estimate_mb_vnc_only)
        = classify_os(&id, &id_like);
    let (detected_desktop, detected_desktop_label) = detect_desktop(runtime, name);
    let desktops = available_desktops(&family);
    Ok(OsInfo {
        id, id_like, version_id, family, supported,
        packages, size_estimate_mb,
        detected_desktop, detected_desktop_label,
        packages_vnc_only, size_estimate_mb_vnc_only,
        available_desktops: desktops,
    })
}

/// Common-utilities bundle installed alongside a Full Desktop when the
/// user keeps the "extras" checkbox on (default). Returns the package
/// list for the chosen distro family + selected DE — the DE-specific
/// polish package (xfce4-goodies / gnome-tweaks) is appended when
/// applicable.
fn extras_packages(family: &str, desktop_id: &str) -> Vec<String> {
    // NOTE: the web browser is NOT in this list — a full desktop always gets a
    // browser via the dedicated BROWSER_BLOCK_* step (run independently of this
    // optional extras bundle), so unchecking extras still leaves a usable
    // browser. The per-distro browser-package quirks (Debian firefox-esr vs
    // Ubuntu's snap-only firefox) are handled there.
    let mut pkgs: Vec<String> = match family {
        "debian" => vec![
            "flatpak".into(),
            "gvfs".into(),
            "gvfs-backends".into(),
            "xdg-utils".into(),
            "network-manager-gnome".into(),
            "file-roller".into(),
        ],
        "alpine" => vec![
            // NOTE: the web browser is installed by browser_install_block (a
            // full desktop always gets one, independent of this extras bundle).
            "flatpak".into(),
            "xdg-utils".into(),
            "gvfs".into(),
        ],
        "rhel" => vec![
            // Browser installed by browser_install_block — see note above.
            "flatpak".into(),
            "xdg-utils".into(),
            "gvfs".into(),
            "gvfs-fuse".into(),
            "network-manager-applet".into(),
            "file-roller".into(),
        ],
        _ => Vec::new(),
    };

    // DE-specific polish — turns the bare metapackage into something
    // pleasant. xfce4-goodies adds notifyd, screenshooter, mousepad,
    // panel plugins. gnome-tweaks adds the standard GNOME tuning UI.
    match (family, desktop_id) {
        ("debian", "xfce") => pkgs.push("xfce4-goodies".into()),
        ("debian", "gnome") => pkgs.push("gnome-tweaks".into()),
        ("rhel", "gnome") => pkgs.push("gnome-tweaks".into()),
        _ => {}
    }

    pkgs
}

/// Browser install for a Debian/Ubuntu/Mint full desktop. Run for EVERY desktop
/// install (not gated on the optional extras bundle) — a desktop with no browser
/// is what users hit as "no web browser installed". Debian/Mint ship a real
/// `firefox-esr` .deb; Ubuntu ships `firefox` only as a snap, which does NOT run
/// inside an LXC container, so we fall back to Mozilla's official APT repo (a
/// real .deb) and finally to Flatpak. Best-effort: never fatal to the install.
const BROWSER_BLOCK_DEBIAN: &str = r#"
echo "[wolfstack] Installing a web browser..."
apt-get install -y --no-install-recommends firefox-esr 2>/dev/null || true
if ! command -v firefox-esr >/dev/null 2>&1 && ! command -v firefox >/dev/null 2>&1; then
    echo "[wolfstack] firefox-esr unavailable — adding Mozilla's APT repo (Ubuntu's firefox is a snap that can't run in LXC)..."
    apt-get install -y --no-install-recommends ca-certificates curl 2>/dev/null || true
    install -d -m 0755 /etc/apt/keyrings
    if curl -fsSL https://packages.mozilla.org/apt/repo-signing-key.gpg -o /etc/apt/keyrings/packages.mozilla.org.asc 2>/dev/null; then
        echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" > /etc/apt/sources.list.d/mozilla.list
        printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' > /etc/apt/preferences.d/mozilla
        apt-get update -qq 2>/dev/null || true
        apt-get install -y --no-install-recommends firefox 2>/dev/null || true
    fi
fi
if ! command -v firefox-esr >/dev/null 2>&1 && ! command -v firefox >/dev/null 2>&1 && command -v flatpak >/dev/null 2>&1; then
    echo "[wolfstack] Falling back to Flatpak Firefox..."
    flatpak install -y --noninteractive flathub org.mozilla.firefox 2>/dev/null || true
fi
if command -v firefox-esr >/dev/null 2>&1 || command -v firefox >/dev/null 2>&1 || flatpak info org.mozilla.firefox >/dev/null 2>&1; then
    echo "[wolfstack] Web browser installed."
else
    echo "[wolfstack] WARNING: could not install a web browser automatically — install one manually, e.g. apt-get install firefox-esr"
fi
"#;

/// Browser install for a RHEL/Fedora/Rocky full desktop. `$PKG` is set by the
/// RHEL head to `dnf -y install` / `yum -y install`. Firefox is a native rpm.
const BROWSER_BLOCK_RHEL: &str = r#"
echo "[wolfstack] Installing a web browser..."
$PKG firefox 2>/dev/null \
    || echo "[wolfstack] WARNING: could not install firefox automatically — install one manually (dnf install firefox)."
"#;

/// Browser install for an Alpine full desktop. firefox / firefox-esr live in the
/// community repo.
const BROWSER_BLOCK_ALPINE: &str = r#"
echo "[wolfstack] Installing a web browser..."
apk add --no-cache firefox 2>/dev/null || apk add --no-cache firefox-esr 2>/dev/null \
    || echo "[wolfstack] WARNING: could not install firefox automatically — install one manually (apk add firefox)."
"#;

/// Shell commands to register Flathub as a Flatpak remote — same line
/// recommended by the Flatpak docs. Idempotent (`--if-not-exists`).
fn flatpak_setup_snippet() -> &'static str {
    "if command -v flatpak >/dev/null 2>&1; then \
         flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo 2>/dev/null || true; \
     fi"
}

/// Build the install script. The VNC password is baked into the script
/// via `vncpasswd -f`. Idempotent: re-running re-installs cleanly.
///
/// `with_desktop = true` installs TigerVNC + the chosen `desktop_id`
/// (defaults to "xfce") and points xstartup at that DE's session
/// binary. `with_desktop = false` installs TigerVNC + xterm only and
/// xstartup walks a list of session binaries — falling back to xterm
/// when none are installed. `detected_desktop` (when present) goes at
/// the head of that probe list so an existing Cinnamon/MATE/GNOME
/// container reuses what it has.
///
/// `extras = true` adds the common-utilities bundle (browser, Flatpak +
/// Flathub, file/archive helpers, network applet, DE polish) on top of
/// the chosen DE — turns a bare metapackage into a usable desktop.
fn build_install_script(
    family: &str,
    password: &str,
    with_desktop: bool,
    detected_desktop: Option<&str>,
    desktop_id: Option<&str>,
    extras: bool,
) -> String {
    // Resolve the chosen desktop (when full-desktop mode). Default to "xfce".
    let chosen = if with_desktop {
        let id = desktop_id.unwrap_or("xfce");
        lookup_desktop(family, id).or_else(|| lookup_desktop(family, "xfce"))
    } else {
        None
    };

    // xstartup body — chosen desktop's session binary (with_desktop), or
    // detect-existing fallback list (vnc-only).
    //
    // GNOME / KDE refuse to run as root. xstartup is invoked by Xvnc as
    // root (LXC containers' init), so for those desktops we su to the
    // admin user we created earlier. XFCE / MATE / LXQt / Cinnamon /
    // Openbox / Fluxbox / IceWM all run fine as root, so the cheap
    // session_binary path is fine.
    let needs_drop_privs = chosen.as_ref()
        .map(|d| matches!(d.id.as_str(), "gnome" | "kde"))
        .unwrap_or(false);
    // Always emit a probe-list xstartup. When the user picked a desktop the
    // chosen one goes first (with the GNOME/KDE privilege-drop dance), but
    // we ALWAYS fall through to the other DE binaries and finally xterm.
    // This is what saves the install when apt couldn't actually resolve
    // the chosen DE's packages — e.g. Mint Zena LXC templates ship a
    // mixed XFCE/GTK package set whose t64 deps are unsatisfiable on the
    // Jammy base, so XFCE never installs even though we asked for it.
    // Without this fallback the user would connect to a black screen.
    let xstartup_body = {
        let chosen_block = if let Some(ref d) = chosen {
            if needs_drop_privs {
                format!(
                    "if command -v {bin} >/dev/null 2>&1; then\n    \
                        if [ \"$(id -u)\" = \"0\" ] && id admin >/dev/null 2>&1; then\n        \
                            exec su - admin -c 'DISPLAY=:1 dbus-launch --exit-with-session {bin}'\n    \
                        fi\n    \
                        exec {bin}\n\
                    fi",
                    bin = d.session_binary
                )
            } else {
                format!(
                    "if command -v {bin} >/dev/null 2>&1; then exec {bin}; fi",
                    bin = d.session_binary
                )
            }
        } else {
            String::new()
        };
        // Build the rest of the probe list. Detected DE (if any) goes
        // first, then everything else; skip whatever's already in the
        // chosen block to avoid duplicates.
        let chosen_bin = chosen.as_ref().map(|d| d.session_binary.as_str());
        let mut probes: Vec<&str> = Vec::new();
        if let Some(b) = detected_desktop {
            if Some(b) != chosen_bin {
                probes.push(b);
            }
        }
        for (bin, _, _) in DE_PROBES {
            if Some(*bin) != detected_desktop && Some(*bin) != chosen_bin {
                probes.push(bin);
            }
        }
        let probe_lines = probes.iter()
            .map(|b| format!("if command -v {b} >/dev/null 2>&1; then exec {b}; fi"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut body = String::new();
        if !chosen_block.is_empty() { body.push_str(&chosen_block); body.push('\n'); }
        if !probe_lines.is_empty()  { body.push_str(&probe_lines);  body.push('\n'); }
        body.push_str("# Last-resort fallback so the user gets *something* on screen\nexec xterm -geometry 120x40");
        body
    };

    // Body of /usr/local/bin/wolfstack-vnc-start. Kept as a separate raw
    // string and substituted into the install script as a single
    // placeholder so format!()'s brace-counting doesn't choke on the
    // shell's `${VAR}` expansions and `function() { … }` bodies.
    let starter_body = r#"#!/bin/sh
# Already running?
if pgrep -f 'Xvnc.*:1|Xtigervnc.*:1' >/dev/null 2>&1; then
    exit 0
fi
export USER=root HOME=/root
export XDG_RUNTIME_DIR=/run/user/0
mkdir -p /tmp/.X11-unix /run/user/0 /root/.vnc
chmod 1777 /tmp/.X11-unix
chmod 700 /run/user/0
chown root:root /run/user/0 2>/dev/null || true

# Prefer /var/log when writable, otherwise /tmp.
if mkdir -p /var/log 2>/dev/null && [ -w /var/log ]; then
    LOG=/var/log/wolfstack-vnc.log
else
    LOG=/tmp/wolfstack-vnc.log
fi
HOSTNAME=$(hostname 2>/dev/null || echo localhost)
echo "--- $(date '+%F %T') wolfstack-vnc-start ---" >>"$LOG"

wait_for_port() {
    i=0
    while [ $i -lt 16 ]; do
        if socat -T 1 /dev/null TCP:127.0.0.1:5901 >/dev/null 2>&1; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.3
    done
    return 1
}

cleanup_x1() {
    rm -f /tmp/.X11-unix/X1 /tmp/.X1-lock 2>/dev/null
    pkill -f 'Xvnc.*:1|Xtigervnc.*:1' 2>/dev/null
    sleep 0.3
}

# The wrapper reads /root/.vnc/config when no CLI flags are given —
# avoids the version-dependent flag-name churn (-localhost, -localhost yes,
# -PasswordFile vs -PasswordFile=) that bites different distros.
cat > /root/.vnc/config <<'CFG_EOF'
geometry=1280x800
depth=24
localhost=yes
SecurityTypes=VncAuth
PasswordFile=/root/.vnc/passwd
session=
CFG_EOF
chmod 600 /root/.vnc/config

cleanup_x1

# Strategy 1: TigerVNC Perl wrapper.
if command -v tigervncserver >/dev/null 2>&1; then
    echo "[wolfstack-vnc] strategy 1: tigervncserver :1 (config-driven)" >>"$LOG"
    tigervncserver :1 >>"$LOG" 2>&1
    if wait_for_port; then exit 0; fi
    echo "[wolfstack-vnc] strategy 1 failed - tearing down" >>"$LOG"
    tigervncserver -kill :1 >>"$LOG" 2>&1
    cleanup_x1
fi
if command -v vncserver >/dev/null 2>&1 && ! command -v tigervncserver >/dev/null 2>&1; then
    echo "[wolfstack-vnc] strategy 1b: vncserver :1 (config-driven)" >>"$LOG"
    vncserver :1 >>"$LOG" 2>&1
    if wait_for_port; then exit 0; fi
    vncserver -kill :1 >>"$LOG" 2>&1
    cleanup_x1
fi

# Strategy 2: direct Xvnc + manual xstartup. Bypasses the Perl wrapper
# entirely - no xauth/cookie shenanigans, no per-distro flag quirks.
if command -v Xvnc >/dev/null 2>&1; then
    echo "[wolfstack-vnc] strategy 2: Xvnc direct" >>"$LOG"
    cleanup_x1
    Xvnc :1 \
        -geometry 1280x800 -depth 24 \
        -rfbport 5901 \
        -rfbauth /root/.vnc/passwd \
        -localhost \
        -SecurityTypes VncAuth \
        -auth /root/.Xauthority \
        >>"$LOG" 2>&1 &
    XVNC_PID=$!
    sleep 0.5
    if kill -0 "$XVNC_PID" 2>/dev/null; then
        # Spawn xstartup against the new display. Detach so it doesn't
        # block this script; Xvnc keeps running independently.
        DISPLAY=:1 nohup /root/.vnc/xstartup >>"$LOG" 2>&1 </dev/null &
        if wait_for_port; then exit 0; fi
        echo "[wolfstack-vnc] strategy 2: port still not up, killing Xvnc $XVNC_PID" >>"$LOG"
        kill "$XVNC_PID" 2>/dev/null
    else
        echo "[wolfstack-vnc] strategy 2: Xvnc died immediately" >>"$LOG"
    fi
fi

# Both strategies failed - dump everything we know to stderr so the
# operator sees it in the install / connect console.
echo "wolfstack-vnc-start: FAILED to start VNC on :1" >&2
echo "--- last 80 lines of $LOG ---" >&2
tail -n 80 "$LOG" 2>/dev/null >&2 || true
for f in /root/.vnc/${HOSTNAME}:1.log /root/.vnc/*:1.log; do
    [ -f "$f" ] || continue
    echo "--- $f ---" >&2
    tail -n 80 "$f" >&2
done
echo "--- environment ---" >&2
echo "USER=$USER HOME=$HOME XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" >&2
echo "tigervncserver: $(command -v tigervncserver || echo MISSING)" >&2
echo "Xvnc:           $(command -v Xvnc || echo MISSING)" >&2
echo "vncpasswd:      $(command -v vncpasswd || echo MISSING)" >&2
echo "xauth:          $(command -v xauth || echo MISSING)" >&2
echo "startxfce4:     $(command -v startxfce4 || echo MISSING)" >&2
exit 1
"#;

    // Flatpak setup runs only when the extras bundle was installed —
    // otherwise the `flatpak` binary won't exist and the snippet's
    // `command -v` guard makes it a no-op anyway, but skipping it
    // entirely keeps the install script tidy.
    let flatpak_setup = if extras && chosen.is_some() {
        flatpak_setup_snippet()
    } else {
        ":"  // shell no-op
    };

    let common_tail = format!(r#"
set -e
export DEBIAN_FRONTEND=noninteractive
mkdir -p /root/.vnc
chmod 700 /root/.vnc

# Encrypt password — TigerVNC's vncpasswd reads stdin, writes encrypted to stdout
printf '%s\n' '{password}' | vncpasswd -f > /root/.vnc/passwd
chmod 600 /root/.vnc/passwd

cat > /root/.vnc/xstartup <<'XSTART_EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
[ -r /etc/profile ] && . /etc/profile
if command -v dbus-launch >/dev/null 2>&1; then
    eval "$(dbus-launch --sh-syntax)"
fi
{xstartup_body}
XSTART_EOF
chmod 700 /root/.vnc/xstartup

# wolfstack-vnc-start: idempotent VNC :1 starter, used by the bridge.
# Two strategies — the TigerVNC Perl wrapper (preferred, runs xstartup
# automatically) with a config file we wrote so it doesn't need any
# CLI flags, and a fallback that drives Xvnc directly + spawns xstartup
# ourselves. The fallback covers the case where the Perl wrapper
# refuses to start because of distro-specific defaults / xauth quirks.
cat > /usr/local/bin/wolfstack-vnc-start <<'STARTER_EOF'
{starter_body}
STARTER_EOF
chmod 755 /usr/local/bin/wolfstack-vnc-start

# When the extras bundle was installed, register Flathub as a Flatpak
# remote so the user has an app store ready to use. Best-effort — won't
# abort the install if the network's offline or flatpak isn't there.
{flatpak_setup}

# Create an 'admin' user with password 'admin' so the user has somewhere to
# log in (SSH, su from the VNC terminal, or for desktops that refuse to run
# as root like Chromium and modern GNOME). Idempotent — skipped if already
# exists. Added to sudo (Debian/Ubuntu) / wheel (RHEL) / nothing (Alpine).
if ! id admin >/dev/null 2>&1; then
    # Alpine ships only busybox adduser by default; useradd / chpasswd /
    # usermod live in the 'shadow' package. Pull it in transparently.
    if [ -f /etc/alpine-release ] && ! command -v useradd >/dev/null 2>&1; then
        apk add --no-cache shadow >/dev/null 2>&1 || true
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd -m -s /bin/bash admin 2>/dev/null \
            || useradd -m admin 2>/dev/null \
            || true
    elif command -v adduser >/dev/null 2>&1; then
        adduser -D -s /bin/sh admin 2>/dev/null || true
    fi
    # Best-effort sudo membership — sudo group on Debian/Ubuntu, wheel on RHEL.
    usermod -aG sudo admin 2>/dev/null \
        || usermod -aG wheel admin 2>/dev/null \
        || true
    if command -v chpasswd >/dev/null 2>&1; then
        echo 'admin:admin' | chpasswd 2>/dev/null || true
    fi
fi

echo
echo "================================================================"
echo "  VNC install complete."
echo "================================================================"
echo "Starting VNC server now to verify..."
echo
if /usr/local/bin/wolfstack-vnc-start; then
    echo "VNC server is running on display :1 (port 5901, localhost-only)."
fi
echo
echo "================================================================"
echo "  >>> RESTART THIS CONTAINER NOW <<<"
echo "================================================================"
echo "  Stop and Start the container in WolfStack, then click the VNC"
echo "  icon. Newly-installed desktop packages register dbus services"
echo "  and users that the running systemd hasn't picked up — a clean"
echo "  boot wires everything together properly."
echo "================================================================"
echo
echo "After restart:"
echo "  - Click the green VNC icon on this container's card."
echo "  - Login on the desktop with:  admin / admin"
echo "    (change anytime with:  passwd admin)"
echo
"#);

    // Required packages: TigerVNC + chosen desktop's metapackages + base
    // utilities. These MUST install successfully — if any are missing the
    // VNC server itself can't run, so we want apt/apk/dnf to fail loudly.
    //
    // Extras packages (browser, flatpak, gvfs, applets) are installed in a
    // SEPARATE best-effort pass below. Splitting the calls means a single
    // distro that's missing one extra (e.g. Linux Mint has no firefox-esr
    // candidate) doesn't break the whole transaction and leave the user
    // with no vncpasswd — which was the v20.11.3 install bug.
    let required_pkgs = if let Some(ref d) = chosen {
        d.packages.join(" ")
    } else {
        "xterm".into()
    };
    let extras_pkgs_list = match (extras, chosen.as_ref()) {
        (true, Some(d)) => extras_packages(family, &d.id),
        _ => Vec::new(),
    };
    let extras_pkgs = extras_pkgs_list.join(" ");
    let has_extras = !extras_pkgs_list.is_empty();

    // A full desktop ALWAYS gets a web browser, independent of the optional
    // extras bundle — a desktop with no browser is what users reported as
    // broken. Empty for vnc-only (no desktop) installs.
    let browser_block = if chosen.is_some() {
        match family {
            "debian" => BROWSER_BLOCK_DEBIAN,
            "rhel" => BROWSER_BLOCK_RHEL,
            "alpine" => BROWSER_BLOCK_ALPINE,
            _ => "",
        }
    } else {
        ""
    };
    let label_suffix = chosen.as_ref()
        .map(|d| format!(" + {}{}", d.label, if extras { " + utilities" } else { "" }))
        .unwrap_or_else(|| " (no desktop)".to_string());

    let head = match family {
        "debian" => {
            // Best-effort extras pass: try the bundle in one shot first
            // (fast path), and if apt rejects it (a single missing
            // candidate fails the whole transaction) fall back to
            // installing each extra one-by-one so we keep what's available.
            //
            // Browser is special: Debian ships `firefox-esr`, Ubuntu /
            // Linux Mint ship `firefox`. Try ESR first, then plain
            // firefox. Either is fine — neither is fatal if absent.
            let extras_block = if has_extras {
                format!(r#"
echo "[wolfstack] Installing extras (best-effort)..."
if ! apt-get install -y --no-install-recommends {extras_pkgs}; then
    echo "[wolfstack] extras bundle failed atomic install — retrying per-package"
    for pkg in {extras_pkgs}; do
        apt-get install -y --no-install-recommends "$pkg" \
            || echo "[wolfstack] skipped extra: $pkg (no candidate)"
    done
fi
"#, extras_pkgs = extras_pkgs)
            } else {
                String::new()
            };

            // Desktop install — separate transaction from the VNC core.
            //
            // Why: some LXC templates (notably Mint Zena, which mixes
            // newer Mint-built XFCE/Thunar onto a Jammy libc6 2.35 base)
            // ship a desktop package set whose dependencies cannot be
            // resolved at all. apt-get is atomic, so when those broken
            // deps were bundled into the SAME apt call as
            // tigervnc-tools, the whole transaction aborted and the
            // user ended up with no vncpasswd — the install was dead on
            // arrival. Splitting the calls keeps the VNC server working
            // on broken templates; the user can manually pick a desktop
            // afterwards or just live with the xterm fallback.
            //
            // Fallback chain: chosen DE → LXQt (Qt-based, immune to the
            // GTK t64 transition that breaks XFCE on Mint Zena) → xterm
            // only. We skip the LXQt step if LXQt was already the user's
            // choice (no point retrying the same packages).
            let desktop_block = if let Some(ref d) = chosen {
                let chosen_pkgs = d.packages.join(" ");
                let chosen_id = d.id.clone();
                let chosen_label = d.label.clone();
                let lxqt_fallback = if chosen_id != "lxqt" {
                    r#"
elif apt-get install -y --no-install-recommends lxqt-core qterminal; then
    echo "[wolfstack] LXQt installed as fallback. The chosen desktop's packages couldn't be resolved on this LXC template (commonly seen on Mint Zena LXCs whose XFCE/GTK package set has unsatisfiable t64 dependencies on a Jammy libc6 base). VNC will start LXQt instead."
    DESKTOP_OK=1"#
                } else {
                    ""
                };
                format!(r#"
echo "[wolfstack] Installing desktop: {chosen_label}..."
DESKTOP_OK=0
if apt-get install -y --no-install-recommends {chosen_pkgs}; then
    DESKTOP_OK=1{lxqt_fallback}
fi
if [ "$DESKTOP_OK" = "0" ]; then
    echo "[wolfstack] WARNING: no desktop environment could be installed on this container. The LXC template's package metadata appears to be unable to resolve a working set of XFCE/GTK packages (this is a template-side problem, not WolfStack). VNC will still start — you'll get an xterm fallback. To install a desktop manually later, try: apt-get install lxqt-core qterminal"
fi
"#, chosen_pkgs = chosen_pkgs, chosen_label = chosen_label, lxqt_fallback = lxqt_fallback)
            } else {
                // vnc-only mode: required_pkgs is just "xterm", which is
                // already in the VNC core list, so nothing to do here.
                String::new()
            };

            // Mint LXC templates from images.linuxcontainers.org for Mint
            // 22.x (Wilma / Xia / Zara / Zena) ship with a broken combo:
            // Ubuntu Jammy (22.04) base packages but Mint's own repo
            // (packages.linuxmint.com/<codename>) full of Noble-targeted
            // packages that depend on the t64 ABI transition libraries
            // (libatk1.0-0t64, libglib2.0-0t64, libgtk-3-0t64, libc6 ≥
            // 2.38). None of those exist in Jammy, so any apt install that
            // pulls in Mint's Thunar / xfce4-session aborts with "held
            // broken packages". Root cause is upstream:
            //   https://github.com/lxc/lxc-ci/blob/main/jenkins/jobs/image-mint.yaml
            // hard-codes source.suite=jammy for every codename except the
            // Mint 20.x ones — so Mint 22.x images were built on the wrong
            // Ubuntu base.
            //
            // Workaround: pin packages.linuxmint.com to priority 100 (below
            // Ubuntu's default 500) before the desktop install. apt then
            // prefers Ubuntu Jammy's xfce4 over Mint's Noble-targeted
            // xfce4 — same metapackage, but the Jammy version's deps stay
            // Jammy-consistent and resolve cleanly. Safe on Mint 21.x too
            // (where Jammy IS the right base) because the Mint and Ubuntu
            // versions of these packages are typically identical there, so
            // pinning is a no-op.
            format!(r#"
echo "[wolfstack] Installing TigerVNC{label_suffix} on Debian/Ubuntu container..."

# Mint LXC fix: when packages.linuxmint.com is enabled, pin it lower
# than the Ubuntu base repo so apt picks Ubuntu's Jammy-consistent
# versions of any package that exists in both. Works around an upstream
# linuxcontainers.org bug (Mint 22.x images built on Jammy base instead
# of Noble) that otherwise makes XFCE / Thunar / xfce4-session
# unresolvable.
#
# Detection is format-agnostic: matches either legacy
# `deb http://packages.linuxmint.com …` lines or modern deb822
# `URIs: http://packages.linuxmint.com` lines, while skipping any line
# whose first non-space char is a comment `#`. Recurses into
# /etc/apt/sources.list.d so we don't miss differently-named files.
if grep -RhsE "^[^#]*packages\.linuxmint\.com" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null \
    | grep -q .; then
    echo "[wolfstack] Detected Linux Mint apt repo — pinning it below Ubuntu so xfce4 deps resolve against the Ubuntu base (works around upstream lxc-ci jammy/noble mismatch on Mint 22.x LXC templates)."
    cat > /etc/apt/preferences.d/wolfstack-mint-fix.pref <<'WOLFSTACK_PREF_EOF'
# Written by WolfStack VNC installer.
# The linuxcontainers.org Mint 22.x LXC templates (Wilma / Xia / Zara /
# Zena) use an Ubuntu Jammy base but expose the Mint repo's
# Noble-targeted xfce4/thunar packages whose t64 deps don't exist in
# Jammy. Pinning the Mint repo below Ubuntu lets apt fall back to
# Ubuntu's Jammy-consistent versions for packages that exist in both.
# Mint-only packages (themes, Cinnamon polish) are unaffected.
# Safe to delete this file once you're on a corrected Mint LXC template.
Package: *
Pin: origin packages.linuxmint.com
Pin-Priority: 100
WOLFSTACK_PREF_EOF
fi

# Recover from an interrupted dpkg state before touching apt. Some LXC
# templates ship with a half-configured dpkg database (or a prior apt/install
# inside the container was killed), which makes EVERY apt operation abort at
# the gate with "dpkg was interrupted, you must manually run 'dpkg --configure
# -a'" — exactly the failure that left a user with no vncpasswd and an
# "exit 127" install. Setting the frontend non-interactive first means neither
# command can stop on a debconf prompt; both are idempotent (a no-op on a clean
# database), so this can only ever unblock a stuck container, never break a
# healthy one.
export DEBIAN_FRONTEND=noninteractive
dpkg --configure -a 2>/dev/null || true
apt-get install -f -y 2>/dev/null || true

apt-get update -qq
# Step 1: VNC core — must succeed. tigervnc-tools provides vncpasswd.
# Kept in its own apt transaction so a broken desktop package set on the
# LXC template (see desktop step below) cannot take the VNC server down
# with it.
apt-get install -y --no-install-recommends \
    tigervnc-standalone-server tigervnc-common tigervnc-tools \
    dbus-x11 socat xterm fonts-dejavu \
    procps
{desktop_block}{extras_block}{browser_block}
"#, label_suffix = label_suffix, desktop_block = desktop_block, extras_block = extras_block, browser_block = browser_block)
        }

        "alpine" => {
            let extras_block = if has_extras {
                format!(r#"
echo "[wolfstack] Installing extras (best-effort)..."
if ! apk add --no-cache {extras_pkgs}; then
    for pkg in {extras_pkgs}; do
        apk add --no-cache "$pkg" \
            || echo "[wolfstack] skipped extra: $pkg (not in repo)"
    done
fi
"#, extras_pkgs = extras_pkgs)
            } else {
                String::new()
            };
            format!(r#"
echo "[wolfstack] Installing TigerVNC{label_suffix} on Alpine container..."
apk update
# Alpine: busybox already provides pgrep, so no procps needed.
apk add --no-cache \
    tigervnc \
    {required_pkgs} \
    dbus-x11 socat xterm ttf-dejavu
{extras_block}{browser_block}
"#, label_suffix = label_suffix, required_pkgs = required_pkgs, extras_block = extras_block, browser_block = browser_block)
        }

        "rhel" => {
            let extras_block = if has_extras {
                format!(r#"
echo "[wolfstack] Installing extras (best-effort)..."
if ! $PKG {extras_pkgs}; then
    for pkg in {extras_pkgs}; do
        $PKG "$pkg" \
            || echo "[wolfstack] skipped extra: $pkg (no candidate)"
    done
fi
"#, extras_pkgs = extras_pkgs)
            } else {
                String::new()
            };
            format!(r#"
echo "[wolfstack] Installing TigerVNC{label_suffix} on RHEL-family container..."
if command -v dnf >/dev/null 2>&1; then
    PKG="dnf -y install"
    dnf -y install epel-release 2>/dev/null || true
elif command -v yum >/dev/null 2>&1; then
    PKG="yum -y install"
    yum -y install epel-release 2>/dev/null || true
else
    echo "No dnf or yum found"; exit 1
fi
# tigervnc client package provides vncpasswd on RHEL family.
$PKG tigervnc-server tigervnc \
     {required_pkgs} \
     dbus-x11 socat xterm dejavu-sans-fonts procps-ng
{extras_block}{browser_block}
"#, label_suffix = label_suffix, required_pkgs = required_pkgs, extras_block = extras_block, browser_block = browser_block)
        }

        _ => return String::new(),
    };

    format!("{}{}", head, common_tail)
}

/// Ensure /etc/wolfstack/container-vnc.json has an entry with a password
/// for this container, returning the (possibly-existing) password.
fn ensure_password(runtime: &str, name: &str) -> Result<String, String> {
    let key = config_key(runtime, name);
    let mut map = load_config();
    if let Some(e) = map.get(&key) {
        return Ok(e.password.clone());
    }
    let password = generate_password();
    map.insert(key, VncEntry {
        runtime: runtime.to_string(),
        name: name.to_string(),
        password: password.clone(),
        installed_at: chrono::Utc::now().to_rfc3339(),
    });
    save_config(&map)?;
    Ok(password)
}

// ---- prepared install scripts (looked up by session_id from console.rs) ----

#[derive(Clone)]
pub struct PreparedInstall {
    pub runtime: String,
    pub name: String,
    pub host_script_path: String,
}

static PREPARED_INSTALLS: std::sync::LazyLock<Mutex<HashMap<String, PreparedInstall>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Look up a prepared install by session_id (called from console.rs).
pub fn take_prepared_install(session_id: &str) -> Option<PreparedInstall> {
    PREPARED_INSTALLS.lock().ok()?.remove(session_id)
}

fn random_session_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    let mut s = String::with_capacity(16);
    for b in &buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ===========================================================================
// REST endpoints
// ===========================================================================

/// GET /api/container-vnc/{runtime}/{name}/status
///
/// Returns the OS info (so the frontend modal can show the user what
/// will be installed), and whether VNC is already installed / running
/// inside the container.
pub async fn vnc_status(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    // OS detection — also tells us if the container is running (exec fails otherwise).
    let os = match detect_os(&runtime, &name) {
        Ok(o) => Some(o),
        Err(e) => {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "installed": false,
                "running": false,
                "container_running": false,
                "os": null,
                "error": format!("Cannot inspect container: {}", e),
            })));
        }
    };

    // Probe inside the container for VNC presence + state.
    // /root/.vnc/passwd → password file written by our installer
    // pgrep Xvnc → whether display :1 is currently running
    let probe = "if [ -f /root/.vnc/passwd ] && [ -x /usr/local/bin/wolfstack-vnc-start ]; \
                 then echo INSTALLED; else echo NOT_INSTALLED; fi; \
                 if pgrep -f 'Xvnc.*:1|Xtigervnc.*:1' >/dev/null 2>&1; \
                 then echo RUNNING; else echo NOT_RUNNING; fi";
    let (installed, running) = match container_exec(&runtime, &name, probe) {
        Ok((_, stdout, _)) => {
            let installed = stdout.contains("INSTALLED") && !stdout.contains("NOT_INSTALLED");
            let running = stdout.contains("RUNNING") && !stdout.contains("NOT_RUNNING");
            (installed, running)
        }
        Err(_) => (false, false),
    };

    // We treat "installed" as: marker files exist AND we have a stored password.
    let stored = load_config().get(&config_key(&runtime, &name)).cloned();
    let installed_final = installed && stored.is_some();
    let password = if installed_final { stored.map(|e| e.password) } else { None };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "installed": installed_final,
        "running": running,
        "container_running": true,
        "os": os,
        "password": password,
    })))
}

/// Body for POST /api/container-vnc/{runtime}/{name}/prepare-install.
/// `mode` is "full" (install a desktop) or "vnc-only" (no desktop —
/// reuse whatever's in the container, fall back to xterm). `desktop`
/// picks which DE to install when mode == "full"; one of the ids in
/// `OsInfo.available_desktops` (xfce / mate / lxqt / cinnamon / kde /
/// gnome). Defaults to "xfce" — lightest, most reliable in LXC.
/// `extras` controls whether to also install the common-utilities bundle
/// (browser, Flatpak + Flathub, file/archive helpers, network applet,
/// DE polish). Defaults to true — turns a bare metapackage desktop into
/// a usable one. Ignored for mode == "vnc-only".
#[derive(Deserialize, Default)]
pub struct PrepareInstallRequest {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub desktop: Option<String>,
    #[serde(default)]
    pub extras: Option<bool>,
}

/// POST /api/container-vnc/{runtime}/{name}/prepare-install
///
/// Generates+stores a VNC password, writes the install script to /tmp,
/// and returns a session_id. The frontend then opens a console session
/// at /ws/console/vnc-install/{session_id} which streams the install live.
pub async fn vnc_prepare_install(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: Option<web::Json<PrepareInstallRequest>>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    let mode = body
        .as_ref()
        .and_then(|b| b.mode.clone())
        .unwrap_or_else(|| "full".to_string());
    let with_desktop = match mode.as_str() {
        "full" => true,
        "vnc-only" => false,
        _ => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "mode must be 'full' or 'vnc-only'",
            })));
        }
    };

    let os = match detect_os(&runtime, &name) {
        Ok(o) => o,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Cannot detect OS: {}", e),
            })));
        }
    };
    if !os.supported {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unsupported OS: {} ({}). Supported: Debian/Ubuntu, Alpine, RHEL/Rocky/Fedora.", os.id, os.id_like),
        })));
    }

    let password = match ensure_password(&runtime, &name) {
        Ok(p) => p,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Cannot persist VNC password: {}", e),
            })));
        }
    };

    let desktop_id = body.as_ref().and_then(|b| b.desktop.clone());
    // Default extras = true: a bare metapackage desktop feels broken
    // without a browser, file utilities, network applet, or Flatpak.
    let extras = body.as_ref().and_then(|b| b.extras).unwrap_or(true);
    let script = build_install_script(
        &os.family,
        &password,
        with_desktop,
        os.detected_desktop.as_deref(),
        desktop_id.as_deref(),
        extras,
    );
    if script.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Internal: empty install script for supported OS",
        })));
    }

    let session_id = random_session_id();
    let host_script_path = format!("/tmp/wolfstack-vnc-install-{}.sh", session_id);
    if let Err(e) = crate::paths::write_secure(&host_script_path, &script) {
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Cannot write install script: {}", e),
        })));
    }

    if let Ok(mut map) = PREPARED_INSTALLS.lock() {
        map.insert(session_id.clone(), PreparedInstall {
            runtime: runtime.clone(),
            name: name.clone(),
            host_script_path: host_script_path.clone(),
        });
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "ws_path": format!("/ws/console/vnc-install/{}", session_id),
        "os": os,
    })))
}

/// POST /api/container-vnc/{runtime}/{name}/uninstall
///
/// Just forgets the stored password and removes our marker files inside
/// the container. Doesn't uninstall packages — those are useful and the
/// user installed them deliberately.
pub async fn vnc_uninstall(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    let key = config_key(&runtime, &name);
    let mut map = load_config();
    map.remove(&key);
    if let Err(e) = save_config(&map) {
        warn!("Failed to save VNC config after uninstall: {}", e);
    }

    // Best-effort: stop the VNC server and delete the marker files.
    let cleanup = "if command -v tigervncserver >/dev/null 2>&1; then \
                       tigervncserver -kill :1 >/dev/null 2>&1 || true; \
                   elif command -v vncserver >/dev/null 2>&1; then \
                       vncserver -kill :1 >/dev/null 2>&1 || true; fi; \
                   pkill -f 'Xvnc.*:1' 2>/dev/null || true; \
                   pkill -f 'Xtigervnc.*:1' 2>/dev/null || true; \
                   rm -f /root/.vnc/passwd /usr/local/bin/wolfstack-vnc-start";
    let _ = container_exec(&runtime, &name, cleanup);

    Ok(HttpResponse::Ok().json(serde_json::json!({ "ok": true })))
}

// ===========================================================================
// WebSocket bridge
// ===========================================================================

/// GET /ws/container-vnc/{runtime}/{name}
///
/// Spawns `<runtime exec> -- sh -c 'wolfstack-vnc-start; exec socat STDIO TCP:127.0.0.1:5901'`
/// and shuttles the child's stdio ↔ noVNC binary frames.
pub async fn container_vnc_ws(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    if !load_config().contains_key(&config_key(&runtime, &name)) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "VNC is not installed for this container — run install first",
        })));
    }

    // Pre-flight: run wolfstack-vnc-start synchronously so we can
    // capture its full diagnostic output and surface it to the user as
    // an HTTP 502 instead of a hung WebSocket. Previously the bridge
    // command swallowed stderr to /dev/null; if Strategy 1 + Strategy 2
    // both failed inside the container, the WS connected and just sat
    // there with no bytes flowing — the user saw "Connecting..." forever.
    let pre_cmd = "/usr/local/bin/wolfstack-vnc-start 2>&1";
    match container_exec(&runtime, &name, pre_cmd) {
        Ok((0, _, _)) => { /* up — proceed to bridge */ }
        Ok((rc, stdout, stderr)) => {
            let mut detail = stdout;
            if !stderr.is_empty() {
                if !detail.is_empty() { detail.push('\n'); }
                detail.push_str(&stderr);
            }
            return Ok(HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("Could not start VNC server inside container (exit {}). See diagnostic below.", rc),
                "diagnostic": detail,
            })));
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to invoke VNC start in container: {}", e),
            })));
        }
    }

    // Bridge command: socat stdio ↔ TCP 127.0.0.1:5901. exec so socat
    // replaces the shell — clean process tree, signals propagate.
    const BRIDGE_CMD: &str = "exec socat STDIO TCP:127.0.0.1:5901";

    let argv = match build_exec_argv(&runtime, &name, BRIDGE_CMD) {
        Ok(a) => a,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": e })));
        }
    };

    let mut command = tokio::process::Command::new(&argv[0]);
    command.args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to spawn VNC bridge for {}/{}: {}", runtime, name, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to spawn VNC bridge: {}", e),
            })));
        }
    };

    let stdin = match child.stdin.take() {
        Some(s) => s,
        None => return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to capture child stdin",
        }))),
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to capture child stdout",
        }))),
    };

    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;
    actix_rt::spawn(bridge_stdio_to_ws(session, msg_stream, child, stdin, stdout));
    Ok(response)
}

/// Bidirectional bridge: child stdio ↔ noVNC binary WebSocket frames.
/// Child stdout is RFB protocol bytes from socat; we forward as binary frames.
/// Browser sends RFB binary frames; we write to child stdin.
async fn bridge_stdio_to_ws(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    mut child: tokio::process::Child,
    mut stdin: tokio::process::ChildStdin,
    mut stdout: tokio::process::ChildStdout,
) {
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            // child stdout (VNC server bytes) → browser
            result = stdout.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if session.binary(buf[..n].to_vec()).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }

            // browser → child stdin
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if stdin.write_all(&data).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if stdin.write_all(text.as_bytes()).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    // kill_on_drop will reap the child when `child` is dropped at function exit.
    let _ = child.start_kill();
    let _ = session.close(None).await;
}

/// GET /api/container-vnc/list
///
/// Returns the keys of every container that has been set up for VNC,
/// so the frontend can show the VNC icon on the right rows without
/// having to probe each container individually.
pub async fn vnc_list(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let map = load_config();
    let keys: Vec<&String> = map.keys().collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({ "keys": keys })))
}

#[cfg(test)]
mod browser_install_tests {
    use super::*;

    #[test]
    fn full_desktop_always_installs_a_browser_even_with_extras_off() {
        for family in ["debian", "rhel", "alpine"] {
            let script = build_install_script(family, "pw", true, None, Some("xfce"), false);
            assert!(
                script.contains("Installing a web browser"),
                "{family}: a full desktop must install a browser even when extras are off"
            );
            assert!(
                script.contains("firefox"),
                "{family}: the browser step should install firefox"
            );
        }
    }

    #[test]
    fn vnc_only_install_has_no_browser_block() {
        // No desktop selected -> no browser step (nothing to put it on).
        for family in ["debian", "rhel", "alpine"] {
            let script = build_install_script(family, "pw", false, None, None, true);
            assert!(
                !script.contains("Installing a web browser"),
                "{family}: vnc-only install must not run the browser block"
            );
        }
    }

    #[test]
    fn generated_install_scripts_are_shell_valid() {
        // Catches an unbalanced quote/paren/heredoc in the generated script —
        // exactly the failure that would leave a user mid-install. Best-effort:
        // skip if bash isn't on the test host.
        if std::process::Command::new("bash").arg("-c").arg("true").output().is_err() {
            return;
        }
        for family in ["debian", "rhel", "alpine"] {
            for extras in [true, false] {
                let script = build_install_script(family, "pw", true, None, Some("xfce"), extras);
                let path = std::env::temp_dir()
                    .join(format!("wolfstack-vnc-{}-{}-{}.sh", family, extras, std::process::id()));
                std::fs::write(&path, &script).unwrap();
                let out = std::process::Command::new("bash").arg("-n").arg(&path).output().unwrap();
                let _ = std::fs::remove_file(&path);
                assert!(
                    out.status.success(),
                    "{family} (extras={extras}): generated install script has a shell syntax error:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}
