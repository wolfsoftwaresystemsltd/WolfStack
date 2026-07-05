// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Distro-aware dependency detection and installation.
//!
//! WolfStack touches a lot of third-party tools (dnsmasq, iproute2,
//! wireguard, qemu…) and the packages that ship them vary by distro
//! (apt on Debian/Ubuntu/PVE, dnf on Fedora/RHEL, pacman on Arch,
//! apk on Alpine, zypper on openSUSE). This module centralises:
//!
//!   • distro family detection (reads /etc/os-release)
//!   • a registry of logical deps → per-distro package names
//!   • `check(group)` — which deps are already satisfied on this node
//!   • `install(group)` — run the local pkg manager non-interactively
//!
//! Each node runs the check/install locally; cross-node calls go via
//! the standard `/api/nodes/{id}/proxy/...` pattern so every node
//! answers for its own OS. We never try to install "remotely" in any
//! other sense — the operator picks the node, we install there.

use serde::Serialize;
use std::process::Command;

/// Package manager family. One per distro family we know how to drive.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PkgMgr {
    Apt,      // Debian, Ubuntu, Proxmox VE
    Dnf,      // Fedora, RHEL 8+, Rocky, AlmaLinux
    Yum,      // RHEL/CentOS 7 (fallback when dnf absent)
    Pacman,   // Arch, CachyOS, Manjaro, EndeavourOS
    Apk,      // Alpine
    Zypper,   // openSUSE, SLES
    Unknown,
}

impl PkgMgr {
    /// Human label for the UI.
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            PkgMgr::Apt => "apt",
            PkgMgr::Dnf => "dnf",
            PkgMgr::Yum => "yum",
            PkgMgr::Pacman => "pacman",
            PkgMgr::Apk => "apk",
            PkgMgr::Zypper => "zypper",
            PkgMgr::Unknown => "unknown",
        }
    }

    /// Command template for installing the given packages. Shown to the
    /// operator before we run it and also offered as a copy-paste hint
    /// so they can run it by hand if they'd rather. Non-interactive
    /// flags are baked in (-y / --noconfirm / etc.) — the UI adds
    /// `sudo` only when not already root.
    pub fn install_cmd(&self, pkgs: &[&str]) -> String {
        let joined = pkgs.join(" ");
        match self {
            // apt: update first so new installs see the current index.
            // DEBIAN_FRONTEND=noninteractive stops installers from
            // prompting for config-file conflicts during unattended runs.
            PkgMgr::Apt => format!(
                "DEBIAN_FRONTEND=noninteractive apt-get update && \
                 DEBIAN_FRONTEND=noninteractive apt-get install -y {joined}"
            ),
            PkgMgr::Dnf => format!("dnf install -y {joined}"),
            PkgMgr::Yum => format!("yum install -y {joined}"),
            // --needed skips already-installed packages so a second run
            // of the same install is a no-op instead of a reinstall.
            PkgMgr::Pacman => format!("pacman -S --noconfirm --needed {joined}"),
            PkgMgr::Apk => format!("apk add --no-cache {joined}"),
            PkgMgr::Zypper => format!("zypper --non-interactive install {joined}"),
            PkgMgr::Unknown => format!("# Install manually: {joined}"),
        }
    }
}

/// A logical dependency — the binary we need on PATH plus per-distro
/// package names that provide it. All fields carry `Option<&str>` so a
/// dep can be "bundled into the base OS" on one distro (None → assumed
/// present) while a separate package elsewhere.
#[derive(Debug, Clone, Copy)]
pub struct Dep {
    /// Logical ID — matches the key the UI/API refers to.
    pub id: &'static str,
    /// Human label shown in the UI.
    pub label: &'static str,
    /// Binary presence test. If any of these are on PATH we consider the
    /// dep satisfied without reading the package database (faster and
    /// doesn't require the pkg manager to be responsive).
    pub binaries: &'static [&'static str],
    /// Per-distro package names.
    pub apt: Option<&'static str>,
    pub dnf: Option<&'static str>,
    pub pacman: Option<&'static str>,
    pub apk: Option<&'static str>,
    pub zypper: Option<&'static str>,
    /// Short note for the UI (e.g. "needed for port 53 detection").
    pub rationale: &'static str,
}

impl Dep {
    /// Pick the package name for the given pkg manager, or None if this
    /// dep isn't packaged on that distro (or is part of the base OS).
    pub fn package_for(&self, mgr: PkgMgr) -> Option<&'static str> {
        match mgr {
            PkgMgr::Apt => self.apt,
            PkgMgr::Dnf | PkgMgr::Yum => self.dnf,
            PkgMgr::Pacman => self.pacman,
            PkgMgr::Apk => self.apk,
            PkgMgr::Zypper => self.zypper,
            PkgMgr::Unknown => None,
        }
    }
}

/// Registry of deps used by WolfRouter's DNS/LAN features. Kept static
/// so routes can reference groups by id. Adding a new surface (VM,
/// WolfNet, etc.) = add another group below.
pub const DNS_DEPS: &[&Dep] = &[
    &Dep {
        id: "dnsmasq",
        label: "dnsmasq (DHCP + DNS server)",
        binaries: &["dnsmasq"],
        apt: Some("dnsmasq"),
        dnf: Some("dnsmasq"),
        pacman: Some("dnsmasq"),
        apk: Some("dnsmasq"),
        zypper: Some("dnsmasq"),
        rationale: "Required — WolfRouter uses one dnsmasq instance per LAN for DHCP and DNS.",
    },
    &Dep {
        id: "iproute2",
        label: "iproute2 (ss, ip)",
        binaries: &["ss", "ip"],
        apt: Some("iproute2"),
        // Fedora/RHEL ship it as `iproute`, but base minimal images
        // usually include it already — install is a no-op in practice.
        dnf: Some("iproute"),
        pacman: Some("iproute2"),
        apk: Some("iproute2"),
        zypper: Some("iproute2"),
        rationale: "Needed for port 53 owner detection (ss) and interface probing (ip).",
    },
    &Dep {
        id: "e2fsprogs",
        label: "e2fsprogs (lsattr, chattr)",
        binaries: &["lsattr", "chattr"],
        apt: Some("e2fsprogs"),
        dnf: Some("e2fsprogs"),
        pacman: Some("e2fsprogs"),
        apk: Some("e2fsprogs"),
        zypper: Some("e2fsprogs"),
        rationale: "Detects/fixes the immutable flag on /etc/resolv.conf when releasing port 53.",
    },
    &Dep {
        id: "dig",
        label: "DNS lookup tools (dig)",
        binaries: &["dig"],
        apt: Some("dnsutils"),          // Debian/Ubuntu splits dig into dnsutils
        dnf: Some("bind-utils"),        // Fedora/RHEL family
        pacman: Some("bind"),           // Arch ships dig in the `bind` package
        apk: Some("bind-tools"),        // Alpine
        zypper: Some("bind-utils"),
        rationale: "Optional — used by DNS diagnostics tests to sanity-check upstream resolvers.",
    },
    &Dep {
        id: "systemd_resolved",
        label: "systemd-resolved",
        binaries: &["resolvectl"],
        // Ubuntu 22.04+ split systemd-resolved into a separate package.
        // On other systemd distros it's bundled with systemd itself and
        // we don't need to install anything — `binaries` check passes
        // when resolvectl is present.
        apt: Some("systemd-resolved"),
        dnf: None,
        pacman: None,
        apk: None,        // Alpine uses openrc; feature inapplicable.
        zypper: None,
        rationale: "Optional — required only if you want the one-click 'release port 53' button.",
    },
];

/// Lookup a dep group by id. Keeps the API surface tiny — the frontend
/// sends a group name, we answer with the registry.
pub fn group(name: &str) -> Option<&'static [&'static Dep]> {
    match name {
        "dns" => Some(DNS_DEPS),
        _ => None,
    }
}

/// Per-dep status surfaced to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct DepStatus {
    pub id: &'static str,
    pub label: &'static str,
    pub rationale: &'static str,
    /// True when any of the dep's binaries is already on PATH.
    pub installed: bool,
    /// Binaries that resolved (for the UI to show paths).
    pub found_binaries: Vec<String>,
    /// Package name we'd install on this host, if we have one for this
    /// distro. None means "nothing to install here" (either bundled or
    /// not packaged on this distro) — the UI greys out the install row.
    pub package: Option<&'static str>,
}

/// Top-level check response. Includes distro + pkg manager so the UI
/// can tell the operator which node they're looking at and what command
/// we'd run.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub distro: String,
    pub pkg_mgr: PkgMgr,
    pub is_root: bool,
    /// The exact command that would run if the operator clicks Install
    /// for everything missing. Empty when nothing needs installing.
    pub install_cmd: String,
    pub deps: Vec<DepStatus>,
}

/// Probe the local node: detect distro, iterate deps, check binaries,
/// build the install command for whatever's missing.
pub fn check(group_name: &str) -> Result<CheckResult, String> {
    let deps = group(group_name).ok_or_else(|| format!("unknown dep group '{}'", group_name))?;
    let (distro, pkg_mgr) = detect_distro_and_pkgmgr();
    let is_root = is_root();

    let mut statuses = Vec::with_capacity(deps.len());
    let mut missing_pkgs: Vec<&str> = Vec::new();
    for d in deps {
        let mut found = Vec::new();
        for bin in d.binaries {
            if let Some(path) = which(bin) { found.push(path); }
        }
        let installed = !found.is_empty();
        let package = d.package_for(pkg_mgr);
        if !installed {
            if let Some(p) = package { missing_pkgs.push(p); }
        }
        statuses.push(DepStatus {
            id: d.id,
            label: d.label,
            rationale: d.rationale,
            installed,
            found_binaries: found,
            package,
        });
    }

    // Deduplicate in case two deps map to the same package (rare but
    // guards against accidental registry collisions).
    missing_pkgs.sort();
    missing_pkgs.dedup();

    let install_cmd = if missing_pkgs.is_empty() {
        String::new()
    } else {
        pkg_mgr.install_cmd(&missing_pkgs)
    };

    Ok(CheckResult {
        distro,
        pkg_mgr,
        is_root,
        install_cmd,
        deps: statuses,
    })
}

/// Run the install for a group. Returns the command output so the UI
/// can show the operator what actually happened (stdout + stderr
/// joined, newest last). This is intentionally synchronous — install
/// jobs take seconds not minutes, and streaming would triple the code
/// for little UX gain.
pub fn install(group_name: &str) -> Result<InstallResult, String> {
    let res = check(group_name)?;
    if res.install_cmd.is_empty() {
        return Ok(InstallResult {
            ran: false,
            command: String::new(),
            exit_code: 0,
            output: "Nothing to install — all dependencies already present.".into(),
        });
    }
    if !res.is_root {
        return Err(
            "Install needs root. WolfStack normally runs as root; if this \
             node is running unprivileged, run the suggested command \
             manually via sudo."
                .into(),
        );
    }
    if res.pkg_mgr == PkgMgr::Unknown {
        return Err(format!(
            "Unknown package manager on distro '{}'. Install manually: {}",
            res.distro, res.install_cmd
        ));
    }

    // We build the cmdline once (above) and execute via `sh -c` so the
    // `&&` and env-var prefixes (DEBIAN_FRONTEND) work unchanged. That
    // also keeps the audit trail identical between "what we showed" and
    // "what we ran" — no hidden argv mutations.
    let out = Command::new("sh")
        .arg("-c")
        .arg(&res.install_cmd)
        .output()
        .map_err(|e| format!("spawn shell: {}", e))?;
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        if !combined.is_empty() && !combined.ends_with('\n') { combined.push('\n'); }
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Ok(InstallResult {
        ran: true,
        command: res.install_cmd,
        exit_code: out.status.code().unwrap_or(-1),
        output: combined,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallResult {
    pub ran: bool,
    pub command: String,
    pub exit_code: i32,
    pub output: String,
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn which(bin: &str) -> Option<String> {
    let out = Command::new("which").arg(bin).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

pub(crate) fn is_root() -> bool {
    // Safe because geteuid is a pure syscall with no args and a
    // trivially-valid return type. We avoid pulling in the `nix` crate
    // just for this one call.
    unsafe { libc::geteuid() == 0 }
}

/// Read /etc/os-release and map ID / ID_LIKE to a pkg manager. Returns
/// the raw ID string for UI display plus the manager enum.
fn detect_distro_and_pkgmgr() -> (String, PkgMgr) {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut id = String::new();
    let mut id_like = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ID=") { id = v.trim_matches('"').to_lowercase(); }
        if let Some(v) = line.strip_prefix("ID_LIKE=") { id_like = v.trim_matches('"').to_lowercase(); }
    }

    let mgr = match id.as_str() {
        "debian" | "ubuntu" | "raspbian" | "linuxmint" | "pop" | "pureos" | "kali" => PkgMgr::Apt,
        // Proxmox VE (`pve`) and other Debian derivatives announce
        // themselves via ID_LIKE rather than ID.
        _ if id_like.contains("debian") => PkgMgr::Apt,
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "amzn" => {
            // Prefer dnf, fall back to yum on very old RHEL/CentOS.
            if which("dnf").is_some() { PkgMgr::Dnf } else { PkgMgr::Yum }
        }
        _ if id_like.contains("rhel") || id_like.contains("fedora") => {
            if which("dnf").is_some() { PkgMgr::Dnf } else { PkgMgr::Yum }
        }
        "arch" | "cachyos" | "manjaro" | "endeavouros" | "artix" => PkgMgr::Pacman,
        _ if id_like.contains("arch") => PkgMgr::Pacman,
        "alpine" => PkgMgr::Apk,
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "suse" => PkgMgr::Zypper,
        _ if id_like.contains("suse") => PkgMgr::Zypper,
        _ => PkgMgr::Unknown,
    };

    let pretty = if id.is_empty() { "unknown".into() } else { id };
    (pretty, mgr)
}
