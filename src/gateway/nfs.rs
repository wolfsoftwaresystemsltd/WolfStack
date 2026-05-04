// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! NFS export configuration.
//!
//! Per-gateway exports are written to
//! `/etc/exports.d/wolfstack-<gateway>.exports` and `exportfs -ra`
//! reloads the kernel server. We never edit `/etc/exports` itself —
//! `exports.d` is the standard drop-in mechanism on every Linux NFS
//! server (nfs-kernel-server, nfs-utils, etc).
//!
//! Anonymous gateways export with `(rw,sync,no_subtree_check,
//! all_squash,anonuid=65534,anongid=65534)`. Users-mode and AD are
//! unsupported in v1.0 NFS — NFSv3 has no real auth (just trust the
//! IP), and NFSv4 with krb5 needs an AD/Kerberos setup we ship in
//! v1.2+. Until then, `auth=users` gateways skip NFS export and the
//! UI flags it.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{AuthConfig, Gateway, NfsVersion, Protocol};

const EXPORTS_DIR: &str = "/etc/exports.d";

#[derive(Debug)]
pub enum NfsError {
    NotInstalled { install_command: String, install_package: String },
    WriteFailed(String),
    ReloadFailed(String),
    Skipped(&'static str),
    Io(std::io::Error),
}

impl std::fmt::Display for NfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NfsError::NotInstalled { install_package, .. } => {
                write!(f, "nfs server not installed (install package '{}')", install_package)
            }
            NfsError::WriteFailed(s) => write!(f, "exports write failed: {}", s),
            NfsError::ReloadFailed(s) => write!(f, "exportfs reload failed: {}", s),
            NfsError::Skipped(s) => write!(f, "nfs export skipped: {}", s),
            NfsError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl From<std::io::Error> for NfsError {
    fn from(e: std::io::Error) -> Self { NfsError::Io(e) }
}

pub fn require_nfs_server() -> Result<(), NfsError> {
    if super::sources::which_helper("exportfs").is_none() {
        return Err(NfsError::NotInstalled {
            install_command: "apt-get install -y nfs-kernel-server".to_string(),
            install_package: "nfs-kernel-server".to_string(),
        });
    }
    Ok(())
}

pub fn write_gateway_export(g: &Gateway, share_path: &Path) -> Result<(), NfsError> {
    if !g.protocols.contains(&Protocol::Nfs) {
        let _ = std::fs::remove_file(export_path(&g.id));
        let _ = reload_exports();
        return Ok(());
    }
    // NFS auth in v1.0 is IP-based only. `users` and `ad` skip NFS
    // export with a clear reason; SMB still works for those gateways.
    if !matches!(g.auth, AuthConfig::Anonymous { .. }) {
        let _ = std::fs::remove_file(export_path(&g.id));
        let _ = reload_exports();
        return Err(NfsError::Skipped(
            "NFS export skipped — users/AD auth not supported on NFS in v1.0; SMB clients still work",
        ));
    }
    require_nfs_server()?;
    std::fs::create_dir_all(EXPORTS_DIR)?;
    let body = render(g, share_path);
    let path = export_path(&g.id);
    std::fs::write(&path, body).map_err(|e| NfsError::WriteFailed(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }
    reload_exports()?;
    Ok(())
}

pub fn remove_gateway_export(gateway_id: &str) -> Result<(), NfsError> {
    let path = export_path(gateway_id);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let _ = reload_exports();
    Ok(())
}

fn export_path(gateway_id: &str) -> PathBuf {
    PathBuf::from(EXPORTS_DIR).join(format!("wolfstack-{}.exports", sanitise(gateway_id)))
}

fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn render(g: &Gateway, share_path: &Path) -> String {
    let writable = matches!(g.auth, AuthConfig::Anonymous { writable: true })
        && !g.options.readonly;
    let rw = if writable { "rw" } else { "ro" };
    let mut opts = vec![
        rw,
        "sync",
        "no_subtree_check",
        "all_squash",
        "anonuid=65534",
        "anongid=65534",
        "fsid=0", // makes this a root-of-namespace export for NFSv4
    ];
    let nfsver = match g.options.nfs_version {
        NfsVersion::V3   => "vers=3",
        NfsVersion::V4   => "vers=4",
        NfsVersion::V4_2 => "vers=4.2",
    };
    opts.push(nfsver);

    // CIDR allowlist. If empty, export to the world (with a warning
    // the UI surfaces). If specified, one line per allowed range.
    let mut clients: Vec<String> = g.options.allow_hosts.clone();
    if clients.is_empty() {
        clients.push("*".to_string());
    }

    let mut out = String::new();
    out.push_str(&format!("# WolfStack gateway: {} ({})\n", g.name, g.id));
    let opts_str = opts.join(",");
    for c in &clients {
        out.push_str(&format!("{} {}({})\n", share_path.display(), c, opts_str));
    }
    out
}

fn reload_exports() -> Result<(), NfsError> {
    require_nfs_server()?;
    let out = Command::new("exportfs").arg("-ra").output()?;
    if !out.status.success() {
        return Err(NfsError::ReloadFailed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct NfsStatus {
    pub installed: bool,
    pub running: bool,
    pub exports: u32,
}

pub fn status() -> NfsStatus {
    let mut st = NfsStatus::default();
    st.installed = super::sources::which_helper("exportfs").is_some();
    if st.installed {
        // Multi-distro probe: nfs-server (Arch/openSUSE/Fedora),
        // nfs-kernel-server (Debian/Ubuntu).
        st.running = ["nfs-server", "nfs-kernel-server"].iter().any(|u| {
            Command::new("systemctl")
                .args(["is-active", "--quiet", u])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        });
        if let Ok(out) = Command::new("exportfs").arg("-v").output() {
            if out.status.success() {
                st.exports = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count() as u32;
            }
        }
    }
    st
}
