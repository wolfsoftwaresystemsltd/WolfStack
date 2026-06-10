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

use super::{AuthConfig, Gateway, Protocol};

const EXPORTS_DIR: &str = "/etc/exports.d";

#[derive(Debug)]
#[allow(dead_code)]
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

/// Deterministic per-gateway filesystem id for the export. exports(5)
/// accepts `fsid=<uuid>`; without SOME fsid, filesystems that lack a usable
/// UUID (tmpfs, overlayfs, some btrfs/ZFS layouts) refuse to export at all
/// ("requires fsid", wabil 2026-06-10 round 2). UUIDv5 of the gateway id is
/// stable across restarts/re-renders (a changing fsid would invalidate
/// client mounts) and unique per gateway — unlike the old hardcoded
/// `fsid=0`, which declared every gateway to be THE NFSv4 pseudo-root.
fn gateway_fsid(gateway_id: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, gateway_id.as_bytes()).to_string()
}

fn render(g: &Gateway, share_path: &Path) -> String {
    let writable = matches!(g.auth, AuthConfig::Anonymous { writable: true })
        && !g.options.readonly;
    let rw = if writable { "rw" } else { "ro" };
    // exports(5) options ONLY — `vers=N` is a CLIENT mount / nfsd-server
    // setting, not an exports keyword; exportfs refused the whole file with
    // `unknown keyword "vers=4"` (wabil, 2026-06-10). Version selection is
    // server-wide ([nfsd] in /etc/nfs.conf); Linux nfsd serves v3+v4 by
    // default, so clients of either version work without us pinning anything.
    let mut opts: Vec<String> = vec![
        rw.to_string(),
        "sync".to_string(),
        "no_subtree_check".to_string(),
        "all_squash".to_string(),
        "anonuid=65534".to_string(),
        "anongid=65534".to_string(),
    ];
    // Operator escape hatch — appended verbatim (validated at save time by
    // gateway::validate; charset-restricted so it can't break the
    // `path host(opts)` line shape or inject a second export line).
    let extra = g.options.nfs_extra_options.trim();
    // Our deterministic fsid, unless the operator pinned their own.
    if !extra.split(',').any(|o| o.trim_start().starts_with("fsid=")) {
        opts.push(format!("fsid={}", gateway_fsid(&g.id)));
    }
    if !extra.is_empty() {
        opts.push(extra.to_string());
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{GatewayMode, GatewayOptions, ModePolicy, sources::Source};

    fn nfs_gateway(writable: bool) -> Gateway {
        Gateway {
            id: "g1".into(),
            name: "media".into(),
            cluster: String::new(),
            mode: GatewayMode::Single,
            protocols: vec![Protocol::Nfs],
            sources: vec![Source::Local { node_id: "node-a".into(), path: "/srv/media".into() }],
            origin_node_id: "node-a".into(),
            serve_nodes: vec![],
            auth: AuthConfig::Anonymous { writable },
            policy: ModePolicy::Single,
            options: GatewayOptions::default(),
            created_at: String::new(),
            updated_at: String::new(),
            disabled: false,
        }
    }

    #[test]
    fn render_emits_only_valid_exports_options() {
        // `vers=` once made exportfs reject the whole file with `unknown
        // keyword "vers=4"` (wabil, 2026-06-10) — it must never come back.
        let g = nfs_gateway(true);
        let out = render(&g, Path::new("/srv/media"));
        assert!(!out.contains("vers="), "vers= is not an exports(5) option: {}", out);
        assert!(out.contains("/srv/media *("), "world export when no allowlist: {}", out);
        // Deterministic per-gateway fsid (round 2: some filesystems refuse
        // to export without one) — present, stable, and never the v4
        // pseudo-root fsid=0 that conflicted across gateways.
        let fsid = gateway_fsid(&g.id);
        assert!(out.contains(&format!("anongid=65534,fsid={})", fsid)),
            "expected fsid after the fixed option set: {}", out);
        assert!(!out.contains("fsid=0,") && !out.contains("fsid=0)"),
            "fsid must never be the pseudo-root 0: {}", out);
        assert!(out.contains("rw,sync,no_subtree_check,all_squash,anonuid=65534,anongid=65534"),
            "expected exact anonymous-rw option set: {}", out);
    }

    #[test]
    fn gateway_fsid_is_stable_and_unique() {
        // Stable across calls (a changing fsid invalidates client mounts)…
        assert_eq!(gateway_fsid("g1"), gateway_fsid("g1"));
        // …and unique per gateway (the whole point vs the old fsid=0).
        assert_ne!(gateway_fsid("g1"), gateway_fsid("g2"));
        // Parseable UUID shape for exports(5) fsid=uuid.
        assert!(uuid::Uuid::parse_str(&gateway_fsid("g1")).is_ok());
    }

    #[test]
    fn render_extra_options_and_fsid_override() {
        // Extra options are appended after the fixed set + auto fsid.
        let mut g = nfs_gateway(true);
        g.options.nfs_extra_options = "no_root_squash".into();
        let out = render(&g, Path::new("/srv/media"));
        assert!(out.contains(",no_root_squash)"), "extra options appended: {}", out);
        assert!(out.contains("fsid="), "auto fsid still present: {}", out);

        // An operator-pinned fsid= suppresses the auto-generated one —
        // two fsid keys in one option list would be ambiguous.
        g.options.nfs_extra_options = "fsid=7,no_root_squash".into();
        let out = render(&g, Path::new("/srv/media"));
        assert!(out.contains(",fsid=7,no_root_squash)"), "pinned fsid kept: {}", out);
        assert_eq!(out.matches("fsid=").count(), 1, "exactly one fsid: {}", out);
    }

    #[test]
    fn render_readonly_and_allowlist() {
        let mut g = nfs_gateway(false);
        g.options.allow_hosts = vec!["10.0.0.0/24".into(), "192.168.1.5".into()];
        let out = render(&g, Path::new("/srv/media"));
        // Read-only auth → ro, one line per allowed range, no world export.
        assert!(out.contains("/srv/media 10.0.0.0/24(ro,"), "{}", out);
        assert!(out.contains("/srv/media 192.168.1.5(ro,"), "{}", out);
        assert!(!out.contains("*("), "allowlist must suppress the world export: {}", out);
    }
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
