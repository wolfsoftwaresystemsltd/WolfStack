// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Gateway sources — every storage thing a gateway can sit in front of.
//!
//! Each source resolves to a directory path on the host where the
//! Samba/NFS daemon will see the data. The orchestrator owns mount
//! lifecycle; this module owns "given a Source, produce a path I can
//! re-export and tell me when it's healthy".

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Storage source — variants align 1:1 with the spec's source matrix.
/// Variants tagged "v1.1+" or later are modeled now so config files
/// don't need migration when their orchestrator path lands; their
/// `mount_path` returns an UnsupportedSource error today.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Source {
    /// A directory on a specific node's filesystem.
    Local {
        node_id: String,
        path: String,
    },
    /// A WolfDisk volume mounted via the WolfDisk service.
    WolfDisk {
        volume_id: String,
        #[serde(default)]
        subpath: Option<String>,
    },
    /// CephFS pool from a Ceph cluster WolfStack already manages.
    CephFs {
        cluster_id: String,
        fs_name: String,
        #[serde(default)]
        subpath: Option<String>,
    },
    /// Re-export an existing SMB share (any CIFS-speaking server).
    Smb {
        server: String,
        share: String,
        #[serde(default)]
        subpath: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        domain: Option<String>,
        #[serde(default)]
        options: Option<String>,
    },
    /// Re-export an existing NFS export.
    Nfs {
        server: String,
        export: String,
        #[serde(default)]
        subpath: Option<String>,
        #[serde(default)]
        options: Option<String>,
    },
    // ─── v1.1+ stubs ───
    Sshfs {
        user: String,
        host: String,
        path: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        key_id: Option<String>,
    },
    S3Rclone {
        remote_id: String,
        bucket: String,
        #[serde(default)]
        prefix: Option<String>,
    },
    ContainerVol {
        node_id: String,
        runtime: String,
        container: String,
        volume: String,
    },
    LxcDir {
        node_id: String,
        container: String,
        path: String,
    },
    Rbd {
        cluster_id: String,
        pool: String,
        image: String,
        #[serde(default = "default_rbd_fs")]
        fs: String,
    },
    VmExport {
        vm_id: String,
        sub_protocol: VmExportProto,
        share_or_export: String,
    },
    PeerGateway {
        peer_cluster_url: String,
        gateway_id: String,
        creds_id: String,
    },
}

fn default_rbd_fs() -> String { "ext4".into() }

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum VmExportProto { Smb, Nfs, Iscsi }

/// Mount lifecycle errors. The variants matter because the API
/// surfaces them (`error_type`) so the UI can suggest a fix —
/// "missing samba package", "bad credentials", "host unreachable".
#[derive(Debug)]
pub enum SourceError {
    Unsupported(&'static str),
    MissingTool { tool: String, install_command: String, install_package: String },
    MountFailed(String),
    PathInvalid(String),
    Timeout,
    Io(std::io::Error),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Unsupported(why) => write!(f, "unsupported source: {}", why),
            SourceError::MissingTool { tool, install_package, .. } => {
                write!(f, "missing tool '{}' (install package '{}')", tool, install_package)
            }
            SourceError::MountFailed(s) => write!(f, "mount failed: {}", s),
            SourceError::PathInvalid(s) => write!(f, "invalid path: {}", s),
            SourceError::Timeout => write!(f, "operation timed out"),
            SourceError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl From<std::io::Error> for SourceError {
    fn from(e: std::io::Error) -> Self { SourceError::Io(e) }
}

/// Validate a Source. Returns the first concrete problem; the gateway
/// validator wraps these in per-index error messages.
pub fn validate(s: &Source) -> Result<(), String> {
    match s {
        Source::Local { node_id, path } => {
            if node_id.trim().is_empty() {
                return Err("local source requires node_id".into());
            }
            if path.trim().is_empty() || !path.starts_with('/') {
                return Err("local source path must be absolute (begin with '/')".into());
            }
            // Block re-sharing /etc, /proc, /sys etc. Operators can
            // override later if they really want; v1.0 keeps the
            // accident floor high.
            for forbidden in &["/etc", "/proc", "/sys", "/dev", "/boot"] {
                if path == forbidden || path.starts_with(&format!("{}/", forbidden)) {
                    return Err(format!("local source path under '{}' is not allowed for safety", forbidden));
                }
            }
        }
        Source::WolfDisk { volume_id, .. } => {
            if volume_id.trim().is_empty() {
                return Err("wolfdisk source requires volume_id".into());
            }
        }
        Source::CephFs { cluster_id, fs_name, .. } => {
            if cluster_id.trim().is_empty() || fs_name.trim().is_empty() {
                return Err("cephfs source requires cluster_id and fs_name".into());
            }
        }
        Source::Smb { server, share, .. } => {
            if server.trim().is_empty() || share.trim().is_empty() {
                return Err("smb source requires server and share".into());
            }
        }
        Source::Nfs { server, export, .. } => {
            if server.trim().is_empty() || export.trim().is_empty() {
                return Err("nfs source requires server and export".into());
            }
        }
        // v1.1+ stubs — config-valid but mount returns Unsupported
        Source::Sshfs { .. } | Source::S3Rclone { .. } | Source::ContainerVol { .. }
        | Source::LxcDir { .. } | Source::Rbd { .. } | Source::VmExport { .. }
        | Source::PeerGateway { .. } => {
            return Err("this source type is reserved for a future release".into());
        }
    }
    Ok(())
}

// ─── Mount lifecycle ───

/// Per-gateway mount root. Each source mounted/bound under
/// `<root>/<gateway_id>/source-<idx>/`. The orchestrator's `share/`
/// directory is then either a symlink/bind to that, or — once
/// aggregate/sharded land — a mergerfs/dir-tree composed from these.
fn gateway_mount_root() -> PathBuf {
    PathBuf::from("/var/lib/wolfstack/gateways")
}

pub fn source_mount_path(gateway_id: &str, idx: usize) -> PathBuf {
    gateway_mount_root().join(gateway_id).join(format!("source-{}", idx))
}

pub fn share_path(gateway_id: &str) -> PathBuf {
    gateway_mount_root().join(gateway_id).join("share")
}

/// Mount a source, returning the path that ends up holding its data
/// (already including any `subpath` selector). Idempotent — calling
/// twice on a source that's already mounted is a no-op (logged).
pub fn mount(gateway_id: &str, idx: usize, source: &Source) -> Result<PathBuf, SourceError> {
    let mount_dir = source_mount_path(gateway_id, idx);
    std::fs::create_dir_all(&mount_dir)?;
    match source {
        Source::Local { path, .. } => {
            // Local: bind-mount so the target stays a stable path
            // regardless of what the source happens to be on this
            // host. Bind also lets us keep the same daemon config
            // shape across all source types.
            if !is_mounted(&mount_dir) {
                run_mount(&["mount", "--bind", path, &mount_dir.to_string_lossy()])?;
            }
            Ok(mount_dir)
        }
        Source::WolfDisk { volume_id, subpath } => {
            // WolfDisk's own service mounts volumes at a known root.
            // We bind a sub-mount from there so unmounting our gateway
            // doesn't disturb the underlying volume mount.
            let wolfdisk_root = wolfdisk_volume_path(volume_id)?;
            let target = match subpath {
                Some(sp) => wolfdisk_root.join(sp.trim_start_matches('/')),
                None => wolfdisk_root,
            };
            if !target.exists() {
                return Err(SourceError::PathInvalid(format!(
                    "wolfdisk volume '{}' subpath '{}' does not exist",
                    volume_id,
                    subpath.as_deref().unwrap_or("/")
                )));
            }
            if !is_mounted(&mount_dir) {
                run_mount(&["mount", "--bind", &target.to_string_lossy(), &mount_dir.to_string_lossy()])?;
            }
            Ok(mount_dir)
        }
        Source::CephFs { fs_name, subpath, .. } => {
            // CephFS via ceph-fuse or kernel cephfs. Prefer kernel —
            // the ceph integration module already prepares
            // /etc/ceph/ceph.conf + a keyring, which kernel mount.ceph
            // picks up.
            require_tool("mount.ceph", "ceph-common")?;
            let mon_addrs = ceph_mon_addrs()?;
            let opts = format!("name=admin,mds_namespace={}", fs_name);
            let src = match subpath {
                Some(sp) if !sp.is_empty() => format!(":{}", sp.trim_start_matches('/')),
                _ => ":/".into(),
            };
            let src_full = format!("{}{}", mon_addrs, src);
            if !is_mounted(&mount_dir) {
                run_mount(&[
                    "mount", "-t", "ceph", &src_full, &mount_dir.to_string_lossy(),
                    "-o", &opts,
                ])?;
            }
            Ok(mount_dir)
        }
        Source::Smb { server, share, subpath, username, password, domain, options } => {
            require_tool("mount.cifs", "cifs-utils")?;
            // Build options string. Credentials NEVER go on the
            // command line (visible to /proc/*/cmdline) — write a
            // creds file with mode 0600 and reference it.
            let creds_path = creds_file_for(gateway_id, idx);
            write_smb_creds(&creds_path, username.as_deref(), password.as_deref(), domain.as_deref())?;
            let mut opts = format!("credentials={},vers=3.0,iocharset=utf8,nofail", creds_path.display());
            if username.is_none() && password.is_none() {
                opts = "guest,vers=3.0,iocharset=utf8,nofail".into();
            }
            if let Some(extra) = options.as_ref().filter(|s| !s.is_empty()) {
                opts.push(',');
                opts.push_str(extra);
            }
            let src = format!("//{}/{}", server.trim_start_matches("//").trim_start_matches('\\'), share);
            if !is_mounted(&mount_dir) {
                run_mount(&[
                    "mount", "-t", "cifs", &src, &mount_dir.to_string_lossy(),
                    "-o", &opts,
                ])?;
            }
            // If a subpath is requested we re-bind to a sibling that
            // points only at that subtree — cleanest way to honour
            // subpath without re-mounting CIFS for every change.
            if let Some(sp) = subpath.as_deref().filter(|s| !s.is_empty()) {
                let target = mount_dir.join(sp.trim_start_matches('/'));
                if !target.exists() {
                    return Err(SourceError::PathInvalid(format!(
                        "smb subpath '{}' does not exist on the share",
                        sp
                    )));
                }
                Ok(target)
            } else {
                Ok(mount_dir)
            }
        }
        Source::Nfs { server, export, subpath, options } => {
            require_tool("mount.nfs", "nfs-common")?;
            let mut opts = String::from("vers=4,nofail,soft,timeo=100");
            if let Some(extra) = options.as_ref().filter(|s| !s.is_empty()) {
                opts.push(',');
                opts.push_str(extra);
            }
            let src = format!("{}:{}", server, export);
            if !is_mounted(&mount_dir) {
                run_mount(&[
                    "mount", "-t", "nfs", &src, &mount_dir.to_string_lossy(),
                    "-o", &opts,
                ])?;
            }
            if let Some(sp) = subpath.as_deref().filter(|s| !s.is_empty()) {
                Ok(mount_dir.join(sp.trim_start_matches('/')))
            } else {
                Ok(mount_dir)
            }
        }
        // v1.1+ stubs
        _ => Err(SourceError::Unsupported(
            "this source type is not yet implemented (reserved for a future release)",
        )),
    }
}

/// Reverse of `mount`. Idempotent — unmount of a non-mount is silent.
pub fn unmount(gateway_id: &str, idx: usize, _source: &Source) -> Result<(), SourceError> {
    let mount_dir = source_mount_path(gateway_id, idx);
    if is_mounted(&mount_dir) {
        let _ = Command::new("umount").arg("-l").arg(&mount_dir).status();
    }
    // Clean up creds file if any
    let creds = creds_file_for(gateway_id, idx);
    if creds.exists() {
        let _ = std::fs::remove_file(&creds);
    }
    Ok(())
}

/// Cheap health check — does the mount root still respond to stat?
pub fn health_check(gateway_id: &str, idx: usize) -> bool {
    let p = source_mount_path(gateway_id, idx);
    std::fs::metadata(&p).is_ok()
}

// ─── Helpers ───

fn is_mounted(p: &Path) -> bool {
    // /proc/mounts is the source of truth — `mountpoint` may not be
    // installed everywhere.
    let target = match p.canonicalize() { Ok(c) => c, Err(_) => p.to_path_buf() };
    let target_s = target.to_string_lossy().to_string();
    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let _src = it.next();
            if let Some(mnt) = it.next() {
                // /proc/mounts encodes spaces as \040 etc — we don't
                // bother decoding because gateway paths never contain
                // spaces (we control them).
                if mnt == target_s {
                    return true;
                }
            }
        }
    }
    false
}

fn run_mount(args: &[&str]) -> Result<(), SourceError> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| {
            // ENOENT on the binary itself → tell the operator which
            // package they need.
            if e.kind() == std::io::ErrorKind::NotFound {
                SourceError::MissingTool {
                    tool: args[0].to_string(),
                    install_command: format!("apt-get install -y {}", default_pkg_for(args[0])),
                    install_package: default_pkg_for(args[0]).to_string(),
                }
            } else {
                SourceError::Io(e)
            }
        })?;
    if !out.status.success() {
        return Err(SourceError::MountFailed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

fn require_tool(bin: &str, pkg: &str) -> Result<(), SourceError> {
    if which(bin).is_none() {
        return Err(SourceError::MissingTool {
            tool: bin.to_string(),
            install_command: format!("apt-get install -y {}", pkg),
            install_package: pkg.to_string(),
        });
    }
    Ok(())
}

/// Public alias for cross-module use (samba.rs / nfs.rs).
pub fn which_helper(bin: &str) -> Option<PathBuf> { which(bin) }

fn which(bin: &str) -> Option<PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = PathBuf::from(dir).join(bin);
        if candidate.exists() { return Some(candidate); }
    }
    // Common explicit paths since `mount.*` helpers often live here
    for fixed in ["/sbin", "/usr/sbin", "/usr/local/sbin"] {
        let candidate = PathBuf::from(fixed).join(bin);
        if candidate.exists() { return Some(candidate); }
    }
    None
}

fn default_pkg_for(bin: &str) -> &'static str {
    match bin {
        "mount.cifs" => "cifs-utils",
        "mount.nfs" | "mount.nfs4" => "nfs-common",
        "mount.ceph" => "ceph-common",
        "smbd" | "smbcontrol" | "smbpasswd" | "pdbedit" => "samba",
        "exportfs" => "nfs-kernel-server",
        _ => "util-linux",
    }
}

fn creds_file_for(gateway_id: &str, idx: usize) -> PathBuf {
    PathBuf::from("/var/lib/wolfstack/gateways")
        .join(gateway_id)
        .join(format!(".source-{}.creds", idx))
}

fn write_smb_creds(
    path: &Path,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<(), SourceError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut content = String::new();
    if let Some(u) = username { content.push_str(&format!("username={}\n", u)); }
    if let Some(p) = password { content.push_str(&format!("password={}\n", p)); }
    if let Some(d) = domain   { content.push_str(&format!("domain={}\n", d)); }
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Resolve a WolfDisk volume to its host mount point. Best-effort —
/// follows the convention used by the WolfDisk service to mount
/// volumes under `/mnt/wolfdisk/<volume_id>`. Override path lives in
/// `/etc/wolfdisk/volumes.json` if present.
fn wolfdisk_volume_path(volume_id: &str) -> Result<PathBuf, SourceError> {
    let default = PathBuf::from(format!("/mnt/wolfdisk/{}", volume_id));
    if default.exists() { return Ok(default); }
    // Fallback: a published-by-WolfDisk volume manifest, if it exists.
    if let Ok(content) = std::fs::read_to_string("/etc/wolfdisk/volumes.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(arr) = v.as_array() {
                for entry in arr {
                    if entry.get("id").and_then(|x| x.as_str()) == Some(volume_id) {
                        if let Some(p) = entry.get("mount_path").and_then(|x| x.as_str()) {
                            return Ok(PathBuf::from(p));
                        }
                    }
                }
            }
        }
    }
    Err(SourceError::PathInvalid(format!(
        "wolfdisk volume '{}' is not currently mounted (expected /mnt/wolfdisk/{} or volumes.json entry)",
        volume_id, volume_id
    )))
}

fn ceph_mon_addrs() -> Result<String, SourceError> {
    // `ceph mon dump --format=json` is the proper way; fall back to
    // ceph.conf parsing if `ceph` isn't installed (rare on a host
    // that has mount.ceph).
    if which("ceph").is_some() {
        if let Ok(out) = Command::new("ceph").args(["mon", "dump", "--format=json"]).output() {
            if out.status.success() {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                    if let Some(mons) = v.get("mons").and_then(|x| x.as_array()) {
                        let addrs: Vec<String> = mons.iter()
                            .filter_map(|m| m.get("public_addr").and_then(|x| x.as_str()))
                            .map(|a| a.split('/').next().unwrap_or(a).to_string())
                            .collect();
                        if !addrs.is_empty() {
                            return Ok(addrs.join(","));
                        }
                    }
                }
            }
        }
    }
    if let Ok(content) = std::fs::read_to_string("/etc/ceph/ceph.conf") {
        for line in content.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("mon_host") {
                if let Some(eq) = rest.find('=') {
                    let val = rest[eq + 1..].trim();
                    if !val.is_empty() {
                        return Ok(val.to_string());
                    }
                }
            }
        }
    }
    Err(SourceError::Unsupported(
        "no Ceph monitor address available — install ceph-common or set up /etc/ceph/ceph.conf",
    ))
}

/// Surfaces the source list to the wizard. Each source describes
/// itself for the "discover sources" picker.
pub fn describe(s: &Source) -> serde_json::Value {
    use Source::*;
    match s {
        Local { node_id, path } => serde_json::json!({
            "type": "local", "node_id": node_id, "path": path,
            "label": format!("Local: {} on {}", path, node_id),
        }),
        WolfDisk { volume_id, subpath } => serde_json::json!({
            "type": "wolfdisk", "volume_id": volume_id, "subpath": subpath,
            "label": format!("WolfDisk: {}{}", volume_id, subpath.as_deref().map(|s| format!(":{}", s)).unwrap_or_default()),
        }),
        CephFs { cluster_id, fs_name, subpath } => serde_json::json!({
            "type": "cephfs", "cluster_id": cluster_id, "fs_name": fs_name, "subpath": subpath,
            "label": format!("CephFS: {}/{}{}", cluster_id, fs_name, subpath.as_deref().map(|s| format!(":{}", s)).unwrap_or_default()),
        }),
        Smb { server, share, subpath, .. } => serde_json::json!({
            "type": "smb", "server": server, "share": share, "subpath": subpath,
            "label": format!("SMB: //{}/{}", server, share),
        }),
        Nfs { server, export, subpath, .. } => serde_json::json!({
            "type": "nfs", "server": server, "export": export, "subpath": subpath,
            "label": format!("NFS: {}:{}", server, export),
        }),
        _ => serde_json::json!({
            "type": "unsupported",
            "label": "Unsupported (reserved for a future release)",
        }),
    }
}
