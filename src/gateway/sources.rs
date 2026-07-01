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
/// `install_command` and `install_package` are read by the JSON
/// serialiser when this enum is surfaced over the API; the compiler
/// can't see that, hence the dead-code allow.
#[derive(Debug)]
#[allow(dead_code)]
pub enum SourceError {
    Unsupported(&'static str),
    MissingTool { tool: String, install_command: String, install_package: String },
    MountFailed(String),
    PathInvalid(String),
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
            SourceError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl From<std::io::Error> for SourceError {
    fn from(e: std::io::Error) -> Self { SourceError::Io(e) }
}

/// Reject any subpath that contains `..` segments or absolute-path
/// shenanigans. Centralised so every source validator gets the same
/// rule. The orchestrator also re-checks at mount time as
/// defence-in-depth — this validate-time check just makes the error
/// happen at the right place (config save, not mount).
fn reject_path_traversal(label: &str, subpath: Option<&String>) -> Result<(), String> {
    let Some(sp) = subpath.filter(|s| !s.is_empty()) else { return Ok(()); };
    if sp.contains('\0') {
        return Err(format!("{} subpath contains a null byte", label));
    }
    for component in std::path::Path::new(sp.as_str()).components() {
        use std::path::Component;
        match component {
            Component::ParentDir => return Err(format!(
                "{} subpath must not contain '..' segments", label
            )),
            Component::RootDir | Component::Prefix(_) => {
                // Root prefixes are stripped at mount time but rejecting
                // them here makes the operator's intent explicit.
                return Err(format!(
                    "{} subpath must be relative (no leading '/' or drive prefix)", label
                ));
            }
            _ => {}
        }
    }
    Ok(())
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
        Source::WolfDisk { volume_id, subpath } => {
            if volume_id.trim().is_empty() {
                return Err("wolfdisk source requires volume_id".into());
            }
            reject_path_traversal("wolfdisk", subpath.as_ref())?;
        }
        Source::CephFs { cluster_id, fs_name, subpath } => {
            if cluster_id.trim().is_empty() || fs_name.trim().is_empty() {
                return Err("cephfs source requires cluster_id and fs_name".into());
            }
            reject_path_traversal("cephfs", subpath.as_ref())?;
        }
        Source::Smb { server, share, subpath, .. } => {
            if server.trim().is_empty() || share.trim().is_empty() {
                return Err("smb source requires server and share".into());
            }
            reject_path_traversal("smb", subpath.as_ref())?;
        }
        Source::Nfs { server, export, subpath, .. } => {
            if server.trim().is_empty() || export.trim().is_empty() {
                return Err("nfs source requires server and export".into());
            }
            reject_path_traversal("nfs", subpath.as_ref())?;
        }
        Source::Rbd { cluster_id, pool, image, fs } => {
            // NOTE: cluster_id is stored for identification only. Like the
            // CephFs source, the mount uses the host's default ceph config +
            // keyring (/etc/ceph/ceph.conf) — it does NOT select between
            // multiple clusters. Multi-cluster selection is future work.
            if cluster_id.trim().is_empty() || pool.trim().is_empty() || image.trim().is_empty() {
                return Err("rbd source requires cluster_id, pool and image".into());
            }
            if !matches!(fs.as_str(), "ext4" | "xfs" | "btrfs") {
                return Err(format!("rbd source fs '{}' is not supported (use ext4, xfs or btrfs)", fs));
            }
        }
        Source::ContainerVol { node_id, runtime, container, volume } => {
            if node_id.trim().is_empty() || container.trim().is_empty() || volume.trim().is_empty() {
                return Err("container-volume source requires node_id, container and volume".into());
            }
            if runtime != "docker" {
                return Err(format!(
                    "container-volume source runtime '{}' is not supported (only 'docker' has named volumes)",
                    runtime));
            }
        }
        Source::LxcDir { node_id, container, path } => {
            if node_id.trim().is_empty() || container.trim().is_empty() {
                return Err("lxc-dir source requires node_id and container".into());
            }
            if path.trim().is_empty() || !path.starts_with('/') {
                return Err("lxc-dir source path must be absolute (a path inside the container)".into());
            }
            if path.contains('\0') {
                return Err("lxc-dir source path contains a null byte".into());
            }
            if path.split('/').any(|seg| seg == "..") {
                return Err("lxc-dir source path must not contain '..' segments".into());
            }
        }
        Source::VmExport { vm_id, sub_protocol, share_or_export } => {
            // NOTE: VmExport re-mounts the guest's share as GUEST (the struct
            // carries no credentials), so only anonymously-readable VM shares
            // can be re-exported. Authenticated guest shares are future work.
            if vm_id.trim().is_empty() || share_or_export.trim().is_empty() {
                return Err("vm-export source requires vm_id and share_or_export".into());
            }
            if matches!(sub_protocol, VmExportProto::Iscsi) {
                return Err("vm-export over iSCSI is reserved for a future release".into());
            }
        }
        // Reserved — these reference credential/key stores (key_id, remote_id,
        // creds_id) and a FUSE-daemon lifecycle that WolfStack doesn't have yet.
        // Rejected at config-save so operators get a clear message, not a
        // cryptic mount failure.
        Source::Sshfs { .. } | Source::S3Rclone { .. } | Source::PeerGateway { .. } => {
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
            let target = match subpath.as_deref() {
                Some(sp) if !sp.is_empty() => safe_join(&wolfdisk_root, sp)?,
                _ => wolfdisk_root,
            };
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
            cifs_mount(gateway_id, idx, &mount_dir, server, share,
                username.as_deref(), password.as_deref(), domain.as_deref(), options.as_deref())?;
            // If a subpath is requested we re-bind to a sibling that
            // points only at that subtree — cleanest way to honour
            // subpath without re-mounting CIFS for every change.
            if let Some(sp) = subpath.as_deref().filter(|s| !s.is_empty()) {
                safe_join(&mount_dir, sp)
            } else {
                Ok(mount_dir)
            }
        }
        Source::Nfs { server, export, subpath, options } => {
            nfs_mount(&mount_dir, server, export, options.as_deref())?;
            if let Some(sp) = subpath.as_deref().filter(|s| !s.is_empty()) {
                safe_join(&mount_dir, sp)
            } else {
                Ok(mount_dir)
            }
        }
        Source::Rbd { pool, image, fs, .. } => {
            // Map the RBD image to a local block device (host's default ceph
            // config + keyring, like the CephFs source), then mount its fs.
            // WARNING for aggregate/failover modes later: an RBD image is NOT a
            // cluster fs — it must only ever be mapped+mounted on ONE node at a
            // time, which the single-origin gateway model guarantees.
            require_tool("rbd", "ceph-common")?;
            let spec = format!("{}/{}", pool, image);
            let dev = rbd_ensure_mapped(&spec)?;
            if !is_mounted(&mount_dir) {
                run_mount(&["mount", "-t", fs, &dev, &mount_dir.to_string_lossy()])?;
            }
            Ok(mount_dir)
        }
        Source::ContainerVol { runtime, container, volume, .. } => {
            // The gateway runs on the source's node (origin_node_id), so the
            // Docker volume is local — resolve its host path and bind it.
            if runtime != "docker" {
                return Err(SourceError::Unsupported(
                    "container-volume source is only supported for the docker runtime"));
            }
            let src = docker_volume_source(container, volume)?;
            if !is_mounted(&mount_dir) {
                run_mount(&["mount", "--bind", &src, &mount_dir.to_string_lossy()])?;
            }
            Ok(mount_dir)
        }
        Source::LxcDir { container, path, .. } => {
            // Bind a directory inside a running LXC / pct container's rootfs.
            // For native LXC and running Proxmox containers the rootfs is at
            // <base>/<container>/rootfs; safe_join blocks traversal (incl.
            // symlinks in the guest that point outside its own rootfs).
            let base = crate::containers::lxc_base_dir(container);
            let rootfs = PathBuf::from(&base).join(container).join("rootfs");
            if !rootfs.exists() {
                return Err(SourceError::PathInvalid(format!(
                    "container '{}' rootfs not found at {} — the container must be running",
                    container, rootfs.display())));
            }
            let target = safe_join(&rootfs, path)?;
            if !is_mounted(&mount_dir) {
                run_mount(&["mount", "--bind", &target.to_string_lossy(), &mount_dir.to_string_lossy()])?;
            }
            Ok(mount_dir)
        }
        Source::VmExport { vm_id, sub_protocol, share_or_export } => {
            // Re-export a share a VM guest serves. The guest's IP must be
            // reachable from this host — we use its WolfNet address.
            let ip = vm_export_address(vm_id)?;
            match sub_protocol {
                VmExportProto::Smb => {
                    cifs_mount(gateway_id, idx, &mount_dir, &ip, share_or_export,
                        None, None, None, None)?;
                    Ok(mount_dir)
                }
                VmExportProto::Nfs => {
                    nfs_mount(&mount_dir, &ip, share_or_export, None)?;
                    Ok(mount_dir)
                }
                VmExportProto::Iscsi => Err(SourceError::Unsupported(
                    "iSCSI VM export is reserved for a future release")),
            }
        }
        // Reserved — need credential/key stores + FUSE-daemon lifecycle.
        Source::Sshfs { .. } | Source::S3Rclone { .. } | Source::PeerGateway { .. } => {
            Err(SourceError::Unsupported(
                "this source type is reserved for a future release"))
        }
    }
}

/// Reverse of `mount`. Idempotent — unmount of a non-mount is silent.
pub fn unmount(gateway_id: &str, idx: usize, source: &Source) -> Result<(), SourceError> {
    let mount_dir = source_mount_path(gateway_id, idx);
    if is_mounted(&mount_dir) {
        let _ = Command::new("umount").arg("-l").arg(&mount_dir).status();
    }
    // RBD images must be unmapped AFTER the fs is unmounted, or the block
    // device stays mapped to this host forever. Best-effort — `rbd unmap`
    // fails harmlessly if it was never mapped.
    if let Source::Rbd { pool, image, .. } = source {
        let _ = Command::new("rbd")
            .args(["unmap", &format!("{}/{}", pool, image)])
            .status();
    }
    // Clean up creds file if any
    let creds = creds_file_for(gateway_id, idx);
    if creds.exists() {
        let _ = std::fs::remove_file(&creds);
    }
    Ok(())
}

/// Cheap health check — does the mount root still respond to stat?
#[allow(dead_code)]
pub fn health_check(gateway_id: &str, idx: usize) -> bool {
    let p = source_mount_path(gateway_id, idx);
    std::fs::metadata(&p).is_ok()
}

/// Safely join `subpath` to `base`, refusing any result that escapes
/// `base` after canonicalisation. Defence-in-depth — `validate()`
/// already rejects `..` segments at config-save time, but this catches
/// symlink tricks (a user-controlled subpath that happens to traverse
/// a symlink in the source pointing outside the mount root). Returns
/// `PathInvalid` on any escape.
pub fn safe_join(base: &Path, subpath: &str) -> Result<PathBuf, SourceError> {
    let trimmed = subpath.trim_start_matches('/');
    if trimmed.is_empty() {
        return Ok(base.to_path_buf());
    }
    // Reject ".." early — even though validate() blocked it, an older
    // config file might have slipped through.
    for component in std::path::Path::new(trimmed).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(SourceError::PathInvalid(format!(
                "subpath '{}' contains a '..' segment", subpath
            )));
        }
    }
    let candidate = base.join(trimmed);
    // Canonicalise both sides so symlink traversal can't escape.
    let base_real = base.canonicalize()
        .map_err(|e| SourceError::PathInvalid(format!("base '{}' canonicalise failed: {}", base.display(), e)))?;
    let cand_real = candidate.canonicalize()
        .map_err(|e| SourceError::PathInvalid(format!("subpath '{}' does not resolve under '{}': {}", subpath, base.display(), e)))?;
    if !cand_real.starts_with(&base_real) {
        return Err(SourceError::PathInvalid(format!(
            "subpath '{}' escapes the source mount root", subpath
        )));
    }
    Ok(cand_real)
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

/// Mount a CIFS/SMB share at `mount_dir`. Shared by the `Smb` source and the
/// SMB `VmExport` sub-protocol. Credentials NEVER go on the command line
/// (visible in /proc/*/cmdline) — they're written to a 0600 creds file. When
/// no username/password is given the mount is a guest mount.
#[allow(clippy::too_many_arguments)]
fn cifs_mount(
    gateway_id: &str, idx: usize, mount_dir: &Path,
    server: &str, share: &str,
    username: Option<&str>, password: Option<&str>, domain: Option<&str>, options: Option<&str>,
) -> Result<(), SourceError> {
    require_tool("mount.cifs", "cifs-utils")?;
    // Guest mount when no credentials are supplied (e.g. VM re-export); only
    // then write a 0600 creds file — credentials NEVER go on the command line
    // (they'd be visible in /proc/*/cmdline) — and reference it.
    let mut opts = if username.is_some() || password.is_some() {
        let creds_path = creds_file_for(gateway_id, idx);
        write_smb_creds(&creds_path, username, password, domain)?;
        format!("credentials={},vers=3.0,iocharset=utf8,nofail", creds_path.display())
    } else {
        "guest,vers=3.0,iocharset=utf8,nofail".into()
    };
    if let Some(extra) = options.filter(|s| !s.is_empty()) {
        opts.push(',');
        opts.push_str(extra);
    }
    let src = format!("//{}/{}", server.trim_start_matches("//").trim_start_matches('\\'), share);
    if !is_mounted(mount_dir) {
        run_mount(&["mount", "-t", "cifs", &src, &mount_dir.to_string_lossy(), "-o", &opts])?;
    }
    Ok(())
}

/// Mount an NFS export at `mount_dir`. Shared by the `Nfs` source and the NFS
/// `VmExport` sub-protocol.
fn nfs_mount(mount_dir: &Path, server: &str, export: &str, options: Option<&str>) -> Result<(), SourceError> {
    require_tool("mount.nfs", "nfs-common")?;
    let mut opts = String::from("vers=4,nofail,soft,timeo=100");
    if let Some(extra) = options.filter(|s| !s.is_empty()) {
        opts.push(',');
        opts.push_str(extra);
    }
    let src = format!("{}:{}", server, export);
    if !is_mounted(mount_dir) {
        run_mount(&["mount", "-t", "nfs", &src, &mount_dir.to_string_lossy(), "-o", &opts])?;
    }
    Ok(())
}

/// Ensure an RBD image (`pool/image`) is mapped to a local block device and
/// return that device path. Idempotent — reuses an existing mapping rather than
/// mapping twice. Uses the host's default ceph config + keyring (same as the
/// CephFs source).
fn rbd_ensure_mapped(spec: &str) -> Result<String, SourceError> {
    if let Some(dev) = rbd_mapped_device(spec)? {
        return Ok(dev);
    }
    let out = Command::new("rbd").args(["map", spec]).output()
        .map_err(rbd_spawn_error)?;
    if !out.status.success() {
        return Err(SourceError::MountFailed(format!(
            "rbd map {} failed: {}", spec, String::from_utf8_lossy(&out.stderr).trim())));
    }
    // `rbd map` prints the /dev/rbdN device on stdout; older versions print
    // nothing (and a stray warning line could appear), so only trust stdout
    // when it's an actual device path — otherwise resolve via showmapped
    // rather than handing a non-path to `mount`.
    let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dev.starts_with("/dev/") {
        return Ok(dev);
    }
    rbd_mapped_device(spec)?
        .ok_or_else(|| SourceError::MountFailed(format!("rbd map {} returned no usable device", spec)))
}

/// Look up the local block device for an already-mapped `pool/image`, if any,
/// via `rbd showmapped --format json`. The JSON is an object keyed by mapping
/// id (older rbd) or an array (newer), each entry carrying `pool`/`name`/`device`.
fn rbd_mapped_device(spec: &str) -> Result<Option<String>, SourceError> {
    // spec is always "pool/image" (validate() ensures pool is non-empty and the
    // caller builds it that way); the unwrap_or is a defensive no-op that can't
    // match a real mapping (empty pool).
    let (pool, image) = spec.split_once('/').unwrap_or(("", spec));
    let out = match Command::new("rbd").args(["showmapped", "--format", "json"]).output() {
        Ok(o) if o.status.success() => o,
        Ok(_) => return Ok(None),
        Err(e) => return Err(rbd_spawn_error(e)),
    };
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    let entries: Vec<&serde_json::Value> = match &v {
        serde_json::Value::Array(a) => a.iter().collect(),
        serde_json::Value::Object(o) => o.values().collect(),
        _ => Vec::new(),
    };
    for e in entries {
        let p = e.get("pool").and_then(|x| x.as_str()).unwrap_or("");
        let i = e.get("name").and_then(|x| x.as_str()).unwrap_or("");
        if p == pool && i == image
            && let Some(dev) = e.get("device").and_then(|x| x.as_str()).filter(|s| !s.is_empty())
        {
            return Ok(Some(dev.to_string()));
        }
    }
    Ok(None)
}

fn rbd_spawn_error(e: std::io::Error) -> SourceError {
    if e.kind() == std::io::ErrorKind::NotFound {
        SourceError::MissingTool {
            tool: "rbd".into(),
            install_command: "apt-get install -y ceph-common".into(),
            install_package: "ceph-common".into(),
        }
    } else {
        SourceError::Io(e)
    }
}

/// Resolve a Docker volume to its host path. Tries the named-volume mountpoint
/// first (`docker volume inspect`); falls back to the container's own mount
/// list, matching `volume` against a mount's destination path (covers bind /
/// anonymous mounts named by their in-container path).
fn docker_volume_source(container: &str, volume: &str) -> Result<String, SourceError> {
    let out = Command::new("docker")
        .args(["volume", "inspect", "--format", "{{.Mountpoint}}", volume])
        .output()
        .map_err(|e| if e.kind() == std::io::ErrorKind::NotFound {
            SourceError::MissingTool {
                tool: "docker".into(),
                install_command: "apt-get install -y docker-ce".into(),
                install_package: "docker-ce".into(),
            }
        } else { SourceError::Io(e) })?;
    if out.status.success() {
        let mp = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !mp.is_empty() && Path::new(&mp).exists() {
            return Ok(mp);
        }
    }
    for m in crate::containers::docker_list_volumes(container) {
        if m.container_path == volume && !m.host_path.is_empty() {
            return Ok(m.host_path);
        }
    }
    Err(SourceError::MountFailed(format!(
        "could not resolve docker volume '{}' for container '{}' \
         (not a named volume, and no matching mount in the container)", volume, container)))
}

/// Resolve a VM's reachable address for re-export. Only WolfNet-addressed VMs
/// can be re-exported — the guest's SMB/NFS server must be reachable from this
/// host, and the WolfNet IP is the address WolfStack knows and can route to.
fn vm_export_address(vm_id: &str) -> Result<String, SourceError> {
    let manager = crate::vms::manager::VmManager::new();
    manager.get_vm(vm_id)
        .and_then(|c| c.wolfnet_ip)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SourceError::MountFailed(format!(
            "VM '{}' has no WolfNet address — re-exporting a VM share requires a \
             reachable guest IP (assign the VM a WolfNet address)", vm_id)))
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
#[allow(dead_code)]
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
        Rbd { cluster_id, pool, image, fs } => serde_json::json!({
            "type": "rbd", "cluster_id": cluster_id, "pool": pool, "image": image, "fs": fs,
            "label": format!("RBD: {}/{} ({})", pool, image, fs),
        }),
        ContainerVol { node_id, runtime, container, volume } => serde_json::json!({
            "type": "container_vol", "node_id": node_id, "runtime": runtime,
            "container": container, "volume": volume,
            "label": format!("{} volume {} on {}", runtime, volume, container),
        }),
        LxcDir { node_id, container, path } => serde_json::json!({
            "type": "lxc_dir", "node_id": node_id, "container": container, "path": path,
            "label": format!("LXC {}:{}", container, path),
        }),
        VmExport { vm_id, sub_protocol, share_or_export } => serde_json::json!({
            "type": "vm_export", "vm_id": vm_id, "sub_protocol": sub_protocol,
            "share_or_export": share_or_export,
            "label": format!("VM {} export {}", vm_id, share_or_export),
        }),
        // Reserved source types — explicit (not a catch-all) so a new Source
        // variant is a compile error here, matching validate()/mount().
        Sshfs { .. } | S3Rclone { .. } | PeerGateway { .. } => serde_json::json!({
            "type": "unsupported",
            "label": "Unsupported (reserved for a future release)",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("wolfstack-gw-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn safe_join_accepts_legit_subpath() {
        let base = tmpdir();
        std::fs::create_dir_all(base.join("ok")).unwrap();
        let result = safe_join(&base, "ok").expect("legit subpath");
        assert!(result.starts_with(&base.canonicalize().unwrap()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn safe_join_rejects_double_dot_traversal() {
        let base = tmpdir();
        let r = safe_join(&base, "../etc");
        assert!(r.is_err(), "expected escape rejection");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn safe_join_rejects_symlink_escape() {
        // Symlink trick: a directory inside the base that points outside.
        // safe_join's canonicalize step must catch this.
        let base = tmpdir();
        let outside = std::env::temp_dir().join(format!("wolfstack-gw-outside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();
        let inside_link = base.join("escape");
        let _ = std::os::unix::fs::symlink(&outside, &inside_link);

        let r = safe_join(&base, "escape");
        assert!(r.is_err(), "symlink-out should be rejected, got {:?}", r);

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn safe_join_strips_leading_slash() {
        let base = tmpdir();
        std::fs::create_dir_all(base.join("ok")).unwrap();
        // "/ok" should be treated as relative "ok", not as "/ok"
        // (which would escape the base on canonicalize).
        let r = safe_join(&base, "/ok").expect("leading slash should be trimmed");
        assert!(r.starts_with(&base.canonicalize().unwrap()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_smb_subpath_traversal() {
        let bad = Source::Smb {
            server: "x".into(), share: "y".into(),
            subpath: Some("../escape".into()),
            username: None, password: None, domain: None, options: None,
        };
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn validate_local_path_must_be_absolute() {
        let s = Source::Local { node_id: "n".into(), path: "relative/path".into() };
        let err = validate(&s).unwrap_err();
        assert!(err.contains("absolute"), "{}", err);
    }

    #[test]
    fn validate_rejects_reserved_source_types() {
        // Sshfs / S3Rclone / PeerGateway still reference credential/key stores
        // and a FUSE-daemon lifecycle WolfStack doesn't have yet, so validate
        // rejects them at config-save with a clear "future release" error.
        let cases = [
            Source::Sshfs { user: "u".into(), host: "h".into(), path: "/p".into(), port: None, key_id: None },
            Source::S3Rclone { remote_id: "r".into(), bucket: "b".into(), prefix: None },
            Source::PeerGateway { peer_cluster_url: "u".into(), gateway_id: "g".into(), creds_id: "c".into() },
        ];
        for s in cases {
            assert!(validate(&s).is_err(), "should reject {:?}", s);
        }
    }

    #[test]
    fn validate_accepts_implemented_source_types() {
        // The four now-implemented source types pass config validation.
        let ok = [
            Source::Rbd { cluster_id: "c".into(), pool: "p".into(), image: "i".into(), fs: "ext4".into() },
            Source::ContainerVol { node_id: "n".into(), runtime: "docker".into(), container: "web".into(), volume: "data".into() },
            Source::LxcDir { node_id: "n".into(), container: "ct1".into(), path: "/srv/data".into() },
            Source::VmExport { vm_id: "vm1".into(), sub_protocol: VmExportProto::Smb, share_or_export: "share".into() },
            Source::VmExport { vm_id: "vm1".into(), sub_protocol: VmExportProto::Nfs, share_or_export: "/export".into() },
        ];
        for s in ok {
            assert!(validate(&s).is_ok(), "should accept {:?}: {:?}", s, validate(&s));
        }
    }

    #[test]
    fn validate_rejects_bad_implemented_configs() {
        // Wrong fs, non-docker runtime, relative lxc path, iSCSI vm-export,
        // and '..' traversal are all rejected.
        let bad = [
            Source::Rbd { cluster_id: "c".into(), pool: "p".into(), image: "i".into(), fs: "zfs".into() },
            Source::ContainerVol { node_id: "n".into(), runtime: "lxc".into(), container: "c".into(), volume: "v".into() },
            Source::LxcDir { node_id: "n".into(), container: "c".into(), path: "relative".into() },
            Source::LxcDir { node_id: "n".into(), container: "c".into(), path: "/a/../../etc".into() },
            Source::VmExport { vm_id: "v".into(), sub_protocol: VmExportProto::Iscsi, share_or_export: "t".into() },
        ];
        for s in bad {
            assert!(validate(&s).is_err(), "should reject {:?}", s);
        }
    }
}
