// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! LXC storage operations: detect backend, resize the rootfs, migrate
//! between storage paths. Native (lxc-* + ZFS / LVM / dir) and Proxmox
//! (via PveClient REST) both go through here so the API surface is
//! consistent regardless of where the container lives.
//!
//! Supported backends (auto-detected from rootfs path / lxc.rootfs.path):
//!   • **Directory** — plain rootfs directory. "Resize" is a no-op
//!     unless the parent filesystem itself is grown (we surface that
//!     to the user as guidance — directories don't have a quota).
//!   • **ZFS dataset** — `zfs set quota=NEWSIZE pool/<dataset>`.
//!     The user-visible "size" is the dataset quota.
//!   • **LVM logical volume** — `lvextend -L NEWSIZE` followed by
//!     `resize2fs` / `xfs_growfs` depending on the filesystem.
//!   • **btrfs subvolume** — `btrfs qgroup limit NEWSIZE`.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LxcBackend {
    Directory,
    Zfs,
    Lvm,
    Btrfs,
    /// Container is on a Proxmox-managed storage pool — operations go
    /// through the PVE API (pct resize / pct move-volume).
    Proxmox,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LxcDiskInfo {
    pub container: String,
    pub backend: LxcBackend,
    /// Filesystem-level path of the rootfs (best-effort). For Proxmox
    /// containers this is the volume identifier (e.g. `local-zfs:subvol-100-disk-0`).
    pub rootfs: String,
    /// Storage path that hosts this container (parent dir / pool /
    /// VG name / Proxmox storage id).
    pub storage: String,
    /// Total bytes available to the container (quota / volume size).
    /// None when we can't determine — typical for directory backends.
    pub size_bytes: Option<u64>,
    /// Bytes in use by the container right now.
    pub used_bytes: Option<u64>,
    /// Filesystem of the rootfs (ext4, xfs, btrfs, zfs, ...).
    #[serde(default)]
    pub fs_type: String,
    /// True when the container is on a Proxmox-managed node.
    #[serde(default)]
    pub proxmox: bool,
    /// PVE node id and vmid when proxmox=true.
    #[serde(default)]
    pub pve_node: String,
    #[serde(default)]
    pub pve_vmid: u64,
}

/// Inspect a container's storage. For native LXC, parses the config
/// file's `lxc.rootfs.path` and detects the backend from the actual
/// path or device. For Proxmox, returns a Proxmox-tagged LxcDiskInfo.
pub fn inspect(name: &str) -> Result<LxcDiskInfo, String> {
    // Proxmox-hosted containers: look them up via `pct config`. WolfStack
    // already knows whether `pct` is on the host (via lxc_list_all).
    if which("pct")
        && let Some(info) = inspect_pct_local(name) {
            return Ok(info);
        }

    // Native LXC: walk the registered storage paths to find this
    // container's config file.
    let storage_paths = super::lxc_storage_paths();
    for parent in &storage_paths {
        let cfg_path = format!("{}/{}/config", parent, name);
        if !Path::new(&cfg_path).exists() { continue; }
        let cfg = fs::read_to_string(&cfg_path)
            .map_err(|e| format!("read {}: {}", cfg_path, e))?;
        let rootfs = parse_rootfs(&cfg);
        let backend = classify_backend(&rootfs, parent);
        let (size, used) = measure_rootfs(&rootfs, parent, name, backend);
        let fs_type = detect_fs_type(&rootfs, parent, name, backend);
        return Ok(LxcDiskInfo {
            container: name.into(),
            backend,
            rootfs,
            storage: parent.clone(),
            size_bytes: size,
            used_bytes: used,
            fs_type,
            proxmox: false,
            pve_node: String::new(),
            pve_vmid: 0,
        });
    }
    Err(format!("container '{}' not found in any registered LXC storage path", name))
}

/// Resize a container's rootfs. `new_size_bytes` is the absolute target
/// size. Container should be stopped for non-online-resize backends
/// (LVM/ext4 can usually grow online; ZFS quota changes are immediate).
pub fn resize(name: &str, new_size_bytes: u64) -> Result<String, String> {
    let info = inspect(name)?;
    // Refuse shrinks below current usage — that's a one-way ticket to
    // data corruption on most backends.
    if let Some(used) = info.used_bytes
        && new_size_bytes < used {
            return Err(format!(
                "refusing to resize below current usage ({} bytes used, requested {})",
                used, new_size_bytes
            ));
        }
    // Belt-and-braces: most backends here are grow-only (lvextend,
    // zfs quota set is technically allowed to shrink but corrupts in
    // practice if used > new). Reject a shrink with a clear message
    // before we hit the underlying tool's "matches existing size" /
    // "out of space" failure modes.
    if let Some(current) = info.size_bytes
        && new_size_bytes < current {
            return Err(format!(
                "shrinking is not supported (current size {} bytes, requested {}). Migrate to a smaller storage instead.",
                current, new_size_bytes
            ));
        }

    if info.proxmox {
        return Err("use proxmox::PveClient::pct_resize for Proxmox containers — the API endpoint will route there automatically".into());
    }

    match info.backend {
        LxcBackend::Zfs => {
            // ZFS quota: identify dataset from rootfs path. Convention:
            // /<pool>/<...>/<container_name>
            let dataset = zfs_dataset_for(&info.rootfs)
                .ok_or_else(|| format!("couldn't derive ZFS dataset from {}", info.rootfs))?;
            let bytes_str = format!("{}", new_size_bytes);
            let out = Command::new("zfs")
                .args(["set", &format!("quota={}", bytes_str), &dataset])
                .output()
                .map_err(|e| format!("zfs set: {}", e))?;
            if !out.status.success() {
                return Err(format!("zfs set quota failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()));
            }
            Ok(format!("ZFS quota on '{}' set to {} bytes", dataset, new_size_bytes))
        }
        LxcBackend::Lvm => {
            // lvextend -L<bytes>B then resize FS.
            let lv = lvm_lv_for(&info.rootfs)
                .ok_or_else(|| format!("couldn't derive LVM logical volume from {}", info.rootfs))?;
            let out = Command::new("lvextend")
                .args(["-L", &format!("{}B", new_size_bytes), &lv])
                .output()
                .map_err(|e| format!("lvextend: {}", e))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.contains("matches existing size") {
                    return Err(format!("lvextend failed: {}", stderr.trim()));
                }
            }
            // Grow the filesystem to fill the new LV.
            let fs_grow = match info.fs_type.as_str() {
                "ext4" | "ext3" | "ext2" => Command::new("resize2fs").arg(&lv).output(),
                "xfs" => Command::new("xfs_growfs").arg(&info.rootfs).output(),
                "btrfs" => Command::new("btrfs").args(["filesystem", "resize", "max", &info.rootfs]).output(),
                other => return Err(format!("unsupported fs '{}' for online grow", other)),
            };
            let out = fs_grow.map_err(|e| format!("fs grow: {}", e))?;
            if !out.status.success() {
                return Err(format!("filesystem grow failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()));
            }
            Ok(format!("LVM volume '{}' grown to {} bytes and {} resized", lv, new_size_bytes, info.fs_type))
        }
        LxcBackend::Btrfs => {
            // btrfs qgroup limit <bytes> <subvol>
            let out = Command::new("btrfs")
                .args(["qgroup", "limit", &format!("{}", new_size_bytes), &info.rootfs])
                .output()
                .map_err(|e| format!("btrfs qgroup: {}", e))?;
            if !out.status.success() {
                return Err(format!("btrfs qgroup limit failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()));
            }
            Ok(format!("btrfs subvolume '{}' quota set to {} bytes", info.rootfs, new_size_bytes))
        }
        LxcBackend::Directory => {
            Err("directory-backend rootfs has no per-container quota — grow the parent filesystem (or move to ZFS/LVM) to add space".into())
        }
        LxcBackend::Proxmox | LxcBackend::Unknown => {
            Err(format!("can't resize backend {:?} — unknown how to grow this volume", info.backend))
        }
    }
}

/// Migrate a stopped container's rootfs to a different storage path.
/// Native: rsync over (preserving perms/xattrs), update lxc.rootfs.path
/// in the config, optionally remove the old. Proxmox: callers should
/// use the PVE move-volume API instead (this helper refuses).
///
/// Refuses to run if the container is up — rsyncing a live rootfs
/// produces an inconsistent copy. The user can stop the container
/// from the LXC card, then retry.
pub fn migrate(name: &str, target_storage: &str, remove_source: bool) -> Result<String, String> {
    let info = inspect(name)?;
    if info.proxmox {
        return Err("use proxmox::PveClient::pct_move_volume for Proxmox containers".into());
    }
    // Refuse to migrate a running container — rsync of a live rootfs
    // is racy and produces an inconsistent copy.
    let state = Command::new("lxc-info").args(["-s", "-H", "-n", name]).output();
    if let Ok(o) = state
        && o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.eq_ignore_ascii_case("RUNNING") {
                return Err(format!(
                    "container '{}' is RUNNING — stop it first (rsync of a live rootfs produces an inconsistent copy)",
                    name
                ));
            }
        }
    if target_storage == info.storage {
        return Err("source and target storage paths are the same".into());
    }
    // The target came from the user picking an option we built out of
    // /api/storage/list (each mounted filesystem + "/lxc"), so it's a
    // legitimate destination even if it isn't in the registered-paths
    // registry yet. Refusing unregistered paths forced the user to
    // visit Settings → LXC storage paths and add /wolfpool/lxc by
    // hand before every migrate, which defeats the point of the
    // dropdown. Auto-register once we've verified the parent mount
    // exists — the post-migrate scanner then finds the container in
    // its new home.
    let parent = std::path::Path::new(target_storage)
        .parent()
        .map(|p| p.to_path_buf());
    if let Some(p) = &parent
        && !p.exists() {
            return Err(format!(
                "target parent '{}' does not exist — mount the filesystem first",
                p.display()
            ));
        }
    if !super::lxc_storage_paths().iter().any(|p| p == target_storage) {
        super::lxc_register_path(target_storage);
    }

    let src_dir = format!("{}/{}", info.storage, name);
    let dst_dir = format!("{}/{}", target_storage, name);
    if Path::new(&dst_dir).exists() {
        return Err(format!("target path {} already exists — refuse to overwrite", dst_dir));
    }

    // rsync the whole container directory with attributes preserved.
    fs::create_dir_all(target_storage).map_err(|e| format!("mkdir {}: {}", target_storage, e))?;
    let out = Command::new("rsync")
        .args(["-aHAX", "--numeric-ids", "--info=stats1",
               &format!("{}/", src_dir), &format!("{}/", dst_dir)])
        .output()
        .map_err(|e| format!("rsync: {}", e))?;
    if !out.status.success() {
        let _ = fs::remove_dir_all(&dst_dir);
        return Err(format!("rsync failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }

    // Rewrite lxc.rootfs.path in the new copy of the config so it
    // points at the new location. Propagating a write failure here is
    // critical — pre-v18.7.30 we swallowed the Err with `let _ =`,
    // which meant a failed rewrite left the moved container's config
    // pointing at the OLD (now-missing) rootfs path. Container would
    // refuse to start on next boot with a cryptic "rootfs doesn't
    // exist" error and no hint about the silent write failure.
    let new_cfg_path = format!("{}/config", dst_dir);
    if let Ok(cfg) = fs::read_to_string(&new_cfg_path) {
        let new_rootfs = info.rootfs.replace(&info.storage, target_storage);
        let updated = rewrite_rootfs_path(&cfg, &new_rootfs);
        fs::write(&new_cfg_path, updated)
            .map_err(|e| format!("rewrite {} after storage migrate: {}", new_cfg_path, e))?;
    }

    if remove_source {
        // Source removal IS fine to swallow — we've already moved the
        // data to dst and rewritten the config. A failure here leaves
        // stale bits in the old storage but doesn't break the
        // migrated container.
        let _ = fs::remove_dir_all(&src_dir);
    }
    Ok(format!("migrated {} → {} ({} → {})", name, target_storage, info.storage, target_storage))
}

// ─── Helpers ──────────────────────────────────────────────────

fn which(cmd: &str) -> bool {
    Command::new("which").arg(cmd).status().map(|s| s.success()).unwrap_or(false)
}

fn parse_rootfs(cfg: &str) -> String {
    for line in cfg.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("lxc.rootfs.path") {
            // form: lxc.rootfs.path = dir:/var/lib/lxc/<name>/rootfs
            // or:   lxc.rootfs.path = zfs:tank/lxc/<name>
            // or:   lxc.rootfs.path = /var/lib/lxc/<name>/rootfs
            let val = rest.trim_start_matches([' ', '=']).trim();
            // Strip type prefix if present (dir:, zfs:, lvm:, ...).
            if let Some((_, p)) = val.split_once(':') {
                return p.trim().to_string();
            }
            return val.to_string();
        }
    }
    String::new()
}

fn rewrite_rootfs_path(cfg: &str, new_path: &str) -> String {
    let mut out = String::new();
    for line in cfg.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("lxc.rootfs.path") {
            // Preserve the prefix (dir:, zfs:, etc) if present.
            let new_line = if let Some((kind, _)) = trimmed.split_once('=')
                .and_then(|(_, v)| v.trim().split_once(':'))
            {
                format!("lxc.rootfs.path = {}:{}", kind, new_path)
            } else {
                format!("lxc.rootfs.path = {}", new_path)
            };
            out.push_str(&new_line);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn classify_backend(rootfs: &str, parent: &str) -> LxcBackend {
    if rootfs.is_empty() { return LxcBackend::Unknown; }
    // Cheapest signal: file's filesystem from `stat -f -c %T <path>`.
    if let Ok(out) = Command::new("stat").args(["-f", "-c", "%T", rootfs]).output()
        && out.status.success() {
            let fs = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return match fs.as_str() {
                "zfs" => LxcBackend::Zfs,
                "btrfs" => LxcBackend::Btrfs,
                _ => {
                    // Could be ext4-on-LVM (still reports "ext4") — check
                    // mount source for a /dev/mapper path.
                    if rootfs_is_on_lvm(rootfs).is_some() { LxcBackend::Lvm }
                    else { LxcBackend::Directory }
                }
            };
        }
    let _ = parent;
    LxcBackend::Directory
}

fn rootfs_is_on_lvm(rootfs: &str) -> Option<String> {
    // findmnt -no SOURCE <path>
    let out = Command::new("findmnt").args(["-no", "SOURCE", rootfs]).output().ok()?;
    if !out.status.success() { return None; }
    let src = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if src.starts_with("/dev/mapper/") || src.contains("-lv-") || src.contains("--") {
        Some(src)
    } else {
        None
    }
}

fn zfs_dataset_for(path: &str) -> Option<String> {
    // `zfs list -H -o name -p <path>` or use zfs list piped + match.
    let out = Command::new("zfs").args(["list", "-H", "-o", "name", path]).output().ok()?;
    if !out.status.success() { return None; }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn lvm_lv_for(rootfs: &str) -> Option<String> {
    rootfs_is_on_lvm(rootfs)
}

fn detect_fs_type(rootfs: &str, _parent: &str, _name: &str, backend: LxcBackend) -> String {
    match backend {
        LxcBackend::Zfs => "zfs".into(),
        LxcBackend::Btrfs => "btrfs".into(),
        _ => Command::new("stat").args(["-f", "-c", "%T", rootfs]).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default(),
    }
}

fn measure_rootfs(rootfs: &str, _parent: &str, _name: &str, backend: LxcBackend) -> (Option<u64>, Option<u64>) {
    if rootfs.is_empty() { return (None, None); }
    match backend {
        LxcBackend::Zfs => {
            let dataset = match zfs_dataset_for(rootfs) {
                Some(d) => d,
                None => return (None, None),
            };
            let out = Command::new("zfs")
                .args(["list", "-H", "-p", "-o", "quota,used", &dataset])
                .output().ok();
            if let Some(o) = out
                && o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout);
                    let mut parts = s.split_whitespace();
                    let q = parts.next().and_then(|x| x.parse::<u64>().ok());
                    let u = parts.next().and_then(|x| x.parse::<u64>().ok());
                    return (q.filter(|&v| v > 0), u);
                }
            (None, None)
        }
        _ => {
            // df -B1 <path>
            let out = Command::new("df").args(["-B1", "--output=size,used", rootfs]).output().ok();
            if let Some(o) = out
                && o.status.success() {
                    let txt = String::from_utf8_lossy(&o.stdout);
                    if let Some(line) = txt.lines().nth(1) {
                        let mut parts = line.split_whitespace();
                        let s = parts.next().and_then(|x| x.parse::<u64>().ok());
                        let u = parts.next().and_then(|x| x.parse::<u64>().ok());
                        return (s, u);
                    }
                }
            (None, None)
        }
    }
}

fn inspect_pct_local(name: &str) -> Option<LxcDiskInfo> {
    // pct list to find the vmid for this container. Format:
    //   VMID Status Lock Name
    // Lock column may be empty. Match the Name column EXACTLY (not
    // a substring of the line) to avoid false matches like "web"
    // hitting "webdb".
    let out = Command::new("pct").args(["list"]).output().ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let vmid: u64 = text.lines().skip(1).find_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { return None; }
        // Last column is Name (Lock may be missing). Strict equality.
        let last = parts.last()?;
        if *last == name { parts[0].parse().ok() } else { None }
    })?;

    // Parse `pct config <vmid>` for rootfs and storage.
    let out = Command::new("pct").args(["config", &vmid.to_string()]).output().ok()?;
    if !out.status.success() { return None; }
    let cfg = String::from_utf8_lossy(&out.stdout).to_string();
    let mut rootfs = String::new();
    let mut size = None;
    for line in cfg.lines() {
        if let Some(rest) = line.strip_prefix("rootfs:") {
            // form: rootfs: local-zfs:subvol-100-disk-0,size=8G
            let val = rest.trim();
            rootfs = val.split(',').next().unwrap_or("").to_string();
            for tok in val.split(',') {
                if let Some(s) = tok.trim().strip_prefix("size=") {
                    size = parse_size(s);
                }
            }
        }
    }
    let storage = rootfs.split(':').next().unwrap_or("").to_string();
    Some(LxcDiskInfo {
        container: name.into(),
        backend: LxcBackend::Proxmox,
        rootfs: rootfs.clone(),
        storage,
        size_bytes: size,
        used_bytes: None,
        fs_type: String::new(),
        proxmox: true,
        // Local pct host = this WolfStack node. Without this the API
        // handler can't find a PveClient (it looks up by node_id) and
        // resize/migrate silently fail with 503.
        pve_node: crate::agent::self_node_id(),
        pve_vmid: vmid,
    })
}

/// Parse a Proxmox-style size string like "8G", "500M", "1T" → bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len()));
    let n: f64 = num.parse().ok()?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        "t" | "tb" => 1024u64 * 1024 * 1024 * 1024,
        _ => return None,
    };
    Some((n * mult as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("8G"), Some(8u64 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("500M"), Some(500u64 * 1024 * 1024));
        assert_eq!(parse_size("1024k"), Some(1024u64 * 1024));
        assert_eq!(parse_size("1.5G"), Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64));
    }
    #[test]
    fn parse_rootfs_native() {
        let cfg = "lxc.utsname = ct1\nlxc.rootfs.path = dir:/var/lib/lxc/ct1/rootfs\n";
        assert_eq!(parse_rootfs(cfg), "/var/lib/lxc/ct1/rootfs");
    }
    #[test]
    fn parse_rootfs_no_prefix() {
        let cfg = "lxc.rootfs.path = /tank/lxc/ct2\n";
        assert_eq!(parse_rootfs(cfg), "/tank/lxc/ct2");
    }
}
