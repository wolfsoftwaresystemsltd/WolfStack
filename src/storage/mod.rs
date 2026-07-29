// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Storage Manager — mount and manage S3, NFS, SMB/CIFS, directory, and WolfDisk storage
//!
//! Supports:
//! - S3 storage via rust-s3 (pure Rust, native, works on IBM Power/ppc64le)
//! - S3 storage via s3fs-fuse (fallback)
//! - SSHFS mounts via sshfs
//! - NFS storage via mount -t nfs
//! - SMB/CIFS storage via mount -t cifs (Synology/QNAP NAS with default SMB shares)
//! - Local directory bind mounts
//! - WolfDisk mounts via wolfdisk CLI
//! - Global mounts replicated across the cluster
//! - Import of S3 configs from rclone.conf

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{warn, error, info};
use chrono::Utc;

fn config_path() -> String { crate::paths::get().storage_config }
const MOUNT_BASE: &str = "/mnt/wolfstack";

// ─── Data Types ───

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    S3,
    Nfs,
    Smb,
    Directory,
    Wolfdisk,
    Sshfs,
    /// A local block device (whole disk or partition) mounted at a directory —
    /// klasSponsor 2026-06 QoL: "mount HDDs to directories". `source` is the
    /// device (a /dev path or, preferred, `UUID=…` so it survives device
    /// renaming across reboots). Persistence is via WolfStack's own auto_mount
    /// on boot, the same as every other mount type — no hand-edited /etc/fstab.
    Disk,
}

/// Per-mount SMB/CIFS credentials + options. Kept separate from S3Config so
/// the two don't share a struct shape for no reason. `password` is stored in
/// /etc/wolfstack/storage.json in plain text (same policy as S3 secrets) —
/// file is root-owned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbConfig {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// Optional AD domain / workgroup
    #[serde(default)]
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_s3_provider")]
    pub provider: String,
    #[serde(default)]
    pub bucket: String,
}

fn default_s3_provider() -> String { "AWS".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMount {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub mount_type: MountType,
    pub source: String,          // NFS: server:/path, Directory: /local/path, WolfDisk: path
    pub mount_point: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub global: bool,            // replicate to cluster nodes
    #[serde(default)]
    pub auto_mount: bool,        // mount on boot
    #[serde(default)]
    pub s3_config: Option<S3Config>,
    #[serde(default)]
    pub nfs_options: Option<String>,
    /// CIFS mount options (e.g. "vers=3.0,sec=ntlmssp"). Appended to the
    /// auto-built credentials options when the mount is CIFS/SMB.
    #[serde(default)]
    pub smb_options: Option<String>,
    #[serde(default)]
    pub smb_config: Option<SmbConfig>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub error_message: Option<String>,
    pub created_at: String,
}

fn default_status() -> String { "unmounted".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub mounts: Vec<StorageMount>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig { mounts: Vec::new() }
    }
}

// ─── Config Persistence ───

pub fn load_config() -> StorageConfig {
    match fs::read_to_string(&config_path()) {
        Ok(content) => {
            serde_json::from_str(&content).unwrap_or_else(|e| {
                error!("Failed to parse storage config: {}", e);
                StorageConfig::default()
            })
        }
        Err(_) => StorageConfig::default(),
    }
}

pub fn save_config(config: &StorageConfig) -> Result<(), String> {
    // Ensure directory exists
    let path = config_path();
    let dir = Path::new(&path).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;

    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(&path, json)
        .map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

// ─── Mount ID Generation ───

pub fn generate_id(name: &str) -> String {
    let slug: String = name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let short_uuid = &uuid::Uuid::new_v4().to_string()[..8];
    format!("{}-{}", slug, short_uuid)
}

// ─── Status Check ───

pub fn check_mounted(mount_point: &str) -> bool {
    Command::new("mountpoint")
        .arg("-q")
        .arg(mount_point)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get the status of all mounts (refreshes live status)
pub fn list_mounts() -> Vec<StorageMount> {
    let mut config = load_config();
    for mount in &mut config.mounts {
        if check_mounted(&mount.mount_point) {
            mount.status = "mounted".to_string();
            mount.error_message = None;
        } else if mount.status == "mounted" {
            // Was mounted but no longer — mark as unmounted
            mount.status = "unmounted".to_string();
        }
        // Preserve "error" status with error_message intact
    }
    config.mounts
}

/// Placeholder the API substitutes for stored secrets, and that update_mount
/// treats as "leave the stored value alone". One constant so the read side
/// and the write side can never disagree about what the sentinel is.
pub const REDACTED_SECRET: &str = "••••••••";

/// `list_mounts` with every stored secret replaced by REDACTED_SECRET.
/// Used by the browser-facing API; the cluster replication path keeps using
/// `list_mounts`, because a peer applying a replicated mount needs the real
/// credentials to mount it.
pub fn list_mounts_redacted() -> Vec<StorageMount> {
    // A secret that was never set stays empty: the edit dialog uses "is there
    // a stored secret?" to decide between "leave blank to keep unchanged" and
    // "enter secret key", and a blanket sentinel would claim every mount had
    // credentials.
    fn redact(secret: &mut String) {
        if !secret.is_empty() {
            *secret = REDACTED_SECRET.to_string();
        }
    }

    let mut mounts = list_mounts();
    for m in &mut mounts {
        if let Some(s3) = m.s3_config.as_mut() {
            redact(&mut s3.secret_access_key);
        }
        if let Some(smb) = m.smb_config.as_mut() {
            redact(&mut smb.password);
        }
    }
    mounts
}

// ─── Mount Operations ───

// ─── Shutdown ordering for WebUI network mounts ─────────────────────────────
// The boot half of mount ordering is wolfstack-mounts.target (see
// auto_mount_all). This is the SHUTDOWN half (wabil 2026-06-11): once a
// mergerfs pool reliably mounts over WebUI NFS/CIFS branches at boot, reboot
// hangs appeared — systemd tried to unmount a branch while the pool still
// held it (busy), retried, and by then the network was down so a hard NFS
// unmount hung to its timeout. WolfStack's mounts are runtime units with no
// dependencies, so nothing ordered pool-before-branches or
// branches-before-network-teardown.
//
// Fix: after a successful NETWORK mount, write a runtime drop-in for its
// .mount unit (in /run/systemd/system — per-boot, nothing persists):
//   • Before=wolfstack-mounts.target → reversed at shutdown, anything
//     ordered on the target (the pool) unmounts BEFORE the branch.
//   • After=network-online/network.target → reversed at shutdown, the
//     branch unmounts while the network is still up.
// Boot-safety: these orderings are inert at boot — the units activate from
// WolfStack's own mount(8) calls, not from a systemd transaction, and
// neither target orders back onto them, so no cycle is possible.
const MOUNT_DROPIN_BODY: &str = "\
[Unit]
# Written at mount time by WolfStack (storage manager). Ensures this network
# mount is unmounted BEFORE the network goes down at shutdown, and BEFORE
# wolfstack-mounts.target stops - so a pool layered over it (mergerfs etc.,
# ordered on the target) unmounts first and never leaves the branch busy.
After=network-online.target network.target
Before=wolfstack-mounts.target
";

/// Mount types that live over the network and need shutdown ordering.
fn is_network_mount(t: &MountType) -> bool {
    matches!(t, MountType::Nfs | MountType::Smb | MountType::Sshfs | MountType::S3)
}

/// The systemd unit name for a mountpoint (via systemd-escape, the only
/// correct escaper). None on non-systemd hosts or escape failure.
fn mount_unit_name(mount_point: &str) -> Option<String> {
    if !std::path::Path::new("/run/systemd/system").exists() {
        return None;
    }
    let out = Command::new("systemd-escape")
        .args(["-p", "--suffix=mount", mount_point])
        .output().ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// Write the shutdown-ordering drop-in for a mounted network mount and
/// daemon-reload so the runtime unit picks it up. Skips the reload when the
/// drop-in already matches (wolfstack restarts within one boot).
fn write_mount_shutdown_dropin(mount_point: &str) {
    let Some(unit) = mount_unit_name(mount_point) else { return };
    let dir = format!("/run/systemd/system/{}.d", unit);
    let path = format!("{}/wolfstack.conf", dir);
    if std::fs::read_to_string(&path).ok().as_deref() == Some(MOUNT_DROPIN_BODY) {
        return;
    }
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if std::fs::write(&path, MOUNT_DROPIN_BODY).is_ok() {
        let _ = Command::new("systemctl").arg("daemon-reload").output();
    }
}

/// Remove the drop-in when the mount is unmounted/deleted.
fn remove_mount_shutdown_dropin(mount_point: &str) {
    let Some(unit) = mount_unit_name(mount_point) else { return };
    let dir = format!("/run/systemd/system/{}.d", unit);
    if std::path::Path::new(&dir).exists() && std::fs::remove_dir_all(&dir).is_ok() {
        let _ = Command::new("systemctl").arg("daemon-reload").output();
    }
}

/// True if `mount_point` is unsafe to mount a filesystem over — a critical
/// system directory (or a path at/under one). Mounting over these hides the
/// running system's own files even though the disk is intact: a mount over
/// `/dev` hides `/dev/null` and every process loses the ability to exec; over
/// `/usr`/`/bin`/`/lib` it hides every binary; over `/` it hides everything.
/// Enforced at the single mount chokepoint so it covers BOTH operator-created
/// mounts and cluster-replicated ones (a global-scoped mount fans out to every
/// peer). Rejects relative paths and `..` traversal too.
fn is_unsafe_mount_target(mount_point: &str) -> bool {
    let p = mount_point.trim();
    if p.is_empty() || !p.starts_with('/') { return true; }
    if p.split('/').any(|seg| seg == "..") { return true; }
    // Normalise: collapse duplicate/trailing slashes.
    let mut norm = String::from("/");
    for seg in p.split('/').filter(|s| !s.is_empty()) {
        if norm.len() > 1 { norm.push('/'); }
        norm.push_str(seg);
    }
    if norm == "/" { return true; }
    // Whole OS trees that must never host a storage mount — rejected at the
    // directory itself AND any path under it (mounting over /usr/bin hides
    // every binary just as surely as mounting over /usr).
    const UNSAFE_TREES: &[&str] = &[
        "/dev", "/proc", "/sys", "/run", "/boot", "/etc", "/usr",
        "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/root",
    ];
    for root in UNSAFE_TREES {
        if norm == *root || norm.starts_with(&format!("{}/", root)) {
            return true;
        }
    }
    // /var and /home: the directory itself is unsafe, but normal data mounts
    // legitimately live *under* them (/var/lib/vz, /home/user/data) — allow
    // those, reject only the bare top-level dir.
    if norm == "/var" || norm == "/home" { return true; }
    false
}

/// Mount a storage entry by ID
pub fn mount_storage(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.mounts.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;

    // SECURITY: refuse to mount over a critical system directory. Both the
    // operator path (create_mount) and the cluster-replicated path
    // (apply_replicated_mount) funnel through here, so this one check guards
    // a single-node mistake AND a global-scoped mount that would otherwise
    // fan out and break every peer simultaneously.
    let mp = config.mounts[idx].mount_point.clone();
    if is_unsafe_mount_target(&mp) {
        let msg = format!("refusing to mount over critical system path '{}'", mp);
        config.mounts[idx].status = "error".to_string();
        config.mounts[idx].error_message = Some(msg.clone());
        let _ = save_config(&config);
        return Err(msg);
    }

    // Already mounted?
    if check_mounted(&config.mounts[idx].mount_point) {
        config.mounts[idx].status = "mounted".to_string();
        save_config(&config)?;
        return Ok("Already mounted".to_string());
    }
    
    // Create mount point directory
    fs::create_dir_all(&config.mounts[idx].mount_point)
        .map_err(|e| format!("Failed to create mount point: {}", e))?;
    
    let result = match config.mounts[idx].mount_type {
        MountType::S3 => mount_s3(&config.mounts[idx]),
        MountType::Nfs => mount_nfs(&config.mounts[idx]),
        MountType::Smb => mount_smb(&config.mounts[idx]),
        MountType::Directory => mount_directory(&config.mounts[idx]),
        MountType::Wolfdisk => mount_wolfdisk(&config.mounts[idx]),
        MountType::Sshfs => mount_sshfs(&config.mounts[idx]),
        MountType::Disk => mount_disk(&config.mounts[idx]),
    };
    
    match result {
        Ok(msg) => {
            config.mounts[idx].status = "mounted".to_string();
            config.mounts[idx].error_message = None;
            config.mounts[idx].enabled = true;
            save_config(&config)?;
            // Network mounts get a shutdown-ordering drop-in (see the block
            // comment above mount_storage) so reboots don't hang on a busy
            // or post-network unmount.
            if is_network_mount(&config.mounts[idx].mount_type) {
                write_mount_shutdown_dropin(&config.mounts[idx].mount_point);
            }

            Ok(msg)
        }
        Err(e) => {
            config.mounts[idx].status = "error".to_string();
            config.mounts[idx].error_message = Some(e.clone());
            save_config(&config)?;
            Err(e)
        }
    }
}

/// Unmount a storage entry by ID
pub fn unmount_storage(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.mounts.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
    if !check_mounted(&config.mounts[idx].mount_point) {
        config.mounts[idx].status = "unmounted".to_string();
        save_config(&config)?;
        return Ok("Not mounted".to_string());
    }
    
    // Type-specific unmount handling
    let output = if config.mounts[idx].mount_type == MountType::S3 {
        // Try fusermount first (s3fs), fall back to regular umount (rust-s3 bind mount)
        let fuse_result = Command::new("fusermount")
            .args(["-u", &config.mounts[idx].mount_point])
            .output();
        match &fuse_result {
            Ok(o) if o.status.success() => fuse_result,
            _ => Command::new("umount")
                .arg(&config.mounts[idx].mount_point)
                .output(),
        }
    } else if config.mounts[idx].mount_type == MountType::Wolfdisk {
        // WolfDisk uses FUSE — try wolfdisk unmount, fall back to fusermount
        let wd_result = Command::new("wolfdisk")
            .args(["unmount", "--mountpoint", &config.mounts[idx].mount_point])
            .output();
        match &wd_result {
            Ok(o) if o.status.success() => wd_result,
            _ => Command::new("fusermount")
                .args(["-u", &config.mounts[idx].mount_point])
                .output(),
        }
    } else {
        Command::new("umount")
            .arg(&config.mounts[idx].mount_point)
            .output()
    };
    
    match output {
        Ok(o) if o.status.success() => {
            config.mounts[idx].status = "unmounted".to_string();
            config.mounts[idx].error_message = None;
            save_config(&config)?;
            remove_mount_shutdown_dropin(&config.mounts[idx].mount_point);

            Ok("Unmounted successfully".to_string())
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            // Try lazy unmount as fallback
            let _ = Command::new("umount").args(["-l", &config.mounts[idx].mount_point]).output();
            config.mounts[idx].status = "unmounted".to_string();
            save_config(&config)?;
            remove_mount_shutdown_dropin(&config.mounts[idx].mount_point);
            Ok(format!("Unmounted (lazy): {}", err))
        }
        Err(e) => Err(format!("Failed to unmount: {}", e)),
    }
}

/// Create a new mount entry and optionally mount it
pub fn create_mount(mut mount: StorageMount, do_mount: bool) -> Result<StorageMount, String> {
    let mut config = load_config();
    
    // Generate ID if empty
    if mount.id.is_empty() {
        mount.id = generate_id(&mount.name);
    }
    
    // Default mount point
    if mount.mount_point.is_empty() {
        mount.mount_point = format!("{}/{}", MOUNT_BASE, mount.id);
    }
    
    // Set created_at
    if mount.created_at.is_empty() {
        mount.created_at = Utc::now().to_rfc3339();
    }
    
    mount.status = "unmounted".to_string();
    
    // Check for duplicate mount points
    if config.mounts.iter().any(|m| m.mount_point == mount.mount_point) {
        return Err(format!("Mount point '{}' already in use", mount.mount_point));
    }
    
    // Check for duplicate names (prevents double-adding the same storage)
    if config.mounts.iter().any(|m| m.name == mount.name) {
        return Err(format!("A mount named '{}' already exists", mount.name));
    }
    
    config.mounts.push(mount.clone());
    save_config(&config)?;
    
    if do_mount {
        mount_storage(&mount.id)?;
        // Refresh status
        let config = load_config();
        if let Some(m) = config.mounts.iter().find(|m| m.id == mount.id) {
            return Ok(m.clone());
        }
    }

    Ok(mount)
}

/// Index of the existing mount a replicated `incoming` should REPLACE on a
/// cluster apply — matched by id first (stable across the cluster), else by
/// mount_point. Pure (no I/O) so the upsert decision is unit-testable.
fn replicated_mount_match(mounts: &[StorageMount], incoming: &StorageMount) -> Option<usize> {
    if !incoming.id.is_empty() {
        if let Some(i) = mounts.iter().position(|m| m.id == incoming.id) {
            return Some(i);
        }
    }
    mounts.iter().position(|m| m.mount_point == incoming.mount_point)
}

/// Idempotently apply a mount replicated from another cluster node. Unlike
/// `create_mount`, this UPSERTS: a matching existing entry is updated in
/// place and the mount is RE-ATTEMPTED, instead of failing with "Mount point
/// already in use". Without this, once a global mount's first sync left an
/// entry on a peer, every later sync returned "already in use" instantly —
/// never creating the dir or retrying the mount (wabil 2026-06-16).
/// `mount_storage` is itself idempotent (already-mounted → no-op), so a
/// working mount is never disturbed; a failed/unmounted one is retried and
/// its real error surfaced (instead of the misleading "already in use").
pub fn apply_replicated_mount(mut incoming: StorageMount) -> Result<StorageMount, String> {
    if incoming.id.is_empty() {
        incoming.id = generate_id(&incoming.name);
    }
    if incoming.mount_point.is_empty() {
        incoming.mount_point = format!("{}/{}", MOUNT_BASE, incoming.id);
    }
    if incoming.created_at.is_empty() {
        incoming.created_at = Utc::now().to_rfc3339();
    }

    let mut config = load_config();
    let mount_id = match replicated_mount_match(&config.mounts, &incoming) {
        Some(i) => {
            // Keep the stored id stable so mount_storage finds it and a later
            // re-sync keeps matching the same row. Preserve a live "mounted"
            // status (mount_storage re-checks the kernel anyway).
            let id = config.mounts[i].id.clone();
            incoming.id = id.clone();
            incoming.status = config.mounts[i].status.clone();
            config.mounts[i] = incoming;
            id
        }
        None => {
            incoming.status = "unmounted".to_string();
            let id = incoming.id.clone();
            config.mounts.push(incoming);
            id
        }
    };
    save_config(&config)?;

    // (Re-)attempt the mount. The config entry is already persisted, so even
    // if the mount fails the row survives in error state on this peer (and
    // shows in Storage Manager) and a later re-sync retries it.
    mount_storage(&mount_id)?;

    load_config().mounts.into_iter().find(|m| m.id == mount_id)
        .ok_or_else(|| "mount vanished after apply".to_string())
}

/// Remove a mount entry (unmount first if needed)
pub fn remove_mount(id: &str) -> Result<String, String> {
    let mut config = load_config();
    
    if let Some(mount) = config.mounts.iter().find(|m| m.id == id) {
        // Unmount if currently mounted
        if check_mounted(&mount.mount_point) {
            let _ = unmount_storage(id);
        }
    }
    
    // Reload after potential unmount
    config = load_config();
    let len_before = config.mounts.len();
    config.mounts.retain(|m| m.id != id);
    
    if config.mounts.len() == len_before {
        return Err(format!("Mount '{}' not found", id));
    }
    
    save_config(&config)?;
    Ok("Mount removed".to_string())
}

/// Duplicate a mount entry — clone with new ID and "(copy)" name
pub fn duplicate_mount(id: &str) -> Result<StorageMount, String> {
    let mut config = load_config();
    let original = config.mounts.iter().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?
        .clone();
    
    let new_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let mut dup = original.clone();
    dup.id = new_id.clone();
    dup.name = format!("{} (copy)", original.name);
    dup.mount_point = format!("{}/{}", MOUNT_BASE, new_id);
    dup.status = "unmounted".to_string();
    dup.error_message = None;
    dup.created_at = Utc::now().to_rfc3339();
    
    config.mounts.push(dup.clone());
    save_config(&config)?;
    Ok(dup)
}

/// Update a mount entry
pub fn update_mount(id: &str, updates: serde_json::Value) -> Result<StorageMount, String> {
    let mut config = load_config();
    let mount = config.mounts.iter_mut().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
    // Apply updates — basic fields
    if let Some(name) = updates.get("name").and_then(|v| v.as_str()) {
        mount.name = name.to_string();
    }
    if let Some(global) = updates.get("global").and_then(|v| v.as_bool()) {
        mount.global = global;
    }
    if let Some(auto_mount) = updates.get("auto_mount").and_then(|v| v.as_bool()) {
        mount.auto_mount = auto_mount;
    }
    if let Some(enabled) = updates.get("enabled").and_then(|v| v.as_bool()) {
        mount.enabled = enabled;
    }
    if let Some(mount_point) = updates.get("mount_point").and_then(|v| v.as_str()) {
        if !mount_point.is_empty() {
            mount.mount_point = mount_point.to_string();
        }
    }
    if let Some(source) = updates.get("source").and_then(|v| v.as_str()) {
        mount.source = source.to_string();
    }
    if let Some(nfs_opts) = updates.get("nfs_options").and_then(|v| v.as_str()) {
        mount.nfs_options = if nfs_opts.is_empty() { None } else { Some(nfs_opts.to_string()) };
    }
    if let Some(smb_opts) = updates.get("smb_options").and_then(|v| v.as_str()) {
        mount.smb_options = if smb_opts.is_empty() { None } else { Some(smb_opts.to_string()) };
    }
    if let Some(smb_updates) = updates.get("smb_config") {
        let smb = mount.smb_config.get_or_insert_with(|| SmbConfig {
            username: String::new(), password: String::new(), domain: String::new(),
        });
        if let Some(v) = smb_updates.get("username").and_then(|v| v.as_str()) {
            smb.username = v.to_string();
        }
        if let Some(v) = smb_updates.get("password").and_then(|v| v.as_str()) {
            // Matches S3 pattern — only overwrite when the UI actually sent a new value
            if v != REDACTED_SECRET {
                smb.password = v.to_string();
            }
        }
        if let Some(v) = smb_updates.get("domain").and_then(|v| v.as_str()) {
            smb.domain = v.to_string();
        }
    }
    
    // Apply S3 config updates
    if let Some(s3_updates) = updates.get("s3_config") {
        let s3 = mount.s3_config.get_or_insert_with(|| S3Config {
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: String::new(),
            endpoint: String::new(),
            provider: default_s3_provider(),
            bucket: String::new(),
        });
        if let Some(v) = s3_updates.get("bucket").and_then(|v| v.as_str()) {
            s3.bucket = v.to_string();
        }
        if let Some(v) = s3_updates.get("access_key_id").and_then(|v| v.as_str()) {
            s3.access_key_id = v.to_string();
        }
        if let Some(v) = s3_updates.get("secret_access_key").and_then(|v| v.as_str()) {
            // Only update if not the placeholder
            if v != REDACTED_SECRET {
                s3.secret_access_key = v.to_string();
            }
        }
        if let Some(v) = s3_updates.get("region").and_then(|v| v.as_str()) {
            s3.region = v.to_string();
        }
        if let Some(v) = s3_updates.get("endpoint").and_then(|v| v.as_str()) {
            s3.endpoint = v.to_string();
        }
        if let Some(v) = s3_updates.get("provider").and_then(|v| v.as_str()) {
            s3.provider = v.to_string();
        }
        // Update source to reflect bucket
        if !s3.bucket.is_empty() {
            mount.source = format!("s3:{}", s3.bucket);
        }
    }
    
    let result = mount.clone();
    save_config(&config)?;
    Ok(result)
}

// ─── Type-specific mount implementations ───

fn mount_s3(mount: &StorageMount) -> Result<String, String> {
    let s3 = mount.s3_config.as_ref()
        .ok_or("S3 config is required for S3 mounts")?;
    
    if s3.bucket.is_empty() {
        return Err("Bucket name is required for S3 mounts".to_string());
    }
    
    // Strategy (order matters — corrects a silent data-loss bug, Gary KO4BSR
    // 2026-06-17):
    //   1. s3fs-fuse — a REAL read-write FUSE mount. This is the only mode
    //      where writes actually reach the bucket, so it is the default
    //      everywhere FUSE is usable.
    //   2. rust-s3 bind — fallback ONLY when s3fs/FUSE is unavailable
    //      (e.g. ppc64le, FUSE-less containers). It is a one-shot download +
    //      local bind mount: reads work but writes land on the local disk and
    //      NEVER reach S3. mount_s3_via_rust_s3 now mounts it READ-ONLY so
    //      writes fail loudly instead of silently vanishing from the bucket.
    //
    // The old order tried rust-s3 FIRST; whenever its sync happened to succeed
    // (correct creds, <1000 objects, <30s) the operator got a read-only-in-
    // disguise mount and every file they wrote disappeared from the bucket's
    // view — exactly Gary's "files written but do not show in R2" report.
    if has_s3fs() {
        return mount_s3_via_s3fs(mount, s3);
    }

    // s3fs is missing. Where FUSE exists, installing it is the right answer
    // and the operator should be the one to approve it: hand the frontend the
    // MISSING_PACKAGE marker so it offers the same watch-it-happen terminal
    // install used for nfs-common/cifs-utils, instead of silently apt-getting
    // behind the operator's back or — worse — degrading to a bind mount whose
    // writes never reach the bucket.
    if Path::new("/dev/fuse").exists() {
        return Err(format!(
            "{}s3fs|{}|{}",
            MISSING_PACKAGE_MARKER, "s3fs", "s3fs-fuse"
        ));
    }

    // No FUSE device at all (a FUSE-less container, ppc64le): installing s3fs
    // would not help, so fall back to the read-only rust-s3 bind and say so.
    warn!("FUSE unavailable for {} — falling back to a READ-ONLY rust-s3 bind mount (writes not supported in this mode)", mount.mount_point);
    mount_s3_via_rust_s3(mount, s3)
}

/// True for a Cloudflare R2 S3 endpoint. R2 requires the SigV4 region
/// "auto"; without a correct region both rust-s3 and s3fs sign for
/// us-east-1, the request fails, and s3fs then falls back to SigV2 — which
/// R2 rejects outright ("SigV2 authorization is not supported. Please use
/// SigV4 instead.") (Gary KO4BSR, 2026-06-15).
fn is_r2_endpoint(endpoint: &str) -> bool {
    // Trim: the endpoint is stored verbatim from the UI field, so a
    // copy-pasted trailing space/newline must not defeat the match.
    endpoint.trim().contains("r2.cloudflarestorage.com")
}

/// Region to use for SigV4 signing: the operator's explicit value if set,
/// else "auto" for Cloudflare R2 (its required region), else empty — in
/// which case callers fall back to "us-east-1" (the AWS/MinIO/Wasabi
/// default). Only R2 behaviour changes; every other provider is untouched.
fn effective_s3_region(s3: &S3Config) -> String {
    let r = s3.region.trim();
    // Cloudflare R2's SigV4 region is ALWAYS "auto" for the standard
    // endpoint. Any other value (e.g. a stale "us-east-1" left on a mount
    // created before the v24.47.3 fix) makes R2 reject the signature, after
    // which s3fs falls back to SigV2 — which R2 forbids outright. Because a
    // *working* R2 mount can only ever carry "auto", forcing it here can
    // never break a working mount; it only repairs a broken one. This is
    // what the v24.47.3 blank→auto fallback missed: an EXISTING mount whose
    // stored region was non-blank never reached the fallback, so the upgrade
    // changed nothing (Gary KO4BSR: still failing on v24.48.0).
    if is_r2_endpoint(&s3.endpoint) {
        return "auto".to_string();
    }
    if !r.is_empty() {
        r.to_string()
    } else {
        String::new()
    }
}

/// Prefix a bare `host[:port]` endpoint with https://. The GUI field accepts
/// what the provider's dashboard prints (`l8k1.fra21.idrivee2-12.com`), which
/// is not a URL — s3fs and rust-s3 both need the scheme.
fn endpoint_url(endpoint: &str) -> String {
    let e = endpoint.trim();
    if e.starts_with("http://") || e.starts_with("https://") {
        e.to_string()
    } else {
        format!("https://{}", e)
    }
}

/// The rust-s3 `Region` for a config. Single definition so the mount path,
/// the sync-back path and the bucket lister can't drift apart on endpoint
/// scheme handling or on R2's mandatory "auto" region.
fn build_s3_region(s3: &S3Config) -> s3::region::Region {
    use s3::region::Region;
    if s3.endpoint.trim().is_empty() {
        return s3.region.parse::<Region>().unwrap_or(Region::UsEast1);
    }
    let region = effective_s3_region(s3);
    Region::Custom {
        region: if region.is_empty() { "us-east-1".to_string() } else { region },
        endpoint: endpoint_url(&s3.endpoint),
    }
}

/// True when `err` looks like an S3 authentication/signature failure — the
/// #1 cause of an otherwise-correct mount failing. S3, and especially R2,
/// surface these as cryptic SigV4/SigV2 messages that read like a
/// region/endpoint bug; they're almost always bad credentials. Gary KO4BSR
/// spent days on exactly this — a wrong secret_access_key in storage.json
/// (2026-06-16) — because the failure never said "check your credentials".
fn s3_credential_hint(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    [
        "sigv4", "sigv2", "signature version", "please use sigv4",
        "signaturedoesnotmatch", "signature does not match", "the request signature",
        "invalidaccesskeyid", "invalid access key",
        "accessdenied", "access denied", "forbidden",
        "missing field name", // R2's auth-error document deserializes to this
    ]
    .iter()
    .any(|m| e.contains(m))
}

/// Append a plain-language credentials hint to `err` when it matches
/// `s3_credential_hint`, otherwise return it unchanged.
fn with_s3_credential_hint(err: String) -> String {
    if s3_credential_hint(&err) {
        format!(
            "{} — this looks like an S3 credentials problem: re-check the Access Key and Secret Key for this mount and re-enter the Secret in the GUI (a wrong or truncated secret is the usual cause; for Cloudflare R2 leave the Region blank).",
            err
        )
    } else {
        err
    }
}

/// Mount S3 using s3fs-fuse — fast, native, handles offline endpoints gracefully
fn mount_s3_via_s3fs(mount: &StorageMount, s3: &S3Config) -> Result<String, String> {
    // Write credentials file: access_key:secret_key
    let creds_dir = crate::paths::get().s3_credentials_dir;
    fs::create_dir_all(&creds_dir)
        .map_err(|e| format!("Failed to create credentials dir: {}", e))?;
    
    let creds_path = format!("{}/{}.passwd", creds_dir, mount.id);
    // write_secure opens with O_CREAT|mode=0600 AND explicitly re-chmods
    // after write — no TOCTOU window where credentials exist on disk
    // at 0644. Pre-v18.7.30 this used fs::write+Command("chmod") which
    // left a ~milliseconds window of world-readable creds on disk.
    crate::paths::write_secure(&creds_path,
        format!("{}:{}", s3.access_key_id, s3.secret_access_key))
        .map_err(|e| format!("Failed to write credentials: {}", e))?;
    
    // s3fs daemonises, so its real failure reason (bad credentials, wrong
    // endpoint, NoSuchBucket) is written by the DAEMON, not by the process we
    // wait on — it goes to syslog, where nothing on a default Debian host
    // collects it. Confirmed on wolfstack-2 (2026-07-29): a failed mount left
    // no trace in the journal at all, so the operator was told only "it did
    // not come up". `-o logfile=` (s3fs ≥1.85) redirects that output to a file
    // we own, and `dbglevel=err` keeps the [CRT]/[ERR] lines — including the
    // provider's own error XML — without the flood of [INF] request tracing.
    // Truncated per mount attempt, so the file only ever holds the current
    // attempt's errors and cannot grow without bound.
    let log_path = s3fs_log_path(&mount.id);
    ensure_s3fs_log_dir(&log_path);
    let _ = fs::remove_file(&log_path);

    // s3fs's local file cache. Uses the configured cache dir rather than
    // /tmp: /tmp is tmpfs (RAM) on a normal systemd host, and a cache of a
    // multi-TB bucket landing there is the same failure that filled
    // wolfstack-1's RAM from backup staging (v25.5.1).
    let cache_dir = format!("{}/{}", crate::paths::get().s3_cache_dir, mount.id);

    // Build s3fs arguments
    let mut args = vec![
        s3.bucket.clone(),
        mount.mount_point.clone(),
        "-o".to_string(), format!("passwd_file={}", creds_path),
        "-o".to_string(), "allow_other".to_string(),
        "-o".to_string(), "mp_umask=022".to_string(),
        "-o".to_string(), format!("use_cache={}", cache_dir),
        "-o".to_string(), "ensure_diskfree=1024".to_string(),  // keep 1GB free
        "-o".to_string(), "connect_timeout=10".to_string(),
        "-o".to_string(), "retries=3".to_string(),
        "-o".to_string(), format!("logfile={}", log_path),
        "-o".to_string(), "dbglevel=err".to_string(),
    ];

    // Custom endpoint for non-AWS providers (R2, MinIO, Wasabi, IDrive e2…)
    if !s3.endpoint.is_empty() {
        args.push("-o".to_string());
        args.push(format!("url={}", endpoint_url(&s3.endpoint)));
        args.push("-o".to_string());
        args.push("use_path_request_style".to_string());
    }

    // Region for SigV4 signing (s3fs's `-o endpoint=` is the legacy alias
    // for `-o region=`). R2 needs "auto" — without a usable region s3fs
    // signs for us-east-1, the request fails, and it falls back to SigV2
    // which R2 rejects. Empty → omit (s3fs defaults to us-east-1, correct
    // for AWS/MinIO/Wasabi). See effective_s3_region.
    let region = effective_s3_region(s3);
    if !region.is_empty() {
        args.push("-o".to_string());
        args.push(format!("endpoint={}", region));
    }
    
    let output = Command::new("s3fs")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run s3fs: {}", e))?;
    
    if output.status.success() {
        // Verify mount — s3fs launches as daemon, may take a moment
        for attempt in 0..4 {
            std::thread::sleep(std::time::Duration::from_millis(500 * (attempt + 1)));
            if check_mounted(&mount.mount_point) {
                return Ok("S3 storage mounted via s3fs".to_string());
            }
        }
        // s3fs forks a daemon, so the parent exiting 0 does NOT mean the
        // mount succeeded: the daemon can fail its startup bucket check (bad
        // credentials, wrong endpoint) and exit, logging the real error to
        // syslog — NOT to the stderr we captured. If the mountpoint never
        // appeared, that's a failure, not "still initializing" — the old
        // false-Ok is exactly why Gary KO4BSR's wrong-secret R2 mount
        // reported success but never mounted (2026-06-16). A genuinely-slow
        // mount that appears later self-corrects on the next status refresh.
        warn!("s3fs started but the mount never came up for {}", mount.mount_point);
        match read_s3fs_error(&log_path) {
            Some(detail) => Err(with_s3_credential_hint(format!(
                "s3fs failed to mount: {}", detail
            ))),
            // No daemon log either — s3fs older than 1.85 has no `logfile`
            // option and ignores it, so keep the guidance that got operators
            // to the answer before the log existed.
            None => Err(format!(
                "s3fs started but the mount never came up, and it wrote no error to {}. \
                 The s3fs daemon most likely failed its startup bucket check — check the \
                 bucket name, endpoint and credentials (for Cloudflare R2 leave the Region blank).",
                log_path
            )),
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let detail = match read_s3fs_error(&log_path) {
            Some(logged) if stderr.trim().is_empty() => logged,
            Some(logged) => format!("{} ({})", stderr.trim(), logged),
            None => stderr.trim().to_string(),
        };
        Err(with_s3_credential_hint(format!("s3fs mount failed: {}", detail)))
    }
}

/// Where the s3fs daemon for a mount writes its errors. Same directory
/// setup.sh already uses for the install manifests.
fn s3fs_log_path(mount_id: &str) -> String {
    format!("/var/log/wolfstack/s3fs-{}.log", mount_id)
}

/// Create the log directory if setup.sh hasn't (a source build, a container
/// image), restricted to root: an s3fs error log quotes the provider's own
/// response, which can name buckets and keys.
fn ensure_s3fs_log_dir(log_path: &str) {
    let Some(parent) = Path::new(log_path).parent() else { return };
    if parent.exists() {
        return;
    }
    if fs::create_dir_all(parent).is_ok() {
        #[cfg(unix)]
        let _ = fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o750));
    }
}

/// Pull the operator-meaningful failure out of an s3fs daemon log.
///
/// Lines look like:
///   `2026-07-29T11:55:19.875Z [CRT] s3fs.cpp:s3fs_check_service(4498): Failed to
///    check bucket and directory for mount point : Bucket or directory not
///    found(host=https://…, message=The specified bucket does not exist)`
/// and the preceding `[ERR]` line carries the provider's raw error document.
/// Both matter, so keep the [CRT]/[ERR] lines and strip the timestamp,
/// severity and C++ source location — none of which help the operator.
fn read_s3fs_error(log_path: &str) -> Option<String> {
    let content = fs::read_to_string(log_path).ok()?;
    let mut messages: Vec<String> = Vec::new();

    for line in content.lines() {
        if !line.contains("[CRT]") && !line.contains("[ERR]") {
            continue;
        }
        // Everything after the `file.cpp:func(line): ` prefix is the message.
        // Falling back to the whole line keeps unexpected formats readable
        // rather than dropping the only diagnostic we have.
        let msg = match line.find("): ") {
            Some(pos) => line[pos + 3..].trim(),
            None => line.trim(),
        };
        // s3fs logs its own log-level change as [CRT] on every start — pure
        // noise, and reporting it as the failure would be actively wrong.
        if msg.is_empty() || msg.contains("change debug level") {
            continue;
        }
        let msg = msg.replace('\n', " ");
        if !messages.contains(&msg) {
            messages.push(msg);
        }
    }

    if messages.is_empty() {
        return None;
    }
    // Cap the length: an error document can be a full XML blob and this
    // string ends up in a toast/modal.
    let mut joined = messages.join(" | ");
    if joined.chars().count() > 600 {
        joined = joined.chars().take(600).collect::<String>() + "…";
    }
    Some(joined)
}

/// Mount S3 using rust-s3 — pure Rust, native, works on IBM Power/ppc64le
/// Syncs bucket contents to a local cache directory and bind-mounts it
fn mount_s3_via_rust_s3(mount: &StorageMount, s3: &S3Config) -> Result<String, String> {
    use s3::bucket::Bucket;
    use s3::creds::Credentials;

    // Build credentials
    let credentials = Credentials::new(
        Some(&s3.access_key_id),
        Some(&s3.secret_access_key),
        None, None, None,
    ).map_err(|e| format!("Invalid S3 credentials: {}", e))?;

    let region = build_s3_region(s3);

    // Create bucket handle
    let bucket = Bucket::new(&s3.bucket, region, credentials)
        .map_err(|e| format!("Failed to create S3 bucket handle: {}", e))?
        .with_path_style();

    // Create local cache directory for this mount
    let cache_dir = format!("/var/cache/wolfstack/s3/{}", mount.id);
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create S3 cache dir: {}", e))?;

    // Use tokio runtime to sync bucket contents
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;

    let sync_result = rt.block_on(async {
        // Wrap the entire S3 operation in a timeout
        let timeout_duration = std::time::Duration::from_secs(30);
        match tokio::time::timeout(timeout_duration, async {
            // List objects in bucket (top-level, first 1000)
            let list = bucket.list("".to_string(), None).await
                .map_err(|e| format!("Failed to list S3 bucket '{}': {}", s3.bucket, e))?;

            let mut synced = 0usize;
            for item in &list {
                for obj in &item.contents {
                    let key = &obj.key;
                    // Skip directory markers
                    if key.ends_with('/') {
                        let dir_path = format!("{}/{}", cache_dir, key);
                        fs::create_dir_all(&dir_path).ok();
                        continue;
                    }

                    let local_path = format!("{}/{}", cache_dir, key);

                    // Create parent directories
                    if let Some(parent) = Path::new(&local_path).parent() {
                        fs::create_dir_all(parent).ok();
                    }

                    // Check if local file exists and matches size
                    let needs_download = match fs::metadata(&local_path) {
                        Ok(meta) => meta.len() != obj.size,
                        Err(_) => true,
                    };

                    if needs_download {
                        match bucket.get_object(key).await {
                            Ok(response) => {
                                if let Err(e) = fs::write(&local_path, response.bytes()) {
                                    error!("Failed to write {}: {}", local_path, e);
                                } else {
                                    synced += 1;
                                }
                            }
                            Err(e) => {
                                error!("Failed to download s3://{}/{}: {}", s3.bucket, key, e);
                            }
                        }
                    }
                }
            }

            Ok::<usize, String>(synced)
        }).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "S3 connection timed out after 30s — check endpoint '{}', credentials, and bucket '{}'",
                s3.endpoint, s3.bucket
            )),
        }
    })?;

    // Bind-mount the cache directory to the mount point
    fs::create_dir_all(&mount.mount_point)
        .map_err(|e| format!("Failed to create mount point: {}", e))?;

    let output = Command::new("mount")
        .args(["--bind", &cache_dir, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to bind mount: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Bind mount failed after S3 sync: {}", stderr));
    }

    // CRITICAL: this bind exposes a LOCAL cache directory. Anything written
    // here lands on the local disk and is NEVER uploaded back to S3 (rust-s3
    // here is a one-shot downloader, not a live filesystem). Re-mount the bind
    // read-only so writes fail loudly at the kernel instead of silently
    // disappearing from the bucket — the silent-loss trap Gary KO4BSR hit
    // (2026-06-17). `remount,bind,ro` is the canonical mount(8) form for making
    // a bind read-only.
    let ro = Command::new("mount")
        .args(["-o", "remount,bind,ro", &mount.mount_point])
        .output();
    let ro_ok = matches!(&ro, Ok(o) if o.status.success());
    if !ro_ok {
        // We could not guarantee read-only, so a WRITABLE local bind is now
        // exposed — exactly the silent-data-loss mount we're trying to avoid.
        // Fail safe: tear it down and error rather than hand back a mount that
        // looks like S3 but quietly swallows every write. No-FUSE host without
        // a working read-only bind simply can't have a safe S3 mount.
        let stderr = ro.as_ref().ok().map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string()).unwrap_or_default();
        error!("rust-s3 bind for {} could not be made read-only ({}) — unmounting to avoid silent write loss", mount.mount_point, stderr);
        let _ = Command::new("umount").arg(&mount.mount_point).output();
        let _ = Command::new("umount").args(["-l", &mount.mount_point]).output();
        return Err(format!(
            "Could not establish a safe S3 mount: s3fs-fuse is unavailable and the \
             read-only fallback bind could not be enforced ({}). Install s3fs-fuse \
             for read-write S3 access.",
            stderr
        ));
    }

    Ok(format!(
        "S3 storage mounted READ-ONLY via rust-s3 ({} objects synced). \
         s3fs-fuse is not available on this host, so read-write S3 mounting is \
         disabled — install s3fs-fuse for full read-write access.",
        sync_result,
    ))
}

/// Sentinel prefix for mount-helper-missing errors. The storage/backup API
/// endpoints parse this out so the UI can offer a "install now" prompt
/// rather than just printing a cryptic mount(8) failure to the user.
/// Format: `MISSING_PACKAGE|<binary>|<debian_pkg>|<redhat_pkg>`
pub const MISSING_PACKAGE_MARKER: &str = "MISSING_PACKAGE|";

/// Return the distro-specific package manager / package name for a given
/// mount helper binary. Used by the API to build the install command for
/// the live-terminal install flow.
pub fn package_for_helper(binary: &str) -> Option<(&'static str, &'static str)> {
    use crate::installer::DistroFamily;
    let distro = crate::installer::detect_distro();
    // Package names differ per distro; SUSE in particular calls the NFS
    // client package `nfs-client` rather than `nfs-utils`. Spell it out
    // rather than share a single "redhat_pkg" for all three RPM-ish families.
    match (binary, &distro) {
        ("mount.nfs", DistroFamily::Debian)  => Some(("apt-get", "nfs-common")),
        ("mount.nfs", DistroFamily::RedHat)  => Some(("dnf",     "nfs-utils")),
        ("mount.nfs", DistroFamily::Suse)    => Some(("zypper",  "nfs-client")),
        ("mount.nfs", DistroFamily::Arch)    => Some(("pacman",  "nfs-utils")),
        ("mount.nfs", DistroFamily::Alpine)  => Some(("apk",     "nfs-utils")),
        ("mount.nfs", DistroFamily::Unknown) => Some(("apt-get", "nfs-common")),

        ("mount.cifs", DistroFamily::Debian)  => Some(("apt-get", "cifs-utils")),
        ("mount.cifs", DistroFamily::RedHat)  => Some(("dnf",     "cifs-utils")),
        ("mount.cifs", DistroFamily::Suse)    => Some(("zypper",  "cifs-utils")),
        ("mount.cifs", DistroFamily::Arch)    => Some(("pacman",  "cifs-utils")),
        ("mount.cifs", DistroFamily::Alpine)  => Some(("apk",     "cifs-utils")),
        ("mount.cifs", DistroFamily::Unknown) => Some(("apt-get", "cifs-utils")),

        ("sshfs", DistroFamily::Debian)  => Some(("apt-get", "sshfs")),
        ("sshfs", DistroFamily::RedHat)  => Some(("dnf",     "fuse-sshfs")),
        ("sshfs", DistroFamily::Suse)    => Some(("zypper",  "sshfs")),
        ("sshfs", DistroFamily::Arch)    => Some(("pacman",  "sshfs")),
        ("sshfs", DistroFamily::Alpine)  => Some(("apk",     "sshfs")),
        ("sshfs", DistroFamily::Unknown) => Some(("apt-get", "sshfs")),

        // s3fs-fuse. Debian/Ubuntu call the package `s3fs`; the RPM and Arch
        // families call it `s3fs-fuse`. On RHEL-likes it lives in EPEL, which
        // prepare_install_package enables as part of the install command.
        ("s3fs", DistroFamily::Debian)  => Some(("apt-get", "s3fs")),
        ("s3fs", DistroFamily::RedHat)  => Some(("dnf",     "s3fs-fuse")),
        ("s3fs", DistroFamily::Suse)    => Some(("zypper",  "s3fs")),
        ("s3fs", DistroFamily::Arch)    => Some(("pacman",  "s3fs-fuse")),
        ("s3fs", DistroFamily::Alpine)  => Some(("apk",     "s3fs-fuse")),
        ("s3fs", DistroFamily::Unknown) => Some(("apt-get", "s3fs")),

        _ => None,
    }
}

fn check_mount_helper(binary: &str, debian_pkg: &str, redhat_pkg: &str) -> Result<(), String> {
    if Path::new(&format!("/sbin/{}", binary)).exists()
        || Path::new(&format!("/usr/sbin/{}", binary)).exists()
    {
        return Ok(());
    }
    Err(format!(
        "{}{}|{}|{}",
        MISSING_PACKAGE_MARKER, binary, debian_pkg, redhat_pkg
    ))
}

fn mount_nfs(mount: &StorageMount) -> Result<String, String> {
    // Prerequisite: mount.nfs must exist. If not, hand control back to the
    // frontend so it can put up a confirm dialog and run the install in a
    // live terminal — we deliberately do NOT silently apt-get here.
    check_mount_helper("mount.nfs", "nfs-common", "nfs-utils")?;
    
    let options = mount.nfs_options.as_deref().unwrap_or("rw,soft,timeo=50");
    
    let output = Command::new("mount")
        .args(["-t", "nfs", "-o", options, &mount.source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    
    if output.status.success() {
        Ok("NFS storage mounted".to_string())
    } else {
        Err(format!("NFS mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn mount_smb(mount: &StorageMount) -> Result<String, String> {
    // Prerequisite: mount.cifs. Same policy as mount_nfs — surface a
    // machine-readable "missing package" error the frontend can turn into
    // a confirm-and-run-in-terminal prompt.
    check_mount_helper("mount.cifs", "cifs-utils", "cifs-utils")?;

    // Normalise the source — users are likely to type the Windows-style
    // `\\server\share` from Synology/QNAP admin UIs. CIFS wants `//server/share`.
    let source = mount.source.replace('\\', "/");
    let source = if source.starts_with("//") { source } else { format!("//{}", source.trim_start_matches('/')) };

    // Build the credentials half of the -o string. Falls back to guest
    // mount if no username is configured (common on open Synology shares).
    let cfg = mount.smb_config.as_ref();
    let mut opt_parts: Vec<String> = Vec::new();
    match cfg {
        Some(c) if !c.username.is_empty() => {
            opt_parts.push(format!("username={}", c.username));
            opt_parts.push(format!("password={}", c.password));
            if !c.domain.is_empty() {
                opt_parts.push(format!("domain={}", c.domain));
            }
        }
        _ => {
            opt_parts.push("guest".to_string());
        }
    }
    // Friendly defaults — uid/gid=0 so root owns the mount, file/dir perms
    // let WolfStack and operators read/write, vers=3.0 matches Synology and
    // modern QNAP defaults. User-supplied smb_options are appended verbatim
    // and override (later values win in CIFS option parsing).
    opt_parts.push("uid=0".to_string());
    opt_parts.push("gid=0".to_string());
    opt_parts.push("file_mode=0660".to_string());
    opt_parts.push("dir_mode=0770".to_string());
    opt_parts.push("vers=3.0".to_string());
    if let Some(extra) = mount.smb_options.as_deref().filter(|s| !s.is_empty()) {
        opt_parts.push(extra.to_string());
    }
    let options = opt_parts.join(",");

    let output = Command::new("mount")
        .args(["-t", "cifs", "-o", &options, &source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;

    if output.status.success() {
        Ok("SMB storage mounted".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let used_guest = !matches!(cfg, Some(c) if !c.username.is_empty());
        Err(format!(
            "SMB mount failed: {}{}",
            stderr.trim(),
            explain_cifs_failure(&stderr, &source, used_guest),
        ))
    }
}

/// Turn mount.cifs's errno into something an operator can act on.
///
/// The raw text is always kept — this only appends. `mount error(2): No
/// such file or directory` is the motivating case: it names neither
/// WHICH thing was not found (the share? the mount point? a
/// subdirectory?) nor the fact that we may have connected anonymously,
/// so it reads as "the path is wrong" when the server is actually
/// saying "I have no share by that name, at least not for you"
/// (klasSponsor 2026-07-29, mounting //10.10.10.20/paperless).
fn explain_cifs_failure(stderr: &str, source: &str, used_guest: bool) -> String {
    let guest_note = if used_guest {
        " This mount connected as guest because no username was set — a share \
         that requires credentials answers exactly this way."
    } else {
        ""
    };
    // Match on the errno mount.cifs prints, not on message wording,
    // which varies between cifs-utils versions.
    if stderr.contains("mount error(2)") {
        format!(
            "\n\nThe server answered that it has no share matching '{}'. The mount point \
             exists (WolfStack creates it), so this is the server refusing the share name.{}\
             \n\nCheck: is it a share, or a folder INSIDE one? A NAS app folder is usually \
             the latter — mount the parent share instead. Share names are also case-sensitive \
             on many servers. `smbclient -L {} -U <user>` lists what the server actually \
             publishes.",
            source, guest_note,
            source.trim_start_matches('/').split('/').next().unwrap_or(""),
        )
    } else if stderr.contains("mount error(13)") {
        format!(
            "\n\nThe server rejected the credentials for '{}'.{}",
            source,
            if used_guest {
                " No username was set, so this was an anonymous attempt — add credentials."
            } else {
                " Check the username, password and domain."
            },
        )
    } else if stderr.contains("mount error(112)") || stderr.contains("mount error(115)") {
        format!("\n\nCould not reach the server for '{}' — check it is up and port 445 is open.", source)
    } else if stderr.contains("mount error(95)") {
        // vers=3.0 is our default; very old NAS boxes need vers=1.0/2.0.
        format!(
            "\n\nThe server refused the SMB protocol version. WolfStack defaults to vers=3.0; \
             for an older NAS add `vers=2.0` (or `vers=1.0`) to the mount options for '{}'.",
            source,
        )
    } else {
        String::new()
    }
}

fn mount_directory(mount: &StorageMount) -> Result<String, String> {
    if !Path::new(&mount.source).exists() {
        return Err(format!("Source directory '{}' does not exist", mount.source));
    }
    
    let output = Command::new("mount")
        .args(["--bind", &mount.source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    
    if output.status.success() {
        Ok("Directory bind-mounted".to_string())
    } else {
        Err(format!("Bind mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

/// Mount a local block device (whole disk or partition) at a directory.
/// `source` is either a `/dev/…` path or a `UUID=…` / `LABEL=…` spec — UUID is
/// preferred because /dev names can shuffle across reboots while WolfStack's
/// auto_mount re-runs this on boot. The kernel auto-detects the filesystem, so
/// ext4/xfs/btrfs/etc. all work without specifying a type.
fn mount_disk(mount: &StorageMount) -> Result<String, String> {
    let src = mount.source.trim();
    if src.is_empty() {
        return Err("No disk device specified".to_string());
    }

    // Validate the source resolves to a real block device before mounting, so a
    // typo can't hand the kernel something unexpected.
    let resolved = if let Some(uuid) = src.strip_prefix("UUID=") {
        Command::new("blkid").args(["-U", uuid]).output()
            .map(|o| o.status.success() && !o.stdout.is_empty()).unwrap_or(false)
    } else if let Some(label) = src.strip_prefix("LABEL=") {
        Command::new("blkid").args(["-L", label]).output()
            .map(|o| o.status.success() && !o.stdout.is_empty()).unwrap_or(false)
    } else if src.starts_with("/dev/") {
        // Require an actual filesystem on the device (FSTYPE non-empty), not just
        // that the node exists — otherwise mounting an unformatted disk fails with
        // an opaque kernel error. -d = the device itself, not its children.
        Command::new("lsblk").args(["-dno", "FSTYPE", src]).output()
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false)
    } else {
        return Err(format!(
            "Disk source must be a /dev path or UUID=…/LABEL=… (got '{}')", src));
    };
    if !resolved {
        return Err(format!(
            "'{}' is not a block device with a filesystem (format it first)", src));
    }

    // Optional mount options (e.g. "noatime,ro") travel in nfs_options — it's the
    // existing free-form options field on the struct; reusing it avoids a schema
    // change and it's only ever read per mount-type. Reject bind/move semantics:
    // is_unsafe_mount_target guards the TARGET, but a bind/move option would change
    // what gets attached there, side-stepping the intent of "mount a block device".
    let mut args: Vec<String> = Vec::new();
    if let Some(opts) = mount.nfs_options.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let lc = opts.to_lowercase();
        if lc.split(|c| c == ',' || c == ' ').any(|o| matches!(o, "bind" | "rbind" | "move")) {
            return Err("bind/rbind/move are not valid options for a disk mount".to_string());
        }
        args.push("-o".to_string());
        args.push(opts.to_string());
    }
    args.push(src.to_string());
    args.push(mount.mount_point.clone());

    let output = Command::new("mount").args(&args).output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    if output.status.success() {
        Ok(format!("Disk {} mounted at {}", src, mount.mount_point))
    } else {
        Err(format!("Mount failed: {}", String::from_utf8_lossy(&output.stderr).trim()))
    }
}

fn mount_wolfdisk(mount: &StorageMount) -> Result<String, String> {
    // Check if wolfdisk binary exists (wolfdisk has mount, wolfdiskctl is monitoring only)
    if !has_wolfdisk() {
        return Err("WolfDisk is not installed. Install it first via Components.".to_string());
    }

    // --config is a top-level arg (before subcommand), --mountpoint is on the mount subcommand
    let mut args: Vec<&str> = Vec::new();
    if !mount.source.is_empty() {
        args.extend(["--config", &mount.source]);
    }
    args.extend(["mount", "--mountpoint", &mount.mount_point]);

    let output = Command::new("wolfdisk")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run wolfdisk: {}", e))?;

    if output.status.success() {
        Ok("WolfDisk storage mounted".to_string())
    } else {
        Err(format!("WolfDisk mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn mount_sshfs(mount: &StorageMount) -> Result<String, String> {
    // Ensure sshfs is installed
    if !has_sshfs() {

        install_sshfs().map_err(|e| format!("Failed to install sshfs: {}", e))?;
        if !has_sshfs() {
            return Err("sshfs is not installed and could not be auto-installed".to_string());
        }
    }

    if mount.source.is_empty() {
        return Err("SSHFS source is required (e.g. user@host:/remote/path)".to_string());
    }

    let mut args = vec![
        mount.source.clone(),
        mount.mount_point.clone(),
        "-o".to_string(), "allow_other".to_string(),
        "-o".to_string(), "reconnect".to_string(),
        "-o".to_string(), "ServerAliveInterval=15".to_string(),
        "-o".to_string(), "ServerAliveCountMax=3".to_string(),
        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
    ];

    // If nfs_options is set, treat it as the SSH key path
    if let Some(ref key_path) = mount.nfs_options {
        if !key_path.is_empty() {
            args.push("-o".to_string());
            args.push(format!("IdentityFile={}", key_path));
        }
    }

    let output = Command::new("sshfs")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run sshfs: {}", e))?;

    if output.status.success() {
        Ok("SSHFS storage mounted".to_string())
    } else {
        Err(format!("SSHFS mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── Helpers ───

fn has_s3fs() -> bool {
    Command::new("s3fs").arg("--version").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn has_sshfs() -> bool {
    Command::new("which").arg("sshfs").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn install_sshfs() -> Result<(), String> {

    let distro = crate::installer::detect_distro();
    let (pkg_mgr, pkg_name) = match distro {
        crate::installer::DistroFamily::Debian => ("apt-get", "sshfs"),
        crate::installer::DistroFamily::RedHat => ("dnf", "fuse-sshfs"),
        crate::installer::DistroFamily::Suse => ("zypper", "sshfs"),
        crate::installer::DistroFamily::Arch => ("pacman", "sshfs"),
        crate::installer::DistroFamily::Alpine => ("apk", "sshfs-fuse"),
        crate::installer::DistroFamily::Unknown => ("apt-get", "sshfs"),
    };
    let output = Command::new(pkg_mgr)
        .args(["install", "-y", pkg_name])
        .output()
        .map_err(|e| format!("Failed to install {}: {}", pkg_name, e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{} installation failed: {}", pkg_name, String::from_utf8_lossy(&output.stderr)))
    }
}

fn has_nfs() -> bool {
    Path::new("/sbin/mount.nfs").exists() || Path::new("/usr/sbin/mount.nfs").exists()
}

fn has_wolfdisk() -> bool {
    let has_binary = Path::new("/usr/local/bin/wolfdisk").exists()
        || Path::new("/opt/wolfdisk/wolfdisk").exists()
        || Command::new("which").arg("wolfdisk").output().map(|o| o.status.success()).unwrap_or(false);
    // Require both the binary AND the systemd service to consider it properly installed
    let has_service = Path::new("/etc/systemd/system/wolfdisk.service").exists()
        || Path::new("/usr/lib/systemd/system/wolfdisk.service").exists();
    has_binary && has_service
}

/// Read WolfDisk configuration and return a summary
fn read_wolfdisk_info() -> Option<WolfDiskInfo> {
    let content = std::fs::read_to_string("/etc/wolfdisk/config.toml").ok()?;
    let config: toml::Value = toml::from_str(&content).ok()?;

    let node = config.get("node")?;
    let cluster = config.get("cluster");
    let replication = config.get("replication");
    let mount = config.get("mount");
    let s3 = config.get("s3");

    let peers: Vec<String> = cluster
        .and_then(|c| c.get("peers"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    Some(WolfDiskInfo {
        cluster_name: cluster.and_then(|c| c.get("name")).and_then(|v| v.as_str()).unwrap_or("default").to_string(),
        node_id: node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        role: node.get("role").and_then(|v| v.as_str()).unwrap_or("auto").to_string(),
        replication_mode: replication.and_then(|r| r.get("mode")).and_then(|v| v.as_str()).unwrap_or("shared").to_string(),
        replication_factor: replication.and_then(|r| r.get("factor")).and_then(|v| v.as_integer()).unwrap_or(3) as usize,
        data_dir: node.get("data_dir").and_then(|v| v.as_str()).unwrap_or("/var/lib/wolfdisk").to_string(),
        mount_path: mount.and_then(|m| m.get("path")).and_then(|v| v.as_str()).unwrap_or("/mnt/wolfdisk").to_string(),
        bind: node.get("bind").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:8550").to_string(),
        peers,
        s3_enabled: s3.and_then(|s| s.get("enabled")).and_then(|v| v.as_bool()).unwrap_or(false),
        s3_bind: s3.and_then(|s| s.get("bind")).and_then(|v| v.as_str()).map(String::from),
    })
}

/// Read the WolfDisk daemon's live cluster status (`<data_dir>/cluster_status.json`,
/// rewritten every second by the daemon). Carries this node's role/state,
/// `index_version` (the replication sync marker — peers with the same version are
/// in sync), file_count/total_size, and each peer's `last_seen_secs_ago`. None if
/// WolfDisk isn't installed/configured or hasn't written a status file yet.
/// klasSponsor 2026-06: "a healthcheck that lets you know how in-sync the
/// different nodes are."
pub fn wolfdisk_cluster_status() -> Option<serde_json::Value> {
    // Resolve the data dir from config (defaults to /var/lib/wolfdisk), then read
    // the status file the daemon maintains there for wolfdiskctl.
    let data_dir = read_wolfdisk_info()
        .map(|i| i.data_dir)
        .unwrap_or_else(|| "/var/lib/wolfdisk".to_string());
    let status_path = Path::new(&data_dir).join("cluster_status.json");
    let content = std::fs::read_to_string(&status_path).ok()?;
    let mut status: serde_json::Value = serde_json::from_str(&content).ok()?;
    // Stamp staleness so the UI can tell "daemon stopped" from "all healthy":
    // the file is rewritten every 1s, so an updated_at more than a few seconds
    // old means the daemon isn't running even though the file exists.
    if let Some(updated) = status.get("updated_at").and_then(|v| v.as_u64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(updated);
        if let Some(obj) = status.as_object_mut() {
            obj.insert("status_age_secs".into(), serde_json::json!(now.saturating_sub(updated)));
        }
    }
    Some(status)
}

/// A single lsblk column for a device (`-d` = device only, not children).
fn lsblk_field(device: &str, col: &str) -> String {
    Command::new("lsblk").args(["-dno", col, device]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// True if `device` or ANY of its partitions is in use — mounted OR claimed by a
/// subsystem that holds data without a mountpoint: an LVM physical volume (even
/// with no LV currently mounted), an mdraid member, a LUKS container (even closed),
/// or active swap. is_protected_device only catches *system* mountpoints; this is
/// the wipe-safety gate, so it must catch everything that would mean "this disk
/// already holds data" — otherwise dedicate-disk would silently destroy an LVM PV
/// or LUKS volume that has nothing mounted right now (code review 2026-06-25).
pub(crate) fn device_or_children_in_use(device: &str) -> Result<bool, String> {
    // Subsystems that hold data (or an active pool/array) WITHOUT a mountpoint — a
    // wipe would destroy them. ZFS/bcache/Ceph added after the paranoid disk review.
    const CLAIMED: &[&str] = &[
        "LVM2_member", "linux_raid_member", "crypto_LUKS", "swap",
        "zfs_member", "bcache", "ceph_bluestore",
    ];
    let output = Command::new("lsblk").args(["-Jno", "MOUNTPOINTS,FSTYPE", device]).output()
        .map_err(|e| format!("lsblk: {}", e))?;
    fn in_use(nodes: &[serde_json::Value]) -> bool {
        nodes.iter().any(|n| {
            let mounted = n.get("mountpoints").and_then(|m| m.as_array())
                .map(|a| a.iter().any(|m| m.as_str().map(|s| !s.is_empty()).unwrap_or(false)))
                .unwrap_or(false);
            let claimed = n.get("fstype").and_then(|f| f.as_str())
                .map(|f| CLAIMED.contains(&f)).unwrap_or(false);
            mounted || claimed
                || n.get("children").and_then(|c| c.as_array()).map(|c| in_use(c)).unwrap_or(false)
        })
    }
    let parsed: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .unwrap_or(serde_json::json!({}));
    Ok(parsed.get("blockdevices").and_then(|b| b.as_array()).map(|d| in_use(d)).unwrap_or(false))
}

/// Idempotently set an /etc/fstab line mounting `UUID=` at `mountpoint`. Boot-time
/// fstab mounts are ordered before services (local-fs.target), so the data disk is
/// present before wolfdisk.service starts. `nofail` keeps a missing disk from
/// wedging boot. Any prior line for the same mountpoint is replaced.
fn ensure_fstab_entry(uuid: &str, mountpoint: &str, fstype: &str) -> Result<(), String> {
    let existing = fs::read_to_string("/etc/fstab").unwrap_or_default();
    let mut lines: Vec<String> = existing.lines()
        .filter(|l| {
            let t = l.trim();
            t.is_empty() || t.starts_with('#') || t.split_whitespace().nth(1) != Some(mountpoint)
        })
        .map(|s| s.to_string())
        .collect();
    lines.push(format!("UUID={} {} {} defaults,nofail 0 2", uuid, mountpoint, fstype));
    let mut out = lines.join("\n");
    out.push('\n');
    fs::write("/etc/fstab", out).map_err(|e| format!("write /etc/fstab: {}", e))
}

/// Give WolfDisk its own disk (klasSponsor 2026-06): wipe `device` with a fresh
/// filesystem, migrate WolfDisk's existing data onto it, mount it at WolfDisk's
/// data_dir, persist via /etc/fstab (so it mounts at boot before wolfdisk.service),
/// and restart the daemon. DESTRUCTIVE — the caller MUST have confirmed the wipe.
/// A whole-disk filesystem (no partition table) keeps it simple and robust.
pub fn wolfdisk_dedicate_disk(device: &str, fstype: &str) -> Result<String, String> {
    let info = read_wolfdisk_info()
        .ok_or("WolfDisk is not installed/configured on this node")?;
    let data_dir = info.data_dir.clone();
    if data_dir.is_empty() || data_dir == "/" || is_unsafe_mount_target(&data_dir) {
        return Err(format!("WolfDisk data_dir '{}' is unset or unsafe", data_dir));
    }

    // Restrict to data-appropriate filesystems and map their whole-device force flag.
    let force_flag = match fstype {
        "ext4" | "ext3" | "ext2" => "-F",
        "xfs" | "btrfs" | "f2fs" => "-f",
        _ => return Err(format!("Use ext4, xfs or btrfs for a WolfDisk data disk (got '{}')", fstype)),
    };

    validate_device(device)?;
    if lsblk_field(device, "TYPE") != "disk" {
        return Err(format!("{} is not a whole disk — pick an unused disk to dedicate", device));
    }
    if device_or_children_in_use(device)? {
        return Err(format!(
            "{} is in use (mounted, or an LVM/RAID/LUKS/swap member) — pick a truly unused disk", device));
    }
    if is_protected_device(device)? {
        return Err(format!("{} carries a system mount — refusing", device));
    }
    // Never let the migration temp path collide with the data_dir itself.
    let tmp = "/mnt/.wolfdisk-dedicate";
    if data_dir.trim_end_matches('/') == tmp {
        return Err("WolfDisk data_dir collides with the migration temp path".into());
    }

    // Quiesce WolfDisk while we move its data_dir.
    let _ = Command::new("systemctl").args(["stop", "wolfdisk"]).output();
    let restart = || { let _ = Command::new("systemctl").args(["start", "wolfdisk"]).output(); };

    // Wipe stale signatures, then lay a fresh whole-disk filesystem.
    let _ = Command::new("wipefs").args(["-a", device]).output();
    let mkfs = format!("mkfs.{}", fstype);
    match Command::new(&mkfs).args([force_flag, device]).output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => { restart(); return Err(format!("Format failed: {}", String::from_utf8_lossy(&o.stderr).trim())); }
        Err(e) => { restart(); return Err(format!("{} not available: {}", mkfs, e)); }
    }

    let uuid = lsblk_field(device, "UUID");
    if uuid.is_empty() {
        restart();
        return Err("Could not read the new filesystem UUID after formatting".into());
    }

    // Migrate any existing WolfDisk data onto the new disk: mount it at a temp
    // path, copy the data_dir contents in (cp -a preserves perms/symlinks), unmount.
    let data_path = Path::new(&data_dir);
    let had_data = data_path.exists()
        && fs::read_dir(data_path).map(|mut d| d.next().is_some()).unwrap_or(false);
    if had_data {
        let _ = fs::create_dir_all(tmp);
        match Command::new("mount").args([device, tmp]).output() {
            Ok(o) if o.status.success() => {}
            other => {
                restart();
                let err = other.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_else(|e| e.to_string());
                return Err(format!("Could not mount new disk to migrate data: {}", err));
            }
        }
        let cp = Command::new("cp").args(["-a", &format!("{}/.", data_dir), tmp]).output();
        let _ = Command::new("umount").arg(tmp).output();
        let _ = fs::remove_dir(tmp);
        match cp {
            Ok(o) if o.status.success() => {}
            other => {
                restart();
                let err = other.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_else(|e| e.to_string());
                return Err(format!("Migrating existing data failed: {}", err));
            }
        }
    }

    // Mount the dedicated disk at data_dir (shadowing the old on-root copy, which
    // stays recoverable underneath), then persist it for boot.
    let _ = fs::create_dir_all(&data_dir);
    match Command::new("mount").args([device, &data_dir]).output() {
        Ok(o) if o.status.success() => {}
        other => {
            restart();
            let err = other.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_else(|e| e.to_string());
            return Err(format!("Mounting dedicated disk at {} failed: {}", data_dir, err));
        }
    }
    if let Err(e) = ensure_fstab_entry(&uuid, &data_dir, fstype) {
        // The disk IS mounted now, but without an fstab entry it won't remount on
        // boot and wolfdisk would write to the bare rootfs underneath. Restart so
        // the daemon runs on the disk for now, and tell the operator to fix fstab.
        let _ = Command::new("systemctl").args(["start", "wolfdisk"]).output();
        return Err(format!(
            "Disk mounted and data migrated, but writing /etc/fstab failed ({}). \
             Add a boot mount for {} manually or it won't persist across reboot.", e, data_dir));
    }

    // Make wolfdisk.service explicitly wait for the data_dir mount at boot rather
    // than relying solely on local-fs ordering (review 2026-06-25).
    let dropin_dir = "/etc/systemd/system/wolfdisk.service.d";
    let _ = fs::create_dir_all(dropin_dir);
    let _ = fs::write(
        format!("{}/dedicated-disk.conf", dropin_dir),
        format!("[Unit]\nRequiresMountsFor={}\n", data_dir),
    );
    let _ = Command::new("systemctl").arg("daemon-reload").output();

    let _ = Command::new("systemctl").args(["start", "wolfdisk"]).output();

    Ok(format!(
        "WolfDisk now stores its data on {} ({}) mounted at {}{}. It mounts on boot via /etc/fstab and WolfDisk has been restarted.",
        device, fstype, data_dir,
        if had_data { " — existing data migrated" } else { "" }
    ))
}

/// Sync local changes back to S3 bucket (called on unmount or periodic sync)
pub fn sync_to_s3(id: &str) -> Result<String, String> {
    use s3::bucket::Bucket;
    use s3::creds::Credentials;

    let config = load_config();
    let mount = config.mounts.iter().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;

    let s3 = mount.s3_config.as_ref()
        .ok_or("Not an S3 mount")?;

    let credentials = Credentials::new(
        Some(&s3.access_key_id),
        Some(&s3.secret_access_key),
        None, None, None,
    ).map_err(|e| format!("Invalid credentials: {}", e))?;

    // build_s3_region also supplies the https:// scheme a bare-hostname
    // endpoint needs — the local copy this replaced passed the endpoint
    // through verbatim, so a sync against `s3.example.com` (no scheme, the
    // form WolfStack's own placeholder invites) never reached the provider.
    let region = build_s3_region(s3);

    let bucket = Bucket::new(&s3.bucket, region, credentials)
        .map_err(|e| format!("Failed to create bucket handle: {}", e))?
        .with_path_style();

    let cache_dir = format!("/var/cache/wolfstack/s3/{}", mount.id);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;

    let uploaded = rt.block_on(async {
        let mut count = 0usize;
        sync_dir_to_s3(&bucket, &cache_dir, &cache_dir, &mut count).await?;
        Ok::<usize, String>(count)
    })?;

    Ok(format!("Synced {} files to S3", uploaded))
}

/// Recursively sync a local directory to S3
async fn sync_dir_to_s3(
    bucket: &s3::bucket::Bucket,
    base_dir: &str,
    current_dir: &str,
    count: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(current_dir)
        .map_err(|e| format!("Failed to read dir {}: {}", current_dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            Box::pin(sync_dir_to_s3(bucket, base_dir, path.to_str().unwrap_or(""), count)).await?;
        } else if path.is_file() {
            let key = path.strip_prefix(base_dir)
                .map_err(|e| format!("Path error: {}", e))?
                .to_str()
                .unwrap_or("")
                .to_string();

            if key.is_empty() { continue; }

            let content = fs::read(&path)
                .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

            bucket.put_object(&key, &content).await
                .map_err(|e| format!("Failed to upload {}: {}", key, e))?;

            *count += 1;
        }
    }

    Ok(())
}

// ─── S3 Remotes (saved credential sets) ─────────────────────────────────────
//
// A "remote" is one set of S3 credentials + endpoint + region, saved once and
// reused for every bucket on that account — exactly what rclone calls a remote.
// Before this existed the Add Mount dialog was the ONLY place S3 credentials
// could live, so an operator who had already configured their provider (in
// rclone.conf, or in the s3fs provider Settings editor) was still asked to
// retype the access key and secret for every single mount, with no way to see
// what was already configured (Paul, 2026-07-29 — IDrive e2 on wolfstack-2).
//
// Remotes come from three places, all merged by list_s3_remotes():
//   • WolfStack's own store (s3-remotes.json, 0600) — editable in the UI
//   • rclone config files on the host — read-only, so we never rewrite a file
//     the operator maintains with the rclone CLI
//   • existing S3 mounts — their credentials are already stored, so they can
//     be reused for a second bucket without retyping
//
// Secrets never leave the host: the API serves S3RemoteInfo (no secret) and
// the mount is created by REFERENCE (s3_remote = "<id>"), with the backend
// resolving the credentials server-side.

/// Rclone remote types that are S3-compatible enough for s3fs to mount.
/// `b2`/`gcs` are only usable via their S3-compatible endpoints, which is
/// why they still need an explicit `endpoint` in the config to work.
const S3_COMPATIBLE_RCLONE_TYPES: [&str; 4] = ["s3", "b2", "gcs", "r2"];

/// Rclone config files WolfStack reads remotes out of. Read-only: WolfStack
/// never writes these — an operator running `rclone config` owns them.
const RCLONE_CONFIG_PATHS: [&str; 3] = [
    "/root/.config/rclone/rclone.conf",
    "/root/.rclone.conf",
    "/etc/rclone.conf",
];

/// A saved set of S3 credentials, reusable across mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Remote {
    /// Stable identifier — `<origin-kind>:<name>`, e.g. `wolfstack:idrive-e2`.
    pub id: String,
    pub name: String,
    #[serde(default = "default_s3_provider")]
    pub provider: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    /// Human-readable source of this remote, shown in the picker so the
    /// operator knows whose credentials they're about to mount with.
    #[serde(default)]
    pub origin: String,
}

/// The API-facing view of a remote. Deliberately a SEPARATE struct rather
/// than `#[serde(skip)]` on S3Remote's secret: S3Remote is what gets
/// persisted, so a skip attribute there would silently drop the secret on
/// every save. Keeping the two apart makes it impossible to leak the secret
/// by adding a field in the wrong place later.
#[derive(Debug, Clone, Serialize)]
pub struct S3RemoteInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub endpoint: String,
    pub region: String,
    pub origin: String,
    /// Access key with the middle masked — enough to tell two accounts
    /// apart in the picker without printing the whole key into the DOM.
    pub access_key_hint: String,
    /// True when the remote lives in WolfStack's own store, i.e. the UI may
    /// edit or delete it. Remotes discovered in rclone.conf are read-only.
    pub editable: bool,
}

impl S3Remote {
    fn info(&self) -> S3RemoteInfo {
        S3RemoteInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            provider: self.provider.clone(),
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            origin: self.origin.clone(),
            access_key_hint: mask_access_key(&self.access_key_id),
            editable: self.id.starts_with("wolfstack:"),
        }
    }

    /// Credentials for a mount, with the bucket filled in by the caller.
    pub fn to_s3_config(&self, bucket: &str) -> S3Config {
        S3Config {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            region: self.region.clone(),
            endpoint: self.endpoint.clone(),
            provider: self.provider.clone(),
            bucket: bucket.to_string(),
        }
    }
}

/// `e2xP52VNa4XYAGPWpHTN` → `e2xP…pHTN`. Short keys are masked entirely
/// rather than revealing most of themselves.
fn mask_access_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() < 12 {
        return "•".repeat(chars.len());
    }
    format!(
        "{}…{}",
        chars[..4].iter().collect::<String>(),
        chars[chars.len() - 4..].iter().collect::<String>()
    )
}

fn remotes_path() -> String {
    let storage = config_path();
    let dir = Path::new(&storage).parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/etc/wolfstack".to_string());
    format!("{}/s3-remotes.json", dir)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct S3RemoteStore {
    #[serde(default)]
    remotes: Vec<S3Remote>,
}

fn load_remote_store() -> S3RemoteStore {
    match fs::read_to_string(remotes_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            error!("Failed to parse {}: {}", remotes_path(), e);
            S3RemoteStore::default()
        }),
        Err(_) => S3RemoteStore::default(),
    }
}

fn save_remote_store(store: &S3RemoteStore) -> Result<(), String> {
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Failed to serialize S3 remotes: {}", e))?;
    // write_secure, not fs::write — this file holds secret access keys, and
    // 0600 must hold from the moment the file is created.
    crate::paths::write_secure(&remotes_path(), json)
        .map_err(|e| format!("Failed to write {}: {}", remotes_path(), e))
}

/// Parse INI/rclone-style `[section]` + `key = value` text into sections.
/// Shared by the rclone importer and the "did the operator paste an
/// rclone.conf into the s3fs credentials editor?" detector, so the two can
/// never disagree about what counts as a valid section.
fn parse_ini_sections(text: &str) -> Vec<(String, std::collections::HashMap<String, String>)> {
    let mut sections: Vec<(String, std::collections::HashMap<String, String>)> = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let name = trimmed[1..trimmed.len() - 1].trim().to_string();
            if !name.is_empty() {
                sections.push((name, std::collections::HashMap::new()));
            }
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            // A key before the first [section] header belongs to nothing —
            // drop it rather than attaching it to whatever section comes next.
            let Some((_, props)) = sections.last_mut() else { continue };
            let key = trimmed[..eq].trim().to_ascii_lowercase();
            let value = trimmed[eq + 1..].trim().to_string();
            props.insert(key, value);
        }
    }
    sections
}

/// Turn one parsed INI section into a remote, if it is an S3-compatible one.
/// `origin` describes where it came from and `id_prefix` namespaces the id so
/// two files can both define a `[backups]` remote without colliding.
fn section_to_remote(
    id_prefix: &str,
    origin: &str,
    name: &str,
    props: &std::collections::HashMap<String, String>,
) -> Option<S3Remote> {
    let rtype = props.get("type").map(|s| s.as_str()).unwrap_or("");
    if !S3_COMPATIBLE_RCLONE_TYPES.contains(&rtype) {
        return None;
    }
    let access_key_id = props.get("access_key_id").cloned().unwrap_or_default();
    let secret_access_key = props.get("secret_access_key").cloned().unwrap_or_default();
    // A remote with no credentials cannot mount anything. env_auth remotes
    // (rclone reading AWS_* from the environment) land here too — s3fs has no
    // equivalent, so offering them in the picker would only produce a mount
    // that fails its bucket check.
    if access_key_id.is_empty() || secret_access_key.is_empty() {
        return None;
    }
    Some(S3Remote {
        id: format!("{}:{}", id_prefix, name),
        name: name.to_string(),
        provider: props.get("provider").cloned().unwrap_or_else(default_s3_provider),
        endpoint: props.get("endpoint").cloned().unwrap_or_default(),
        region: props.get("region").cloned().unwrap_or_default(),
        access_key_id,
        secret_access_key,
        origin: origin.to_string(),
    })
}

/// Extract every S3-compatible remote from rclone.conf-formatted text.
pub fn parse_rclone_remotes(conf: &str, id_prefix: &str, origin: &str) -> Vec<S3Remote> {
    parse_ini_sections(conf)
        .iter()
        .filter_map(|(name, props)| section_to_remote(id_prefix, origin, name, props))
        .collect()
}

/// Every S3 remote WolfStack can mount with, from all three sources.
/// Earlier sources win on id collision; ids are namespaced per source so a
/// collision only happens between two entries that really are the same remote.
pub fn list_s3_remotes() -> Vec<S3Remote> {
    let mut remotes: Vec<S3Remote> = load_remote_store().remotes;

    for path in RCLONE_CONFIG_PATHS {
        if let Ok(content) = fs::read_to_string(path) {
            remotes.extend(parse_rclone_remotes(&content, "rclone", path));
        }
    }

    // The s3fs provider Settings editor writes /etc/passwd-s3fs, and an
    // operator reasonably reads "S3 (s3fs-fuse) → Settings" as "where my S3
    // config goes" and pastes an rclone remote in. That file is NOT rclone
    // format, so s3fs ignores it — but the credentials in it are real, so
    // surface them here rather than pretending nothing is configured. (New
    // saves are converted by save_provider_config; this covers hosts that
    // already have the bad file.)
    if let Ok(content) = fs::read_to_string(S3FS_PASSWD_PATH) {
        remotes.extend(parse_rclone_remotes(&content, "s3fs-config", S3FS_PASSWD_PATH));
    }

    // Existing mounts: their credentials are already on this host, so let a
    // second bucket on the same account be added without retyping them.
    for mount in load_config().mounts {
        if let Some(s3) = mount.s3_config {
            if s3.access_key_id.is_empty() || s3.secret_access_key.is_empty() {
                continue;
            }
            remotes.push(S3Remote {
                id: format!("mount:{}", mount.id),
                name: mount.name.clone(),
                provider: s3.provider,
                endpoint: s3.endpoint,
                region: s3.region,
                access_key_id: s3.access_key_id,
                secret_access_key: s3.secret_access_key,
                origin: format!("mount “{}”", mount.name),
            });
        }
    }

    let mut seen = std::collections::HashSet::new();
    remotes.retain(|r| seen.insert(r.id.clone()));
    remotes
}

/// Secret-free listing for the API.
pub fn list_s3_remote_infos() -> Vec<S3RemoteInfo> {
    list_s3_remotes().iter().map(|r| r.info()).collect()
}

pub fn find_s3_remote(id: &str) -> Option<S3Remote> {
    list_s3_remotes().into_iter().find(|r| r.id == id)
}

/// Resolve a remote reference into the credentials a mount needs. This is
/// how credentials get into a mount without ever passing through the
/// browser: the UI posts `s3_remote` + `bucket`, never a secret.
pub fn s3_config_from_remote(remote_id: &str, bucket: &str) -> Result<S3Config, String> {
    let remote = find_s3_remote(remote_id).ok_or_else(|| {
        format!(
            "Saved S3 credentials '{}' no longer exist — pick another set, or enter the keys directly",
            remote_id
        )
    })?;
    Ok(remote.to_s3_config(bucket))
}

/// Create or replace a remote in WolfStack's own store. `name` is the
/// identity — saving the same name twice updates it rather than duplicating.
/// An empty `secret_access_key` keeps the stored secret (the UI never round-
/// trips a secret it was never given).
pub fn save_s3_remote(mut remote: S3Remote) -> Result<S3Remote, String> {
    if remote.name.trim().is_empty() {
        return Err("Remote name is required".to_string());
    }
    remote.name = remote.name.trim().to_string();
    // The id is `<origin>:<name>`, so a name carrying ':' or '/' would make
    // ids ambiguous and unroutable. Control characters would also let a name
    // corrupt any log line it appears in.
    if remote.name.contains(':')
        || remote.name.contains('/')
        || remote.name.chars().any(|c| c.is_control())
    {
        return Err("Remote name cannot contain ':' or '/'".to_string());
    }
    remote.id = format!("wolfstack:{}", remote.name);
    remote.origin = "WolfStack".to_string();
    if remote.access_key_id.trim().is_empty() {
        return Err("Access Key ID is required".to_string());
    }

    let mut store = load_remote_store();
    match store.remotes.iter_mut().find(|r| r.id == remote.id) {
        Some(existing) => {
            if remote.secret_access_key.is_empty() {
                remote.secret_access_key = existing.secret_access_key.clone();
            }
            *existing = remote.clone();
        }
        None => {
            if remote.secret_access_key.is_empty() {
                return Err("Secret Access Key is required".to_string());
            }
            store.remotes.push(remote.clone());
        }
    }
    save_remote_store(&store)?;
    Ok(remote)
}

pub fn delete_s3_remote(id: &str) -> Result<(), String> {
    let mut store = load_remote_store();
    let before = store.remotes.len();
    store.remotes.retain(|r| r.id != id);
    if store.remotes.len() == before {
        return Err(format!(
            "Remote '{}' is not one of WolfStack's own saved remotes — remotes read from rclone.conf are managed with the rclone CLI",
            id
        ));
    }
    save_remote_store(&store)
}

/// Import every S3-compatible remote from pasted rclone.conf text into
/// WolfStack's store. Returns the names imported.
///
/// This deliberately imports REMOTES, not mounts: an rclone remote has no
/// bucket, and a WolfStack S3 mount without a bucket can never mount
/// ("Bucket name is required for S3 mounts"), so the old import produced a
/// table full of permanently-broken entries.
pub fn import_rclone_remotes(conf: &str) -> Result<Vec<String>, String> {
    let parsed = parse_rclone_remotes(conf, "wolfstack", "WolfStack");
    if parsed.is_empty() {
        return Err(
            "No S3-compatible remotes with credentials found. WolfStack imports rclone \
             sections whose type is s3, b2, gcs or r2 and that carry both access_key_id \
             and secret_access_key."
                .to_string(),
        );
    }
    let mut imported = Vec::new();
    for remote in parsed {
        let name = remote.name.clone();
        save_s3_remote(remote)?;
        imported.push(name);
    }
    Ok(imported)
}

/// List the buckets a remote's credentials can see, so the operator picks a
/// bucket from a list instead of typing one and finding out it was wrong only
/// when the s3fs daemon fails its startup bucket check.
pub fn list_remote_buckets(id: &str) -> Result<Vec<String>, String> {
    use s3::bucket::Bucket;
    use s3::creds::Credentials;

    let remote = find_s3_remote(id).ok_or_else(|| format!("Remote '{}' not found", id))?;
    let s3 = remote.to_s3_config("");

    let credentials = Credentials::new(
        Some(&s3.access_key_id),
        Some(&s3.secret_access_key),
        None, None, None,
    ).map_err(|e| format!("Invalid S3 credentials: {}", e))?;

    let region = build_s3_region(&s3);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;

    let response = rt.block_on(Bucket::list_buckets(region, credentials))
        .map_err(|e| with_s3_credential_hint(format!("Could not list buckets: {}", e)))?;

    let mut names: Vec<String> = response.bucket_names().collect();
    names.sort();
    Ok(names)
}

// ─── Auto-mount on boot ───

// ─── systemd ordering for WebUI auto-mounts ─────────────────────────────────
// WolfStack mounts its WebUI storage entries itself (raw `mount` from a
// startup thread), so systemd has no .mount units to order against — an
// fstab line like a mergerfs pool over WebUI CIFS branches could never use
// `x-systemd.requires=mnt-….mount` and raced WolfStack at every boot
// (community report 2026-06-10: 2-3 successes in 100 reboots). The fix is
// the standard systemd signalling pattern:
//   • wolfstack-mounts-wait.service — oneshot that polls for the per-boot
//     flag file below (in /run, a tmpfs, so a stale flag from the previous
//     boot is impossible).
//   • wolfstack-mounts.target — Requires/After the wait service.
//   • WolfStack touches the flag once every auto_mount entry has been
//     ATTEMPTED (settled — success or failure; "all succeeded" can't be the
//     contract or one unreachable NAS would wedge boot ordering forever).
// Operators order with `nofail,_netdev,x-systemd.requires=wolfstack-mounts.target`
// on their fstab line. `nofail` is MANDATORY, not advisory: without it the
// fstab generator orders the mount Before=local-fs.target, while this chain
// forces it after wolfstack.service (after basic.target, after
// local-fs.target) — an ordering cycle systemd breaks by dropping a job from
// the boot transaction. With nofail, systemd documents the mount is neither
// required by nor ordered before local-fs.target, so no cycle. A bare target
// WolfStack merely `systemctl start`s would NOT work either: a target with
// no blocking dependency activates instantly when an fstab Requires= pulls
// it in at boot.
const MOUNTS_READY_FLAG: &str = "/run/wolfstack/mounts-ready";
const MOUNTS_WAIT_UNIT_PATH: &str = "/etc/systemd/system/wolfstack-mounts-wait.service";
const MOUNTS_TARGET_PATH: &str = "/etc/systemd/system/wolfstack-mounts.target";

const MOUNTS_WAIT_UNIT: &str = "\
[Unit]
Description=Wait for WolfStack WebUI storage auto-mounts to settle
Documentation=https://wolfstack.org
After=wolfstack.service
Wants=wolfstack.service

[Service]
Type=oneshot
RemainAfterExit=yes
# WolfStack touches this flag once every auto-mount entry has been attempted
# (success or failure). /run is per-boot tmpfs - no stale flag across boots.
ExecStart=/bin/sh -c 'until [ -e /run/wolfstack/mounts-ready ]; do sleep 1; done'
TimeoutStartSec=300
";

const MOUNTS_TARGET_UNIT: &str = "\
[Unit]
Description=WolfStack WebUI storage auto-mounts settled
Documentation=https://wolfstack.org
Requires=wolfstack-mounts-wait.service
After=wolfstack-mounts-wait.service
";

// Docker drop-in: make dockerd wait for WolfStack's WebUI auto-mounts to settle
// before it starts containers. Without it, Docker comes up first and any
// container with a bind mount onto a WolfStack-managed NFS/CIFS path starts
// pointing at an empty directory until it is restarted (wabil 2026-06-17, after
// the NFS mount fixes made the mounts reliable enough to expose the race).
//
// `Wants=` (NOT `Requires=`) is deliberate and Golden-Rule-critical: a failed
// mount, an unreachable NAS, or a stopped/disabled WolfStack must never PREVENT
// Docker from starting — it may only order Docker *after* the mounts have been
// attempted. wolfstack-mounts.target signals once every auto-mount has been
// tried (success OR failure), and in normal operation WolfStack touches that
// flag within seconds of boot, so the added delay is negligible.
const DOCKER_MOUNTS_DROPIN_PATH: &str = "/etc/systemd/system/docker.service.d/wolfstack-mounts.conf";
const DOCKER_MOUNTS_DROPIN: &str = "\
[Unit]
# Written by WolfStack (storage manager). Orders Docker AFTER WolfStack's WebUI
# storage auto-mounts settle so bind-mount containers don't start before their
# data is mounted. Wants= (not Requires=) so a mount failure never blocks Docker.
After=wolfstack-mounts.target
Wants=wolfstack-mounts.target
";

/// Order Docker after `wolfstack-mounts.target` via a drop-in, so containers
/// with bind mounts onto WolfStack-managed network mounts don't start before
/// those mounts exist. Self-healing (content-compared, daemon-reload only on
/// change) and a no-op when systemd or Docker isn't present.
fn ensure_docker_mounts_ordering() {
    if !std::path::Path::new("/run/systemd/system").exists() {
        return;
    }
    // Only act when systemd actually knows a docker.service to order against —
    // otherwise the drop-in is dead weight and we'd daemon-reload for nothing.
    let docker_known = Command::new("systemctl")
        .args(["cat", "docker.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !docker_known {
        return;
    }
    if std::fs::read_to_string(DOCKER_MOUNTS_DROPIN_PATH).ok().as_deref() == Some(DOCKER_MOUNTS_DROPIN) {
        return;
    }
    let Some(dir) = std::path::Path::new(DOCKER_MOUNTS_DROPIN_PATH).parent() else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    if std::fs::write(DOCKER_MOUNTS_DROPIN_PATH, DOCKER_MOUNTS_DROPIN).is_ok() {
        let _ = Command::new("systemctl").arg("daemon-reload").output();
    }
}

/// Write the two units when missing or outdated (content-compared, so a
/// binary upgrade that changes them self-heals without setup.sh). Only
/// daemon-reloads when something actually changed.
fn ensure_mounts_target_units() {
    // Canonical "is systemd PID 1" check — on non-systemd hosts (containers,
    // dev runs) there is nothing to order and the unit writes would just log
    // errors every boot.
    if !std::path::Path::new("/run/systemd/system").exists() {
        return;
    }
    let mut changed = false;
    for (path, body) in [
        (MOUNTS_WAIT_UNIT_PATH, MOUNTS_WAIT_UNIT),
        (MOUNTS_TARGET_PATH, MOUNTS_TARGET_UNIT),
    ] {
        if std::fs::read_to_string(path).ok().as_deref() == Some(body) {
            continue;
        }
        match std::fs::write(path, body) {
            Ok(()) => changed = true,
            Err(e) => error!("storage: could not write {}: {}", path, e),
        }
    }
    if changed {
        let _ = Command::new("systemctl").arg("daemon-reload").output();
    }
}

/// Mount all entries that have auto_mount: true — called at startup.
/// Mounts run in parallel; a supervisor thread joins them and then signals
/// wolfstack-mounts.target (see the block comment above) so fstab entries
/// ordered on the target are released. Signals even with zero auto-mounts —
/// a node without any must not leave dependants waiting for the timeout.
/// Non-blocking for the caller: the startup task sequence (LXC autostart
/// etc.) must not stall behind a slow CIFS mount.
pub fn auto_mount_all() {
    ensure_mounts_target_units();
    // Make Docker wait for these mounts so bind-mount containers don't start
    // before their data is mounted (wabil 2026-06-17).
    ensure_docker_mounts_ordering();

    let config = load_config();
    let auto_mounts: Vec<_> = config.mounts.iter()
        .filter(|m| m.auto_mount && m.enabled)
        .map(|m| (m.id.clone(), m.name.clone()))
        .collect();

    std::thread::spawn(move || {
        let handles: Vec<std::thread::JoinHandle<()>> = auto_mounts
            .into_iter()
            .map(|(id, name)| std::thread::spawn(move || {
                match mount_storage(&id) {
                    Ok(_msg) => {}
                    Err(e) => error!("  ✗ Failed to auto-mount {}: {}", name, e),
                }
            }))
            .collect();
        let total = handles.len();
        for h in handles {
            let _ = h.join();
        }
        let _ = std::fs::create_dir_all("/run/wolfstack");
        if let Err(e) = std::fs::write(
            MOUNTS_READY_FLAG,
            format!("settled {} auto-mount(s)\n", total),
        ) {
            error!("storage: could not write {}: {}", MOUNTS_READY_FLAG, e);
        }
        // Belt-and-braces: also activate the target directly so units that
        // only use After= (without Requires= pulling the chain) see it too.
        let _ = Command::new("systemctl").args(["start", "wolfstack-mounts.target"]).output();
        info!("storage: {} auto-mount(s) settled — wolfstack-mounts.target signalled", total);
    });
}

// ─── Container Mount Integration ───

/// Get all mounted storage entries that can be attached to containers
pub fn available_mounts() -> Vec<StorageMount> {
    load_config().mounts.into_iter()
        .filter(|m| m.status == "mounted" || check_mounted(&m.mount_point))
        .collect()
}

// ─── Storage Provider Detection ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProvider {
    pub name: String,
    pub label: String,
    pub icon: String,
    pub installed: bool,
    pub description: String,
    pub package: String,
    /// systemd service name (if applicable)
    pub service: Option<String>,
    /// Service status: "running", "stopped", "not-installed", "no-service"
    pub status: String,
    /// Path to config file (if applicable)
    pub config_path: Option<String>,
    /// Installed version (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// WolfDisk-specific configuration summary (only set for wolfdisk provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wolfdisk_info: Option<WolfDiskInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfDiskInfo {
    pub cluster_name: String,
    pub node_id: String,
    pub role: String,
    pub replication_mode: String,
    pub replication_factor: usize,
    pub data_dir: String,
    pub mount_path: String,
    pub bind: String,
    pub peers: Vec<String>,
    pub s3_enabled: bool,
    pub s3_bind: Option<String>,
}

fn service_status(service_name: &str) -> String {
    match Command::new("systemctl").args(["is-active", service_name]).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match s.as_str() {
                "active" => "running".to_string(),
                "inactive" => "stopped".to_string(),
                "failed" => "failed".to_string(),
                _ => s,
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

/// List all available storage providers with their install status
pub fn list_providers() -> Vec<StorageProvider> {
    vec![
        {
            let installed = has_nfs();
            let svc = if installed { Some("nfs-server".to_string()) } else { None };
            let status = if !installed { "not-installed".to_string() }
                else { service_status("nfs-server") };
            StorageProvider {
                name: "nfs".to_string(),
                label: "NFS".to_string(),
                icon: "\u{1f5c4}\u{fe0f}".to_string(),
                installed,
                description: "Network File System \u{2014} mount remote directories over the network".to_string(),
                package: "nfs-common".to_string(),
                service: svc,
                status,
                config_path: Some("/etc/exports".to_string()),
                version: None,
                wolfdisk_info: None,
            }
        },
        {
            let installed = has_sshfs();
            StorageProvider {
                name: "sshfs".to_string(),
                label: "SSHFS".to_string(),
                icon: "\u{1f511}".to_string(),
                installed,
                description: "SSH Filesystem \u{2014} mount remote directories over SSH".to_string(),
                package: "sshfs".to_string(),
                service: None,
                status: if installed { "no-service".to_string() } else { "not-installed".to_string() },
                config_path: Some("/etc/fuse.conf".to_string()),
                version: None,
                wolfdisk_info: None,
            }
        },
        {
            let installed = has_s3fs();
            StorageProvider {
                name: "s3fs".to_string(),
                label: "S3 (s3fs-fuse)".to_string(),
                icon: "\u{2601}\u{fe0f}".to_string(),
                installed,
                description: "S3-compatible object storage via FUSE".to_string(),
                package: "s3fs".to_string(),
                service: None,
                status: if installed { "no-service".to_string() } else { "not-installed".to_string() },
                config_path: Some("/etc/passwd-s3fs".to_string()),
                version: None,
                wolfdisk_info: None,
            }
        },
        {
            let installed = has_wolfdisk();
            let svc = if installed { Some("wolfdisk".to_string()) } else { None };
            let status = if !installed { "not-installed".to_string() }
                else { service_status("wolfdisk") };
            let wolfdisk_info = if installed { read_wolfdisk_info() } else { None };
            let version = if installed {
                crate::installer::get_component_version(crate::installer::Component::WolfDisk)
            } else { None };
            StorageProvider {
                name: "wolfdisk".to_string(),
                label: "WolfDisk".to_string(),
                icon: "\u{1f43a}".to_string(),
                installed,
                description: "Distributed file system with replicated and shared storage".to_string(),
                package: "wolfdisk".to_string(),
                service: svc,
                status,
                config_path: Some("/etc/wolfdisk/config.toml".to_string()),
                version,
                wolfdisk_info,
            }
        },
    ]
}

/// Perform an action on a storage provider service (start/stop/restart)
pub fn provider_action(name: &str, action: &str) -> Result<String, String> {
    let service_name = match name {
        "nfs" => "nfs-server",
        "wolfdisk" => "wolfdisk",
        _ => return Err(format!("Provider '{}' has no manageable service", name)),
    };

    // For wolfdisk start/restart, ensure config exists and mount dir is ready
    if name == "wolfdisk" && (action == "start" || action == "restart") {
        let config_path = "/etc/wolfdisk/config.toml";
        if !Path::new(config_path).exists() {
            return Err("WolfDisk config not found at /etc/wolfdisk/config.toml — configure WolfDisk first".to_string());
        }
        // Check FUSE is available — auto-install if missing
        if !Path::new("/dev/fuse").exists() {
            let _ = Command::new("modprobe").arg("fuse").output();
        }
        if !Path::new("/dev/fuse").exists() {
            // Try installing fuse package — detect distro for correct package manager
            let distro = crate::installer::detect_distro();
            let install_result = match distro {
                crate::installer::DistroFamily::Debian => Command::new("apt-get").args(["install", "-y", "fuse3"]).output(),
                crate::installer::DistroFamily::RedHat => Command::new("dnf").args(["install", "-y", "fuse3"]).output(),
                crate::installer::DistroFamily::Suse => Command::new("zypper").args(["install", "-y", "fuse3"]).output(),
                crate::installer::DistroFamily::Arch => Command::new("pacman").args(["-S", "--noconfirm", "fuse3"]).output(),
                crate::installer::DistroFamily::Alpine => Command::new("apk").args(["add", "--no-cache", "fuse3"]).output(),
                crate::installer::DistroFamily::Unknown => Command::new("apt-get").args(["install", "-y", "fuse3"]).output(),
            };
            if let Ok(o) = &install_result {
                if !o.status.success() {
                    eprintln!("fuse3 install failed: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
            let _ = Command::new("modprobe").arg("fuse").output();
            if !Path::new("/dev/fuse").exists() {
                return Err("FUSE is not available (/dev/fuse missing). Automatic install of fuse3 failed — install manually and try again.".to_string());
            }
        }
        // Ensure /etc/fuse.conf exists and has user_allow_other
        let fuse_conf = std::fs::read_to_string("/etc/fuse.conf").unwrap_or_default();
        if !fuse_conf.lines().any(|l| l.trim() == "user_allow_other") {
            let _ = std::fs::write("/etc/fuse.conf", format!("{}\nuser_allow_other\n", fuse_conf.trim()));
        }
        // Read mount path from config and ensure directory exists
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(config) = content.parse::<toml::Value>() {
                let mount_path = config.get("mount")
                    .and_then(|m| m.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("/mnt/wolfdisk");
                let _ = std::fs::create_dir_all(mount_path);
                // Clean up stale FUSE mount if present
                let _ = Command::new("fusermount").args(["-u", mount_path]).output();
                let data_dir = config.get("node")
                    .and_then(|n| n.get("data_dir"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("/var/lib/wolfdisk");
                let _ = std::fs::create_dir_all(data_dir);
            }
        }
        // Regenerate the service file from current config to keep paths in sync
        regenerate_wolfdisk_service();
    }

    match action {
        "start" | "stop" | "restart" | "enable" | "disable" => {
            let output = Command::new("systemctl")
                .args([action, service_name])
                .output()
                .map_err(|e| format!("Failed to {} {}: {}", action, service_name, e))?;
            if output.status.success() {
                // For start/restart, verify the service is actually running after a brief wait
                if (action == "start" || action == "restart") && name == "wolfdisk" {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let status = service_status(service_name);
                    if status != "running" {
                        let journal = Command::new("journalctl")
                            .args(["-u", service_name, "-n", "10", "--no-pager", "-o", "cat"])
                            .output()
                            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                            .unwrap_or_default();
                        return Err(format!("WolfDisk exited shortly after starting (status: {}). Journal:\n{}", status, journal));
                    }
                }
                Ok(format!("{} {} successful", service_name, action))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                // Also grab journal for more context on failure
                let journal = Command::new("journalctl")
                    .args(["-u", service_name, "-n", "5", "--no-pager", "-o", "cat"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                let detail = if journal.is_empty() { stderr } else { format!("{}\n{}", stderr, journal) };
                Err(format!("{} failed: {}", action, detail))
            }
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

/// Regenerate the wolfdisk.service file from the current config to keep paths in sync
fn regenerate_wolfdisk_service() {
    let config_path = "/etc/wolfdisk/config.toml";
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let config: toml::Value = match content.parse() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mount_path = config.get("mount")
        .and_then(|m| m.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("/mnt/wolfdisk");

    let service = format!(
        "[Unit]\n\
         Description=WolfDisk Distributed File System\n\
         After=network.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=/usr/local/bin/wolfdisk --config {} mount --mountpoint {}\n\
         ExecStop=/usr/local/bin/wolfdisk unmount --mountpoint {}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         NoNewPrivileges=false\n\
         ProtectSystem=false\n\
         PrivateTmp=false\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        config_path, mount_path, mount_path
    );

    if std::fs::write("/etc/systemd/system/wolfdisk.service", &service).is_ok() {
        let _ = Command::new("systemctl").arg("daemon-reload").output();
    }
}

/// Perform an action on a storage provider service, optionally inside a container
pub fn provider_action_targeted(name: &str, action: &str, target: &crate::configurator::ExecTarget) -> Result<String, String> {
    use crate::configurator::ExecTarget;
    let service_name = match name {
        "nfs" => "nfs-server",
        "wolfdisk" => "wolfdisk",
        _ => return Err(format!("Provider '{}' has no manageable service", name)),
    };

    match action {
        "start" | "stop" | "restart" | "enable" | "disable" => {
            match target {
                ExecTarget::Host => provider_action(name, action),
                _ => {
                    let cmd = format!("systemctl {} {}", action, service_name);
                    target.exec(&cmd).map(|_| format!("{} {} successful", service_name, action))
                }
            }
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

/// s3fs's global credentials file. Format is one `access_key:secret_key` per
/// line (optionally `bucket:access_key:secret_key`) — NOT rclone's INI.
pub const S3FS_PASSWD_PATH: &str = "/etc/passwd-s3fs";

fn provider_config_path(name: &str) -> Result<&'static str, String> {
    match name {
        "nfs" => Ok("/etc/exports"),
        "sshfs" => Ok("/etc/fuse.conf"),
        "s3fs" => Ok(S3FS_PASSWD_PATH),
        "wolfdisk" => Ok("/etc/wolfdisk/config.toml"),
        _ => Err(format!("Unknown provider: {}", name)),
    }
}

/// Read a provider's config file contents
pub fn provider_config(name: &str) -> Result<String, String> {
    let path = provider_config_path(name)?;
    std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path, e))
}

/// Write a provider's config file contents
pub fn save_provider_config(name: &str, content: &str) -> Result<String, String> {
    let path = provider_config_path(name)?;

    // s3fs credentials get their own path: the file holds secrets (so 0600,
    // which s3fs also *requires* — it refuses to start against a credentials
    // file with group/other permissions), and an operator who pastes an
    // rclone remote in here has configured something real that s3fs would
    // otherwise silently ignore.
    if name == "s3fs" {
        return save_s3fs_passwd(path, content);
    }

    // Ensure the parent directory exists before writing. WolfDisk's
    // /etc/wolfdisk is normally created by its installer, but the dashboard
    // lets the operator save the config before/independently of the install,
    // which failed with "Failed to write /etc/wolfdisk/config.toml: No such
    // file or directory" (WolfDisk install report B1, 2026-06-08). create_dir_all
    // is a no-op when the directory already exists (the other providers' /etc).
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {}", parent.display(), e))?;
    }
    std::fs::write(path, content)
        .map_err(|e| format!("Cannot write {}: {}", path, e))?;
    // If NFS, reload exports
    if name == "nfs" {
        let _ = Command::new("exportfs").arg("-ra").output();
    }
    Ok(format!("Config saved to {}", path))
}

/// Save /etc/passwd-s3fs, converting a pasted rclone.conf into saved remotes.
///
/// "S3 (s3fs-fuse) → Settings" reads as "where my S3 configuration goes", so
/// operators paste an rclone remote block into it (Paul, 2026-07-29). s3fs
/// cannot read that — it would ignore the file and report nothing — so rather
/// than storing something inert, import the remotes into WolfStack's own
/// store (where the Add Mount picker finds them) and write s3fs the
/// `access_key:secret_key` lines it actually understands.
fn save_s3fs_passwd(path: &str, content: &str) -> Result<String, String> {
    let rclone_remotes = parse_rclone_remotes(content, "wolfstack", "WolfStack");

    if !rclone_remotes.is_empty() {
        let mut names = Vec::new();
        let mut passwd_lines = Vec::new();
        for remote in rclone_remotes {
            passwd_lines.push(format!("{}:{}", remote.access_key_id, remote.secret_access_key));
            names.push(remote.name.clone());
            save_s3_remote(remote)?;
        }
        // Dedupe: two remotes on the same account produce an identical line.
        // Vec::dedup only removes CONSECUTIVE duplicates, and duplicates here
        // need not be adjacent — keep the first occurrence of each instead.
        let mut seen = std::collections::HashSet::new();
        passwd_lines.retain(|l| seen.insert(l.clone()));
        crate::paths::write_secure(path, format!("{}\n", passwd_lines.join("\n")))
            .map_err(|e| format!("Cannot write {}: {}", path, e))?;
        return Ok(format!(
            "That is rclone.conf format, which s3fs cannot read — saved {} as reusable S3 remote{} instead \
             (pick them under Add Mount → S3 → Saved credentials), and wrote the matching \
             access_key:secret_key line{} to {}.",
            names.join(", "),
            if names.len() == 1 { "" } else { "s" },
            if passwd_lines.len() == 1 { "" } else { "s" },
            path
        ));
    }

    // Plain s3fs format. Validate before writing so a typo is caught here
    // rather than surfacing hours later as a mount that won't come up.
    for (n, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields = trimmed.split(':').count();
        if !(2..=3).contains(&fields) {
            return Err(format!(
                "Line {} is not valid for {}: expected `access_key:secret_key` \
                 (or `bucket:access_key:secret_key`), got `{}`.",
                n + 1, path, trimmed
            ));
        }
    }

    crate::paths::write_secure(path, content)
        .map_err(|e| format!("Cannot write {}: {}", path, e))?;
    Ok(format!("Config saved to {} (permissions 0600, as s3fs requires)", path))
}

/// Install a storage provider by name
pub fn install_provider(name: &str) -> Result<String, String> {
    let distro = crate::installer::detect_distro();
    let (pkg_mgr, pkg_name) = match name {
        "nfs" => match distro {
            crate::installer::DistroFamily::RedHat => ("dnf", "nfs-utils"),
            crate::installer::DistroFamily::Suse => ("zypper", "nfs-client"),
            _ => ("apt-get", "nfs-common"),
        },
        "sshfs" => match distro {
            crate::installer::DistroFamily::RedHat => ("dnf", "fuse-sshfs"),
            _ => ("apt-get", "sshfs"),
        },
        "s3fs" => match distro {
            crate::installer::DistroFamily::RedHat => {
                let _ = Command::new("dnf").args(["install", "-y", "epel-release"]).output();
                ("dnf", "s3fs-fuse")
            },
            _ => ("apt-get", "s3fs"),
        },
        "wolfdisk" => {
            return crate::installer::install_component(crate::installer::Component::WolfDisk);
        },
        _ => return Err(format!("Unknown provider: {}", name)),
    };


    let output = Command::new(pkg_mgr)
        .args(["install", "-y", pkg_name])
        .output()
        .map_err(|e| format!("Failed to run {}: {}", pkg_mgr, e))?;

    if output.status.success() {
        Ok(format!("{} installed successfully", pkg_name))
    } else {
        Err(format!("Installation failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── System Logs ───

/// Read system logs from journalctl
pub fn read_system_logs(lines: usize, search: Option<&str>, unit: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--no-pager".to_string(),
        "-n".to_string(), lines.to_string(),
        "--output".to_string(), "short-iso".to_string(),
    ];
    if let Some(u) = unit {
        if !u.is_empty() {
            args.push("-u".to_string());
            args.push(u.to_string());
        }
    }
    if let Some(s) = search {
        if !s.is_empty() {
            args.push("-g".to_string());
            args.push(s.to_string());
        }
    }

    match Command::new("journalctl").args(&args).output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines().map(|l| l.to_string()).collect()
        }
        // journalctl absent (Unraid/Slackware, Alpine — no systemd) or
        // erroring: fall back to the classic syslog files (klasSponsor
        // 2026-07-04: System Logs view was empty on Unraid because only
        // journald was ever consulted).
        _ => read_syslog_file_fallback(lines, search, unit),
    }
}

/// Tail-read a classic syslog file for systems without journald. Reads a
/// bounded window from the file's end (never the whole file — a busy syslog
/// runs to hundreds of MB), newest window sized generously per requested
/// line. `unit` approximates journald's -u by matching the syslog tag
/// (`hostname tag[pid]:`), `search` is a case-insensitive substring, both
/// mirroring the journalctl behaviour above.
fn read_syslog_file_fallback(lines: usize, search: Option<&str>, unit: Option<&str>) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    // Unraid (Slackware/rsyslog) writes /var/log/syslog; Alpine and
    // RHEL-family classic setups use /var/log/messages.
    let path = ["/var/log/syslog", "/var/log/messages"]
        .iter()
        .find(|p| std::path::Path::new(p).exists());
    let Some(path) = path else {
        return vec!["No system log source found (no journalctl, no /var/log/syslog or /var/log/messages)".to_string()];
    };
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return vec![format!("Error reading {}: {}", path, e)],
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    // ~512 bytes/line is generous; floor 1MB so small requests still see
    // enough history, cap 8MB to bound memory on 5000-line requests.
    let window = ((lines as u64) * 512).clamp(1_048_576, 8 * 1_048_576).min(len);
    if f.seek(SeekFrom::Start(len - window)).is_err() {
        return vec![format!("Error seeking {}", path)];
    }
    let mut buf = Vec::with_capacity(window as usize);
    if let Err(e) = f.read_to_end(&mut buf) {
        return vec![format!("Error reading {}: {}", path, e)];
    }
    let text = String::from_utf8_lossy(&buf);
    let search_lower = search.filter(|s| !s.is_empty()).map(str::to_lowercase);
    let unit_lower = unit.filter(|u| !u.is_empty()).map(str::to_lowercase);
    let mut out: Vec<String> = text
        .lines()
        .skip(1) // first line of the window is almost always a partial record
        .filter(|l| {
            let ll = l.to_lowercase();
            let search_ok = search_lower.as_ref().is_none_or(|s| ll.contains(s));
            // syslog tag match: " tag[123]:" or " tag:" — approximates
            // journald's unit filter by process name.
            let unit_ok = unit_lower.as_ref().is_none_or(|u|
                ll.contains(&format!(" {}[", u)) || ll.contains(&format!(" {}:", u)));
            search_ok && unit_ok
        })
        .map(|l| l.to_string())
        .collect();
    if out.len() > lines {
        out.drain(..out.len() - lines);
    }
    out
}

// ─── Disk Partitioning & Formatting ───

/// Protected device prefixes and mount points that must never be modified
const PROTECTED_MOUNTS: &[&str] = &["/", "/boot", "/boot/efi", "/home"];

/// Supported filesystem types for formatting
pub const SUPPORTED_FILESYSTEMS: &[&str] = &[
    "ext4", "ext3", "ext2", "xfs", "btrfs", "f2fs", "jfs", "reiserfs",
    "nilfs2", "exfat", "vfat", "fat32", "swap",
];

/// Validate that a device path is a real block device and not protected
fn validate_device(device: &str) -> Result<(), String> {
    // Must be an absolute path starting with /dev/
    if !device.starts_with("/dev/") {
        return Err("Device path must start with /dev/".into());
    }
    // Reject path traversal
    if device.contains("..") {
        return Err("Invalid device path".into());
    }
    // Must actually exist as a block device
    let p = Path::new(device);
    if !p.exists() {
        return Err(format!("{} does not exist", device));
    }
    // Use lsblk to verify it's a real block device
    let output = Command::new("lsblk")
        .args(["-no", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk failed: {}", e))?;
    if !output.status.success() {
        return Err(format!("{} is not a block device", device));
    }
    Ok(())
}

/// Check if a device or any of its children are mounted at a protected mount point
pub(crate) fn is_protected_device(device: &str) -> Result<bool, String> {
    let output = Command::new("lsblk")
        .args(["-Jno", "NAME,MOUNTPOINTS,TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
        fn check_nodes(nodes: &[serde_json::Value]) -> bool {
            for node in nodes {
                if let Some(mounts) = node.get("mountpoints").and_then(|m| m.as_array()) {
                    for mp in mounts {
                        if let Some(s) = mp.as_str() {
                            for protected in PROTECTED_MOUNTS {
                                if s == *protected {
                                    return true;
                                }
                            }
                        }
                    }
                }
                if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                    if check_nodes(children) { return true; }
                }
            }
            false
        }
        if let Some(devs) = val.get("blockdevices").and_then(|b| b.as_array()) {
            return Ok(check_nodes(devs));
        }
    }
    Ok(false)
}

/// Check if a specific device is currently mounted
fn is_mounted(device: &str) -> bool {
    Command::new("findmnt")
        .args(["-n", "-S", device])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get partition table type for a disk (gpt, dos/mbr, or empty)
pub fn get_partition_table(disk: &str) -> Result<String, String> {
    let output = Command::new("blkid")
        .args(["-p", "-o", "value", "-s", "PTTYPE", disk])
        .output()
        .map_err(|e| format!("blkid: {}", e))?;
    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if result.is_empty() { "none".to_string() } else { result })
}

/// Create a new partition table on a disk (gpt or msdos)
pub fn create_partition_table(disk: &str, table_type: &str) -> Result<String, String> {
    validate_device(disk)?;

    // Only allow on whole disks
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", disk])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "disk" {
        return Err(format!("{} is not a whole disk (type: {})", disk, dev_type_str));
    }

    if is_protected_device(disk)? {
        return Err(format!("{} has partitions mounted at protected locations — refusing", disk));
    }
    // A new partition table erases EVERY partition on the disk. Refuse if any
    // partition is mounted (even at a non-system path like /mnt/data) or is an
    // LVM/RAID/LUKS/swap/ZFS member — that data would be destroyed (paranoid review).
    if device_or_children_in_use(disk)? {
        return Err(format!(
            "{} has a partition that is mounted or in use (LVM/RAID/LUKS/swap/ZFS) — \
             unmount/clear it first; a new partition table erases the whole disk", disk));
    }

    let label = match table_type {
        "gpt" => "gpt",
        "msdos" | "mbr" => "msdos",
        _ => return Err(format!("Unsupported partition table type: {}. Use 'gpt' or 'msdos'.", table_type)),
    };

    let output = Command::new("parted")
        .args(["-s", disk, "mklabel", label])
        .output()
        .map_err(|e| format!("parted: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("parted mklabel failed: {}", stderr.trim()));
    }
    tracing::info!("Created {} partition table on {}", label, disk);
    Ok(format!("Created {} partition table on {}", label, disk))
}

/// Create a new partition on a disk
pub fn create_partition(disk: &str, size_mb: Option<u64>, fs_type_hint: Option<&str>) -> Result<String, String> {
    validate_device(disk)?;

    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", disk])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "disk" {
        return Err(format!("{} is not a whole disk", disk));
    }

    if is_protected_device(disk)? {
        return Err(format!("{} has partitions at protected mount points — refusing", disk));
    }

    // Check the disk has a partition table
    let pt = get_partition_table(disk)?;
    if pt == "none" {
        return Err(format!("{} has no partition table. Create one first (GPT or MBR).", disk));
    }

    // Find the end of the last partition to know where to start
    let output = Command::new("parted")
        .args(["-s", "-m", disk, "unit", "MiB", "print", "free"])
        .output()
        .map_err(|e| format!("parted print: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the last free space block
    let mut free_start: Option<f64> = None;
    let mut free_end: Option<f64> = None;
    for line in stdout.lines() {
        // Machine-parseable lines: "1:1.00MiB:500MiB:499MiB:ext4::;"  or "1:500MiB:1000MiB:500MiB:free;"
        if line.contains(":free;") || line.contains(":free:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let start = parts[1].trim_end_matches("MiB").parse::<f64>().unwrap_or(0.0);
                let end = parts[2].trim_end_matches("MiB").parse::<f64>().unwrap_or(0.0);
                if end - start > 1.0 {
                    free_start = Some(start);
                    free_end = Some(end);
                }
            }
        }
    }

    let start = free_start.ok_or_else(|| "No free space available on the disk".to_string())?;
    let max_end = free_end.unwrap_or(start);

    let end = if let Some(sz) = size_mb {
        let proposed = start + sz as f64;
        if proposed > max_end {
            return Err(format!("Requested {}MiB but only {:.0}MiB free", sz, max_end - start));
        }
        proposed
    } else {
        max_end // Use all remaining space
    };

    let fs_hint = fs_type_hint.unwrap_or("");
    let part_type = match fs_hint {
        "swap" => "linux-swap",
        "vfat" | "fat32" => "fat32",
        "linux-lvm" => "ext2", // parted will set LVM flag separately
        "linux-raid" => "ext2", // parted will set raid flag separately
        "zfs" => "zfs",
        _ => "ext2", // parted type hint, actual filesystem is created by mkfs later
    };

    let start_str = format!("{:.2}MiB", start);
    let end_str = format!("{:.2}MiB", end);

    let output = Command::new("parted")
        .args(["-s", "-a", "optimal", disk, "mkpart", "primary", part_type, &start_str, &end_str])
        .output()
        .map_err(|e| format!("parted mkpart: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("parted mkpart failed: {}", stderr.trim()));
    }

    // Set LVM or RAID flag if requested — find the newest partition number
    if fs_hint == "linux-lvm" || fs_hint == "linux-raid" {
        let list_out = Command::new("parted")
            .args(["-s", "-m", disk, "print"])
            .output()
            .ok();
        if let Some(lo) = list_out {
            let text = String::from_utf8_lossy(&lo.stdout);
            // Lines like "1:1049kB:500MB:499MB:ext2:primary:;" — last numbered line is newest
            let last_num = text.lines()
                .filter_map(|l| l.split(':').next()?.parse::<u32>().ok())
                .last();
            if let Some(num) = last_num {
                let flag = if fs_hint == "linux-lvm" { "lvm" } else { "raid" };
                let _ = Command::new("parted")
                    .args(["-s", disk, "set", &num.to_string(), flag, "on"])
                    .output();
            }
        }
    }

    // Inform kernel of partition changes
    let _ = Command::new("partprobe").arg(disk).output();
    // Small delay for udev to settle
    let _ = Command::new("udevadm").args(["settle", "--timeout=3"]).output();

    tracing::info!("Created partition on {}: {}-{}", disk, start_str, end_str);
    Ok(format!("Partition created on {} ({} - {})", disk, start_str, end_str))
}

/// Delete a partition
pub fn delete_partition(device: &str) -> Result<String, String> {
    validate_device(device)?;

    // Must be a partition, not a whole disk
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "part" {
        return Err(format!("{} is not a partition (type: {})", device, dev_type_str));
    }

    // Check it's not mounted at a protected location
    if is_protected_device(device)? {
        return Err(format!("{} is mounted at a protected location — refusing", device));
    }
    // Refuse to delete a partition that is mounted ANYWHERE or in use as an
    // LVM/RAID/LUKS/swap/ZFS member. Previously this silently `umount`ed a live
    // data mount (e.g. /mnt/data) and then deleted it — a careless YES could wipe a
    // running mount. Make the operator unmount/clear it deliberately first.
    if is_mounted(device) {
        return Err(format!(
            "{} is currently mounted — unmount it first, then delete the partition", device));
    }
    if device_or_children_in_use(device)? {
        return Err(format!(
            "{} is in use (LVM/RAID/LUKS/swap/ZFS member) — clear it before deleting the partition", device));
    }

    // Extract disk and partition number
    // /dev/sda1 -> disk=/dev/sda, num=1
    // /dev/nvme0n1p2 -> disk=/dev/nvme0n1, num=2
    let name = device.trim_start_matches("/dev/");
    let (disk, part_num) = if name.contains("nvme") || name.contains("mmcblk") || name.contains("loop") {
        // NVMe style: nvme0n1p2
        if let Some(idx) = name.rfind('p') {
            let num = &name[idx+1..];
            let disk_name = &name[..idx];
            (format!("/dev/{}", disk_name), num.to_string())
        } else {
            return Err(format!("Cannot parse partition number from {}", device));
        }
    } else {
        // SCSI style: sda1
        let split_pos = name.len() - name.chars().rev().take_while(|c| c.is_ascii_digit()).count();
        if split_pos == name.len() {
            return Err(format!("Cannot parse partition number from {}", device));
        }
        let disk_name = &name[..split_pos];
        let num = &name[split_pos..];
        (format!("/dev/{}", disk_name), num.to_string())
    };

    let output = Command::new("parted")
        .args(["-s", &disk, "rm", &part_num])
        .output()
        .map_err(|e| format!("parted rm: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("parted rm failed: {}", stderr.trim()));
    }

    let _ = Command::new("partprobe").arg(&disk).output();
    let _ = Command::new("udevadm").args(["settle", "--timeout=3"]).output();

    tracing::info!("Deleted partition {}", device);
    Ok(format!("Partition {} deleted", device))
}

/// Format a partition with a given filesystem type
pub fn format_partition(device: &str, fstype: &str, label: Option<&str>) -> Result<String, String> {
    validate_device(device)?;

    if !SUPPORTED_FILESYSTEMS.contains(&fstype) {
        return Err(format!("Unsupported filesystem type: {}. Supported: {}", fstype, SUPPORTED_FILESYSTEMS.join(", ")));
    }

    // Must be a partition or LVM, not a whole disk
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str == "disk" {
        return Err("Cannot format a whole disk — format individual partitions instead".into());
    }

    // Check it's not mounted at a protected location
    if is_protected_device(device)? {
        return Err(format!("{} is mounted at a protected location — refusing", device));
    }
    // Refuse to format a mounted partition rather than silently unmounting it — a
    // careless YES on a live data mount (e.g. /mnt/data) would otherwise wipe it
    // (paranoid review). The operator must unmount it deliberately first.
    if is_mounted(device) {
        return Err(format!(
            "{} is currently mounted — unmount it first, then format", device));
    }

    // Build mkfs command
    let cmd;
    let mut args: Vec<&str> = Vec::new();

    match fstype {
        "ext4" | "ext3" | "ext2" => {
            cmd = format!("mkfs.{}", fstype);
            args.push("-F"); // Force — don't ask for confirmation
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "xfs" => {
            cmd = "mkfs.xfs".to_string();
            args.push("-f"); // Force overwrite
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "btrfs" => {
            cmd = "mkfs.btrfs".to_string();
            args.push("-f");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "f2fs" => {
            cmd = "mkfs.f2fs".to_string();
            args.push("-f");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-l"); args.push(l); }
            }
        }
        "jfs" => {
            cmd = "mkfs.jfs".to_string();
            args.push("-q"); // Don't prompt
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "reiserfs" => {
            cmd = "mkfs.reiserfs".to_string();
            args.push("-f");
            args.push("-q");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-l"); args.push(l); }
            }
        }
        "nilfs2" => {
            cmd = "mkfs.nilfs2".to_string();
            args.push("-f");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "exfat" => {
            cmd = "mkfs.exfat".to_string();
            if let Some(l) = label {
                if !l.is_empty() { args.push("-n"); args.push(l); }
            }
        }
        "vfat" | "fat32" => {
            cmd = "mkfs.vfat".to_string();
            args.push("-F"); args.push("32");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-n"); args.push(l); }
            }
        }
        "swap" => {
            cmd = "mkswap".to_string();
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        _ => return Err(format!("Unsupported filesystem: {}", fstype)),
    }

    args.push(device);

    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .map_err(|e| format!("{} failed: {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{} failed: {}", cmd, stderr.trim()));
    }

    tracing::info!("Formatted {} as {} (label: {:?})", device, fstype, label);
    Ok(format!("{} formatted as {}", device, fstype))
}

/// Resize a partition to fill its available space, then grow the filesystem.
///
/// This handles the common case where a virtual disk has been extended
/// (e.g. in a VM or cloud) and the partition + filesystem need to be grown
/// to use the new space.
///
/// Steps:
///  1. Use `growpart` (if available) or `parted resizepart` to extend the partition
///  2. Detect the filesystem type
///  3. Run the appropriate filesystem resize tool (resize2fs, xfs_growfs, btrfs resize)
pub fn resize_partition(device: &str) -> Result<String, String> {
    validate_device(device)?;

    // Must be a partition, not a whole disk
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "part" && dev_type_str != "lvm" {
        return Err(format!("{} is not a partition (type: {}). Resize individual partitions, not whole disks.", device, dev_type_str));
    }

    // Extract parent disk and partition number
    let name = device.trim_start_matches("/dev/");
    let (disk, part_num) = if name.contains("nvme") || name.contains("mmcblk") || name.contains("loop") {
        if let Some(idx) = name.rfind('p') {
            (format!("/dev/{}", &name[..idx]), name[idx+1..].to_string())
        } else {
            return Err(format!("Cannot parse partition number from {}", device));
        }
    } else {
        let split_pos = name.len() - name.chars().rev().take_while(|c| c.is_ascii_digit()).count();
        if split_pos == name.len() {
            return Err(format!("Cannot parse partition number from {}", device));
        }
        (format!("/dev/{}", &name[..split_pos]), name[split_pos..].to_string())
    };

    let mut messages: Vec<String> = Vec::new();

    // Step 1: Grow the partition to fill available space
    // Try growpart first (cloud-utils), then fall back to parted
    let part_grown = if Command::new("which").arg("growpart").output().map(|o| o.status.success()).unwrap_or(false) {
        let output = Command::new("growpart")
            .args([&disk, &part_num])
            .output()
            .map_err(|e| format!("growpart: {}", e))?;
        if output.status.success() {
            messages.push("Partition extended with growpart".into());
            true
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // growpart returns exit code 1 with "NOCHANGE" if already at max size
            if stderr.contains("NOCHANGE") || String::from_utf8_lossy(&output.stdout).contains("NOCHANGE") {
                messages.push("Partition already at maximum size".into());
                true
            } else {
                // Fall back to parted
                false
            }
        }
    } else {
        false
    };

    if !part_grown {
        // Try parted resizepart — grow to 100%
        let output = Command::new("parted")
            .args(["-s", &disk, "resizepart", &part_num, "100%"])
            .output()
            .map_err(|e| format!("parted resizepart: {}", e))?;
        if output.status.success() {
            messages.push("Partition extended with parted".into());
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Not fatal — the partition may already be at max, or this may be LVM
            messages.push(format!("Partition resize skipped: {}", stderr.trim()));
        }
    }

    // Inform kernel of changes
    let _ = Command::new("partprobe").arg(&disk).output();
    let _ = Command::new("udevadm").args(["settle", "--timeout=3"]).output();

    // Step 2: Detect filesystem type
    let fstype_out = Command::new("blkid")
        .args(["-o", "value", "-s", "TYPE", device])
        .output()
        .map_err(|e| format!("blkid: {}", e))?;
    let fstype = String::from_utf8_lossy(&fstype_out.stdout).trim().to_string();

    if fstype.is_empty() {
        // No filesystem — partition resize is all we can do
        messages.push("No filesystem detected — only partition was resized".into());
        tracing::info!("Resized partition {} (no filesystem): {:?}", device, messages);
        return Ok(messages.join(". "));
    }

    // Step 3: Resize the filesystem
    match fstype.as_str() {
        "ext4" | "ext3" | "ext2" => {
            // resize2fs works on mounted or unmounted ext filesystems
            let output = Command::new("resize2fs")
                .arg(device)
                .output()
                .map_err(|e| format!("resize2fs: {}", e))?;
            if output.status.success() {
                messages.push(format!("{} filesystem resized with resize2fs", fstype));
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("resize2fs failed: {}", stderr.trim()));
            }
        }
        "xfs" => {
            // xfs_growfs requires the filesystem to be mounted
            let mountpoint = get_mountpoint(device);
            if let Some(mp) = mountpoint {
                let output = Command::new("xfs_growfs")
                    .arg(&mp)
                    .output()
                    .map_err(|e| format!("xfs_growfs: {}", e))?;
                if output.status.success() {
                    messages.push("XFS filesystem resized with xfs_growfs".into());
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("xfs_growfs failed: {}", stderr.trim()));
                }
            } else {
                return Err("XFS filesystem must be mounted to resize. Mount it first, then retry.".into());
            }
        }
        "btrfs" => {
            // btrfs filesystem resize requires the filesystem to be mounted
            let mountpoint = get_mountpoint(device);
            if let Some(mp) = mountpoint {
                let output = Command::new("btrfs")
                    .args(["filesystem", "resize", "max", &mp])
                    .output()
                    .map_err(|e| format!("btrfs resize: {}", e))?;
                if output.status.success() {
                    messages.push("Btrfs filesystem resized".into());
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("btrfs resize failed: {}", stderr.trim()));
                }
            } else {
                return Err("Btrfs filesystem must be mounted to resize. Mount it first, then retry.".into());
            }
        }
        "swap" => {
            // Recreate swap to match new partition size
            let was_on = Command::new("swapon").args(["--show=NAME", "--noheadings"])
                .output().map(|o| String::from_utf8_lossy(&o.stdout).contains(device)).unwrap_or(false);
            if was_on {
                let _ = Command::new("swapoff").arg(device).output();
            }
            let output = Command::new("mkswap").arg(device).output()
                .map_err(|e| format!("mkswap: {}", e))?;
            if output.status.success() {
                messages.push("Swap recreated at new size".into());
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("mkswap failed: {}", stderr.trim()));
            }
            if was_on {
                let _ = Command::new("swapon").arg(device).output();
                messages.push("Swap re-enabled".into());
            }
        }
        other => {
            messages.push(format!("Filesystem '{}' does not support online resize — partition was extended but filesystem was not grown", other));
        }
    }

    tracing::info!("Resized {}: {:?}", device, messages);
    Ok(messages.join(". "))
}

/// Get the mount point for a device, if mounted
fn get_mountpoint(device: &str) -> Option<String> {
    let output = Command::new("findmnt")
        .args(["-n", "-o", "TARGET", "-S", device])
        .output()
        .ok()?;
    let mp = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if mp.is_empty() { None } else { Some(mp) }
}

#[cfg(test)]
mod mounts_target_tests {
    use super::*;

    /// A WolfStack mount must never be allowed to land on a critical system
    /// directory — a mount over /dev/, /usr, /bin, / etc. hides the running
    /// system's own files (disk intact) and breaks exec host-wide; a global
    /// mount would fan that out to every peer. Legit targets under /mnt,
    /// /srv, /var/lib, /usr/local must still be accepted.
    #[test]
    fn unsafe_mount_targets_are_rejected() {
        for bad in &[
            "/", "/dev", "/dev/", "/dev/null", "/usr", "/usr/bin", "/bin",
            "/sbin", "/lib", "/lib64", "/etc", "/boot", "/boot/efi", "/proc",
            "/sys", "/run", "/var", "/root", "/home",
            "/mnt/../dev", "relative/path", "",
        ] {
            assert!(is_unsafe_mount_target(bad), "{bad:?} must be rejected");
        }
        for ok in &[
            "/mnt/data", "/srv/share", "/var/lib/vz",
            "/home/paul/data", "/mnt/pve/cephfs", "/opt/storage",
        ] {
            assert!(!is_unsafe_mount_target(ok), "{ok:?} must be allowed");
        }
    }

    /// The three pieces of the signalling chain reference each other by
    /// literal name/path — this pins them together so an edit to one can't
    /// silently break the ordering contract.
    #[test]
    fn signalling_chain_is_consistent() {
        // The wait service polls exactly the flag the supervisor writes.
        assert!(MOUNTS_WAIT_UNIT.contains(MOUNTS_READY_FLAG),
            "wait unit must poll {}", MOUNTS_READY_FLAG);
        // The target gates on the wait service (Requires AND After) — a
        // bare target would activate instantly when fstab Requires= it.
        assert!(MOUNTS_TARGET_UNIT.contains("Requires=wolfstack-mounts-wait.service"));
        assert!(MOUNTS_TARGET_UNIT.contains("After=wolfstack-mounts-wait.service"));
        // Unit paths match the names units reference.
        assert!(MOUNTS_WAIT_UNIT_PATH.ends_with("/wolfstack-mounts-wait.service"));
        assert!(MOUNTS_TARGET_PATH.ends_with("/wolfstack-mounts.target"));
        // The wait service must order after wolfstack itself, and survive
        // ExecStart exit so the target stays up (oneshot + RemainAfterExit).
        assert!(MOUNTS_WAIT_UNIT.contains("After=wolfstack.service"));
        assert!(MOUNTS_WAIT_UNIT.contains("RemainAfterExit=yes"));
        // A bounded wait — an absent/broken wolfstack must not hang boot
        // ordering forever (dependants should also use nofail).
        assert!(MOUNTS_WAIT_UNIT.contains("TimeoutStartSec="));
    }
}

#[cfg(test)]
mod mount_dropin_tests {
    use super::*;

    #[test]
    fn network_mount_classification() {
        // Network types need the shutdown-ordering drop-in…
        assert!(is_network_mount(&MountType::Nfs));
        assert!(is_network_mount(&MountType::Smb));
        assert!(is_network_mount(&MountType::Sshfs));
        assert!(is_network_mount(&MountType::S3));
        // …local ones must not get one: a bind mount ordered after
        // network-online would needlessly couple local storage to the
        // network at shutdown. WolfDisk's own daemon manages its lifecycle.
        assert!(!is_network_mount(&MountType::Directory));
        assert!(!is_network_mount(&MountType::Wolfdisk));
    }

    #[test]
    fn dropin_orders_against_both_halves() {
        // Shutdown contract: pool (on the target) unmounts before the branch,
        // branch unmounts before the network goes down.
        assert!(MOUNT_DROPIN_BODY.contains("Before=wolfstack-mounts.target"));
        assert!(MOUNT_DROPIN_BODY.contains("After=network-online.target network.target"));
        assert!(MOUNT_DROPIN_BODY.starts_with("[Unit]\n"));
    }

    fn s3cfg(region: &str, endpoint: &str) -> S3Config {
        S3Config {
            access_key_id: "k".into(), secret_access_key: "s".into(),
            region: region.into(), endpoint: endpoint.into(),
            provider: "Custom".into(), bucket: "b".into(),
        }
    }

    #[test]
    fn r2_endpoint_detection() {
        assert!(is_r2_endpoint("https://abc123.r2.cloudflarestorage.com"));
        assert!(is_r2_endpoint("abc123.r2.cloudflarestorage.com"));
        assert!(!is_r2_endpoint("https://s3.us-west-1.wasabisys.com"));
        assert!(!is_r2_endpoint("https://minio.local:9000"));
        assert!(!is_r2_endpoint(""));
    }

    #[test]
    fn r2_always_uses_auto_region_for_sigv4() {
        // R2 + blank region → "auto" (its required SigV4 region); without it
        // s3fs falls back to SigV2, which R2 rejects (Gary KO4BSR).
        assert_eq!(effective_s3_region(&s3cfg("", "https://x.r2.cloudflarestorage.com")), "auto");
        // R2 FORCES "auto" even over a stored non-auto region — that stale
        // value is precisely what kept an existing mount broken after the
        // v24.47.3 blank→auto fallback (it never reached the fallback). A
        // working R2 mount can only be "auto", so this can't regress one.
        assert_eq!(effective_s3_region(&s3cfg("us-east-1", "https://x.r2.cloudflarestorage.com")), "auto");
        assert_eq!(effective_s3_region(&s3cfg("wnam", "https://x.r2.cloudflarestorage.com")), "auto");
        // Non-R2 custom endpoint with blank region → empty (caller defaults
        // to us-east-1; MinIO/Wasabi behaviour is unchanged).
        assert_eq!(effective_s3_region(&s3cfg("", "https://minio.local:9000")), "");
        // Non-R2 with explicit region → that region (unchanged).
        assert_eq!(effective_s3_region(&s3cfg("us-east-2", "https://minio.local:9000")), "us-east-2");
    }

    #[test]
    fn s3_credential_hint_classifies_auth_failures() {
        // Gary KO4BSR's actual error strings (R2, wrong secret).
        assert!(s3_credential_hint("Failed to connect by sigv4, so retry to connect by signature version 2"));
        assert!(s3_credential_hint("SigV2 authorization is not supported. Please use SigV4 instead."));
        assert!(s3_credential_hint("Failed to list S3 bucket 'wolfstack': serde xml: missing field Name"));
        assert!(s3_credential_hint("The request signature we calculated does not match"));
        assert!(s3_credential_hint("InvalidAccessKeyId"));
        assert!(s3_credential_hint("AccessDenied: Forbidden"));
        // Non-auth failures must NOT be misclassified as a credentials problem.
        assert!(!s3_credential_hint("mount.nfs: Connection timed out"));
        assert!(!s3_credential_hint("No such file or directory"));
        assert!(!s3_credential_hint("ensure_diskfree=1024 exceeded"));
        // The wrapper appends only on a match.
        assert!(with_s3_credential_hint("sigv4 rejected".to_string()).contains("credentials problem"));
        assert_eq!(with_s3_credential_hint("disk full".to_string()), "disk full");
    }

    #[test]
    fn replicated_mount_match_prefers_id_then_mount_point() {
        let sm = |id: &str, mp: &str| -> StorageMount {
            serde_json::from_value(serde_json::json!({
                "id": id, "name": id, "type": "nfs",
                "source": "srv:/data", "mount_point": mp, "created_at": ""
            })).unwrap()
        };
        let existing = vec![sm("m1", "/mnt/a"), sm("m2", "/mnt/b")];
        // Same id → match that row (the cluster re-sync case that used to
        // blow up with "already in use").
        assert_eq!(replicated_mount_match(&existing, &sm("m2", "/mnt/zzz")), Some(1));
        // Different id but same mount_point → match by mount_point.
        assert_eq!(replicated_mount_match(&existing, &sm("new", "/mnt/a")), Some(0));
        // No id/mount_point match → None (a genuinely new mount).
        assert_eq!(replicated_mount_match(&existing, &sm("new", "/mnt/c")), None);
        // Empty incoming id never matches on id — falls through to mount_point.
        assert_eq!(replicated_mount_match(&existing, &sm("", "/mnt/b")), Some(1));
    }
}

#[cfg(test)]
mod s3_remote_tests {
    use super::*;

    /// The exact block Paul pasted into the s3fs provider Settings editor on
    /// wolfstack-2 (2026-07-29). It is rclone.conf format, which s3fs cannot
    /// read — WolfStack must recognise it and turn it into a usable remote
    /// rather than storing an inert file and reporting nothing configured.
    const IDRIVE_RCLONE: &str = "\
[ff2]
type = s3
provider = IDrive
env_auth = false
region = eu-central-1
location_constraint = 
server_side_encryption = 
endpoint = l8k1.fra21.idrivee2-12.com
access_key_id = AKIAEXAMPLEKEY123456
secret_access_key = ExampleSecretKeyValueForUnitTestOnly1234
";

    #[test]
    fn parses_an_idrive_rclone_remote() {
        let remotes = parse_rclone_remotes(IDRIVE_RCLONE, "wolfstack", "WolfStack");
        assert_eq!(remotes.len(), 1);
        let r = &remotes[0];
        assert_eq!(r.id, "wolfstack:ff2");
        assert_eq!(r.name, "ff2");
        assert_eq!(r.provider, "IDrive");
        assert_eq!(r.region, "eu-central-1");
        assert_eq!(r.endpoint, "l8k1.fra21.idrivee2-12.com");
        assert_eq!(r.access_key_id, "AKIAEXAMPLEKEY123456");
        assert_eq!(r.secret_access_key, "ExampleSecretKeyValueForUnitTestOnly1234");
    }

    /// Blank values in the pasted config (location_constraint,
    /// server_side_encryption) must not be mistaken for missing sections, and
    /// comments must not become keys.
    #[test]
    fn ignores_comments_and_blank_values() {
        let conf = "\
# a comment
; another comment

[withblank]
type = s3
region =
access_key_id = AKIAEXAMPLEKEY123456
secret_access_key = SecretValueLongEnoughToBeRealistic123456
";
        let remotes = parse_rclone_remotes(conf, "rclone", "/etc/rclone.conf");
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].region, "");
        assert_eq!(remotes[0].origin, "/etc/rclone.conf");
    }

    /// Non-S3 remotes and credential-less ones (env_auth, or an rclone remote
    /// whose secret lives in the obscured form rclone writes) must be skipped:
    /// offering them in the picker would only produce a mount that fails its
    /// bucket check.
    #[test]
    fn skips_non_s3_and_credential_less_remotes() {
        let conf = "\
[dropbox]
type = dropbox
token = {}

[nokeys]
type = s3
region = us-east-1

[keyonly]
type = s3
access_key_id = AKIAEXAMPLEKEY123456
";
        assert!(parse_rclone_remotes(conf, "rclone", "test").is_empty());
    }

    /// Every S3-compatible rclone type is accepted, not just `s3`.
    #[test]
    fn accepts_every_s3_compatible_type() {
        for t in S3_COMPATIBLE_RCLONE_TYPES {
            let conf = format!(
                "[r]\ntype = {}\naccess_key_id = AKIAEXAMPLEKEY123456\nsecret_access_key = SecretValueLongEnoughToBeRealistic123456\n",
                t
            );
            assert_eq!(parse_rclone_remotes(&conf, "rclone", "test").len(), 1, "type {} rejected", t);
        }
    }

    /// A key-value line before any section header has no section to belong to
    /// and must not panic or be silently attached to the next one.
    #[test]
    fn tolerates_keys_before_any_section() {
        let sections = parse_ini_sections("stray = value\n[real]\ntype = s3\n");
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].0, "real");
        assert!(!sections[0].1.contains_key("stray"));
    }

    #[test]
    fn access_keys_are_masked_not_printed() {
        assert_eq!(mask_access_key("AKIAEXAMPLEKEY123456"), "AKIA…3456");
        // Anything short enough that a 4+4 reveal would expose most of it is
        // hidden entirely.
        assert_eq!(mask_access_key("short"), "•••••");
        assert_eq!(mask_access_key(""), "");
    }

    /// The remote picker exposes an S3RemoteInfo; a secret must not be
    /// reachable through it, and read-only sources must be marked so.
    #[test]
    fn remote_info_carries_no_secret() {
        let remote = S3Remote {
            id: "rclone:ff2".to_string(),
            name: "ff2".to_string(),
            provider: "IDrive".to_string(),
            endpoint: "l8k1.fra21.idrivee2-12.com".to_string(),
            region: "eu-central-1".to_string(),
            access_key_id: "AKIAEXAMPLEKEY123456".to_string(),
            secret_access_key: "ExampleSecretKeyValueForUnitTestOnly1234".to_string(),
            origin: "/root/.config/rclone/rclone.conf".to_string(),
        };
        let json = serde_json::to_string(&remote.info()).unwrap();
        assert!(!json.contains("ExampleSecretKeyValueForUnitTestOnly1234"));
        assert!(!json.contains("AKIAEXAMPLEKEY123456"));
        // Not WolfStack's own store → the UI must not offer to edit it.
        assert!(!remote.info().editable);
    }

    /// A remote supplies everything except the bucket, which is per-mount.
    #[test]
    fn remote_to_config_takes_bucket_from_caller() {
        let remote = S3Remote {
            id: "wolfstack:e2".to_string(),
            name: "e2".to_string(),
            provider: "IDrive".to_string(),
            endpoint: "l8k1.fra21.idrivee2-12.com".to_string(),
            region: "eu-central-1".to_string(),
            access_key_id: "AKIAEXAMPLEKEY123456".to_string(),
            secret_access_key: "SecretValueLongEnoughToBeRealistic123456".to_string(),
            origin: "WolfStack".to_string(),
        };
        let cfg = remote.to_s3_config("backups");
        assert_eq!(cfg.bucket, "backups");
        assert_eq!(cfg.endpoint, "l8k1.fra21.idrivee2-12.com");
        assert_eq!(cfg.region, "eu-central-1");
    }

    /// A provider dashboard prints `host` — s3fs and rust-s3 both need a URL.
    #[test]
    fn bare_endpoint_hosts_get_a_scheme() {
        assert_eq!(endpoint_url("l8k1.fra21.idrivee2-12.com"), "https://l8k1.fra21.idrivee2-12.com");
        assert_eq!(endpoint_url("https://s3.example.com"), "https://s3.example.com");
        assert_eq!(endpoint_url("http://minio.lan:9000"), "http://minio.lan:9000");
        assert_eq!(endpoint_url("  s3.example.com  "), "https://s3.example.com");
    }
}

#[cfg(test)]
mod s3fs_log_tests {
    use super::*;

    /// Verbatim output from s3fs 1.95 on wolfstack-2 mounting a bucket that
    /// does not exist (2026-07-29). s3fs EXITS 0 here — the daemon fails its
    /// startup bucket check afterwards — so this log is the only place the
    /// real reason exists, and nothing on a default host collects syslog.
    const NO_SUCH_BUCKET_LOG: &str = "\
2026-07-29T11:55:19.780Z [CRT] s3fs_logger.cpp:LowSetLogLevel(233): change debug level from [CRT] to [INF] 
2026-07-29T11:55:19.782Z [INF] s3fs.cpp:s3fs_check_service(4382): check services.
2026-07-29T11:55:19.875Z [ERR] curl.cpp:CheckBucket(3833): Check bucket failed, S3 response: <Error><Code>NoSuchBucket</Code></Error>
2026-07-29T11:55:19.875Z [CRT] s3fs.cpp:s3fs_check_service(4498): Failed to check bucket and directory for mount point : Bucket or directory not found(host=https://l8k1.fra21.idrivee2-12.com, message=The specified bucket does not exist)
2026-07-29T11:55:19.875Z [ERR] s3fs.cpp:s3fs_exit_fuseloop(4199): Exiting FUSE event loop due to errors
";

    fn write_temp_log(name: &str, content: &str) -> String {
        let path = format!("{}/wolfstack-s3fs-test-{}.log", std::env::temp_dir().display(), name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn extracts_the_real_failure_from_the_daemon_log() {
        let path = write_temp_log("nosuchbucket", NO_SUCH_BUCKET_LOG);
        let err = read_s3fs_error(&path).expect("failure lines should be found");
        let _ = fs::remove_file(&path);

        assert!(err.contains("The specified bucket does not exist"), "got: {}", err);
        assert!(err.contains("NoSuchBucket"), "got: {}", err);
        // The C++ source location and severity tag are noise for an operator.
        assert!(!err.contains("s3fs.cpp"), "got: {}", err);
        assert!(!err.contains("[CRT]"), "got: {}", err);
        // s3fs logs its own log-level change as [CRT] on EVERY start; reporting
        // that as the failure would be actively misleading.
        assert!(!err.contains("change debug level"), "got: {}", err);
    }

    #[test]
    fn a_clean_log_yields_no_error() {
        let path = write_temp_log(
            "clean",
            "2026-07-29T11:55:19.780Z [CRT] s3fs_logger.cpp:LowSetLogLevel(233): change debug level from [CRT] to [INF]\n\
             2026-07-29T11:55:19.782Z [INF] s3fs.cpp:s3fs_init(4209): init v1.95\n",
        );
        let err = read_s3fs_error(&path);
        let _ = fs::remove_file(&path);
        assert!(err.is_none(), "got: {:?}", err);
    }

    /// s3fs older than 1.85 ignores `-o logfile`, so no file is written. The
    /// caller must fall back to its own guidance rather than showing nothing.
    #[test]
    fn missing_log_yields_no_error() {
        assert!(read_s3fs_error("/nonexistent/wolfstack-s3fs-missing.log").is_none());
    }

    #[test]
    fn error_text_is_capped_for_a_dialog() {
        let long = format!(
            "2026-07-29T11:55:19.875Z [ERR] curl.cpp:CheckBucket(3833): {}\n",
            "x".repeat(5000)
        );
        let path = write_temp_log("long", &long);
        let err = read_s3fs_error(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(err.chars().count() <= 601, "length {}", err.chars().count());
        assert!(err.ends_with('…'));
    }
}
