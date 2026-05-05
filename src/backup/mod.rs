// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Backup & Restore — Docker, LXC, VM, and config backup management
//!
//! Supports storage targets: local path, S3, remote WolfStack node, WolfDisk
//! Includes scheduling with retention policies


//! backup needs lxcs to have more information

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, warn};
use chrono::{Utc, Datelike};
use uuid::Uuid;

fn backup_config_path() -> String { crate::paths::get().backup_config }
fn backup_staging_dir() -> String { crate::paths::get().backup_staging_dir }

// ─── Data Types ───

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackupTargetType {
    Docker,
    Lxc,
    Vm,
    Config,
}

impl std::fmt::Display for BackupTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "docker"),
            Self::Lxc => write!(f, "lxc"),
            Self::Vm => write!(f, "vm"),
            Self::Config => write!(f, "config"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupTarget {
    #[serde(rename = "type")]
    pub target_type: BackupTargetType,
    /// Name of the container/VM (empty for Config type)
    pub name: String,
    /// Actual hostname (e.g. Proxmox LXC where name is a numeric VMID)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Running state (running, stopped, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Brief spec summary (e.g. "2 cores, 2GB RAM, Ubuntu 22.04")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specs: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    Local,
    S3,
    Remote,
    Wolfdisk,
    Pbs,
    /// NFS export — direct backup destination. Mounted on-demand at
    /// /mnt/wolfstack-backup/<id>/ and written through like Local.
    Nfs,
    /// SMB/CIFS share — as Nfs but for Synology/QNAP and Windows NAS boxes.
    Smb,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::S3 => write!(f, "s3"),
            Self::Remote => write!(f, "remote"),
            Self::Wolfdisk => write!(f, "wolfdisk"),
            Self::Pbs => write!(f, "pbs"),
            Self::Nfs => write!(f, "nfs"),
            Self::Smb => write!(f, "smb"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStorage {
    #[serde(rename = "type")]
    pub storage_type: StorageType,
    /// Local path or WolfDisk mount point
    #[serde(default)]
    pub path: String,
    /// S3 bucket name
    #[serde(default)]
    pub bucket: String,
    /// S3 region
    #[serde(default)]
    pub region: String,
    /// S3 endpoint URL
    #[serde(default)]
    pub endpoint: String,
    /// S3 access key
    #[serde(default)]
    pub access_key: String,
    /// S3 secret key
    #[serde(default)]
    pub secret_key: String,
    /// Remote WolfStack node URL
    #[serde(default)]
    pub remote_url: String,
    /// PBS server hostname/IP
    #[serde(default)]
    pub pbs_server: String,
    /// PBS datastore name
    #[serde(default)]
    pub pbs_datastore: String,
    /// PBS user (e.g. backup@pbs)
    #[serde(default)]
    pub pbs_user: String,
    /// PBS API token name
    #[serde(default)]
    pub pbs_token_name: String,
    /// PBS API token secret
    #[serde(default)]
    pub pbs_token_secret: String,
    /// PBS password (alternative to API token)
    #[serde(default)]
    pub pbs_password: String,
    /// PBS server TLS fingerprint (optional)
    #[serde(default)]
    pub pbs_fingerprint: String,
    /// PBS namespace (optional, for organizing backups)
    #[serde(default)]
    pub pbs_namespace: String,
    // ── NFS direct backup destination ─────────────────
    /// `server:/export` — same syntax as `mount -t nfs`.
    #[serde(default)]
    pub nfs_source: String,
    /// Mount options; empty string uses the default `rw,soft,timeo=50`.
    #[serde(default)]
    pub nfs_options: String,
    // ── SMB/CIFS direct backup destination ────────────
    /// `//server/share` (Windows-style `\\server\share` is normalised).
    #[serde(default)]
    pub smb_source: String,
    /// Subdirectory under the share root to write backups into.
    #[serde(default)]
    pub smb_subpath: String,
    #[serde(default)]
    pub smb_username: String,
    #[serde(default)]
    pub smb_password: String,
    #[serde(default)]
    pub smb_domain: String,
    /// Extra CIFS mount options, e.g. `vers=2.1` for older NAS.
    #[serde(default)]
    pub smb_options: String,
    /// Subdirectory under the WolfDisk mount point to write backups
    /// into. Empty means write to the mount root (default, original
    /// behaviour). Sanitized at write time — leading/trailing
    /// slashes are trimmed, `..` segments are rejected so a
    /// misconfigured destination can't escape the mount root.
    #[serde(default)]
    pub wolfdisk_subpath: String,
}

#[allow(dead_code)]
impl BackupStorage {
    pub fn local(path: &str) -> Self {
        Self {
            storage_type: StorageType::Local,
            path: path.to_string(),
            ..Self::default()
        }
    }

    pub fn s3(bucket: &str, region: &str, endpoint: &str, key: &str, secret: &str) -> Self {
        Self {
            storage_type: StorageType::S3,
            bucket: bucket.to_string(),
            region: region.to_string(),
            endpoint: endpoint.to_string(),
            access_key: key.to_string(),
            secret_key: secret.to_string(),
            ..Self::default()
        }
    }

    pub fn remote(url: &str) -> Self {
        Self {
            storage_type: StorageType::Remote,
            remote_url: url.to_string(),
            ..Self::default()
        }
    }

    pub fn wolfdisk(path: &str) -> Self {
        Self {
            storage_type: StorageType::Wolfdisk,
            path: path.to_string(),
            ..Self::default()
        }
    }

    pub fn pbs(server: &str, datastore: &str, user: &str, token_name: &str, token_secret: &str) -> Self {
        Self {
            storage_type: StorageType::Pbs,
            pbs_server: server.to_string(),
            pbs_datastore: datastore.to_string(),
            pbs_user: user.to_string(),
            pbs_token_name: token_name.to_string(),
            pbs_token_secret: token_secret.to_string(),
            ..Self::default()
        }
    }
}

impl Default for BackupStorage {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Local,
            path: String::new(),
            bucket: String::new(),
            region: String::new(),
            endpoint: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
            remote_url: String::new(),
            pbs_server: String::new(),
            pbs_datastore: String::new(),
            pbs_user: String::new(),
            pbs_token_name: String::new(),
            pbs_token_secret: String::new(),
            pbs_password: String::new(),
            pbs_fingerprint: String::new(),
            pbs_namespace: String::new(),
            nfs_source: String::new(),
            nfs_options: String::new(),
            smb_source: String::new(),
            smb_subpath: String::new(),
            smb_username: String::new(),
            smb_password: String::new(),
            smb_domain: String::new(),
            smb_options: String::new(),
            wolfdisk_subpath: String::new(),
        }
    }
}

impl BackupStorage {
    /// Resolve the local-filesystem write path for a Local or
    /// WolfDisk destination, joining the WolfDisk subpath under the
    /// mount root when set. For non-Local/Wolfdisk types the
    /// configured `path` is returned unchanged.
    ///
    /// Sanitization:
    ///   - Trims trailing slashes from the base path.
    ///   - Trims leading/trailing slashes from the subpath.
    ///   - Drops empty / `.` / `..` segments. The save-time API
    ///     check rejects `..` outright, but this defence-in-depth
    ///     filter ensures an older config file (or a hand-edited
    ///     `/etc/wolfstack/backup.json`) can't escape the mount.
    pub fn resolved_local_path(&self) -> String {
        let base = self.path.trim_end_matches('/').to_string();
        if !matches!(self.storage_type, StorageType::Wolfdisk) {
            return self.path.clone();
        }
        let raw = self.wolfdisk_subpath.trim().trim_matches('/');
        if raw.is_empty() { return base; }
        let safe: Vec<&str> = raw.split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .collect();
        if safe.is_empty() { return base; }
        format!("{}/{}", base, safe.join("/"))
    }

    /// Validate a WolfDisk subpath at the API save boundary. Strict
    /// — any `..` or `.` segment is rejected (vs the lenient
    /// resolver which silently strips them). Empty subpath is
    /// allowed (it means "use the mount root", the default).
    ///
    /// `.` is rejected even though it's harmless, because keeping
    /// the validator and resolver consistent avoids the surprise
    /// where an operator types `./backups` and the storage label
    /// shows `backups` — a silent normalisation that looks like
    /// the system "ate" their input.
    pub fn validate_wolfdisk_subpath(sub: &str) -> Result<(), String> {
        let s = sub.trim().trim_matches('/');
        if s.is_empty() { return Ok(()); }
        for seg in s.split('/') {
            if seg.is_empty() {
                return Err("WolfDisk subpath has empty segment (consecutive slashes)".into());
            }
            if seg == ".." {
                return Err("WolfDisk subpath must not contain '..' segments".into());
            }
            if seg == "." {
                return Err("WolfDisk subpath must not contain '.' segments — drop it".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wd(path: &str, sub: &str) -> BackupStorage {
        BackupStorage {
            storage_type: StorageType::Wolfdisk,
            path: path.to_string(),
            wolfdisk_subpath: sub.to_string(),
            ..BackupStorage::default()
        }
    }

    #[test]
    fn resolved_local_path_no_subpath_returns_mount_root() {
        let s = wd("/mnt/wolfdisk-data", "");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data");
    }

    #[test]
    fn resolved_local_path_joins_subpath() {
        let s = wd("/mnt/wolfdisk-data", "backups/prod");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data/backups/prod");
    }

    #[test]
    fn resolved_local_path_strips_leading_trailing_slashes() {
        let s = wd("/mnt/wolfdisk-data/", "/backups/prod/");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data/backups/prod");
    }

    #[test]
    fn resolved_local_path_drops_dot_dot_segments() {
        // The lenient resolver is defence in depth — the API save
        // boundary rejects `..` outright, but if a hand-edited
        // config file makes it past, we still don't escape the mount.
        let s = wd("/mnt/wolfdisk-data", "../../etc/passwd");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data/etc/passwd");
    }

    #[test]
    fn resolved_local_path_for_local_returns_path_unchanged() {
        let s = BackupStorage {
            storage_type: StorageType::Local,
            path: "/var/lib/wolfstack/backups".into(),
            wolfdisk_subpath: "ignored".into(),  // shouldn't apply for Local
            ..BackupStorage::default()
        };
        assert_eq!(s.resolved_local_path(), "/var/lib/wolfstack/backups");
    }

    #[test]
    fn validate_subpath_rejects_dot_dot() {
        assert!(BackupStorage::validate_wolfdisk_subpath("../etc").is_err());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups/../../etc").is_err());
    }

    #[test]
    fn validate_subpath_rejects_single_dot() {
        // Resolver silently strips `.` segments; the validator
        // rejects them so the operator gets clear feedback rather
        // than a surprise normalisation.
        assert!(BackupStorage::validate_wolfdisk_subpath("./backups").is_err());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups/./prod").is_err());
    }

    #[test]
    fn validate_subpath_rejects_consecutive_slashes() {
        assert!(BackupStorage::validate_wolfdisk_subpath("backups//prod").is_err());
    }

    #[test]
    fn validate_subpath_accepts_empty_and_normal() {
        assert!(BackupStorage::validate_wolfdisk_subpath("").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("   ").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups/prod").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("/backups/prod/").is_ok());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackupFrequency {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSchedule {
    pub id: String,
    pub name: String,
    pub frequency: BackupFrequency,
    /// Time of day to run (HH:MM format)
    pub time: String,
    /// Number of backups to keep (0 = unlimited)
    pub retention: u32,
    /// Backup all targets or specific list
    pub backup_all: bool,
    /// Specific targets if backup_all is false
    #[serde(default)]
    pub targets: Vec<BackupTarget>,
    /// Where to store backups
    pub storage: BackupStorage,
    pub enabled: bool,
    /// Last time this schedule ran (ISO 8601)
    #[serde(default)]
    pub last_run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackupStatus {
    Completed,
    Failed,
    InProgress,
}

/// One Docker mount captured into a backup. Lets the UI show what's in
/// each backup ("3 volumes, 2 binds") without re-reading the tarball,
/// and the restore path knows where to put each piece back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    /// "volume" | "bind" | "tmpfs" (tmpfs is recorded for visibility but
    /// never actually backed up — it's by definition ephemeral).
    #[serde(rename = "type")]
    pub mount_type: String,
    /// For volume: the named-volume name. For bind: the host source path.
    pub source: String,
    /// Where the container sees this mounted (e.g. "/var/lib/postgresql/data").
    pub destination: String,
    /// Filename inside the wrapper tarball (`volumes/vol-foo.tar.gz` or
    /// `binds/bind-0.tar.gz`). Empty when this mount was skipped (tmpfs,
    /// missing source, or refused by the safety deny-list).
    #[serde(default)]
    pub archive_path: String,
    /// On-disk size of the tarball (uncompressed source size hint).
    #[serde(default)]
    pub size_bytes: u64,
    /// Reason this mount was skipped, if any (deny-list, missing source,
    /// tmpfs, etc.). Empty when the mount was successfully archived.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub skipped_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub id: String,
    pub target: BackupTarget,
    pub storage: BackupStorage,
    pub filename: String,
    pub size_bytes: u64,
    pub created_at: String,
    pub status: BackupStatus,
    #[serde(default)]
    pub error: String,
    /// Schedule ID that created this, if any
    #[serde(default)]
    pub schedule_id: String,
    /// Description of what was backed up (e.g. container image, LXC rootfs, VM disks)
    #[serde(default)]
    pub comments: String,
    /// Hostname of the node that performed the backup
    #[serde(default)]
    pub node_hostname: String,
    /// Docker container config (docker inspect JSON) for restoring with original settings
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub docker_config: String,
    /// Mounts captured into this backup (Docker only). Empty for non-
    /// Docker entries and for legacy backups created before v20.11.0
    /// (those used a flat `docker save | gzip` with no volume capture).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountInfo>,
}

/// Permissive deny-list of host paths we refuse to back up via bind
/// mounts. Backing these up is either catastrophic (root, /var/lib/docker
/// recursion, kernel virtual filesystems) or pointlessly dangerous —
/// the user almost certainly did not mean to capture these into a user-
/// accessible tarball. Subpaths of /etc, /sys, /proc, /dev, /boot are
/// blocked too (their content is system state, not application data).
/// Everything else is allowed — admins binding /opt/myapp, /srv/data,
/// /home/x/stuff, /var/www, /var/log/myapp, /mnt/disk, etc. all work.
fn bind_source_safe(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("source path is empty".into());
    }
    let canonical = path.trim_end_matches('/');
    if canonical.is_empty() || canonical == "" {
        return Err("refusing to back up the host root filesystem '/'".into());
    }
    let exact_deny: &[&str] = &[
        "/", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/var", "/run", "/tmp",
    ];
    if exact_deny.iter().any(|d| *d == canonical) {
        return Err(format!("refusing to back up system path '{}' — bind a specific subdirectory instead", canonical));
    }
    let prefix_deny: &[&str] = &[
        "/etc", "/sys", "/proc", "/dev", "/boot", "/var/lib/docker",
    ];
    for p in prefix_deny {
        if canonical == *p || canonical.starts_with(&format!("{}/", p)) {
            return Err(format!(
                "refusing to back up '{}' — paths under {} are system state and not safe to archive",
                canonical, p
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(default)]
    pub schedules: Vec<BackupSchedule>,
    #[serde(default)]
    pub entries: Vec<BackupEntry>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            schedules: Vec::new(),
            entries: Vec::new(),
        }
    }
}

// ─── Config Persistence ───

pub fn load_config() -> BackupConfig {
    match fs::read_to_string(&backup_config_path()) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => BackupConfig::default(),
    }
}

pub fn save_config(config: &BackupConfig) -> Result<(), String> {
    let path = backup_config_path();
    let dir = Path::new(&path).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize backup config: {}", e))?;
    fs::write(&path, json)
        .map_err(|e| format!("Failed to write backup config: {}", e))
}

// ─── Backup Functions ───

/// Create staging directory
fn ensure_staging_dir() -> Result<PathBuf, String> {
    let path = PathBuf::from(backup_staging_dir());
    fs::create_dir_all(&path).map_err(|e| format!("Failed to create staging dir: {}", e))?;
    Ok(path)
}

/// Backup a Docker container — commit + save + gzip
/// Returns (path, size, docker_inspect_json)
/// Back up a Docker container including its volumes and bind mounts.
///
/// The output tarball is a *wrapper* containing:
///   inspect.json              ← `docker inspect` output (the original docker_config)
///   mounts.json               ← list of MountInfo, telling restore where each archive goes
///   image.tar.gz              ← `docker commit` + `docker save | gzip` (existing v20.10.x behaviour)
///   volumes/vol-{name}.tar.gz ← per named volume, content of /var/lib/docker/volumes/{name}/_data
///   binds/bind-{idx}.tar.gz   ← per bind mount, content of the host source path
///
/// Legacy v20.10.x backups (just `docker save | gzip`) are still
/// restorable — `restore_docker` detects the format by looking for
/// `inspect.json` inside the outer tarball.
///
/// Bind mounts to system paths (/, /etc, /var/lib/docker, etc.) are
/// refused with a recorded skipped_reason so the user can tell from the
/// backup metadata what was excluded and why.
pub fn backup_docker(name: &str) -> Result<(PathBuf, u64, String, Vec<MountInfo>), String> {
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("docker-{}-{}.tar.gz", name, timestamp);
    let final_path = staging.join(&filename);
    let temp_image = format!("wolfstack-backup/{}", name);

    // Per-backup work area we'll tar up at the end.
    let work_id = Uuid::new_v4().to_string();
    let work_dir = staging.join(format!("docker-work-{}", work_id));
    fs::create_dir_all(work_dir.join("volumes"))
        .map_err(|e| format!("Failed to create work dir: {}", e))?;
    fs::create_dir_all(work_dir.join("binds"))
        .map_err(|e| format!("Failed to create binds dir: {}", e))?;

    // Save container config (docker inspect) for restore.
    let docker_config = Command::new("docker")
        .args(["inspect", name])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // Parse the Mounts[] array — populated by docker for every
    // -v / --mount on the container, regardless of whether the source
    // is a named volume or a host bind.
    let inspect_val: serde_json::Value = serde_json::from_str(&docker_config)
        .unwrap_or(serde_json::Value::Null);
    let mounts_arr = inspect_val.get(0)
        .and_then(|c| c.get("Mounts"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    let mut mounts: Vec<MountInfo> = Vec::new();
    for (idx, m) in mounts_arr.iter().enumerate() {
        let mtype = m.get("Type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let source = m.get("Source").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let destination = m.get("Destination").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vol_name = m.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();

        match mtype.as_str() {
            "volume" => {
                // Named volume — find its data dir on the host. Source
                // is usually /var/lib/docker/volumes/{name}/_data already.
                let data_dir = if !source.is_empty() && Path::new(&source).is_dir() {
                    source.clone()
                } else if !vol_name.is_empty() {
                    format!("/var/lib/docker/volumes/{}/_data", vol_name)
                } else {
                    String::new()
                };
                let label = if !vol_name.is_empty() { vol_name.clone() } else { format!("idx{}", idx) };
                let archive_rel = format!("volumes/vol-{}.tar.gz", sanitize_archive_name(&label));
                let archive_abs = work_dir.join(&archive_rel);

                if data_dir.is_empty() || !Path::new(&data_dir).is_dir() {
                    mounts.push(MountInfo {
                        mount_type: "volume".into(),
                        source: vol_name.clone(),
                        destination: destination.clone(),
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: format!("volume data directory not found ({})", data_dir),
                    });
                    continue;
                }
                match tar_dir_to_gz(&data_dir, &archive_abs) {
                    Ok(size) => {
                        mounts.push(MountInfo {
                            mount_type: "volume".into(),
                            source: vol_name,
                            destination,
                            archive_path: archive_rel,
                            size_bytes: size,
                            skipped_reason: String::new(),
                        });
                    }
                    Err(e) => {
                        mounts.push(MountInfo {
                            mount_type: "volume".into(),
                            source: vol_name,
                            destination,
                            archive_path: String::new(),
                            size_bytes: 0,
                            skipped_reason: format!("tar failed: {}", e),
                        });
                    }
                }
            }
            "bind" => {
                if let Err(reason) = bind_source_safe(&source) {
                    warn!("backup_docker: skipping bind mount {} -> {}: {}", source, destination, reason);
                    mounts.push(MountInfo {
                        mount_type: "bind".into(),
                        source,
                        destination,
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: reason,
                    });
                    continue;
                }
                if !Path::new(&source).exists() {
                    mounts.push(MountInfo {
                        mount_type: "bind".into(),
                        source,
                        destination,
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: "host source path does not exist".into(),
                    });
                    continue;
                }
                let archive_rel = format!("binds/bind-{}.tar.gz", idx);
                let archive_abs = work_dir.join(&archive_rel);
                match tar_path_to_gz(&source, &archive_abs) {
                    Ok(size) => {
                        mounts.push(MountInfo {
                            mount_type: "bind".into(),
                            source,
                            destination,
                            archive_path: archive_rel,
                            size_bytes: size,
                            skipped_reason: String::new(),
                        });
                    }
                    Err(e) => {
                        mounts.push(MountInfo {
                            mount_type: "bind".into(),
                            source,
                            destination,
                            archive_path: String::new(),
                            size_bytes: 0,
                            skipped_reason: format!("tar failed: {}", e),
                        });
                    }
                }
            }
            _ => {
                // tmpfs / npipe / unknown — record but don't archive.
                mounts.push(MountInfo {
                    mount_type: mtype,
                    source,
                    destination,
                    archive_path: String::new(),
                    size_bytes: 0,
                    skipped_reason: "tmpfs/unsupported mount type — not archived".into(),
                });
            }
        }
    }

    // Commit + save the image into work_dir/image.tar.gz. Same as
    // pre-v20.11.0 behaviour, just in a subdirectory now.
    let image_path = work_dir.join("image.tar.gz");
    let commit = Command::new("docker")
        .env("DOCKER_CONTENT_TRUST", "0")
        .args(["commit", name, &temp_image])
        .output()
        .map_err(|e| format!("Failed to commit container: {}", e))?;
    if !commit.status.success() {
        let _ = fs::remove_dir_all(&work_dir);
        return Err(format!("Docker commit failed: {}", String::from_utf8_lossy(&commit.stderr)));
    }
    let save = Command::new("sh")
        .args(["-c", &format!("docker save '{}' | gzip > '{}'", temp_image, image_path.display())])
        .output()
        .map_err(|e| format!("Failed to save image: {}", e))?;
    let _ = Command::new("docker").args(["rmi", &temp_image]).output();
    if !save.status.success() {
        let _ = fs::remove_dir_all(&work_dir);
        return Err(format!("Docker save failed: {}", String::from_utf8_lossy(&save.stderr)));
    }

    // inspect.json + mounts.json — the metadata restore will read.
    fs::write(work_dir.join("inspect.json"), &docker_config)
        .map_err(|e| format!("Failed to write inspect.json: {}", e))?;
    let mounts_json = serde_json::to_string_pretty(&mounts)
        .map_err(|e| format!("Failed to serialise mounts: {}", e))?;
    fs::write(work_dir.join("mounts.json"), &mounts_json)
        .map_err(|e| format!("Failed to write mounts.json: {}", e))?;

    // Wrap the whole work_dir into the final backup tarball.
    let wrap = Command::new("tar")
        .arg("czf")
        .arg(&final_path)
        .arg("-C")
        .arg(&work_dir)
        .arg(".")
        .output()
        .map_err(|e| format!("Failed to wrap backup tarball: {}", e))?;
    let _ = fs::remove_dir_all(&work_dir);
    if !wrap.status.success() {
        return Err(format!("tar wrap failed: {}", String::from_utf8_lossy(&wrap.stderr)));
    }

    let size = fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    Ok((final_path, size, docker_config, mounts))
}

/// Sanitize a string for use as a filename component. Volume names are
/// usually fine but compose can produce `myproject_data` which is OK,
/// while user-supplied names could contain slashes / spaces.
fn sanitize_archive_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

/// tar.gz a directory's contents (NOT the directory itself) into the
/// given archive path. Returns the resulting archive size in bytes.
fn tar_dir_to_gz(src_dir: &str, archive: &Path) -> Result<u64, String> {
    let out = Command::new("tar")
        .arg("czf")
        .arg(archive)
        .arg("-C")
        .arg(src_dir)
        .arg(".")
        .output()
        .map_err(|e| format!("tar spawn failed: {}", e))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(fs::metadata(archive).map(|m| m.len()).unwrap_or(0))
}

/// tar.gz an arbitrary path (file or dir). Used for bind mounts where
/// `Source` may be a file (e.g. a single config) or a directory.
fn tar_path_to_gz(src: &str, archive: &Path) -> Result<u64, String> {
    let p = Path::new(src);
    let (parent, name) = if p.is_dir() {
        // tar -C parent name → archive contains a "name" entry at the root.
        let parent = p.parent().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|| "/".into());
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| ".".into());
        (parent, name)
    } else {
        let parent = p.parent().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|| ".".into());
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        (parent, name)
    };
    let out = Command::new("tar")
        .arg("czf")
        .arg(archive)
        .arg("-C")
        .arg(&parent)
        .arg(&name)
        .output()
        .map_err(|e| format!("tar spawn failed: {}", e))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(fs::metadata(archive).map(|m| m.len()).unwrap_or(0))
}

/// Backup an LXC container — tar rootfs + config
pub fn backup_lxc(name: &str) -> Result<(PathBuf, u64), String> {

    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");

    // Proxmox: use vzdump which properly handles ZFS/LVM/Ceph storage backends
    if crate::containers::is_proxmox() {
        return backup_lxc_proxmox(name, &staging, &timestamp.to_string());
    }

    // Native LXC: tar the container directory (rootfs + config)
    let filename = format!("lxc-{}-{}.tar.gz", name, timestamp);
    let tar_path = staging.join(&filename);

    // Check if container is running — stop it for consistent backup
    let was_running = is_lxc_running(name);
    if was_running {
        let _ = Command::new("lxc-stop").args(["-n", name]).output();
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    // Check LXC path — could be /var/lib/lxc/{name} or custom storage
    let lxc_base = crate::containers::lxc_base_dir(name);
    let lxc_path = format!("{}/{}", lxc_base, name);
    if !Path::new(&lxc_path).exists() {
        if was_running {
            let _ = Command::new("lxc-start").args(["-n", name]).output();
        }
        return Err(format!("LXC container path not found: {}", lxc_path));
    }

    // Create tar.gz of the entire container directory (rootfs + config)
    let output = Command::new("tar")
        .args(["czf", &tar_path.to_string_lossy(), "-C", &lxc_base, name])
        .output()
        .map_err(|e| format!("Failed to tar LXC container: {}", e))?;

    // Restart if it was running
    if was_running {
        let _ = Command::new("lxc-start").args(["-n", name]).output();
    }

    if !output.status.success() {
        return Err(format!("LXC tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    Ok((tar_path, size))
}

/// Proxmox LXC backup using vzdump — handles ZFS, LVM, Ceph, and directory storage
fn backup_lxc_proxmox(vmid: &str, staging: &Path, timestamp: &str) -> Result<(PathBuf, u64), String> {
    // vzdump creates a full container backup including rootfs on any storage backend
    // --mode snapshot uses LVM/ZFS snapshots for live backup when available,
    // falls back to suspend mode, then stop mode
    let output = Command::new("vzdump")
        .args([
            vmid,
            "--dumpdir", &staging.to_string_lossy(),
            "--mode", "snapshot",
            "--compress", "zstd",
        ])
        .output()
        .map_err(|e| format!("vzdump failed to start: {}", e))?;

    // Combine stdout+stderr — vzdump may log the archive path to either
    let all_output = format!("{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        // Snapshot mode may not be supported (e.g. directory storage) — retry with stop mode
        let output2 = Command::new("vzdump")
            .args([
                vmid,
                "--dumpdir", &staging.to_string_lossy(),
                "--mode", "stop",
                "--compress", "zstd",
            ])
            .output()
            .map_err(|e| format!("vzdump (stop mode) failed to start: {}", e))?;

        if !output2.status.success() {
            let stderr2 = String::from_utf8_lossy(&output2.stderr);
            return Err(format!("vzdump failed: {}", stderr2.trim()));
        }

        let all_output2 = format!("{}{}",
            String::from_utf8_lossy(&output2.stdout),
            String::from_utf8_lossy(&output2.stderr));
        return find_vzdump_result(&all_output2, staging, vmid, timestamp);
    }

    find_vzdump_result(&all_output, staging, vmid, timestamp)
}

/// Locate the vzdump archive and return its path + size
fn find_vzdump_result(stdout: &str, staging: &Path, vmid: &str, _timestamp: &str) -> Result<(PathBuf, u64), String> {
    // Try to find the archive from vzdump output
    for line in stdout.lines() {
        if line.contains("creating") && line.contains("vzdump") {
            if let Some(start) = line.find('\'') {
                if let Some(end) = line.rfind('\'') {
                    if start < end {
                        let path = PathBuf::from(&line[start+1..end]);
                        if path.exists() {
                            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                            return Ok((path, size));
                        }
                    }
                }
            }
        }
    }

    // Fallback: search staging dir for the newest vzdump file for this VMID
    if let Ok(entries) = fs::read_dir(staging) {
        let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("vzdump-lxc-{}-", vmid)) {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if best.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                            best = Some((entry.path(), modified));
                        }
                    }
                }
            }
        }
        if let Some((path, _)) = best {
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            return Ok((path, size));
        }
    }

    Err(format!("vzdump completed but could not find archive for VMID {}", vmid))
}

/// Check if an LXC container is running
fn is_lxc_running(name: &str) -> bool {
    Command::new("lxc-info")
        .args(["-n", name, "-s"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

/// Backup a KVM/QEMU VM — copy disk images + JSON config
pub fn backup_vm(name: &str) -> Result<(PathBuf, u64), String> {

    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("vm-{}-{}.tar.gz", name, timestamp);
    let tar_path = staging.join(&filename);

    let vm_base = "/var/lib/wolfstack/vms";
    let config_file = format!("{}.json", name);
    let config_path = format!("{}/{}", vm_base, config_file);
    if !Path::new(&config_path).exists() {
        return Err(format!("VM config not found: {}", config_path));
    }

    // Check if VM is running (check for QEMU process)
    let was_running = is_vm_running(name);
    if was_running {

        // Send ACPI shutdown
        let _ = Command::new("sh")
            .args(["-c", &format!(
                "echo 'system_powerdown' | socat - UNIX-CONNECT:/var/run/wolfstack-vm-{}.sock 2>/dev/null || true", name
            )])
            .output();
        std::thread::sleep(std::time::Duration::from_secs(5));
        // Force kill if still running
        if is_vm_running(name) {
            let _ = Command::new("pkill")
                .args(["-f", &format!("wolfstack-vm-{}", name)])
                .output();
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    // Collect all files belonging to this VM:
    // - {name}.json (config - required)
    // - {name}.qcow2 (OS disk)
    // - {name}.log, {name}.runtime.json (optional)
    // - {name}/ subdirectory (extra volumes, if exists)
    let mut tar_items: Vec<String> = vec![config_file];
    
    // Add OS disk image
    let disk_file = format!("{}.qcow2", name);
    if Path::new(&format!("{}/{}", vm_base, disk_file)).exists() {
        tar_items.push(disk_file);
    }
    
    // Add optional files (log, runtime)
    for ext in &["log", "runtime.json"] {
        let f = format!("{}.{}", name, ext);
        if Path::new(&format!("{}/{}", vm_base, f)).exists() {
            tar_items.push(f);
        }
    }
    
    // Add VM subdirectory if it exists (extra volumes stored here)
    if Path::new(&format!("{}/{}", vm_base, name)).is_dir() {
        tar_items.push(name.to_string());
    }

    let output = Command::new("tar")
        .arg("czf")
        .arg(&tar_path.to_string_lossy().to_string())
        .arg("-C")
        .arg(vm_base)
        .args(&tar_items)
        .output()
        .map_err(|e| format!("Failed to tar VM: {}", e))?;

    if !output.status.success() {
        return Err(format!("VM tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Restart if it was running
    if was_running {

    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

    Ok((tar_path, size))
}

/// Check if a VM is running
fn is_vm_running(name: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", &format!("wolfstack-vm-{}", name)])
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Backup WolfStack configuration files
pub fn backup_config() -> Result<(PathBuf, u64), String> {

    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("config-wolfstack-{}.tar.gz", timestamp);
    let tar_path = staging.join(&filename);

    // Create a temp directory with all config files
    let temp_dir = staging.join("config-bundle");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Copy all relevant config files
    let config_files = [
        "/etc/wolfstack/config.toml",
        "/etc/wolfstack/ip-mappings.json",
        "/etc/wolfstack/storage.json",
        "/etc/wolfstack/backups.json",
        "/etc/wolfnet/config.toml",
    ];

    for path in &config_files {
        if Path::new(path).exists() {
            let dest = temp_dir.join(
                Path::new(path)
                    .strip_prefix("/")
                    .unwrap_or(Path::new(path))
            );
            if let Some(parent) = dest.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::copy(path, &dest);
        }
    }

    // Also include VM configs (JSON only, not disk images)
    let vm_config_dir = Path::new("/var/lib/wolfstack/vms");
    if vm_config_dir.exists() {
        if let Ok(entries) = fs::read_dir(vm_config_dir) {
            for entry in entries.flatten() {
                let config_file = entry.path().join("config.json");
                if config_file.exists() {
                    let dest = temp_dir.join(format!("var/lib/wolfstack/vms/{}/config.json",
                        entry.file_name().to_string_lossy()));
                    if let Some(parent) = dest.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::copy(&config_file, &dest);
                }
            }
        }
    }

    // Tar the bundle
    let output = Command::new("tar")
        .args(["czf", &tar_path.to_string_lossy(), "-C", &temp_dir.to_string_lossy(), "."])
        .output()
        .map_err(|e| format!("Failed to tar config: {}", e))?;

    let _ = fs::remove_dir_all(&temp_dir);

    if !output.status.success() {
        return Err(format!("Config tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

    Ok((tar_path, size))
}

/// Backup everything on the server
pub fn backup_all(storage: &BackupStorage) -> Vec<BackupEntry> {
    let mut entries = Vec::new();

    // Backup all Docker containers
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        for name in names {
            entries.push(create_backup_entry(
                BackupTarget { target_type: BackupTargetType::Docker, name: name.clone(), hostname: None, state: None, specs: None },
                storage,
            ));
        }
    }

    // Backup all LXC containers
    if let Ok(output) = Command::new("lxc-ls").output() {
        let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        for name in names {
            entries.push(create_backup_entry(
                BackupTarget { target_type: BackupTargetType::Lxc, name: name.clone(), hostname: None, state: None, specs: None },
                storage,
            ));
        }
    }

    // Backup all VMs
    let vm_dir = Path::new("/var/lib/wolfstack/vms");
    if vm_dir.exists() {
        if let Ok(dirs) = fs::read_dir(vm_dir) {
            for entry in dirs.flatten() {
                if entry.path().is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    entries.push(create_backup_entry(
                        BackupTarget { target_type: BackupTargetType::Vm, name, hostname: None, state: None, specs: None },
                        storage,
                    ));
                }
            }
        }
    }

    // Backup config
    entries.push(create_backup_entry(
        BackupTarget { target_type: BackupTargetType::Config, name: String::new(), hostname: None, state: None, specs: None },
        storage,
    ));

    entries
}

/// Get the local hostname for backup entries
fn local_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Get the local cluster name from /etc/wolfstack/self_cluster.json
/// Used as fallback when cluster name isn't passed from the API layer
pub fn local_cluster_name() -> String {
    std::fs::read_to_string(&crate::paths::get().self_cluster_config)
        .ok()
        .and_then(|data| serde_json::from_str::<String>(&data).ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "WolfStack".to_string())
}

/// Generate a descriptive comment for a backup target, prefixed with cluster name
fn backup_comments(target: &BackupTarget) -> String {
    backup_comments_with_cluster(target, &local_cluster_name())
}

fn backup_comments_with_cluster(target: &BackupTarget, cluster: &str) -> String {
    let detail = match target.target_type {
        BackupTargetType::Docker => {
            let image = Command::new("docker")
                .args(["inspect", "--format", "{{.Config.Image}}", &target.name])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if image.is_empty() {
                format!("Docker container: {}", target.name)
            } else {
                format!("Docker container: {} (image: {})", target.name, image)
            }
        }
        BackupTargetType::Lxc => {
            if crate::containers::is_proxmox() {
                let hostname = target.hostname.as_deref().unwrap_or("");
                if hostname.is_empty() || hostname == target.name {
                    format!("LXC container: {} (vzdump full backup)", target.name)
                } else {
                    format!("LXC container: {} ({}) (vzdump full backup)", target.name, hostname)
                }
            } else {
                format!("LXC container: {} (rootfs + config)", target.name)
            }
        }
        BackupTargetType::Vm => {
            let config_path = format!("/var/lib/wolfstack/vms/{}.json", target.name);
            if let Ok(data) = std::fs::read_to_string(&config_path) {
                if let Ok(vm) = serde_json::from_str::<serde_json::Value>(&data) {
                    let os = vm.get("os").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let mem = vm.get("memory_mb").and_then(|v| v.as_u64()).unwrap_or(0);
                    return format!("[{}] VM: {} (OS: {}, {}MB RAM, disks + config)", cluster, target.name, os, mem);
                }
            }
            format!("VM: {} (disks + config)", target.name)
        }
        BackupTargetType::Config => "WolfStack configuration files".to_string(),
    };
    format!("[{}] {}", cluster, detail)
}

/// Create a single backup entry — performs the backup and stores it
fn create_backup_entry(target: BackupTarget, storage: &BackupStorage) -> BackupEntry {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let hostname = local_hostname();
    let comments = backup_comments(&target);

    let (result, docker_config, mounts) = match target.target_type {
        BackupTargetType::Docker => {
            match backup_docker(&target.name) {
                Ok((path, size, config, m)) => (Ok((path, size)), config, m),
                Err(e) => (Err(e), String::new(), Vec::new()),
            }
        }
        BackupTargetType::Lxc => (backup_lxc(&target.name), String::new(), Vec::new()),
        BackupTargetType::Vm => (backup_vm(&target.name), String::new(), Vec::new()),
        BackupTargetType::Config => (backup_config(), String::new(), Vec::new()),
    };

    match result {
        Ok((local_path, size)) => {
            // Store to target location
            let filename = local_path.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("backup-{}.tar.gz", id));

            let pbs_notes = format!("Cluster: {} | Node: {} | {}", local_cluster_name(), hostname, comments);

            match store_backup_with_notes(&local_path, storage, &filename, Some(&pbs_notes)) {
                Ok(_) => {
                    // Remove staging file after successful store
                    let _ = fs::remove_file(&local_path);
                    BackupEntry {
                        id,
                        target,
                        storage: storage.clone(),
                        filename,
                        size_bytes: size,
                        created_at: now,
                        status: BackupStatus::Completed,
                        error: String::new(),
                        schedule_id: String::new(),
                        comments,
                        node_hostname: hostname,
                        docker_config,
                        mounts,
                    }
                },
                Err(e) => {
                    let _ = fs::remove_file(&local_path);
                    error!("Failed to store backup: {}", e);
                    BackupEntry {
                        id,
                        target,
                        storage: storage.clone(),
                        filename,
                        size_bytes: size,
                        created_at: now,
                        status: BackupStatus::Failed,
                        error: e,
                        schedule_id: String::new(),
                        comments,
                        node_hostname: hostname,
                        docker_config: String::new(),
                        mounts: Vec::new(),
                    }
                }
            }
        },
        Err(e) => {
            error!("Backup failed for {:?}: {}", target.target_type, e);
            BackupEntry {
                id,
                target,
                storage: storage.clone(),
                filename: String::new(),
                size_bytes: 0,
                created_at: now,
                status: BackupStatus::Failed,
                error: e,
                schedule_id: String::new(),
                comments,
                node_hostname: hostname,
                docker_config: String::new(),
                mounts: Vec::new(),
            }
        }
    }
}

// ─── Storage Functions ───

/// Store a backup file to the configured storage target
fn store_backup_with_notes(local_path: &Path, storage: &BackupStorage, filename: &str, notes: Option<&str>) -> Result<(), String> {
    match storage.storage_type {
        StorageType::Local => store_local(local_path, &storage.path, filename),
        StorageType::S3 => store_s3(local_path, storage, filename),
        StorageType::Remote => store_remote(local_path, &storage.remote_url, filename),
        StorageType::Wolfdisk => store_local(local_path, &storage.resolved_local_path(), filename),
        StorageType::Pbs => store_pbs_with_notes(local_path, storage, filename, notes),
        StorageType::Nfs => {
            let dir = ensure_nfs_mounted(storage)?;
            store_local(local_path, &dir, filename)
        }
        StorageType::Smb => {
            let dir = ensure_smb_mounted(storage)?;
            store_local(local_path, &dir, filename)
        }
    }
}

/// Build the stable per-destination mount point. Destinations are
/// identified by the source spec so two backup configs pointing at the
/// same share reuse one mount.
fn nas_mount_dir(kind: &str, source: &str, subpath: &str) -> String {
    // Slashes and colons can't live in a dirname — replace with `_`.
    let key: String = source.chars().map(|c| match c {
        '/' | ':' | '\\' | ' ' => '_',
        _ => c,
    }).collect();
    let mut p = format!("/mnt/wolfstack-backup/{}-{}", kind, key);
    if !subpath.is_empty() {
        p.push('/');
        p.push_str(subpath.trim_matches('/'));
    }
    p
}

/// Check whether the helper package that provides a userspace mount tool
/// (`mount.nfs`, `mount.cifs`) is installed. When missing, emit the
/// standard MISSING_PACKAGE marker (see storage::MISSING_PACKAGE_MARKER)
/// so the API + UI can prompt the user and run the install in a live
/// terminal instead of doing it silently from a mount request.
fn ensure_mount_helper(binary: &str, debian_pkg: &str, redhat_pkg: &str) -> Result<(), String> {
    if std::path::Path::new(&format!("/sbin/{}", binary)).exists()
        || std::path::Path::new(&format!("/usr/sbin/{}", binary)).exists()
    {
        return Ok(());
    }
    Err(format!(
        "{}{}|{}|{}",
        crate::storage::MISSING_PACKAGE_MARKER, binary, debian_pkg, redhat_pkg
    ))
}

/// Mount (idempotently) an NFS export for backups and return the local
/// path that store_local should write into. Reuses the existing export
/// if already mounted.
/// Validate a backup storage config by exercising whatever setup step the
/// type actually needs. Used by the "test destination" endpoint so the UI
/// can catch problems (missing mount helper, bad credentials) at save time
/// rather than letting a scheduled backup fail in the background hours
/// later. Returns Ok on success; on failure the error string may carry the
/// standard MISSING_PACKAGE marker that the frontend knows how to prompt
/// on.
pub fn test_storage(storage: &BackupStorage) -> Result<String, String> {
    match storage.storage_type {
        StorageType::Nfs => ensure_nfs_mounted(storage).map(|p| format!("NFS mount OK at {}", p)),
        StorageType::Smb => ensure_smb_mounted(storage).map(|p| format!("SMB mount OK at {}", p)),
        StorageType::Local | StorageType::Wolfdisk => {
            if storage.path.is_empty() {
                return Err("path is required".into());
            }
            if matches!(storage.storage_type, StorageType::Wolfdisk) {
                BackupStorage::validate_wolfdisk_subpath(&storage.wolfdisk_subpath)?;
            }
            let target = storage.resolved_local_path();
            std::fs::create_dir_all(&target)
                .map_err(|e| format!("Failed to create {}: {}", target, e))?;
            Ok(format!("OK — writes will go to {}", target))
        }
        // S3 / Remote / PBS each have their own connectivity concerns; they
        // aren't wired through this check yet because their failure modes
        // don't benefit from the MISSING_PACKAGE install prompt.
        StorageType::S3 | StorageType::Remote | StorageType::Pbs => {
            Ok(format!("{} destinations are not pre-tested", storage.storage_type))
        }
    }
}

fn ensure_nfs_mounted(storage: &BackupStorage) -> Result<String, String> {
    if storage.nfs_source.is_empty() {
        return Err("NFS source is not configured (expected `server:/export`)".into());
    }
    ensure_mount_helper("mount.nfs", "nfs-common", "nfs-utils")?;
    let dir = nas_mount_dir("nfs", &storage.nfs_source, "");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create mount dir {}: {}", dir, e))?;
    if is_mounted(&dir) {
        return Ok(dir);
    }
    let options = if storage.nfs_options.is_empty() { "rw,soft,timeo=50" } else { storage.nfs_options.as_str() };
    let output = std::process::Command::new("mount")
        .args(["-t", "nfs", "-o", options, &storage.nfs_source, &dir])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    if !output.status.success() {
        return Err(format!("NFS mount failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(dir)
}

/// SMB/CIFS equivalent of ensure_nfs_mounted. Handles optional subpath
/// so a single share can host multiple backup trees.
fn ensure_smb_mounted(storage: &BackupStorage) -> Result<String, String> {
    if storage.smb_source.is_empty() {
        return Err("SMB source is not configured (expected `//server/share`)".into());
    }
    ensure_mount_helper("mount.cifs", "cifs-utils", "cifs-utils")?;
    // Normalise Windows-style backslashes.
    let source = storage.smb_source.replace('\\', "/");
    let source = if source.starts_with("//") { source } else { format!("//{}", source.trim_start_matches('/')) };

    let root = nas_mount_dir("smb", &source, "");
    fs::create_dir_all(&root).map_err(|e| format!("Failed to create mount dir {}: {}", root, e))?;
    if !is_mounted(&root) {
        let mut opt_parts: Vec<String> = Vec::new();
        if !storage.smb_username.is_empty() {
            opt_parts.push(format!("username={}", storage.smb_username));
            opt_parts.push(format!("password={}", storage.smb_password));
            if !storage.smb_domain.is_empty() {
                opt_parts.push(format!("domain={}", storage.smb_domain));
            }
        } else {
            opt_parts.push("guest".into());
        }
        opt_parts.push("uid=0".into());
        opt_parts.push("gid=0".into());
        opt_parts.push("file_mode=0660".into());
        opt_parts.push("dir_mode=0770".into());
        opt_parts.push("vers=3.0".into());
        if !storage.smb_options.is_empty() {
            opt_parts.push(storage.smb_options.clone());
        }
        let options = opt_parts.join(",");
        let output = std::process::Command::new("mount")
            .args(["-t", "cifs", "-o", &options, &source, &root])
            .output()
            .map_err(|e| format!("Failed to run mount: {}", e))?;
        if !output.status.success() {
            return Err(format!("SMB mount failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
    }
    // Optional subpath inside the share — create if missing.
    let dest = if storage.smb_subpath.is_empty() {
        root
    } else {
        let sub = storage.smb_subpath.trim_matches('/');
        let p = format!("{}/{}", root, sub);
        fs::create_dir_all(&p).map_err(|e| format!("Failed to create subpath {}: {}", p, e))?;
        p
    };
    Ok(dest)
}

fn is_mounted(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| s.lines().any(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts.len() >= 2 && parts[1] == path
        }))
        .unwrap_or(false)
}

/// Store backup to local path
fn store_local(local_path: &Path, dest_dir: &str, filename: &str) -> Result<(), String> {
    fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Failed to create backup dir {}: {}", dest_dir, e))?;
    let dest = Path::new(dest_dir).join(filename);
    fs::copy(local_path, &dest)
        .map_err(|e| format!("Failed to copy backup to {}: {}", dest.display(), e))?;

    Ok(())
}

/// Store backup to S3
fn store_s3(local_path: &Path, storage: &BackupStorage, filename: &str) -> Result<(), String> {


    // Use tokio runtime for the async S3 upload
    let _rt = tokio::runtime::Handle::try_current()
        .map_err(|_| "No tokio runtime available".to_string())?;

    let data = fs::read(local_path)
        .map_err(|e| format!("Failed to read backup file: {}", e))?;

    let bucket_name = storage.bucket.clone();
    let region_str = storage.region.clone();
    let endpoint_str = storage.endpoint.clone();
    let access_key = storage.access_key.clone();
    let secret_key = storage.secret_key.clone();
    let key = format!("wolfstack-backups/{}", filename);

    // Spawn blocking to avoid nested runtime issues
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let region = if endpoint_str.is_empty() {
                s3::Region::Custom {
                    region: region_str,
                    endpoint: format!("https://s3.{}.amazonaws.com", "us-east-1"),
                }
            } else {
                s3::Region::Custom {
                    region: region_str,
                    endpoint: endpoint_str,
                }
            };

            let credentials = s3::creds::Credentials::new(
                Some(&access_key),
                Some(&secret_key),
                None, None, None,
            ).map_err(|e| format!("S3 credentials error: {}", e))?;

            let bucket = s3::Bucket::new(&bucket_name, region, credentials)
                .map_err(|e| format!("S3 bucket error: {}", e))?;

            bucket.put_object(&key, &data).await
                .map_err(|e| format!("S3 upload error: {}", e))?;


            Ok::<(), String>(())
        })
    }).join().map_err(|_| "S3 upload thread panicked".to_string())?
}

/// Store backup to remote WolfStack node
fn store_remote(local_path: &Path, remote_url: &str, filename: &str) -> Result<(), String> {

    let import_url = format!("{}/api/backups/import?filename={}", 
        remote_url.trim_end_matches('/'), filename);

    let output = Command::new("curl")
        .args([
            "-s", "-f",
            "--max-time", "600",
            "-X", "POST",
            "-H", "Content-Type: application/octet-stream",
            "--data-binary", &format!("@{}", local_path.display()),
            &import_url,
        ])
        .output()
        .map_err(|e| format!("Failed to send to remote: {}", e))?;

    if !output.status.success() {
        return Err(format!("Remote transfer failed: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }


    Ok(())
}

/// Build the PBS repository string: user!token@server:datastore
fn pbs_repo_string(storage: &BackupStorage) -> String {
    if !storage.pbs_token_name.is_empty() {
        format!("{}!{}@{}:{}", storage.pbs_user, storage.pbs_token_name,
                storage.pbs_server, storage.pbs_datastore)
    } else {
        format!("{}@{}:{}", storage.pbs_user, storage.pbs_server, storage.pbs_datastore)
    }
}

/// Store backup to Proxmox Backup Server
fn store_pbs_with_notes(local_path: &Path, storage: &BackupStorage, filename: &str, notes: Option<&str>) -> Result<(), String> {
    store_pbs_with_notes_and_log(local_path, storage, filename, notes, None)
}

fn store_pbs_with_notes_and_log(local_path: &Path, storage: &BackupStorage, filename: &str, notes: Option<&str>, log: Option<&std::sync::mpsc::Sender<String>>) -> Result<(), String> {
    let repo = pbs_repo_string(storage);

    // Extract the actual VMID/container name from the filename
    // Formats: "vzdump-lxc-131-2026..." → "131", "lxc-myct-2026..." → "myct",
    //          "docker-myapp-2026..." → "myapp", "vm-myvm-2026..." → "myvm"
    let backup_id = extract_backup_id_from_filename(filename);

    // Determine backup type from filename prefix
    let backup_type = if filename.starts_with("vzdump-lxc-") || filename.starts_with("lxc-") {
        "ct"
    } else if filename.starts_with("vm-") || filename.starts_with("vzdump-qemu-") {
        "vm"
    } else {
        "host"
    };

    // Isolate this one backup file in its own subdirectory before
    // handing the directory to `proxmox-backup-client backup …pxar:DIR`.
    // The shared staging dir (`/tmp/wolfstack-backups/`) can contain
    // stale files from previous runs (e.g. from a backup that failed
    // before cleanup), and backup_all() runs many targets in sequence
    // — without isolation each snapshot's pxar archive pulls in every
    // file currently sitting in staging, which wastes PBS space and
    // makes per-snapshot restore nonsensical.
    let parent = local_path.parent().unwrap_or(Path::new("/tmp"));
    let isolate = parent.join(format!(".pbs-stage-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&isolate)
        .map_err(|e| format!("PBS stage dir: {}", e))?;
    let file_name = local_path.file_name()
        .ok_or_else(|| "local_path has no filename".to_string())?;
    let isolate_file = isolate.join(file_name);
    // Hardlink when possible so a 5 GB vzdump archive doesn't
    // double its disk footprint just for the PBS upload.
    if std::fs::hard_link(local_path, &isolate_file).is_err() {
        std::fs::copy(local_path, &isolate_file)
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&isolate);
                format!("PBS stage copy: {}", e)
            })?;
    }

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("backup")
       .arg(format!("backup.pxar:{}", isolate.display()))
       .arg("--repository").arg(&repo)
       .arg("--backup-id").arg(&backup_id)
       .arg("--backup-type").arg(backup_type);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    // Stream stderr for progress when log channel is available
    if let Some(log_tx) = log {
        use std::process::Stdio;
        use std::io::BufReader;
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .map_err(|e| format!("Failed to start proxmox-backup-client: {}", e))?;

        if let Some(stderr) = child.stderr.take() {
            use std::io::Read;
            let mut reader = BufReader::new(stderr);
            let mut buf = [0u8; 1];
            let mut line_buf = String::new();
            while reader.read(&mut buf).unwrap_or(0) > 0 {
                let ch = buf[0] as char;
                if ch == '\n' || ch == '\r' {
                    let trimmed = line_buf.trim().to_string();
                    if !trimmed.is_empty() {
                        let _ = log_tx.send(format!("  PBS: {}", trimmed));
                    }
                    line_buf.clear();
                } else {
                    line_buf.push(ch);
                }
            }
            let trimmed = line_buf.trim().to_string();
            if !trimmed.is_empty() {
                let _ = log_tx.send(format!("  PBS: {}", trimmed));
            }
        }

        let status = child.wait()
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&isolate);
                format!("PBS backup wait failed: {}", e)
            })?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&isolate);
            return Err("PBS backup failed (see log above)".to_string());
        }
    } else {
        let output = cmd.output()
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&isolate);
                format!("Failed to run proxmox-backup-client: {}", e)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let _ = std::fs::remove_dir_all(&isolate);
            return Err(format!("PBS backup failed: {}", stderr.trim()));
        }
    }
    // Drop the per-backup isolation dir now that the upload succeeded.
    // The snapshot-notes API call below only needs repo+snapshot info.
    let _ = std::fs::remove_dir_all(&isolate);

    // Set snapshot notes with cluster/node/container metadata for identification
    if let Some(notes_text) = notes {
        // Find the snapshot we just created — latest one matching our backup-type/id
        let mut list_cmd = Command::new("proxmox-backup-client");
        list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", &repo]);
        if !storage.pbs_fingerprint.is_empty() {
            list_cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
        }
        if !storage.pbs_namespace.is_empty() {
            list_cmd.arg("--ns").arg(&storage.pbs_namespace);
        }
        if !pbs_pw.is_empty() {
            list_cmd.env("PBS_PASSWORD", pbs_pw);
        }

        if let Ok(snap_out) = list_cmd.output() {
            if let Ok(snaps) = serde_json::from_slice::<serde_json::Value>(&snap_out.stdout) {
                if let Some(arr) = snaps.as_array() {
                    let mut best_time: i64 = 0;
                    let mut best_snap = String::new();
                    for s in arr {
                        let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
                        let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
                        let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
                        if st == backup_type && si == backup_id && stime > best_time {
                            best_time = stime;
                            best_snap = format!("{}/{}/{}", st, si, stime);
                        }
                    }
                    if !best_snap.is_empty() {
                        // proxmox-backup-client snapshot notes update [OPTIONS] <snapshot> <notes>
                        //
                        // Both `snapshot` and `notes` are POSITIONAL.
                        // Earlier versions passed `--notes <text>`, which the
                        // PBS CLI parser dropped as an unknown-option value
                        // and then rejected with "parameter verification
                        // failed - 'notes': missing argument" (reported
                        // 2026-05-05).
                        //
                        // We put the trailing `--` before the positionals so
                        // a notes string that happens to begin with `-`
                        // (e.g. an operator-supplied comment field) can't
                        // be re-interpreted as an option. Spaces in the
                        // notes text are preserved automatically — every
                        // arg goes to the child via execve as one argv
                        // element, no shell expansion.
                        let mut notes_cmd = Command::new("proxmox-backup-client");
                        notes_cmd.args(["snapshot", "notes", "update", "--repository", &repo]);
                        if !storage.pbs_fingerprint.is_empty() {
                            notes_cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
                        }
                        if !storage.pbs_namespace.is_empty() {
                            notes_cmd.arg("--ns").arg(&storage.pbs_namespace);
                        }
                        notes_cmd.arg("--").arg(&best_snap).arg(notes_text);
                        if !pbs_pw.is_empty() {
                            notes_cmd.env("PBS_PASSWORD", pbs_pw);
                        }
                        let notes_result = notes_cmd.output();
                        if let Ok(out) = &notes_result {
                            if !out.status.success() {
                                warn!("Failed to set PBS snapshot notes: {}",
                                    String::from_utf8_lossy(&out.stderr));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Extract the container/VM ID from a backup filename
fn extract_backup_id_from_filename(filename: &str) -> String {
    // "vzdump-lxc-131-2026..." → "131"
    if filename.starts_with("vzdump-lxc-") || filename.starts_with("vzdump-qemu-") {
        let rest = filename.splitn(3, '-').nth(2).unwrap_or("");
        return rest.split('-').next().unwrap_or("unknown").to_string();
    }
    // "lxc-myct-2026..." → "myct", "docker-myapp-2026..." → "myapp", "vm-myvm-2026..." → "myvm"
    if let Some(rest) = filename.split_once('-') {
        // rest.1 = "myct-20260316-123456.tar.gz" — take everything before the timestamp
        let parts: Vec<&str> = rest.1.split('-').collect();
        // Find where the timestamp starts (8 digits)
        for (i, part) in parts.iter().enumerate() {
            if part.len() == 8 && part.chars().all(|c| c.is_ascii_digit()) {
                return parts[..i].join("-");
            }
        }
        return parts[0].to_string();
    }
    filename.split('.').next().unwrap_or("unknown").to_string()
}

/// Retrieve a backup file from storage for restore
fn retrieve_backup(entry: &BackupEntry) -> Result<PathBuf, String> {
    let staging = ensure_staging_dir()?;
    let local_path = staging.join(&entry.filename);

    match entry.storage.storage_type {
        StorageType::Local | StorageType::Wolfdisk => {
            let source = Path::new(&entry.storage.resolved_local_path()).join(&entry.filename);
            if !source.exists() {
                return Err(format!("Backup file not found: {}", source.display()));
            }
            fs::copy(&source, &local_path)
                .map_err(|e| format!("Failed to copy backup: {}", e))?;
        },
        StorageType::S3 => {
            retrieve_from_s3(entry, &local_path)?;
        },
        StorageType::Remote => {
            return Err("Cannot restore from remote node storage directly — download the backup file first".to_string());
        },
        StorageType::Pbs => {
            retrieve_from_pbs(entry, &local_path)?;
        },
        StorageType::Nfs => {
            let dir = ensure_nfs_mounted(&entry.storage)?;
            let source = Path::new(&dir).join(&entry.filename);
            if !source.exists() {
                return Err(format!("Backup file not found: {}", source.display()));
            }
            fs::copy(&source, &local_path)
                .map_err(|e| format!("Failed to copy backup: {}", e))?;
        },
        StorageType::Smb => {
            let dir = ensure_smb_mounted(&entry.storage)?;
            let source = Path::new(&dir).join(&entry.filename);
            if !source.exists() {
                return Err(format!("Backup file not found: {}", source.display()));
            }
            fs::copy(&source, &local_path)
                .map_err(|e| format!("Failed to copy backup: {}", e))?;
        },
    }

    Ok(local_path)
}

/// Download a backup from S3
fn retrieve_from_s3(entry: &BackupEntry, dest: &Path) -> Result<(), String> {
    let storage = &entry.storage;
    let key = format!("wolfstack-backups/{}", entry.filename);

    let bucket_name = storage.bucket.clone();
    let region_str = storage.region.clone();
    let endpoint_str = storage.endpoint.clone();
    let access_key = storage.access_key.clone();
    let secret_key = storage.secret_key.clone();
    let dest_path = dest.to_path_buf();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let region = s3::Region::Custom {
                region: region_str.clone(),
                endpoint: if endpoint_str.is_empty() {
                    format!("https://s3.{}.amazonaws.com", region_str)
                } else {
                    endpoint_str
                },
            };

            let credentials = s3::creds::Credentials::new(
                Some(&access_key),
                Some(&secret_key),
                None, None, None,
            ).map_err(|e| format!("S3 credentials error: {}", e))?;

            let bucket = s3::Bucket::new(&bucket_name, region, credentials)
                .map_err(|e| format!("S3 bucket error: {}", e))?;

            let response = bucket.get_object(&key).await
                .map_err(|e| format!("S3 download error: {}", e))?;

            fs::write(&dest_path, response.bytes())
                .map_err(|e| format!("Failed to write downloaded backup: {}", e))?;

            Ok::<(), String>(())
        })
    }).join().map_err(|_| "S3 download thread panicked".to_string())?
}

// ─── Restore Functions ───

/// Restore a Docker container from backup
/// Build docker run arguments from a docker inspect JSON
fn docker_run_args_from_inspect(inspect: &serde_json::Value) -> Vec<String> {
    let mut args = Vec::new();
    let container = if inspect.is_array() { &inspect[0] } else { inspect };
    let config = &container["Config"];
    let host_config = &container["HostConfig"];

    // Port bindings: HostConfig.PortBindings
    if let Some(bindings) = host_config["PortBindings"].as_object() {
        for (container_port, host_ports) in bindings {
            if let Some(arr) = host_ports.as_array() {
                for hp in arr {
                    let host_ip = hp["HostIp"].as_str().unwrap_or("");
                    let host_port = hp["HostPort"].as_str().unwrap_or("");
                    if !host_port.is_empty() {
                        let binding = if !host_ip.is_empty() && host_ip != "0.0.0.0" {
                            format!("{}:{}:{}", host_ip, host_port, container_port)
                        } else {
                            format!("{}:{}", host_port, container_port)
                        };
                        args.push("-p".to_string());
                        args.push(binding);
                    }
                }
            }
        }
    }

    // Environment variables: Config.Env
    if let Some(env) = config["Env"].as_array() {
        for e in env {
            if let Some(s) = e.as_str() {
                // Skip common default vars that come from the image
                if s.starts_with("PATH=") || s.starts_with("HOME=") || s.starts_with("HOSTNAME=") {
                    continue;
                }
                args.push("-e".to_string());
                args.push(s.to_string());
            }
        }
    }

    // Volume mounts: HostConfig.Binds
    if let Some(binds) = host_config["Binds"].as_array() {
        for b in binds {
            if let Some(s) = b.as_str() {
                args.push("-v".to_string());
                args.push(s.to_string());
            }
        }
    }

    // Restart policy: HostConfig.RestartPolicy
    let restart_name = host_config["RestartPolicy"]["Name"].as_str().unwrap_or("");
    if !restart_name.is_empty() && restart_name != "no" {
        let max_retry = host_config["RestartPolicy"]["MaximumRetryCount"].as_u64().unwrap_or(0);
        if restart_name == "on-failure" && max_retry > 0 {
            args.push("--restart".to_string());
            args.push(format!("on-failure:{}", max_retry));
        } else {
            args.push("--restart".to_string());
            args.push(restart_name.to_string());
        }
    } else {
        args.push("--restart".to_string());
        args.push("unless-stopped".to_string());
    }

    // Network mode: HostConfig.NetworkMode
    let network = host_config["NetworkMode"].as_str().unwrap_or("default");
    if network != "default" && network != "bridge" && !network.is_empty() {
        args.push("--network".to_string());
        args.push(network.to_string());
    }

    // Hostname
    if let Some(hostname) = config["Hostname"].as_str() {
        if !hostname.is_empty() {
            args.push("--hostname".to_string());
            args.push(hostname.to_string());
        }
    }

    // Working dir
    if let Some(workdir) = config["WorkingDir"].as_str() {
        if !workdir.is_empty() {
            args.push("-w".to_string());
            args.push(workdir.to_string());
        }
    }

    // Entrypoint override (only if different from image default)
    if let Some(ep) = config["Entrypoint"].as_array() {
        if !ep.is_empty() {
            args.push("--entrypoint".to_string());
            args.push(ep[0].as_str().unwrap_or("").to_string());
        }
    }

    // TTY and stdin (needed for interactive containers like debian, ubuntu)
    if config["Tty"].as_bool().unwrap_or(false) {
        args.push("-t".to_string());
    }
    if config["OpenStdin"].as_bool().unwrap_or(false) {
        args.push("-i".to_string());
    }

    // Privileged
    if host_config["Privileged"].as_bool().unwrap_or(false) {
        args.push("--privileged".to_string());
    }

    // Memory limit
    if let Some(mem) = host_config["Memory"].as_u64() {
        if mem > 0 {
            args.push("-m".to_string());
            args.push(format!("{}b", mem));
        }
    }

    // CPU quota
    if let Some(cpus) = host_config["NanoCpus"].as_u64() {
        if cpus > 0 {
            args.push("--cpus".to_string());
            args.push(format!("{:.2}", cpus as f64 / 1_000_000_000.0));
        }
    }

    args
}

pub fn restore_docker(entry: &BackupEntry, overwrite: bool) -> Result<String, String> {
    let container_name = &entry.target.name;

    // Check if a container with this name already exists before downloading.
    let check = Command::new("docker")
        .args(["container", "inspect", container_name])
        .output();
    let exists = check.map(|o| o.status.success()).unwrap_or(false);

    if exists && !overwrite {
        return Err(format!("CONTAINER_EXISTS:{}", container_name));
    }

    // Saved docker inspect from the backup entry — used for restoring the
    // original `docker run` flags. New-format backups also embed an
    // inspect.json inside the wrapper tarball; either source works.
    let mut inspect_json: Option<serde_json::Value> = if !entry.docker_config.is_empty() {
        serde_json::from_str(&entry.docker_config).ok()
    } else {
        None
    };

    let local_path = retrieve_backup(entry)?;

    // Detect format. New v20.11.0+ backups are a wrapper tarball that
    // contains `inspect.json` + `image.tar.gz` + per-mount tarballs.
    // Pre-v20.11.0 backups are a flat `docker save | gzip`. Detect by
    // extracting the outer archive to a temp dir and checking what's
    // there. If `inspect.json` is present, new format; else fall back
    // to the legacy `docker load` path so old backups still restore.
    let work_dir = ensure_staging_dir()?.join(format!("docker-restore-{}", Uuid::new_v4()));
    fs::create_dir_all(&work_dir).map_err(|e| format!("Failed to create restore work dir: {}", e))?;

    let xt = Command::new("tar")
        .arg("xzf").arg(&local_path)
        .arg("-C").arg(&work_dir)
        .output();
    let extracted_ok = xt.as_ref().map(|o| o.status.success()).unwrap_or(false);

    let new_format = extracted_ok && work_dir.join("inspect.json").exists();
    let mut restored_mounts: Vec<String> = Vec::new();
    let mut skipped_mounts: Vec<String> = Vec::new();

    let image_load_path: PathBuf = if new_format {
        // Read the wrapper's inspect.json (overrides entry.docker_config
        // if entry didn't have it for some reason).
        if inspect_json.is_none() {
            if let Ok(text) = fs::read_to_string(work_dir.join("inspect.json")) {
                inspect_json = serde_json::from_str(&text).ok();
            }
        }

        // Restore each mount BEFORE creating the container — so when
        // docker run mounts them, the data's already in place.
        let mounts_text = fs::read_to_string(work_dir.join("mounts.json")).unwrap_or_default();
        let mounts: Vec<MountInfo> = serde_json::from_str(&mounts_text).unwrap_or_default();
        for m in &mounts {
            if m.archive_path.is_empty() {
                if !m.skipped_reason.is_empty() {
                    skipped_mounts.push(format!("{} {} ({})", m.mount_type, m.destination, m.skipped_reason));
                }
                continue;
            }
            let archive_abs = work_dir.join(&m.archive_path);
            if !archive_abs.exists() {
                skipped_mounts.push(format!("{} {} (archive missing inside backup)", m.mount_type, m.destination));
                continue;
            }
            match m.mount_type.as_str() {
                "volume" => {
                    if m.source.is_empty() {
                        skipped_mounts.push(format!("volume {} (no name)", m.destination));
                        continue;
                    }
                    // Idempotent — if the volume already exists docker
                    // returns its name and we just write into it.
                    let _ = Command::new("docker").args(["volume", "create", &m.source]).output();
                    let data_dir = format!("/var/lib/docker/volumes/{}/_data", m.source);
                    if !Path::new(&data_dir).is_dir() {
                        skipped_mounts.push(format!("volume {} (data dir not created: {})", m.source, data_dir));
                        continue;
                    }
                    let xv = Command::new("tar")
                        .arg("xzf").arg(&archive_abs)
                        .arg("-C").arg(&data_dir)
                        .output();
                    match xv {
                        Ok(o) if o.status.success() => {
                            restored_mounts.push(format!("volume {}", m.source));
                        }
                        Ok(o) => {
                            skipped_mounts.push(format!("volume {} (extract failed: {})", m.source, String::from_utf8_lossy(&o.stderr).trim()));
                        }
                        Err(e) => skipped_mounts.push(format!("volume {} (tar spawn: {})", m.source, e)),
                    }
                }
                "bind" => {
                    // Ensure parent dir exists; tar can extract into it.
                    let target = Path::new(&m.source);
                    if let Some(parent) = target.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    // tar archive_path was created with `tar -C {parent}
                    // {basename}`, so it contains an entry at the root
                    // named after the basename. Extract into the parent
                    // dir so it lands at the original Source path.
                    let parent = target.parent().map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".into());
                    let xb = Command::new("tar")
                        .arg("xzf").arg(&archive_abs)
                        .arg("-C").arg(&parent)
                        .output();
                    match xb {
                        Ok(o) if o.status.success() => {
                            restored_mounts.push(format!("bind {}", m.source));
                        }
                        Ok(o) => {
                            skipped_mounts.push(format!("bind {} (extract failed: {})", m.source, String::from_utf8_lossy(&o.stderr).trim()));
                        }
                        Err(e) => skipped_mounts.push(format!("bind {} (tar spawn: {})", m.source, e)),
                    }
                }
                _ => {
                    // tmpfs etc. — not archived, nothing to restore.
                }
            }
        }

        work_dir.join("image.tar.gz")
    } else {
        // Legacy backup — the file at `local_path` IS the `docker save |
        // gzip` output. docker load reads it directly.
        local_path.clone()
    };

    // Load the image from the (legacy or new-format) tarball.
    let output = Command::new("sh")
        .args(["-c", &format!("gunzip -c '{}' | docker load", image_load_path.display())])
        .output()
        .map_err(|e| {
            let _ = fs::remove_dir_all(&work_dir);
            let _ = fs::remove_file(&local_path);
            format!("Failed to load Docker image: {}", e)
        })?;

    // Tarball + work dir done. Clean up.
    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("Docker load failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let load_result = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Extract the loaded image name from "Loaded image: <name>".
    let image_name = load_result
        .lines()
        .find_map(|line| line.strip_prefix("Loaded image: "))
        .unwrap_or(&format!("wolfstack-backup/{}", entry.target.name))
        .to_string();

    // If overwriting, stop and remove the existing container.
    if exists {
        let _ = Command::new("docker").args(["stop", container_name]).output();
        let _ = Command::new("docker").args(["rm", "-f", container_name]).output();
    }

    // Build docker run args from inspect config, or use defaults.
    let extra_args = inspect_json.as_ref()
        .map(|j| docker_run_args_from_inspect(j))
        .unwrap_or_else(|| vec!["--restart".to_string(), "unless-stopped".to_string()]);

    let mut run_args = vec!["run".to_string(), "-d".to_string(), "--name".to_string(), container_name.to_string()];
    run_args.extend(extra_args);
    run_args.push(image_name.clone());

    let create = Command::new("docker")
        .args(&run_args)
        .output()
        .map_err(|e| format!("Image loaded but failed to create container: {}", e))?;

    if !create.status.success() {
        let err = String::from_utf8_lossy(&create.stderr);
        return Ok(format!("Docker image restored ({}). Could not auto-create container: {}",
            image_name, err.trim()));
    }

    let config_note = if inspect_json.is_some() { " (with original config)" } else { " (default config)" };
    let mut msg = format!("Docker container '{}' restored and started{}", container_name, config_note);
    if !restored_mounts.is_empty() {
        msg.push_str(&format!(" — restored data: {}", restored_mounts.join(", ")));
    }
    if !skipped_mounts.is_empty() {
        msg.push_str(&format!(" (skipped: {})", skipped_mounts.join(", ")));
    }
    Ok(msg)
}

/// Restore an LXC container from backup
pub fn restore_lxc(entry: &BackupEntry) -> Result<String, String> {

    let local_path = retrieve_backup(entry)?;
    let container_name = &entry.target.name;

    // Detect if this is a vzdump archive (Proxmox backup)
    let filename = local_path.file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let is_vzdump = filename.contains("vzdump");

    if is_vzdump && crate::containers::is_proxmox() {
        return restore_lxc_proxmox(entry, &local_path);
    }

    // Native LXC restore: extract tar to /var/lib/lxc/
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", "/var/lib/lxc/"])
        .output()
        .map_err(|e| format!("Failed to extract LXC backup: {}", e))?;

    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("LXC extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let container_dir = format!("/var/lib/lxc/{}", container_name);
    let config_path = format!("{}/config", container_dir);
    let rootfs_path = format!("{}/rootfs", container_dir);

    // Ensure rootfs directory exists
    if !std::path::Path::new(&rootfs_path).exists() {
        warn!("Restored LXC container '{}' has no rootfs directory", container_name);
    }

    // Fix config: ensure lxc.rootfs.path is set correctly
    if let Ok(config) = std::fs::read_to_string(&config_path) {
        let mut lines: Vec<String> = config.lines()
            .filter(|l| !l.trim().starts_with("lxc.rootfs.path"))
            .map(|l| l.to_string())
            .collect();
        lines.insert(0, format!("lxc.rootfs.path = dir:{}", rootfs_path));

        if !lines.iter().any(|l| l.contains("lxc.apparmor.profile")) {
            lines.push("lxc.apparmor.profile = unconfined".to_string());
        }

        let new_config = lines.join("\n") + "\n";
        let _ = std::fs::write(&config_path, &new_config);
    }

    let _ = Command::new("chown").args(["-R", "root:root", &container_dir]).output();
    let _ = Command::new("chmod").args(["755", &container_dir]).output();

    Ok(format!("LXC container '{}' restored — you can now start it from the Containers page", container_name))
}

/// Restore a Proxmox LXC container from a vzdump archive using pct restore
fn restore_lxc_proxmox(entry: &BackupEntry, archive_path: &Path) -> Result<String, String> {
    let vmid = &entry.target.name;

    // Check if the VMID already exists — pct restore will fail if it does
    let exists = Command::new("pct").args(["status", vmid]).output()
        .map(|o| o.status.success()).unwrap_or(false);

    if exists {
        // Container exists — stop it first if running, then destroy and recreate
        let _ = Command::new("pct").args(["stop", vmid]).output();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let destroy = Command::new("pct").args(["destroy", vmid, "--force", "1"]).output()
            .map_err(|e| format!("Failed to destroy existing container {}: {}", vmid, e))?;
        if !destroy.status.success() {
            return Err(format!("Failed to destroy existing container {}: {}",
                vmid, String::from_utf8_lossy(&destroy.stderr)));
        }
    }

    // Restore using pct restore — handles all storage backends
    let output = Command::new("pct")
        .args(["restore", vmid, &archive_path.to_string_lossy()])
        .output()
        .map_err(|e| format!("pct restore failed to start: {}", e))?;

    let _ = fs::remove_file(archive_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pct restore failed: {}", stderr.trim()));
    }

    Ok(format!("Proxmox LXC container {} restored from vzdump backup — you can now start it from the Containers page", vmid))
}

/// Restore a VM from backup
pub fn restore_vm(entry: &BackupEntry) -> Result<String, String> {

    let local_path = retrieve_backup(entry)?;

    let vm_base = "/var/lib/wolfstack/vms";
    fs::create_dir_all(vm_base).map_err(|e| format!("Failed to create VM dir: {}", e))?;

    // Extract to /var/lib/wolfstack/vms/
    // The tar contains: {name}.json, {name}.qcow2, and optionally {name}/ directory
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", vm_base])
        .output()
        .map_err(|e| format!("Failed to extract VM backup: {}", e))?;

    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("VM extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Verify the config JSON was restored
    let config_path = format!("{}/{}.json", vm_base, entry.target.name);
    if !Path::new(&config_path).exists() {
        // Legacy backup format: config might be inside a subdirectory
        let legacy_config = format!("{}/{}/config.json", vm_base, entry.target.name);
        if Path::new(&legacy_config).exists() {
            // Move it to the expected flat location
            let _ = fs::copy(&legacy_config, &config_path);

        } else {
            warn!("VM config not found after restore: {} — VM may not appear in list until config is recreated", config_path);
        }
    }


    Ok(format!("VM '{}' restored", entry.target.name))
}

/// Restore WolfStack configuration from backup
pub fn restore_config_backup(entry: &BackupEntry) -> Result<String, String> {

    let local_path = retrieve_backup(entry)?;

    // Extract to root (files are stored with their relative paths)
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", "/"])
        .output()
        .map_err(|e| format!("Failed to extract config backup: {}", e))?;

    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("Config extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }


    Ok("WolfStack configuration restored. Restart services to apply changes.".to_string())
}

/// Restore from a backup entry (auto-detects type)
pub fn restore_backup(entry: &BackupEntry, overwrite: bool) -> Result<String, String> {
    match entry.target.target_type {
        BackupTargetType::Docker => restore_docker(entry, overwrite),
        BackupTargetType::Lxc => restore_lxc(entry),
        BackupTargetType::Vm => restore_vm(entry),
        BackupTargetType::Config => restore_config_backup(entry),
    }
}

// ─── Public API Functions ───

/// List all backup entries
pub fn list_backups() -> Vec<BackupEntry> {
    load_config().entries
}

/// Create a backup (single target or all)
pub fn create_backup(target: Option<BackupTarget>, storage: BackupStorage) -> Vec<BackupEntry> {
    let mut config = load_config();

    let new_entries = match target {
        Some(t) => vec![create_backup_entry(t, &storage)],
        None => backup_all(&storage),
    };

    config.entries.extend(new_entries.clone());
    let _ = save_config(&config);

    new_entries
}

/// Create a backup with real-time log output via a sender channel
pub fn create_backup_with_log(
    target: Option<BackupTarget>,
    storage: BackupStorage,
    log: std::sync::mpsc::Sender<String>,
    cluster_name: Option<String>,
) -> Vec<BackupEntry> {
    let targets = match target {
        Some(t) => vec![t],
        None => list_available_targets(),
    };

    let mut entries = Vec::new();
    let total = targets.len();
    let cluster = cluster_name.unwrap_or_else(local_cluster_name);
    let _ = log.send(format!("Cluster: {} | Node: {}", cluster, local_hostname()));

    for (i, t) in targets.iter().enumerate() {
        let type_name = t.target_type.to_string().to_uppercase();
        let display_name = if let Some(h) = &t.hostname {
            format!("{} ({})", t.name, h)
        } else {
            t.name.clone()
        };

        let _ = log.send(format!("[{}/{}] Starting {} backup: {}",
            i + 1, total, type_name, display_name));

        let comments = backup_comments_with_cluster(t, &cluster);

        // Run the backup with line-by-line output for vzdump
        let (result, docker_config, mounts) = match t.target_type {
            BackupTargetType::Docker => {
                let _ = log.send(format!("  Exporting Docker container '{}'...", t.name));
                match backup_docker(&t.name) {
                    Ok((path, size, config, m)) => {
                        if !m.is_empty() {
                            let archived = m.iter().filter(|x| !x.archive_path.is_empty()).count();
                            let skipped  = m.iter().filter(|x|  x.archive_path.is_empty()).count();
                            let _ = log.send(format!("  + {} mount(s) captured ({} archived, {} skipped)", m.len(), archived, skipped));
                            for x in m.iter().filter(|x| !x.skipped_reason.is_empty()) {
                                let _ = log.send(format!("    skipped {} {}: {}", x.mount_type, x.destination, x.skipped_reason));
                            }
                        }
                        (Ok((path, size)), config, m)
                    },
                    Err(e) => (Err(e), String::new(), Vec::new()),
                }
            }
            BackupTargetType::Lxc => {
                let r = if crate::containers::is_proxmox() {
                    let _ = log.send(format!("  Running vzdump for container {}...", t.name));
                    backup_lxc_proxmox_with_log(&t.name, &log)
                } else {
                    let _ = log.send(format!("  Tarring LXC rootfs for '{}'...", t.name));
                    backup_lxc(&t.name)
                };
                (r, String::new(), Vec::new())
            }
            BackupTargetType::Vm => {
                let _ = log.send(format!("  Backing up VM '{}'...", t.name));
                (backup_vm(&t.name), String::new(), Vec::new())
            }
            BackupTargetType::Config => {
                let _ = log.send("  Archiving WolfStack config files...".to_string());
                (backup_config(), String::new(), Vec::new())
            }
        };

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let hostname = local_hostname();

        let entry = match result {
            Ok((local_path, size)) => {
                let _ = log.send(format!("  Backup created: {} ({})",
                    local_path.file_name().unwrap_or_default().to_string_lossy(),
                    format_size_human(size)));

                let filename = local_path.file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("backup-{}.tar.gz", id));

                let _ = log.send(format!("  Storing to {}...", storage_label(&storage)));
                let pbs_notes = format!("Cluster: {} | Node: {} | {}", cluster, hostname, comments);

                let store_result = if storage.storage_type == StorageType::Pbs {
                    store_pbs_with_notes_and_log(&local_path, &storage, &filename, Some(&pbs_notes), Some(&log))
                } else {
                    store_backup_with_notes(&local_path, &storage, &filename, Some(&pbs_notes))
                };
                match store_result {
                    Ok(_) => {
                        let _ = fs::remove_file(&local_path);
                        let _ = log.send(format!("  ✓ {} backup complete ({})", type_name, format_size_human(size)));
                        BackupEntry {
                            id, target: t.clone(), storage: storage.clone(), filename,
                            size_bytes: size, created_at: now, status: BackupStatus::Completed,
                            error: String::new(), schedule_id: String::new(),
                            comments, node_hostname: hostname, docker_config,
                            mounts: mounts.clone(),
                        }
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&local_path);
                        let _ = log.send(format!("  ✗ Storage failed: {}", e));
                        BackupEntry {
                            id, target: t.clone(), storage: storage.clone(), filename,
                            size_bytes: size, created_at: now, status: BackupStatus::Failed,
                            error: e, schedule_id: String::new(),
                            comments, node_hostname: hostname, docker_config: String::new(),
                            mounts: Vec::new(),
                        }
                    }
                }
            }
            Err(e) => {
                let _ = log.send(format!("  ✗ Backup failed: {}", e));
                BackupEntry {
                    id, target: t.clone(), storage: storage.clone(),
                    filename: String::new(), size_bytes: 0, created_at: now,
                    status: BackupStatus::Failed, error: e,
                    schedule_id: String::new(), comments, node_hostname: hostname,
                    docker_config: String::new(),
                    mounts: Vec::new(),
                }
            }
        };
        entries.push(entry);
    }

    let ok = entries.iter().filter(|e| e.status == BackupStatus::Completed).count();
    let fail = entries.iter().filter(|e| e.status == BackupStatus::Failed).count();
    let _ = log.send(format!("\nDone: {} succeeded, {} failed", ok, fail));

    let mut config = load_config();
    config.entries.extend(entries.clone());
    let _ = save_config(&config);

    entries
}

/// Proxmox vzdump with real-time log output
fn backup_lxc_proxmox_with_log(
    vmid: &str,
    log: &std::sync::mpsc::Sender<String>,
) -> Result<(PathBuf, u64), String> {
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();

    // Try snapshot mode first, then stop mode
    for mode in &["snapshot", "stop"] {
        let _ = log.send(format!("  vzdump --mode {} ...", mode));

        let mut child = Command::new("vzdump")
            .args([
                vmid,
                "--dumpdir", &staging.to_string_lossy(),
                "--mode", mode,
                "--compress", "zstd",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("vzdump failed to start: {}", e))?;

        // Read stdout and stderr in parallel threads to avoid pipe deadlock
        // (vzdump writes to both — if one pipe buffer fills while we block on
        // the other, the process hangs)
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let log_clone = log.clone();
        let stdout_handle = std::thread::spawn(move || {
            let mut all = String::new();
            if let Some(stdout) = stdout {
                use std::io::BufRead;
                for line in std::io::BufReader::new(stdout).lines().flatten() {
                    let _ = log_clone.send(format!("  {}", line));
                    all.push_str(&line);
                    all.push('\n');
                }
            }
            all
        });

        let log_clone2 = log.clone();
        let stderr_handle = std::thread::spawn(move || {
            let mut all = String::new();
            if let Some(stderr) = stderr {
                use std::io::BufRead;
                for line in std::io::BufReader::new(stderr).lines().flatten() {
                    let _ = log_clone2.send(format!("  {}", line));
                    all.push_str(&line);
                    all.push('\n');
                }
            }
            all
        });

        let all_stdout = stdout_handle.join().unwrap_or_default();
        let all_stderr = stderr_handle.join().unwrap_or_default();
        // Combine stdout+stderr — vzdump may log the archive path to either
        let all_output = format!("{}{}", all_stdout, all_stderr);

        let status = child.wait().map_err(|e| format!("vzdump wait failed: {}", e))?;
        if status.success() {
            return find_vzdump_result(&all_output, &staging, vmid, &timestamp);
        }

        if *mode == "snapshot" {
            let _ = log.send("  Snapshot mode not supported, trying stop mode...".to_string());
        }
    }

    Err("vzdump failed in all modes".to_string())
}


fn storage_label(storage: &BackupStorage) -> String {
    match storage.storage_type {
        StorageType::Local => format!("local: {}", storage.path),
        StorageType::S3 => format!("S3: {}", storage.bucket),
        StorageType::Remote => format!("remote: {}", storage.remote_url),
        StorageType::Wolfdisk => {
            let sub = storage.wolfdisk_subpath.trim().trim_matches('/');
            if sub.is_empty() {
                format!("WolfDisk: {}", storage.path)
            } else {
                format!("WolfDisk: {}/{}", storage.path.trim_end_matches('/'), sub)
            }
        }
        StorageType::Pbs => format!("PBS: {}", storage.pbs_server),
        StorageType::Nfs => format!("NFS: {}", storage.nfs_source),
        StorageType::Smb => {
            if storage.smb_subpath.is_empty() {
                format!("SMB: {}", storage.smb_source)
            } else {
                format!("SMB: {}/{}", storage.smb_source, storage.smb_subpath.trim_matches('/'))
            }
        }
    }
}

/// Delete a backup entry and its file
pub fn delete_backup(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.entries.iter().position(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;

    let entry = config.entries.remove(idx);

    // Try to delete the file from storage
    match entry.storage.storage_type {
        StorageType::Local | StorageType::Wolfdisk => {
            let path = Path::new(&entry.storage.resolved_local_path()).join(&entry.filename);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        },
        StorageType::Nfs => {
            if let Ok(dir) = ensure_nfs_mounted(&entry.storage) {
                let path = Path::new(&dir).join(&entry.filename);
                if path.exists() { let _ = fs::remove_file(&path); }
            }
        },
        StorageType::Smb => {
            if let Ok(dir) = ensure_smb_mounted(&entry.storage) {
                let path = Path::new(&dir).join(&entry.filename);
                if path.exists() { let _ = fs::remove_file(&path); }
            }
        },
        _ => {} // S3, Remote, PBS deletion not implemented yet
    }

    save_config(&config)?;
    Ok(format!("Backup {} deleted", id))
}

/// Restore from a backup by ID
pub fn restore_by_id(id: &str, overwrite: bool) -> Result<String, String> {
    let config = load_config();
    let entry = config.entries.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;
    restore_backup(entry, overwrite)
}

/// Restore from a backup by ID with streaming log output
pub fn restore_by_id_with_log(id: &str, overwrite: bool, log: std::sync::mpsc::Sender<String>) -> Result<String, String> {
    let config = load_config();
    let entry = config.entries.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;

    let type_name = entry.target.target_type.to_string().to_uppercase();
    let display_name = entry.target.hostname.as_deref()
        .map(|h| format!("{} ({})", entry.target.name, h))
        .unwrap_or_else(|| entry.target.name.clone());

    let _ = log.send(format!("Starting {} restore: {}", type_name, display_name));

    // Check for container existence before downloading
    if entry.target.target_type == BackupTargetType::Docker {
        let check = Command::new("docker")
            .args(["container", "inspect", &entry.target.name])
            .output();
        let exists = check.map(|o| o.status.success()).unwrap_or(false);
        if exists && !overwrite {
            return Err(format!("CONTAINER_EXISTS:{}", entry.target.name));
        }
        if exists && overwrite {
            let _ = log.send(format!("Stopping existing container '{}'...", entry.target.name));
            let _ = Command::new("docker").args(["stop", &entry.target.name]).output();
            let _ = Command::new("docker").args(["rm", "-f", &entry.target.name]).output();
            let _ = log.send("Existing container removed".to_string());
        }
    }

    // Use saved docker inspect config from the backup entry
    let inspect_json = if entry.target.target_type == BackupTargetType::Docker && !entry.docker_config.is_empty() {
        let json = serde_json::from_str::<serde_json::Value>(&entry.docker_config).ok();
        if json.is_some() { let _ = log.send("Found saved container config".to_string()); }
        json
    } else {
        if entry.target.target_type == BackupTargetType::Docker {
            let _ = log.send("No saved config — will use defaults".to_string());
        }
        None
    };

    let _ = log.send("Downloading backup...".to_string());
    let local_path = retrieve_backup(entry)?;
    let _ = log.send("Download complete".to_string());

    match entry.target.target_type {
        BackupTargetType::Docker => {
            let _ = log.send("Loading Docker image...".to_string());
            let output = Command::new("sh")
                .args(["-c", &format!("gunzip -c '{}' | docker load", local_path.display())])
                .output()
                .map_err(|e| format!("Failed to load Docker image: {}", e))?;

            let _ = fs::remove_file(&local_path);

            if !output.status.success() {
                let err = format!("Docker load failed: {}", String::from_utf8_lossy(&output.stderr));
                let _ = log.send(err.clone());
                return Err(err);
            }

            let load_result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let image_name = load_result
                .lines()
                .find_map(|line| line.strip_prefix("Loaded image: "))
                .unwrap_or(&format!("wolfstack-backup/{}", entry.target.name))
                .to_string();

            let _ = log.send(format!("Image loaded: {}", image_name));

            let extra_args = inspect_json.as_ref()
                .map(|j| docker_run_args_from_inspect(j))
                .unwrap_or_else(|| vec!["--restart".to_string(), "unless-stopped".to_string()]);

            let _ = log.send(format!("Creating container '{}'...", entry.target.name));

            let mut run_args = vec!["run".to_string(), "-d".to_string(), "--name".to_string(), entry.target.name.clone()];
            run_args.extend(extra_args);
            run_args.push(image_name.clone());

            let create = Command::new("docker")
                .args(&run_args)
                .output()
                .map_err(|e| format!("Failed to create container: {}", e))?;

            if !create.status.success() {
                let err = String::from_utf8_lossy(&create.stderr);
                let msg = format!("Image restored but container creation failed: {}", err.trim());
                let _ = log.send(msg.clone());
                return Ok(msg);
            }

            let config_note = if inspect_json.is_some() { " (with original config)" } else { " (default config)" };
            let msg = format!("✅ Docker container '{}' restored and started{}", entry.target.name, config_note);
            let _ = log.send(msg.clone());
            Ok(msg)
        }
        BackupTargetType::Lxc => {
            let _ = log.send("Restoring LXC container...".to_string());
            let result = restore_lxc(entry);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::Vm => {
            let _ = log.send("Restoring VM...".to_string());
            let result = restore_vm(entry);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::Config => {
            let _ = log.send("Restoring WolfStack configuration...".to_string());
            let result = restore_config_backup(entry);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
    }
}

// ─── Schedule Management ───

/// List all schedules
pub fn list_schedules() -> Vec<BackupSchedule> {
    load_config().schedules
}

/// Create or update a schedule
pub fn save_schedule(schedule: BackupSchedule) -> Result<BackupSchedule, String> {
    let mut config = load_config();

    // Update existing or insert new
    if let Some(existing) = config.schedules.iter_mut().find(|s| s.id == schedule.id) {
        *existing = schedule.clone();
    } else {
        config.schedules.push(schedule.clone());
    }

    save_config(&config)?;
    Ok(schedule)
}

/// Delete a schedule
pub fn delete_schedule(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let len_before = config.schedules.len();
    config.schedules.retain(|s| s.id != id);

    if config.schedules.len() == len_before {
        return Err(format!("Schedule not found: {}", id));
    }

    save_config(&config)?;
    Ok(format!("Schedule {} deleted", id))
}

// ─── Available Targets ───

/// List all available backup targets on the system with full details
pub fn list_available_targets() -> Vec<BackupTarget> {
    let mut targets = Vec::new();

    // Docker containers — include image and state
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.State}}"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            let name = parts.first().unwrap_or(&"").to_string();
            if name.is_empty() { continue; }
            let image = parts.get(1).unwrap_or(&"").to_string();
            let state = parts.get(2).map(|s| s.to_string());
            targets.push(BackupTarget {
                target_type: BackupTargetType::Docker,
                name,
                hostname: None,
                state,
                specs: if image.is_empty() { None } else { Some(image) },
            });
        }
    }

    // LXC containers — detect Proxmox (pct) vs native LXC and gather full details
    let is_proxmox = Command::new("which").arg("pct").output()
        .map(|o| o.status.success()).unwrap_or(false);

    if is_proxmox {
        // Proxmox: use pct list + pct config for hostname, cores, memory
        if let Ok(output) = Command::new("pct").arg("list").output() {
            if output.status.success() {
                let listing = String::from_utf8_lossy(&output.stdout);
                let entries: Vec<(String, String, String)> = listing.lines()
                    .skip(1)
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        let vmid = parts.first()?.to_string();
                        let state = parts.get(1).unwrap_or(&"stopped").to_lowercase();
                        // Name may have a "Lock" column before it on locked containers
                        let pct_name = parts.last().map(|s| s.to_string()).unwrap_or_default();
                        Some((vmid, state, pct_name))
                    })
                    .collect();

                // Fetch configs in parallel
                let configs: Vec<String> = std::thread::scope(|s| {
                    let handles: Vec<_> = entries.iter().map(|(vmid, _, _)| {
                        let vmid = vmid.clone();
                        s.spawn(move || {
                            Command::new("pct").args(["config", &vmid]).output().ok()
                                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                                .unwrap_or_default()
                        })
                    }).collect();
                    handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
                });

                for ((vmid, state, pct_name), cfg) in entries.iter().zip(configs.iter()) {
                    let mut hostname = if pct_name.is_empty() { None } else { Some(pct_name.clone()) };
                    let mut memory_mb: u64 = 0;
                    let mut cores: u64 = 0;
                    let mut os_type = String::new();

                    for cline in cfg.lines() {
                        let cline = cline.trim();
                        if cline.starts_with("hostname:") {
                            hostname = cline.split(':').nth(1).map(|s| s.trim().to_string());
                        } else if cline.starts_with("memory:") {
                            memory_mb = cline.split(':').nth(1)
                                .and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                        } else if cline.starts_with("cores:") {
                            cores = cline.split(':').nth(1)
                                .and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                        } else if cline.starts_with("ostype:") {
                            os_type = cline.split(':').nth(1).unwrap_or("").trim().to_string();
                        }
                    }

                    let mut spec_parts = Vec::new();
                    if cores > 0 { spec_parts.push(format!("{} core{}", cores, if cores > 1 { "s" } else { "" })); }
                    if memory_mb > 0 {
                        if memory_mb >= 1024 { spec_parts.push(format!("{}GB RAM", memory_mb / 1024)); }
                        else { spec_parts.push(format!("{}MB RAM", memory_mb)); }
                    }
                    if !os_type.is_empty() { spec_parts.push(os_type); }

                    targets.push(BackupTarget {
                        target_type: BackupTargetType::Lxc,
                        name: vmid.clone(),
                        hostname,
                        state: Some(state.clone()),
                        specs: if spec_parts.is_empty() { None } else { Some(spec_parts.join(", ")) },
                    });
                }
            }
        }
    } else {
        // Native LXC: use lxc-ls -f for state + hostname from config
        if let Ok(output) = Command::new("lxc-ls")
            .args(["-f", "-F", "NAME,STATE"])
            .output()
        {
            for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let name = match parts.first() {
                    Some(n) if !n.is_empty() => n.to_string(),
                    _ => continue,
                };
                let state = parts.get(1).map(|s| s.to_lowercase());

                // Try to read hostname from LXC config
                let hostname = lxc_config_hostname(&name);

                targets.push(BackupTarget {
                    target_type: BackupTargetType::Lxc,
                    name,
                    hostname,
                    state,
                    specs: None,
                });
            }
        }
    }

    // VMs (stored as {name}.json in the vms directory)
    let vm_dir = Path::new("/var/lib/wolfstack/vms");
    if vm_dir.exists() {
        if let Ok(entries) = fs::read_dir(vm_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json")
                    && !path.to_string_lossy().contains(".runtime.")
                {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        targets.push(BackupTarget {
                            target_type: BackupTargetType::Vm,
                            name: stem.to_string(),
                            hostname: None, state: None, specs: None,
                        });
                    }
                }
            }
        }
    }

    // Config is always available
    targets.push(BackupTarget {
        target_type: BackupTargetType::Config,
        name: String::new(),
        hostname: None, state: None, specs: None,
    });

    targets
}

/// Read hostname from native LXC config file
fn lxc_config_hostname(name: &str) -> Option<String> {
    for base in &["/var/lib/lxc", "/var/snap/lxd/common/lxd/storage-pools"] {
        let config_path = format!("{}/{}/config", base, name);
        if let Ok(content) = fs::read_to_string(&config_path) {
            if let Some(line) = content.lines().find(|l| l.trim().starts_with("lxc.uts.name")) {
                return line.split('=').nth(1).map(|s| s.trim().to_string());
            }
        }
    }
    None
}

// ─── Scheduling ───

/// Check all schedules and run any that are due
/// Called from background task loop in main.rs
pub fn check_schedules() {
    let mut config = load_config();
    let now = Utc::now();
    let current_time = now.format("%H:%M").to_string();
    let mut changed = false;

    for schedule in config.schedules.iter_mut() {
        if !schedule.enabled {
            continue;
        }

        // Check if it's time to run
        if current_time != schedule.time {
            continue;
        }

        // Check if already ran today/this period
        if !schedule.last_run.is_empty() {
            if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&schedule.last_run) {
                let last_utc = last.with_timezone(&Utc);
                match schedule.frequency {
                    BackupFrequency::Daily => {
                        if last_utc.date_naive() == now.date_naive() {
                            continue; // Already ran today
                        }
                    },
                    BackupFrequency::Weekly => {
                        let days_since = (now - last_utc).num_days();
                        if days_since < 7 {
                            continue; // Ran within last 7 days
                        }
                    },
                    BackupFrequency::Monthly => {
                        if last_utc.month() == now.month() && last_utc.year() == now.year() {
                            continue; // Already ran this month
                        }
                    },
                }
            }
        }

        // Time to run this schedule!

        // Scheduler form may have saved storage as `{type:"pbs"}` only.
        // Fill in server/user/credentials from the saved PBS config so
        // proxmox-backup-client gets PBS_PASSWORD instead of failing with
        // "no password input mechanism".
        let mut storage = schedule.storage.clone();
        merge_pbs_secrets(&mut storage);

        let new_entries = if schedule.backup_all {
            backup_all(&storage)
        } else {
            schedule.targets.iter()
                .map(|t| create_backup_entry(t.clone(), &storage))
                .collect()
        };

        // Tag entries with schedule ID
        for mut entry in new_entries {
            entry.schedule_id = schedule.id.clone();
            config.entries.push(entry);
        }

        schedule.last_run = now.to_rfc3339();
        changed = true;

        // Prune old backups if retention is set
        if schedule.retention > 0 {
            let schedule_id = schedule.id.clone();
            let retention = schedule.retention as usize;
            let mut schedule_entries: Vec<usize> = config.entries.iter()
                .enumerate()
                .filter(|(_, e)| e.schedule_id == schedule_id && e.status == BackupStatus::Completed)
                .map(|(i, _)| i)
                .collect();

            // Sort by date (newest first), remove excess
            schedule_entries.sort_by(|a, b| {
                config.entries[*b].created_at.cmp(&config.entries[*a].created_at)
            });

            if schedule_entries.len() > retention {
                let to_remove: Vec<usize> = schedule_entries[retention..].to_vec();
                // Delete files and remove entries (in reverse order to preserve indices)
                for &idx in to_remove.iter().rev() {
                    let entry = &config.entries[idx];
                    match entry.storage.storage_type {
                        StorageType::Local | StorageType::Wolfdisk => {
                            let path = Path::new(&entry.storage.resolved_local_path()).join(&entry.filename);
                            let _ = fs::remove_file(&path);
                        },
                        StorageType::Nfs => {
                            if let Ok(dir) = ensure_nfs_mounted(&entry.storage) {
                                let _ = fs::remove_file(Path::new(&dir).join(&entry.filename));
                            }
                        },
                        StorageType::Smb => {
                            if let Ok(dir) = ensure_smb_mounted(&entry.storage) {
                                let _ = fs::remove_file(Path::new(&dir).join(&entry.filename));
                            }
                        },
                        StorageType::Pbs => {
                            // PBS handles its own garbage collection / pruning
                        },
                        _ => {}
                    }
                    config.entries.remove(idx);
                }

            }
        }
    }

    if changed {
        let _ = save_config(&config);
    }
}

/// Receive a backup file from a remote node — save to local storage
pub fn import_backup(data: &[u8], filename: &str) -> Result<String, String> {
    let dest_dir = crate::paths::get().backup_received_dir;
    fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create import dir: {}", e))?;

    let dest = Path::new(&dest_dir).join(filename);
    fs::write(&dest, data)
        .map_err(|e| format!("Failed to write imported backup: {}", e))?;

    let size = data.len();


    // Add to config as an entry
    let mut config = load_config();
    config.entries.push(BackupEntry {
        id: Uuid::new_v4().to_string(),
        target: BackupTarget {
            target_type: guess_target_type(filename),
            name: extract_name_from_filename(filename),
            hostname: None, state: None, specs: None,
        },
        storage: BackupStorage::local(&dest_dir),
        filename: filename.to_string(),
        size_bytes: size as u64,
        created_at: Utc::now().to_rfc3339(),
        status: BackupStatus::Completed,
        error: String::new(),
        schedule_id: String::new(),
        comments: format!("[{}] Imported backup: {}", local_cluster_name(), filename),
        node_hostname: local_hostname(),
        docker_config: String::new(),
        mounts: Vec::new(),
    });
    let _ = save_config(&config);

    Ok(format!("Backup imported: {}", filename))
}

/// Guess the backup target type from filename prefix
fn guess_target_type(filename: &str) -> BackupTargetType {
    if filename.starts_with("docker-") { BackupTargetType::Docker }
    else if filename.starts_with("lxc-") { BackupTargetType::Lxc }
    else if filename.starts_with("vm-") { BackupTargetType::Vm }
    else { BackupTargetType::Config }
}

/// Extract the target name from a backup filename
fn extract_name_from_filename(filename: &str) -> String {
    // Format: type-name-timestamp.tar.gz
    let parts: Vec<&str> = filename.splitn(3, '-').collect();
    if parts.len() >= 2 {
        // Remove timestamp and extension from the last part
        let name_and_rest = parts[1..].join("-");
        if let Some(idx) = name_and_rest.rfind('-') {
            return name_and_rest[..idx].to_string();
        }
        return name_and_rest;
    }
    filename.to_string()
}

// ─── Proxmox Backup Server (PBS) Integration ───

/// Retrieve a backup from PBS — restore a specific archive from a snapshot
fn retrieve_from_pbs(entry: &BackupEntry, dest: &Path) -> Result<(), String> {
    let storage = &entry.storage;
    let repo = pbs_repo_string(storage);

    let backup_id = extract_backup_id_from_filename(&entry.filename);
    let backup_type = if entry.filename.starts_with("vzdump-lxc-") || entry.filename.starts_with("lxc-") {
        "ct"
    } else if entry.filename.starts_with("vm-") || entry.filename.starts_with("vzdump-qemu-") {
        "vm"
    } else {
        "host"
    };

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };

    // List snapshots to find the latest matching one (PBS needs exact timestamp, not "latest")
    let mut list_cmd = Command::new("proxmox-backup-client");
    list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", &repo]);
    if !storage.pbs_fingerprint.is_empty() { list_cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint); }
    if !storage.pbs_namespace.is_empty() { list_cmd.arg("--ns").arg(&storage.pbs_namespace); }
    if !pbs_pw.is_empty() { list_cmd.env("PBS_PASSWORD", pbs_pw); }

    let list_output = list_cmd.output()
        .map_err(|e| format!("Failed to list PBS snapshots: {}", e))?;

    let snapshot = if list_output.status.success() {
        let snaps: serde_json::Value = serde_json::from_slice(&list_output.stdout)
            .unwrap_or(serde_json::Value::Array(vec![]));
        if let Some(arr) = snaps.as_array() {
            let mut best_time: i64 = 0;
            let mut best_snap = String::new();
            for s in arr {
                let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
                let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
                let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
                if st == backup_type && si == backup_id && stime > best_time {
                    best_time = stime;
                    best_snap = format!("{}/{}/{}", st, si, stime);
                }
            }
            if best_snap.is_empty() {
                return Err(format!("No PBS snapshot found for {}/{}", backup_type, backup_id));
            }
            best_snap
        } else {
            return Err("Failed to parse PBS snapshot list".to_string());
        }
    } else {
        return Err(format!("PBS snapshot list failed: {}", String::from_utf8_lossy(&list_output.stderr)));
    };

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot)
       .arg("backup.pxar")
       .arg(dest.parent().unwrap_or(Path::new("/tmp")).to_string_lossy().to_string())
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let output = cmd.output()
        .map_err(|e| format!("PBS restore failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("PBS restore error: {}",
            String::from_utf8_lossy(&output.stderr)));
    }

    Ok(())
}

/// List all snapshots on a Proxmox Backup Server
pub fn list_pbs_snapshots(storage: &BackupStorage) -> Result<serde_json::Value, String> {
    if storage.pbs_server.is_empty() || storage.pbs_datastore.is_empty() {
        return Err("PBS server and datastore must be configured".to_string());
    }

    let repo = pbs_repo_string(storage);

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("snapshot").arg("list")
       .arg("--output-format").arg("json")
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let output = cmd.output()
        .map_err(|e| format!("Failed to run proxmox-backup-client: {}", e))?;

    if !output.status.success() {
        return Err(format!("PBS snapshot list failed: {}",
            String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let snapshots: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse PBS output: {}", e))?;

    Ok(snapshots)
}

/// Enrich PBS snapshots with local container/VM details (hostname, specs)
pub fn enrich_pbs_snapshots(snapshots: serde_json::Value) -> serde_json::Value {
    let arr = match snapshots.as_array() {
        Some(a) => a,
        None => return snapshots,
    };

    // Build a lookup of VMID → (hostname, specs) from pct list + pct config
    let ct_info = build_pct_lookup();

    let enriched: Vec<serde_json::Value> = arr.iter().map(|snap| {
        let mut s = snap.clone();
        let btype = s.get("backup-type").or_else(|| s.get("backup_type"))
            .and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bid = s.get("backup-id").or_else(|| s.get("backup_id"))
            .and_then(|v| v.as_str()).unwrap_or("").to_string();

        if btype == "ct" || btype == "lxc" {
            if let Some((hostname, specs)) = ct_info.get(&bid) {
                if let Some(obj) = s.as_object_mut() {
                    if !hostname.is_empty() {
                        obj.insert("hostname".to_string(), serde_json::json!(hostname));
                    }
                    if !specs.is_empty() {
                        obj.insert("specs".to_string(), serde_json::json!(specs));
                    }
                }
            }
        }
        s
    }).collect();

    serde_json::json!(enriched)
}

/// Build a VMID → (hostname, specs) lookup from Proxmox pct list/config
fn build_pct_lookup() -> std::collections::HashMap<String, (String, String)> {
    let mut map = std::collections::HashMap::new();

    let output = match Command::new("pct").arg("list").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return map,
    };

    let entries: Vec<(String, String)> = output.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let vmid = parts.first()?.to_string();
            let pct_name = parts.last().map(|s| s.to_string()).unwrap_or_default();
            Some((vmid, pct_name))
        })
        .collect();

    // Fetch configs in parallel
    let configs: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = entries.iter().map(|(vmid, _)| {
            let vmid = vmid.clone();
            s.spawn(move || {
                Command::new("pct").args(["config", &vmid]).output().ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default()
            })
        }).collect();
        handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
    });

    for ((vmid, pct_name), cfg) in entries.iter().zip(configs.iter()) {
        let mut hostname = pct_name.clone();
        let mut memory_mb: u64 = 0;
        let mut cores: u64 = 0;
        let mut os_type = String::new();

        for cline in cfg.lines() {
            let cline = cline.trim();
            if cline.starts_with("hostname:") {
                hostname = cline.split(':').nth(1).unwrap_or("").trim().to_string();
            } else if cline.starts_with("memory:") {
                memory_mb = cline.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            } else if cline.starts_with("cores:") {
                cores = cline.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            } else if cline.starts_with("ostype:") {
                os_type = cline.split(':').nth(1).unwrap_or("").trim().to_string();
            }
        }

        let mut spec_parts = Vec::new();
        if cores > 0 { spec_parts.push(format!("{} core{}", cores, if cores > 1 { "s" } else { "" })); }
        if memory_mb > 0 {
            if memory_mb >= 1024 { spec_parts.push(format!("{}GB RAM", memory_mb / 1024)); }
            else { spec_parts.push(format!("{}MB RAM", memory_mb)); }
        }
        if !os_type.is_empty() { spec_parts.push(os_type); }

        map.insert(vmid.clone(), (hostname, spec_parts.join(", ")));
    }

    map
}

/// Restore with real-time progress tracking via callback
pub fn restore_from_pbs_with_progress<F>(
    storage: &BackupStorage,
    snapshot: &str,
    archive: &str,
    target_dir: &str,
    on_progress: F,
    overwrite: bool,
) -> Result<String, String>
where
    F: Fn(String, Option<f64>),
{
    let repo = pbs_repo_string(storage);

    // Parse snapshot "type/id/timestamp" to determine backup kind and ID
    let parts: Vec<&str> = snapshot.split('/').collect();
    let snap_type = parts.first().copied().unwrap_or("");
    let snap_id = parts.get(1).copied().unwrap_or("");

    // Compute the effective target directory based on backup type:
    // - ct: /var/lib/lxc/pbs-{id}/rootfs/  (LXC container structure)
    // - vm: /var/lib/wolfstack/vms/pbs-{id}/  (VM disk image)
    // - host/other: use target_dir as-is
    let (effective_target, container_name) = if snap_type == "ct" && !snap_id.is_empty() {
        let name = format!("pbs-{}", snap_id);
        let rootfs = format!("/var/lib/lxc/{}/rootfs", name);
        on_progress(format!("Setting up container {}...", name), Some(0.5));
        (rootfs, Some(name))
    } else if snap_type == "vm" && !snap_id.is_empty() {
        let name = format!("pbs-{}", snap_id);
        let vm_dir = format!("/var/lib/wolfstack/vms/{}", name);
        on_progress(format!("Setting up VM directory {}...", name), Some(0.5));
        (vm_dir, None)
    } else {
        (target_dir.to_string(), None)
    };

    // Check if target already has files from a previous restore
    if Path::new(&effective_target).exists() {
        let has_files = fs::read_dir(&effective_target)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if has_files && !overwrite {
            return Err("TARGET_EXISTS".to_string());
        }
        if has_files && overwrite {
            on_progress("Cleaning previous restore files...".to_string(), Some(0.2));
            let _ = fs::remove_dir_all(&effective_target);
        }
    }

    fs::create_dir_all(&effective_target)
        .map_err(|e| format!("Failed to create target dir: {}", e))?;

    let snapshot_fixed = fix_pbs_snapshot_timestamp(snapshot);

    on_progress("Detecting archive...".to_string(), Some(1.0));

    let actual_archive = if archive.is_empty() || archive == "root.pxar" {
        detect_pbs_archive(storage, &snapshot_fixed).unwrap_or_else(|| "root.pxar".to_string())
    } else {
        archive.to_string()
    };

    on_progress(format!("Downloading {}...", actual_archive), Some(2.0));

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot_fixed)
       .arg(&actual_archive)
       .arg(&effective_target)
       .arg("--repository").arg(&repo)
       .arg("--ignore-ownership").arg("true");

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    // Capture stderr for error reporting — stdout can be null since we monitor dir size
    use std::process::Stdio;
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to start proxmox-backup-client: {}", e))?;

    // Monitor target directory size growth while child runs
    let target_path = effective_target.clone();
    let progress_fn = &on_progress;

    loop {
        // Check if child is still running
        match child.try_wait() {
            Ok(Some(_status)) => break,  // Process finished
            Ok(None) => {},               // Still running
            Err(_) => break,
        }

        // Measure directory size
        let dir_size = dir_size_bytes(&target_path);
        let size_str = format_size_human(dir_size);
        progress_fn(format!("Downloaded: {}", size_str), None);

        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let status = child.wait()
        .map_err(|e| format!("PBS restore wait failed: {}", e))?;

    if !status.success() {
        // Read stderr for the actual error message
        let stderr_output = if let Some(stderr) = child.stderr.take() {
            use std::io::Read;
            let mut buf = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let _ = reader.read_to_string(&mut buf);
            buf
        } else {
            String::new()
        };
        let err_detail = if stderr_output.trim().is_empty() {
            format!("exit code {}", status.code().unwrap_or(-1))
        } else {
            stderr_output.trim().to_string()
        };
        return Err(format!("PBS restore failed for '{}': {}", snapshot_fixed, err_detail));
    }

    // Post-restore: create LXC config for container restores
    if let Some(ref cname) = container_name {
        let container_dir = format!("/var/lib/lxc/{}", cname);
        let config_path = format!("{}/config", container_dir);

        on_progress("Creating LXC configuration...".to_string(), Some(98.0));

        // Try to extract pct.conf.blob from PBS for reference
        let pct_path = format!("{}/pct.conf.blob", container_dir);
        let mut pct_cmd = Command::new("proxmox-backup-client");
        pct_cmd.arg("restore").arg(&snapshot_fixed).arg("pct.conf.blob").arg(&pct_path)
            .arg("--repository").arg(&repo);
        if !pbs_pw.is_empty() { pct_cmd.env("PBS_PASSWORD", pbs_pw); }
        if !storage.pbs_fingerprint.is_empty() { pct_cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint); }
        let _ = pct_cmd.output(); // Best-effort

        // Create a basic LXC config so `lxc-ls` discovers the container
        if !Path::new(&config_path).exists() {
            let lxc_config = format!(
                "# LXC container restored from PBS\n\
                 # Original Proxmox VMID: {}\n\
                 # Snapshot: {}\n\
                 lxc.uts.name = {}\n\
                 lxc.rootfs.path = dir:{}/rootfs\n\
                 lxc.include = /usr/share/lxc/config/common.conf\n\
                 lxc.arch = amd64\n\
                 \n\
                 # Network — configure as needed\n\
                 lxc.net.0.type = veth\n\
                 lxc.net.0.link = lxcbr0\n\
                 lxc.net.0.flags = up\n\
                 lxc.net.0.hwaddr = 00:16:3e:xx:xx:xx\n",
                snap_id, snapshot, cname, container_dir,
            );
            let _ = fs::write(&config_path, lxc_config);

        }


        return Ok(format!("Container {} restored to {}", cname, container_dir));
    }


    // Post-restore: if the extracted files contain a Docker backup tar.gz, load and create the container
    if snap_type == "host" {
        // Look for docker-*.tar.gz files in the restore directory
        if let Ok(entries) = fs::read_dir(&effective_target) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with("docker-") && fname.ends_with(".tar.gz") {
                    on_progress(format!("Loading Docker image from {}...", fname), Some(90.0));
                    let tar_path = entry.path();

                    let output = Command::new("sh")
                        .args(["-c", &format!("gunzip -c '{}' | docker load", tar_path.display())])
                        .output();

                    match output {
                        Ok(o) if o.status.success() => {
                            let load_result = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            let image_name = load_result
                                .lines()
                                .find_map(|line| line.strip_prefix("Loaded image: "))
                                .unwrap_or("unknown")
                                .to_string();
                            on_progress(format!("Image loaded: {}", image_name), Some(95.0));

                            // Extract container name from filename: docker-{name}-{timestamp}.tar.gz
                            // Strip "docker-" prefix and ".tar.gz" suffix, then remove the timestamp suffix
                            let parts: Vec<&str> = fname.strip_prefix("docker-").unwrap_or(&fname)
                                .strip_suffix(".tar.gz").unwrap_or(&fname)
                                .rsplitn(3, '-').collect();
                            let container_name = if parts.len() == 3 { parts[2].to_string() }
                                else { snap_id.to_string() };

                            if !container_name.is_empty() {
                                // Look for inspect config alongside the tar
                                let inspect_name = fname.replace(".tar.gz", ".inspect.json");
                                let inspect_path = Path::new(&effective_target).join(&inspect_name);
                                let inspect_json = fs::read_to_string(&inspect_path).ok()
                                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
                                if inspect_json.is_some() {
                                    on_progress("Found original container config".to_string(), Some(95.5));
                                }
                                let _ = fs::remove_file(&inspect_path);

                                // Check if container already exists
                                let check = Command::new("docker")
                                    .args(["container", "inspect", &container_name])
                                    .output();
                                let exists = check.map(|o| o.status.success()).unwrap_or(false);

                                if exists && !overwrite {
                                    on_progress(format!("Container '{}' already exists — image loaded but not replaced", container_name), Some(98.0));
                                } else {
                                    if exists {
                                        on_progress(format!("Replacing existing container '{}'...", container_name), Some(96.0));
                                        let _ = Command::new("docker").args(["stop", &container_name]).output();
                                        let _ = Command::new("docker").args(["rm", "-f", &container_name]).output();
                                    }

                                    let extra_args = inspect_json.as_ref()
                                        .map(|j| docker_run_args_from_inspect(j))
                                        .unwrap_or_else(|| vec!["--restart".to_string(), "unless-stopped".to_string()]);

                                    on_progress(format!("Creating container '{}'...", container_name), Some(97.0));
                                    let mut run_args = vec!["run".to_string(), "-d".to_string(), "--name".to_string(), container_name.clone()];
                                    run_args.extend(extra_args);
                                    run_args.push(image_name.clone());
                                    let create = Command::new("docker")
                                        .args(&run_args)
                                        .output();
                                    match create {
                                        Ok(c) if c.status.success() => {
                                            on_progress(format!("Docker container '{}' restored and started", container_name), Some(99.0));
                                        }
                                        Ok(c) => {
                                            let err = String::from_utf8_lossy(&c.stderr);
                                            on_progress(format!("Image loaded but container creation failed: {}", err.trim()), Some(99.0));
                                        }
                                        Err(e) => {
                                            on_progress(format!("Image loaded but failed to create container: {}", e), Some(99.0));
                                        }
                                    }
                                }
                            }

                            // Clean up the tar.gz
                            let _ = fs::remove_file(&tar_path);
                            return Ok(format!("Docker container '{}' restored from PBS", container_name));
                        }
                        Ok(o) => {
                            let err = String::from_utf8_lossy(&o.stderr);
                            on_progress(format!("Docker load failed: {}", err.trim()), Some(99.0));
                        }
                        Err(e) => {
                            on_progress(format!("Failed to run docker load: {}", e), Some(99.0));
                        }
                    }
                }
            }
        }
    }

    Ok(format!("Restored {} to {}", actual_archive, effective_target))
}

/// Recursively calculate directory size in bytes
fn dir_size_bytes(path: &str) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += dir_size_bytes(&p.to_string_lossy());
            } else if let Ok(meta) = p.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// Format bytes as human-readable size
fn format_size_human(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.0} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Convert Unix epoch timestamps in snapshot IDs to ISO format
/// Input:  "ct/105/1707600000" -> "ct/105/2024-02-11T04:00:00Z"
/// If already in ISO format (contains 'T'), pass through unchanged
fn fix_pbs_snapshot_timestamp(snapshot: &str) -> String {
    let parts: Vec<&str> = snapshot.splitn(3, '/').collect();
    if parts.len() != 3 {
        return snapshot.to_string();
    }
    let timestamp_part = parts[2];
    // If it already contains 'T' or '-', it's probably already in ISO format
    if timestamp_part.contains('T') || timestamp_part.contains('-') {
        return snapshot.to_string();
    }
    // Try to parse as Unix epoch
    if let Ok(epoch) = timestamp_part.parse::<i64>() {
        if let Some(dt) = chrono::DateTime::from_timestamp(epoch, 0) {
            return format!("{}/{}/{}", parts[0], parts[1], dt.format("%Y-%m-%dT%H:%M:%SZ"));
        }
    }
    snapshot.to_string()
}

/// Try to detect the correct archive name by listing snapshot files
fn detect_pbs_archive(storage: &BackupStorage, snapshot: &str) -> Option<String> {
    let repo = pbs_repo_string(storage);
    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("snapshot").arg("files")
       .arg(snapshot)
       .arg("--output-format").arg("json")
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", &storage.pbs_fingerprint);
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let output = cmd.output().ok()?;
    if !output.status.success() {
        warn!("Failed to list snapshot files: {}", String::from_utf8_lossy(&output.stderr));
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: serde_json::Value = serde_json::from_str(&stdout).ok()?;
    
    // Look for .pxar or .img archives (skip index.json and catalog)
    if let Some(arr) = files.as_array() {
        for f in arr {
            let filename = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
            // Prefer .pxar (filesystem backup), then .img (disk image)
            if filename.ends_with(".pxar.didx") || filename.ends_with(".pxar") {
                let name = filename.trim_end_matches(".didx");

                return Some(name.to_string());
            }
        }
        // Fallback to .img
        for f in arr {
            let filename = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
            if filename.ends_with(".img.fidx") || filename.ends_with(".img") {
                let name = filename.trim_end_matches(".fidx");

                return Some(name.to_string());
            }
        }
    }
    None
}

/// Check if PBS is reachable and proxmox-backup-client is installed
pub fn check_pbs_status(storage: &BackupStorage) -> serde_json::Value {
    let client_installed = Command::new("which")
        .arg("proxmox-backup-client")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !client_installed {
        return serde_json::json!({
            "installed": false,
            "connected": false,
            "error": "proxmox-backup-client not installed"
        });
    }

    if storage.pbs_server.is_empty() {
        return serde_json::json!({
            "installed": true,
            "connected": false,
            "error": "PBS not configured"
        });
    }

    // Try to list snapshots as a connectivity test
    match list_pbs_snapshots(storage) {
        Ok(snapshots) => {
            let count = snapshots.as_array().map(|a| a.len()).unwrap_or(0);
            serde_json::json!({
                "installed": true,
                "connected": true,
                "server": storage.pbs_server,
                "datastore": storage.pbs_datastore,
                "snapshot_count": count
            })
        },
        Err(e) => serde_json::json!({
            "installed": true,
            "connected": false,
            "server": storage.pbs_server,
            "error": e
        })
    }
}

/// Fill any empty PBS connection/credential fields on `storage` from the
/// saved PBS config. The cluster-wide scheduler form only sends
/// `{type:"pbs"}` — without this merge, scheduled runs invoke
/// proxmox-backup-client with no PBS_PASSWORD and fail with
/// "no password input mechanism".
pub fn merge_pbs_secrets(storage: &mut BackupStorage) {
    if storage.storage_type != StorageType::Pbs { return; }
    let saved = load_pbs_config();
    if storage.pbs_server.is_empty()      { storage.pbs_server      = saved.pbs_server; }
    if storage.pbs_datastore.is_empty()   { storage.pbs_datastore   = saved.pbs_datastore; }
    if storage.pbs_user.is_empty()        { storage.pbs_user        = saved.pbs_user; }
    if storage.pbs_token_name.is_empty()  { storage.pbs_token_name  = saved.pbs_token_name; }
    if storage.pbs_token_secret.is_empty(){ storage.pbs_token_secret= saved.pbs_token_secret; }
    if storage.pbs_password.is_empty()    { storage.pbs_password    = saved.pbs_password; }
    if storage.pbs_fingerprint.is_empty() { storage.pbs_fingerprint = saved.pbs_fingerprint; }
    if storage.pbs_namespace.is_empty()   { storage.pbs_namespace   = saved.pbs_namespace; }
}

/// PBS configuration — stored in /etc/wolfstack/pbs/config.json
pub fn load_pbs_config() -> BackupStorage {
    let path = "/etc/wolfstack/pbs/config.json";
    if let Ok(content) = fs::read_to_string(path) {
        if let Ok(storage) = serde_json::from_str::<BackupStorage>(&content) {
            return storage;
        }
    }
    BackupStorage {
        storage_type: StorageType::Pbs,
        ..BackupStorage::default()
    }
}

/// Save PBS configuration
pub fn save_pbs_config(storage: &BackupStorage) -> Result<(), String> {
    let path = "/etc/wolfstack/pbs/config.json";
    fs::create_dir_all("/etc/wolfstack/pbs")
        .map_err(|e| format!("Failed to create PBS config dir: {}", e))?;
    let json = serde_json::to_string_pretty(storage)
        .map_err(|e| format!("Failed to serialize PBS config: {}", e))?;
    fs::write(path, json)
        .map_err(|e| format!("Failed to write PBS config: {}", e))?;
    Ok(())
}

// ─── Proxmox Config Translation (for migration) ───

/// Parse a Proxmox VE VM .conf file into a WolfStack-compatible JSON config
/// Proxmox format: key: value (one per line), with comments starting with #
#[allow(dead_code)]
pub fn proxmox_conf_to_vm_config(conf: &str, vm_name: &str) -> serde_json::Value {
    let mut cpus: u32 = 1;
    let mut memory_mb: u32 = 1024;
    let mut disk_size_gb: u32 = 10;
    let mut net_model = "virtio".to_string();
    let mut os_disk_bus = "virtio".to_string();
    let mut iso_path: Option<String> = None;

    for line in conf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "cores" => { cpus = value.parse().unwrap_or(1); },
            "sockets" => {
                let sockets: u32 = value.parse().unwrap_or(1);
                cpus *= sockets; // total = cores * sockets
            },
            "memory" => { memory_mb = value.parse().unwrap_or(1024); },
            "ide0" | "ide1" | "ide2" | "scsi0" | "sata0" | "virtio0" => {
                // Parse disk: local:vm-100-disk-0,size=32G
                if !value.contains("media=cdrom") {
                    for part in value.split(',') {
                        if part.starts_with("size=") {
                            let size_str = part.trim_start_matches("size=");
                            disk_size_gb = size_str.trim_end_matches('G')
                                .trim_end_matches('T')
                                .parse().unwrap_or(10);
                            if size_str.ends_with('T') {
                                disk_size_gb *= 1024;
                            }
                        }
                    }
                    // Detect bus type from key
                    if key.starts_with("ide") { os_disk_bus = "ide".to_string(); }
                    else if key.starts_with("sata") { os_disk_bus = "ide".to_string(); } // QEMU maps sata to ide
                    else if key.starts_with("scsi") { os_disk_bus = "scsi".to_string(); }
                    else { os_disk_bus = "virtio".to_string(); }
                }
                // Check for ISO (cdrom)
                if value.contains("media=cdrom") {
                    let iso = value.split(',').next().unwrap_or("");
                    if !iso.is_empty() && iso != "none" {
                        iso_path = Some(iso.to_string());
                    }
                }
            },
            "net0" => {
                // Parse network: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0
                if value.starts_with("virtio") { net_model = "virtio".to_string(); }
                else if value.starts_with("e1000") { net_model = "e1000".to_string(); }
                else if value.starts_with("rtl8139") { net_model = "rtl8139".to_string(); }
            },
            _ => {}
        }
    }

    serde_json::json!({
        "name": vm_name,
        "cpus": cpus,
        "memory_mb": memory_mb,
        "disk_size_gb": disk_size_gb,
        "running": false,
        "auto_start": false,
        "os_disk_bus": os_disk_bus,
        "net_model": net_model,
        "iso_path": iso_path,
        "extra_disks": [],
        "source": "proxmox"
    })
}

/// Parse a Proxmox LXC .conf into key info for recreation
#[allow(dead_code)]
pub fn proxmox_lxc_conf_to_config(conf: &str) -> serde_json::Value {
    let mut hostname = String::new();
    let mut memory_mb: u32 = 512;
    let mut cpus: u32 = 1;
    let mut rootfs_size = String::new();
    let mut net_config = String::new();
    let mut ostype = "ubuntu".to_string();

    for line in conf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 { continue; }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "hostname" => { hostname = value.to_string(); },
            "memory" => { memory_mb = value.parse().unwrap_or(512); },
            "cores" => { cpus = value.parse().unwrap_or(1); },
            "rootfs" => {
                for part in value.split(',') {
                    if part.starts_with("size=") {
                        rootfs_size = part.trim_start_matches("size=").to_string();
                    }
                }
            },
            "net0" => { net_config = value.to_string(); },
            "ostype" => { ostype = value.to_string(); },
            _ => {}
        }
    }

    serde_json::json!({
        "hostname": hostname,
        "memory_mb": memory_mb,
        "cpus": cpus,
        "rootfs_size": rootfs_size,
        "net_config": net_config,
        "ostype": ostype,
        "source": "proxmox"
    })
}
