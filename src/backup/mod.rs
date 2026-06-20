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
    /// Arbitrary host system folder (e.g. /etc, /home, app data). The
    /// folder path travels in `BackupTarget::system_path`; `name` carries
    /// an operator-supplied label used in the backup filename.
    SystemPath,
}

impl std::fmt::Display for BackupTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "docker"),
            Self::Lxc => write!(f, "lxc"),
            Self::Vm => write!(f, "vm"),
            Self::Config => write!(f, "config"),
            Self::SystemPath => write!(f, "systempath"),
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
    /// Host source paths (bind mounts / system sub-paths) and named-volume
    /// names to SKIP when backing this target up. Empty (the default for
    /// every existing config) preserves the original "back everything up"
    /// behaviour exactly. Matched exactly, or as a trailing-slash prefix
    /// (`/mnt/media` excludes `/mnt/media/...`).
    #[serde(default)]
    pub exclude_mounts: Vec<String>,
    /// For `SystemPath` targets: the absolute host directory to archive.
    /// Empty for every other target type.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub system_path: String,
}

impl Default for BackupTarget {
    fn default() -> Self {
        Self {
            target_type: BackupTargetType::Config,
            name: String::new(),
            hostname: None,
            state: None,
            specs: None,
            exclude_mounts: Vec::new(),
            system_path: String::new(),
        }
    }
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
    /// PBS file-level (pxar) backup. When false (the default, and what every
    /// existing config has) WolfStack uploads its `.tar.gz` wrapped in a
    /// single `backup.pxar` — opaque, restorable only as a whole. When true,
    /// the workload's CONTENT directory is uploaded as native pxar archives so
    /// PBS's per-file restore works. Golden-Rule safe: absent field → false →
    /// byte-identical to the original behaviour.
    #[serde(default)]
    pub pbs_file_level: bool,
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
            pbs_file_level: false,
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

    /// Return a copy with an empty Local `path` filled in from the configured
    /// default backup directory. Called when a backup entry is created so the
    /// concrete destination is baked into the stored entry — restore then reads
    /// exactly where the backup was written, independent of any later change to
    /// the default. Non-Local types and already-set paths are returned as-is.
    fn with_concrete_local(&self, default_dir: &str) -> BackupStorage {
        let mut s = self.clone();
        if matches!(s.storage_type, StorageType::Local) && s.path.trim().is_empty() {
            s.path = default_dir.to_string();
        }
        s
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
    fn pbs_fingerprint_gets_colons_when_pasted_without_them() {
        // 64 hex chars, no separators → colon-separated (what the client needs).
        let raw = "650b69e1c2d3a4b5e6f70819202122232425262728292a2b2c2d2e2f30313233";
        let out = format_pbs_fingerprint(raw);
        assert_eq!(out, "65:0b:69:e1:c2:d3:a4:b5:e6:f7:08:19:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33");
        assert_eq!(out.matches(':').count(), 31); // 32 bytes → 31 separators
    }

    #[test]
    fn pbs_fingerprint_already_coloned_is_idempotent() {
        let coloned = "65:0b:69:e1:c2:d3:a4:b5:e6:f7:08:19:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33";
        assert_eq!(format_pbs_fingerprint(coloned), coloned);
        // Whitespace/newlines from a paste are tolerated too.
        assert_eq!(format_pbs_fingerprint(&format!("  {coloned}\n")), coloned);
    }

    fn pbs(user: &str, token: &str) -> BackupStorage {
        BackupStorage {
            storage_type: StorageType::Pbs,
            pbs_user: user.to_string(),
            pbs_token_name: token.to_string(),
            pbs_server: "pbs.example.com".to_string(),
            pbs_datastore: "store".to_string(),
            ..BackupStorage::default()
        }
    }

    #[test]
    fn pbs_repo_token_form_when_user_has_realm_only() {
        assert_eq!(pbs_repo_string(&pbs("root@pam", "wolfstack-backup")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_does_not_double_the_token_when_user_already_has_it() {
        // Operator pasted the whole `root@pam!wolfstack-backup` into the user
        // field AND set the token name — must not produce a doubled `!token`.
        assert_eq!(pbs_repo_string(&pbs("root@pam!wolfstack-backup", "wolfstack-backup")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_full_principal_in_token_field() {
        // Livid's case: user=root@pam, and the WHOLE `root@pam!wolfstack-backup`
        // (the form the PBS UI shows) pasted into the token-NAME field. Must not
        // double the user prefix.
        assert_eq!(pbs_repo_string(&pbs("root@pam", "root@pam!wolfstack-backup")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_full_token_in_user_with_no_token_name() {
        assert_eq!(pbs_repo_string(&pbs("root@pam!wolfstack-backup", "")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_password_auth_no_token() {
        assert_eq!(pbs_repo_string(&pbs("root@pam", "")),
                   "root@pam@pbs.example.com:store");
    }

    #[test]
    fn pbs_fingerprint_non_sha256_passes_through_untouched() {
        // Not a clean 64-char hex string → returned trimmed, never mangled.
        assert_eq!(format_pbs_fingerprint("  not-a-fingerprint  "), "not-a-fingerprint");
        assert_eq!(format_pbs_fingerprint(""), "");
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
    fn with_concrete_local_fills_empty_local_path() {
        let s = BackupStorage {
            storage_type: StorageType::Local,
            path: String::new(),
            ..BackupStorage::default()
        };
        // An empty Local path is concretized to the configured default, so the
        // stored entry is self-sufficient at restore time.
        assert_eq!(s.with_concrete_local("/mnt/r2-backups").path, "/mnt/r2-backups");
    }

    #[test]
    fn with_concrete_local_keeps_nonempty_local_path() {
        let s = BackupStorage {
            storage_type: StorageType::Local,
            path: "/data/backups".into(),
            ..BackupStorage::default()
        };
        assert_eq!(s.with_concrete_local("/mnt/r2-backups").path, "/data/backups");
    }

    #[test]
    fn with_concrete_local_ignores_non_local_types() {
        let s = BackupStorage {
            storage_type: StorageType::S3,
            path: String::new(),
            ..BackupStorage::default()
        };
        assert_eq!(s.with_concrete_local("/mnt/r2-backups").path, "");
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

    // ── Feature 1: mount exclusion matching ──

    #[test]
    fn mount_exclude_exact_match() {
        let ex = vec!["/mnt/media".to_string()];
        assert!(mount_is_excluded("/mnt/media", &ex));
        assert!(mount_is_excluded("/mnt/media/", &ex)); // trailing slash normalised
    }

    #[test]
    fn mount_exclude_prefix_match() {
        let ex = vec!["/mnt/media".to_string()];
        assert!(mount_is_excluded("/mnt/media/tv", &ex));
        assert!(mount_is_excluded("/mnt/media/movies/4k", &ex));
    }

    #[test]
    fn mount_exclude_no_false_prefix() {
        // "/mnt/media2" must NOT be caught by an exclude of "/mnt/media".
        let ex = vec!["/mnt/media".to_string()];
        assert!(!mount_is_excluded("/mnt/media2", &ex));
        assert!(!mount_is_excluded("/mnt/other", &ex));
    }

    #[test]
    fn mount_exclude_volume_name() {
        let ex = vec!["pgdata".to_string()];
        assert!(mount_is_excluded("pgdata", &ex));
        assert!(!mount_is_excluded("pgdata-backup", &ex));
    }

    #[test]
    fn mount_exclude_empty_list_matches_nothing() {
        // Golden Rule: no exclusions configured → nothing skipped, so existing
        // targets back up byte-identically.
        assert!(!mount_is_excluded("/mnt/media", &[]));
        assert!(!mount_is_excluded("anyvol", &[]));
    }

    #[test]
    fn mount_exclude_ignores_empty_entries() {
        // An empty exclude entry must NOT match everything.
        let ex = vec!["".to_string(), "   ".to_string()];
        assert!(!mount_is_excluded("/mnt/media", &ex));
    }

    #[test]
    fn mount_exclude_trailing_slash_on_entry() {
        let ex = vec!["/mnt/media/".to_string()];
        assert!(mount_is_excluded("/mnt/media", &ex));
        assert!(mount_is_excluded("/mnt/media/tv", &ex));
    }

    // ── Feature 3: system-path validation ──

    #[test]
    fn system_path_rejects_relative() {
        assert!(validate_system_path("etc").is_err());
        assert!(validate_system_path("").is_err());
    }

    #[test]
    fn system_path_rejects_dangerous_roots() {
        assert!(validate_system_path("/").is_err());
        assert!(validate_system_path("/proc").is_err());
        assert!(validate_system_path("/sys").is_err());
        assert!(validate_system_path("/dev").is_err());
        assert!(validate_system_path("/proc/1").is_err());
        assert!(validate_system_path("/sys/kernel").is_err());
    }

    #[test]
    fn system_path_accepts_existing_dir() {
        // /tmp always exists and is a directory on a Linux test host.
        assert!(validate_system_path("/tmp").is_ok());
        assert!(validate_system_path("/tmp/").is_ok());
    }

    #[test]
    fn system_path_rejects_nonexistent() {
        assert!(validate_system_path("/this/does/not/exist/anywhere-xyz").is_err());
    }

    // ── Feature 2: PBS file-level entry detection ──

    #[test]
    fn file_level_entry_detected_by_prefix_and_type() {
        let mut e = BackupEntry {
            id: "x".into(),
            target: BackupTarget { target_type: BackupTargetType::Lxc, name: "ct1".into(), ..Default::default() },
            storage: BackupStorage { storage_type: StorageType::Pbs, ..BackupStorage::default() },
            filename: "pbsfl-ct-ct1-20260620-101010.pxar".into(),
            size_bytes: 0, created_at: String::new(), status: BackupStatus::Completed,
            error: String::new(), schedule_id: String::new(), comments: String::new(),
            node_hostname: String::new(), docker_config: String::new(), mounts: Vec::new(),
        };
        assert!(is_pbs_file_level_entry(&e));
        // A tarball-in-pxar PBS entry is NOT file-level.
        e.filename = "lxc-ct1-20260620-101010.tar.gz".into();
        assert!(!is_pbs_file_level_entry(&e));
        // A local backup with a pbsfl-ish name is NOT file-level (wrong storage).
        e.filename = "pbsfl-ct-ct1-20260620-101010.pxar".into();
        e.storage.storage_type = StorageType::Local;
        assert!(!is_pbs_file_level_entry(&e));
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

/// Does `candidate` (a bind source path or a named-volume name) match any
/// entry in the operator's exclude list? Match is either exact, or a
/// trailing-slash prefix so excluding `/mnt/media` also excludes
/// `/mnt/media/tv`. Trailing slashes on the exclude entry itself are
/// normalised away so `/mnt/media/` and `/mnt/media` behave the same.
/// Empty exclude entries are ignored (they'd otherwise match everything).
fn mount_is_excluded(candidate: &str, exclude_mounts: &[String]) -> bool {
    let cand = candidate.trim_end_matches('/');
    exclude_mounts.iter().any(|raw| {
        let ex = raw.trim().trim_end_matches('/');
        if ex.is_empty() {
            return false;
        }
        cand == ex || cand.starts_with(&format!("{}/", ex))
    })
}

/// One bind/volume mount discovered on a container, for the UI's
/// "choose what to exclude" checklist. Distinct from `MountInfo` (which
/// records what actually went INTO a backup) — this is a pre-backup
/// inventory with no archive yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMount {
    /// "volume" | "bind"
    #[serde(rename = "type")]
    pub mount_type: String,
    /// Named-volume name (volume) or host source path (bind). This is the
    /// value the operator puts in `exclude_mounts` to skip it.
    pub source: String,
    /// Mount point inside the container.
    pub destination: String,
    /// On-disk size of the source in bytes, 0 if not cheaply known.
    #[serde(default)]
    pub size_bytes: u64,
}

/// Cheap directory size — used only for the mount-inventory UI so the
/// operator can see which binds are the huge ones worth excluding. Bounded
/// by `du`'s own traversal; failures return 0 rather than blocking the UI.
fn quick_dir_size_bytes(path: &str) -> u64 {
    // `du -sb` reports apparent total bytes for the whole tree. It's the
    // same tool the rest of the codebase shells out to and avoids a manual
    // recursive walk here. Failure (missing path, permission) → 0.
    let out = match Command::new("du").args(["-sb", path]).output() {
        Ok(o) if o.status.success() => o,
        _ => return 0,
    };
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().next()
        .and_then(|first| first.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Enumerate a Docker container's bind/volume mounts (no backup performed).
/// Reuses the same `docker inspect` Mounts[] parsing as `backup_docker`.
pub fn discover_docker_mounts(name: &str) -> Result<Vec<DiscoveredMount>, String> {
    let inspect = Command::new("docker")
        .args(["inspect", name])
        .output()
        .map_err(|e| format!("Failed to run docker inspect: {}", e))?;
    if !inspect.status.success() {
        return Err(format!(
            "docker inspect {} failed: {}",
            name,
            String::from_utf8_lossy(&inspect.stderr).trim()
        ));
    }
    let inspect_val: serde_json::Value =
        serde_json::from_slice(&inspect.stdout).unwrap_or(serde_json::Value::Null);
    let mounts_arr = inspect_val
        .get(0)
        .and_then(|c| c.get("Mounts"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    let mut out = Vec::new();
    for m in &mounts_arr {
        let mtype = m.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        let source = m.get("Source").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let destination = m.get("Destination").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vol_name = m.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match mtype {
            "volume" => {
                let label = if !vol_name.is_empty() { vol_name.clone() } else { source.clone() };
                let data_dir = if !source.is_empty() && Path::new(&source).is_dir() {
                    source.clone()
                } else if !vol_name.is_empty() {
                    format!("/var/lib/docker/volumes/{}/_data", vol_name)
                } else {
                    String::new()
                };
                let size = if data_dir.is_empty() { 0 } else { quick_dir_size_bytes(&data_dir) };
                out.push(DiscoveredMount {
                    mount_type: "volume".into(),
                    source: label,
                    destination,
                    size_bytes: size,
                });
            }
            "bind" => {
                let size = if Path::new(&source).exists() { quick_dir_size_bytes(&source) } else { 0 };
                out.push(DiscoveredMount {
                    mount_type: "bind".into(),
                    source,
                    destination,
                    size_bytes: size,
                });
            }
            _ => { /* tmpfs/npipe — never backed up, omit from the checklist */ }
        }
    }
    Ok(out)
}

/// Enumerate an LXC container's bind mounts (no backup performed).
/// Native LXC: parse `lxc.mount.entry` lines in the container config.
/// Proxmox: parse `mp<N>:` mountpoints from `pct config`.
pub fn discover_lxc_mounts(name: &str) -> Result<Vec<DiscoveredMount>, String> {
    let mut out = Vec::new();
    if crate::containers::is_proxmox() {
        // `pct config <vmid>` → lines like `mp0: storage:vm-105-disk-1,mp=/data,size=8G`
        // or bind form `mp0: /host/path,mp=/data`. We expose the host source
        // (the part before the first comma) when it's an absolute path bind.
        let cfg = Command::new("pct").args(["config", name]).output()
            .map_err(|e| format!("Failed to run pct config: {}", e))?;
        if !cfg.status.success() {
            return Err(format!("pct config {} failed: {}", name,
                String::from_utf8_lossy(&cfg.stderr).trim()));
        }
        let text = String::from_utf8_lossy(&cfg.stdout);
        for line in text.lines() {
            let line = line.trim();
            // Match mp0:, mp1:, … (mountpoints). rootfs is excluded — it's the
            // container's own rootfs, always backed up.
            let rest = match line.strip_prefix("mp") {
                Some(r) => r, None => continue,
            };
            let colon = match rest.find(':') {
                Some(c) => c, None => continue,
            };
            let idx_part = &rest[..colon];
            if idx_part.is_empty() || !idx_part.chars().all(|c| c.is_ascii_digit()) { continue; }
            let spec = rest[colon + 1..].trim();
            let volume = spec.split(',').next().unwrap_or("").trim();
            // Bind mount form: the volume part is an absolute host path.
            let mut mountpoint = String::new();
            for opt in spec.split(',') {
                if let Some(mp) = opt.trim().strip_prefix("mp=") {
                    mountpoint = mp.to_string();
                }
            }
            if volume.starts_with('/') {
                let size = if Path::new(volume).exists() { quick_dir_size_bytes(volume) } else { 0 };
                out.push(DiscoveredMount {
                    mount_type: "bind".into(),
                    source: volume.to_string(),
                    destination: mountpoint,
                    size_bytes: size,
                });
            } else {
                // Storage-backed mountpoint (ZFS/LVM/dir volume). It IS part of
                // the vzdump backup; expose it so the operator can exclude it
                // by its volume id.
                out.push(DiscoveredMount {
                    mount_type: "volume".into(),
                    source: volume.to_string(),
                    destination: mountpoint,
                    size_bytes: 0,
                });
            }
        }
        return Ok(out);
    }

    // Native LXC — parse the container config for `lxc.mount.entry` lines.
    let base = crate::containers::lxc_base_dir(name);
    let cfg_path = format!("{}/{}/config", base, name);
    let text = fs::read_to_string(&cfg_path)
        .map_err(|e| format!("Failed to read LXC config {}: {}", cfg_path, e))?;
    for line in text.lines() {
        let line = line.trim();
        // lxc.mount.entry = <source> <mountpoint> <fstype> <options> <dump> <pass>
        if let Some(rest) = line.strip_prefix("lxc.mount.entry") {
            let rest = rest.trim_start_matches('=').trim();
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            let source = parts[0];
            let mountpoint = parts[1];
            // Only host-path bind mounts are interesting — skip the kernel
            // pseudo-filesystems (proc/sysfs/etc.) whose source isn't a path.
            if !source.starts_with('/') { continue; }
            let size = if Path::new(source).exists() { quick_dir_size_bytes(source) } else { 0 };
            out.push(DiscoveredMount {
                mount_type: "bind".into(),
                source: source.to_string(),
                destination: mountpoint.to_string(),
                size_bytes: size,
            });
        }
    }
    Ok(out)
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
pub fn backup_docker(name: &str, exclude_mounts: &[String]) -> Result<(PathBuf, u64, String, Vec<MountInfo>), String> {
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
                // Operator-excluded? Match on the volume name OR its host
                // source path. Record it as skipped (empty archive) so the
                // backup metadata shows what was deliberately left out.
                if mount_is_excluded(&vol_name, exclude_mounts)
                    || (!source.is_empty() && mount_is_excluded(&source, exclude_mounts))
                {
                    mounts.push(MountInfo {
                        mount_type: "volume".into(),
                        source: vol_name.clone(),
                        destination: destination.clone(),
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: "excluded by operator".into(),
                    });
                    continue;
                }
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
                // Operator-excluded? Match on the host source path (exact or
                // prefix). This is the headline use case — sonarr/radarr media
                // arrays bind-mounted in that would blow up the staging dir.
                if mount_is_excluded(&source, exclude_mounts) {
                    mounts.push(MountInfo {
                        mount_type: "bind".into(),
                        source,
                        destination,
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: "excluded by operator".into(),
                    });
                    continue;
                }
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
pub fn backup_lxc(name: &str, exclude_mounts: &[String]) -> Result<(PathBuf, u64), String> {

    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");

    // Proxmox: use vzdump which properly handles ZFS/LVM/Ceph storage backends
    if crate::containers::is_proxmox() {
        return backup_lxc_proxmox(name, &staging, &timestamp.to_string(), exclude_mounts);
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

    // Create tar.gz of the entire container directory (rootfs + config).
    // Honour operator exclusions: only paths that actually fall UNDER the
    // backed-up tree (`lxc_path`) make sense as `tar --exclude` args — a
    // native LXC bind mount whose source lives elsewhere on the host isn't
    // inside the rootfs tarball anyway. We rewrite each excluded absolute
    // path to one relative to `lxc_base` (tar's -C dir) so the glob matches.
    let mut tar_cmd = Command::new("tar");
    let lxc_prefix = format!("{}/", lxc_path);
    for raw in exclude_mounts {
        let ex = raw.trim().trim_end_matches('/');
        if ex.is_empty() { continue; }
        // Under the container tree? (the rootfs sits at lxc_path)
        if ex != lxc_path && !ex.starts_with(&lxc_prefix) { continue; }
        if let Ok(rel) = Path::new(ex).strip_prefix(&lxc_base) {
            // GNU tar's `--exclude=<dir>` skips the directory AND its whole
            // subtree (no trailing glob needed — and a `/*` glob would
            // require `--wildcards` to even work). Match the archived
            // member name, which is `name/rootfs/...` here.
            tar_cmd.arg(format!("--exclude={}", rel.to_string_lossy()));
        }
    }
    tar_cmd.args(["czf", &tar_path.to_string_lossy(), "-C", &lxc_base, name]);
    let output = tar_cmd
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

/// Append operator mount-exclusions to a vzdump command. vzdump takes
/// `--exclude-path <path>` (repeatable) — the path is the mountpoint as
/// seen INSIDE the container, or a host path/glob. We pass each excluded
/// entry through verbatim; the operator picked these from the discovered
/// mount list which already reports container-relative mountpoints.
/// Source: pve-docs vzdump.1 — `--exclude-path <string>` "Exclude certain
/// files/directories", may be specified multiple times.
fn vzdump_apply_excludes(cmd: &mut Command, exclude_mounts: &[String]) {
    for raw in exclude_mounts {
        let ex = raw.trim();
        // vzdump `--exclude-path` expects a filesystem path/glob, not a storage
        // volume id (`local-lvm:vm-105-disk-0`). discover_lxc_mounts exposes
        // both; only forward the path-shaped ones so a volume id can't become a
        // bogus exclude arg that vzdump rejects.
        if ex.is_empty() || !ex.starts_with('/') { continue; }
        cmd.arg("--exclude-path").arg(ex);
    }
}

/// Proxmox LXC backup using vzdump — handles ZFS, LVM, Ceph, and directory storage
fn backup_lxc_proxmox(vmid: &str, staging: &Path, timestamp: &str, exclude_mounts: &[String]) -> Result<(PathBuf, u64), String> {
    // vzdump creates a full container backup including rootfs on any storage backend
    // --mode snapshot uses LVM/ZFS snapshots for live backup when available,
    // falls back to suspend mode, then stop mode
    let mut cmd = Command::new("vzdump");
    cmd.args([
        vmid,
        "--dumpdir", &staging.to_string_lossy(),
        "--mode", "snapshot",
        "--compress", "zstd",
    ]);
    vzdump_apply_excludes(&mut cmd, exclude_mounts);
    let output = cmd
        .output()
        .map_err(|e| format!("vzdump failed to start: {}", e))?;

    // Combine stdout+stderr — vzdump may log the archive path to either
    let all_output = format!("{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        // Snapshot mode may not be supported (e.g. directory storage) — retry with stop mode
        let mut cmd2 = Command::new("vzdump");
        cmd2.args([
            vmid,
            "--dumpdir", &staging.to_string_lossy(),
            "--mode", "stop",
            "--compress", "zstd",
        ]);
        vzdump_apply_excludes(&mut cmd2, exclude_mounts);
        let output2 = cmd2
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

/// Backup a KVM/QEMU VM — copy disk images + JSON config.
///
/// Platform dispatch:
///   • **Proxmox** → `backup_vm_proxmox` (vzdump-style: stop VM, read
///     `/etc/pve/qemu-server/<vmid>.conf`, convert every disk to qcow2
///     via `pvesm path` + `qemu-img convert`, write portable JSON
///     config, tar everything). Output matches the native WolfStack
///     archive format so `restore_vm_local` works on any host.
///   • **libvirt** → `backup_vm_libvirt` (stop VM, read disks via
///     `virsh domblklist --details`, convert each to qcow2 via
///     `qemu-img convert`, write portable JSON config, tar everything).
///     Same archive format as the Proxmox + native paths.
///   • **native** → existing in-place tar.gz with the RAII restart
///     guard from A.1.
pub fn backup_vm(name: &str) -> Result<(PathBuf, u64), String> {
    if crate::containers::is_proxmox() {
        return backup_vm_proxmox(name);
    }
    if crate::containers::is_libvirt() {
        return backup_vm_libvirt(name);
    }
    backup_vm_native(name)
}

/// Backup a libvirt-managed VM. Same pattern as Proxmox: stop with
/// RAII restart guard, delegate the export to the shared helper in
/// vms::manager. Output matches the native WolfStack format so
/// `restore_vm_local` works on any host.
fn backup_vm_libvirt(name: &str) -> Result<(PathBuf, u64), String> {
    let manager = crate::vms::manager::VmManager::new();
    let vm = manager.list_vms().into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("libvirt VM '{}' not found", name))?;

    // Same C1 fix as Proxmox: graceful stop + poll + force fallback.
    // virsh shutdown is fire-and-forget too — must wait for the VM
    // to actually power down before qemu-img convert touches the disk.
    let was_running = vm.running;
    if was_running {
        stop_vm_and_wait_for_stop(&manager, name, 60)?;
    }
    let _restart_guard = VmRestartGuard { name: name.to_string(), should_restart: was_running };

    let staging = ensure_staging_dir()?;
    let staging_str = staging.to_string_lossy().to_string();
    let archive = crate::vms::manager::export_libvirt_vm_with_staging(name, Some(&staging_str))?;
    let size = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    Ok((archive, size))
}

/// RAII guard that restarts a VM on Drop. Used by every backup_vm_*
/// path to ensure we restart the VM on EVERY exit (success, error,
/// panic). Pre-fix this struct was duplicated inline in three
/// functions; reviewer rightly flagged the maintenance risk.
struct VmRestartGuard {
    name: String,
    should_restart: bool,
}
impl Drop for VmRestartGuard {
    fn drop(&mut self) {
        if !self.should_restart { return; }
        let m = crate::vms::manager::VmManager::new();
        if let Err(e) = m.start_vm(&self.name) {
            tracing::error!(target: "backup",
                "VM backup: failed to restart {} after backup: {} \
                 — operator must start the VM manually", self.name, e);
        } else {
            tracing::info!(target: "backup",
                "VM backup: restarted {} after backup", self.name);
        }
    }
}

/// Graceful stop with poll-until-stopped + force fallback. Pre-fix
/// the backup paths called `stop_vm(name, false)` and slept 2 s —
/// but on Proxmox/libvirt that's fire-and-forget (qm shutdown / virsh
/// shutdown run detached). The 2 s sleep was nowhere near enough for
/// the VM to actually power down, so `qemu-img convert` ran against a
/// LIVE disk → corrupt backup. Now we initiate graceful, poll for
/// `running=false`, force-stop after `grace_secs` if needed.
///
/// `max_wait_secs` budgets the graceful phase. After that we send
/// the force signal (qm stop / virsh destroy) and wait another 5s.
/// Returns Err only if even the force-stop fails or the VM is not
/// known. Returns Ok if VM is already stopped at entry.
fn stop_vm_and_wait_for_stop(
    manager: &crate::vms::manager::VmManager,
    name: &str,
    max_wait_secs: u64,
) -> Result<(), String> {
    // N2: no initial `list_vms()` check — callers gate on their own
    // `was_running` already. Saves a per-backup directory scan on
    // Proxmox + closes a TOCTOU window between callers and the helper.
    //
    // Initiate graceful shutdown.
    manager.stop_vm(name, false)
        .map_err(|e| format!("graceful stop of '{}' failed to start: {}", name, e))?;

    // Poll until stopped or until deadline.
    //
    // A1 fix: tri-state interpretation of list_vms. The previous
    // `.unwrap_or(false)` collapsed two very different outcomes into
    // "stopped":
    //   • VM not in list (deleted, renamed, OR list_vms failed because
    //     `qm list` / `virsh list` errored transiently) → None
    //   • VM in list with running=true → Some(true)
    //   • VM in list with running=false → Some(false)
    // Only `Some(false)` is genuine confirmation that the VM is stopped.
    // A transient subprocess failure used to silently false-positive
    // here, letting `qemu-img convert` run against a still-live disk.
    // Now we keep polling on `None` (don't assume stopped); only
    // `Some(false)` exits the loop early.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(max_wait_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let state: Option<bool> = manager.list_vms().into_iter()
            .find(|v| v.name == name)
            .map(|v| v.running);
        match state {
            Some(false) => {
                // Brief settle so qemu-img doesn't race storage unmount.
                std::thread::sleep(std::time::Duration::from_secs(1));
                return Ok(());
            }
            Some(true) | None => {
                // Keep polling. None means VM not listed — could be
                // a transient list_vms error, or the VM was deleted
                // out from under us. Either way, don't assume stopped.
            }
        }
    }

    // Force stop — guest didn't ACPI-shutdown in time.
    tracing::warn!(target: "backup",
        "VM '{}' did not gracefully stop within {}s — forcing power off \
         for backup consistency. Filesystem inside the guest may need fsck on next boot.",
        name, max_wait_secs);
    manager.stop_vm(name, true)
        .map_err(|e| format!("force stop of '{}' failed after graceful timeout: {}", name, e))?;

    // A2 fix: actually verify the VM stopped after the force-stop,
    // don't just sleep and trust it. `qm stop` is documented as
    // synchronous, but races have been reported, and `virsh destroy`
    // returns before the QEMU process necessarily exits on some
    // libvirt versions. Three 1-second polls is enough to catch the
    // common case without lengthening the worst-case backup time.
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Some(false) = manager.list_vms().into_iter()
            .find(|v| v.name == name)
            .map(|v| v.running)
        {
            return Ok(());
        }
    }
    Err(format!(
        "force-stop of '{}' returned Ok but the VM is still listed as running 3 s later \
         — refusing to back up a live disk", name))
}

/// Native WolfStack VM backup — the original path. KVM/QEMU process
/// spawned by `wolfstack-vm-<name>`, config + disk in
/// `/var/lib/wolfstack/vms/`. Stop the VM, archive its files, restart
/// via the RAII guard so it never stays stopped silently.
fn backup_vm_native(name: &str) -> Result<(PathBuf, u64), String> {
    // The VM name flows into a shell string (the socat socket path) and
    // into tar/JSON filenames. Refuse anything that isn't filename-safe so
    // a crafted name can't inject shell here. Real VM names are already
    // filename-safe (used as vm-<name>.tar.gz / <name>.json), so this
    // never rejects a legitimate VM.
    if !crate::auth::is_safe_name(name) {
        return Err(format!("refusing to back up VM with unsafe name: {:?}", name));
    }

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
        // N1 fix: poll until stopped instead of a fixed 5s sleep that
        // could be too short for a slow guest. Cap at 60s, then
        // pkill -9 if the guest still hasn't powered down. Matches
        // the budget the Proxmox/libvirt paths use via
        // stop_vm_and_wait_for_stop.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut stopped_gracefully = false;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if !is_vm_running(name) {
                stopped_gracefully = true;
                break;
            }
        }
        if !stopped_gracefully {
            tracing::warn!(target: "backup",
                "VM '{}' did not gracefully ACPI-shutdown within 60s — forcing pkill \
                 for backup consistency. Guest filesystem may need fsck on next boot.", name);
            let _ = Command::new("pkill")
                .args(["-f", &format!("wolfstack-vm-{}", name)])
                .output();
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    // RAII guard: restart on EVERY exit path (success, tar-failure
    // early return, panic). Shared `VmRestartGuard` is defined
    // module-level so all three backup_vm_* paths use the same logic.
    let _restart_guard = VmRestartGuard {
        name: name.to_string(),
        should_restart: was_running,
    };

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

    // Restart handled by RestartGuard's Drop above — fires on success
    // here OR on any earlier `?`/`return`. Don't add a manual restart
    // call below; we'd double-start.

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

    Ok((tar_path, size))
}

/// Backup a Proxmox-managed VM. Stops the VM (with an RAII restart
/// guard so it never stays stopped silently), then delegates the
/// actual export to `vms::manager::export_proxmox_vm_with_staging`
/// (also called by the migration path — single source of truth for
/// the per-platform export format). Output is a WolfStack-format
/// tar.gz that restores cleanly on any host.
fn backup_vm_proxmox(name: &str) -> Result<(PathBuf, u64), String> {
    let manager = crate::vms::manager::VmManager::new();
    let vm = manager.list_vms().into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("Proxmox VM '{}' not found", name))?;

    // Stop VM for consistent export. C1 fix: graceful stop + poll-
    // until-stopped + force fallback (pre-fix was stop_vm(false) which
    // is fire-and-forget on Proxmox — qemu-img would have run against
    // a live disk → corrupt backup). Shared VmRestartGuard ensures we
    // always restart afterwards.
    let was_running = vm.running;
    if was_running {
        stop_vm_and_wait_for_stop(&manager, name, 60)?;
    }
    let _restart_guard = VmRestartGuard { name: name.to_string(), should_restart: was_running };

    // Delegate the export. The shared helper lives in vms::manager so
    // migration uses the exact same archive format.
    let staging = ensure_staging_dir()?;
    let staging_str = staging.to_string_lossy().to_string();
    let archive = crate::vms::manager::export_proxmox_vm_with_staging(name, Some(&staging_str))?;
    let size = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    Ok((archive, size))
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

/// Refuse the filesystem root and the kernel virtual filesystems (and any
/// sub-path of them). Shared by backup + restore validation. `for_backup`
/// tunes the message; `/` itself is always refused.
fn reject_dangerous_root(path: &str, for_backup: bool) -> Result<(), String> {
    let canonical = path.trim_end_matches('/');
    let canonical = if canonical.is_empty() { "/" } else { canonical };
    let kernel_fs: &[&str] = &["/proc", "/sys", "/dev"];
    // "/" is refused as a BACKUP source (it would pull the whole host into
    // staging) but is a LEGITIMATE RESTORE target: a top-level folder like
    // /etc is archived with leaf member `etc/`, so extracting into "/" lands
    // it back in place and writes only under /etc — nothing else at the root
    // is touched. So allow "/" for restore, refuse it for backup.
    if canonical == "/" {
        return if for_backup {
            Err("Refusing to back up '/' — it's the system root; \
                 pick a specific folder like /etc or /home".to_string())
        } else {
            Ok(())
        };
    }
    if kernel_fs.iter().any(|d| *d == canonical) {
        return Err(if for_backup {
            format!("Refusing to back up '{}' — kernel filesystem; \
                     pick a specific folder like /etc or /home", canonical)
        } else {
            format!("Refusing to restore into '{}' — kernel filesystem", canonical)
        });
    }
    for d in kernel_fs {
        if canonical.starts_with(&format!("{}/", d)) {
            return Err(format!("'{}' is under {} — kernel state, not application data", canonical, d));
        }
    }
    Ok(())
}

/// Reject system-folder backup targets that point at dangerous roots.
/// The path must be absolute, exist, and be a directory; the kernel
/// virtual filesystems and the filesystem root are refused outright —
/// archiving them is either meaningless (/proc, /sys, /dev) or a
/// foot-gun (`/` would try to pull the entire host into staging).
/// The path is canonicalised (symlinks resolved) before the deny-check so a
/// `/data/evil -> /proc` symlink can't sneak past it.
pub fn validate_system_path(path: &str) -> Result<(), String> {
    let p = path.trim();
    if p.is_empty() {
        return Err("System folder path is required".into());
    }
    if !p.starts_with('/') {
        return Err("System folder path must be absolute (start with '/')".into());
    }
    // Check the literal path first (catches `/proc` typed directly).
    reject_dangerous_root(p, true)?;
    // Then resolve symlinks and re-check — a symlinked path that resolves to a
    // forbidden root must also be rejected. canonicalize() also confirms the
    // path exists.
    let resolved = fs::canonicalize(p)
        .map_err(|e| format!("Cannot access '{}': {}", p, e))?;
    let resolved_str = resolved.to_string_lossy().to_string();
    reject_dangerous_root(&resolved_str, true)?;
    let meta = fs::metadata(&resolved)
        .map_err(|e| format!("Cannot access '{}': {}", resolved_str, e))?;
    if !meta.is_dir() {
        return Err(format!("'{}' is not a directory", resolved_str));
    }
    Ok(())
}

/// Backup an arbitrary host system folder — tar.gz the directory to staging.
/// `label` is the operator-supplied name baked into the filename so several
/// folder backups are distinguishable; `path` is the absolute directory.
/// `exclude_mounts` skips sub-paths (same exact/prefix matching as binds).
pub fn backup_system_path(label: &str, path: &str, exclude_mounts: &[String]) -> Result<(PathBuf, u64), String> {
    validate_system_path(path)?;
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    // Filename uses the SAME `systempath-` prefix the scanner/guesser key off.
    let safe_label = sanitize_archive_name(if label.trim().is_empty() {
        Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("folder")
    } else { label.trim() });
    let filename = format!("systempath-{}-{}.tar.gz", safe_label, timestamp);
    let tar_path = staging.join(&filename);

    let src = path.trim_end_matches('/');
    // Archive the folder itself (so restore lands it back where it was):
    // `tar -C <parent> <basename>` keeps the leaf dir as the top archive
    // entry. For a top-level folder like /etc the parent is "/".
    let p = Path::new(src);
    let parent = p.parent().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|| "/".into());
    let leaf = p.file_name().map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| format!("Cannot determine folder name from '{}'", src))?;

    let mut tar_cmd = Command::new("tar");
    let prefix = format!("{}/", src);
    for raw in exclude_mounts {
        let ex = raw.trim().trim_end_matches('/');
        if ex.is_empty() { continue; }
        // Only sub-paths of the backed-up folder make sense to exclude.
        if ex != src && !ex.starts_with(&prefix) { continue; }
        if let Ok(rel) = Path::new(ex).strip_prefix(&parent) {
            // `--exclude=<dir>` already excludes the subtree (see backup_lxc).
            tar_cmd.arg(format!("--exclude={}", rel.to_string_lossy()));
        }
    }
    tar_cmd.args(["czf", &tar_path.to_string_lossy(), "-C", &parent, &leaf]);
    let output = tar_cmd
        .output()
        .map_err(|e| format!("Failed to tar system folder: {}", e))?;
    if !output.status.success() {
        return Err(format!("System folder tar failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    Ok((tar_path, size))
}

/// Restore a system-folder backup by extracting the tarball into `target_dir`
/// (the parent into which the archived top-level folder is unpacked). The
/// archive stores the folder by its leaf name, so extracting into the
/// ORIGINAL parent restores it in place. Destructive over existing data —
/// callers must require explicit confirmation.
pub fn restore_system_path(entry: &BackupEntry, target_dir: &str) -> Result<String, String> {
    let dest = target_dir.trim();
    if dest.is_empty() || !dest.starts_with('/') {
        return Err("Restore target directory must be an absolute path".into());
    }
    // Refuse the kernel filesystems (/proc, /sys, /dev) as the restore
    // destination. "/" IS allowed here: the archive's top member is the
    // folder's leaf name (e.g. `etc/`), so extracting into "/" recreates only
    // `/etc/...` in place and never touches other root entries — that's the
    // correct in-place restore for a top-level folder. Destructive over
    // existing data, so callers must require explicit confirmation.
    reject_dangerous_root(dest, false)?;
    fs::create_dir_all(dest)
        .map_err(|e| format!("Cannot create restore target '{}': {}", dest, e))?;
    let local_path = retrieve_backup(entry)?;
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", dest])
        .output();
    // Always drop the staging copy, on success and on every error path.
    let _ = fs::remove_file(&local_path);
    let output = output.map_err(|e| format!("Failed to extract system folder backup: {}", e))?;
    if !output.status.success() {
        return Err(format!("System folder extract failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(format!("System folder restored into {}", dest))
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
                BackupTarget { target_type: BackupTargetType::Docker, name: name.clone(), ..Default::default() },
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
                BackupTarget { target_type: BackupTargetType::Lxc, name: name.clone(), ..Default::default() },
                storage,
            ));
        }
    }

    // Backup all VMs — native WolfStack VMs only at this stage.
    //
    // A.2 fix: the pre-fix code filtered `is_dir()` in /var/lib/wolfstack/vms,
    // which only matched the extra-volumes-subdir layout (rare). The
    // common case is a flat `name.json + name.qcow2` layout, and those
    // were silently invisible to "backup all". Now we parse .json
    // config files — same source of truth as VmManager::list_vms()'s
    // native scan path. Proxmox + libvirt branches below enumerate
    // via VmManager which dispatches to the platform-correct path
    // (qm/virsh).
    if crate::containers::is_proxmox() || crate::containers::is_libvirt() {
        // Enumerate Proxmox / libvirt VMs via VmManager (same source
        // the dashboard uses — /etc/pve/qemu-server/*.conf on Proxmox,
        // `virsh list --all` on libvirt). backup_vm dispatches by
        // platform so all three types (native / Proxmox / libvirt) get
        // the correct backup path.
        let manager = crate::vms::manager::VmManager::new();
        for vm in manager.list_vms() {
            entries.push(create_backup_entry(
                BackupTarget {
                    target_type: BackupTargetType::Vm,
                    name: vm.name.clone(),
                    ..Default::default()
                },
                storage,
            ));
        }
    } else {
        // Native WolfStack VMs — parse .json configs from /var/lib/wolfstack/vms.
        let vm_dir = Path::new("/var/lib/wolfstack/vms");
        if vm_dir.exists() {
            if let Ok(read) = fs::read_dir(vm_dir) {
                for entry in read.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                    let file_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n, None => continue,
                    };
                    if file_name.ends_with(".runtime.json") { continue; }
                    let name = file_name.trim_end_matches(".json").to_string();
                    if name.is_empty() { continue; }
                    entries.push(create_backup_entry(
                        BackupTarget {
                            target_type: BackupTargetType::Vm,
                            name, ..Default::default()
                        },
                        storage,
                    ));
                }
            }
        }
    }

    // Backup config
    entries.push(create_backup_entry(
        BackupTarget { target_type: BackupTargetType::Config, name: String::new(), ..Default::default() },
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
        BackupTargetType::SystemPath => {
            if target.system_path.is_empty() {
                format!("System folder: {}", target.name)
            } else {
                format!("System folder: {} ({})", target.name, target.system_path)
            }
        }
    };
    format!("[{}] {}", cluster, detail)
}

/// Create a single backup entry — performs the backup and stores it
fn create_backup_entry(target: BackupTarget, storage: &BackupStorage) -> BackupEntry {
    // Bake the concrete Local directory into the entry up front so the stored
    // destination is self-sufficient (restore reads it back unchanged).
    let storage = &storage.with_concrete_local(&crate::paths::get().backup_local_dir);
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let hostname = local_hostname();
    let comments = backup_comments(&target);
    let cluster = local_cluster_name();

    // PBS file-level (pxar) path — see create_backup_with_log for the rationale.
    if storage.storage_type == StorageType::Pbs && storage.pbs_file_level {
        if let Some(res) = make_pbs_file_level_entry(&target, storage, &comments, &cluster, &hostname, None) {
            match res {
                Ok(entry) => return entry,
                Err(e) => {
                    error!("PBS file-level backup failed for {:?}: {}", target.target_type, e);
                    return BackupEntry {
                        id, target, storage: storage.clone(),
                        filename: String::new(), size_bytes: 0, created_at: now,
                        status: BackupStatus::Failed, error: e,
                        schedule_id: String::new(), comments, node_hostname: hostname,
                        docker_config: String::new(), mounts: Vec::new(),
                    };
                }
            }
        }
        // else: fall through to the tarball path (VM/Proxmox-LXC/Config).
    }

    let (result, docker_config, mounts) = match target.target_type {
        BackupTargetType::Docker => {
            match backup_docker(&target.name, &target.exclude_mounts) {
                Ok((path, size, config, m)) => (Ok((path, size)), config, m),
                Err(e) => (Err(e), String::new(), Vec::new()),
            }
        }
        BackupTargetType::Lxc => (backup_lxc(&target.name, &target.exclude_mounts), String::new(), Vec::new()),
        BackupTargetType::Vm => (backup_vm(&target.name), String::new(), Vec::new()),
        BackupTargetType::Config => (backup_config(), String::new(), Vec::new()),
        BackupTargetType::SystemPath => (
            backup_system_path(&target.name, &target.system_path, &target.exclude_mounts),
            String::new(), Vec::new(),
        ),
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
    // PBS token-auth repo form: `user@realm!tokenid@server:datastore`.
    // The principal is `user@realm!tokenid`. Operators paste the token in
    // assorted ways: the bare id (`wolfstack-backup`) in the token field, OR the
    // WHOLE `root@pam!wolfstack-backup` that the PBS UI shows — into either the
    // token field or the user field. We must NOT re-prepend the user when a
    // field already carries the full principal, or we get the doubled
    // `root@pam!root@pam!wolfstack-backup` PBS rejects as "token disabled".
    let user = storage.pbs_user.trim();
    let token = storage.pbs_token_name.trim();
    let principal = if token.is_empty() {
        user.to_string()
    } else if token.contains('!') || token.contains('@') {
        // The token field already holds the full `user@realm!tokenid`.
        token.to_string()
    } else if user.contains('!') {
        // The user field already holds the full principal; token is the bare id.
        user.to_string()
    } else {
        format!("{}!{}", user, token)
    };
    format!("{}@{}:{}", principal, storage.pbs_server, storage.pbs_datastore)
}

/// Normalize a PBS server TLS fingerprint to the colon-separated form
/// `proxmox-backup-client` expects (`65:0b:69:…`). Operators paste it in either
/// form (the PBS UI and `proxmox-backup-manager cert info` show different ones);
/// passed un-coloned, the client can't match it and drops to an interactive
/// y/n prompt the daemon can't answer, so the connection just fails. We strip
/// any separators, then re-insert a colon every byte. A value that isn't a
/// clean 64-char SHA-256 hex string is returned trimmed-but-unchanged rather
/// than mangled — a faithful pass-through beats a corrupted fingerprint.
pub fn format_pbs_fingerprint(fp: &str) -> String {
    let hex: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 {
        return fp.trim().to_string();
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
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
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
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
            list_cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
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
                            // The snapshot's time component must be an RFC3339
                            // string (e.g. "ct/131/2026-05-21T09:35:01Z"): the
                            // PBS CLI parses the <snapshot> argument as a
                            // BackupDir and rejects a raw unix epoch.
                            // `snapshot list --output-format json` reports
                            // `backup-time` as an epoch, so convert it here —
                            // without this, `snapshot notes update` fails and
                            // the snapshot lands on PBS with an empty comment.
                            // Source: pbs.proxmox.com/docs/backup-client.html
                            //   — snapshot paths shown as host/elsa/2019-12-03T09:35:01Z
                            if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
                                best_time = stime;
                                best_snap = format!("{}/{}/{}", st, si,
                                    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
                            }
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
                            notes_cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
                        }
                        if !storage.pbs_namespace.is_empty() {
                            notes_cmd.arg("--ns").arg(&storage.pbs_namespace);
                        }
                        notes_cmd.arg("--").arg(&best_snap).arg(notes_text);
                        if !pbs_pw.is_empty() {
                            notes_cmd.env("PBS_PASSWORD", pbs_pw);
                        }
                        match notes_cmd.output() {
                            Ok(out) if out.status.success() => {
                                if let Some(log_tx) = log {
                                    let _ = log_tx.send(
                                        "  PBS: snapshot notes set".to_string());
                                }
                            }
                            Ok(out) => {
                                let err = String::from_utf8_lossy(&out.stderr);
                                warn!("Failed to set PBS snapshot notes for {}: {}",
                                    best_snap, err.trim());
                                if let Some(log_tx) = log {
                                    let _ = log_tx.send(format!(
                                        "  PBS: warning — could not set snapshot \
                                         notes: {}", err.trim()));
                                }
                            }
                            Err(e) => {
                                warn!("Failed to run `proxmox-backup-client \
                                       snapshot notes update`: {}", e);
                                if let Some(log_tx) = log {
                                    let _ = log_tx.send(format!(
                                        "  PBS: warning — could not run snapshot \
                                         notes update: {}", e));
                                }
                            }
                        }
                    } else {
                        warn!("PBS snapshot notes: no snapshot matching {}/{} \
                               found — comment not set", backup_type, backup_id);
                        if let Some(log_tx) = log {
                            let _ = log_tx.send(format!(
                                "  PBS: warning — uploaded snapshot {}/{} not \
                                 found, comment not set", backup_type, backup_id));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Return an Err carrying the standard MISSING_PACKAGE marker when
/// `proxmox-backup-client` isn't installed, so the UI shows its install
/// prompt instead of a raw spawn error.
/// Source: storage::MISSING_PACKAGE_MARKER = "MISSING_PACKAGE|"; format is
/// `MISSING_PACKAGE|<binary>|<debian_pkg>|<redhat_pkg>`.
fn ensure_pbs_client_installed() -> Result<(), String> {
    let present = Command::new("which")
        .arg("proxmox-backup-client")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }
    Err(format!(
        "{}{}|{}|{}",
        crate::storage::MISSING_PACKAGE_MARKER,
        "proxmox-backup-client",
        "proxmox-backup-client",
        "proxmox-backup-client",
    ))
}

/// Apply the shared PBS auth/connection env + flags to a backup-client
/// command. Centralises the fingerprint / namespace / password handling
/// every PBS invocation repeats, so file-level backup + restore can't
/// drift from the tarball path. `pbs_pw` chooses token-secret over
/// password, exactly as `store_pbs_with_notes_and_log` does.
fn pbs_apply_common(cmd: &mut Command, storage: &BackupStorage) {
    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }
}

/// One `name.pxar:dir` pair for a file-level PBS snapshot.
struct PxarPair {
    /// Archive name as it appears in the snapshot, e.g. "root.pxar".
    archive: String,
    /// Absolute host directory to archive.
    dir: PathBuf,
    /// Cleaned up after the snapshot (true for the docker `docker export`
    /// staging tree we materialise; false for paths we don't own such as a
    /// live rootfs or a system folder).
    ephemeral: bool,
}

/// Does PBS file-level apply to this target type, without performing any
/// side-effecting work (no docker export)? Used to decide whether to take
/// the file-level path or fall back to the tarball path. Docker / native LXC
/// / SystemPath qualify; VM / Proxmox-LXC / Config do not.
fn pbs_file_level_applies(target: &BackupTarget) -> bool {
    match target.target_type {
        BackupTargetType::Docker => true,
        BackupTargetType::Lxc => !crate::containers::is_proxmox(),
        BackupTargetType::SystemPath => true,
        BackupTargetType::Vm | BackupTargetType::Config => false,
    }
}

/// Build the pxar source pairs for a file-level PBS backup of `target`.
/// Returns (backup_type, backup_id, pairs). For Docker the container's
/// filesystem is materialised into a staging tree via `docker export`;
/// volumes/binds become their own pxar archives. For LXC the live rootfs
/// directory is used directly. For SystemPath the folder is used directly.
/// VMs return Err — disk images aren't a file tree (caller falls back to
/// the image backup).
fn build_pxar_pairs(target: &BackupTarget) -> Result<(String, String, Vec<PxarPair>), String> {
    let staging = ensure_staging_dir()?;
    match target.target_type {
        BackupTargetType::Docker => {
            let mut pairs: Vec<PxarPair> = Vec::new();
            // Materialise the container filesystem. `docker export` streams the
            // flattened container fs as a tar; pipe it into a fresh dir.
            let work = staging.join(format!("pbs-fl-docker-{}", Uuid::new_v4().simple()));
            fs::create_dir_all(&work)
                .map_err(|e| format!("file-level staging dir: {}", e))?;
            let rootfs = work.join("rootfs");
            fs::create_dir_all(&rootfs)
                .map_err(|e| format!("file-level rootfs dir: {}", e))?;
            // No shell — pipe `docker export <name>` directly into `tar -x`.
            // Using two Command processes with an OS pipe avoids any shell
            // metacharacter interpretation of the container name (a name like
            // `$(rm -rf /)` is just an argv element to docker, never evaluated).
            use std::process::Stdio;
            // stderr is sent to null rather than piped: nothing drains it while
            // we block on tar consuming stdout, and a full stderr pipe buffer
            // would deadlock docker. `docker export` stderr is trivial anyway;
            // the exit code is the signal we act on.
            let mut exporter = Command::new("docker")
                .arg("export")
                .arg(&target.name)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| { let _ = fs::remove_dir_all(&work); format!("docker export failed to start: {}", e) })?;
            let export_stdout = exporter.stdout.take()
                .ok_or_else(|| { let _ = fs::remove_dir_all(&work); "docker export produced no stdout".to_string() })?;
            let tar_status = Command::new("tar")
                .arg("-x")
                .arg("-C").arg(&rootfs)
                .stdin(Stdio::from(export_stdout))
                .status()
                .map_err(|e| { let _ = fs::remove_dir_all(&work); format!("tar extract failed to start: {}", e) })?;
            let exporter_status = exporter.wait()
                .map_err(|e| { let _ = fs::remove_dir_all(&work); format!("docker export wait failed: {}", e) })?;
            if !exporter_status.success() {
                let _ = fs::remove_dir_all(&work);
                return Err(format!("docker export failed (exit {})",
                    exporter_status.code().unwrap_or(-1)));
            }
            if !tar_status.success() {
                let _ = fs::remove_dir_all(&work);
                return Err("docker export tar extract failed".to_string());
            }
            pairs.push(PxarPair { archive: "root.pxar".into(), dir: rootfs, ephemeral: false });
            // The whole `work` dir is the ephemeral owner — track it via a
            // sentinel pair so cleanup removes it once.
            pairs.push(PxarPair { archive: String::new(), dir: work.clone(), ephemeral: true });

            // Volumes + binds as separate pxar archives, honouring exclusions.
            if let Ok(mounts) = discover_docker_mounts(&target.name) {
                let mut vol_idx = 0usize;
                let mut bind_idx = 0usize;
                for m in mounts {
                    if mount_is_excluded(&m.source, &target.exclude_mounts) { continue; }
                    match m.mount_type.as_str() {
                        "volume" => {
                            let data_dir = if Path::new(&m.source).is_dir() {
                                m.source.clone()
                            } else {
                                format!("/var/lib/docker/volumes/{}/_data", m.source)
                            };
                            if Path::new(&data_dir).is_dir() {
                                pairs.push(PxarPair {
                                    archive: format!("volume-{}.pxar", vol_idx),
                                    dir: PathBuf::from(data_dir),
                                    ephemeral: false,
                                });
                                vol_idx += 1;
                            }
                        }
                        "bind" => {
                            if bind_source_safe(&m.source).is_ok() && Path::new(&m.source).is_dir() {
                                pairs.push(PxarPair {
                                    archive: format!("bind-{}.pxar", bind_idx),
                                    dir: PathBuf::from(&m.source),
                                    ephemeral: false,
                                });
                                bind_idx += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(("ct".to_string(), target.name.clone(), pairs))
        }
        BackupTargetType::Lxc => {
            if crate::containers::is_proxmox() {
                // Proxmox rootfs commonly lives on ZFS/LVM (block) — not a
                // plain directory we can hand to pxar. File-level isn't
                // available there; caller falls back to the vzdump image.
                return Err("PBS file-level backup isn't available for Proxmox LXC \
                    (rootfs is on block storage) — using vzdump image backup instead".into());
            }
            let base = crate::containers::lxc_base_dir(&target.name);
            let rootfs = format!("{}/{}/rootfs", base, target.name);
            if !Path::new(&rootfs).is_dir() {
                return Err(format!("LXC rootfs not found at {}", rootfs));
            }
            Ok(("ct".to_string(), target.name.clone(),
                vec![PxarPair { archive: "root.pxar".into(), dir: PathBuf::from(rootfs), ephemeral: false }]))
        }
        BackupTargetType::SystemPath => {
            validate_system_path(&target.system_path)?;
            let dir = target.system_path.trim_end_matches('/').to_string();
            Ok(("host".to_string(),
                sanitize_archive_name(if target.name.trim().is_empty() {
                    Path::new(&dir).file_name().and_then(|n| n.to_str()).unwrap_or("folder")
                } else { target.name.trim() }),
                vec![PxarPair { archive: "root.pxar".into(), dir: PathBuf::from(dir), ephemeral: false }]))
        }
        BackupTargetType::Config => {
            // Config is the small tar bundle — no benefit to file-level; let
            // the caller keep the tarball-in-pxar path.
            Err("PBS file-level backup doesn't apply to config backups".into())
        }
        BackupTargetType::Vm => {
            Err("PBS file-level backup isn't available for VMs (disk images are \
                 not a file tree) — using the disk-image backup instead".into())
        }
    }
}

/// Perform a file-level (pxar) PBS backup for `target`. Uploads the
/// workload's content directory as native pxar archives so PBS per-file
/// restore works. `notes` becomes the snapshot comment. Returns the
/// snapshot's backup-type/backup-id so the caller can record a matching
/// BackupEntry (filename uses a `pbsfl-` marker so restore routes to the
/// file-level path). On VM/Proxmox-LXC/Config the caller falls back to the
/// tarball path — those return Err from build_pxar_pairs.
fn backup_pbs_file_level(
    target: &BackupTarget,
    storage: &BackupStorage,
    notes: Option<&str>,
    log: Option<&std::sync::mpsc::Sender<String>>,
) -> Result<(String, String), String> {
    ensure_pbs_client_installed()?;
    let repo = pbs_repo_string(storage);
    let (backup_type, backup_id, pairs) = build_pxar_pairs(target)?;

    // Owners we must clean up regardless of outcome.
    let ephemeral_dirs: Vec<PathBuf> = pairs.iter()
        .filter(|p| p.ephemeral)
        .map(|p| p.dir.clone())
        .collect();
    let cleanup = |dirs: &[PathBuf]| { for d in dirs { let _ = fs::remove_dir_all(d); } };

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("backup");
    let mut archive_count = 0;
    for p in &pairs {
        if p.archive.is_empty() { continue; } // sentinel cleanup-only pair
        cmd.arg(format!("{}:{}", p.archive, p.dir.display()));
        archive_count += 1;
    }
    if archive_count == 0 {
        cleanup(&ephemeral_dirs);
        return Err("file-level backup produced no archives to upload".into());
    }
    cmd.arg("--repository").arg(&repo)
       .arg("--backup-id").arg(&backup_id)
       .arg("--backup-type").arg(&backup_type);
    pbs_apply_common(&mut cmd, storage);

    if let Some(log_tx) = log {
        let _ = log_tx.send(format!("  PBS file-level: {} archive(s) → {}/{}",
            archive_count, backup_type, backup_id));
    }

    let output = cmd.output()
        .map_err(|e| { cleanup(&ephemeral_dirs); format!("Failed to run proxmox-backup-client: {}", e) })?;
    cleanup(&ephemeral_dirs);
    if !output.status.success() {
        return Err(format!("PBS file-level backup failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()));
    }
    if let Some(log_tx) = log {
        let _ = log_tx.send("  PBS file-level: upload complete".to_string());
    }

    // Set snapshot notes — reuse the same "find latest matching snapshot"
    // logic the tarball path uses.
    if let Some(notes_text) = notes {
        set_pbs_snapshot_notes(storage, &repo, &backup_type, &backup_id, notes_text, log);
    }
    Ok((backup_type, backup_id))
}

/// Filename marker that flags a BackupEntry as a PBS file-level (pxar)
/// snapshot rather than a tarball-in-pxar. Restore keys off this prefix to
/// route to the file-level restore path.
const PBS_FILE_LEVEL_PREFIX: &str = "pbsfl-";

/// True if this entry is a PBS file-level (pxar) snapshot.
fn is_pbs_file_level_entry(entry: &BackupEntry) -> bool {
    entry.storage.storage_type == StorageType::Pbs
        && entry.filename.starts_with(PBS_FILE_LEVEL_PREFIX)
}

/// Run a file-level PBS backup for `target` and build the resulting
/// BackupEntry. `None` means file-level doesn't apply to this target
/// (VM/Proxmox-LXC/Config) — the caller falls back to the tarball path.
/// `Some(Err)` means file-level applied but failed.
fn make_pbs_file_level_entry(
    target: &BackupTarget,
    storage: &BackupStorage,
    comments: &str,
    cluster: &str,
    hostname: &str,
    log: Option<&std::sync::mpsc::Sender<String>>,
) -> Option<Result<BackupEntry, String>> {
    // Probe applicability without side effects first (build_pxar_pairs does a
    // real `docker export` for Docker, so we must NOT call it just to test).
    if !pbs_file_level_applies(target) {
        return None;
    }
    let pbs_notes = format!("Cluster: {} | Node: {} | {}", cluster, hostname, comments);
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();
    match backup_pbs_file_level(target, storage, Some(&pbs_notes), log) {
        Ok((btype, bid)) => {
            let ts = Utc::now().format("%Y%m%d-%H%M%S");
            let filename = format!("{}{}-{}-{}.pxar", PBS_FILE_LEVEL_PREFIX, btype, bid, ts);
            Some(Ok(BackupEntry {
                id,
                target: target.clone(),
                storage: storage.clone(),
                filename,
                size_bytes: 0, // PBS dedups; per-snapshot byte size isn't reported here
                created_at: now,
                status: BackupStatus::Completed,
                error: String::new(),
                schedule_id: String::new(),
                comments: comments.to_string(),
                node_hostname: hostname.to_string(),
                docker_config: String::new(),
                mounts: Vec::new(),
            }))
        }
        Err(e) => Some(Err(e)),
    }
}

/// Full-archive restore of a PBS file-level (pxar) snapshot. Extracts the
/// `root.pxar` filesystem tree into `target_dir` using
/// `proxmox-backup-client restore <snapshot> <archive> <target>`.
/// Per-FILE restore (picking one file out of the tree) is done through PBS's
/// own web UI / `proxmox-backup-client catalog` + interactive restore — this
/// function does the complete-archive case end to end.
///
/// `target_override` (non-empty) chooses where the tree lands; empty applies
/// a type-appropriate default:
///   • native LXC  → the container rootfs (`<base>/<name>/rootfs`)
///   • SystemPath  → the original folder
///   • Docker      → a staging dir under the restore area (operator then has
///                   the files; container re-creation from a flat fs isn't
///                   automatic — surfaced in the returned message)
fn restore_pbs_file_level_entry(entry: &BackupEntry, target_override: &str) -> Result<String, String> {
    ensure_pbs_client_installed()?;
    let storage = &entry.storage;
    let repo = pbs_repo_string(storage);

    // Re-derive the snapshot type/id from the entry's target — robust against
    // any filename-parsing fragility. These mirror exactly what
    // build_pxar_pairs produced at backup time.
    let backup_type = match entry.target.target_type {
        BackupTargetType::SystemPath => "host",
        _ => "ct",
    }.to_string();
    let backup_id = match entry.target.target_type {
        BackupTargetType::SystemPath => sanitize_archive_name(if entry.target.name.trim().is_empty() {
            Path::new(entry.target.system_path.trim_end_matches('/'))
                .file_name().and_then(|n| n.to_str()).unwrap_or("folder")
        } else { entry.target.name.trim() }),
        _ => entry.target.name.clone(),
    };

    // Find the newest snapshot matching type/id.
    let mut list_cmd = Command::new("proxmox-backup-client");
    list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", &repo]);
    pbs_apply_common(&mut list_cmd, storage);
    let list_out = list_cmd.output()
        .map_err(|e| format!("Failed to list PBS snapshots: {}", e))?;
    if !list_out.status.success() {
        return Err(format!("PBS snapshot list failed: {}",
            String::from_utf8_lossy(&list_out.stderr).trim()));
    }
    let snaps: serde_json::Value = serde_json::from_slice(&list_out.stdout)
        .unwrap_or(serde_json::Value::Array(vec![]));
    let mut best_time: i64 = 0;
    let mut snapshot = String::new();
    if let Some(arr) = snaps.as_array() {
        for s in arr {
            let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
            let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
            let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
            if st != backup_type || si != backup_id || stime <= best_time { continue; }
            if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
                best_time = stime;
                snapshot = format!("{}/{}/{}", st, si,
                    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            }
        }
    }
    if snapshot.is_empty() {
        return Err(format!("No PBS file-level snapshot found for {}/{}", backup_type, backup_id));
    }

    // Decide the target directory.
    let target_dir = if !target_override.trim().is_empty() {
        target_override.trim().to_string()
    } else {
        match entry.target.target_type {
            BackupTargetType::Lxc => {
                let base = crate::containers::lxc_base_dir(&entry.target.name);
                format!("{}/{}/rootfs", base, entry.target.name)
            }
            BackupTargetType::SystemPath => entry.target.system_path.trim_end_matches('/').to_string(),
            _ => ensure_staging_dir()?
                .join(format!("pbs-fl-restore-{}", Uuid::new_v4().simple()))
                .to_string_lossy().to_string(),
        }
    };
    // Guard the filesystem root + kernel filesystems as a restore destination.
    // (A native-LXC rootfs target like `<base>/<name>/rootfs` is fine.)
    reject_dangerous_root(&target_dir, false)?;
    fs::create_dir_all(&target_dir)
        .map_err(|e| format!("Cannot create restore target '{}': {}", target_dir, e))?;

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot)
       .arg("root.pxar")
       .arg(&target_dir)
       .arg("--repository").arg(&repo);
    pbs_apply_common(&mut cmd, storage);
    let out = cmd.output()
        .map_err(|e| format!("PBS file-level restore failed: {}", e))?;
    if !out.status.success() {
        return Err(format!("PBS file-level restore error: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }

    let note = match entry.target.target_type {
        BackupTargetType::Docker =>
            " — container filesystem extracted; rebuild the container from these \
             files or use PBS's per-file restore for individual files.",
        _ => "",
    };
    Ok(format!("PBS file-level snapshot '{}' restored into {}{}", snapshot, target_dir, note))
}

/// Find the latest snapshot matching backup-type/id and set its notes.
/// Extracted so both the tarball and file-level paths share it.
fn set_pbs_snapshot_notes(
    storage: &BackupStorage,
    repo: &str,
    backup_type: &str,
    backup_id: &str,
    notes_text: &str,
    log: Option<&std::sync::mpsc::Sender<String>>,
) {
    let mut list_cmd = Command::new("proxmox-backup-client");
    list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", repo]);
    pbs_apply_common(&mut list_cmd, storage);
    let snap_out = match list_cmd.output() { Ok(o) => o, Err(_) => return };
    let snaps: serde_json::Value = match serde_json::from_slice(&snap_out.stdout) {
        Ok(v) => v, Err(_) => return,
    };
    let arr = match snaps.as_array() { Some(a) => a, None => return };
    let mut best_time: i64 = 0;
    let mut best_snap = String::new();
    for s in arr {
        let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
        let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
        let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
        if st != backup_type || si != backup_id || stime <= best_time { continue; }
        if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
            best_time = stime;
            best_snap = format!("{}/{}/{}", st, si,
                ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        }
    }
    if best_snap.is_empty() { return; }
    let mut notes_cmd = Command::new("proxmox-backup-client");
    notes_cmd.args(["snapshot", "notes", "update", "--repository", repo]);
    // pbs_apply_common adds --ns + the auth env (all options, safe before the
    // `--` positional separator below).
    pbs_apply_common(&mut notes_cmd, storage);
    notes_cmd.arg("--").arg(&best_snap).arg(notes_text);
    match notes_cmd.output() {
        Ok(out) if out.status.success() => {
            if let Some(log_tx) = log { let _ = log_tx.send("  PBS: snapshot notes set".to_string()); }
        }
        Ok(out) => warn!("Failed to set PBS snapshot notes for {}: {}",
            best_snap, String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => warn!("Failed to run snapshot notes update: {}", e),
    }
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
pub fn restore_lxc(entry: &BackupEntry, storage: &str, overwrite: bool, new_name: &str) -> Result<String, String> {
    // Fast-fail an obviously bad restore-as name before the (possibly
    // large, remote) archive download. restore_lxc_local re-validates,
    // so callers that bypass this wrapper (PBS restore) are still covered.
    let trimmed = new_name.trim();
    if !trimmed.is_empty() && !crate::auth::is_safe_name(trimmed) {
        return Err(format!(
            "'{}' is not a valid container name — use letters, digits, '-', '_' and '.' only, with no '..'.",
            trimmed));
    }
    if !trimmed.is_empty()
        && entry.filename.contains("vzdump")
        && crate::containers::is_proxmox()
        && trimmed.parse::<u32>().map(|n| n < 100).unwrap_or(true)
    {
        return Err(format!(
            "'{}' is not a valid Proxmox container ID — it must be a whole number, 100 or higher.",
            trimmed));
    }

    let local_path = retrieve_backup(entry)?;
    restore_lxc_local(&local_path, &entry.target.name, storage, overwrite, new_name)
}

/// Restore an LXC container from an archive that is ALREADY on local disk.
/// Shared core: `restore_lxc` calls it after downloading from backup
/// storage; the PBS snapshot restore calls it after un-wrapping the
/// snapshot's `backup.pxar`. `local_path` is consumed (removed on both
/// success and failure). `new_name` empty = keep `original_name`.
pub fn restore_lxc_local(
    local_path: &Path,
    original_name: &str,
    storage: &str,
    overwrite: bool,
    new_name: &str,
) -> Result<String, String> {
    let new_name = new_name.trim();
    if !new_name.is_empty() && !crate::auth::is_safe_name(new_name) {
        let _ = fs::remove_file(local_path);
        return Err(format!(
            "'{}' is not a valid container name — use letters, digits, '-', '_' and '.' only, with no '..'.",
            new_name));
    }
    let container_name: &str = if new_name.is_empty() { original_name } else { new_name };
    // Validate the EFFECTIVE name. When new_name is empty it falls back to
    // `original_name`, which on the PBS path is the snapshot id ("ct/<id>/..")
    // and has NOT been through is_safe_name — a crafted id like "../../etc"
    // would otherwise escape /var/lib/lxc on the native restore paths.
    if !crate::auth::is_safe_name(container_name) {
        let _ = fs::remove_file(local_path);
        return Err(format!(
            "'{}' is not a valid container name/id — use letters, digits, '-', '_' and '.' only, with no '..'.",
            container_name));
    }

    // Detect whether this is a Proxmox vzdump archive vs a native WolfStack
    // rootfs tar, and which platform we're restoring ONTO. All four
    // combinations are routed independently so a backup taken on one platform
    // restores correctly on the other — PBS snapshots and exported archives
    // move freely between Proxmox and native WolfStack nodes.
    let is_vzdump = crate::containers::lxc_archive_is_vzdump(&local_path.to_string_lossy());
    let proxmox_host = crate::containers::is_proxmox();

    if is_vzdump {
        if proxmox_host {
            // vzdump → Proxmox: `pct restore` handles it natively.
            return restore_lxc_proxmox(local_path, storage, overwrite, container_name);
        }
        // vzdump → native host: `pct restore` is unavailable, so unwrap the
        // rootfs and stand it up as a native LXC with a synthesised config.
        return restore_lxc_vzdump_native(local_path, container_name, overwrite);
    }
    // Below: a native WolfStack archive (`<name>/config` + `<name>/rootfs/`).
    // On a native host it installs directly; on a Proxmox host it is adopted
    // into PVE at the end of this function.

    // Native LXC restore. `backup_lxc` archives the container directory with
    // its ORIGINAL name at the archive's top level (`<orig>/config`,
    // `<orig>/rootfs/...`). Extract into a temp dir UNDER /var/lib/lxc — same
    // filesystem, so the final install is an atomic rename — then verify the
    // contents before declaring success.
    let extract_root = PathBuf::from(format!("/var/lib/lxc/.wolfstack-restore-{}", Uuid::new_v4().simple()));
    let _ = fs::remove_dir_all(&extract_root);
    fs::create_dir_all(&extract_root)
        .map_err(|e| format!("Failed to create restore staging dir: {}", e))?;

    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", &extract_root.to_string_lossy()])
        .output()
        .map_err(|e| format!("Failed to extract LXC backup: {}", e))?;
    let _ = fs::remove_file(&local_path);
    if !output.status.success() {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!("LXC extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // The archive should yield exactly one top-level container directory.
    let extracted = fs::read_dir(&extract_root).ok()
        .and_then(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).find(|p| p.is_dir()));
    let extracted = match extracted {
        Some(d) => d,
        None => {
            let _ = fs::remove_dir_all(&extract_root);
            return Err("Backup archive did not contain an LXC container directory".to_string());
        }
    };

    // Verify the backup actually carries a root filesystem AND a config.
    // Without this the container starts and instantly dies with
    // "Failed to exec /sbin/init" — better to fail the restore loudly here.
    let src_rootfs = extracted.join("rootfs");
    let rootfs_ok = ["sbin", "etc", "bin", "usr"].iter().any(|d| src_rootfs.join(d).exists());
    if !rootfs_ok {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!(
            "Backup is incomplete — no root filesystem inside it (rootfs/ has no sbin, etc or bin). \
             Nothing was restored for '{}'.", container_name));
    }
    if !extracted.join("config").exists() {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!(
            "Backup is incomplete — no LXC config inside it. Nothing was restored for '{}'.", container_name));
    }

    // Install under the requested name. An existing container is only
    // replaced when the operator ticked "replace" — otherwise refuse,
    // because silently merging two rootfs trees is worse than failing.
    let container_dir = format!("/var/lib/lxc/{}", container_name);
    if Path::new(&container_dir).exists() {
        if !overwrite {
            let _ = fs::remove_dir_all(&extract_root);
            return Err(format!(
                "A container already exists at {} — re-run the restore with \"replace\" enabled to overwrite it.",
                container_dir));
        }
        // Operator consented to replace it: stop it if still running, then
        // drop the old directory so the rename below lands cleanly.
        let _ = Command::new("lxc-stop").args(["-n", container_name, "-k"]).output();
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            let _ = fs::remove_dir_all(&extract_root);
            return Err(format!("Failed to remove the existing container at {}: {}", container_dir, e));
        }
    }
    if let Err(e) = fs::rename(&extracted, &container_dir) {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!("Failed to install restored container at {}: {}", container_dir, e));
    }
    let _ = fs::remove_dir_all(&extract_root);

    let config_path = format!("{}/config", container_dir);
    let rootfs_path = format!("{}/rootfs", container_dir);

    // Rewrite the config for THIS node: correct rootfs path, the restored
    // name, and a permissive apparmor profile (the backed-up profile name
    // may not exist on the new host).
    let config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Restored container config could not be read: {}", e))?;
    let mut lines: Vec<String> = config.lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("lxc.rootfs.path") && !t.starts_with("lxc.uts.name")
        })
        .map(|l| l.to_string())
        .collect();
    lines.insert(0, format!("lxc.rootfs.path = dir:{}", rootfs_path));
    lines.insert(1, format!("lxc.uts.name = {}", container_name));
    if !lines.iter().any(|l| l.contains("lxc.apparmor.profile")) {
        lines.push("lxc.apparmor.profile = unconfined".to_string());
    }
    std::fs::write(&config_path, lines.join("\n") + "\n")
        .map_err(|e| format!("Failed to write restored config: {}", e))?;

    // Own the container directory and its config file as root — but DO NOT
    // recurse. The rootfs files keep the ownership `tar` restored from the
    // archive; a `chown -R root:root` here would flatten every non-root file
    // inside the rootfs and break the container (fatally so for an
    // unprivileged container, whose files are owned by shifted UIDs).
    let _ = Command::new("chown").args(["root:root", &container_dir]).output();
    let _ = Command::new("chown").args(["root:root", &config_path]).output();
    let _ = Command::new("chmod").args(["755", &container_dir]).output();

    // Restore copies the source's lxc.net.N.hwaddr verbatim — there is
    // no clone-style MAC rewrite. The operator may have intentionally
    // pinned a specific MAC for upstream router/firewall whitelisting
    // (Hetzner vSwitch, MAC-based DHCP reservations, license dongles
    // keyed off MAC), so silently re-randomising would break those
    // setups. Instead, surface a loud warning — and if another local
    // container is already using one of these MACs, name it. The
    // operator can then edit the NIC in Settings → Resources to mint
    // a fresh MAC if they need one.
    //
    // Cross-node duplicates (e.g. restoring the same backup on two
    // nodes for HA) are not detectable here without trusting the
    // cluster cache; the generic warning covers that case.
    let mac_warning = build_mac_duplication_warning(&config_path, container_name);

    // A native WolfStack backup restored onto a Proxmox host lands as a
    // native /var/lib/lxc container PVE can't see. Adopt it into PVE now so
    // it's a first-class container immediately (fresh VMID), instead of
    // waiting for the next startup reconciliation. Adoption re-tars the rootfs
    // into a new PVE container with fresh networking, so the carried-MAC note
    // no longer applies on success.
    if proxmox_host {
        return match crate::containers::pct_adopt_native_orphan(container_name) {
            Ok(vmid) => Ok(format!(
                "LXC container '{}' restored and adopted into Proxmox as VMID {} — start it from the Containers page.",
                container_name, vmid
            )),
            Err(e) => {
                // Surface it in the log too — if the cause is permanent
                // (e.g. no free VMID) a restart won't fix it and the operator
                // needs to see why.
                tracing::warn!(target: "backup",
                    "PVE adoption of restored container '{}' failed: {} — left as a native /var/lib/lxc container",
                    container_name, e);
                Ok(format!(
                    "LXC container '{}' restored as a native container, but Proxmox adoption failed ({}). \
                     It will be adopted automatically on the next WolfStack restart.{}",
                    container_name, e, mac_warning
                ))
            }
        };
    }

    Ok(format!(
        "LXC container '{}' restored and verified — start it from the Containers page.{}",
        container_name, mac_warning
    ))
}

/// Restore a Proxmox vzdump LXC archive onto a NATIVE (non-Proxmox) host.
///
/// `pct restore` isn't available here, so unwrap the vzdump's root filesystem
/// and stand it up as a native LXC container under /var/lib/lxc. The carried
/// `etc/vzdump/pct.conf` is Proxmox-specific and can't be used verbatim, so a
/// fresh bootable config is synthesised from the rootfs (systemd / privilege
/// auto-detected). `local_path` (the extracted archive) is consumed.
fn restore_lxc_vzdump_native(archive: &Path, container_name: &str, overwrite: bool) -> Result<String, String> {
    let container_dir = format!("/var/lib/lxc/{}", container_name);

    // Replace an existing container only with explicit consent.
    if Path::new(&container_dir).exists() {
        if !overwrite {
            let _ = fs::remove_file(archive);
            return Err(format!(
                "A container already exists at {} — re-run the restore with \"replace\" enabled to overwrite it.",
                container_dir));
        }
        let _ = Command::new("lxc-stop").args(["-n", container_name, "-k"]).output();
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            let _ = fs::remove_file(archive);
            return Err(format!("Failed to remove the existing container at {}: {}", container_dir, e));
        }
    }

    let rootfs_target = format!("{}/rootfs", container_dir);
    if let Err(e) = fs::create_dir_all(&rootfs_target) {
        let _ = fs::remove_file(archive);
        return Err(format!("Failed to create container directory {}: {}", container_dir, e));
    }

    // Shared extractor: handles zstd, flattens a nested rootfs/, strips
    // etc/vzdump. Leaves the container's root filesystem in `rootfs_target`.
    let archive_str = archive.to_string_lossy().to_string();
    if let Err(e) = crate::containers::lxc_extract_archive_to_rootfs(&archive_str, &rootfs_target) {
        let _ = fs::remove_dir_all(&container_dir);
        let _ = fs::remove_file(archive);
        return Err(format!("Failed to unpack vzdump archive for '{}': {}", container_name, e));
    }
    // Verify a real root filesystem actually landed — otherwise the container
    // would start and instantly die with "Failed to exec /sbin/init". Keep the
    // (ephemeral) archive until this passes so a failed restore is recoverable.
    let rootfs_ok = ["sbin", "etc", "bin", "usr"]
        .iter()
        .any(|d| Path::new(&format!("{}/{}", rootfs_target, d)).exists());
    if !rootfs_ok {
        let _ = fs::remove_dir_all(&container_dir);
        let _ = fs::remove_file(archive);
        return Err(format!(
            "The vzdump archive contained no usable root filesystem (no sbin, etc or bin). \
             Nothing was restored for '{}'.", container_name));
    }
    let _ = fs::remove_file(archive);

    // Synthesise a bootable native config from the rootfs (the carried
    // pct.conf is Proxmox-format and unusable here).
    crate::containers::lxc_write_bootable_config(&container_dir, container_name, None);

    // Own the container dir + config as root — NOT recursive, so the rootfs
    // keeps the UIDs tar restored (recursing would break an unprivileged
    // container whose files are owned by shifted UIDs).
    let config_path = format!("{}/config", container_dir);
    let _ = Command::new("chown").args(["root:root", &container_dir]).output();
    let _ = Command::new("chown").args(["root:root", &config_path]).output();
    let _ = Command::new("chmod").args(["755", &container_dir]).output();

    Ok(format!(
        "Proxmox container restored as native LXC '{}' — start it from the Containers page. \
         Its network was reset to a fresh veth on lxcbr0; adjust it in Settings → Resources if needed.",
        container_name
    ))
}

/// Build a human-readable warning about MAC-address duplication risk
/// for a freshly restored container. Always warns generically (since
/// we can't reliably scan cluster-wide MACs from this call site); also
/// names local conflicts when the restored container shares a MAC with
/// another container already on this node.
fn build_mac_duplication_warning(restored_config_path: &str, restored_name: &str) -> String {
    // Pull the restored container's MACs from its newly-installed config.
    let restored_macs = read_hwaddrs(restored_config_path);
    if restored_macs.is_empty() {
        // No MACs to worry about (very unusual — most LXC configs pin
        // hwaddr) — just the generic warning.
        return "\n\nNOTE: restore copies the source's network settings verbatim. \
                Check that this container's MAC addresses, hostname, and any pinned \
                IPs don't clash with other containers — especially important on \
                vSwitches and shared L2 networks, where duplicate MACs cause silent \
                connectivity failures."
            .to_string();
    }

    // Walk every other LXC container's config for matching MACs.
    let mut local_conflicts: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip the container we just restored, hidden dirs, and the
            // restore staging directory pattern.
            if name == restored_name || name.starts_with('.') {
                continue;
            }
            let other_config = format!("/var/lib/lxc/{}/config", name);
            if !std::path::Path::new(&other_config).exists() {
                continue;
            }
            for mac in read_hwaddrs(&other_config) {
                if restored_macs.iter().any(|m| m.eq_ignore_ascii_case(&mac)) {
                    local_conflicts.push((name.clone(), mac));
                }
            }
        }
    }

    let mut warning = String::from(
        "\n\nNOTE: restore copies the source's network settings verbatim, including \
         MAC addresses. Check for duplicates — especially on vSwitches and shared \
         L2 networks, where two containers with the same MAC cause silent \
         connectivity failures (flapping switch FDB, traffic to the wrong host).",
    );
    if !local_conflicts.is_empty() {
        warning.push_str("\n\nDUPLICATE MAC DETECTED on this node:");
        for (other, mac) in &local_conflicts {
            warning.push_str(&format!(
                "\n  - '{}' also uses MAC {} — edit one of them in Settings → Resources.",
                other, mac
            ));
        }
    } else {
        warning.push_str(
            "\n\nNo duplicates on this node; verify across the cluster too if you \
             restored this from a backup of a container that's still running elsewhere.",
        );
    }
    warning
}

/// Extract every `lxc.net.N.hwaddr` value from an LXC config file.
/// Tolerates `key = value` and `key=value`. Returns lowercase MACs.
fn read_hwaddrs(config_path: &str) -> Vec<String> {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut macs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        // Match lxc.net.<N>.hwaddr — N is any digit run.
        let stripped = trimmed.strip_prefix("lxc.net.").unwrap_or("");
        if stripped.is_empty() {
            continue;
        }
        // Skip past the digits to find ".hwaddr".
        let rest = stripped.trim_start_matches(|c: char| c.is_ascii_digit());
        let rest = match rest.strip_prefix(".hwaddr") {
            Some(r) => r.trim_start(),
            None => continue,
        };
        let rest = match rest.strip_prefix('=') {
            Some(r) => r.trim(),
            None => continue,
        };
        if !rest.is_empty() {
            macs.push(rest.to_ascii_lowercase());
        }
    }
    macs
}

/// Restore a Proxmox LXC container from a vzdump archive using pct restore
fn restore_lxc_proxmox(archive_path: &Path, storage: &str, overwrite: bool, vmid: &str) -> Result<String, String> {
    // Proxmox VMIDs are whole numbers, 100 or higher. A restore-as name
    // typed in the dialog reaches here — reject anything that isn't a
    // usable VMID rather than letting `pct` fail cryptically.
    if vmid.parse::<u32>().map(|n| n < 100).unwrap_or(true) {
        let _ = fs::remove_file(archive_path);
        return Err(format!(
            "'{}' is not a valid Proxmox container ID — it must be a whole number, 100 or higher.", vmid));
    }

    // Check if the VMID already exists — pct restore will fail if it does
    let exists = Command::new("pct").args(["status", vmid]).output()
        .map(|o| o.status.success()).unwrap_or(false);

    if exists {
        // `pct destroy` purges the container's disks — never do that
        // without the operator explicitly asking to replace it.
        if !overwrite {
            let _ = fs::remove_file(archive_path);
            return Err(format!(
                "Container {} already exists — re-run the restore with \"replace\" enabled to overwrite it.", vmid));
        }
        // Container exists — stop it first if running, then destroy and recreate
        let _ = Command::new("pct").args(["stop", vmid]).output();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let destroy = match Command::new("pct").args(["destroy", vmid, "--force", "1"]).output() {
            Ok(d) => d,
            Err(e) => {
                let _ = fs::remove_file(archive_path);
                return Err(format!("Failed to destroy existing container {}: {}", vmid, e));
            }
        };
        if !destroy.status.success() {
            let _ = fs::remove_file(archive_path);
            return Err(format!("Failed to destroy existing container {}: {}",
                vmid, String::from_utf8_lossy(&destroy.stderr)));
        }
    }

    // Restore using pct restore — handles all storage backends. When the
    // operator picked a target storage, pass it through; pct args go
    // straight to execve (no shell), but reject anything that is not a
    // plausible PVE storage id as defence in depth.
    let mut args: Vec<String> = vec![
        "restore".to_string(), vmid.to_string(),
        archive_path.to_string_lossy().to_string(),
    ];
    let storage = storage.trim();
    if !storage.is_empty() {
        if !storage.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            let _ = fs::remove_file(archive_path);
            return Err(format!("Invalid Proxmox storage id: '{}'", storage));
        }
        args.push("--storage".to_string());
        args.push(storage.to_string());
    }
    let output = match Command::new("pct").args(&args).output() {
        Ok(o) => o,
        Err(e) => {
            let _ = fs::remove_file(archive_path);
            return Err(format!("pct restore failed to start: {}", e));
        }
    };

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
    // Backups-list VM restore keeps Proxmox's default storage (local-lvm);
    // the PBS path threads an operator-picked storage instead.
    restore_vm_local(&local_path, &entry.target.name, None)
}

/// Restore a VM from an archive already on local disk. Shared by
/// `restore_vm` (after download from backup storage) and the PBS
/// snapshot restore (after it un-wraps the snapshot's `backup.pxar`).
/// `local_path` is consumed.
///
/// Platform-dispatched:
///   • Proxmox host → `restore_vm_to_proxmox` (qm create + qm importdisk)
///   • libvirt host → `restore_vm_to_libvirt` (move disks into
///     /var/lib/libvirt/images, generate minimal domain XML, `virsh define`)
///   • native host → existing in-place extraction to /var/lib/wolfstack/vms
///
/// The archive format produced by `backup_vm` (Stage B) is the same
/// across platforms — flat tar.gz with `<name>.json` (portable VmConfig)
/// + `<name>.qcow2` (OS disk) + optional `<name>-<slot>.qcow2` extra
/// disks. Restore reads the JSON, then routes to the per-platform
/// creation primitives.
pub fn restore_vm_local(local_path: &Path, vm_name: &str, target_storage: Option<&str>) -> Result<String, String> {
    if crate::containers::is_proxmox() {
        return restore_vm_to_proxmox(local_path, vm_name, target_storage);
    }
    if crate::containers::is_libvirt() {
        return restore_vm_to_libvirt(local_path, vm_name);
    }
    restore_vm_to_native(local_path, vm_name)
}

/// Extract a tar.gz to `dest` after verifying NO entry contains a path
/// traversal vector. The portable backup archive comes from operator-
/// controlled storage (S3 / NFS / SSHFS / PBS); a crafted archive with
/// entries like `../../../etc/cron.d/evil` could climb out of the
/// `dest` work-dir on extraction.
///
/// Two-step strategy:
///   1. `tar tzf <archive>` lists entries; we reject any that start
///      with `/`, contain a `..` path component, or carry a NUL.
///   2. Only after validation do we extract.
///
/// This costs an extra tar invocation but is small overhead for our
/// portable VM archives (which contain only a JSON config and a
/// handful of qcow2 files), and it's the correct defence on top of
/// whatever GNU tar's default behaviour happens to be on the host.
fn safe_extract_tar(archive: &Path, dest: &Path) -> Result<(), String> {
    let list = Command::new("tar")
        .args(["tzf", &archive.to_string_lossy()])
        .output()
        .map_err(|e| format!("tar list failed to start: {}", e))?;
    if !list.status.success() {
        return Err(format!(
            "tar listing failed: {}",
            String::from_utf8_lossy(&list.stderr).trim()
        ));
    }
    let listing = String::from_utf8_lossy(&list.stdout);
    for raw in listing.lines() {
        let entry = raw.trim_end_matches('/').trim();
        if entry.is_empty() { continue; }
        if entry.starts_with('/') {
            return Err(format!(
                "archive contains absolute path entry '{}' — refusing to extract", entry));
        }
        if entry.split('/').any(|c| c == "..") {
            return Err(format!(
                "archive entry '{}' contains '..' — refusing to extract", entry));
        }
        if entry.contains('\0') {
            return Err("archive entry contains NUL byte — refusing to extract".into());
        }
    }
    // All entries safe — extract.
    let extract = Command::new("tar")
        .args(["xzf", &archive.to_string_lossy(),
               "-C", &dest.to_string_lossy()])
        .output()
        .map_err(|e| format!("tar extract failed to start: {}", e))?;
    if !extract.status.success() {
        return Err(format!(
            "tar extract failed: {}",
            String::from_utf8_lossy(&extract.stderr).trim()));
    }
    Ok(())
}

/// XML-escape the five characters that change meaning inside attribute
/// values or element text. Used everywhere libvirt XML is constructed
/// from values that originated in the portable backup archive (which
/// is operator-supplied content and therefore untrusted at restore
/// time). A crafted backup containing `bus="virtio'/></disk><foo"` or
/// a `vm_name` with `<`/`>` would otherwise break out of the
/// surrounding markup and inject arbitrary XML — `virsh define` would
/// reject the result, but the failure mode (restore aborts mid-flow)
/// is worse than catching it here.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Validate a disk bus name against the allowlist libvirt accepts.
/// Rejects anything else with a clear error rather than letting it
/// flow into the XML (defence-in-depth alongside `xml_escape`).
fn validate_libvirt_bus(bus: &str) -> Result<&str, String> {
    match bus {
        "virtio" | "scsi" | "ide" | "sata" => Ok(bus),
        other => Err(format!(
            "invalid disk bus '{}' in backup archive — libvirt accepts only \
             virtio / scsi / ide / sata", other)),
    }
}

/// N2: validate fields from the portable VmConfig's `extra_disks`
/// entries before they're interpolated into filesystem paths. Same
/// shape as the VM-name check but allowed against the field name in
/// errors so the operator can locate the bad entry.
fn validate_archive_path_field(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("archive field `{}` is empty", what));
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0')
        || value.contains("..") || value.starts_with('.')
    {
        return Err(format!(
            "archive field `{}` value '{}' contains a path-traversal character — refused",
            what, value));
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric()
        || c == '_' || c == '-' || c == '.' || c == '+' || c == ':')
    {
        return Err(format!(
            "archive field `{}` value '{}' contains characters outside [A-Za-z0-9_.+:-]",
            what, value));
    }
    Ok(())
}

/// N3: validate a MAC address against `AA:BB:CC:DD:EE:FF`. Pre-fix
/// the value flowed from the portable archive straight into a
/// `qm create --net0 virtio={mac},bridge=vmbr0` arg — and qm parses
/// --net0 as comma-separated key=value pairs. A crafted MAC value of
/// `DE:AD:BE:EF:00:01,firewall=1,queues=65535` would inject extra qm
/// network options from the archive. Strict regex check eliminates
/// the vector entirely.
fn validate_mac_address(mac: &str) -> Result<(), String> {
    if mac.len() != 17 {
        return Err(format!("MAC '{}' must be 17 chars (AA:BB:CC:DD:EE:FF)", mac));
    }
    for (i, c) in mac.chars().enumerate() {
        let is_separator = i % 3 == 2;
        if is_separator {
            if c != ':' {
                return Err(format!("MAC '{}' separator at position {} must be ':'", mac, i));
            }
        } else if !c.is_ascii_hexdigit() {
            return Err(format!("MAC '{}' has non-hex char '{}' at position {}", mac, c, i));
        }
    }
    Ok(())
}

/// Reject VM names that would either break out of file paths or break
/// libvirt's element-name validation. Mirrors the check
/// `export_vm_with_staging` uses at the export side.
fn validate_vm_name_for_restore(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("VM name is empty".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0')
        || name.contains("..") || name.starts_with('.') || name.starts_with('-')
    {
        // Leading `-` rejected for the same reason as
        // validate_clone_vm_name: a name like `--full` becomes a flag
        // when passed as an argv positional to qm/virsh.
        return Err(format!(
            "invalid VM name '{}' — must not contain /, \\, NUL, '..' or start with '.' or '-'", name));
    }
    // libvirt domain names: letters, digits, _, -, +, ., :.
    // Be a touch stricter and refuse anything not in [A-Za-z0-9_.+:-].
    if !name.chars().all(|c| c.is_ascii_alphanumeric()
        || c == '_' || c == '-' || c == '.' || c == '+' || c == ':')
    {
        return Err(format!(
            "invalid VM name '{}' — only A-Z a-z 0-9 _ . - + : are allowed", name));
    }
    Ok(())
}

/// libvirt restore: extract the archive into the libvirt images dir,
/// translate the portable VmConfig into a minimal domain XML, then
/// `virsh define` it. Disk(s) end up at /var/lib/libvirt/images/<name>.qcow2.
fn restore_vm_to_libvirt(local_path: &Path, vm_name: &str) -> Result<String, String> {
    // Validate name before any filesystem or XML work — refuses crafted
    // archives whose VmConfig.name would escape the libvirt images
    // dir or inject XML. Same check applied to the Proxmox path below.
    validate_vm_name_for_restore(vm_name)?;
    use crate::vms::manager::VmConfig;

    let images_dir = Path::new("/var/lib/libvirt/images");
    fs::create_dir_all(images_dir)
        .map_err(|e| format!("create libvirt images dir: {}", e))?;

    // Extract into a per-restore work dir; move disks to images_dir at
    // the end so a half-failed extract doesn't pollute libvirt's
    // storage pool.
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let work_dir = staging.join(format!("libvirt-restore-{}-{}", vm_name, timestamp));
    fs::create_dir_all(&work_dir).map_err(|e| format!("create work dir: {}", e))?;
    struct WorkDirGuard(PathBuf);
    impl Drop for WorkDirGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _work_guard = WorkDirGuard(work_dir.clone());

    // N1: path-traversal hardening — refuse absolute or `..` paths in
    // the archive before extracting. Operator-controlled backup storage
    // means the archive content is untrusted at restore time.
    safe_extract_tar(local_path, &work_dir)?;
    let _ = fs::remove_file(local_path);

    let config_path = work_dir.join(format!("{}.json", vm_name));
    if !config_path.exists() {
        return Err(format!("archive did not contain {}.json — cannot restore", vm_name));
    }
    let config_text = fs::read_to_string(&config_path)
        .map_err(|e| format!("read config: {}", e))?;
    let config: VmConfig = serde_json::from_str(&config_text)
        .map_err(|e| format!("parse config: {}", e))?;

    // Move OS disk to libvirt images dir.
    let os_disk_src = work_dir.join(format!("{}.qcow2", vm_name));
    if !os_disk_src.exists() {
        return Err(format!("archive contained no OS disk ({}.qcow2)", vm_name));
    }
    let os_disk_dest = images_dir.join(format!("{}.qcow2", vm_name));
    if os_disk_dest.exists() {
        return Err(format!(
            "{} already exists — refuse to overwrite. Delete it manually or restore under a different name.",
            os_disk_dest.display()));
    }
    fs::rename(&os_disk_src, &os_disk_dest)
        .or_else(|_| {
            // Cross-filesystem move falls back to copy + remove.
            fs::copy(&os_disk_src, &os_disk_dest)?;
            fs::remove_file(&os_disk_src)?;
            Ok::<(), std::io::Error>(())
        })
        .map_err(|e| format!("move OS disk: {}", e))?;

    // Move each extra disk too, tracking final paths for XML generation.
    //
    // N4 fix: device letter uses a counter for SUCCESSFULLY placed
    // disks rather than the source-array index. Pre-fix, if one extra
    // disk was skipped (missing in archive OR dest already exists),
    // the next disk got a letter with a gap (e.g. vdd when vdb/vdc
    // were skipped) — some guests fail to boot on non-sequential
    // target dev names.
    let mut extra_disk_paths: Vec<(String, String, String)> = Vec::new();  // (path, target, bus)
    let mut placed_count: u32 = 0;
    for extra in config.extra_disks.iter() {
        // N2: validate every archive-derived field before using it in a
        // filesystem path. A crafted VmConfig with extra.name like
        // `../../etc/cron.d/evil` would escape work_dir / images_dir
        // on the fs::rename / fs::copy below.
        if let Err(e) = validate_archive_path_field(&extra.name, "extra_disks[].name") {
            warn!("libvirt restore: skipping extra disk — {}", e);
            continue;
        }
        if let Err(e) = validate_archive_path_field(&extra.format, "extra_disks[].format") {
            warn!("libvirt restore: skipping extra disk '{}' — {}", extra.name, e);
            continue;
        }
        let src = work_dir.join(format!("{}.{}", extra.name, extra.format));
        if !src.exists() {
            warn!("extra disk {} listed in config but not in archive — skipped", extra.name);
            continue;
        }
        let dest = images_dir.join(format!("{}-{}.qcow2", vm_name, extra.name));
        if dest.exists() {
            warn!("extra disk dest {} already exists — skipped", dest.display());
            continue;
        }
        if fs::rename(&src, &dest).is_err() {
            fs::copy(&src, &dest).map_err(|e| format!("copy extra disk {}: {}", extra.name, e))?;
            let _ = fs::remove_file(&src);
        }
        // A4: validate bus against the libvirt allowlist BEFORE it
        // flows into XML. The portable archive's VmConfig is untrusted
        // (operator-supplied content); a bus value like
        // `virtio'/></disk><foo` would break out of the attribute.
        let safe_bus = match validate_libvirt_bus(&extra.bus) {
            Ok(b) => b,
            Err(e) => {
                warn!("libvirt restore: skipping extra disk {} — {}", extra.name, e);
                continue;
            }
        };
        // libvirt target dev: vdb, vdc… for virtio bus; sdb, sdc… for scsi.
        let prefix = match safe_bus {
            "scsi" => "sd",
            "ide" => "hd",
            _ => "vd",
        };
        // 'a' is OS disk; extras start at 'b'. Cap at 'z' (26 extras) —
        // beyond that libvirt's single-letter dev naming doesn't apply
        // anyway, and the operator should be using a custom XML.
        if placed_count >= 25 {
            warn!("libvirt restore: more than 25 extra disks ({}); skipping {} — \
                   operator must edit XML to attach beyond vdz.", extra.name, extra.name);
            continue;
        }
        let letter = (b'b' + placed_count as u8) as char;
        let target = format!("{}{}", prefix, letter);
        placed_count += 1;
        extra_disk_paths.push((dest.to_string_lossy().to_string(), target, safe_bus.to_string()));
    }

    // Build a minimal libvirt domain XML. Operator can customise after
    // `virsh edit <name>` if they need machine type / NIC bridge changes.
    let machine = if config.bios_type == "ovmf" || config.bios_type == "uefi" {
        "q35"
    } else {
        "pc"
    };
    // A4: XML-escape every string that originates from operator-supplied
    // content (the portable archive's VmConfig). vm_name was already
    // shape-validated above by `validate_vm_name_for_restore`, so the
    // escape is defence-in-depth — same for the file paths, which
    // embed vm_name plus chrono timestamps.
    let safe_name = xml_escape(vm_name);
    let safe_os_disk = xml_escape(&os_disk_dest.to_string_lossy());
    let mut xml = format!(
        "<domain type='kvm'>\n  \
         <name>{}</name>\n  \
         <memory unit='MiB'>{}</memory>\n  \
         <vcpu>{}</vcpu>\n  \
         <os>\n    <type arch='x86_64' machine='{}'>hvm</type>\n    <boot dev='hd'/>\n  </os>\n  \
         <features>\n    <acpi/>\n    <apic/>\n  </features>\n  \
         <clock offset='utc'/>\n  \
         <devices>\n    \
         <disk type='file' device='disk'>\n      \
         <driver name='qemu' type='qcow2'/>\n      \
         <source file='{}'/>\n      \
         <target dev='vda' bus='virtio'/>\n    </disk>\n",
        safe_name, config.memory_mb, config.cpus, machine,
        safe_os_disk,
    );
    // Append extra disks — `bus` has already passed `validate_libvirt_bus`
    // (allowlist), `target` is constructed from hardcoded prefix + a
    // single letter, and `path` is escaped here.
    for (path, target, bus) in &extra_disk_paths {
        let safe_path = xml_escape(path);
        // target and bus are from our allowlist/prefix construction so
        // escape is redundant but cheap; keep for consistency.
        xml.push_str(&format!(
            "    <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='qcow2'/>\n      \
             <source file='{}'/>\n      \
             <target dev='{}' bus='{}'/>\n    </disk>\n",
            safe_path, xml_escape(target), xml_escape(bus),
        ));
    }
    // Network — virbr0 is libvirt's default NAT bridge.
    // N3: validate MAC shape AND xml_escape — defence in depth.
    // If validation fails we drop the MAC and let libvirt assign one
    // rather than aborting restore for a cosmetic mismatch.
    let mac_line = if let Some(mac) = &config.mac_address {
        match validate_mac_address(mac) {
            Ok(()) => format!("      <mac address='{}'/>\n", xml_escape(mac)),
            Err(e) => {
                warn!("libvirt restore: ignoring invalid MAC from archive — {}", e);
                String::new()
            }
        }
    } else { String::new() };
    xml.push_str(&format!(
        "    <interface type='network'>\n      \
         <source network='default'/>\n{}\
         <model type='virtio'/>\n    </interface>\n    \
         <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n    \
         <console type='pty'/>\n  </devices>\n</domain>\n",
        mac_line,
    ));

    // Write the XML to a temp file and virsh define.
    let xml_path = work_dir.join(format!("{}.xml", vm_name));
    fs::write(&xml_path, &xml).map_err(|e| format!("write XML: {}", e))?;
    let define = Command::new("virsh")
        .args(["define", &xml_path.to_string_lossy()])
        .output()
        .map_err(|e| format!("virsh define failed to start: {}", e))?;
    if !define.status.success() {
        // Roll back: remove the disks we just placed.
        let _ = fs::remove_file(&os_disk_dest);
        for (path, _, _) in &extra_disk_paths {
            let _ = fs::remove_file(path);
        }
        return Err(format!(
            "virsh define failed: {} — disks rolled back",
            String::from_utf8_lossy(&define.stderr).trim()));
    }

    Ok(format!(
        "VM '{}' restored to libvirt (disk: {}, {} extra disk(s)). \
         Start it with `virsh start {}` or via the WolfStack VM list. \
         W5: NIC is attached to libvirt's 'default' network. If your \
         libvirt setup uses a custom bridge (virbr1, br0, etc.) or has \
         'default' disabled, edit with `virsh edit {}` before starting \
         or the VM will have no network connectivity.",
        vm_name, os_disk_dest.display(), extra_disk_paths.len(), vm_name, vm_name))
}

/// Native restore — extract the tar.gz to /var/lib/wolfstack/vms/ and
/// verify the config landed at the expected flat path. Handles legacy
/// archives that wrap the config inside a subdirectory.
fn restore_vm_to_native(local_path: &Path, vm_name: &str) -> Result<String, String> {
    // Same name-shape validation as the libvirt/Proxmox paths — refuse
    // crafted archives whose VmConfig.name would let extracted files
    // land outside /var/lib/wolfstack/vms.
    validate_vm_name_for_restore(vm_name)?;

    let vm_base = "/var/lib/wolfstack/vms";
    fs::create_dir_all(vm_base).map_err(|e| format!("Failed to create VM dir: {}", e))?;

    // Extract to /var/lib/wolfstack/vms/. Uses the same path-traversal-
    // safe helper as the libvirt and Proxmox restore paths: lists
    // archive entries first and refuses absolute / `..` / NUL paths
    // before extracting. Pre-fix this used raw `tar xzf` which would
    // have allowed a crafted archive to write `../../../etc/cron.d/evil`.
    safe_extract_tar(local_path, Path::new(vm_base))?;
    let _ = fs::remove_file(local_path);

    // Verify the config JSON was restored
    let config_path = format!("{}/{}.json", vm_base, vm_name);
    if !Path::new(&config_path).exists() {
        // Legacy backup format: config might be inside a subdirectory
        let legacy_config = format!("{}/{}/config.json", vm_base, vm_name);
        if Path::new(&legacy_config).exists() {
            // Move it to the expected flat location
            let _ = fs::copy(&legacy_config, &config_path);
        } else {
            warn!("VM config not found after restore: {} — VM may not appear in list until config is recreated", config_path);
        }
    }

    Ok(format!("VM '{}' restored to /var/lib/wolfstack/vms/ as a native KVM VM", vm_name))
}

/// Proxmox restore — extract the portable archive to a work dir,
/// read the JSON config, allocate a free VMID, create the VM via
/// `qm create`, and import each disk via `qm importdisk`. The OS
/// disk lands at scsi0; extras at scsi1, scsi2, … (or their original
/// bus name when StorageVolume.bus is set).
///
/// `target_storage = None` (operator left the picker blank) auto-selects
/// the first ACTIVE images-capable PVE storage, falling back to `local-lvm`
/// only if none is found. An explicit pick is validated and used as-is.
fn restore_vm_to_proxmox(
    local_path: &Path,
    vm_name: &str,
    target_storage: Option<&str>,
) -> Result<String, String> {
    use crate::vms::manager::VmConfig;

    // Same validation as the libvirt restore — refuse names that
    // would escape paths or break `qm create` arg passing.
    validate_vm_name_for_restore(vm_name)?;

    // `qm importdisk` REQUIRES a target storage (unlike `pct restore
    // --storage`, which is optional and lets PVE pick its own default). So
    // when the operator left the picker blank we must choose one ourselves —
    // the first ACTIVE images-capable PVE storage, rather than blindly
    // assuming `local-lvm`, which doesn't exist on ZFS-only / custom hosts
    // (that assumption was itself a restore-failure source). Any explicit
    // pick is validated the same way the LXC path validates its storage id —
    // it becomes a `qm` execve arg, so reject anything that isn't a plausible
    // PVE storage id as defence in depth.
    let storage_owned: String = match target_storage.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => {
            if !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
                return Err(format!("Invalid Proxmox storage id: '{}'", s));
            }
            s.to_string()
        }
        None => crate::containers::pvesm_list_storage().into_iter()
            .find(|st| st.status == "active" && st.content.iter().any(|c| c == "images"))
            .map(|st| st.id)
            .unwrap_or_else(|| "local-lvm".to_string()),
    };
    let storage = storage_owned.as_str();

    // 1) Extract the portable archive into a per-restore work dir so
    //    we don't pollute staging if the qm step fails halfway.
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let work_dir = staging.join(format!("pmx-restore-{}-{}", vm_name, timestamp));
    fs::create_dir_all(&work_dir)
        .map_err(|e| format!("create work dir: {}", e))?;
    struct WorkDirGuard(PathBuf);
    impl Drop for WorkDirGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _work_guard = WorkDirGuard(work_dir.clone());

    // N1: same path-traversal hardening as the libvirt restore path.
    safe_extract_tar(local_path, &work_dir)?;
    let _ = fs::remove_file(local_path);

    // 2) Read the portable VmConfig.
    let config_path = work_dir.join(format!("{}.json", vm_name));
    if !config_path.exists() {
        return Err(format!(
            "archive did not contain {}.json — operator may have an old-format \
             backup that needs manual conversion. Nothing was created.", vm_name));
    }
    let config_text = fs::read_to_string(&config_path)
        .map_err(|e| format!("read config: {}", e))?;
    let config: VmConfig = serde_json::from_str(&config_text)
        .map_err(|e| format!("parse config: {}", e))?;

    // 3) Allocate a free VMID via the cluster-safe Proxmox API. C2 fix:
    //    pre-fix this used a local-filesystem scan which races other
    //    cluster nodes during concurrent restore (or against the PVE
    //    HA manager). `pvesh get /cluster/nextid` is the cluster-wide
    //    primitive.
    let vmid = crate::vms::manager::next_pve_vmid()?;

    // 4) Create the VM with `qm create`. Use BIOS / cores / memory from
    //    the config; default to virtio NIC on vmbr0 if a MAC is present.
    let bios_arg = match config.bios_type.as_str() {
        "ovmf" | "uefi" => "ovmf",
        _ => "seabios",
    };
    let mut qm_args: Vec<String> = vec![
        "create".to_string(),
        vmid.to_string(),
        "--name".to_string(), vm_name.to_string(),
        "--cores".to_string(), config.cpus.to_string(),
        "--memory".to_string(), config.memory_mb.to_string(),
        "--bios".to_string(), bios_arg.to_string(),
        // No disks yet — qm importdisk attaches them below. Without
        // any disk, `--ostype l26` is a safe default for Linux guests;
        // Windows users will edit it post-restore.
        "--ostype".to_string(), "l26".to_string(),
    ];
    // N3: validate MAC before it flows into qm's comma-separated arg.
    // A crafted archive MAC like `DE:AD:BE:EF:00:01,firewall=1` would
    // inject extra --net0 options. On validation failure we drop the
    // MAC and fall back to qm picking one, rather than aborting the
    // restore — the operator can fix the MAC post-restore.
    let safe_mac = config.mac_address.as_ref().and_then(|m| {
        match validate_mac_address(m) {
            Ok(()) => Some(m.clone()),
            Err(e) => {
                warn!("Proxmox restore: ignoring invalid MAC from archive — {}", e);
                None
            }
        }
    });
    if let Some(mac) = safe_mac {
        qm_args.push("--net0".to_string());
        qm_args.push(format!("virtio={},bridge=vmbr0", mac));
    } else {
        qm_args.push("--net0".to_string());
        qm_args.push("virtio,bridge=vmbr0".to_string());
    }

    let create = Command::new("qm").args(&qm_args).output()
        .map_err(|e| format!("qm create failed to start: {}", e))?;
    if !create.status.success() {
        return Err(format!(
            "qm create {} failed: {}",
            vmid, String::from_utf8_lossy(&create.stderr).trim()));
    }

    // 5) Import the OS disk first (lands at unused0 after import, then
    //    we move it to scsi0).
    let os_disk = work_dir.join(format!("{}.qcow2", vm_name));
    if !os_disk.exists() {
        // Roll back the half-created VM so the operator isn't left
        // with a husk to clean up by hand.
        let _ = Command::new("qm").args(["destroy", &vmid.to_string()]).output();
        return Err(format!(
            "archive contained no OS disk ({}.qcow2). VM {} created+destroyed; \
             nothing to attach.", vm_name, vmid));
    }
    // C3 fix: use the shared `pve_import_and_attach_disk` helper from
    // vms::manager — it CORRECTLY omits `--format qcow2` (forcing that
    // breaks LVM-thin and ZFS, the most common production PVE storage
    // layouts). The buggy local copy `import_disk_to_proxmox` is gone.
    crate::vms::manager::pve_import_and_attach_disk(vmid, &os_disk, storage, "scsi0")
        .map_err(|e| {
            let _ = Command::new("qm").args(["destroy", &vmid.to_string()]).output();
            format!("OS disk import failed: {}. VM {} rolled back.", e, vmid)
        })?;

    // Set boot device to the imported OS disk.
    let boot = Command::new("qm")
        .args(["set", &vmid.to_string(), "--boot", "order=scsi0"])
        .output()
        .map_err(|e| format!("qm set boot failed to start: {}", e))?;
    if !boot.status.success() {
        // Non-fatal — VM exists and has a disk, operator can set boot
        // manually. Log instead of failing the whole restore.
        warn!("qm set --boot for {} failed: {} — operator may need to set boot device manually",
            vmid, String::from_utf8_lossy(&boot.stderr).trim());
    }

    // 6) Import extra disks (scsi1, scsi2, …). The slot name comes
    //    from the portable config's extra_disks entries — bus is
    //    preserved where possible.
    let mut next_slot_by_bus: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    next_slot_by_bus.insert("scsi".into(), 1);  // scsi0 already used by OS disk
    next_slot_by_bus.insert("virtio".into(), 0);
    next_slot_by_bus.insert("ide".into(), 0);
    next_slot_by_bus.insert("sata".into(), 0);
    for extra in &config.extra_disks {
        // N2: same archive-field validation as the libvirt restore path.
        if let Err(e) = validate_archive_path_field(&extra.name, "extra_disks[].name") {
            warn!("Proxmox restore: skipping extra disk — {}", e);
            continue;
        }
        if let Err(e) = validate_archive_path_field(&extra.format, "extra_disks[].format") {
            warn!("Proxmox restore: skipping extra disk '{}' — {}", extra.name, e);
            continue;
        }
        let extra_path = work_dir.join(format!("{}.{}", extra.name, extra.format));
        if !extra_path.exists() {
            warn!("extra disk {} listed in config but not present in archive — skipped",
                extra.name);
            continue;
        }
        let bus = if next_slot_by_bus.contains_key(extra.bus.as_str()) {
            extra.bus.clone()
        } else {
            "scsi".to_string()
        };
        let slot_num = next_slot_by_bus.get(bus.as_str()).copied().unwrap_or(0);
        let slot_name = format!("{}{}", bus, slot_num);
        next_slot_by_bus.insert(bus.clone(), slot_num + 1);
        if let Err(e) = crate::vms::manager::pve_import_and_attach_disk(
            vmid, &extra_path, storage, &slot_name)
        {
            warn!("extra disk {} import failed: {} — operator must attach manually",
                extra.name, e);
        }
    }

    Ok(format!(
        "VM '{}' restored to Proxmox as VMID {} on storage '{}' (boot device: scsi0). \
         Start it with `qm start {}` or via the WolfStack VM list.",
        vm_name, vmid, storage, vmid))
}

// `import_disk_to_proxmox` and `allocate_free_proxmox_vmid` were
// removed in the C2/C3 fix round — both duplicated logic that already
// existed (correctly) in vms::manager, and both had subtle bugs:
//   • allocate_free_proxmox_vmid scanned local files and raced the
//     cluster — replaced by `next_pve_vmid` (uses `pvesh /cluster/nextid`)
//   • import_disk_to_proxmox passed `--format qcow2` which breaks
//     LVM-thin and ZFS — replaced by `pve_import_and_attach_disk`

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

/// Restore from a backup entry (auto-detects type). Non-streaming path:
/// an LXC restore here uses the node's default storage — the streaming
/// restore (`restore_by_id_with_log`) is the one that honours a storage
/// the operator picked in the restore dialog.
pub fn restore_backup(entry: &BackupEntry, overwrite: bool) -> Result<String, String> {
    // PBS file-level (pxar) snapshots restore by extracting the tree, not via
    // the tarball-based per-type restore paths.
    if is_pbs_file_level_entry(entry) {
        return restore_pbs_file_level_entry(entry, "");
    }
    match entry.target.target_type {
        BackupTargetType::Docker => restore_docker(entry, overwrite),
        BackupTargetType::Lxc => restore_lxc(entry, "", overwrite, ""),
        BackupTargetType::Vm => restore_vm(entry),
        BackupTargetType::Config => restore_config_backup(entry),
        // System-folder restore defaults to the PARENT of the original
        // path so the folder lands back exactly where it came from. The
        // streaming/targeted path (restore_entry_with_log) lets the
        // operator choose a different parent.
        BackupTargetType::SystemPath => {
            let parent = Path::new(entry.target.system_path.trim_end_matches('/'))
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            restore_system_path(entry, &parent)
        }
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
    // Bake the concrete Local directory in up front (see with_concrete_local)
    // so restore is independent of any later default-dir change.
    let storage = storage.with_concrete_local(&crate::paths::get().backup_local_dir);
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
        let hostname = local_hostname();

        // PBS file-level (pxar) path — upload the workload's content directory
        // directly so PBS per-file restore works. Applies to Docker, native
        // LXC, and SystemPath; for VM / Proxmox-LXC / Config make_pbs_file_
        // level_entry returns None and we fall through to the tarball path.
        if storage.storage_type == StorageType::Pbs && storage.pbs_file_level {
            let _ = log.send("  PBS file-level backup requested...".to_string());
            if let Some(res) = make_pbs_file_level_entry(t, &storage, &comments, &cluster, &hostname, Some(&log)) {
                match res {
                    Ok(entry) => {
                        let _ = log.send(format!("  ✓ {} file-level backup complete", type_name));
                        entries.push(entry);
                    }
                    Err(e) => {
                        let _ = log.send(format!("  ✗ PBS file-level backup failed: {}", e));
                        entries.push(BackupEntry {
                            id: Uuid::new_v4().to_string(),
                            target: t.clone(),
                            storage: storage.clone(),
                            filename: String::new(),
                            size_bytes: 0,
                            created_at: Utc::now().to_rfc3339(),
                            status: BackupStatus::Failed,
                            error: e,
                            schedule_id: String::new(),
                            comments,
                            node_hostname: hostname,
                            docker_config: String::new(),
                            mounts: Vec::new(),
                        });
                    }
                }
                continue;
            }
            let _ = log.send("  (file-level not applicable to this target — using image backup)".to_string());
        }

        // Run the backup with line-by-line output for vzdump
        let (result, docker_config, mounts) = match t.target_type {
            BackupTargetType::Docker => {
                let _ = log.send(format!("  Exporting Docker container '{}'...", t.name));
                if !t.exclude_mounts.is_empty() {
                    let _ = log.send(format!("  Excluding {} mount(s): {}",
                        t.exclude_mounts.len(), t.exclude_mounts.join(", ")));
                }
                match backup_docker(&t.name, &t.exclude_mounts) {
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
                if !t.exclude_mounts.is_empty() {
                    let _ = log.send(format!("  Excluding {} mount(s): {}",
                        t.exclude_mounts.len(), t.exclude_mounts.join(", ")));
                }
                let r = if crate::containers::is_proxmox() {
                    let _ = log.send(format!("  Running vzdump for container {}...", t.name));
                    backup_lxc_proxmox_with_log(&t.name, &t.exclude_mounts, &log)
                } else {
                    let _ = log.send(format!("  Tarring LXC rootfs for '{}'...", t.name));
                    backup_lxc(&t.name, &t.exclude_mounts)
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
            BackupTargetType::SystemPath => {
                let _ = log.send(format!("  Archiving system folder '{}'...", t.system_path));
                if !t.exclude_mounts.is_empty() {
                    let _ = log.send(format!("  Excluding {} sub-path(s): {}",
                        t.exclude_mounts.len(), t.exclude_mounts.join(", ")));
                }
                (backup_system_path(&t.name, &t.system_path, &t.exclude_mounts), String::new(), Vec::new())
            }
        };

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

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
    exclude_mounts: &[String],
    log: &std::sync::mpsc::Sender<String>,
) -> Result<(PathBuf, u64), String> {
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();

    // Try snapshot mode first, then stop mode
    for mode in &["snapshot", "stop"] {
        let _ = log.send(format!("  vzdump --mode {} ...", mode));

        let mut cmd = Command::new("vzdump");
        cmd.args([
                vmid,
                "--dumpdir", &staging.to_string_lossy(),
                "--mode", mode,
                "--compress", "zstd",
            ]);
        vzdump_apply_excludes(&mut cmd, exclude_mounts);
        let mut child = cmd
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
pub fn restore_by_id_with_log(id: &str, overwrite: bool, storage: &str, new_name: &str, log: std::sync::mpsc::Sender<String>) -> Result<String, String> {
    let config = load_config();
    let entry = config.entries.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;
    restore_entry_with_log(entry, overwrite, storage, new_name, log)
}

/// Restore one backup entry — shared by id-based restore and the folder /
/// disaster-recovery restore (which builds an ephemeral entry, see
/// `restore_from_path`). Everything below operates purely on `entry`.
fn restore_entry_with_log(entry: &BackupEntry, overwrite: bool, storage: &str, new_name: &str, log: std::sync::mpsc::Sender<String>) -> Result<String, String> {
    let type_name = entry.target.target_type.to_string().to_uppercase();
    let display_name = entry.target.hostname.as_deref()
        .map(|h| format!("{} ({})", entry.target.name, h))
        .unwrap_or_else(|| entry.target.name.clone());

    let _ = log.send(format!("Starting {} restore: {}", type_name, display_name));

    // PBS file-level (pxar) snapshot — extract the tree directly. `new_name`
    // carries an optional target directory override (LXC rootfs / system
    // folder / docker staging are the per-type defaults when empty).
    if is_pbs_file_level_entry(entry) {
        let _ = log.send("Restoring PBS file-level snapshot...".to_string());
        let result = restore_pbs_file_level_entry(entry, new_name);
        match &result {
            Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
            Err(e) => { let _ = log.send(format!("❌ {}", e)); }
        }
        return result;
    }

    // Check for container existence before downloading
    if entry.target.target_type == BackupTargetType::Docker {
        let check = Command::new("docker")
            .args(["container", "inspect", &entry.target.name])
            .output();
        let exists = check.map(|o| o.status.success()).unwrap_or(false);
        if exists && !overwrite {
            return Err(format!("CONTAINER_EXISTS:{}", entry.target.name));
        }
        // When overwrite is set, restore_docker stops and removes the
        // existing container itself — no need to duplicate that here.
    }

    match entry.target.target_type {
        BackupTargetType::Docker => {
            // The streaming path used to run `docker load` on the
            // v20.11+ wrapper tarball (image + volumes + binds), which
            // `docker load` rejects. Delegate to restore_docker, which
            // unpacks the wrapper and restores the mounts correctly.
            let _ = log.send("Restoring Docker container...".to_string());
            let result = restore_docker(entry, overwrite);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::Lxc => {
            let _ = log.send("Restoring LXC container...".to_string());
            let result = restore_lxc(entry, storage, overwrite, new_name);
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
        BackupTargetType::SystemPath => {
            // `new_name` carries an operator-chosen restore-target directory
            // (the PARENT into which the folder is unpacked). Empty = restore
            // in place, i.e. the parent of the original `system_path`.
            let target_dir = if new_name.trim().is_empty() {
                Path::new(entry.target.system_path.trim_end_matches('/'))
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "/".to_string())
            } else {
                new_name.trim().to_string()
            };
            let _ = log.send(format!("Restoring system folder into {}...", target_dir));
            let result = restore_system_path(entry, &target_dir);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
    }
}

/// Restore a backup directly from a folder + filename, WITHOUT a backups.json
/// entry — for disaster recovery: restore onto a surviving node from a shared
/// mount when the original server (and its entry) is gone. Builds an ephemeral
/// entry and reuses the normal restore dispatch. The file must be reachable at
/// `source_path`/`filename` on THIS node; the frontend proxies the request to
/// the chosen target node so the workload is recreated there.
pub fn restore_from_path(
    source_path: &str,
    filename: &str,
    overwrite: bool,
    storage: &str,
    new_name: &str,
    log: std::sync::mpsc::Sender<String>,
) -> Result<String, String> {
    if filename.trim().is_empty() || filename.contains('/') || filename.contains("..") {
        return Err("Invalid backup filename (must be a bare file name)".into());
    }
    let target_type = guess_target_type(filename);
    // Config backups extract via `tar xzf -C /` (can touch any path); restoring
    // one from an ARBITRARY folder would be a write-anywhere vector. Folder /
    // disaster-recovery restore is for workloads (Docker/LXC/VM) only.
    if matches!(target_type, BackupTargetType::Config) {
        return Err("Config backups can't be restored from a folder — restore them from the Backups list.".into());
    }
    // System-folder backups don't carry their original target path in the
    // filename, and extracting them touches arbitrary host paths — same
    // write-anywhere concern as Config. Restore them from the Backups list.
    if matches!(target_type, BackupTargetType::SystemPath) {
        return Err("System-folder backups can't be restored from a folder — restore them from the Backups list.".into());
    }
    let size_bytes = fs::metadata(Path::new(source_path).join(filename))
        .map(|m| m.len()).unwrap_or(0);
    let entry = BackupEntry {
        id: Uuid::new_v4().to_string(),
        target: BackupTarget {
            target_type,
            name: extract_name_from_filename(filename),
            ..Default::default()
        },
        storage: BackupStorage::local(source_path),
        filename: filename.to_string(),
        size_bytes,
        created_at: Utc::now().to_rfc3339(),
        status: BackupStatus::Completed,
        error: String::new(),
        schedule_id: String::new(),
        comments: String::new(),
        node_hostname: local_hostname(),
        docker_config: String::new(),
        mounts: Vec::new(),
    };
    restore_entry_with_log(&entry, overwrite, storage, new_name, log)
}

/// A backup file discovered by scanning a folder (no backups.json needed).
#[derive(Debug, Clone, Serialize)]
pub struct ScannedBackup {
    pub filename: String,
    pub target_type: String,
    pub name: String,
    pub size_bytes: u64,
    pub modified: String,
}

/// List WolfStack backup files (`{docker,lxc,vm,config}-*.tar.gz`) in a folder,
/// identifying each from its filename alone — powers "restore from a folder".
pub fn scan_backup_folder(path: &str) -> Result<Vec<ScannedBackup>, String> {
    let dir = Path::new(path);
    if !dir.is_dir() {
        return Err(format!("Not a folder: {}", path));
    }
    let rd = fs::read_dir(dir).map_err(|e| format!("Cannot read folder: {}", e))?;
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if !p.is_file() { continue; }
        let fname = match p.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        // Workload backups only — config backups are intentionally excluded:
        // they can't be restored from a folder (see restore_from_path).
        let is_backup = fname.ends_with(".tar.gz")
            && (fname.starts_with("docker-") || fname.starts_with("lxc-")
                || fname.starts_with("vm-"));
        if !is_backup { continue; }
        let meta = ent.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta.as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339())
            .unwrap_or_default();
        let type_str = match guess_target_type(&fname) {
            BackupTargetType::Docker => "docker",
            BackupTargetType::Lxc => "lxc",
            BackupTargetType::Vm => "vm",
            BackupTargetType::Config => "config",
            // SystemPath files are filtered out above by `is_backup`, but the
            // match must stay exhaustive.
            BackupTargetType::SystemPath => "systempath",
        }.to_string();
        let name = extract_name_from_filename(&fname);
        out.push(ScannedBackup { filename: fname, target_type: type_str, name, size_bytes: size, modified });
    }
    out.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(out)
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
                ..Default::default()
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
                        ..Default::default()
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
                    ..Default::default()
                });
            }
        }
    }

    // VMs — enumerated via VmManager so Proxmox (`qm list`) and libvirt
    // (`virsh list --all`) hosts surface their VMs in the backup picker
    // too. Before v24.6.0 this scanned only `/var/lib/wolfstack/vms/*.json`
    // (the native-KVM layout), so Proxmox/libvirt operators saw zero VMs
    // in the Backups page even though backup_vm_proxmox / backup_vm_libvirt
    // are perfectly capable of backing them up.
    let vm_manager = crate::vms::manager::VmManager::new();
    for vm in vm_manager.list_vms() {
        let mut spec_parts: Vec<String> = Vec::new();
        if vm.cpus > 0 { spec_parts.push(format!("{} vCPU", vm.cpus)); }
        if vm.memory_mb > 0 {
            if vm.memory_mb >= 1024 {
                spec_parts.push(format!("{} GB RAM", vm.memory_mb / 1024));
            } else {
                spec_parts.push(format!("{} MB RAM", vm.memory_mb));
            }
        }
        let specs = if spec_parts.is_empty() { None } else { Some(spec_parts.join(", ")) };
        let state = Some(if vm.running { "running".to_string() } else { "stopped".to_string() });
        targets.push(BackupTarget {
            target_type: BackupTargetType::Vm,
            name: vm.name,
            hostname: None,
            state,
            specs,
            ..Default::default()
        });
    }

    // Config is always available
    targets.push(BackupTarget {
        target_type: BackupTargetType::Config,
        name: String::new(),
        ..Default::default()
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
            ..Default::default()
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
    else if filename.starts_with("systempath-") { BackupTargetType::SystemPath }
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
    if !storage.pbs_fingerprint.is_empty() { list_cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint)); }
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
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
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
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
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
        // Surface the exact repository (no secret — just user!token@host:store
        // and the auth method) so a connection failure is self-diagnosing.
        let auth = if !storage.pbs_token_secret.is_empty() { "API token" }
                   else if !storage.pbs_password.is_empty() { "password" }
                   else { "no credentials" };
        return Err(format!("PBS snapshot list failed [repo {}, auth {}]: {}",
            repo, auth, String::from_utf8_lossy(&output.stderr).trim()));
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
    _target_dir: &str,
    on_progress: F,
    overwrite: bool,
    new_name: &str,
    target_storage: &str,
) -> Result<String, String>
where
    F: Fn(String, Option<f64>),
{
    let repo = pbs_repo_string(storage);

    // Parse snapshot "type/id/timestamp" to determine backup kind and ID
    let parts: Vec<&str> = snapshot.split('/').collect();
    let snap_type = parts.first().copied().unwrap_or("");
    let snap_id = parts.get(1).copied().unwrap_or("");

    if snap_id.is_empty() {
        return Err(format!("Malformed PBS snapshot id: '{}'", snapshot));
    }

    // A WolfStack PBS snapshot is a `backup.pxar` that wraps exactly ONE
    // WolfStack archive file. Extract the pxar into a private staging
    // dir, then hand that archive to the SAME restore code the Backups
    // list uses. The old code reimplemented restore here and got it
    // wrong — it left the archive un-extracted and wrote a stub config.
    // Stage under the backup staging dir (operator-controlled, sized for
    // backup archives) rather than /tmp, which may be a small tmpfs.
    let stage = ensure_staging_dir()?
        .join(format!("pbs-restore-{}", Uuid::new_v4().simple()));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage)
        .map_err(|e| format!("Failed to create PBS restore staging dir: {}", e))?;

    let snapshot_fixed = fix_pbs_snapshot_timestamp(snapshot);

    on_progress("Detecting archive...".to_string(), Some(1.0));

    // Detect the archive kind. A WolfStack *tarball* snapshot wraps its
    // .tar.gz as `backup.pxar`; a WolfStack *file-level* snapshot stores the
    // content tree as `root.pxar` (+ volume-*/bind-* pxars). The caller may
    // request a specific archive; otherwise we sniff the snapshot's files.
    let detected = detect_pbs_archive(storage, &snapshot_fixed);
    let actual_archive = if !archive.is_empty() && archive != "root.pxar" {
        archive.to_string()
    } else {
        detected.clone().unwrap_or_else(|| "backup.pxar".to_string())
    };

    // File-level snapshot: extract the `root.pxar` tree directly. There's no
    // inner WolfStack archive to hand to restore_lxc_local — the snapshot IS
    // the filesystem. Restore the whole tree into a clearly-named directory
    // under the restore area; per-FILE restore is done from PBS's own UI.
    let is_file_level = actual_archive == "root.pxar";
    if is_file_level {
        on_progress(format!("Restoring file-level tree {}...", actual_archive), Some(2.0));
        let out_dir = ensure_staging_dir().unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("pbs-fl-restore-{}-{}", snap_id, Uuid::new_v4().simple()));
        let _ = fs::remove_dir_all(&stage); // not used on this branch
        fs::create_dir_all(&out_dir)
            .map_err(|e| format!("Failed to create restore dir: {}", e))?;
        let mut cmd = Command::new("proxmox-backup-client");
        cmd.arg("restore")
           .arg(&snapshot_fixed)
           .arg("root.pxar")
           .arg(&out_dir)
           .arg("--repository").arg(&repo)
           .arg("--ignore-ownership").arg("true");
        pbs_apply_common(&mut cmd, storage);
        let out = cmd.output()
            .map_err(|e| { let _ = fs::remove_dir_all(&out_dir); format!("PBS file-level restore failed: {}", e) })?;
        if !out.status.success() {
            let _ = fs::remove_dir_all(&out_dir);
            return Err(format!("PBS file-level restore error: {}",
                String::from_utf8_lossy(&out.stderr).trim()));
        }
        on_progress("File-level restore complete".to_string(), Some(100.0));
        return Ok(format!(
            "File-level snapshot '{}' restored into {} — the container/folder \
             filesystem is there; use PBS's per-file restore for individual files.",
            snapshot, out_dir.display()));
    }

    on_progress(format!("Downloading {}...", actual_archive), Some(2.0));

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot_fixed)
       .arg(&actual_archive)
       .arg(&stage)
       .arg("--repository").arg(&repo)
       .arg("--ignore-ownership").arg("true");

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
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

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!("Failed to start proxmox-backup-client: {}", e));
        }
    };

    // Monitor staging-dir size growth while the download runs
    let target_path = stage.to_string_lossy().to_string();
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

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!("PBS restore wait failed: {}", e));
        }
    };

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
        let _ = fs::remove_dir_all(&stage);
        return Err(format!("PBS restore failed for '{}': {}", snapshot_fixed, err_detail));
    }

    // The pxar yielded the WolfStack archive — the single regular file
    // now sitting in the staging dir.
    on_progress("Unpacking restored backup...".to_string(), Some(90.0));
    let archive_file = fs::read_dir(&stage).ok()
        .and_then(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).find(|p| p.is_file()));
    let archive_file = match archive_file {
        Some(f) => f,
        None => {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!(
                "Snapshot '{}' contains no WolfStack backup archive — it may be a \
                 native Proxmox backup; restore those from a Proxmox host.", snapshot));
        }
    };

    // Hand the archive to the SAME restore path the Backups list uses —
    // it un-archives the rootfs properly and restores the real config,
    // instead of leaving a compressed file behind under a stub config.
    // The operator-picked Proxmox storage (empty = let Proxmox default)
    // flows into both `pct restore --storage` (LXC) and `qm` restore (VM).
    let pve_storage = if target_storage.trim().is_empty() { None } else { Some(target_storage.trim()) };
    let result = match snap_type {
        "ct" => restore_lxc_local(&archive_file, snap_id, pve_storage.unwrap_or(""), overwrite, new_name),
        "vm" => restore_vm_local(&archive_file, snap_id, pve_storage),
        other => {
            let _ = fs::remove_file(&archive_file);
            Err(format!(
                "Restoring a '{}' snapshot from the PBS list isn't supported here — \
                 restore it from the Backups list instead.", other))
        }
    };
    let _ = fs::remove_dir_all(&stage);
    result
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
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
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
        // Prefer the well-known WolfStack archive names first so a file-level
        // snapshot (root.pxar + volume-*/bind-*) resolves to `root.pxar` and a
        // tarball snapshot to `backup.pxar`, regardless of PBS listing order.
        for preferred in ["root.pxar", "backup.pxar"] {
            for f in arr {
                let filename = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                let name = filename.trim_end_matches(".didx");
                if name == preferred {
                    return Some(name.to_string());
                }
            }
        }
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
    // file-level is a saved preference of the PBS destination — adopt it when
    // the caller (e.g. the cluster scheduler form sending only `{type:"pbs"}`)
    // didn't explicitly request it. A POST that DID set it wins.
    if !storage.pbs_file_level         { storage.pbs_file_level  = saved.pbs_file_level; }
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

#[cfg(test)]
mod restore_warning_tests {
    use super::read_hwaddrs;
    use std::io::Write;

    fn write_tmp(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wolfstack-hwaddr-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn extracts_every_lxc_net_hwaddr_line() {
        let p = write_tmp(
            "lxc.uts.name = foo\n\
             lxc.net.0.type = veth\n\
             lxc.net.0.hwaddr = 00:16:3e:aa:bb:cc\n\
             lxc.net.1.hwaddr=00:16:3e:DD:EE:FF\n\
             # commented = 11:22:33:44:55:66\n\
             lxc.net.2.type = veth\n",
        );
        let mut macs = read_hwaddrs(p.to_str().unwrap());
        macs.sort();
        let _ = std::fs::remove_file(&p);
        assert_eq!(
            macs,
            vec!["00:16:3e:aa:bb:cc".to_string(), "00:16:3e:dd:ee:ff".to_string()]
        );
    }

    #[test]
    fn returns_empty_for_missing_or_macless_config() {
        // Nonexistent path → empty.
        assert!(read_hwaddrs("/nonexistent/wolfstack/test/config").is_empty());
        // Config without any hwaddr lines → empty.
        let p = write_tmp("lxc.uts.name = bar\nlxc.net.0.type = veth\n");
        let macs = read_hwaddrs(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(macs.is_empty());
    }

    #[test]
    fn does_not_confuse_other_keys_containing_hwaddr_substring() {
        // Hypothetical comment line + look-alike key. Neither should match.
        let p = write_tmp(
            "# lxc.net.0.hwaddr = ff:ff:ff:ff:ff:ff\n\
             lxc.net.x.hwaddr = aa:bb:cc:dd:ee:ff\n",
        );
        let macs = read_hwaddrs(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(macs.is_empty(), "matched a non-numeric net index: {:?}", macs);
    }
}
