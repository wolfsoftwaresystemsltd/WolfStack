//! Backup & Restore — Docker, LXC, VM, and config backup management
//!
//! Supports storage targets: local path, S3, remote WolfStack node, WolfDisk
//! Includes scheduling with retention policies

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, error};
use chrono::{Utc, Datelike};
use uuid::Uuid;

const BACKUP_CONFIG_PATH: &str = "/etc/wolfstack/backups.json";
const BACKUP_STAGING_DIR: &str = "/tmp/wolfstack-backups";

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    Local,
    S3,
    Remote,
    Wolfdisk,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::S3 => write!(f, "s3"),
            Self::Remote => write!(f, "remote"),
            Self::Wolfdisk => write!(f, "wolfdisk"),
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
        }
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
    match fs::read_to_string(BACKUP_CONFIG_PATH) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => BackupConfig::default(),
    }
}

pub fn save_config(config: &BackupConfig) -> Result<(), String> {
    let dir = Path::new(BACKUP_CONFIG_PATH).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize backup config: {}", e))?;
    fs::write(BACKUP_CONFIG_PATH, json)
        .map_err(|e| format!("Failed to write backup config: {}", e))
}

// ─── Backup Functions ───

/// Create staging directory
fn ensure_staging_dir() -> Result<PathBuf, String> {
    let path = PathBuf::from(BACKUP_STAGING_DIR);
    fs::create_dir_all(&path).map_err(|e| format!("Failed to create staging dir: {}", e))?;
    Ok(path)
}

/// Backup a Docker container — commit + save + gzip
pub fn backup_docker(name: &str) -> Result<(PathBuf, u64), String> {
    info!("Backing up Docker container: {}", name);
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("docker-{}-{}.tar.gz", name, timestamp);
    let tar_path = staging.join(&filename);
    let temp_image = format!("wolfstack-backup/{}", name);

    // Commit the container to a temp image
    let output = Command::new("docker")
        .args(["commit", name, &temp_image])
        .output()
        .map_err(|e| format!("Failed to commit container: {}", e))?;

    if !output.status.success() {
        return Err(format!("Docker commit failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Save the image to tar, pipe through gzip
    let output = Command::new("sh")
        .args(["-c", &format!("docker save '{}' | gzip > '{}'", temp_image, tar_path.display())])
        .output()
        .map_err(|e| format!("Failed to save image: {}", e))?;

    // Clean up temp image
    let _ = Command::new("docker").args(["rmi", &temp_image]).output();

    if !output.status.success() {
        return Err(format!("Docker save failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    info!("Docker backup complete: {} ({} bytes)", filename, size);
    Ok((tar_path, size))
}

/// Backup an LXC container — tar rootfs + config
pub fn backup_lxc(name: &str) -> Result<(PathBuf, u64), String> {
    info!("Backing up LXC container: {}", name);
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("lxc-{}-{}.tar.gz", name, timestamp);
    let tar_path = staging.join(&filename);

    // Check if container is running — stop it for consistent backup
    let was_running = is_lxc_running(name);
    if was_running {
        info!("Stopping LXC container {} for backup", name);
        let _ = Command::new("lxc-stop").args(["-n", name]).output();
        // Wait briefly for clean stop
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    // Check LXC path — could be /var/lib/lxc/{name} or custom
    let lxc_path = format!("/var/lib/lxc/{}", name);
    if !Path::new(&lxc_path).exists() {
        if was_running {
            let _ = Command::new("lxc-start").args(["-n", name]).output();
        }
        return Err(format!("LXC container path not found: {}", lxc_path));
    }

    // Create tar.gz of the entire container directory
    let output = Command::new("tar")
        .args(["czf", &tar_path.to_string_lossy(), "-C", "/var/lib/lxc", name])
        .output()
        .map_err(|e| format!("Failed to tar LXC container: {}", e))?;

    // Restart if it was running
    if was_running {
        info!("Restarting LXC container {} after backup", name);
        let _ = Command::new("lxc-start").args(["-n", name]).output();
    }

    if !output.status.success() {
        return Err(format!("LXC tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    info!("LXC backup complete: {} ({} bytes)", filename, size);
    Ok((tar_path, size))
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
    info!("Backing up VM: {}", name);
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("vm-{}-{}.tar.gz", name, timestamp);
    let tar_path = staging.join(&filename);

    let vm_dir = format!("/var/lib/wolfstack/vms/{}", name);
    if !Path::new(&vm_dir).exists() {
        return Err(format!("VM directory not found: {}", vm_dir));
    }

    // Check if VM is running (check for QEMU process)
    let was_running = is_vm_running(name);
    if was_running {
        info!("Stopping VM {} for backup", name);
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

    // Find all files belonging to this VM (config + disk images)
    // We tar the entire VM directory which contains config.json and disk images
    let output = Command::new("tar")
        .args(["czf", &tar_path.to_string_lossy(), "-C", "/var/lib/wolfstack/vms", name])
        .output()
        .map_err(|e| format!("Failed to tar VM: {}", e))?;

    if !output.status.success() {
        return Err(format!("VM tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Restart if it was running
    if was_running {
        info!("VM {} was running before backup — you may need to restart it manually", name);
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    info!("VM backup complete: {} ({} bytes)", filename, size);
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
    info!("Backing up WolfStack configuration");
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
    info!("Config backup complete: {} ({} bytes)", filename, size);
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
                BackupTarget { target_type: BackupTargetType::Docker, name: name.clone() },
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
                BackupTarget { target_type: BackupTargetType::Lxc, name: name.clone() },
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
                        BackupTarget { target_type: BackupTargetType::Vm, name },
                        storage,
                    ));
                }
            }
        }
    }

    // Backup config
    entries.push(create_backup_entry(
        BackupTarget { target_type: BackupTargetType::Config, name: String::new() },
        storage,
    ));

    entries
}

/// Create a single backup entry — performs the backup and stores it
fn create_backup_entry(target: BackupTarget, storage: &BackupStorage) -> BackupEntry {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = match target.target_type {
        BackupTargetType::Docker => backup_docker(&target.name),
        BackupTargetType::Lxc => backup_lxc(&target.name),
        BackupTargetType::Vm => backup_vm(&target.name),
        BackupTargetType::Config => backup_config(),
    };

    match result {
        Ok((local_path, size)) => {
            // Store to target location
            let filename = local_path.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("backup-{}.tar.gz", id));

            match store_backup(&local_path, storage, &filename) {
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
            }
        }
    }
}

// ─── Storage Functions ───

/// Store a backup file to the configured storage target
fn store_backup(local_path: &Path, storage: &BackupStorage, filename: &str) -> Result<(), String> {
    match storage.storage_type {
        StorageType::Local => store_local(local_path, &storage.path, filename),
        StorageType::S3 => store_s3(local_path, storage, filename),
        StorageType::Remote => store_remote(local_path, &storage.remote_url, filename),
        StorageType::Wolfdisk => store_local(local_path, &storage.path, filename), // WolfDisk is just a mount path
    }
}

/// Store backup to local path
fn store_local(local_path: &Path, dest_dir: &str, filename: &str) -> Result<(), String> {
    fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Failed to create backup dir {}: {}", dest_dir, e))?;
    let dest = Path::new(dest_dir).join(filename);
    fs::copy(local_path, &dest)
        .map_err(|e| format!("Failed to copy backup to {}: {}", dest.display(), e))?;
    info!("Backup stored locally: {}", dest.display());
    Ok(())
}

/// Store backup to S3
fn store_s3(local_path: &Path, storage: &BackupStorage, filename: &str) -> Result<(), String> {
    info!("Uploading backup to S3: {}/{}", storage.bucket, filename);

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

            info!("Backup uploaded to S3: {}/{}", bucket_name, key);
            Ok::<(), String>(())
        })
    }).join().map_err(|_| "S3 upload thread panicked".to_string())?
}

/// Store backup to remote WolfStack node
fn store_remote(local_path: &Path, remote_url: &str, filename: &str) -> Result<(), String> {
    info!("Sending backup to remote node: {}", remote_url);
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

    info!("Backup sent to remote node: {}", remote_url);
    Ok(())
}

/// Retrieve a backup file from storage for restore
fn retrieve_backup(entry: &BackupEntry) -> Result<PathBuf, String> {
    let staging = ensure_staging_dir()?;
    let local_path = staging.join(&entry.filename);

    match entry.storage.storage_type {
        StorageType::Local | StorageType::Wolfdisk => {
            let source = Path::new(&entry.storage.path).join(&entry.filename);
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
pub fn restore_docker(entry: &BackupEntry) -> Result<String, String> {
    info!("Restoring Docker container from backup: {}", entry.filename);
    let local_path = retrieve_backup(entry)?;

    // Load the image from the tar.gz
    let output = Command::new("sh")
        .args(["-c", &format!("gunzip -c '{}' | docker load", local_path.display())])
        .output()
        .map_err(|e| format!("Failed to load Docker image: {}", e))?;

    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("Docker load failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let result = String::from_utf8_lossy(&output.stdout).to_string();
    info!("Docker restore complete: {}", result.trim());
    Ok(format!("Docker image restored: {}", result.trim()))
}

/// Restore an LXC container from backup
pub fn restore_lxc(entry: &BackupEntry) -> Result<String, String> {
    info!("Restoring LXC container from backup: {}", entry.filename);
    let local_path = retrieve_backup(entry)?;

    // Extract to /var/lib/lxc/
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", "/var/lib/lxc/"])
        .output()
        .map_err(|e| format!("Failed to extract LXC backup: {}", e))?;

    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("LXC extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    info!("LXC restore complete: {}", entry.target.name);
    Ok(format!("LXC container '{}' restored", entry.target.name))
}

/// Restore a VM from backup
pub fn restore_vm(entry: &BackupEntry) -> Result<String, String> {
    info!("Restoring VM from backup: {}", entry.filename);
    let local_path = retrieve_backup(entry)?;

    let vm_base = "/var/lib/wolfstack/vms";
    fs::create_dir_all(vm_base).map_err(|e| format!("Failed to create VM dir: {}", e))?;

    // Extract to /var/lib/wolfstack/vms/
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", vm_base])
        .output()
        .map_err(|e| format!("Failed to extract VM backup: {}", e))?;

    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("VM extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    info!("VM restore complete: {}", entry.target.name);
    Ok(format!("VM '{}' restored", entry.target.name))
}

/// Restore WolfStack configuration from backup
pub fn restore_config_backup(entry: &BackupEntry) -> Result<String, String> {
    info!("Restoring WolfStack config from backup: {}", entry.filename);
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

    info!("Config restore complete");
    Ok("WolfStack configuration restored. Restart services to apply changes.".to_string())
}

/// Restore from a backup entry (auto-detects type)
pub fn restore_backup(entry: &BackupEntry) -> Result<String, String> {
    match entry.target.target_type {
        BackupTargetType::Docker => restore_docker(entry),
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

/// Delete a backup entry and its file
pub fn delete_backup(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.entries.iter().position(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;

    let entry = config.entries.remove(idx);

    // Try to delete the file from storage
    match entry.storage.storage_type {
        StorageType::Local | StorageType::Wolfdisk => {
            let path = Path::new(&entry.storage.path).join(&entry.filename);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        },
        _ => {} // S3 and Remote deletion not implemented yet
    }

    save_config(&config)?;
    Ok(format!("Backup {} deleted", id))
}

/// Restore from a backup by ID
pub fn restore_by_id(id: &str) -> Result<String, String> {
    let config = load_config();
    let entry = config.entries.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;
    restore_backup(entry)
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

/// List all available backup targets on the system
pub fn list_available_targets() -> Vec<BackupTarget> {
    let mut targets = Vec::new();

    // Docker containers
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        for name in String::from_utf8_lossy(&output.stdout).lines() {
            if !name.is_empty() {
                targets.push(BackupTarget {
                    target_type: BackupTargetType::Docker,
                    name: name.to_string(),
                });
            }
        }
    }

    // LXC containers
    if let Ok(output) = Command::new("lxc-ls").output() {
        for name in String::from_utf8_lossy(&output.stdout).split_whitespace() {
            if !name.is_empty() {
                targets.push(BackupTarget {
                    target_type: BackupTargetType::Lxc,
                    name: name.to_string(),
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
    });

    targets
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
        info!("Running scheduled backup: {} ({})", schedule.name, schedule.id);
        
        let new_entries = if schedule.backup_all {
            backup_all(&schedule.storage)
        } else {
            schedule.targets.iter()
                .map(|t| create_backup_entry(t.clone(), &schedule.storage))
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
                            let path = Path::new(&entry.storage.path).join(&entry.filename);
                            let _ = fs::remove_file(&path);
                        },
                        _ => {}
                    }
                    config.entries.remove(idx);
                }
                info!("Pruned {} old backups for schedule {}", to_remove.len(), schedule_id);
            }
        }
    }

    if changed {
        let _ = save_config(&config);
    }
}

/// Receive a backup file from a remote node — save to local storage
pub fn import_backup(data: &[u8], filename: &str) -> Result<String, String> {
    let dest_dir = "/var/lib/wolfstack/backups/received";
    fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Failed to create import dir: {}", e))?;

    let dest = Path::new(dest_dir).join(filename);
    fs::write(&dest, data)
        .map_err(|e| format!("Failed to write imported backup: {}", e))?;

    let size = data.len();
    info!("Received backup import: {} ({} bytes)", filename, size);

    // Add to config as an entry
    let mut config = load_config();
    config.entries.push(BackupEntry {
        id: Uuid::new_v4().to_string(),
        target: BackupTarget {
            target_type: guess_target_type(filename),
            name: extract_name_from_filename(filename),
        },
        storage: BackupStorage::local(dest_dir),
        filename: filename.to_string(),
        size_bytes: size as u64,
        created_at: Utc::now().to_rfc3339(),
        status: BackupStatus::Completed,
        error: String::new(),
        schedule_id: String::new(),
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
