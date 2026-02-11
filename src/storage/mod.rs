//! Storage Manager — mount and manage S3, NFS, directory, and WolfDisk storage
//!
//! Supports:
//! - S3 storage via rclone mount
//! - NFS storage via mount -t nfs
//! - Local directory bind mounts
//! - WolfDisk mounts via wolfdiskctl
//! - Global mounts replicated across the cluster
//! - Import of S3 configs from rclone.conf

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, error};
use chrono::Utc;

const CONFIG_PATH: &str = "/etc/wolfstack/storage.json";
const MOUNT_BASE: &str = "/mnt/wolfstack";

// ─── Data Types ───

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    S3,
    Nfs,
    Directory,
    Wolfdisk,
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
    match fs::read_to_string(CONFIG_PATH) {
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
    let dir = Path::new(CONFIG_PATH).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(CONFIG_PATH, json)
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
        } else if mount.enabled {
            mount.status = "unmounted".to_string();
        }
    }
    config.mounts
}

// ─── Mount Operations ───

/// Mount a storage entry by ID
pub fn mount_storage(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.mounts.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
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
        MountType::Directory => mount_directory(&config.mounts[idx]),
        MountType::Wolfdisk => mount_wolfdisk(&config.mounts[idx]),
    };
    
    match result {
        Ok(msg) => {
            config.mounts[idx].status = "mounted".to_string();
            config.mounts[idx].error_message = None;
            config.mounts[idx].enabled = true;
            save_config(&config)?;
            info!("Mounted storage '{}' at {}", config.mounts[idx].name, config.mounts[idx].mount_point);
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
    
    // For S3/rclone mounts, use fusermount -u
    let output = if config.mounts[idx].mount_type == MountType::S3 {
        Command::new("fusermount")
            .args(["-u", &config.mounts[idx].mount_point])
            .output()
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
            info!("Unmounted storage '{}' from {}", config.mounts[idx].name, config.mounts[idx].mount_point);
            Ok("Unmounted successfully".to_string())
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            // Try lazy unmount as fallback
            let _ = Command::new("umount").args(["-l", &config.mounts[idx].mount_point]).output();
            config.mounts[idx].status = "unmounted".to_string();
            save_config(&config)?;
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

/// Update a mount entry
pub fn update_mount(id: &str, updates: serde_json::Value) -> Result<StorageMount, String> {
    let mut config = load_config();
    let mount = config.mounts.iter_mut().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
    // Apply updates
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
    
    let result = mount.clone();
    save_config(&config)?;
    Ok(result)
}

// ─── Type-specific mount implementations ───

fn mount_s3(mount: &StorageMount) -> Result<String, String> {
    let s3 = mount.s3_config.as_ref()
        .ok_or("S3 config is required for S3 mounts")?;
    
    // Ensure rclone is installed
    ensure_rclone_installed()?;
    
    // Write rclone config for this mount
    let rclone_config_dir = "/etc/wolfstack/rclone";
    fs::create_dir_all(rclone_config_dir)
        .map_err(|e| format!("Failed to create rclone config dir: {}", e))?;
    
    let remote_name = format!("wolfstack-{}", mount.id);
    let config_path = format!("{}/rclone.conf", rclone_config_dir);
    
    // Build rclone config section
    let mut config_section = format!(
        "[{}]\ntype = s3\nprovider = {}\naccess_key_id = {}\nsecret_access_key = {}\n",
        remote_name, s3.provider, s3.access_key_id, s3.secret_access_key
    );
    if !s3.region.is_empty() {
        config_section.push_str(&format!("region = {}\n", s3.region));
    }
    if !s3.endpoint.is_empty() {
        config_section.push_str(&format!("endpoint = {}\n", s3.endpoint));
    }
    
    // Read existing config or create new
    let mut full_config = fs::read_to_string(&config_path).unwrap_or_default();
    
    // Remove existing section for this remote if present
    let section_header = format!("[{}]", remote_name);
    if let Some(start) = full_config.find(&section_header) {
        let end = full_config[start + section_header.len()..]
            .find("\n[")
            .map(|i| start + section_header.len() + i)
            .unwrap_or(full_config.len());
        full_config = format!("{}{}", &full_config[..start], &full_config[end..]);
    }
    
    full_config.push_str(&config_section);
    fs::write(&config_path, &full_config)
        .map_err(|e| format!("Failed to write rclone config: {}", e))?;
    
    // Run rclone mount in background
    let bucket_path = if s3.bucket.is_empty() {
        format!("{}:", remote_name)
    } else {
        format!("{}:{}", remote_name, s3.bucket)
    };
    
    let child = Command::new("rclone")
        .args([
            "mount",
            &bucket_path,
            &mount.mount_point,
            "--config", &config_path,
            "--vfs-cache-mode", "full",
            "--daemon",
            "--allow-other",
            "--allow-non-empty",
        ])
        .spawn();
    
    match child {
        Ok(_) => {
            // Give it a moment to mount
            std::thread::sleep(std::time::Duration::from_secs(2));
            if check_mounted(&mount.mount_point) {
                Ok("S3 storage mounted via rclone".to_string())
            } else {
                Err("rclone mount started but mount point not detected — check credentials".to_string())
            }
        }
        Err(e) => Err(format!("Failed to start rclone mount: {}", e)),
    }
}

fn mount_nfs(mount: &StorageMount) -> Result<String, String> {
    // Ensure nfs-common is installed
    if !Path::new("/sbin/mount.nfs").exists() && !Path::new("/usr/sbin/mount.nfs").exists() {
        info!("Installing nfs-common...");
        let install = Command::new("apt-get")
            .args(["install", "-y", "nfs-common"])
            .output()
            .map_err(|e| format!("Failed to install nfs-common: {}", e))?;
        if !install.status.success() {
            return Err(format!("Failed to install nfs-common: {}", 
                String::from_utf8_lossy(&install.stderr)));
        }
    }
    
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

fn mount_wolfdisk(mount: &StorageMount) -> Result<String, String> {
    // Check if wolfdiskctl exists
    if !Path::new("/usr/local/bin/wolfdiskctl").exists() 
        && !Path::new("/opt/wolfdisk/wolfdiskctl").exists() {
        return Err("WolfDisk is not installed. Install it first via Components.".to_string());
    }
    
    let output = Command::new("wolfdiskctl")
        .args(["mount", &mount.source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run wolfdiskctl: {}", e))?;
    
    if output.status.success() {
        Ok("WolfDisk storage mounted".to_string())
    } else {
        Err(format!("WolfDisk mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── Helpers ───

fn ensure_rclone_installed() -> Result<(), String> {
    if let Ok(output) = Command::new("rclone").arg("version").output() {
        if output.status.success() {
            return Ok(());
        }
    }
    
    info!("Installing rclone...");
    let output = Command::new("bash")
        .args(["-c", "curl -s https://rclone.org/install.sh | bash"])
        .output()
        .map_err(|e| format!("Failed to install rclone: {}", e))?;
    
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("rclone installation failed: {}", 
            String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── Rclone Config Import ───

/// Parse an rclone.conf file contents and extract S3 remotes as StorageMount definitions
pub fn import_rclone_config(rclone_conf: &str) -> Result<Vec<StorageMount>, String> {
    let mut mounts = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_props: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    
    for line in rclone_conf.lines() {
        let trimmed = line.trim();
        
        // New section
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Save previous section
            if let Some(ref name) = current_section {
                if let Some(mount) = rclone_section_to_mount(name, &current_props) {
                    mounts.push(mount);
                }
            }
            current_section = Some(trimmed[1..trimmed.len()-1].to_string());
            current_props.clear();
            continue;
        }
        
        // Key = value
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos+1..].trim().to_string();
            current_props.insert(key, value);
        }
    }
    
    // Don't forget the last section
    if let Some(ref name) = current_section {
        if let Some(mount) = rclone_section_to_mount(name, &current_props) {
            mounts.push(mount);
        }
    }
    
    if mounts.is_empty() {
        return Err("No S3-compatible remotes found in rclone.conf".to_string());
    }
    
    Ok(mounts)
}

fn rclone_section_to_mount(
    name: &str, 
    props: &std::collections::HashMap<String, String>
) -> Option<StorageMount> {
    let rtype = props.get("type").map(|s| s.as_str()).unwrap_or("");
    
    // Only import S3-compatible types
    if rtype != "s3" && rtype != "b2" && rtype != "gcs" && rtype != "r2" {
        return None;
    }
    
    let s3_config = S3Config {
        access_key_id: props.get("access_key_id").cloned().unwrap_or_default(),
        secret_access_key: props.get("secret_access_key").cloned().unwrap_or_default(),
        region: props.get("region").cloned().unwrap_or_default(),
        endpoint: props.get("endpoint").cloned().unwrap_or_default(),
        provider: props.get("provider").cloned().unwrap_or_else(|| "AWS".to_string()),
        bucket: String::new(),
    };
    
    let id = generate_id(name);
    Some(StorageMount {
        id: id.clone(),
        name: name.to_string(),
        mount_type: MountType::S3,
        source: format!("{}:", name),
        mount_point: format!("{}/{}", MOUNT_BASE, id),
        enabled: false,
        global: false,
        auto_mount: false,
        s3_config: Some(s3_config),
        nfs_options: None,
        status: "unmounted".to_string(),
        error_message: None,
        created_at: Utc::now().to_rfc3339(),
    })
}

// ─── Auto-mount on boot ───

/// Mount all entries that have auto_mount: true — called at startup
pub fn auto_mount_all() {
    let config = load_config();
    let auto_mounts: Vec<_> = config.mounts.iter()
        .filter(|m| m.auto_mount && m.enabled)
        .map(|m| m.id.clone())
        .collect();
    
    if auto_mounts.is_empty() {
        return;
    }
    
    info!("Auto-mounting {} storage entries...", auto_mounts.len());
    for id in auto_mounts {
        match mount_storage(&id) {
            Ok(msg) => info!("  ✓ Auto-mounted {}: {}", id, msg),
            Err(e) => error!("  ✗ Failed to auto-mount {}: {}", id, e),
        }
    }
}

// ─── Container Mount Integration ───

/// Get all mounted storage entries that can be attached to containers
pub fn available_mounts() -> Vec<StorageMount> {
    load_config().mounts.into_iter()
        .filter(|m| m.status == "mounted" || check_mounted(&m.mount_point))
        .collect()
}
