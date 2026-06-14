// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Ceph Cluster Management — setup, monitoring, and administration of Ceph storage clusters
//!
//! Supports:
//! - Cluster bootstrap (mon, mgr, osd setup)
//! - Cluster status and health monitoring
//! - OSD management (add, remove, reweight)
//! - Pool management (create, delete, set options)
//! - CephFS management
//! - RBD image management
//! - Dashboard integration via `ceph` CLI

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{error, info};

fn config_path() -> String { crate::paths::get().ceph_config }

// ─── Data Types ───

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CephHealthStatus {
    Ok,
    Warn,
    Error,
    Unknown,
}

impl Default for CephHealthStatus {
    fn default() -> Self { CephHealthStatus::Unknown }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CephClusterStatus {
    pub health: CephHealthStatus,
    pub health_detail: String,
    #[serde(default)]
    pub monitors: Vec<CephMonitor>,
    #[serde(default)]
    pub mgrs: Vec<CephManager>,
    #[serde(default)]
    pub osds: Vec<CephOsd>,
    #[serde(default)]
    pub pools: Vec<CephPool>,
    #[serde(default)]
    pub pg_summary: String,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub available_bytes: u64,
    #[serde(default)]
    pub objects: u64,
    #[serde(default)]
    pub fsid: String,
    #[serde(default)]
    pub ceph_version: String,
    #[serde(default)]
    pub services: HashMap<String, u32>,
    #[serde(default)]
    pub filesystems: Vec<CephFilesystem>,
    #[serde(default)]
    pub rbd_images: Vec<RbdImage>,
    #[serde(default)]
    pub crush_rules: Vec<CrushRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CephMonitor {
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub rank: u32,
    #[serde(default)]
    pub in_quorum: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CephManager {
    pub name: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CephOsd {
    pub id: u32,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub device_class: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub up: bool,
    #[serde(rename = "in")]
    #[serde(default)]
    pub in_cluster: bool,
    #[serde(default)]
    pub weight: f64,
    #[serde(default)]
    pub reweight: f64,
    #[serde(default)]
    pub pgs: u32,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CephPool {
    pub name: String,
    pub id: u32,
    #[serde(default)]
    pub pool_type: String,
    #[serde(default)]
    pub size: u32,
    #[serde(default)]
    pub min_size: u32,
    #[serde(default)]
    pub pg_num: u32,
    #[serde(default)]
    pub pgp_num: u32,
    #[serde(default)]
    pub crush_rule: String,
    #[serde(default)]
    pub stored_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub objects: u64,
    #[serde(default)]
    pub percent_used: f64,
    #[serde(default)]
    pub max_avail: u64,
    #[serde(default)]
    pub application: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CephFilesystem {
    pub name: String,
    #[serde(default)]
    pub metadata_pool: String,
    #[serde(default)]
    pub data_pools: Vec<String>,
    #[serde(default)]
    pub active_mds: u32,
    #[serde(default)]
    pub standby_mds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbdImage {
    pub pool: String,
    pub name: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub features: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrushRule {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub rule_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CephConfig {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub cluster_name: String,
    #[serde(default)]
    pub mon_initial_members: Vec<String>,
    #[serde(default)]
    pub public_network: String,
    #[serde(default)]
    pub cluster_network: String,
}

// ─── Config Persistence ───

#[allow(dead_code)]
pub fn load_config() -> CephConfig {
    match std::fs::read_to_string(&config_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            error!("Failed to parse ceph config: {}", e);
            CephConfig::default()
        }),
        Err(_) => CephConfig::default(),
    }
}

pub fn save_config(config: &CephConfig) -> Result<(), String> {
    let path = config_path();
    let dir = std::path::Path::new(&path).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {}", e))?;
    let json = serde_json::to_string_pretty(config).map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("write: {}", e))?;
    Ok(())
}

// ─── Ceph CLI Helpers ───

/// Check whether ceph CLI is available
pub fn is_ceph_installed() -> bool {
    Command::new("which").arg("ceph")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a ceph command and return JSON output
fn ceph_json(args: &[&str]) -> Result<serde_json::Value, String> {
    let mut cmd_args: Vec<&str> = args.to_vec();
    cmd_args.push("-f");
    cmd_args.push("json");
    let output = Command::new("ceph")
        .args(&cmd_args)
        .output()
        .map_err(|e| format!("Failed to run ceph: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ceph {} failed: {}", args.join(" "), stderr.trim()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).map_err(|e| format!("JSON parse error: {} — output: {}", e, &stdout[..stdout.len().min(200)]))
}

/// Run a ceph command and return raw text output
fn ceph_text(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ceph")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run ceph: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ceph {} failed: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a ceph-volume or other system command
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{} failed: {}", cmd, stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// ─── Cluster Status ───

/// Get full cluster status
pub fn get_cluster_status() -> CephClusterStatus {
    if !is_ceph_installed() {
        return CephClusterStatus {
            health: CephHealthStatus::Unknown,
            health_detail: "Ceph is not installed".into(),
            ..Default::default()
        };
    }

    let mut status = CephClusterStatus::default();

    // ceph status
    if let Ok(val) = ceph_json(&["status"]) {
        // Health
        if let Some(health) = val.get("health") {
            let overall = health.get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("UNKNOWN");
            status.health = match overall {
                "HEALTH_OK" => CephHealthStatus::Ok,
                "HEALTH_WARN" => CephHealthStatus::Warn,
                "HEALTH_ERR" => CephHealthStatus::Error,
                _ => CephHealthStatus::Unknown,
            };
            // Collect health check messages
            if let Some(checks) = health.get("checks").and_then(|c| c.as_object()) {
                let msgs: Vec<String> = checks.iter().map(|(k, v)| {
                    let msg = v.get("summary").and_then(|s| s.get("message")).and_then(|m| m.as_str()).unwrap_or("");
                    format!("{}: {}", k, msg)
                }).collect();
                status.health_detail = msgs.join("; ");
            }
        }

        // FSID
        if let Some(fsid) = val.get("fsid").and_then(|f| f.as_str()) {
            status.fsid = fsid.to_string();
        }

        // Monitors from quorum_names
        if let Some(quorum) = val.get("quorum_names").and_then(|q| q.as_array()) {
            status.monitors = quorum.iter().filter_map(|n| n.as_str()).map(|name| {
                CephMonitor {
                    name: name.to_string(),
                    address: String::new(),
                    rank: 0,
                    in_quorum: true,
                }
            }).collect();
        }

        // Manager info — ceph status only has a summary (available, num_standbys),
        // so we need "ceph mgr dump" for the actual active_name and standbys list
        if let Ok(mgr_dump) = ceph_json(&["mgr", "dump"]) {
            if let Some(active_name) = mgr_dump.get("active_name").and_then(|n| n.as_str()) {
                if !active_name.is_empty() {
                    status.mgrs.push(CephManager {
                        name: active_name.to_string(),
                        active: true,
                        available: true,
                    });
                }
            }
            if let Some(standbys) = mgr_dump.get("standbys").and_then(|s| s.as_array()) {
                for sb in standbys {
                    if let Some(name) = sb.get("name").and_then(|n| n.as_str()) {
                        status.mgrs.push(CephManager {
                            name: name.to_string(),
                            active: false,
                            available: true,
                        });
                    }
                }
            }
        }

        // Services summary
        if let Some(svc) = val.get("servicemap").and_then(|s| s.get("services")).and_then(|s| s.as_object()) {
            for (k, _v) in svc {
                status.services.insert(k.clone(), 1);
            }
        }

        // OSD map summary
        if let Some(osdmap) = val.get("osdmap") {
            // Count OSDs from summary
            let _num_osds = osdmap.get("num_osds").and_then(|n| n.as_u64()).unwrap_or(0);
        }

        // PG summary
        if let Some(pgmap) = val.get("pgmap") {
            status.total_bytes = pgmap.get("bytes_total").and_then(|b| b.as_u64()).unwrap_or(0);
            status.used_bytes = pgmap.get("bytes_used").and_then(|b| b.as_u64()).unwrap_or(0);
            status.available_bytes = pgmap.get("bytes_avail").and_then(|b| b.as_u64()).unwrap_or(0);
            status.objects = pgmap.get("num_objects").and_then(|n| n.as_u64()).unwrap_or(0);

            if let Some(pgs_by_state) = pgmap.get("pgs_by_state").and_then(|p| p.as_array()) {
                let parts: Vec<String> = pgs_by_state.iter().filter_map(|entry| {
                    let name = entry.get("state_name")?.as_str()?;
                    let count = entry.get("count")?.as_u64()?;
                    Some(format!("{} {}", count, name))
                }).collect();
                status.pg_summary = parts.join(", ");
            }
        }
    }

    // Get ceph version
    if let Ok(ver) = ceph_text(&["version"]) {
        status.ceph_version = ver;
    }

    // Get OSD details
    if let Ok(val) = ceph_json(&["osd", "tree"]) {
        if let Some(nodes) = val.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                let type_name = node.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if type_name != "osd" { continue; }
                let id = node.get("id").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
                let name = node.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let status_val = node.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
                let crush_weight = node.get("crush_weight").and_then(|w| w.as_f64()).unwrap_or(0.0);
                let reweight = node.get("reweight").and_then(|w| w.as_f64()).unwrap_or(0.0);
                let device_class = node.get("device_class").and_then(|d| d.as_str()).unwrap_or("");

                // Find the host this OSD belongs to
                let host = nodes.iter().find(|h| {
                    h.get("type").and_then(|t| t.as_str()) == Some("host") &&
                    h.get("children").and_then(|c| c.as_array())
                        .map(|arr| arr.iter().any(|ch| ch.as_u64() == Some(id as u64)))
                        .unwrap_or(false)
                }).and_then(|h| h.get("name").and_then(|n| n.as_str())).unwrap_or("").to_string();

                status.osds.push(CephOsd {
                    id,
                    host,
                    device_class: device_class.to_string(),
                    status: status_val.to_string(),
                    up: status_val == "up",
                    in_cluster: reweight > 0.0,
                    weight: crush_weight,
                    reweight,
                    pgs: 0,
                    size_bytes: 0,
                    used_bytes: 0,
                    available_bytes: 0,
                });
                let _ = name; // used for debug only
            }
        }
    }

    // Get OSD usage (df)
    if let Ok(val) = ceph_json(&["osd", "df"]) {
        if let Some(nodes) = val.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                let id = node.get("id").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
                if let Some(osd) = status.osds.iter_mut().find(|o| o.id == id) {
                    osd.size_bytes = node.get("kb").and_then(|k| k.as_u64()).unwrap_or(0) * 1024;
                    osd.used_bytes = node.get("kb_used").and_then(|k| k.as_u64()).unwrap_or(0) * 1024;
                    osd.available_bytes = node.get("kb_avail").and_then(|k| k.as_u64()).unwrap_or(0) * 1024;
                    osd.pgs = node.get("pgs").and_then(|p| p.as_u64()).unwrap_or(0) as u32;
                }
            }
        }
    }

    // Get pools
    if let Ok(val) = ceph_json(&["osd", "pool", "ls", "detail"]) {
        if let Some(pools) = val.as_array() {
            for p in pools {
                let pool_name = p.get("pool_name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let pool_id = p.get("pool").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
                let size = p.get("size").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
                let min_size = p.get("min_size").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
                let pg_num = p.get("pg_num").and_then(|n| n.as_u64()).unwrap_or(0) as u32;
                let pgp_num = p.get("pg_placement_num").and_then(|n| n.as_u64()).unwrap_or(0) as u32;
                let pool_type_num = p.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
                let pool_type = if pool_type_num == 1 { "replicated" } else { "erasure" };
                let crush_rule_id = p.get("crush_rule").and_then(|r| r.as_u64()).unwrap_or(0);
                let app = p.get("application_metadata").and_then(|a| a.as_object())
                    .map(|obj| obj.keys().cloned().collect::<Vec<_>>().join(", "))
                    .unwrap_or_default();

                status.pools.push(CephPool {
                    name: pool_name,
                    id: pool_id,
                    pool_type: pool_type.to_string(),
                    size,
                    min_size,
                    pg_num,
                    pgp_num,
                    crush_rule: format!("{}", crush_rule_id),
                    stored_bytes: 0,
                    used_bytes: 0,
                    objects: 0,
                    percent_used: 0.0,
                    max_avail: 0,
                    application: app,
                });
            }
        }
    }

    // Get pool usage stats
    if let Ok(val) = ceph_json(&["df", "detail"]) {
        if let Some(pools) = val.get("pools").and_then(|p| p.as_array()) {
            for p in pools {
                let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if let Some(pool) = status.pools.iter_mut().find(|pl| pl.name == name) {
                    if let Some(stats) = p.get("stats") {
                        pool.stored_bytes = stats.get("stored").and_then(|b| b.as_u64()).unwrap_or(0);
                        pool.used_bytes = stats.get("bytes_used").and_then(|b| b.as_u64()).unwrap_or(0);
                        pool.objects = stats.get("objects").and_then(|n| n.as_u64()).unwrap_or(0);
                        pool.percent_used = stats.get("percent_used").and_then(|p| p.as_f64()).unwrap_or(0.0);
                        pool.max_avail = stats.get("max_avail").and_then(|m| m.as_u64()).unwrap_or(0);
                    }
                }
            }
        }
    }

    // Get CRUSH rules
    if let Ok(val) = ceph_json(&["osd", "crush", "rule", "dump"]) {
        if let Some(rules) = val.as_array() {
            for rule in rules {
                let id = rule.get("rule_id").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
                let name = rule.get("rule_name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let rule_type = rule.get("type").and_then(|t| t.as_u64()).map(|t| {
                    if t == 1 { "replicated" } else { "erasure" }
                }).unwrap_or("unknown").to_string();
                status.crush_rules.push(CrushRule { id, name, rule_type });
            }
            // Update pool crush_rule names
            let rules_clone: Vec<CrushRule> = status.crush_rules.clone();
            for pool in &mut status.pools {
                if let Ok(rid) = pool.crush_rule.parse::<u32>() {
                    if let Some(rule) = rules_clone.iter().find(|r| r.id == rid) {
                        pool.crush_rule = rule.name.clone();
                    }
                }
            }
        }
    }

    // Get CephFS
    if let Ok(val) = ceph_json(&["fs", "ls"]) {
        if let Some(filesystems) = val.as_array() {
            for fs in filesystems {
                let name = fs.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let metadata_pool = fs.get("metadata_pool").and_then(|p| p.as_str()).unwrap_or("").to_string();
                let data_pools = fs.get("data_pools").and_then(|p| p.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                status.filesystems.push(CephFilesystem {
                    name,
                    metadata_pool,
                    data_pools,
                    active_mds: 0,
                    standby_mds: 0,
                });
            }
        }
    }

    status
}

// ─── Pool Management ───

/// Create a new pool
pub fn create_pool(name: &str, pg_num: u32, pool_type: &str, size: Option<u32>, rule: Option<&str>, application: Option<&str>) -> Result<String, String> {
    if name.is_empty() { return Err("Pool name is required".into()); }
    let pg = if pg_num == 0 { 32 } else { pg_num };

    let mut args = vec!["osd", "pool", "create", name, &pg.to_string()];
    let pg_str = pg.to_string();
    args = vec!["osd", "pool", "create", name, &pg_str];

    if pool_type == "erasure" {
        args.push("erasure");
    }

    ceph_text(&args)?;

    // Set replication size
    if let Some(s) = size {
        if pool_type != "erasure" {
            let size_str = s.to_string();
            let _ = ceph_text(&["osd", "pool", "set", name, "size", &size_str]);
        }
    }

    // Set CRUSH rule
    if let Some(r) = rule {
        if !r.is_empty() {
            let _ = ceph_text(&["osd", "pool", "set", name, "crush_rule", r]);
        }
    }

    // Enable application
    if let Some(app) = application {
        if !app.is_empty() {
            let _ = ceph_text(&["osd", "pool", "application", "enable", name, app, "--yes-i-really-mean-it"]);
        }
    }

    info!("Created Ceph pool: {}", name);
    Ok(format!("Pool '{}' created successfully", name))
}

/// Delete a pool
pub fn delete_pool(name: &str) -> Result<String, String> {
    if name.is_empty() { return Err("Pool name is required".into()); }
    // Ceph requires the pool name twice and the --yes-i-really-really-mean-it flag
    ceph_text(&["osd", "pool", "delete", name, name, "--yes-i-really-really-mean-it"])?;
    info!("Deleted Ceph pool: {}", name);
    Ok(format!("Pool '{}' deleted", name))
}

/// Set a pool option
pub fn set_pool_option(pool: &str, key: &str, value: &str) -> Result<String, String> {
    ceph_text(&["osd", "pool", "set", pool, key, value])
}

// ─── OSD Management ───

/// Get available devices for OSD creation
pub fn get_available_devices() -> Result<serde_json::Value, String> {
    // Use ceph-volume to inventory available devices
    let output = Command::new("ceph-volume")
        .args(["inventory", "--format", "json"])
        .output()
        .map_err(|e| format!("Failed to run ceph-volume: {}", e))?;
    if !output.status.success() {
        // ceph-volume might not be installed, fall back to lsblk
        return get_available_devices_lsblk();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("JSON parse error: {}", e))
}

fn get_available_devices_lsblk() -> Result<serde_json::Value, String> {
    let output = Command::new("lsblk")
        .args(["-J", "-b", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL,SERIAL"])
        .output()
        .map_err(|e| format!("lsblk failed: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("JSON parse error: {}", e))
}

/// Add an OSD using ceph-volume
pub fn add_osd(device: &str) -> Result<String, String> {
    if device.is_empty() { return Err("Device path is required".into()); }
    // Basic sanity check
    if !device.starts_with("/dev/") { return Err("Device must start with /dev/".into()); }

    info!("Adding OSD on device: {}", device);
    let output = Command::new("ceph-volume")
        .args(["lvm", "create", "--data", device, "--bluestore"])
        .output()
        .map_err(|e| format!("ceph-volume failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to create OSD: {}", stderr.trim()));
    }
    Ok(format!("OSD created on {}", device))
}

/// Remove (purge) an OSD
pub fn remove_osd(osd_id: u32) -> Result<String, String> {
    info!("Removing OSD.{}", osd_id);
    let id_str = osd_id.to_string();

    // Mark out
    let _ = ceph_text(&["osd", "out", &id_str]);
    // Stop the daemon (best effort)
    let _ = Command::new("systemctl").args(["stop", &format!("ceph-osd@{}", osd_id)]).output();
    // Purge
    ceph_text(&["osd", "purge", &id_str, "--yes-i-really-mean-it"])?;

    Ok(format!("OSD.{} removed", osd_id))
}

/// Reweight an OSD
pub fn reweight_osd(osd_id: u32, weight: f64) -> Result<String, String> {
    let id_str = osd_id.to_string();
    let weight_str = format!("{:.4}", weight);
    ceph_text(&["osd", "reweight", &id_str, &weight_str])
}

/// Mark OSD in/out
pub fn set_osd_in(osd_id: u32, mark_in: bool) -> Result<String, String> {
    let id_str = osd_id.to_string();
    let action = if mark_in { "in" } else { "out" };
    ceph_text(&["osd", action, &id_str])
}

// ─── CephFS Management ───

/// Create a CephFS filesystem
pub fn create_filesystem(name: &str, metadata_pool: &str, data_pool: &str) -> Result<String, String> {
    if name.is_empty() || metadata_pool.is_empty() || data_pool.is_empty() {
        return Err("Name, metadata pool, and data pool are required".into());
    }
    ceph_text(&["fs", "new", name, metadata_pool, data_pool])
}

/// Remove a CephFS filesystem
pub fn remove_filesystem(name: &str) -> Result<String, String> {
    let _ = ceph_text(&["fs", "set", name, "cluster_down", "true"]);
    ceph_text(&["fs", "rm", name, "--yes-i-really-mean-it"])
}

// ─── RBD Management ───

/// List RBD images in a pool
pub fn list_rbd_images(pool: &str) -> Result<Vec<RbdImage>, String> {
    let output = Command::new("rbd")
        .args(["ls", "-l", "--format", "json", "--pool", pool])
        .output()
        .map_err(|e| format!("rbd ls failed: {}", e))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let items: Vec<serde_json::Value> = serde_json::from_str(stdout.trim()).unwrap_or_default();
    Ok(items.iter().map(|img| {
        RbdImage {
            pool: pool.to_string(),
            name: img.get("image").and_then(|n| n.as_str()).unwrap_or("").to_string(),
            size_bytes: img.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
            features: String::new(),
        }
    }).collect())
}

/// Create an RBD image
pub fn create_rbd_image(pool: &str, name: &str, size_mb: u64) -> Result<String, String> {
    if pool.is_empty() || name.is_empty() || size_mb == 0 {
        return Err("Pool, name, and size are required".into());
    }
    let size_str = format!("{}M", size_mb);
    run_cmd("rbd", &["create", "--pool", pool, "--image", name, "--size", &size_str])
}

/// Delete an RBD image
pub fn delete_rbd_image(pool: &str, name: &str) -> Result<String, String> {
    run_cmd("rbd", &["rm", "--pool", pool, "--image", name])
}

// ─── Bootstrap / Setup ───

/// Check if Ceph packages are available for install
pub fn get_install_status() -> serde_json::Value {
    let installed = is_ceph_installed();
    let ceph_mon = Command::new("which").arg("ceph-mon").output().map(|o| o.status.success()).unwrap_or(false);
    let ceph_osd = Command::new("which").arg("ceph-osd").output().map(|o| o.status.success()).unwrap_or(false);
    let ceph_mgr = Command::new("which").arg("ceph-mgr").output().map(|o| o.status.success()).unwrap_or(false);
    let ceph_mds = Command::new("which").arg("ceph-mds").output().map(|o| o.status.success()).unwrap_or(false);
    let ceph_volume = Command::new("which").arg("ceph-volume").output().map(|o| o.status.success()).unwrap_or(false);
    let radosgw = Command::new("which").arg("radosgw").output().map(|o| o.status.success()).unwrap_or(false);

    // Check if cluster is bootstrapped (ceph.conf exists)
    let bootstrapped = std::path::Path::new("/etc/ceph/ceph.conf").exists();

    serde_json::json!({
        "installed": installed,
        "bootstrapped": bootstrapped,
        "components": {
            "ceph_cli": installed,
            "ceph_mon": ceph_mon,
            "ceph_osd": ceph_osd,
            "ceph_mgr": ceph_mgr,
            "ceph_mds": ceph_mds,
            "ceph_volume": ceph_volume,
            "radosgw": radosgw,
        }
    })
}

/// Install Ceph packages using the system package manager
pub fn install_ceph() -> Result<String, String> {
    let distro = crate::installer::detect_distro();
    info!("Installing Ceph packages (distro: {:?})", distro);

    match distro {
        crate::installer::DistroFamily::Debian => {
            // apt-get install
            let output = Command::new("apt-get")
                .args(["install", "-y", "ceph", "ceph-common", "ceph-mon", "ceph-osd", "ceph-mgr", "ceph-mds", "ceph-volume", "ceph-fuse", "radosgw"])
                .output()
                .map_err(|e| format!("Failed to run apt-get: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("apt-get install failed: {}", stderr.trim()));
            }
            Ok("Ceph packages installed successfully via apt".to_string())
        }
        crate::installer::DistroFamily::RedHat => {
            // Enable EPEL if needed, then dnf install
            let _ = Command::new("dnf").args(["install", "-y", "epel-release"]).output();
            let output = Command::new("dnf")
                .args(["install", "-y", "ceph", "ceph-common", "ceph-mon", "ceph-osd", "ceph-mgr", "ceph-mds", "ceph-volume", "ceph-fuse", "ceph-radosgw"])
                .output()
                .map_err(|e| format!("Failed to run dnf: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("dnf install failed: {}", stderr.trim()));
            }
            Ok("Ceph packages installed successfully via dnf".to_string())
        }
        crate::installer::DistroFamily::Suse => {
            let output = Command::new("zypper")
                .args(["install", "-y", "ceph", "ceph-common", "ceph-mon", "ceph-osd", "ceph-mgr", "ceph-mds", "ceph-volume", "ceph-fuse", "ceph-radosgw"])
                .output()
                .map_err(|e| format!("Failed to run zypper: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("zypper install failed: {}", stderr.trim()));
            }
            Ok("Ceph packages installed successfully via zypper".to_string())
        }
        crate::installer::DistroFamily::Arch => {
            let output = Command::new("pacman")
                .args(["-S", "--noconfirm", "ceph"])
                .output()
                .map_err(|e| format!("Failed to run pacman: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("pacman install failed: {} — Ceph may need to be installed from AUR", stderr.trim()));
            }
            Ok("Ceph packages installed successfully via pacman".to_string())
        }
        crate::installer::DistroFamily::Alpine => {
            // Alpine ships ceph in the community repo, but the package
            // set is narrower than Debian/RedHat and split (no
            // ceph-volume helper, radosgw is `ceph-radosgw`). For now
            // we refuse the auto-install rather than ship half a stack;
            // operator can install manually with apk add ceph ceph-common
            // ceph-mon ceph-osd ceph-mgr ceph-mds ceph-fuse ceph-radosgw.
            Err("Alpine Ceph auto-install is not supported — install manually: \
                 apk add ceph ceph-common ceph-mon ceph-osd ceph-mgr ceph-mds ceph-fuse ceph-radosgw. \
                 (Some helper tools are missing on Alpine; full feature set is not guaranteed.)".to_string())
        }
        crate::installer::DistroFamily::Unknown => {
            Err("Unsupported distro — cannot auto-install. Please install Ceph packages manually.".to_string())
        }
    }
}

/// Bootstrap a new Ceph cluster (mon + mgr on this node)
pub fn bootstrap_cluster(cluster_name: &str, public_network: &str, mon_ip: &str) -> Result<String, String> {
    if public_network.is_empty() || mon_ip.is_empty() {
        return Err("Public network (CIDR) and monitor IP are required".into());
    }

    let cluster = if cluster_name.is_empty() { "ceph" } else { cluster_name };
    let hostname = hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "localhost".to_string());

    info!("Bootstrapping Ceph cluster '{}' on {}", cluster, hostname);

    // Generate a UUID for the cluster
    let fsid = uuid::Uuid::new_v4().to_string();

    // Write ceph.conf
    let ceph_conf = format!(
        "[global]\nfsid = {}\nmon initial members = {}\nmon host = {}\npublic network = {}\ncluster network = {}\nauth cluster required = cephx\nauth service required = cephx\nauth client required = cephx\nosd journal size = 1024\nosd pool default size = 3\nosd pool default min size = 2\nosd pool default pg num = 32\nosd pool default pgp num = 32\nosd crush chooseleaf type = 1\n",
        fsid, hostname, mon_ip, public_network, public_network
    );

    std::fs::create_dir_all("/etc/ceph").map_err(|e| format!("mkdir /etc/ceph: {}", e))?;
    std::fs::write("/etc/ceph/ceph.conf", &ceph_conf).map_err(|e| format!("write ceph.conf: {}", e))?;

    // Create monitor keyring
    run_cmd("ceph-authtool", &["--create-keyring", "/tmp/ceph.mon.keyring", "--gen-key", "-n", "mon.", "--cap", "mon", "allow *"])?;
    run_cmd("ceph-authtool", &["--create-keyring", "/etc/ceph/ceph.client.admin.keyring", "--gen-key", "-n", "client.admin", "--cap", "mon", "allow *", "--cap", "osd", "allow *", "--cap", "mds", "allow *", "--cap", "mgr", "allow *"])?;
    run_cmd("ceph-authtool", &["--create-keyring", "/var/lib/ceph/bootstrap-osd/ceph.keyring", "--gen-key", "-n", "client.bootstrap-osd", "--cap", "mon", "profile bootstrap-osd", "--cap", "mgr", "allow r"])?;
    run_cmd("ceph-authtool", &["/tmp/ceph.mon.keyring", "--import-keyring", "/etc/ceph/ceph.client.admin.keyring"])?;
    run_cmd("ceph-authtool", &["/tmp/ceph.mon.keyring", "--import-keyring", "/var/lib/ceph/bootstrap-osd/ceph.keyring"])?;

    // Create monmap
    run_cmd("monmaptool", &["--create", "--add", &hostname, &format!("{}:6789", mon_ip), "--fsid", &fsid, "/tmp/monmap"])?;

    // Create monitor directory and populate
    let mon_dir = format!("/var/lib/ceph/mon/ceph-{}", hostname);
    std::fs::create_dir_all(&mon_dir).map_err(|e| format!("mkdir mon: {}", e))?;

    run_cmd("ceph-mon", &["--mkfs", "-i", &hostname, "--monmap", "/tmp/monmap", "--keyring", "/tmp/ceph.mon.keyring"])?;

    // Ensure correct ownership
    let _ = Command::new("chown").args(["-R", "ceph:ceph", "/var/lib/ceph/", "/etc/ceph/"]).output();

    // Start and enable the monitor
    let mon_svc = format!("ceph-mon@{}", hostname);
    run_cmd("systemctl", &["enable", "--now", &mon_svc])?;

    // Wait a moment for the monitor to come up, then enable msgr2
    std::thread::sleep(std::time::Duration::from_secs(3));
    let _ = ceph_text(&["mon", "enable-msgr2"]);

    // Create and start the manager
    let mgr_dir = format!("/var/lib/ceph/mgr/ceph-{}", hostname);
    std::fs::create_dir_all(&mgr_dir).map_err(|e| format!("mkdir mgr: {}", e))?;

    let _ = ceph_text(&["auth", "get-or-create", &format!("mgr.{}", hostname), "mon", "allow profile mgr", "osd", "allow *", "mds", "allow *"]);

    // Write mgr keyring
    if let Ok(key_output) = ceph_text(&["auth", "get", &format!("mgr.{}", hostname)]) {
        let mgr_keyring = format!("{}/keyring", mgr_dir);
        let _ = std::fs::write(&mgr_keyring, key_output);
        let _ = Command::new("chown").args(["ceph:ceph", &mgr_keyring]).output();
    }

    let mgr_svc = format!("ceph-mgr@{}", hostname);
    run_cmd("systemctl", &["enable", "--now", &mgr_svc])?;

    // Save config
    let config = CephConfig {
        configured: true,
        cluster_name: cluster.to_string(),
        mon_initial_members: vec![hostname.clone()],
        public_network: public_network.to_string(),
        cluster_network: public_network.to_string(),
    };
    let _ = save_config(&config);

    // Cleanup temp files
    let _ = std::fs::remove_file("/tmp/ceph.mon.keyring");
    let _ = std::fs::remove_file("/tmp/monmap");

    Ok(format!("Ceph cluster '{}' bootstrapped with mon+mgr on {}", cluster, hostname))
}

// ─── Join an existing cluster ───

const CEPH_CONF_PATH: &str = "/etc/ceph/ceph.conf";
const CEPH_ADMIN_KEYRING_PATH: &str = "/etc/ceph/ceph.client.admin.keyring";
const CEPH_BOOTSTRAP_OSD_KEYRING_PATH: &str = "/var/lib/ceph/bootstrap-osd/ceph.keyring";

/// The files a node needs to JOIN an existing cluster and contribute OSDs: the
/// cluster config and the admin + bootstrap-osd keyrings. A bootstrapped node
/// exports this; the joining node writes it verbatim, after which the existing
/// "Add OSD" flow works against the same cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CephJoinBundle {
    pub ceph_conf: String,
    pub admin_keyring: String,
    pub bootstrap_osd_keyring: String,
    pub cluster_name: String,
}

/// Read the join bundle from THIS node. Errors unless the node is actually
/// bootstrapped (has the config + both keyrings), so a non-cluster node can't
/// hand out an empty/garbage bundle.
pub fn export_join_bundle() -> Result<CephJoinBundle, String> {
    if !std::path::Path::new(CEPH_CONF_PATH).exists() {
        return Err("This node is not part of a Ceph cluster (no /etc/ceph/ceph.conf) — bootstrap or join one first".into());
    }
    let ceph_conf = std::fs::read_to_string(CEPH_CONF_PATH)
        .map_err(|e| format!("read ceph.conf: {}", e))?;
    let admin_keyring = std::fs::read_to_string(CEPH_ADMIN_KEYRING_PATH)
        .map_err(|e| format!("read admin keyring: {}", e))?;
    let bootstrap_osd_keyring = std::fs::read_to_string(CEPH_BOOTSTRAP_OSD_KEYRING_PATH)
        .map_err(|e| format!("read bootstrap-osd keyring (is this the bootstrap node?): {}", e))?;
    Ok(CephJoinBundle {
        ceph_conf,
        admin_keyring,
        bootstrap_osd_keyring,
        cluster_name: load_config().cluster_name,
    })
}

/// Pull a single `key = value` line out of a ceph.conf body.
fn parse_conf_value(conf: &str, key: &str) -> Option<String> {
    conf.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        if k.trim() == key { Some(v.trim().to_string()) } else { None }
    })
}

/// Join an existing cluster by installing the bundle's config + keyrings, after
/// which this node can add OSDs (the existing flow) and `ceph -s` resolves
/// against the cluster's mon(s) via the config. Does NOT add a monitor — the
/// node joins as an OSD-contributing member (mon HA is a separate step). Refuses
/// to clobber an existing local config so a mistaken join can't break a node
/// that's already in a cluster.
pub fn join_cluster(bundle: &CephJoinBundle) -> Result<String, String> {
    if std::path::Path::new(CEPH_CONF_PATH).exists() {
        return Err("This node already has /etc/ceph/ceph.conf — it's already in a cluster. Remove it first if you really mean to re-join a different one".into());
    }
    // Sanity-check the bundle before we write anything: a real bundle has the
    // cluster fsid and a client.admin secret.
    if !bundle.ceph_conf.contains("fsid") {
        return Err("Join bundle has no cluster fsid — the source node may not be bootstrapped".into());
    }
    if !bundle.admin_keyring.contains("client.admin") {
        return Err("Join bundle is missing the client.admin keyring".into());
    }

    std::fs::create_dir_all("/etc/ceph").map_err(|e| format!("mkdir /etc/ceph: {}", e))?;
    std::fs::create_dir_all("/var/lib/ceph/bootstrap-osd")
        .map_err(|e| format!("mkdir bootstrap-osd: {}", e))?;
    std::fs::write(CEPH_CONF_PATH, &bundle.ceph_conf)
        .map_err(|e| format!("write ceph.conf: {}", e))?;
    std::fs::write(CEPH_ADMIN_KEYRING_PATH, &bundle.admin_keyring)
        .map_err(|e| format!("write admin keyring: {}", e))?;
    std::fs::write(CEPH_BOOTSTRAP_OSD_KEYRING_PATH, &bundle.bootstrap_osd_keyring)
        .map_err(|e| format!("write bootstrap-osd keyring: {}", e))?;
    // Keyrings are cluster secrets — lock them to root-only before ceph adopts
    // them, then hand the tree to the ceph user (mirrors bootstrap_cluster).
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(CEPH_ADMIN_KEYRING_PATH, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(CEPH_BOOTSTRAP_OSD_KEYRING_PATH, std::fs::Permissions::from_mode(0o600));
    let _ = Command::new("chown").args(["-R", "ceph:ceph", "/var/lib/ceph/", "/etc/ceph/"]).output();

    // Persist membership so the UI shows the cluster view (status reads the
    // cluster's mon via the config + admin keyring we just installed).
    let cfg = CephConfig {
        configured: true,
        cluster_name: if bundle.cluster_name.is_empty() { "ceph".into() } else { bundle.cluster_name.clone() },
        mon_initial_members: Vec::new(),
        public_network: parse_conf_value(&bundle.ceph_conf, "public network").unwrap_or_default(),
        cluster_network: parse_conf_value(&bundle.ceph_conf, "cluster network").unwrap_or_default(),
    };
    let _ = save_config(&cfg);

    Ok("Joined the Ceph cluster — config + keyrings installed. Add OSDs on this node to contribute storage to the cluster.".to_string())
}

#[cfg(test)]
mod join_tests {
    use super::*;

    #[test]
    fn parse_conf_value_extracts_keys() {
        let conf = "[global]\nfsid = abc-123\npublic network = 10.0.0.0/24\nmon host = 10.0.0.1\n";
        assert_eq!(parse_conf_value(conf, "fsid").as_deref(), Some("abc-123"));
        assert_eq!(parse_conf_value(conf, "public network").as_deref(), Some("10.0.0.0/24"));
        assert_eq!(parse_conf_value(conf, "cluster network"), None);
    }
}
