// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Xen Orchestra 6 / XCP-ng integration.
//!
//! Mirrors `proxmox/mod.rs` in shape — WolfStack acts as the
//! management layer above an XO instance, the XO instance drives
//! one or more XCP-ng pools, and the XCP-ng pools host the actual
//! VMs. Two important differences vs Proxmox:
//!
//!   * XCP-ng is a Type-1 hypervisor — there's no host-level LXC.
//!     Anything LXC-shaped lives inside a guest VM. So the
//!     "WolfStack workloads" on an XO-managed pool live one VM
//!     deeper than they do on a PVE box.
//!   * XO's REST API talks token-auth (`Authorization: Bearer
//!     <token>`); tokens are minted in the XO UI under
//!     Settings → Tokens. We never see the user's password.
//!
//! Endpoint reference: <https://docs.xen-orchestra.com/restapi>

#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::time::Duration;

static XO_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            // XO defaults to a self-signed cert behind nginx.
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

// ─── Connection record persisted on disk ──────────────────────────

const POOLS_FILE_DEFAULT: &str = "/etc/wolfstack/xo_pools.json";

/// One XO instance the operator has registered. Multiple pools
/// belonging to the same XO instance are exposed through a single
/// row — XO already aggregates pools internally, so we don't
/// register them separately on our side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XoPool {
    pub id: String,
    pub name: String,
    /// Base URL e.g. `https://xo.example.com` (no trailing slash).
    pub url: String,
    /// Bearer token from Settings → Tokens. Stored obfuscated to
    /// stay consistent with the rest of WolfStack — see
    /// `obfuscate_token` / `deobfuscate_token` below.
    pub token_enc: String,
    /// Last time we polled successfully (RFC3339).
    #[serde(default)]
    pub last_seen: String,
    /// Last status string from a probe. `"ok"`, `"unreachable"`,
    /// `"auth_failed"`. Empty until the first probe runs.
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub pool_count: u32,
    #[serde(default)]
    pub host_count: u32,
    #[serde(default)]
    pub vm_count: u32,
}

/// Trivial XOR-with-prefix obfuscation. Same scheme as the rest
/// of WolfStack's at-rest secrets — keeps the file from being
/// trivially `cat`-able while not pretending to be encryption.
/// The actual access control is filesystem permissions on
/// `/etc/wolfstack/`.
pub fn obfuscate_token(plain: &str) -> String {
    use base64::Engine;
    let key = b"wolfstack-xo-v1";
    let bytes: Vec<u8> = plain.bytes().enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn deobfuscate_token(encoded: &str) -> String {
    use base64::Engine;
    let key = b"wolfstack-xo-v1";
    let raw = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    raw.into_iter().enumerate()
        .map(|(i, b)| (b ^ key[i % key.len()]) as char)
        .collect()
}

// ─── Live data types ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XoPoolInfo {
    pub uuid: String,
    pub name: String,
    pub master_uuid: String,
    pub host_count: u32,
    pub default_sr: String,
    pub ha_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XoHost {
    pub uuid: String,
    pub name: String,
    pub pool_uuid: String,
    /// `running` / `halted` / `unknown`.
    pub power_state: String,
    pub address: String,
    pub cpus: u32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub version: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XoVm {
    pub uuid: String,
    pub name: String,
    pub host_uuid: String,
    pub pool_uuid: String,
    /// `Running` / `Halted` / `Suspended` / `Paused`.
    pub power_state: String,
    pub cpus: u32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub ip_addresses: Vec<String>,
    pub os_version: String,
    pub tags: Vec<String>,
    pub started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XoTemplate {
    pub uuid: String,
    pub name: String,
    pub pool_uuid: String,
    pub os: String,
    pub memory: u64,
    pub disks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XoInventory {
    pub pools: Vec<XoPoolInfo>,
    pub hosts: Vec<XoHost>,
    pub vms: Vec<XoVm>,
}

// ─── Client ───────────────────────────────────────────────────────

pub struct XoClient {
    base_url: String,
    token: String,
}

impl XoClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = XO_CLIENT.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send().await
            .map_err(|e| format!("XO request failed: {}", e))?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err("XO rejected the token (401). Mint a new token in Settings → Tokens.".into());
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("XO HTTP {}: {}", status,
                body.chars().take(300).collect::<String>()));
        }
        let body = resp.text().await.map_err(|e| format!("XO read failed: {}", e))?;
        serde_json::from_str(&body).map_err(|e| {
            format!("XO response not JSON ({}). Body: {}", e,
                body.chars().take(200).collect::<String>())
        })
    }

    /// Cheap probe: hit `/rest/v0/` which returns a banner with
    /// links. Used by the Test Connection button so the operator
    /// gets fast feedback before storing the token.
    pub async fn test_connection(&self) -> Result<(), String> {
        let _ = self.get("/rest/v0").await?;
        Ok(())
    }

    pub async fn list_pools(&self) -> Result<Vec<XoPoolInfo>, String> {
        // XO returns either a flat array of objects or — when
        // `?fields=` is omitted — an array of href strings. We ask
        // for the full set of fields we need so the response is
        // always object-shaped.
        let data = self.get("/rest/v0/pools?fields=uuid,name_label,master,default_SR,HA_enabled").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(arr.len());
        for v in &arr {
            out.push(XoPoolInfo {
                uuid: v.get("uuid").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                name: v.get("name_label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                master_uuid: v.get("master").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                host_count: 0, // filled in by caller after list_hosts
                default_sr: v.get("default_SR").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                ha_enabled: v.get("HA_enabled").and_then(|x| x.as_bool()).unwrap_or(false),
            });
        }
        Ok(out)
    }

    pub async fn list_hosts(&self) -> Result<Vec<XoHost>, String> {
        let data = self.get("/rest/v0/hosts?fields=uuid,name_label,$pool,power_state,address,cpu_info,memory,version,startTime").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut out = Vec::with_capacity(arr.len());
        for v in &arr {
            // CPU count: XO returns `cpu_info: { cpu_count: N, ... }`
            let cpus = v.get("cpu_info")
                .and_then(|c| c.get("cpu_count"))
                .and_then(|n| n.as_u64()).unwrap_or(0) as u32;
            // Memory: `memory: { size, usage }` (bytes)
            let mem = v.get("memory");
            let memory_total = mem.and_then(|m| m.get("size")).and_then(|n| n.as_u64()).unwrap_or(0);
            let memory_used = mem.and_then(|m| m.get("usage")).and_then(|n| n.as_u64()).unwrap_or(0);
            let started = v.get("startTime").and_then(|n| n.as_u64()).unwrap_or(0);
            // Version: nested `version: { product_version: "8.x", ... }`
            let version = v.get("version")
                .and_then(|x| x.get("product_version"))
                .and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(XoHost {
                uuid: v.get("uuid").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                name: v.get("name_label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                pool_uuid: v.get("$pool").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                power_state: v.get("power_state").and_then(|x| x.as_str()).unwrap_or("unknown").to_string(),
                address: v.get("address").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                cpus,
                memory_used,
                memory_total,
                version,
                uptime_seconds: if started > 0 && now > started { now - started } else { 0 },
            });
        }
        Ok(out)
    }

    pub async fn list_vms(&self) -> Result<Vec<XoVm>, String> {
        let data = self.get("/rest/v0/vms?fields=uuid,name_label,$container,$pool,power_state,CPUs,memory,addresses,os_version,tags,startTime").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(arr.len());
        for v in &arr {
            let mem = v.get("memory");
            let memory_total = mem.and_then(|m| m.get("size")).and_then(|n| n.as_u64())
                .or_else(|| mem.and_then(|m| m.get("dynamic")).and_then(|d| d.get(1)).and_then(|n| n.as_u64()))
                .unwrap_or(0);
            let memory_used = mem.and_then(|m| m.get("usage")).and_then(|n| n.as_u64()).unwrap_or(0);
            let cpus = v.get("CPUs")
                .and_then(|c| c.get("number").or_else(|| c.get("max")))
                .and_then(|n| n.as_u64()).unwrap_or(0) as u32;
            // `addresses` is an object { "0/ipv4/0": "10.0.0.5", ... };
            // flatten to a Vec.
            let mut ip_addresses: Vec<String> = Vec::new();
            if let Some(addrs) = v.get("addresses").and_then(|x| x.as_object()) {
                for (_k, val) in addrs {
                    if let Some(s) = val.as_str() { ip_addresses.push(s.to_string()); }
                }
            }
            let tags = v.get("tags").and_then(|x| x.as_array()).cloned().unwrap_or_default()
                .into_iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>();
            let os_version = v.get("os_version")
                .and_then(|x| x.get("name").or_else(|| x.get("uname")))
                .and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(XoVm {
                uuid: v.get("uuid").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                name: v.get("name_label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                host_uuid: v.get("$container").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                pool_uuid: v.get("$pool").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                power_state: v.get("power_state").and_then(|x| x.as_str()).unwrap_or("unknown").to_string(),
                cpus,
                memory_used,
                memory_total,
                ip_addresses,
                os_version,
                tags,
                started_at: v.get("startTime").and_then(|n| n.as_u64()).unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Drive a VM lifecycle action. P2 — wired but the frontend
    /// won't expose buttons until the read-only inventory page
    /// is shaken out.
    pub async fn vm_action(&self, vm_uuid: &str, action: &str) -> Result<(), String> {
        // XO accepts: start, clean_shutdown, hard_shutdown,
        // clean_reboot, hard_reboot, suspend, resume.
        let valid = ["start", "clean_shutdown", "hard_shutdown",
            "clean_reboot", "hard_reboot", "suspend", "resume"];
        if !valid.contains(&action) {
            return Err(format!("invalid VM action: {} (allowed: {:?})", action, valid));
        }
        let url = format!("{}/rest/v0/vms/{}/actions/{}", self.base_url, vm_uuid, action);
        let resp = XO_CLIENT.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send().await
            .map_err(|e| format!("XO request failed: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("XO HTTP {}: {}", status,
                body.chars().take(300).collect::<String>()));
        }
        Ok(())
    }

    pub async fn full_inventory(&self) -> Result<XoInventory, String> {
        // Fire the three calls in parallel — XO returns them
        // independently and they don't depend on each other.
        let (pools, hosts, vms) = tokio::join!(
            self.list_pools(),
            self.list_hosts(),
            self.list_vms(),
        );
        let mut pools = pools?;
        let hosts = hosts?;
        let vms = vms?;

        // Fill host_count on each pool.
        for p in &mut pools {
            p.host_count = hosts.iter().filter(|h| h.pool_uuid == p.uuid).count() as u32;
        }

        Ok(XoInventory { pools, hosts, vms })
    }
}

// ─── On-disk store ────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct XoStore {
    pools: Vec<XoPool>,
    path: String,
}

impl XoStore {
    pub fn load() -> Self {
        let path = crate::paths::get().xo_pools_config.clone();
        let pools = match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Self { pools, path }
    }

    fn save(&self) -> Result<(), String> {
        let s = serde_json::to_string_pretty(&self.pools)
            .map_err(|e| format!("serialize: {}", e))?;
        let parent = std::path::Path::new(&self.path).parent()
            .unwrap_or_else(|| std::path::Path::new("/etc/wolfstack"));
        let _ = std::fs::create_dir_all(parent);
        let tmp = format!("{}.tmp", self.path);
        std::fs::write(&tmp, &s).map_err(|e| format!("write: {}", e))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("rename: {}", e))?;
        Ok(())
    }

    pub fn list(&self) -> Vec<XoPool> { self.pools.clone() }

    pub fn get(&self, id: &str) -> Option<XoPool> {
        self.pools.iter().find(|p| p.id == id).cloned()
    }

    pub fn add(&mut self, mut pool: XoPool) -> Result<(), String> {
        if pool.id.is_empty() {
            pool.id = uuid::Uuid::new_v4().to_string();
        }
        if pool.name.trim().is_empty() {
            return Err("pool name is required".into());
        }
        if pool.url.trim().is_empty() {
            return Err("XO URL is required".into());
        }
        if self.pools.iter().any(|p| p.id == pool.id) {
            return Err(format!("pool with id {} already exists", pool.id));
        }
        self.pools.push(pool);
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        let before = self.pools.len();
        self.pools.retain(|p| p.id != id);
        if self.pools.len() == before {
            return Err(format!("pool {} not found", id));
        }
        self.save()
    }

    pub fn update_status(&mut self, id: &str, status: &str, pool_count: u32, host_count: u32, vm_count: u32) {
        if let Some(p) = self.pools.iter_mut().find(|p| p.id == id) {
            p.status = status.to_string();
            p.pool_count = pool_count;
            p.host_count = host_count;
            p.vm_count = vm_count;
            p.last_seen = chrono::Utc::now().to_rfc3339();
            let _ = self.save();
        }
    }
}

#[allow(dead_code)]
pub const POOLS_FILE: &str = POOLS_FILE_DEFAULT;
