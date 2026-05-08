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
//
// The actual on-disk path is resolved via
// `crate::paths::get().xo_pools_config` (default
// `/etc/wolfstack/xo_pools.json`, overridable via paths.json) —
// no hard-coded constant here, since `XoStore::load` reads the
// path through the paths module like every other config file.

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

    /// Delete a VM (record + disks). XO REST: DELETE /rest/v0/vms/{uuid}.
    /// VM must be halted first — caller should hard_shutdown then
    /// poll until power_state=Halted, then call this. We do the
    /// stop+poll+delete sequence inside `pools::xo_driver::destroy`.
    pub async fn delete_vm(&self, vm_uuid: &str) -> Result<(), String> {
        let url = format!("{}/rest/v0/vms/{}", self.base_url, vm_uuid);
        let resp = XO_CLIENT.delete(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send().await
            .map_err(|e| format!("XO delete request failed: {}", e))?;
        let status = resp.status();
        // 404 means already gone — treat as success (idempotent).
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("XO HTTP {} on delete_vm: {}", status,
                body.chars().take(300).collect::<String>()));
        }
        let _ = resp.bytes().await;
        Ok(())
    }

    /// List VM templates available for cloning. P3 uses this to
    /// populate the "Provision new VM" form. Returns lightweight
    /// rows; full details come from `/rest/v0/vm-templates/{uuid}`
    /// when the operator clicks one.
    pub async fn list_templates(&self) -> Result<Vec<XoTemplate>, String> {
        let data = self.get("/rest/v0/vm-templates?fields=uuid,name_label,$pool,os_version,memory,VBDs").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(arr.len());
        for v in &arr {
            let mem = v.get("memory")
                .and_then(|m| m.get("size").or_else(|| m.get("static").and_then(|s| s.get(1))))
                .and_then(|n| n.as_u64()).unwrap_or(0);
            let os = v.get("os_version")
                .and_then(|x| x.get("name").or_else(|| x.get("uname")))
                .and_then(|x| x.as_str()).unwrap_or("").to_string();
            let disks = v.get("VBDs").and_then(|b| b.as_array()).map(|a| a.len() as u32).unwrap_or(0);
            out.push(XoTemplate {
                uuid: v.get("uuid").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                name: v.get("name_label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                pool_uuid: v.get("$pool").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                os,
                memory: mem,
                disks,
            });
        }
        Ok(out)
    }

    /// Create a VM from a template, optionally with a cloud-init
    /// `user_data` payload. XO's "create from template" REST call
    /// is `POST /rest/v0/vms` with a body of clone params.
    /// Returns the new VM's UUID.
    pub async fn create_vm(&self, r: CreateVmRequest) -> Result<String, String> {
        if r.template_uuid.is_empty() || r.name.is_empty() {
            return Err("template_uuid and name are required".into());
        }
        let mut body = serde_json::json!({
            "template": r.template_uuid,
            "name_label": r.name,
        });
        if r.memory_mb > 0 {
            // XO accepts memory in bytes.
            body["memoryMax"] = serde_json::json!(r.memory_mb as u64 * 1024 * 1024);
        }
        if r.cpus > 0 {
            body["CPUs"] = serde_json::json!(r.cpus);
        }
        if !r.user_data.is_empty() {
            // XO accepts cloud-config under `cloudConfig`. The VM
            // template needs the cloud-init guest tools installed
            // for this to take effect on first boot. The Vates
            // and the upstream XO templates include them.
            body["cloudConfig"] = serde_json::json!(r.user_data);
        }

        let url = format!("{}/rest/v0/vms", self.base_url);
        let resp = XO_CLIENT.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send().await
            .map_err(|e| format!("XO create_vm request failed: {}", e))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("XO HTTP {} on create_vm: {}", status,
                body.chars().take(400).collect::<String>()));
        }
        // XO returns the new UUID in one of three shapes
        // depending on version: a bare JSON string, an object
        // with a `uuid` (or `id`) field, or — for async creates —
        // a task URL like `/rest/v0/tasks/<task-id>`. We must
        // distinguish "this is a UUID" from "this is a task path"
        // because returning the task path to the operator would
        // mislead them into thinking they have a VM when they
        // really have a still-running create job.
        fn looks_like_uuid(s: &str) -> bool {
            // 36 chars, hyphens at 8, 13, 18, 23, rest hex.
            let s = s.trim();
            let bytes = s.as_bytes();
            if bytes.len() != 36 { return false; }
            for (i, &b) in bytes.iter().enumerate() {
                let want_hyphen = matches!(i, 8 | 13 | 18 | 23);
                let is_hex = b.is_ascii_hexdigit();
                if want_hyphen && b != b'-' { return false; }
                if !want_hyphen && !is_hex { return false; }
            }
            true
        }
        let body_text = resp.text().await.map_err(|e| format!("XO read: {}", e))?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body_text) {
            if let Some(s) = v.as_str() {
                let candidate = s.trim().trim_matches('"');
                if looks_like_uuid(candidate) {
                    return Ok(candidate.to_string());
                }
                // Could be a task URL — surface that instead of
                // pretending it's the VM we asked for.
                if candidate.contains("/tasks/") {
                    return Err(format!(
                        "XO accepted the create as an async task ({}). \
                         WolfStack doesn't track XO tasks yet — provision \
                         from XO directly and refresh inventory.",
                        candidate
                    ));
                }
                return Err(format!("XO returned an unexpected create_vm body: {}", candidate));
            }
            if let Some(s) = v.get("uuid").and_then(|x| x.as_str()) {
                if looks_like_uuid(s) { return Ok(s.to_string()); }
            }
            if let Some(s) = v.get("id").and_then(|x| x.as_str()) {
                if looks_like_uuid(s) { return Ok(s.to_string()); }
            }
            return Err(format!(
                "XO returned a JSON body without a UUID-shaped uuid/id field: {}",
                body_text.chars().take(300).collect::<String>(),
            ));
        }
        // Fallback: a few XO builds return a raw UUID string
        // outside JSON. Validate before accepting.
        let trimmed = body_text.trim().trim_matches('"').to_string();
        if looks_like_uuid(&trimmed) {
            Ok(trimmed)
        } else if trimmed.is_empty() {
            Err("XO returned empty body on create_vm".into())
        } else {
            Err(format!("XO returned non-UUID body on create_vm: {}",
                trimmed.chars().take(200).collect::<String>()))
        }
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
        // Defence in depth: file holds obfuscated XO tokens.
        // /etc/wolfstack/ is already 700 from setup.sh, but we
        // chmod the file 600 too in case the parent has been
        // relaxed (custom paths, debugging). Best-effort —
        // failures here don't fail the save.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path,
                std::fs::Permissions::from_mode(0o600));
        }
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

#[derive(Debug, Clone)]
pub struct CreateVmRequest {
    pub template_uuid: String,
    pub name: String,
    pub memory_mb: u32,
    pub cpus: u32,
    pub user_data: String,
}

// ─── Cloud-init payload generator ─────────────────────────────────
//
// P3's headline feature: the Provision wizard ticks a box and the
// new VM auto-installs WolfStack on first boot, joins the customer
// cluster, registers with the SP's federation token, and comes up
// with WolfNet pre-configured for the inside-VM environment.
//
// Cloud-init runs as root on first boot, so this is privileged
// code that lands on the customer's VM. Keep it minimal and
// auditable — every line should be defensible.

pub mod cloud_init {
    /// Bootstrap parameters passed into the cloud-init template.
    /// Honest scope: this template installs WolfStack on a fresh
    /// VM and brings up the daemon. It does NOT form a multi-VM
    /// cluster on its own — cluster formation requires the SP /
    /// operator to call `POST /api/nodes` on the chosen master
    /// AFTER each VM is reachable, which is the same flow the
    /// existing dashboard "Add Node" UI uses. A future
    /// orchestration wizard (P5) will automate that; for now
    /// it's a manual step documented in the post-provision
    /// instructions.
    pub struct WolfStackBootstrap {
        /// Hostname to set on the new VM.
        pub hostname: String,
        /// SP's WolfStack URL — used as the install proxy origin
        /// (Path B). When set, cloud-init pulls setup.sh from
        /// `<sp_url>/api/install/setup.sh` first, falling back to
        /// the canonical GitHub raw URL if the SP is unreachable.
        /// Empty → cloud-init uses GitHub directly.
        pub sp_url: String,
        /// Whether to install in --agent mode (no management UI,
        /// just the cluster API listening). Useful for the
        /// non-leader VMs in a multi-VM cluster — the leader
        /// runs the full UI, agents are headless.
        pub agent_mode: bool,
    }

    /// Generate a cloud-config (YAML) that:
    ///   1. Sets the hostname
    ///   2. Installs WolfStack — preferring the SP's install
    ///      proxy when given, falling back to the canonical
    ///      GitHub raw URL
    ///   3. Brings up the systemd unit
    ///
    /// The setup.sh script handles its own dependency install,
    /// WolfNet bootstrap, cluster-secret generation, and
    /// systemd service creation — we don't second-guess any of
    /// that here. WolfNet MTU tuning (e.g. 1380 for nested
    /// wireguard inside the VM) is a post-install operator
    /// adjustment in `/etc/wolfnet/config.toml`; we don't touch
    /// it from cloud-init because writing a partial TOML file
    /// would break the schema.
    pub fn build_wolfstack_user_data(b: WolfStackBootstrap) -> String {
        // The hostname has already been validated upstream as
        // RFC 1123 (alphanumeric or hyphen, 1-63 chars). We
        // belt-and-braces strip anything outside that set as a
        // last-resort defence — a hostname ending up in YAML or
        // a shell command must not contain `:`, `#`, `'`, `"`,
        // newlines, `/`, `;`, `$`, `` ` ``, etc.
        let hostname: String = b.hostname.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(63)
            .collect();
        // If something completely upstream of the validator slips
        // an empty hostname through, fall back to a stable
        // placeholder rather than emitting `hostname: ""`.
        let hostname = if hostname.is_empty() { "wolfstack-vm".to_string() } else { hostname };

        // Canonical install URL — confirmed in setup.sh comments
        // (`curl -sSL https://raw.githubusercontent.com/...master/setup.sh`).
        let github_url = "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh";

        // Path B: try SP first, fall back to GitHub. The whole
        // download-then-execute chain uses `&&` so we never run
        // bash on an empty/missing /tmp/wolfstack-setup.sh, and
        // we explicitly check the file exists + is non-empty
        // before sudo'ing it as root. If both curls fail, exit
        // non-zero so cloud-init logs the failure clearly
        // instead of silently no-op'ing.
        let setup_flags = if b.agent_mode { "--yes --agent" } else { "--yes" };
        let install_cmd = if !b.sp_url.is_empty() {
            let sp_setup = format!("{}/api/install/setup.sh", b.sp_url.trim_end_matches('/'));
            format!(
                "rm -f /tmp/wolfstack-setup.sh && \
                 (curl -fsSL --max-time 30 \"{sp}\" -o /tmp/wolfstack-setup.sh \
                  || curl -fsSL --max-time 60 \"{gh}\" -o /tmp/wolfstack-setup.sh) && \
                 [ -s /tmp/wolfstack-setup.sh ] && \
                 sudo bash /tmp/wolfstack-setup.sh {flags}",
                sp = sp_setup, gh = github_url, flags = setup_flags,
            )
        } else {
            format!(
                "rm -f /tmp/wolfstack-setup.sh && \
                 curl -fsSL --max-time 60 \"{gh}\" -o /tmp/wolfstack-setup.sh && \
                 [ -s /tmp/wolfstack-setup.sh ] && \
                 sudo bash /tmp/wolfstack-setup.sh {flags}",
                gh = github_url, flags = setup_flags,
            )
        };

        let runcmds = vec![
            format!("hostnamectl set-hostname '{}'", hostname),
            install_cmd,
            "systemctl enable wolfstack || true".to_string(),
            "systemctl restart wolfstack || true".to_string(),
        ];
        let runcmd_yaml = runcmds.iter()
            .map(|c| format!("  - bash -lc '{}'", c.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join("\n");

        // Hostname is YAML-quoted to defend against any value
        // that would otherwise be interpreted as a YAML mapping
        // (`:` triggers map-value), comment (`#`), or anchor
        // (`&`/`*`). The validator above already strips those,
        // but the quoting is free defence in depth.
        format!(
            "#cloud-config\n\
             # WolfStack auto-bootstrap — generated by SP via XO Provision wizard.\n\
             # After first-boot, the new VM runs WolfStack as a single-node cluster.\n\
             # Multi-VM cluster formation is an operator step: from the chosen master,\n\
             # use the dashboard \"Add Node\" flow (or POST /api/nodes) with this VM's\n\
             # IP + the contents of /etc/wolfstack/join-token on this VM.\n\
             hostname: \"{hostname}\"\n\
             package_update: false\n\
             package_upgrade: false\n\
             runcmd:\n\
             {runcmd}\n\
             final_message: \"WolfStack first-boot finished. Daemon should be reachable on this VM's IP at port 8553.\"\n",
            hostname = hostname,
            runcmd = runcmd_yaml,
        )
    }
}
