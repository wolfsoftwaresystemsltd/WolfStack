// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! TrueNAS integration — register one or more TrueNAS servers and view their
//! pools, datasets, disks, NFS exports and ZFS snapshots (and create/delete
//! snapshots) over the REST API v2.0.
//!
//! Mirrors the Xen Orchestra integration (`src/xo/mod.rs`): a JSON store of
//! registered instances at `/etc/wolfstack/truenas.json`, each instance's API
//! key encrypted at rest (AES via `at_rest_crypto`, never returned to the
//! browser), and an optional per-instance `cluster` tag so a server shows under
//! the right cluster's Storage view.
//!
//! REST API note: TrueNAS SCALE up to ~25.04 serves the full `/api/v2.0` REST
//! API. 25.10+ (Goldeye) deprecates the ZFS REST endpoints — `/zfs/snapshot`
//! returns 404 in favour of the JSON-RPC/WebSocket API — so snapshot
//! create/delete surface a clear "not supported on this TrueNAS version"
//! message there rather than failing opaquely. All size fields are parsed
//! defensively (flat number OR nested `{parsed,rawvalue,value}`) so field-shape
//! differences across versions don't break the read paths.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;

/// Shared client that VERIFIES TLS — used when an instance is not flagged
/// insecure.
static TN_CLIENT_STRICT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Shared client that accepts self-signed certs — TrueNAS ships a self-signed
/// cert by default, so most homelab instances need this (the `insecure_tls`
/// flag, on by default in the register form).
static TN_CLIENT_INSECURE: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Purpose label for HKDF key derivation — NEVER renamed (would invalidate
/// every stored key on this install).
const AT_REST_PURPOSE: &[u8] = b"truenas-keys";

// ─── Registered instance (persisted) ──────────────────────────────

/// One TrueNAS server the operator has registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrueNasInstance {
    pub id: String,
    /// Friendly label shown in the UI (e.g. "atlas").
    pub label: String,
    /// Optional cluster tag — shows under that cluster's Storage view; empty =
    /// visible on every cluster.
    #[serde(default)]
    pub cluster: Option<String>,
    /// Base API URL including the version prefix, e.g.
    /// `https://10.2.0.153/api/v2.0` (trailing slash trimmed).
    pub api_url: String,
    /// API key, encrypted at rest. Created in the TrueNAS UI under
    /// Credentials → Local Users → API Keys. Never serialised to the frontend.
    pub api_key_enc: String,
    /// Primary pool to surface in the Overview (e.g. "vault"). Empty = first
    /// pool the server reports.
    #[serde(default)]
    pub pool_name: String,
    /// Accept a self-signed TLS cert (TrueNAS default).
    #[serde(default = "default_insecure_tls")]
    pub insecure_tls: bool,
    /// Cache TTL for read data, seconds.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    /// Last successful probe (RFC3339).
    #[serde(default)]
    pub last_seen: String,
    /// Last probe result: "ok" | "unreachable" | "auth_failed". Empty until
    /// first probe.
    #[serde(default)]
    pub status: String,
}

fn default_insecure_tls() -> bool { true }
fn default_cache_ttl() -> u64 { 300 }

impl TrueNasInstance {
    /// Decrypted API key (plaintext) for outbound requests.
    pub fn api_key(&self) -> String {
        deobfuscate_key(&self.api_key_enc)
    }

    /// A frontend-safe view: NEVER includes the key.
    pub fn redacted(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "label": self.label,
            "cluster": self.cluster,
            "api_url": self.api_url,
            "pool_name": self.pool_name,
            "insecure_tls": self.insecure_tls,
            "cache_ttl_secs": self.cache_ttl_secs,
            "last_seen": self.last_seen,
            "status": self.status,
            "has_key": !self.api_key_enc.is_empty(),
        })
    }

    fn client(&self) -> &'static reqwest::Client {
        if self.insecure_tls { &TN_CLIENT_INSECURE } else { &TN_CLIENT_STRICT }
    }
}

// ─── API key encryption (mirror of XO token handling) ──────────────

/// Encrypt a TrueNAS API key for at-rest storage (AES v2, XOR v1 fallback).
pub fn obfuscate_key(plain: &str) -> String {
    match crate::at_rest_crypto::encrypt(plain.as_bytes(), AT_REST_PURPOSE) {
        Ok(v2) => v2,
        Err(_) => obfuscate_key_v1_xor(plain),
    }
}

/// Decrypt a TrueNAS API key (accepts v2 AES or v1 XOR).
pub fn deobfuscate_key(encoded: &str) -> String {
    if encoded.is_empty() { return String::new(); }
    crate::at_rest_crypto::decrypt_or_legacy(encoded, AT_REST_PURPOSE, deobfuscate_key_v1_xor)
}

fn obfuscate_key_v1_xor(plain: &str) -> String {
    use base64::Engine;
    let key = b"wolfstack-tn-v1";
    let bytes: Vec<u8> = plain.bytes().enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn deobfuscate_key_v1_xor(encoded: &str) -> String {
    use base64::Engine;
    let key = b"wolfstack-tn-v1";
    let raw = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let bytes: Vec<u8> = raw.into_iter().enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ─── Live data types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PoolInfo {
    pub name: String,
    pub status: String,
    pub healthy: bool,
    pub total_bytes: i64,
    pub used_bytes: i64,
    pub free_bytes: i64,
    /// Last scrub end time (RFC3339-ish, as TrueNAS reports it). Empty if none.
    pub scrub_end: String,
    /// Last scrub state, e.g. "FINISHED". Empty if none.
    pub scrub_state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatasetInfo {
    /// Short name (last path component), e.g. "projects".
    pub name: String,
    /// Full ZFS path, e.g. "vault/projects".
    pub path: String,
    pub used_bytes: i64,
    pub available_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub name: String,
    pub size_bytes: i64,
    pub model: String,
    pub serial: String,
    pub disk_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NfsExport {
    pub path: String,
    pub networks: Vec<String>,
    pub enabled: bool,
    pub read_only: bool,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub dataset: String,
    pub name: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrueNasOverview {
    pub pool: Option<PoolInfo>,
    pub datasets: Vec<DatasetInfo>,
    pub disks: Vec<DiskInfo>,
}

// ─── Defensive size parsing ────────────────────────────────────────

/// TrueNAS reports ZFS sizes either as a bare integer or as a nested object
/// `{ "parsed": <int>, "rawvalue": "<int-string>", "value": "1.2T" }`. Read
/// whichever is present, preferring the integer byte count.
fn parse_size(v: Option<&serde_json::Value>) -> i64 {
    let v = match v { Some(v) => v, None => return 0 };
    if let Some(n) = v.as_i64() { return n; }
    if let Some(f) = v.as_f64() { return f as i64; }
    if let Some(obj) = v.as_object() {
        if let Some(p) = obj.get("parsed").and_then(|x| x.as_i64()) { return p; }
        if let Some(p) = obj.get("parsed").and_then(|x| x.as_f64()) { return p as i64; }
        if let Some(r) = obj.get("rawvalue").and_then(|x| x.as_str()) {
            if let Ok(n) = r.parse::<i64>() { return n; }
        }
        if let Some(val) = obj.get("value").and_then(|x| x.as_str()) {
            if let Ok(n) = val.parse::<i64>() { return n; }
        }
    }
    0
}

fn jstr(v: &serde_json::Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

// ─── REST client ───────────────────────────────────────────────────

pub struct TrueNasClient {
    base_url: String,
    api_key: String,
    client: &'static reqwest::Client,
}

impl TrueNasClient {
    pub fn for_instance(inst: &TrueNasInstance) -> Self {
        Self {
            base_url: inst.api_url.trim_end_matches('/').to_string(),
            api_key: inst.api_key(),
            client: inst.client(),
        }
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Option<serde_json::Value>)
        -> Result<serde_json::Value, String>
    {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.request(method, &url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Accept", "application/json");
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await
            .map_err(|e| format!("TrueNAS request failed: {}", e))?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err("TrueNAS rejected the API key (401/403). Create a new key in the TrueNAS UI under Credentials → API Keys, and make sure it has write access if you want to manage snapshots.".into());
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err("TrueNAS returned 404 for this endpoint. On TrueNAS SCALE 25.10+ the REST ZFS endpoints were removed in favour of the WebSocket API — snapshot management isn't available over REST on that version.".into());
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("TrueNAS HTTP {}: {}", status, body.chars().take(300).collect::<String>()));
        }
        let text = resp.text().await.map_err(|e| format!("TrueNAS read failed: {}", e))?;
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| {
            format!("TrueNAS response not JSON ({}): {}", e, text.chars().take(200).collect::<String>())
        })
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        self.request(reqwest::Method::GET, path, None).await
    }

    /// Cheap probe used by Test Connection — confirms the key works and
    /// returns the TrueNAS version for the UI.
    pub async fn test_connection(&self) -> Result<String, String> {
        let info = self.get("/system/info").await?;
        Ok(jstr(&info, "version"))
    }

    /// Pool + datasets + disks in one shot.
    pub async fn overview(&self, pool_name: &str) -> Result<TrueNasOverview, String> {
        let pools = self.get("/pool").await?;
        let pool = self.pick_pool(&pools, pool_name);
        let chosen = pool.as_ref().map(|p| p.name.clone()).unwrap_or_else(|| pool_name.to_string());

        let datasets = self.datasets_for(&chosen).await.unwrap_or_default();
        let disks = self.disks().await.unwrap_or_default();
        Ok(TrueNasOverview { pool, datasets, disks })
    }

    fn pick_pool(&self, pools: &serde_json::Value, want: &str) -> Option<PoolInfo> {
        let arr = pools.as_array()?;
        let chosen = arr.iter().find(|p| !want.is_empty() && jstr(p, "name").eq_ignore_ascii_case(want))
            .or_else(|| arr.first())?;
        let status = jstr(chosen, "status");
        let total = parse_size(chosen.get("size"));
        let used = parse_size(chosen.get("allocated"));
        // Some versions omit `free`; derive it.
        let mut free = parse_size(chosen.get("free"));
        if free == 0 && total > 0 { free = (total - used).max(0); }
        let scan = chosen.get("scan");
        Some(PoolInfo {
            name: jstr(chosen, "name"),
            healthy: chosen.get("healthy").and_then(|x| x.as_bool())
                .unwrap_or_else(|| status.eq_ignore_ascii_case("online")),
            status,
            total_bytes: total,
            used_bytes: used,
            free_bytes: free,
            scrub_end: scan.map(|s| jstr(s, "end_time")).unwrap_or_default(),
            scrub_state: scan.map(|s| jstr(s, "state")).unwrap_or_default(),
        })
    }

    /// Direct child datasets of the pool, with sizes. Handles both the nested
    /// shape (pool root dataset with a `children` array) and the flat shape
    /// (one object per dataset, filtered by `<pool>/<child>`).
    async fn datasets_for(&self, pool: &str) -> Result<Vec<DatasetInfo>, String> {
        let data = self.get("/pool/dataset").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        let mut out = Vec::new();

        // Nested: find the pool root, take its children.
        if let Some(root) = arr.iter().find(|d| jstr(d, "name").eq_ignore_ascii_case(pool)) {
            if let Some(children) = root.get("children").and_then(|c| c.as_array()) {
                for c in children {
                    out.push(dataset_from(c));
                }
            }
        }
        // Flat fallback: any dataset exactly one level under the pool.
        if out.is_empty() {
            let prefix = format!("{}/", pool);
            for d in &arr {
                let name = jstr(d, "name");
                if let Some(rest) = name.strip_prefix(&prefix) {
                    if !rest.contains('/') {
                        out.push(dataset_from(d));
                    }
                }
            }
        }
        out.sort_by(|a, b| b.used_bytes.cmp(&a.used_bytes));
        Ok(out)
    }

    async fn disks(&self) -> Result<Vec<DiskInfo>, String> {
        let data = self.get("/disk").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        Ok(arr.iter().map(|d| DiskInfo {
            name: jstr(d, "name"),
            size_bytes: parse_size(d.get("size")),
            model: jstr(d, "model"),
            serial: jstr(d, "serial"),
            disk_type: jstr(d, "type"),
        }).collect())
    }

    pub async fn nfs_exports(&self) -> Result<Vec<NfsExport>, String> {
        let data = self.get("/sharing/nfs").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        Ok(arr.iter().map(|s| {
            // Newer SCALE uses a single `path`; older used `paths: []`.
            let path = if let Some(p) = s.get("path").and_then(|x| x.as_str()) {
                p.to_string()
            } else {
                s.get("paths").and_then(|x| x.as_array())
                    .and_then(|a| a.first()).and_then(|x| x.as_str())
                    .unwrap_or("").to_string()
            };
            let networks = s.get("networks").and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_str().map(String::from)).collect())
                .unwrap_or_default();
            NfsExport {
                path,
                networks,
                enabled: s.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true),
                read_only: s.get("ro").and_then(|x| x.as_bool()).unwrap_or(false),
                comment: jstr(s, "comment"),
            }
        }).collect())
    }

    pub async fn snapshots(&self) -> Result<Vec<SnapshotInfo>, String> {
        let data = self.get("/zfs/snapshot").await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        Ok(arr.iter().map(|s| {
            let created = s.get("properties")
                .and_then(|p| p.get("creation"))
                .map(|c| parse_size(Some(c)))
                .filter(|n| *n > 0)
                .map(|epoch| epoch.to_string())
                .unwrap_or_default();
            SnapshotInfo {
                id: jstr(s, "id"),
                dataset: jstr(s, "dataset"),
                name: {
                    let n = jstr(s, "snapshot_name");
                    if n.is_empty() { jstr(s, "name") } else { n }
                },
                created,
            }
        }).collect())
    }

    /// Create a ZFS snapshot. `dataset` is the full path (e.g. "vault/projects"),
    /// `name` is the snapshot label (the part after `@`).
    pub async fn create_snapshot(&self, dataset: &str, name: &str, recursive: bool) -> Result<(), String> {
        let body = serde_json::json!({ "dataset": dataset, "name": name, "recursive": recursive });
        self.request(reqwest::Method::POST, "/zfs/snapshot", Some(body)).await?;
        Ok(())
    }

    /// Delete a ZFS snapshot by its id (e.g. "vault/projects@daily-2026-06-06").
    pub async fn delete_snapshot(&self, id: &str) -> Result<(), String> {
        let path = format!("/zfs/snapshot/id/{}", urlencoding_encode(id));
        self.request(reqwest::Method::DELETE, &path, None).await?;
        Ok(())
    }
}

fn dataset_from(d: &serde_json::Value) -> DatasetInfo {
    let path = jstr(d, "name");
    let short = path.rsplit('/').next().unwrap_or(&path).to_string();
    DatasetInfo {
        name: short,
        path,
        used_bytes: parse_size(d.get("used")),
        available_bytes: parse_size(d.get("available")),
    }
}

/// Minimal percent-encoding for the snapshot id path segment (it contains `@`
/// and `/`). Avoids pulling in a urlencoding crate for one call site.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ─── Persisted store (mirror of XoStore) ───────────────────────────

pub struct TrueNasStore {
    instances: Vec<TrueNasInstance>,
    path: String,
}

impl TrueNasStore {
    pub fn load() -> Self {
        let path = crate::paths::get().truenas_config.clone();
        let instances = match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Self { instances, path }
    }

    fn save(&self) -> Result<(), String> {
        let s = serde_json::to_string_pretty(&self.instances).map_err(|e| format!("serialize: {}", e))?;
        let parent = std::path::Path::new(&self.path).parent()
            .unwrap_or_else(|| std::path::Path::new("/etc/wolfstack"));
        let _ = std::fs::create_dir_all(parent);
        let tmp = format!("{}.tmp", self.path);
        // The file holds encrypted API keys — the TEMP file must already be
        // 0600 at creation, not chmodded after the rename (that left a
        // umask-mode window; code review 2026-06-11, found via the Unraid
        // mirror of this store).
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(&tmp).map_err(|e| format!("write: {}", e))?;
            f.write_all(s.as_bytes()).map_err(|e| format!("write: {}", e))?;
        }
        #[cfg(not(unix))]
        std::fs::write(&tmp, &s).map_err(|e| format!("write: {}", e))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("rename: {}", e))?;
        // Re-assert on the final path in case it pre-existed with looser perms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<TrueNasInstance> { self.instances.clone() }

    pub fn get(&self, id: &str) -> Option<TrueNasInstance> {
        self.instances.iter().find(|i| i.id == id).cloned()
    }

    pub fn add(&mut self, mut inst: TrueNasInstance) -> Result<String, String> {
        if inst.label.trim().is_empty() { return Err("label is required".into()); }
        if inst.api_url.trim().is_empty() { return Err("API URL is required".into()); }
        if inst.id.is_empty() { inst.id = uuid::Uuid::new_v4().to_string(); }
        if self.instances.iter().any(|i| i.id == inst.id) {
            return Err(format!("instance {} already exists", inst.id));
        }
        let id = inst.id.clone();
        self.instances.push(inst);
        self.save()?;
        Ok(id)
    }

    /// Update mutable fields of an existing instance. A blank `new_key` leaves
    /// the stored key unchanged (so the operator can edit other fields without
    /// re-entering the key).
    pub fn update(&mut self, id: &str, label: String, cluster: Option<String>, api_url: String,
                  pool_name: String, insecure_tls: bool, cache_ttl_secs: u64, new_key: Option<String>)
        -> Result<(), String>
    {
        let inst = self.instances.iter_mut().find(|i| i.id == id)
            .ok_or_else(|| format!("instance {} not found", id))?;
        if label.trim().is_empty() { return Err("label is required".into()); }
        if api_url.trim().is_empty() { return Err("API URL is required".into()); }
        inst.label = label;
        inst.cluster = cluster;
        inst.api_url = api_url;
        inst.pool_name = pool_name;
        inst.insecure_tls = insecure_tls;
        inst.cache_ttl_secs = cache_ttl_secs;
        if let Some(k) = new_key {
            if !k.trim().is_empty() {
                inst.api_key_enc = obfuscate_key(k.trim());
            }
        }
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        let before = self.instances.len();
        self.instances.retain(|i| i.id != id);
        if self.instances.len() == before { return Err(format!("instance {} not found", id)); }
        self.save()
    }

    /// Re-tag instances when a WolfStack cluster is renamed (case-insensitive
    /// match, same rule as `agent::cluster_eq`). Untagged instances (visible on
    /// every cluster) are untouched. Returns how many changed.
    pub fn rename_cluster(&mut self, old_name: &str, new_name: &str) -> usize {
        let mut n = 0;
        for i in self.instances.iter_mut() {
            if i.cluster.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(old_name)) {
                i.cluster = Some(new_name.to_string());
                n += 1;
            }
        }
        if n > 0 { let _ = self.save(); }
        n
    }

    pub fn update_status(&mut self, id: &str, status: &str) {
        if let Some(i) = self.instances.iter_mut().find(|i| i.id == id) {
            i.status = status.to_string();
            i.last_seen = chrono::Utc::now().to_rfc3339();
            let _ = self.save();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_handles_flat_and_nested() {
        assert_eq!(parse_size(Some(&serde_json::json!(1024))), 1024);
        assert_eq!(parse_size(Some(&serde_json::json!({"parsed": 2048, "value": "2K"}))), 2048);
        assert_eq!(parse_size(Some(&serde_json::json!({"rawvalue": "4096"}))), 4096);
        assert_eq!(parse_size(Some(&serde_json::json!({"value": "8192"}))), 8192);
        assert_eq!(parse_size(Some(&serde_json::json!({"value": "1.2T"}))), 0); // non-integer string → 0
        assert_eq!(parse_size(None), 0);
    }

    #[test]
    fn key_roundtrips_through_v1_xor() {
        // v1 path is deterministic without at_rest_crypto init in tests.
        let enc = obfuscate_key_v1_xor("my-secret-key");
        assert_ne!(enc, "my-secret-key");
        assert_eq!(deobfuscate_key_v1_xor(&enc), "my-secret-key");
    }

    #[test]
    fn url_segment_encoding_escapes_at_and_slash() {
        assert_eq!(urlencoding_encode("vault/projects@daily-1"), "vault%2Fprojects%40daily-1");
    }
}
