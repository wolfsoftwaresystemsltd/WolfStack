// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Unraid integration — register one or more Unraid servers and view their
//! array, disks, user shares, parity status/history, Docker containers and
//! VMs over the official GraphQL API.
//!
//! Mirrors the TrueNAS integration (`src/truenas/mod.rs`): a JSON store of
//! registered instances at `/etc/wolfstack/unraid.json`, each instance's API
//! key encrypted at rest (AES via `at_rest_crypto`, never returned to the
//! browser), and an optional per-instance `cluster` tag so a server shows
//! under the right cluster's Storage view.
//!
//! API notes:
//! - The Unraid API is GraphQL-only at `http(s)://server/graphql`,
//!   authenticated with an `x-api-key` header. Built into Unraid 7.2+;
//!   available on 6.12+ via the Unraid Connect plugin. Keys are created in
//!   Settings → Management Access → API Keys (a read-only "guest"/viewer
//!   role is enough for everything WolfStack reads).
//! - All size fields in the array/shares schema are KILOBYTES — the schema
//!   sources annotate `size`/`fsSize`/`fsFree`/`fsUsed` and share
//!   `free`/`used`/`size` with "(KB)" (unraid/api array.model.ts /
//!   share.model.ts) — so everything is converted to bytes here once,
//!   defensively (GraphQL BigInt arrives as number OR string).
//! - Unraid's UI likes to redirect to hashed `*.myunraid.net` hostnames;
//!   operators should register the LAN IP/hostname directly.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;

/// Shared client that VERIFIES TLS — used when an instance is not flagged
/// insecure.
static UR_CLIENT_STRICT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Shared client that accepts self-signed certs — Unraid on plain LAN IPs
/// either runs HTTP or a self-signed cert, so this is the register-form
/// default (mirrors TrueNAS).
static UR_CLIENT_INSECURE: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Purpose label for HKDF key derivation — NEVER renamed (would invalidate
/// every stored key on this install).
const AT_REST_PURPOSE: &[u8] = b"unraid-keys";

// ─── Registered instance (persisted) ──────────────────────────────

/// One Unraid server the operator has registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnraidInstance {
    pub id: String,
    /// Friendly label shown in the UI (e.g. "tower").
    pub label: String,
    /// Optional cluster tag — shows under that cluster's Storage view; empty =
    /// visible on every cluster.
    #[serde(default)]
    pub cluster: Option<String>,
    /// Base server URL, e.g. `https://10.2.0.40` or `http://tower.lan`
    /// (trailing slash and any `/graphql` suffix are normalised away; the
    /// GraphQL endpoint is derived).
    pub api_url: String,
    /// API key, encrypted at rest. Created in the Unraid UI under
    /// Settings → Management Access → API Keys. Never serialised to the
    /// frontend.
    pub api_key_enc: String,
    /// Accept a self-signed TLS cert (common on LAN-IP Unraid).
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

impl UnraidInstance {
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
            "insecure_tls": self.insecure_tls,
            "cache_ttl_secs": self.cache_ttl_secs,
            "last_seen": self.last_seen,
            "status": self.status,
            "has_key": !self.api_key_enc.is_empty(),
        })
    }

    fn client(&self) -> &'static reqwest::Client {
        if self.insecure_tls { &UR_CLIENT_INSECURE } else { &UR_CLIENT_STRICT }
    }

    /// The GraphQL endpoint derived from `api_url` — tolerates the operator
    /// pasting the bare server URL, a trailing slash, the full /graphql path,
    /// or a stray query/fragment. The HOST was already validated by the SSRF
    /// gate at register time; this only normalises the path.
    fn graphql_url(&self) -> String {
        let base = self.api_url.trim();
        let base = base.split(['#', '?']).next().unwrap_or(base);
        let base = base.trim_end_matches('/');
        let base = base.strip_suffix("/graphql").unwrap_or(base);
        format!("{}/graphql", base)
    }
}

// ─── API key encryption (mirror of TrueNAS key handling) ───────────

/// Encrypt an Unraid API key for at-rest storage (AES v2, XOR v1 fallback).
pub fn obfuscate_key(plain: &str) -> String {
    match crate::at_rest_crypto::encrypt(plain.as_bytes(), AT_REST_PURPOSE) {
        Ok(v2) => v2,
        Err(_) => obfuscate_key_v1_xor(plain),
    }
}

/// Decrypt an Unraid API key (accepts v2 AES or v1 XOR).
pub fn deobfuscate_key(encoded: &str) -> String {
    if encoded.is_empty() { return String::new(); }
    crate::at_rest_crypto::decrypt_or_legacy(encoded, AT_REST_PURPOSE, deobfuscate_key_v1_xor)
}

fn obfuscate_key_v1_xor(plain: &str) -> String {
    use base64::Engine;
    let key = b"wolfstack-ur-v1";
    let bytes: Vec<u8> = plain.bytes().enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn deobfuscate_key_v1_xor(encoded: &str) -> String {
    use base64::Engine;
    let key = b"wolfstack-ur-v1";
    let raw = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let bytes: Vec<u8> = raw.into_iter().enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ─── GraphQL transport ──────────────────────────────────────────────

/// POST one GraphQL query and return the `data` object. GraphQL-level
/// errors (the `errors` array) become `Err` with the joined messages; an
/// HTTP 401/403 becomes a distinguishable "unauthorized:" error so the
/// probe can report `auth_failed` vs `unreachable`.
async fn graphql(inst: &UnraidInstance, query: &str) -> Result<serde_json::Value, String> {
    let resp = inst.client()
        .post(inst.graphql_url())
        .header("x-api-key", inst.api_key())
        .header("Accept", "application/json")
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await
        .map_err(|e| format!("Unraid request failed: {}", e))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(format!("unauthorized: Unraid rejected the API key (HTTP {})", status.as_u16()));
    }
    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("Unraid returned non-JSON (is the URL the server root, not a redirect?): {}", e))?;

    if let Some(errors) = body.get("errors").and_then(|e| e.as_array())
        && !errors.is_empty()
    {
        let msgs: Vec<String> = errors.iter()
            .filter_map(|e| e.get("message").and_then(|m| m.as_str()).map(str::to_string))
            .collect();
        let joined = if msgs.is_empty() { "unknown GraphQL error".to_string() } else { msgs.join("; ") };
        // The API reports permission problems as GraphQL errors too.
        if joined.to_ascii_lowercase().contains("unauthoriz") || joined.to_ascii_lowercase().contains("permission") {
            return Err(format!("unauthorized: {}", joined));
        }
        return Err(format!("Unraid GraphQL error: {}", joined));
    }
    body.get("data").cloned().ok_or_else(|| "Unraid response had no data".to_string())
}

// ─── Live data types (stable WolfStack shapes — frontend never sees raw GraphQL) ───

#[derive(Debug, Clone, Serialize, Default)]
pub struct ArrayInfo {
    /// e.g. "STARTED" / "STOPPED".
    pub state: String,
    pub total_bytes: i64,
    pub used_bytes: i64,
    pub free_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArrayDiskInfo {
    /// Slot index within its group.
    pub idx: i64,
    pub name: String,
    pub device: String,
    /// "parity" | "data" | "cache" | "boot".
    pub kind: String,
    pub size_bytes: i64,
    /// e.g. "DISK_OK".
    pub status: String,
    /// Celsius; None when the array is stopped / device standby.
    pub temp: Option<i64>,
    pub fs_type: String,
    pub fs_size_bytes: i64,
    pub fs_free_bytes: i64,
    pub num_errors: i64,
    pub rotational: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareInfo {
    pub name: String,
    pub free_bytes: i64,
    pub used_bytes: i64,
    pub size_bytes: i64,
    /// Cache pool usage mode as reported (e.g. "yes"/"no"/pool name).
    pub cache: String,
    pub comment: String,
    /// LUKS encryption status string, empty when n/a.
    pub luks_status: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ParityCheck {
    pub status: String,
    pub running: bool,
    pub paused: bool,
    pub correcting: bool,
    /// Percent 0-100 when running.
    pub progress: i64,
    pub speed: String,
    pub errors: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParityRun {
    pub date: String,
    pub duration: i64,
    pub speed: String,
    pub status: String,
    pub errors: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub auto_start: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VmInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub distro: String,
    pub release: String,
    pub kernel: String,
    pub uptime: String,
    pub cpu_brand: String,
    pub cpu_cores: i64,
    pub cpu_threads: i64,
    pub unraid_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnraidOverview {
    pub info: SystemInfo,
    pub array: ArrayInfo,
    pub disks: Vec<ArrayDiskInfo>,
    pub shares: Vec<ShareInfo>,
    pub parity: ParityCheck,
}

// ─── Defensive JSON helpers ─────────────────────────────────────────

/// GraphQL BigInt fields arrive as a JSON number OR a numeric string
/// depending on size/serializer — accept both; anything else is 0.
fn jint(v: Option<&serde_json::Value>) -> i64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or_else(|| n.as_f64().map(|f| f as i64).unwrap_or(0)),
        Some(serde_json::Value::String(s)) => s.trim().parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

/// KB field → bytes (array/share sizes are documented "(KB)" in the schema).
fn kb_to_bytes(v: Option<&serde_json::Value>) -> i64 {
    jint(v).saturating_mul(1024)
}

fn jstr(v: &serde_json::Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn jbool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

/// Disk temp: Celsius number, but NaN/null when the array is stopped or the
/// disk is spun down — those become None.
fn jtemp(v: &serde_json::Value) -> Option<i64> {
    match v.get("temp") {
        Some(serde_json::Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()).map(|f| f as i64),
        Some(serde_json::Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn parse_array_disk(v: &serde_json::Value, kind: &str) -> ArrayDiskInfo {
    ArrayDiskInfo {
        idx: jint(v.get("idx")),
        name: jstr(v, "name"),
        device: jstr(v, "device"),
        kind: kind.to_string(),
        size_bytes: kb_to_bytes(v.get("size")),
        status: jstr(v, "status"),
        temp: jtemp(v),
        fs_type: jstr(v, "fsType"),
        fs_size_bytes: kb_to_bytes(v.get("fsSize")),
        fs_free_bytes: kb_to_bytes(v.get("fsFree")),
        num_errors: jint(v.get("numErrors")),
        rotational: jbool(v, "rotational"),
    }
}

// ─── Fetchers ───────────────────────────────────────────────────────

/// Everything the Overview tab shows, in ONE GraphQL round-trip.
/// Field sets verified against the official schema (unraid/api
/// array.model.ts, share model) and the documented example queries.
const OVERVIEW_QUERY: &str = r#"query WolfStackOverview {
  info {
    os { platform distro release kernel hostname uptime }
    cpu { brand cores threads }
    versions { core { unraid } }
  }
  array {
    state
    capacity { kilobytes { free used total } }
    parities { idx name device size status rotational temp numErrors fsType fsSize fsFree }
    disks { idx name device size status rotational temp numErrors fsType fsSize fsFree }
    caches { idx name device size status rotational temp numErrors fsType fsSize fsFree }
    parityCheckStatus { progress speed errors status paused running correcting }
  }
  shares { name free used size cache comment luksStatus }
}"#;

pub async fn fetch_overview(inst: &UnraidInstance) -> Result<UnraidOverview, String> {
    let data = graphql(inst, OVERVIEW_QUERY).await?;

    let info_v = data.get("info").cloned().unwrap_or(serde_json::Value::Null);
    let os = info_v.get("os").cloned().unwrap_or(serde_json::Value::Null);
    let cpu = info_v.get("cpu").cloned().unwrap_or(serde_json::Value::Null);
    let info = SystemInfo {
        hostname: jstr(&os, "hostname"),
        distro: jstr(&os, "distro"),
        release: jstr(&os, "release"),
        kernel: jstr(&os, "kernel"),
        uptime: jstr(&os, "uptime"),
        cpu_brand: jstr(&cpu, "brand"),
        cpu_cores: jint(cpu.get("cores")),
        cpu_threads: jint(cpu.get("threads")),
        unraid_version: info_v.get("versions").and_then(|v| v.get("core"))
            .map(|c| jstr(c, "unraid")).unwrap_or_default(),
    };

    let array_v = data.get("array").cloned().unwrap_or(serde_json::Value::Null);
    let kb = array_v.get("capacity").and_then(|c| c.get("kilobytes")).cloned()
        .unwrap_or(serde_json::Value::Null);
    let array = ArrayInfo {
        state: jstr(&array_v, "state"),
        total_bytes: kb_to_bytes(kb.get("total")),
        used_bytes: kb_to_bytes(kb.get("used")),
        free_bytes: kb_to_bytes(kb.get("free")),
    };

    let mut disks: Vec<ArrayDiskInfo> = Vec::new();
    for (key, kind) in [("parities", "parity"), ("disks", "data"), ("caches", "cache")] {
        if let Some(arr) = array_v.get(key).and_then(|a| a.as_array()) {
            for d in arr {
                disks.push(parse_array_disk(d, kind));
            }
        }
    }

    let pcs = array_v.get("parityCheckStatus").cloned().unwrap_or(serde_json::Value::Null);
    let parity = ParityCheck {
        status: jstr(&pcs, "status"),
        running: jbool(&pcs, "running"),
        paused: jbool(&pcs, "paused"),
        correcting: jbool(&pcs, "correcting"),
        progress: jint(pcs.get("progress")),
        speed: jstr(&pcs, "speed"),
        errors: jint(pcs.get("errors")),
    };

    let shares = data.get("shares").and_then(|s| s.as_array()).map(|arr| {
        arr.iter().map(|s| ShareInfo {
            name: jstr(s, "name"),
            free_bytes: kb_to_bytes(s.get("free")),
            used_bytes: kb_to_bytes(s.get("used")),
            size_bytes: kb_to_bytes(s.get("size")),
            cache: jstr(s, "cache"),
            comment: jstr(s, "comment"),
            luks_status: jstr(s, "luksStatus"),
        }).collect()
    }).unwrap_or_default();

    Ok(UnraidOverview { info, array, disks, shares, parity })
}

pub async fn fetch_docker(inst: &UnraidInstance) -> Result<Vec<DockerInfo>, String> {
    let data = graphql(inst,
        "query WolfStackDocker { docker { containers { id names image state status autoStart } } }").await?;
    let list = data.get("docker").and_then(|d| d.get("containers")).and_then(|c| c.as_array())
        .cloned().unwrap_or_default();
    Ok(list.iter().map(|c| DockerInfo {
        id: jstr(c, "id"),
        // `names` is an array; Docker prefixes "/" on the primary name.
        name: c.get("names").and_then(|n| n.as_array())
            .and_then(|a| a.first()).and_then(|n| n.as_str())
            .unwrap_or("").trim_start_matches('/').to_string(),
        image: jstr(c, "image"),
        state: jstr(c, "state"),
        status: jstr(c, "status"),
        auto_start: jbool(c, "autoStart"),
    }).collect())
}

pub async fn fetch_vms(inst: &UnraidInstance) -> Result<Vec<VmInfo>, String> {
    let data = graphql(inst,
        "query WolfStackVms { vms { domains { id name state uuid } } }").await?;
    let list = data.get("vms").and_then(|v| v.get("domains")).and_then(|d| d.as_array())
        .cloned().unwrap_or_default();
    Ok(list.iter().map(|d| VmInfo {
        id: jstr(d, "id"),
        name: jstr(d, "name"),
        state: jstr(d, "state"),
        uuid: jstr(d, "uuid"),
    }).collect())
}

pub async fn fetch_parity_history(inst: &UnraidInstance) -> Result<Vec<ParityRun>, String> {
    let data = graphql(inst,
        "query WolfStackParityHistory { parityHistory { date duration speed status errors } }").await?;
    let list = data.get("parityHistory").and_then(|p| p.as_array()).cloned().unwrap_or_default();
    Ok(list.iter().map(|r| ParityRun {
        date: jstr(r, "date"),
        duration: jint(r.get("duration")),
        speed: jstr(r, "speed"),
        status: jstr(r, "status"),
        errors: jint(r.get("errors")),
    }).collect())
}

/// Connection probe: the cheapest authenticated query. Returns the server's
/// reported hostname on success; "unauthorized:"-prefixed errors mean the
/// key was rejected, anything else means unreachable.
pub async fn test_connection(inst: &UnraidInstance) -> Result<String, String> {
    let data = graphql(inst, "query WolfStackProbe { info { os { hostname } } }").await?;
    Ok(data.get("info").and_then(|i| i.get("os")).map(|o| jstr(o, "hostname")).unwrap_or_default())
}

// ─── Persisted store (mirror of TrueNasStore) ───────────────────────

pub struct UnraidStore {
    instances: Vec<UnraidInstance>,
    path: String,
}

impl UnraidStore {
    pub fn load() -> Self {
        let path = crate::paths::get().unraid_config.clone();
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
        // umask-mode window; code review 2026-06-11).
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

    pub fn list(&self) -> Vec<UnraidInstance> { self.instances.clone() }

    pub fn get(&self, id: &str) -> Option<UnraidInstance> {
        self.instances.iter().find(|i| i.id == id).cloned()
    }

    pub fn add(&mut self, mut inst: UnraidInstance) -> Result<String, String> {
        if inst.label.trim().is_empty() { return Err("label is required".into()); }
        if inst.api_url.trim().is_empty() { return Err("server URL is required".into()); }
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
    // Arg-per-field mirrors TrueNasStore::update exactly — a params struct
    // would diverge the two stores for no behavioural gain.
    #[allow(clippy::too_many_arguments)]
    pub fn update(&mut self, id: &str, label: String, cluster: Option<String>, api_url: String,
                  insecure_tls: bool, cache_ttl_secs: u64, new_key: Option<String>)
        -> Result<(), String>
    {
        let inst = self.instances.iter_mut().find(|i| i.id == id)
            .ok_or_else(|| format!("instance {} not found", id))?;
        if label.trim().is_empty() { return Err("label is required".into()); }
        if api_url.trim().is_empty() { return Err("server URL is required".into()); }
        inst.label = label;
        inst.cluster = cluster;
        inst.api_url = api_url;
        inst.insecure_tls = insecure_tls;
        inst.cache_ttl_secs = cache_ttl_secs;
        if let Some(k) = new_key
            && !k.trim().is_empty()
        {
            inst.api_key_enc = obfuscate_key(k.trim());
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

    fn inst(url: &str) -> UnraidInstance {
        UnraidInstance {
            id: "u1".into(), label: "tower".into(), cluster: None,
            api_url: url.into(), api_key_enc: String::new(),
            insecure_tls: true, cache_ttl_secs: 300,
            last_seen: String::new(), status: String::new(),
        }
    }

    #[test]
    fn graphql_url_normalises_operator_input() {
        assert_eq!(inst("https://10.0.0.5").graphql_url(), "https://10.0.0.5/graphql");
        assert_eq!(inst("https://10.0.0.5/").graphql_url(), "https://10.0.0.5/graphql");
        assert_eq!(inst("http://tower.lan/graphql").graphql_url(), "http://tower.lan/graphql");
        assert_eq!(inst("http://tower.lan/graphql/").graphql_url(), "http://tower.lan/graphql");
        // Stray fragments/queries from a pasted browser URL are dropped.
        assert_eq!(inst("https://10.0.0.5/graphql#frag").graphql_url(), "https://10.0.0.5/graphql");
        assert_eq!(inst("https://10.0.0.5/?tab=main").graphql_url(), "https://10.0.0.5/graphql");
    }

    #[test]
    fn key_roundtrips_through_v1_xor() {
        let enc = obfuscate_key_v1_xor("my-unraid-key");
        assert_ne!(enc, "my-unraid-key");
        assert_eq!(deobfuscate_key_v1_xor(&enc), "my-unraid-key");
    }

    #[test]
    fn bigint_fields_parse_as_number_or_string_and_convert_kb() {
        // GraphQL BigInt arrives as number OR numeric string.
        assert_eq!(jint(Some(&serde_json::json!(42))), 42);
        assert_eq!(jint(Some(&serde_json::json!("42"))), 42);
        assert_eq!(jint(Some(&serde_json::json!(null))), 0);
        assert_eq!(jint(None), 0);
        // Sizes are KB in the schema — converted to bytes exactly once.
        assert_eq!(kb_to_bytes(Some(&serde_json::json!(4))), 4096);
        assert_eq!(kb_to_bytes(Some(&serde_json::json!("1048576"))), 1073741824);
    }

    #[test]
    fn overview_shapes_parse_from_canned_response() {
        // A representative `data` object in the documented schema shape.
        let array = serde_json::json!({
            "state": "STARTED",
            "capacity": { "kilobytes": { "free": "1000", "used": "3000", "total": "4000" } },
            "parities": [{ "idx": 0, "name": "parity", "device": "sdb", "size": 1000, "status": "DISK_OK",
                           "rotational": true, "temp": 34, "numErrors": 0, "fsType": null,
                           "fsSize": null, "fsFree": null }],
            "disks": [{ "idx": 1, "name": "disk1", "device": "sdc", "size": "1000", "status": "DISK_OK",
                        "rotational": true, "temp": null, "numErrors": 0, "fsType": "xfs",
                        "fsSize": 900, "fsFree": 100 }],
            "caches": [],
        });
        let parity = parse_array_disk(&array["parities"][0], "parity");
        assert_eq!(parity.kind, "parity");
        assert_eq!(parity.size_bytes, 1_024_000);
        assert_eq!(parity.temp, Some(34));
        assert_eq!(parity.fs_size_bytes, 0); // null on parity drives

        let d1 = parse_array_disk(&array["disks"][0], "data");
        assert_eq!(d1.size_bytes, 1_024_000); // string BigInt
        assert_eq!(d1.temp, None);            // spun down / array stopped
        assert_eq!(d1.fs_free_bytes, 102_400);
    }
}
