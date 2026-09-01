// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Federation — a small registry of *other* WolfStack clusters this
//! one trusts for read-only cross-cluster aggregation.
//!
//! Each federation entry holds a base URL and a long-lived API key
//! minted on the remote cluster. Used today by the Gateway feature
//! to surface shares from every connected cluster in one panel;
//! future features (Control Panel inventory, predictive inbox,
//! WolfFlow targets) can adopt the same registry.
//!
//! This is intentionally a minimal "outbound only" primitive — it
//! authorises THIS cluster to PULL from a remote one. The remote
//! cluster's API key controls what scopes are visible. There's no
//! "join two clusters into one" semantic; each cluster stays its
//! own administrative domain.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn config_path() -> PathBuf {
    PathBuf::from(crate::paths::get().config_dir.clone()).join("federations.json")
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FederatedCluster {
    /// Stable id (uuid) so the UI can target update/delete.
    pub id: String,
    /// Operator-friendly label shown in the UI ("Datacenter Bay 1",
    /// "Home Lab", "AWS Frankfurt"). Unique-ish; not enforced.
    pub name: String,
    /// Base URL of the remote cluster's API (no trailing slash). e.g.
    /// `https://wolfstack.example.com:8553` or `http://10.0.0.42:8553`.
    pub base_url: String,
    /// Long-lived API key from the REMOTE cluster (minted there via
    /// Settings → API Keys, scope=read). Stored locally in the file
    /// (mode 0600); never sent anywhere except the Authorization
    /// header on outbound calls to this base_url.
    pub api_key: String,
    /// Allow self-signed TLS certs on the remote endpoint. Off by
    /// default; opt-in for homelab/dev setups.
    #[serde(default)]
    pub insecure_tls: bool,
    /// When the entry was created (RFC3339, informational only).
    #[serde(default)]
    pub created_at: String,
    /// Set when last call succeeded — surfaced in the UI.
    #[serde(default)]
    pub last_ok_unix: u64,
    /// Last error string from a failed call (cleared on success).
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct FederationStore {
    pub clusters: Vec<FederatedCluster>,
}

impl FederationStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(config_path()) {
            Ok(c) => serde_json::from_str::<Vec<FederatedCluster>>(&c)
                .map(|v| FederationStore { clusters: v })
                .unwrap_or_default(),
            Err(_) => FederationStore::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        let json = serde_json::to_string_pretty(&self.clusters)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::paths::write_secure(&path.to_string_lossy(), json)
            .map_err(std::io::Error::other)
    }

    pub fn upsert(&mut self, mut c: FederatedCluster) -> FederatedCluster {
        if c.id.is_empty() { c.id = uuid::Uuid::new_v4().to_string(); }
        if c.created_at.is_empty() {
            c.created_at = chrono::Utc::now().to_rfc3339();
        }
        // Trim trailing slashes once to keep URL building predictable.
        c.base_url = c.base_url.trim_end_matches('/').to_string();
        if let Some(existing) = self.clusters.iter_mut().find(|x| x.id == c.id) {
            *existing = c.clone();
        } else {
            self.clusters.push(c.clone());
        }
        c
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.clusters.len();
        self.clusters.retain(|c| c.id != id);
        self.clusters.len() != before
    }

    /// Public-facing rendering — strips the API key so the UI never
    /// receives it back.
    pub fn redacted(&self) -> serde_json::Value {
        serde_json::json!(self.clusters.iter().map(|c| serde_json::json!({
            "id": c.id,
            "name": c.name,
            "base_url": c.base_url,
            "insecure_tls": c.insecure_tls,
            "created_at": c.created_at,
            "last_ok_unix": c.last_ok_unix,
            "last_error": c.last_error,
            "api_key_set": !c.api_key.is_empty(),
        })).collect::<Vec<_>>())
    }
}

/// Validate operator input on create/update.
pub fn validate(c: &FederatedCluster) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    if c.name.trim().is_empty() {
        errs.push("name is required".into());
    }
    let url = c.base_url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        errs.push("base_url must start with http:// or https://".into());
    }
    if url.len() < 10 {
        errs.push("base_url is too short".into());
    }
    if c.api_key.trim().is_empty() {
        errs.push("api_key is required".into());
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

/// One-shot HTTP client for federation calls. Per-call instances so
/// `insecure_tls` is honoured per-cluster without a connection pool
/// pinning the previous setting. Local-AI-style settings: no idle
/// pool, fast connect, sane outer timeout.
pub fn build_client(insecure_tls: bool) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15));
    if insecure_tls {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// Issue a GET to <base_url><path> on a federated cluster, with the
/// API key in the Authorization header. Returns the parsed JSON or
/// an error string suitable for surfacing in the UI.
pub async fn fetch_json(c: &FederatedCluster, path: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", c.base_url, path);
    let client = build_client(c.insecure_tls);
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", c.api_key))
        .send()
        .await
        .map_err(|e| {
            // Walk reqwest's source chain so the operator sees the
            // real cause (TLS failure, host unreachable, etc.) rather
            // than the opaque outer wrapper.
            use std::error::Error;
            let mut msg = format!("{}", e);
            let mut cur: &dyn Error = &e;
            while let Some(s) = cur.source() {
                msg.push_str(" — ");
                msg.push_str(&s.to_string());
                cur = s;
            }
            msg
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "remote returned HTTP {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        ));
    }
    resp.json::<serde_json::Value>().await.map_err(|e| format!("invalid JSON: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_entry() -> FederatedCluster {
        FederatedCluster {
            id: String::new(),
            name: "Main".into(),
            base_url: "https://wolfstack.example.com:8553".into(),
            api_key: "wsk_xxx".into(),
            insecure_tls: false,
            created_at: String::new(),
            last_ok_unix: 0,
            last_error: None,
        }
    }

    #[test]
    fn validate_accepts_minimum_valid_entry() {
        assert!(validate(&ok_entry()).is_ok());
    }

    #[test]
    fn validate_rejects_empty_name() {
        let mut e = ok_entry(); e.name = "".into();
        assert!(validate(&e).is_err());
    }

    #[test]
    fn validate_rejects_non_http_base_url() {
        for bad in ["wolfstack.example.com:8553", "ftp://x", "/relative", ""] {
            let mut e = ok_entry();
            e.base_url = bad.into();
            assert!(validate(&e).is_err(), "should reject base_url: {:?}", bad);
        }
    }

    #[test]
    fn validate_rejects_missing_api_key() {
        let mut e = ok_entry(); e.api_key = "".into();
        assert!(validate(&e).is_err());
    }

    #[test]
    fn upsert_assigns_id_and_trims_trailing_slash() {
        let mut store = FederationStore::default();
        let mut e = ok_entry();
        e.base_url = "https://example.com:8553/".into(); // trailing slash
        let stored = store.upsert(e);
        assert!(!stored.id.is_empty(), "upsert should assign a uuid");
        assert_eq!(stored.base_url, "https://example.com:8553");
        assert!(!stored.created_at.is_empty());
    }

    #[test]
    fn upsert_with_existing_id_updates_in_place() {
        let mut store = FederationStore::default();
        let mut e = ok_entry();
        let stored = store.upsert(e.clone());
        let id = stored.id.clone();

        e.id = id.clone();
        e.name = "Renamed".into();
        let updated = store.upsert(e);
        assert_eq!(updated.id, id);
        assert_eq!(store.clusters.len(), 1, "must update in place, not append");
        assert_eq!(store.clusters[0].name, "Renamed");
    }

    #[test]
    fn redacted_strips_api_key() {
        let mut store = FederationStore::default();
        store.upsert(ok_entry());
        let v = store.redacted();
        let arr = v.as_array().unwrap();
        let first = &arr[0];
        assert!(first.get("api_key").is_none(), "api_key must NEVER be in the redacted JSON");
        assert_eq!(first.get("api_key_set").and_then(|x| x.as_bool()), Some(true));
        // base_url, name etc still present
        assert!(first.get("base_url").is_some());
        assert!(first.get("name").is_some());
    }

    #[test]
    fn remove_returns_false_for_unknown_id() {
        let mut store = FederationStore::default();
        store.upsert(ok_entry());
        assert!(!store.remove("does-not-exist"));
        assert_eq!(store.clusters.len(), 1);
    }
}
