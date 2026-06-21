// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Cloud-provider credentials store. Holds infrastructure-side API
//! tokens (Cloudflare, Hetzner, etc.) — distinct from
//! `crate::dns_providers` which holds *DNS-only* tokens used for ACME
//! DNS-01 challenges. The two stores stay separate because:
//!
//!   • DNS providers are picked when issuing certs; cloud providers
//!     are picked when provisioning LBs / tunnels. Different surfaces.
//!   • Some operators have DNS at Cloudflare but infrastructure on
//!     Hetzner. Storing them in one undifferentiated bucket would
//!     mean the picker has to filter by capability — annoying.
//!   • The DNS store's plugin whitelist maps to certbot's `dns-*`
//!     plugins; the cloud store's whitelist maps to our internal
//!     edge providers. No overlap.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const STORE_PATH: &str = "/etc/wolfstack/cloud-providers.json";
/// Legacy XOR key — kept ONLY for reading pre-v24.4 stored values.
/// New writes use AES-256-GCM via `crate::at_rest_crypto`.
const XOR_KEY: &[u8] = b"wolfstack-cloud-v1";
const AT_REST_PURPOSE: &[u8] = b"cloud-providers";

/// Cloud provider kind. New providers land as additive whitelist
/// entries. Pre-v23.2 the only one that ships is Cloudflare; v23.3
/// adds Hetzner and DigitalOcean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloudProviderKind {
    /// Cloudflare account credentials — used by both DnsRoundRobin /
    /// CloudflareDns edge strategies and by CloudflareTunnel.
    /// Credentials shape: {account_id, api_token}.
    Cloudflare,
    /// Hetzner Cloud project token — for HetznerLb edge strategy.
    /// Credentials shape: {api_token}.
    Hetzner,
    /// DigitalOcean personal access token — for DigitalOceanLb edge
    /// strategy AND the DigitalOcean DNS provider (one token, both).
    /// Credentials shape: {api_token}.
    DigitalOcean,
}

impl CloudProviderKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Cloudflare   => "cloudflare",
            Self::Hetzner      => "hetzner",
            Self::DigitalOcean => "digitalocean",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "cloudflare"   => Some(Self::Cloudflare),
            "hetzner"      => Some(Self::Hetzner),
            "digitalocean" => Some(Self::DigitalOcean),
            _ => None,
        }
    }
}

/// A single stored credential set. `credentials_enc` is XOR-obfuscated
/// JSON whose shape depends on `kind`:
///
///   Cloudflare → `{"account_id": "...", "api_token": "..."}`
///
/// We don't model per-provider shapes as separate types because they
/// all go through the same serde dance and the validation lives in
/// the provider impl that consumes them. The store treats them as
/// opaque blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProvider {
    pub id: String,
    pub name: String,
    pub kind: CloudProviderKind,
    pub credentials_enc: String,
    #[serde(default)]
    pub created_at: String,
    /// Last successful `ping` against this provider's API. Set by the
    /// "test connection" endpoint. Empty if never tested.
    #[serde(default)]
    pub last_verified_at: String,
    /// Last test outcome — "ok" or a truncated error message. Drives
    /// the green/red badge in the Settings UI.
    #[serde(default)]
    pub last_verify_result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudProviderRedacted {
    pub id: String,
    pub name: String,
    pub kind: CloudProviderKind,
    pub created_at: String,
    pub last_verified_at: String,
    pub last_verify_result: String,
}

impl CloudProvider {
    pub fn redacted(&self) -> CloudProviderRedacted {
        CloudProviderRedacted {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind,
            created_at: self.created_at.clone(),
            last_verified_at: self.last_verified_at.clone(),
            last_verify_result: self.last_verify_result.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CloudProviderStore {
    #[serde(default)]
    pub providers: Vec<CloudProvider>,
}

static SAVE_LOCK: Mutex<()> = Mutex::new(());

impl CloudProviderStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(STORE_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let _guard = SAVE_LOCK.lock().map_err(|e| format!("save lock: {e}"))?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(STORE_PATH, json)
            .map_err(|e| format!("write {}: {}", STORE_PATH, e))
    }

    pub fn list_redacted(&self) -> Vec<CloudProviderRedacted> {
        self.providers.iter().map(|p| p.redacted()).collect()
    }

    pub fn get(&self, id: &str) -> Option<&CloudProvider> {
        self.providers.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut CloudProvider> {
        self.providers.iter_mut().find(|p| p.id == id)
    }

    pub fn add(&mut self, name: String, kind: CloudProviderKind, credentials_json: &str) -> Result<String, String> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".into());
        }
        // Sanity-check the credentials JSON parses. We don't validate
        // the shape — that's the provider impl's job — but rejecting
        // syntactically-bad JSON up front saves operators chasing a
        // ghost when the test endpoint later fails for a completely
        // different reason.
        if serde_json::from_str::<serde_json::Value>(credentials_json).is_err() {
            return Err("credentials must be a JSON object".into());
        }
        let id = format!("cld-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = chrono::Utc::now().to_rfc3339();
        self.providers.push(CloudProvider {
            id: id.clone(),
            name,
            kind,
            credentials_enc: obfuscate(credentials_json),
            created_at: now,
            last_verified_at: String::new(),
            last_verify_result: String::new(),
        });
        Ok(id)
    }

    pub fn update(&mut self, id: &str, name: Option<String>, credentials_json: Option<&str>) -> Result<(), String> {
        let entry = self.get_mut(id).ok_or_else(|| format!("provider '{}' not found", id))?;
        if let Some(n) = name {
            let n = n.trim().to_string();
            if n.is_empty() { return Err("name cannot be blank".into()); }
            entry.name = n;
        }
        if let Some(json) = credentials_json {
            if !json.trim().is_empty() {
                if serde_json::from_str::<serde_json::Value>(json).is_err() {
                    return Err("credentials must be a JSON object".into());
                }
                entry.credentials_enc = obfuscate(json);
                entry.last_verified_at = String::new();
                entry.last_verify_result = String::new();
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.providers.len();
        self.providers.retain(|p| p.id != id);
        before != self.providers.len()
    }

    /// Decrypt + deserialize the credentials. Returned `serde_json::Value`
    /// so the caller (the per-provider edge module) can pick out
    /// exactly the fields it needs without this layer learning each
    /// provider's schema.
    pub fn credentials_json(&self, id: &str) -> Result<serde_json::Value, String> {
        let p = self.get(id).ok_or_else(|| format!("provider '{}' not found", id))?;
        let raw = deobfuscate(&p.credentials_enc);
        if raw.is_empty() {
            return Err(format!("provider '{}' has empty credentials", id));
        }
        serde_json::from_str(&raw).map_err(|e| format!("decode credentials for '{}': {}", id, e))
    }
}

/// Write path — v2 AES-256-GCM via at_rest_crypto. Falls back to v1
/// XOR only if at_rest_crypto isn't initialised (defensive — shouldn't
/// happen in a normally-started process).
fn obfuscate(plain: &str) -> String {
    match crate::at_rest_crypto::encrypt(plain.as_bytes(), AT_REST_PURPOSE) {
        Ok(v2) => v2,
        Err(_) => obfuscate_v1_xor(plain),
    }
}

/// Read path — accept v2 or v1. v2 decrypts via AES-GCM; v1 falls
/// through to the legacy XOR decoder. Backward compat is permanent.
fn deobfuscate(encoded: &str) -> String {
    crate::at_rest_crypto::decrypt_or_legacy(encoded, AT_REST_PURPOSE, deobfuscate_v1_xor)
}

fn obfuscate_v1_xor(plain: &str) -> String {
    use base64::Engine;
    let bytes: Vec<u8> = plain.bytes().enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn deobfuscate_v1_xor(encoded: &str) -> String {
    use base64::Engine;
    let raw = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let bytes: Vec<u8> = raw.into_iter().enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

impl CloudProviderStore {
    /// Re-encrypt every v1 entry as v2 AES-256-GCM. Backs up the
    /// existing file to `<path>.bak.<ts>` BEFORE the save. Returns
    /// (migrated, already_v2, errored).
    pub fn migrate_to_v2(&mut self) -> Result<(usize, usize, usize), String> {
        // W5 fix: skip backup when no v1 entries remain.
        let any_v1 = self.providers.iter().any(|e|
            !crate::at_rest_crypto::is_v2_format(&e.credentials_enc));
        if any_v1 && std::path::Path::new(STORE_PATH).exists() {
            let backup = format!("{}.bak.{}", STORE_PATH,
                chrono::Utc::now().format("%Y%m%d%H%M%S"));
            std::fs::copy(STORE_PATH, &backup)
                .map_err(|e| format!("backup before migrate: {}", e))?;
        }
        let mut migrated = 0;
        let mut already = 0;
        let mut errored = 0;
        for entry in &mut self.providers {
            if crate::at_rest_crypto::is_v2_format(&entry.credentials_enc) {
                already += 1;
                continue;
            }
            let plaintext = deobfuscate_v1_xor(&entry.credentials_enc);
            if plaintext.is_empty() {
                errored += 1;
                continue;
            }
            match crate::at_rest_crypto::encrypt(plaintext.as_bytes(), AT_REST_PURPOSE) {
                Ok(v2) => { entry.credentials_enc = v2; migrated += 1; }
                Err(_) => errored += 1,
            }
        }
        if migrated > 0 {
            self.save()?;
        }
        Ok((migrated, already, errored))
    }

    /// Re-encrypt every v2 (cluster-secret-keyed) credential blob from the
    /// OLD cluster secret to the NEW one, as part of a cluster-secret
    /// rotation. Returns the number of entries re-keyed. See
    /// `at_rest_crypto::reencrypt_v2_field` for the loss-free / idempotent
    /// safety contract — legacy v1 XOR values (static key) are left
    /// untouched; v2 values that don't decrypt under `old` are skipped,
    /// never destroyed.
    pub fn reencrypt_at_rest(&mut self, old: &str, new: &str) -> Result<usize, String> {
        if old == new {
            return Ok(0);
        }
        let mut rekeyed = 0usize;
        let mut skipped = 0usize;
        for entry in &mut self.providers {
            match crate::at_rest_crypto::reencrypt_v2_field(
                &entry.credentials_enc, AT_REST_PURPOSE, old, new,
            ) {
                crate::at_rest_crypto::ReencryptOutcome::Rekeyed(v) => {
                    entry.credentials_enc = v; rekeyed += 1;
                }
                crate::at_rest_crypto::ReencryptOutcome::Skipped => { skipped += 1; }
                crate::at_rest_crypto::ReencryptOutcome::Untouched => {}
            }
        }
        if rekeyed > 0 {
            self.save()?;
        }
        if skipped > 0 {
            tracing::info!(target: "secret_rotation",
                "cloud-providers: re-keyed {} credential(s), skipped {} (legacy-v1/undecryptable)",
                rekeyed, skipped);
        }
        Ok(rekeyed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_roundtrips_json() {
        let creds = r#"{"account_id":"abc","api_token":"def"}"#;
        let enc = obfuscate(creds);
        assert_ne!(enc, creds);
        assert_eq!(deobfuscate(&enc), creds);
    }

    #[test]
    fn add_get_remove() {
        let mut s = CloudProviderStore::default();
        let id = s.add(
            "CF main".into(),
            CloudProviderKind::Cloudflare,
            r#"{"account_id":"a","api_token":"t"}"#,
        ).unwrap();
        let p = s.get(&id).unwrap();
        assert_eq!(p.kind, CloudProviderKind::Cloudflare);
        assert!(!p.credentials_enc.contains("\"api_token\""));
        // Redacted view doesn't carry the encrypted blob.
        let red = serde_json::to_string(&p.redacted()).unwrap();
        assert!(!red.contains("credentials_enc"));
        assert!(s.remove(&id));
        assert!(!s.remove(&id));
    }

    #[test]
    fn add_rejects_non_json_credentials() {
        let mut s = CloudProviderStore::default();
        let err = s.add(
            "bad".into(),
            CloudProviderKind::Cloudflare,
            "not json at all",
        ).unwrap_err();
        assert!(err.contains("JSON"));
    }

    #[test]
    fn update_blanks_test_result_when_creds_change() {
        let mut s = CloudProviderStore::default();
        let id = s.add("CF".into(), CloudProviderKind::Cloudflare, r#"{"x":1}"#).unwrap();
        // Simulate prior successful test.
        let p = s.get_mut(&id).unwrap();
        p.last_verified_at = "ts".into();
        p.last_verify_result = "ok".into();

        s.update(&id, None, Some(r#"{"x":2}"#)).unwrap();
        let p = s.get(&id).unwrap();
        assert!(p.last_verified_at.is_empty());
        assert!(p.last_verify_result.is_empty());
    }

    #[test]
    fn credentials_json_decrypts() {
        let mut s = CloudProviderStore::default();
        let id = s.add("CF".into(), CloudProviderKind::Cloudflare, r#"{"k":"v"}"#).unwrap();
        let v = s.credentials_json(&id).unwrap();
        assert_eq!(v["k"], "v");
    }
}
