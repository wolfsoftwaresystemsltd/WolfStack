// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! DNS provider credential store for ACME DNS-01 challenges.
//!
//! Lets the operator add one credentials file per DNS API (Cloudflare,
//! Route53, etc.) once at the cluster level, then issue wildcard certs
//! (`*.zone.tld`) without re-pasting tokens every time. This is the
//! piece that lets WolfStack drop from "22 per-host certs, port-80
//! standalone, breaks when WolfProxy is up" to "1-3 wildcard certs,
//! DNS-01, never touches port 80".
//!
//! Storage: `/etc/wolfstack/dns-providers.json`, mode 0600. Credentials
//! are XOR-obfuscated with a static key — same scheme as `xo::token_enc`
//! and the cluster-secret store. **This is obfuscation, not encryption.**
//! The real defence is filesystem permissions on `/etc/wolfstack/`.
//!
//! Plugin names are whitelisted: certbot maps `--<plugin>` to argv flags
//! and we never want an operator string to influence the certbot command
//! line.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

const STORE_PATH: &str = "/etc/wolfstack/dns-providers.json";
const TMP_CREDS_DIR: &str = "/run/wolfstack/dns-creds";
/// Legacy XOR key — kept ONLY for reading pre-v24.4 stored values.
/// New writes go through `at_rest_crypto::encrypt` (AES-256-GCM keyed
/// off the per-install cluster secret). The audit module surfaces a
/// finding while any v1 entries remain on disk.
const XOR_KEY: &[u8] = b"wolfstack-dns-v1";
/// Purpose label for HKDF key derivation — NEVER renamed (would
/// invalidate every stored v2 credential on this install).
const AT_REST_PURPOSE: &[u8] = b"dns-providers";

/// Plugin names accepted by certbot's stock `certbot-dns-*` set. New
/// providers must be added here explicitly — the plugin name is
/// interpolated into the certbot command line as `--<plugin>` and
/// `--<plugin>-credentials`, so accepting arbitrary strings would be a
/// command-injection vector via the plugin field.
pub const KNOWN_PLUGINS: &[&str] = &[
    "cloudflare",
    "route53",
    "google",
    "digitalocean",
    "linode",
    "rfc2136",
    "ovh",
    "gandi",
    "godaddy",
    "hetzner",
    "namecheap",
    "porkbun",
    "vultr",
    "njalla",
    "dnsimple",
    "dynu",
];

pub fn is_known_plugin(plugin: &str) -> bool {
    KNOWN_PLUGINS.iter().any(|p| *p == plugin)
}

/// One DNS provider entry. `credentials_enc` is XOR-obfuscated INI
/// content; never expose it directly via the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProvider {
    pub id: String,
    /// Operator-facing label, e.g. "Cloudflare — wolf.uk.com zone".
    pub name: String,
    /// Certbot plugin name. Must be in `KNOWN_PLUGINS`.
    pub plugin: String,
    /// Obfuscated INI content (multiline, keyed `dns_<plugin>_<option>`).
    pub credentials_enc: String,
    /// RFC3339 timestamp of creation. Set on `add`.
    #[serde(default)]
    pub created_at: String,
    /// RFC3339 timestamp of the last successful staging-CA dry-run via
    /// `POST /api/dns-providers/{id}/test`. Empty if never tested.
    #[serde(default)]
    pub last_tested_at: String,
    /// Last test result string. Empty if never tested; `"ok"` on
    /// success; an error excerpt on failure (capped to 240 chars so
    /// nodes.json-style files don't bloat).
    #[serde(default)]
    pub last_test_result: String,
}

/// Redacted view returned to the UI. Never carries the credentials.
#[derive(Debug, Clone, Serialize)]
pub struct DnsProviderRedacted {
    pub id: String,
    pub name: String,
    pub plugin: String,
    pub created_at: String,
    pub last_tested_at: String,
    pub last_test_result: String,
}

impl DnsProvider {
    pub fn redacted(&self) -> DnsProviderRedacted {
        DnsProviderRedacted {
            id: self.id.clone(),
            name: self.name.clone(),
            plugin: self.plugin.clone(),
            created_at: self.created_at.clone(),
            last_tested_at: self.last_tested_at.clone(),
            last_test_result: self.last_test_result.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DnsProviderStore {
    #[serde(default)]
    pub providers: Vec<DnsProvider>,
}

/// Serialise concurrent writes. The struct itself is cheap and small;
/// the lock just prevents two POSTs from interleaving their save() and
/// dropping one of the writes.
static SAVE_LOCK: Mutex<()> = Mutex::new(());

impl DnsProviderStore {
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

    pub fn list_redacted(&self) -> Vec<DnsProviderRedacted> {
        self.providers.iter().map(|p| p.redacted()).collect()
    }

    pub fn get(&self, id: &str) -> Option<&DnsProvider> {
        self.providers.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut DnsProvider> {
        self.providers.iter_mut().find(|p| p.id == id)
    }

    /// Add a provider. Returns the new id. Validates plugin against the
    /// whitelist and trims/validates the credentials INI.
    pub fn add(
        &mut self,
        name: String,
        plugin: String,
        credentials_ini: &str,
    ) -> Result<String, String> {
        let name = name.trim().to_string();
        let plugin = plugin.trim().to_lowercase();
        if name.is_empty() {
            return Err("name is required".into());
        }
        if !is_known_plugin(&plugin) {
            return Err(format!(
                "unknown plugin '{}' — supported: {}",
                plugin,
                KNOWN_PLUGINS.join(", ")
            ));
        }
        validate_ini(credentials_ini)?;
        let id = format!("dns-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = chrono::Utc::now().to_rfc3339();
        self.providers.push(DnsProvider {
            id: id.clone(),
            name,
            plugin,
            credentials_enc: obfuscate(credentials_ini),
            created_at: now,
            last_tested_at: String::new(),
            last_test_result: String::new(),
        });
        Ok(id)
    }

    /// Update name and/or credentials. Either field is optional; an
    /// empty `credentials_ini` means "leave existing creds alone".
    pub fn update(
        &mut self,
        id: &str,
        name: Option<String>,
        credentials_ini: Option<&str>,
    ) -> Result<(), String> {
        let entry = self.get_mut(id).ok_or_else(|| format!("provider '{}' not found", id))?;
        if let Some(n) = name {
            let n = n.trim().to_string();
            if n.is_empty() {
                return Err("name cannot be blank".into());
            }
            entry.name = n;
        }
        if let Some(ini) = credentials_ini {
            if !ini.trim().is_empty() {
                validate_ini(ini)?;
                entry.credentials_enc = obfuscate(ini);
                // Re-test status is now stale.
                entry.last_tested_at = String::new();
                entry.last_test_result = String::new();
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.providers.len();
        self.providers.retain(|p| p.id != id);
        before != self.providers.len()
    }

    /// Materialize a provider's credentials to a 0600 INI file at a
    /// fresh path under `TMP_CREDS_DIR`. Returns a `MaterializedCreds`
    /// guard that unlinks the file on drop — caller MUST NOT leak the
    /// path or hold the guard across an await boundary that could be
    /// cancelled (use `tokio::task::spawn_blocking` for the certbot
    /// invocation; the guard then lives entirely on one thread).
    pub fn materialize(&self, id: &str) -> Result<MaterializedCreds, String> {
        let p = self.get(id).ok_or_else(|| format!("provider '{}' not found", id))?;
        let ini = deobfuscate(&p.credentials_enc);
        if ini.is_empty() {
            return Err(format!("provider '{}' has empty credentials", id));
        }
        std::fs::create_dir_all(TMP_CREDS_DIR)
            .map_err(|e| format!("create {}: {}", TMP_CREDS_DIR, e))?;
        // Tighten dir perms too — even though we write the file with
        // 0600, a 0755 parent dir leaks the existence of credentials
        // to other local users via readdir.
        let _ = set_mode(Path::new(TMP_CREDS_DIR), 0o700);
        let file = format!(
            "{}/{}-{}.ini",
            TMP_CREDS_DIR,
            id,
            uuid::Uuid::new_v4().to_string().split_at(8).0
        );
        crate::paths::write_secure(&file, ini.as_bytes())
            .map_err(|e| format!("write {}: {}", file, e))?;
        Ok(MaterializedCreds { path: file })
    }
}

/// RAII guard for a materialised credentials file. Unlinks on drop —
/// even on panic — so a half-failed certbot run can't leave the secret
/// on disk under `/run/wolfstack/dns-creds/`.
pub struct MaterializedCreds {
    pub path: String,
}

impl Drop for MaterializedCreds {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}

/// Best-effort INI validity check. We don't try to parse against
/// certbot's per-plugin schema (it varies); we just reject anything
/// that's obviously not a key=value file. The real validator is
/// `POST /api/dns-providers/{id}/test` which runs a staging dry-run.
fn validate_ini(ini: &str) -> Result<(), String> {
    let trimmed = ini.trim();
    if trimmed.is_empty() {
        return Err("credentials INI is empty".into());
    }
    let mut saw_kv = false;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Section headers like `[default]` are allowed.
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }
        if !line.contains('=') {
            return Err(format!(
                "credentials INI: line '{}' is neither a comment, a [section], nor key=value",
                line
            ));
        }
        saw_kv = true;
    }
    if !saw_kv {
        return Err("credentials INI has no key=value lines".into());
    }
    Ok(())
}

/// Write path — prefer v2 AES-256-GCM; fall back to v1 XOR only if the
/// at-rest crypto module hasn't been initialised (shouldn't happen
/// after startup, but means a missing init() doesn't break credential
/// writes on a partially-initialised process).
fn obfuscate(plain: &str) -> String {
    match crate::at_rest_crypto::encrypt(plain.as_bytes(), AT_REST_PURPOSE) {
        Ok(v2) => v2,
        Err(_) => obfuscate_v1_xor(plain),
    }
}

/// Read path — accept either format. v2 values decrypt via AES-GCM;
/// anything without the v2 prefix is treated as a legacy v1 (XOR)
/// value and routed through the legacy decoder. Backward compat is
/// permanent: even years from now, an install that hasn't migrated
/// still reads correctly.
fn deobfuscate(encoded: &str) -> String {
    crate::at_rest_crypto::decrypt_or_legacy(encoded, AT_REST_PURPOSE, deobfuscate_v1_xor)
}

/// Legacy v1 XOR encoder — retained ONLY for the at_rest_crypto-not-
/// initialised fallback path. New code should never reach this.
fn obfuscate_v1_xor(plain: &str) -> String {
    use base64::Engine;
    let bytes: Vec<u8> = plain
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Legacy v1 XOR decoder — used as the fallback for any stored value
/// that doesn't start with `v2:`. Kept correct for UTF-8 (pre-fix
/// version cast each byte to char, mangling multi-byte sequences).
fn deobfuscate_v1_xor(encoded: &str) -> String {
    use base64::Engine;
    let raw = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let bytes: Vec<u8> = raw
        .into_iter()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

impl DnsProviderStore {
    /// Re-encrypt every v1 entry as v2 AES-256-GCM. Takes a backup of
    /// the existing file to `<path>.bak.<ts>` BEFORE the save so the
    /// operator can recover by hand if anything goes wrong. Returns
    /// (migrated, already_v2, errored).
    pub fn migrate_to_v2(&mut self) -> Result<(usize, usize, usize), String> {
        // W5 fix: only back up if there's actually any v1 entry to
        // migrate. Re-clicking the migrate button on an already-
        // migrated store shouldn't churn the backup retention slots.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_roundtrips() {
        let cases = [
            "dns_cloudflare_api_token = abc123\n",
            "[default]\ndns_route53_access_key_id = AKIA...\n",
            "\u{1F600} weird unicode is fine",
        ];
        for c in &cases {
            let enc = obfuscate(c);
            assert_ne!(enc, *c, "obfuscation must change the bytes");
            assert_eq!(deobfuscate(&enc), *c, "roundtrip must restore the original");
        }
        // Empty roundtrips to empty without panicking — degenerate but
        // shouldn't crash callers that pass a default-constructed value.
        assert_eq!(deobfuscate(&obfuscate("")), "");
    }

    #[test]
    fn plugin_whitelist_rejects_unknown() {
        let mut s = DnsProviderStore::default();
        let err = s.add("X".into(), "shellinject; rm -rf /".into(), "k = v").unwrap_err();
        assert!(err.contains("unknown plugin"), "rejection message must say so: {}", err);
        let err = s.add("X".into(), "bind9".into(), "k = v").unwrap_err();
        assert!(err.contains("unknown plugin"));
    }

    #[test]
    fn add_get_remove_redacts() {
        let mut s = DnsProviderStore::default();
        let id = s
            .add(
                "CF".into(),
                "cloudflare".into(),
                "dns_cloudflare_api_token = secrettoken123\n",
            )
            .expect("add");
        // Provider exists.
        let p = s.get(&id).expect("get");
        // Stored form must not be the raw secret.
        assert!(!p.credentials_enc.contains("secrettoken123"));
        // Redacted output has no credentials_enc field.
        let red = p.redacted();
        let json = serde_json::to_string(&red).unwrap();
        assert!(!json.contains("credentials_enc"));
        assert!(!json.contains("secrettoken123"));
        // Remove works idempotently — second call returns false.
        assert!(s.remove(&id));
        assert!(!s.remove(&id));
    }

    #[test]
    fn validate_ini_accepts_comments_sections_kv() {
        validate_ini("# a comment\n[default]\ndns_cloudflare_api_token = x\n").unwrap();
    }

    #[test]
    fn validate_ini_rejects_blank_and_non_kv() {
        assert!(validate_ini("").is_err());
        assert!(validate_ini("   \n  \n").is_err());
        assert!(validate_ini("# only comments\n").is_err());
        assert!(validate_ini("a line without equals\n").is_err());
    }

    #[test]
    fn update_clears_test_status_when_creds_change() {
        let mut s = DnsProviderStore::default();
        let id = s.add("CF".into(), "cloudflare".into(), "k = v").unwrap();
        // Simulate a prior successful test.
        let p = s.get_mut(&id).unwrap();
        p.last_tested_at = "2026-05-12T14:00:00Z".into();
        p.last_test_result = "ok".into();
        // Updating the creds invalidates the test status.
        s.update(&id, None, Some("k = v2")).unwrap();
        let p = s.get(&id).unwrap();
        assert!(p.last_tested_at.is_empty());
        assert!(p.last_test_result.is_empty());
        // Updating only the name leaves the test status alone after
        // we re-set it.
        let p = s.get_mut(&id).unwrap();
        p.last_tested_at = "2026-05-12T14:30:00Z".into();
        p.last_test_result = "ok".into();
        s.update(&id, Some("Renamed".into()), None).unwrap();
        let p = s.get(&id).unwrap();
        assert_eq!(p.name, "Renamed");
        assert_eq!(p.last_test_result, "ok");
    }

    #[test]
    fn known_plugins_are_lowercase_simple_ascii() {
        // Plugins are interpolated into argv as `--<plugin>` — make
        // sure none can ever ship a shell metachar through accident.
        for p in KNOWN_PLUGINS {
            assert!(
                p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "plugin '{}' contains unsafe chars",
                p
            );
        }
    }
}
