// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Dashboard Sync — operator-driven push of dashboard config to chosen
//! peer nodes.
//!
//! Simple model, no automation:
//! - Operator picks a set of target node IDs in the UI.
//! - When the operator presses "Push now", this node bundles a fixed
//!   set of admin-curated config files and POSTs them to each target
//!   via the existing inter-node HTTPS chain (X-WolfStack-Secret auth).
//! - No on-write replication, no pull, no last-writer-wins metadata.
//!   Just "push these files to those nodes now". The operator is the
//!   consistency guarantee.
//!
//! The bundle is defined in [`BUNDLE_FILES`] — every file under
//! `config_dir` that drives an operator-curated dashboard panel. Per-
//! node hardware state, TLS certs, the cluster secret, and the join
//! token are deliberately excluded. Receivers reject any path not on
//! the allowlist, so a peer can't push arbitrary files even with a
//! valid cluster secret.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Files included in the push bundle. Filenames are relative to
/// `crate::paths::get().config_dir`. Anything not in this list never
/// crosses the wire, in either direction.
///
/// Categories below are documented for the UI's "what gets pushed"
/// disclosure — keep the comments in sync with the frontend list.
pub const BUNDLE_FILES: &[&str] = &[
    // Cluster registry — the single biggest visible delta between a
    // master node and a peer with an empty sidebar.
    "nodes.json",
    // Sponsor / enterprise identity — drives the top-right header
    // badge and the sponsor banner state.
    "patreon.json",
    // Multi-cluster organisation.
    "tenants.json",
    "pools.json",
    "federations.json",
    "federation_tokens.json",
    // Auth — same logins on every target so the operator (and any
    // admin user) can sign in to the mirror with their existing
    // credentials. Per-node active lockouts are NOT in the bundle;
    // they're local state.
    "users.json",
    "auth-config.json",
    "oidc.json",
    "webauthn.json",
    "auth-lockout.json",
    // Operator-curated feature config that drives dashboard panels.
    "statuspage.json",
    "statuspage-uptime.json",
    "alerts.json",
    "reverse-proxy.json",
    "backups.json",
    "storage.json",
    "arrays.json",
    "ceph.json",
    "kubernetes.json",
    "vms.json",
    "cloud-providers.json",
    "dns-providers.json",
    "threat-intel.json",
    "router.json",
    "xo_pools.json",
    "ai-config.json",
    "antivirus.json",
    "sql-connections.json",
    "sql-saved-queries.json",
    "wolfnote.json",
    "wolfusb.json",
    "vlan-attachments.json",
    "image-watcher.json",
    "ip-mappings.json",
    "homepage.conf",
];

/// On-disk state — operator's chosen targets plus the per-target
/// outcome of the most recent push. Persisted to
/// `config_dir/dashboard-sync.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardSyncConfig {
    /// Node IDs the operator wants pushes to go to. Order is preserved
    /// for stable UI rendering; duplicates are removed on save.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Keyed by node ID. Stays around for unreached nodes so the UI
    /// can show "last successful push 3 days ago" even after the
    /// target falls offline.
    #[serde(default)]
    pub last_push: HashMap<String, PushOutcome>,
}

/// Outcome of a single push attempt against one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushOutcome {
    /// Unix seconds when the attempt finished.
    pub at: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Files the receiver reported as written. Useful for spotting a
    /// target that's running an older version with a smaller bundle.
    #[serde(default)]
    pub files: u32,
}

fn config_path() -> String {
    format!("{}/dashboard-sync.json", crate::paths::get().config_dir)
}

impl DashboardSyncConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(config_path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // 0600 — same posture as users.json / cluster-secret. The file
        // doesn't itself contain secrets, but the target list reveals
        // which peers receive the master view, which is sensitive
        // operational metadata.
        crate::paths::write_secure(&config_path(), json).map_err(|e| e.to_string())
    }
}

/// Build the push bundle from the local config directory. Missing
/// files are silently skipped — a target running a newer build with
/// extra modules simply won't receive those modules' files yet, and
/// that's fine (we never delete on the receiver side either).
pub fn build_bundle() -> HashMap<String, Vec<u8>> {
    let dir = crate::paths::get().config_dir;
    let mut out = HashMap::new();
    for name in BUNDLE_FILES {
        let path = format!("{}/{}", dir, name);
        if let Ok(bytes) = std::fs::read(&path) {
            out.insert((*name).to_string(), bytes);
        }
    }
    out
}

/// Wire format for `/api/dashboard-sync/receive`. File contents are
/// base64-encoded so the envelope stays plain JSON — saves us a
/// multipart encoder and matches the rest of the inter-node protocol.
#[derive(Debug, Serialize, Deserialize)]
pub struct PushPayload {
    /// Sending node's ID. Surfaced in the UI as "last push from <id>"
    /// even though we don't gate writes on it — auth is the cluster
    /// secret, this field is just informational.
    pub from_node: String,
    /// filename → base64(contents). Keys are validated against
    /// [`BUNDLE_FILES`] on the receiver.
    pub files: HashMap<String, String>,
}

/// Encode a built bundle into the wire envelope.
pub fn encode_payload(from_node: String, bundle: HashMap<String, Vec<u8>>) -> PushPayload {
    let files = bundle
        .into_iter()
        .map(|(name, bytes)| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            (name, b64)
        })
        .collect();
    PushPayload { from_node, files }
}

/// Apply a received bundle to the local config directory. Filenames are
/// validated against [`BUNDLE_FILES`] before any write, so a peer with
/// a valid cluster secret can't drop arbitrary paths. Returns the
/// number of files written.
pub fn apply_bundle(payload: &PushPayload) -> Result<u32, String> {
    let dir = crate::paths::get().config_dir;
    let allowed: std::collections::HashSet<&str> = BUNDLE_FILES.iter().copied().collect();
    let mut written = 0u32;
    for (name, b64) in &payload.files {
        if !allowed.contains(name.as_str()) {
            // A peer attempting to write outside the allowlist is a
            // protocol violation worth a warning, but not an abort:
            // we still want to apply the legitimate files in the same
            // payload.
            tracing::warn!(
                "dashboard-sync: dropping non-allowlisted file '{}' from peer '{}'",
                name,
                payload.from_node
            );
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| format!("decode {}: {}", name, e))?;
        let path = format!("{}/{}", dir, name);
        crate::paths::write_secure(&path, &bytes)
            .map_err(|e| format!("write {}: {}", name, e))?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_files_are_unique() {
        let mut sorted: Vec<&str> = BUNDLE_FILES.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "BUNDLE_FILES contains duplicates");
    }

    #[test]
    fn allowlist_rejects_path_traversal() {
        // A malicious peer attempting to write outside the config dir
        // must be silently dropped. The function returns Ok with a
        // written count of 0 because no allowlisted files were
        // included in the payload.
        let mut files = HashMap::new();
        files.insert(
            "../../etc/passwd".to_string(),
            base64::engine::general_purpose::STANDARD.encode(b"x"),
        );
        files.insert(
            "users.json/../foo".to_string(),
            base64::engine::general_purpose::STANDARD.encode(b"x"),
        );
        let payload = PushPayload {
            from_node: "test".to_string(),
            files,
        };
        let n = apply_bundle(&payload).unwrap();
        assert_eq!(n, 0);
    }
}
