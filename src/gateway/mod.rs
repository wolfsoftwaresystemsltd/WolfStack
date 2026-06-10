// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfStack Gateway — universal SMB/NFS re-export of any storage source.
//!
//! Sits in front of WolfStack-reachable storage (local dirs, WolfDisk,
//! CephFS, peer SMB/NFS shares, container volumes, VM-exported shares,
//! …) and exposes it to LAN clients as a normal SMB share and/or NFS
//! export. Re-exports only — never owns the data — so we never have
//! to solve the distributed-storage problem ourselves.
//!
//! v1.0 scope:
//!   * Sources: Local, WolfDisk, CephFS, Smb (re-export), Nfs (re-export)
//!   * Mode:    `single` (one source per gateway)
//!   * Protocols: SMB and/or NFS, both implementable via host-installed
//!     samba / nfs-kernel-server (matches the missing-tool inline-install
//!     pattern; we never auto-install)
//!   * Auth:    Anonymous, Users (tdbsam-managed local users)
//!   * Serve:   single node per gateway
//!   * Cluster: gossip-synced via the existing inter-node secret pattern
//!
//! Out of v1.0: failover/aggregate/sharded modes, AD auth, CTDB
//! clustering, client-side LB. Roadmap items, not partial features —
//! their absence is documented; v1.0 single-mode works fully on its
//! own.

pub mod nfs;
pub mod orchestrator;
pub mod samba;
pub mod sources;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use sources::Source;

// ─── Persistence path ───

fn gateways_path() -> PathBuf {
    PathBuf::from(crate::paths::get().config_dir.clone()).join("gateways.json")
}

// ─── Public types ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Gateway {
    pub id: String,
    pub name: String,
    /// Cluster-scoped, like statuspage / backup destinations. Empty
    /// string means "default cluster" — matches existing convention.
    #[serde(default)]
    pub cluster: String,
    pub mode: GatewayMode,
    pub protocols: Vec<Protocol>,
    pub sources: Vec<Source>,
    /// `node_id` (self_id) of the WolfStack node that owns this
    /// gateway — the only node that runs the SMB/NFS daemons for
    /// it in v1.0. Stamped at create time and never changed without
    /// an explicit migrate-share API call (post-v1.0). Cluster sync
    /// distributes the config to every peer for visibility, but only
    /// `origin_node_id` actually applies it; peers ignore.
    #[serde(default)]
    pub origin_node_id: String,
    /// Reserved for v2.0 — multi-node serve. v1.0 honours
    /// `origin_node_id` only; non-empty `serve_nodes` is rejected by
    /// validate() so operators get a clear "v2.0 feature" error
    /// rather than silently-wrong behaviour.
    #[serde(default)]
    pub serve_nodes: Vec<String>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub policy: ModePolicy,
    #[serde(default)]
    pub options: GatewayOptions,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    Single,
    /// Reserved for v1.1+. Modeled now so existing config files don't
    /// need migration when the orchestrator gains the capability.
    Failover,
    /// Reserved for v1.2+.
    Aggregate,
    /// Reserved for v1.2+.
    Sharded,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Smb,
    Nfs,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModePolicy {
    #[default]
    Single,
    Failover {
        primary_index: usize,
        health_interval_secs: u32,
        switchback: bool,
    },
    Aggregate {
        write_target: AggregatePolicy,
        min_free_pct: u8,
    },
    Sharded {
        rules: Vec<ShardRule>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum AggregatePolicy {
    #[default]
    MostFreeSpace,
    RoundRobin,
    FirstAvailable,
    ExistingPathFirst,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShardRule {
    pub prefix: String,
    pub source_index: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AuthConfig {
    Anonymous {
        #[serde(default)]
        writable: bool,
    },
    Users {
        users: Vec<UserGrant>,
        #[serde(default = "default_true")]
        default_writable: bool,
    },
    /// Reserved for v1.2+. Stub modeled now so config files don't
    /// break when the AD path lands.
    Ad {
        domain: String,
        allowed_groups: Vec<String>,
        idmap_range: (u32, u32),
    },
}

fn default_true() -> bool { true }

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig::Anonymous { writable: false }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserGrant {
    pub username: String,
    #[serde(default = "default_true")]
    pub writable: bool,
}
// Passwords are NEVER stored in `gateways.json`. The API sets a user's
// password by piping plaintext directly into `smbpasswd` (which holds
// it in Samba's tdbsam at /var/lib/samba/private/passdb.tdb, 0600
// root-only). The username list IS replicated across the cluster (so
// every node's `gateways.json` agrees on who's allowed) but the
// password is per-node.
//
// v1.0 IMPLICATION: only the gateway's `origin_node_id` actually
// serves the share, so passwords only need to live there. The
// orchestrator's startup re-apply skips peers (see
// `reconcile_on_startup`), and mutating endpoints reject calls on
// non-owner nodes (see `require_owner`). When v2.0 multi-node serve
// lands, password replication becomes a real concern — handled either
// via CTDB's shared pdb backend, or a privileged push-to-peers call
// triggered from the password-set endpoint.

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct GatewayOptions {
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub guest_ok: bool,
    /// SMB: enable Apple Time Machine support (vfs_fruit + spotlight).
    #[serde(default)]
    pub time_machine: bool,
    /// SMB: server-side recycle bin (vfs_recycle).
    #[serde(default)]
    pub recycle_bin: bool,
    #[serde(default)]
    pub smb_encrypt: SmbEncrypt,
    /// CIDR allowlist. Empty = allow any.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default)]
    pub case_sensitive: Option<bool>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    /// SMB workgroup advertised in the [global] section. Defaults to
    /// `WORKGROUP` (the de-facto Windows default) so out-of-the-box
    /// LAN browsing just works. Override per-cluster for AD-joined
    /// or non-default home networks.
    #[serde(default = "default_workgroup")]
    pub smb_workgroup: String,
}

fn default_workgroup() -> String { "WORKGROUP".to_string() }

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmbEncrypt {
    /// `smb encrypt = auto` — negotiate per client.
    #[default]
    Auto,
    /// Reject unencrypted connections. SMB3 only.
    Required,
    Off,
}

// NfsVersion was removed 2026-06-10: per-export version pinning doesn't exist
// in exports(5) — the `vers=N` option it drove made exportfs reject the whole
// export file (`unknown keyword "vers=4"`, wabil). Which NFS versions nfsd
// serves is a server-wide [nfsd] /etc/nfs.conf concern, and the default
// (v3+v4) covers all clients. Saved gateway configs that still carry an
// `nfs_version` key load fine — serde ignores unknown fields.

// ─── Runtime status (not persisted) ───

#[derive(Serialize, Clone, Debug)]
pub struct GatewayRuntime {
    pub gateway_id: String,
    pub node_id: String,
    pub serving: bool,
    pub healthy: bool,
    pub active_source_index: usize,
    pub last_error: Option<String>,
    pub last_health_check_unix: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_sessions: u32,
    /// One of "fast" / "ok" / "slow" / "cold" — computed from the
    /// source mix. Surfaced as a UI badge so operators don't wire a
    /// VM disk to an S3-backed share by accident.
    pub performance_tier: String,
    pub mount_path: Option<String>,
}

// ─── GatewayStore ───

/// Persisted set of gateways for this node. Cluster-synced via the
/// existing inter-node secret-header pattern; each node maintains its
/// own copy and pushes/merges on write. The on-disk file is the
/// authoritative source — runtime state lives separately.
#[derive(Default)]
pub struct GatewayStore {
    pub gateways: HashMap<String, Gateway>,
    /// Non-persisted runtime state, keyed by gateway id.
    pub runtime: HashMap<String, GatewayRuntime>,
}

impl GatewayStore {
    pub fn load() -> Self {
        let path = gateways_path();
        let mut store = GatewayStore::default();
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(list) = serde_json::from_str::<Vec<Gateway>>(&content) {
                for g in list {
                    store.gateways.insert(g.id.clone(), g);
                }
            } else {
                tracing::warn!(target: "wolfstack::gateway", "gateways.json present but malformed — starting empty");
            }
        }
        store
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = gateways_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let list: Vec<&Gateway> = self.gateways.values().collect();
        let json = serde_json::to_string_pretty(&list)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::paths::write_secure(&path.to_string_lossy(), json)
            .map_err(|e| std::io::Error::other(e))?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Gateway> {
        self.gateways.get(id)
    }

    /// Insert or replace. `updated_at` is stamped here so callers can
    /// pass a Gateway with an empty timestamp.
    pub fn upsert(&mut self, mut g: Gateway) -> Gateway {
        let now = chrono::Utc::now().to_rfc3339();
        if g.created_at.is_empty() {
            g.created_at = now.clone();
        }
        g.updated_at = now;
        self.gateways.insert(g.id.clone(), g.clone());
        g
    }

    pub fn remove(&mut self, id: &str) -> Option<Gateway> {
        self.runtime.remove(id);
        self.gateways.remove(id)
    }

    /// Merge a peer's snapshot into this store. Most-recent
    /// `updated_at` wins — matches how other config files are
    /// reconciled across the cluster.
    pub fn merge_from_peer(&mut self, peer_list: Vec<Gateway>) -> bool {
        let mut changed = false;
        for incoming in peer_list {
            match self.gateways.get(&incoming.id) {
                Some(existing) if existing.updated_at >= incoming.updated_at => {}
                _ => {
                    self.gateways.insert(incoming.id.clone(), incoming);
                    changed = true;
                }
            }
        }
        changed
    }
}

// ─── Validation ───

/// Validate a Gateway before persisting. Surface every error in one go
/// so the UI can show them all rather than the operator playing
/// whack-a-mole.
pub fn validate(g: &Gateway) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    if g.name.trim().is_empty() {
        errs.push("name is required".into());
    }
    if !g.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        errs.push("name must contain only A-Z, a-z, 0-9, '-' or '_' (Samba share name compatible)".into());
    }
    if g.name.len() > 63 {
        errs.push("name must be 63 characters or fewer".into());
    }
    if g.protocols.is_empty() {
        errs.push("at least one protocol (smb or nfs) is required".into());
    }
    if g.sources.is_empty() {
        errs.push("at least one source is required".into());
    }
    if !g.serve_nodes.is_empty() {
        errs.push(
            "`serve_nodes` is reserved for a future release (v2.0 multi-node serve). \
             Leave empty in v1.0; the gateway runs on whichever node you create it from."
                .into(),
        );
    }
    match g.mode {
        GatewayMode::Single => {
            if g.sources.len() != 1 {
                errs.push("single mode requires exactly one source".into());
            }
        }
        GatewayMode::Failover | GatewayMode::Aggregate | GatewayMode::Sharded => {
            errs.push(format!(
                "{:?} mode is reserved for a future release — only `single` is available in v1.0",
                g.mode
            ));
        }
    }
    // Sources must each pass per-variant validation.
    for (i, s) in g.sources.iter().enumerate() {
        if let Err(e) = sources::validate(s) {
            errs.push(format!("source {}: {}", i, e));
        }
    }
    // Auth checks
    match &g.auth {
        AuthConfig::Anonymous { .. } => {}
        AuthConfig::Users { users, .. } => {
            if users.is_empty() {
                errs.push("auth=users requires at least one user".into());
            }
            for u in users {
                if u.username.trim().is_empty() {
                    errs.push("user with empty username".into());
                }
                // Passwords are managed by Samba directly (set via
                // POST .../users/<n>/password); no validation possible
                // at config-write time.
            }
        }
        AuthConfig::Ad { .. } => {
            errs.push("AD auth is reserved for a future release".into());
        }
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

// ─── Performance tier ───

/// Classify a gateway's expected performance from its sources.
/// Surfaced as a badge in the UI — operators see whether the share
/// is suitable for VM disks vs cold storage.
pub fn performance_tier(g: &Gateway) -> &'static str {
    let mut worst = 0u8;
    for s in &g.sources {
        let rank = match s {
            Source::Local { .. } | Source::WolfDisk { .. } | Source::CephFs { .. } => 0,
            Source::Smb { .. } | Source::Nfs { .. } => 1,
            Source::Sshfs { .. } => 2,
            Source::S3Rclone { .. } => 3,
            Source::ContainerVol { .. } | Source::LxcDir { .. } => 0,
            Source::Rbd { .. } => 0,
            Source::VmExport { .. } => 1,
            Source::PeerGateway { .. } => 2,
        };
        if rank > worst { worst = rank; }
    }
    match worst {
        0 => "fast",
        1 => "ok",
        2 => "slow",
        _ => "cold",
    }
}

// ─── Cluster sync helpers ───

/// Snapshot of the local gateways for peer sync.
pub fn snapshot_for_sync(store: &GatewayStore) -> Vec<Gateway> {
    store.gateways.values().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sources::Source;

    fn ok_gateway(name: &str) -> Gateway {
        Gateway {
            id: "g1".into(),
            name: name.into(),
            cluster: String::new(),
            mode: GatewayMode::Single,
            protocols: vec![Protocol::Smb],
            sources: vec![Source::Local { node_id: "node-a".into(), path: "/srv/data".into() }],
            origin_node_id: "node-a".into(),
            serve_nodes: vec![],
            auth: AuthConfig::Anonymous { writable: false },
            policy: ModePolicy::Single,
            options: GatewayOptions::default(),
            created_at: String::new(),
            updated_at: String::new(),
            disabled: false,
        }
    }

    #[test]
    fn validate_accepts_minimum_valid_gateway() {
        let g = ok_gateway("ops");
        assert!(validate(&g).is_ok());
    }

    #[test]
    fn validate_rejects_empty_name() {
        let mut g = ok_gateway("ops");
        g.name = "".into();
        let errs = validate(&g).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("name is required")), "errs: {:?}", errs);
    }

    #[test]
    fn validate_rejects_share_name_with_special_chars() {
        // Samba section header must be a clean identifier; bracket
        // injection or quoting would break the smb.conf parser.
        for bad in ["ops share", "ops]bad", "../etc", "foo\nbar", "$ipc$"] {
            let mut g = ok_gateway(bad);
            assert!(validate(&g).is_err(), "should reject name: {:?}", bad);
            g.name = bad.into();
        }
    }

    #[test]
    fn validate_rejects_empty_protocols() {
        let mut g = ok_gateway("ops");
        g.protocols.clear();
        assert!(validate(&g).is_err());
    }

    #[test]
    fn validate_rejects_zero_or_multiple_sources_in_single_mode() {
        let mut g = ok_gateway("ops");
        g.sources.clear();
        let errs = validate(&g).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("at least one source")), "{:?}", errs);

        let mut g2 = ok_gateway("ops");
        g2.sources.push(Source::Local { node_id: "node-a".into(), path: "/other".into() });
        let errs2 = validate(&g2).unwrap_err();
        assert!(errs2.iter().any(|e| e.contains("single mode requires exactly one source")), "{:?}", errs2);
    }

    #[test]
    fn validate_rejects_non_single_modes_in_v1_0() {
        for mode in [GatewayMode::Failover, GatewayMode::Aggregate, GatewayMode::Sharded] {
            let mut g = ok_gateway("ops");
            g.mode = mode.clone();
            let errs = validate(&g).unwrap_err();
            assert!(errs.iter().any(|e| e.contains("reserved for a future release")),
                "mode {:?} should be rejected, got {:?}", mode, errs);
        }
    }

    #[test]
    fn validate_rejects_non_empty_serve_nodes_in_v1_0() {
        // serve_nodes is reserved for v2.0 multi-node serve. v1.0 must
        // refuse it cleanly, otherwise operators get silent
        // "I set this but it's ignored" behaviour.
        let mut g = ok_gateway("ops");
        g.serve_nodes = vec!["node-b".into()];
        let errs = validate(&g).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("serve_nodes")), "{:?}", errs);
    }

    #[test]
    fn validate_rejects_users_auth_with_no_users() {
        let mut g = ok_gateway("ops");
        g.auth = AuthConfig::Users { users: vec![], default_writable: true };
        let errs = validate(&g).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("at least one user")), "{:?}", errs);
    }

    #[test]
    fn validate_rejects_path_traversal_in_subpath() {
        // Three forms of path-traversal at config-save time. The
        // runtime safe_join provides a second line of defence (symlink
        // tricks); this test pins the validator's behaviour.
        let mut g = ok_gateway("ops");
        g.sources = vec![Source::Smb {
            server: "10.0.0.1".into(),
            share: "media".into(),
            subpath: Some("../etc".into()),
            username: None, password: None, domain: None, options: None,
        }];
        let errs = validate(&g).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("..") || e.contains("traversal")
                || e.contains("not contain")), "expected traversal rejection, got {:?}", errs);

        g.sources = vec![Source::Smb {
            server: "10.0.0.1".into(),
            share: "media".into(),
            subpath: Some("/absolute".into()),
            username: None, password: None, domain: None, options: None,
        }];
        assert!(validate(&g).is_err(), "absolute subpath should be rejected");

        g.sources = vec![Source::Nfs {
            server: "10.0.0.1".into(),
            export: "/mnt".into(),
            subpath: Some("ok/../../escape".into()),
            options: None,
        }];
        assert!(validate(&g).is_err(), "nested .. should be rejected");
    }

    #[test]
    fn validate_rejects_local_path_under_system_dirs() {
        for bad in ["/etc/wolfstack", "/proc/1", "/sys", "/dev/null", "/boot/efi"] {
            let mut g = ok_gateway("ops");
            g.sources = vec![Source::Local { node_id: "node-a".into(), path: bad.into() }];
            assert!(validate(&g).is_err(), "should reject system path: {}", bad);
        }
    }

    #[test]
    fn performance_tier_picks_worst_source() {
        let local = Source::Local { node_id: "n".into(), path: "/srv".into() };
        let smb = Source::Smb {
            server: "x".into(), share: "y".into(), subpath: None,
            username: None, password: None, domain: None, options: None,
        };
        let s3 = Source::S3Rclone { remote_id: "r".into(), bucket: "b".into(), prefix: None };

        let mut g = ok_gateway("ops");
        g.sources = vec![local.clone()];
        assert_eq!(performance_tier(&g), "fast");
        g.sources = vec![smb.clone()];
        assert_eq!(performance_tier(&g), "ok");
        g.sources = vec![s3.clone()];
        assert_eq!(performance_tier(&g), "cold");
        // Mixed → worst tier wins (so operators can't accidentally
        // mark a cold-backed gateway as fast).
        g.sources = vec![local, s3];
        assert_eq!(performance_tier(&g), "cold");
    }

    #[test]
    fn merge_from_peer_uses_most_recent_updated_at() {
        let mut store = GatewayStore::default();

        let mut older = ok_gateway("ops");
        older.updated_at = "2026-01-01T00:00:00Z".into();
        store.upsert(older); // NB: upsert re-stamps updated_at = now

        let mut newer = ok_gateway("ops");
        // Far future so it's unambiguously newer than upsert's now-stamp —
        // a near-term date here silently decays into the past and the merge
        // (correctly) keeps the now-stamped local copy, failing the test.
        newer.updated_at = "2099-06-01T00:00:00Z".into();
        newer.options.readonly = true; // distinguishing change

        let changed = store.merge_from_peer(vec![newer]);
        assert!(changed);
        let stored = store.get("g1").unwrap();
        assert_eq!(stored.updated_at, "2099-06-01T00:00:00Z");
        assert!(stored.options.readonly, "newer payload should win");
    }

    #[test]
    fn merge_from_peer_ignores_older_updates() {
        // Last-write-wins must be strict — a peer that comes back
        // online with a STALE config shouldn't overwrite this node's
        // newer state.
        let mut store = GatewayStore::default();
        let mut newer = ok_gateway("ops");
        newer.updated_at = "2026-06-01T00:00:00Z".into();
        newer.options.readonly = true;
        store.upsert(newer);

        let mut older = ok_gateway("ops");
        older.updated_at = "2026-01-01T00:00:00Z".into();
        older.options.readonly = false;

        let changed = store.merge_from_peer(vec![older]);
        assert!(!changed, "older payload must not overwrite newer");
        assert!(store.get("g1").unwrap().options.readonly);
    }

    #[test]
    fn upsert_stamps_updated_at_and_creates_created_at() {
        let mut store = GatewayStore::default();
        let g = ok_gateway("ops");
        let stored = store.upsert(g);
        assert!(!stored.created_at.is_empty(), "created_at should be stamped");
        assert!(!stored.updated_at.is_empty(), "updated_at should be stamped");
        // Second upsert preserves created_at, advances updated_at.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut g2 = stored.clone();
        g2.options.readonly = true;
        let stored2 = store.upsert(g2);
        assert_eq!(stored.created_at, stored2.created_at, "created_at must not change on update");
        assert!(stored2.updated_at >= stored.updated_at);
    }

    #[test]
    fn resolve_tier_via_validator_consistency() {
        // resolve_tier in compat::mod.rs is for licence tiers (different
        // module). Here we pin the gateway equivalent: performance_tier
        // must be deterministic for the same input.
        let g = ok_gateway("ops");
        assert_eq!(performance_tier(&g), performance_tier(&g));
    }
}

/// Reconcile on-disk daemon configuration with the current gateway
/// store. Removes:
///
///   1. Orphaned Samba snippets / NFS exports / mount trees whose ID
///      isn't in `gateways.json` (failed creates from before the
///      apply-then-teardown landed, or a peer-pushed delete that
///      arrived while this node was offline).
///   2. Snippets/exports for gateways owned by *another* node — only
///      the owner serves in v1.0. Pre-v22.9 multi-node clusters where
///      every peer applied every gateway leave stale serving state on
///      non-owner peers; this purges it.
///
/// Called once on startup with the local `node_id` so we can tell
/// whether each known gateway is "ours to serve" or "a peer's".
pub fn reconcile_on_startup(store: &GatewayStore, local_node_id: &str) {
    // Set of IDs that this node should leave configs in place for —
    // i.e. the gateways this node owns. Peer-owned gateways are still
    // "known" but their configs must be purged from this node.
    let owned: std::collections::HashSet<String> = store.gateways.values()
        .filter(|g| g.origin_node_id.is_empty() || g.origin_node_id == local_node_id)
        .map(|g| g.id.clone())
        .collect();
    let known = &owned;

    // Samba snippets — match by filename stem.
    let snippets_dir = std::path::Path::new("/etc/samba/wolfstack-gateways.d");
    if let Ok(rd) = std::fs::read_dir(snippets_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("conf") { continue; }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if !known.contains(&stem) {
                let _ = std::fs::remove_file(&path);
                tracing::info!(target: "wolfstack::gateway", "reconciled orphan samba snippet: {}", path.display());
            }
        }
    }

    // NFS exports — match by `wolfstack-<id>.exports`.
    let exports_dir = std::path::Path::new("/etc/exports.d");
    if let Ok(rd) = std::fs::read_dir(exports_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|x| x.to_str()) { Some(s) => s, None => continue };
            if !name.starts_with("wolfstack-") || !name.ends_with(".exports") { continue; }
            let id = name.trim_start_matches("wolfstack-").trim_end_matches(".exports");
            if !known.contains(id) {
                let _ = std::fs::remove_file(&path);
                tracing::info!(target: "wolfstack::gateway", "reconciled orphan nfs export: {}", path.display());
            }
        }
    }

    // Per-gateway mount roots.
    let mount_root = std::path::Path::new("/var/lib/wolfstack/gateways");
    if let Ok(rd) = std::fs::read_dir(mount_root) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }
            let id = match path.file_name().and_then(|x| x.to_str()) { Some(s) => s, None => continue };
            if !known.contains(id) {
                // Best-effort unmount everything inside, then drop.
                if let Ok(inside) = std::fs::read_dir(&path) {
                    for e in inside.flatten() {
                        let p = e.path();
                        if p.file_name().and_then(|x| x.to_str()) == Some("share")
                           || p.file_name().and_then(|x| x.to_str()).map(|s| s.starts_with("source-")).unwrap_or(false)
                        {
                            let _ = std::process::Command::new("umount").arg("-l").arg(&p).status();
                        }
                    }
                }
                let _ = std::fs::remove_dir_all(&path);
                tracing::info!(target: "wolfstack::gateway", "reconciled orphan mount tree: {}", path.display());
            }
        }
    }

    // After purging snippets, rebuild the Samba aggregator and reload
    // smbd so the changes take effect. Best-effort — fail silently if
    // smbd isn't running yet (it'll pick up the new aggregator on
    // next start).
    let _ = std::fs::write(
        "/etc/samba/wolfstack-gateways.conf",
        rebuild_aggregator_for_reconcile(store),
    );
    let _ = std::process::Command::new("smbcontrol").args(["smbd", "reload-config"]).status();
    let _ = std::process::Command::new("exportfs").arg("-ra").status();
}

/// Same content as `samba::render_aggregator` but without recursion
/// into the gateway store (we already hold the snapshot).
fn rebuild_aggregator_for_reconcile(store: &GatewayStore) -> String {
    let workgroup = store.gateways.values()
        .find(|g| g.protocols.contains(&Protocol::Smb)
            && !g.options.smb_workgroup.trim().is_empty())
        .map(|g| g.options.smb_workgroup.trim().to_string())
        .unwrap_or_else(|| "WORKGROUP".to_string());
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — do not edit\n");
    out.push_str("# Per-gateway snippets live in /etc/samba/wolfstack-gateways.d/*.conf\n\n");
    out.push_str("[global]\n");
    out.push_str(&format!("    workgroup = {}\n", workgroup));
    out.push_str("    server string = WolfStack Gateway %h\n");
    out.push_str("    server role = standalone server\n");
    out.push_str("    log file = /var/log/samba/log.%m\n");
    out.push_str("    max log size = 1000\n");
    out.push_str("    map to guest = bad user\n");
    out.push_str("    passdb backend = tdbsam\n");
    out.push_str("    smb encrypt = auto\n");
    out.push_str("    server min protocol = SMB2_10\n");
    out.push_str("    client min protocol = SMB2_10\n");
    out.push_str("    panic action = /usr/share/samba/panic-action %d\n");
    out.push_str("    obey pam restrictions = no\n");
    out.push_str("    unix password sync = no\n\n");
    if let Ok(entries) = std::fs::read_dir("/etc/samba/wolfstack-gateways.d") {
        let mut paths: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("conf"))
            .collect();
        paths.sort();
        for p in paths {
            if let Ok(s) = std::fs::read_to_string(&p) {
                out.push_str(&s);
                if !s.ends_with('\n') { out.push('\n'); }
            }
        }
    }
    out
}
