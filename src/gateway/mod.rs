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
    /// node_ids (self_ids) that should run the share daemons. Empty
    /// = serve from the operator's current node only.
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
// password by piping plaintext directly into `smbpasswd`/`pdbedit`
// (which holds it in Samba's tdbsam at /var/lib/samba/private/passdb.tdb,
// 0600 root-only). Multi-node password replication is a v2.0 concern
// (CTDB shared pdb backend); single-node v1.0 leaves passwords on
// the serve node alone — same trust boundary as any traditional NAS.

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
    #[serde(default)]
    pub nfs_version: NfsVersion,
    /// CIDR allowlist. Empty = allow any.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default)]
    pub case_sensitive: Option<bool>,
    #[serde(default)]
    pub max_connections: Option<u32>,
}

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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum NfsVersion {
    V3,
    #[default]
    V4,
    V4_2,
}

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

/// Reconcile on-disk daemon configuration with the current gateway
/// store. Removes orphaned Samba snippets, NFS exports, and per-gateway
/// mount roots whose ID is no longer in `gateways.json`.
///
/// Called once on startup. Catches three classes of leak:
///   * a previous create that wrote a Samba snippet but failed before
///     the gateway was persisted (fixed by apply-then-teardown, but
///     this catches any historical leftovers);
///   * a peer-pushed delete that arrived while this node was offline;
///   * an operator who hand-edited `gateways.json` and removed a row.
pub fn reconcile_on_startup(store: &GatewayStore) {
    let known: std::collections::HashSet<String> = store.gateways.keys().cloned().collect();

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
fn rebuild_aggregator_for_reconcile(_store: &GatewayStore) -> String {
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — do not edit\n");
    out.push_str("# Per-gateway snippets live in /etc/samba/wolfstack-gateways.d/*.conf\n\n");
    out.push_str("[global]\n");
    out.push_str("    workgroup = WORKGROUP\n");
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
