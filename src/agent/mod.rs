// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Agent — handles server-to-server communication
//!
//! Each WolfStack instance runs an agent that:
//! - Reports its metrics to the cluster
//! - Accepts commands from other WolfStack nodes
//! - Discovers other nodes (via WolfNet or direct IP)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::monitoring::SystemMetrics;
use crate::installer::ComponentStatus;

/// Per-file result of `leave_wipe_membership_files`. A `cleared` of
/// `false` either means the file was already absent (treat as success)
/// or the unlink failed; `error` differentiates the two so the CLI can
/// print a useful message and the HTTP handler can surface it to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct LeaveWipeFile {
    pub path: String,
    pub cleared: bool,
    pub already_absent: bool,
    pub error: Option<String>,
}

/// Summary of the on-disk side of leaving the cluster. Returned by
/// `leave_wipe_membership_files` and surfaced to both the CLI and the
/// HTTP response. `previous_cluster_name` is captured before deletion
/// so the operator can see which cluster they were just in.
#[derive(Debug, Clone, Serialize)]
pub struct LeaveWipeResult {
    pub previous_cluster_name: Option<String>,
    pub files: Vec<LeaveWipeFile>,
}

/// Delete the on-disk files that make this node a member of its cluster:
///   • `self_cluster.json`  — this node's chosen cluster name
///   • `nodes.json`         — every peer we know about
///   • `deleted_nodes.json` — tombstones (stale once we're starting fresh)
///   • `node_id`            — this node's stable identity; regenerated on
///                            next start so any tombstones held by old peers
///                            for our prior ID can't block a clean re-join
///
/// Does NOT touch `custom-cluster-secret` — secret rotation is a separate
/// opt-in step so the operator can decide whether to lock old peers out.
/// Caller is responsible for ensuring the running service won't immediately
/// re-write these files (`ClusterState::clear_membership_in_memory` first,
/// or stop the service for the CLI path).
pub fn leave_wipe_membership_files() -> LeaveWipeResult {
    let p = crate::paths::get();
    let previous_cluster_name = std::fs::read_to_string(&p.self_cluster_config)
        .ok()
        .and_then(|s| serde_json::from_str::<String>(s.trim()).ok())
        .filter(|s| !s.is_empty());

    let targets = [
        p.self_cluster_config.clone(),
        p.nodes_config.clone(),
        p.deleted_nodes_config.clone(),
        p.node_id_file.clone(),
    ];

    let mut files = Vec::with_capacity(targets.len());
    for path in &targets {
        match std::fs::remove_file(path) {
            Ok(()) => files.push(LeaveWipeFile {
                path: path.clone(),
                cleared: true,
                already_absent: false,
                error: None,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => files.push(LeaveWipeFile {
                path: path.clone(),
                cleared: false,
                already_absent: true,
                error: None,
            }),
            Err(e) => files.push(LeaveWipeFile {
                path: path.clone(),
                cleared: false,
                already_absent: false,
                error: Some(e.to_string()),
            }),
        }
    }
    LeaveWipeResult { previous_cluster_name, files }
}

/// Check whether `wolfstack.service` is currently active. Used by the
/// `--leave-cluster` CLI to refuse a wipe while the daemon is running
/// (otherwise its in-memory copies would race-rewrite the files we just
/// deleted). Returns `None` when systemctl isn't available — caller
/// should treat that as "unknown, allow with warning".
pub fn leave_is_service_active() -> Option<bool> {
    let out = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "wolfstack"])
        .status()
        .ok()?;
    Some(out.success())
}

/// Check if an address is on a private/local network (RFC1918 + loopback + link-local)
/// This is used to restrict gossip auto-discovery to local networks only.
fn is_private_address(addr: &str) -> bool {
    // Parse as IP address
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private()       // 10.x, 172.16-31.x, 192.168.x
                || v4.is_loopback()   // 127.x
                || v4.is_link_local() // 169.254.x
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()      // ::1
            }
        }
    } else {
        // Not a valid IP (could be a hostname) — treat as local
        // This handles things like "localhost" or hostnames on local DNS
        true
    }
}

/// An address peers can actually CONNECT to. A node advertises its own address
/// as the bind address (`cli.bind`, usually the wildcard `0.0.0.0`), which is
/// unreachable from anywhere else — so a self-entry carrying `0.0.0.0` must
/// never be added or used to overwrite a real address. Peers learn a node's
/// real address from the source IP of its inbound pushes instead (GitHub: the
/// hub "main" was missing from every other node because its self-entry's
/// 0.0.0.0 failed is_private_address).
pub fn is_usable_addr(addr: &str) -> bool {
    let a = addr.trim();
    !a.is_empty()
        && a != "0.0.0.0"
        && a != "::"
        && a != "[::]"
        && a != "0.0.0.0/0"
        && !a.starts_with("0.0.0.0:")
        && !a.starts_with("[::]:")
}

/// Track consecutive poll failures per node — only mark offline after 2+ failures
static POLL_FAIL_COUNTS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, u32>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// A node in the WolfStack cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub hostname: String,
    pub address: String,
    pub port: u16,
    pub last_seen: u64,     // unix timestamp
    pub metrics: Option<SystemMetrics>,
    pub components: Vec<ComponentStatus>,
    pub online: bool,
    pub is_self: bool,
    #[serde(default)]
    pub docker_count: u32,
    #[serde(default)]
    pub lxc_count: u32,
    #[serde(default)]
    pub vm_count: u32,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_node_type")]
    pub node_type: String,              // "wolfstack" or "proxmox"
    #[serde(default)]
    pub pve_token: Option<String>,      // PVEAPIToken string
    #[serde(default)]
    pub pve_fingerprint: Option<String>,
    #[serde(default)]
    pub pve_node_name: Option<String>,  // Proxmox node name for API calls
    #[serde(default)]
    pub pve_cluster_name: Option<String>, // User-friendly cluster name for sidebar grouping
    #[serde(default)]
    pub cluster_name: Option<String>,     // Generic cluster name for WolfStack nodes
    #[serde(default)]
    pub join_verified: bool,              // Whether this node was added with a valid join token
    #[serde(default)]
    pub has_docker: bool,                 // Whether Docker is installed on this node
    #[serde(default)]
    pub has_lxc: bool,                    // Whether LXC is installed on this node
    #[serde(default)]
    pub has_kvm: bool,                    // Whether KVM/QEMU is installed on this node
    #[serde(default)]
    pub login_disabled: bool,             // Whether direct login is disabled on this node
    #[serde(default)]
    pub tls: bool,                        // Whether this node serves HTTPS on its main port
    #[serde(default)]
    pub update_script: Option<String>,    // Custom install/update script command
    /// The peer's own self_id (from its `/etc/wolfstack/node_id`). Captured
    /// on first successful poll. Cluster.nodes is keyed by a locally-assigned
    /// `node-{uuid}` ID, but topology / router config / WolfNet endpoints
    /// stamp responses with the peer's self_id — so cross-node proxy lookups
    /// must accept either form. `get_node` falls back to a self_id scan when
    /// the direct key lookup misses; this field is what that scan reads.
    /// `None` until the first poll succeeds (and forever for self).
    #[serde(default)]
    pub self_id: Option<String>,
    /// Workload subnets (Docker / LXC / VM bridges) on this peer. Shipped
    /// in every StatusReport so the cluster can detect when WolfRouter
    /// subnet_routes are missing for a remote peer's workloads — that's
    /// the "peers reachable but the VMs behind them aren't" symptom Klas
    /// 2026-05-11 hit, and what the `missing_wolfnet_subnet_route`
    /// analyzer scans for. Empty for self until populated by the agent
    /// loop on first poll. Backward-compat: nodes from older versions
    /// deserialize this as an empty Vec.
    #[serde(default)]
    pub workload_subnets: Vec<String>,
    /// Optional physical-location tag declared by the operator. Two
    /// nodes that share a `site` are considered to be on the same
    /// L2/L3 LAN and can dial each other directly at their
    /// `lan_address`; nodes with different sites (or one tagged + one
    /// untagged in a way that doesn't match) must go via public IP.
    ///
    /// Drives `pick_wolfnet_endpoint` in the cluster-sync. When `None`,
    /// `networking::effective_site` falls back to the first three
    /// octets of `address` (e.g. `auto:192.168.10`) so single-LAN
    /// clusters keep their pre-tag behaviour — all members share an
    /// auto-derived site and dial directly. The operator-set value
    /// overrides the auto-derived one and is what shows up in the
    /// UI's "Site" field.
    ///
    /// Backward-compat: serializes/deserializes as missing for older
    /// configs and older peers (gossip stays compatible).
    #[serde(default)]
    pub site: Option<String>,
}

fn default_node_type() -> String { "wolfstack".to_string() }

/// Read this node's ID from the persisted file (cheap, no state needed)
pub fn self_node_id() -> String {
    std::fs::read_to_string(&crate::paths::get().node_id_file)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Cluster state
pub struct ClusterState {
    pub nodes: RwLock<HashMap<String, Node>>,
    pub self_id: String,
    pub self_address: String,
    pub port: u16,
    /// Tombstone set: node IDs that were explicitly deleted and must not be re-added by gossip
    deleted_ids: RwLock<HashSet<String>>,
}

impl ClusterState {
    fn nodes_file() -> String { crate::paths::get().nodes_config }
    fn deleted_file() -> String { crate::paths::get().deleted_nodes_config }
    fn self_cluster_file() -> String { crate::paths::get().self_cluster_config }
    fn self_site_file() -> String { crate::paths::get().self_site_config }
    const SELF_LOGIN_DISABLED_FILE: &'static str = "/etc/wolfstack/login_disabled";

    pub fn new(self_id: String, self_address: String, port: u16) -> Self {
        let state = Self {
            nodes: RwLock::new(HashMap::new()),
            self_id,
            self_address,
            port,
            deleted_ids: RwLock::new(HashSet::new()),
        };
        // Load persisted state
        state.load_deleted_ids();
        state.load_nodes();
        // Auto-remove legacy Proxmox-API entries (writes a one-shot notice for the UI)
        state.cleanup_proxmox_legacy();
        // Remove ghost nodes (same IP/port but different ID)
        state.cleanup_ghosts();
        // Purge unverified wolfstack nodes (except self)
        state.purge_unverified();
        // Heal a list bloated by a pre-fix build: collapse duplicate records
        // (the multi-homed self_id explosion). This self-recovers a node hit by
        // the v24.27 convergence storm on its first restart after upgrading.
        // NOTE: peers are NEVER dropped for belonging to another named cluster —
        // control-plane replication shows the whole multi-cluster fleet.
        let pruned = state.prune_duplicate_nodes();
        if pruned > 0 {
            tracing::warn!(
                "cluster: collapsed {} duplicate node record(s) in membership at startup",
                pruned
            );
        }
        state
    }

    /// Remove ghost nodes: nodes with same hostname or matching self_id pattern but different ID
    fn cleanup_ghosts(&self) {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut nodes = self.nodes.write().unwrap();
        
        // Collect IDs of ghost nodes to remove:
        // - Any non-self WolfStack node whose hostname matches ours (previous restarts of this server)
        // - Any non-self node whose ID matches our self_id (shouldn't happen, but safety)
        let ghost_ids: Vec<String> = nodes.values()
            .filter(|n| {
                if n.is_self || n.id == self.self_id {
                    return false;
                }
                // Ghost: same hostname + same port + wolfstack type
                n.hostname == hostname && n.port == self.port && n.node_type == "wolfstack"
            })
            .map(|n| n.id.clone())
            .collect();

        for id in &ghost_ids {
            nodes.remove(id);
        }

        if !ghost_ids.is_empty() {

            // Persist the cleaned-up state
            drop(nodes);
            self.save_nodes();
        }
    }

    /// Remove non-self WolfStack nodes that were not added with a verified join token
    fn purge_unverified(&self) {
        let mut nodes = self.nodes.write().unwrap();
        let unverified: Vec<String> = nodes.values()
            .filter(|n| !n.is_self && n.node_type == "wolfstack" && !n.join_verified)
            .map(|n| n.id.clone())
            .collect();

        for id in &unverified {
            nodes.remove(id);
        }

        if !unverified.is_empty() {
            tracing::warn!("Purged {} unverified WolfStack node(s)", unverified.len());
            drop(nodes);
            self.save_nodes();
        }
    }

    /// Load saved remote nodes from disk
    fn load_nodes(&self) {
        if let Ok(data) = std::fs::read_to_string(&Self::nodes_file()) {
            if let Ok(saved) = serde_json::from_str::<Vec<Node>>(&data) {
                let mut nodes = self.nodes.write().unwrap();
                for mut node in saved {
                    node.online = false; // Will be updated by polling
                    node.is_self = false;
                    // H7 fix: do NOT silently overwrite `None` cluster_name
                    // with the hardcoded "WolfStack" — that masks the
                    // genuine "this peer was never assigned to a cluster"
                    // state. The sidebar grouping handles None at display
                    // time via its own normalise() helper.
                    nodes.insert(node.id.clone(), node);
                }
            }
        }
    }

    /// Save remote nodes to disk
    pub fn save_nodes(&self) {
        let nodes = self.nodes.read().unwrap();
        let remote_nodes: Vec<&Node> = nodes.values()
            .filter(|n| !n.is_self)
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&remote_nodes) {
            let path = Self::nodes_file();
            // Written with mode 0600 because each Node row embeds the
            // peer's pve_token (if any) and pve_fingerprint. Pre-v18.7.27
            // nodes.json was world-readable — any unprivileged local user
            // could siphon every PVE API token on the cluster.
            if let Err(e) = crate::paths::write_secure(&path, json) {
                warn!("Failed to save nodes: {}", e);
            }
        }
    }

    /// Update this node's own status
    pub fn update_self(&self, metrics: SystemMetrics, components: Vec<ComponentStatus>, docker_count: u32, lxc_count: u32, vm_count: u32, public_ip: Option<String>, has_docker: bool, has_lxc: bool, has_kvm: bool, tls_enabled: bool) {
        let mut nodes = self.nodes.write().unwrap();
        // Fetch existing cluster_name: in-memory first, then persisted file, then default
        let cluster_name = nodes.get(&self.self_id)
            .and_then(|n| n.cluster_name.clone())
            .or_else(|| Self::load_self_cluster_name())
            .or_else(|| Some("WolfStack".to_string()));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let prev_login_disabled = nodes.get(&self.self_id).map(|n| n.login_disabled);
        let prev_update_script = nodes.get(&self.self_id).and_then(|n| n.update_script.clone());
        // Site is persisted to disk via the same path as cluster_name —
        // in-memory if present, else the file written by
        // `update_node_settings`, else None (which lets the cluster-sync
        // auto-derive the site from this node's address).
        let prev_site = nodes.get(&self.self_id)
            .and_then(|n| n.site.clone())
            .or_else(Self::load_self_site);
        nodes.insert(self.self_id.clone(), Node {
            id: self.self_id.clone(),
            hostname: metrics.hostname.clone(),
            address: self.self_address.clone(),
            port: self.port,
            last_seen: now,
            metrics: Some(metrics),
            components,
            online: true,
            is_self: true,
            docker_count,
            lxc_count,
            vm_count,
            public_ip,
            node_type: "wolfstack".to_string(),
            pve_token: None,
            pve_fingerprint: None,
            pve_node_name: None,

            pve_cluster_name: None,
            cluster_name,
            join_verified: true, // self is always verified
            has_docker,
            has_lxc,
            has_kvm,
            login_disabled: prev_login_disabled.or_else(|| Self::load_self_login_disabled()).unwrap_or(false),
            tls: tls_enabled,
            update_script: prev_update_script,
            // Self's id IS the self_id by construction; the field is for
            // OTHER nodes' self_ids as observed via polling. Self has no
            // need to record one.
            self_id: None,
            // Snapshot the current workload subnets — Docker / LXC / VM
            // bridges live on this node. Other peers consume this via
            // gossip to detect missing subnet_routes.
            workload_subnets: crate::networking::collect_workload_subnets(),
            site: prev_site,
        });
    }

    /// Update a remote node's status
    pub fn update_remote(&self, node: Node) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node.id.clone(), node);
    }

    /// Get all nodes (deduplicated: if a non-self WolfStack node has same hostname+port as self, skip it)
    pub fn get_all_nodes(&self) -> Vec<Node> {
        let nodes = self.nodes.read().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Find self node's hostname and port for dedup
        let self_hostname = nodes.get(&self.self_id).map(|n| n.hostname.clone()).unwrap_or_default();
        let self_port = self.port;
        nodes.values().filter(|n| {
            // Filter out non-self wolfstack nodes that are actually us (duplicate from gossip)
            if !n.is_self && n.id != self.self_id && n.node_type == "wolfstack"
                && n.hostname == self_hostname && n.port == self_port {
                return false;
            }
            true
        }).map(|n| {
            let mut node = n.clone();
            if !node.is_self {
                node.online = now - node.last_seen < 60;
            }
            node
        }).collect()
    }

    /// Get a single node by either its locally-assigned cluster key
    /// (`node-{uuid}`) or its self-reported self_id (from
    /// `/etc/wolfstack/node_id` on the peer). The direct key lookup
    /// is the hot path; the self_id scan handles cross-node calls
    /// where the caller (WolfRouter topology, LAN records, WolfNet
    /// peer tables) only knows the peer's self_id. Linear scan is
    /// fine — clusters are tens of nodes, not thousands.
    pub fn get_node(&self, id: &str) -> Option<Node> {
        let nodes = self.nodes.read().unwrap();
        if let Some(n) = nodes.get(id) { return Some(n.clone()); }
        nodes.values().find(|n| n.self_id.as_deref() == Some(id)).cloned()
    }

    /// Get this node's cluster name
    pub fn get_self_cluster_name(&self) -> String {
        let nodes = self.nodes.read().unwrap();
        nodes.get(&self.self_id)
            .and_then(|n| n.cluster_name.clone())
            .unwrap_or_else(|| "WolfStack".to_string())
    }

    /// Add a server by address — persists to disk (join_verified=true because only called after token validation)
    pub fn add_server(&self, address: String, port: u16, cluster_name: Option<String>) -> String {
        let id = self.add_server_full(address, port, "wolfstack".to_string(), None, None, None, None, cluster_name);
        self.mark_verified(&id);
        id
    }

    /// Add a Proxmox server (always verified — PVE API token is its own auth)
    #[allow(dead_code)]
    pub fn add_proxmox_server(&self, address: String, port: u16, token: String, fingerprint: Option<String>, node_name: String, pve_cluster_name: Option<String>) -> String {
        // Use pve_cluster_name as the generic cluster_name too
        let id = self.add_server_full(address, port, "proxmox".to_string(), Some(token), fingerprint, Some(node_name), pve_cluster_name.clone(), pve_cluster_name);
        self.mark_verified(&id);
        id
    }

    /// Mark a node as join-verified
    pub fn mark_verified(&self, id: &str) {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            node.join_verified = true;
        }
        drop(nodes);
        self.save_nodes();
    }

    /// Add a server with full options (deduplicates by address+port+pve_node_name)
    fn add_server_full(&self, address: String, port: u16, node_type: String, pve_token: Option<String>, pve_fingerprint: Option<String>, pve_node_name: Option<String>, pve_cluster_name: Option<String>, cluster_name: Option<String>) -> String {
        let mut nodes = self.nodes.write().unwrap();
        
        // Dedup: check if a node with the same address+port+node_type already exists
        if let Some(existing) = nodes.values().find(|n| {
            n.address == address && n.port == port && n.node_type == node_type
                && n.pve_node_name == pve_node_name
        }) {
            let existing_id = existing.id.clone();

            return existing_id;
        }
        
        let id = format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        nodes.insert(id.clone(), Node {
            id: id.clone(),
            hostname: address.clone(),
            address,
            port,
            last_seen: now,
            metrics: None,
            components: vec![],
            online: false,
            is_self: false,
            docker_count: 0,
            lxc_count: 0,
            vm_count: 0,
            public_ip: None,
            node_type,
            pve_token,
            pve_fingerprint,
            pve_node_name,
            pve_cluster_name,
            cluster_name,
            join_verified: false, // will be set true by add_node after token validation
            has_docker: false,
            has_lxc: false,
            has_kvm: false,
            login_disabled: false,
            tls: false,
            update_script: None,
            // Filled in on first successful poll from the peer's status report.
            self_id: None,
            workload_subnets: Vec::new(),
            // Site arrives on the first successful poll (gossip carries
            // each peer's own declared site). Until then we don't know
            // it; effective_site() will auto-derive from the address.
            site: None,
        });
        drop(nodes);
        self.save_nodes();
        id
    }

    /// Remove a server — persists to disk and adds to tombstone set
    pub fn remove_server(&self, id: &str) -> bool {
        let mut nodes = self.nodes.write().unwrap();
        let removed = nodes.remove(id).is_some();
        drop(nodes);
        if removed {
            self.save_nodes();
            // Tombstone: prevent gossip from re-adding this node
            self.add_tombstone(id);
        }
        removed
    }

    /// Add a node ID to the tombstone set (prevents gossip re-adding)
    fn add_tombstone(&self, id: &str) {
        let mut deleted = self.deleted_ids.write().unwrap();
        deleted.insert(id.to_string());
        drop(deleted);
        self.save_deleted_ids();
    }

    /// Check if a node ID is tombstoned
    pub fn is_tombstoned(&self, id: &str) -> bool {
        self.deleted_ids.read().unwrap().contains(id)
    }

    /// Merge remote tombstones into local set
    pub fn merge_tombstones(&self, remote_deleted: &[String]) {
        let mut deleted = self.deleted_ids.write().unwrap();
        let mut changed = false;
        for id in remote_deleted {
            if id != &self.self_id && deleted.insert(id.clone()) {
                changed = true;
            }
        }
        drop(deleted);
        if changed {
            // Also remove any nodes that are now tombstoned
            let mut nodes = self.nodes.write().unwrap();
            let to_remove: Vec<String> = nodes.keys()
                .filter(|k| self.deleted_ids.read().unwrap().contains(*k))
                .cloned()
                .collect();
            for id in &to_remove {
                nodes.remove(id);
            }
            drop(nodes);
            self.save_deleted_ids();
            if !to_remove.is_empty() {
                self.save_nodes();

            }
        }
    }

    /// Get the current tombstone set
    pub fn get_deleted_ids(&self) -> Vec<String> {
        self.deleted_ids.read().unwrap().iter().cloned().collect()
    }

    /// Merge a peer's advertised cluster members into our own list so that ANY
    /// node converges to the full mesh — not just the node the cluster was
    /// built on. This is what lets an operator log into a secondary node and
    /// see every other node (the previous behaviour showed only itself,
    /// because membership only ever flowed toward the polling node).
    ///
    /// Conservative and re-injection-safe — mirrors the pull-gossip merge's
    /// rules: it only ADDS peers we don't already know, skips ourselves (by
    /// local id, global self_id, or hostname/address + port), and skips any
    /// tombstoned (operator-removed) node, so it can never resurrect a peer the
    /// operator deleted. Node settings and online status stay owned by the
    /// regular poll — this only seeds the existence of a peer so the poll can
    /// then reach it.
    pub fn merge_member_refs(&self, members: &[Node]) {
        let self_hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let current = self.get_all_nodes();
        // Dedup WITHIN this single bundle too: a sender that hasn't been pruned
        // yet can advertise the same physical node under two record ids sharing
        // one self_id. `current` is a pre-loop snapshot, so without this set both
        // would pass the already-known check and both get inserted.
        let mut added_self_ids: HashSet<String> = HashSet::new();
        for m in members {
            if m.node_type != "wolfstack" { continue; }
            // Skip a self-entry carrying the wildcard bind address (0.0.0.0):
            // it's unreachable, and the sender's REAL address is repaired into
            // the bundle from the connection source IP before we get here.
            if !is_usable_addr(&m.address) { continue; }
            // REQUIRE a stable global self_id before seeding. Without it we can
            // only dedup by address, which FAILS for multi-homed nodes (a node
            // with both a LAN IP and a 10.x WolfNet IP looks like two different
            // peers, and the v24.27 peer-IP repair added a third address
            // variant). That mismatch is what let the same physical node be
            // added over and over until every node's poll list exploded and the
            // 10s poll loop pegged the CPU. Skipping here only DEFERS the seed:
            // the regular pull-gossip poll populates self_id on first contact,
            // after which convergence proceeds with a reliable identity key.
            let m_self_id = match m.self_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };
            // Never seed ourselves as a peer.
            if m.id == self.self_id { continue; }
            if m_self_id == self.self_id.as_str() { continue; }
            if m.hostname == self_hostname && m.port == self.port { continue; }
            if m.address == self.self_address && m.port == self.port { continue; }
            // Already seeded earlier in THIS same bundle (under another record
            // id sharing this self_id)? Skip — the snapshot below can't see it.
            if added_self_ids.contains(m_self_id) { continue; }
            // Never resurrect an operator-removed node (same guard the pull
            // gossip uses).
            if self.is_tombstoned(&m.id) { continue; }
            // Already known — dedup STRICTLY by the stable self_id first, then
            // fall back to id / address+port / hostname+port for records that
            // predate self_id. Leave refinement to the regular poll.
            let already_known = current.iter().any(|n| {
                n.self_id.as_deref() == Some(m_self_id)
                    || n.id == m.id
                    || (n.address == m.address && n.port == m.port && n.pve_node_name == m.pve_node_name)
                    || (n.hostname == m.hostname && n.port == m.port && n.node_type == m.node_type)
            });
            if already_known { continue; }
            // Only auto-seed nodes on private/local networks — a public-IP node
            // must be added manually. Mirrors the pull-gossip guard so a
            // tampered or compromised peer can't make us start polling an
            // attacker-controlled address.
            if !is_private_address(&m.address) { continue; }
            // Mirror the pull-gossip new-node path: carry the peer's full
            // record (id, self_id, cluster_name…), marked offline until our own
            // poll reaches it. (update_remote, NOT add_server — keeps the
            // global self_id so cross-node proxy lookups resolve.)
            let mut new_node = m.clone();
            new_node.online = false;
            new_node.is_self = false;
            self.update_remote(new_node);
            self.save_nodes();
            added_self_ids.insert(m_self_id.to_string());
        }
    }

    /// One-shot cleanup of a node list that a pre-fix build may have bloated:
    /// collapse duplicate records (same global `self_id`, or same address+port)
    /// down to a single best entry. This heals a list exploded by the v24.27
    /// multi-homed convergence storm on the first restart after upgrading — the
    /// operator does not have to hand-edit `nodes.json`.
    ///
    /// Cluster-agnostic by design: control-plane replication shows the WHOLE
    /// fleet across clusters (`cluster_name` is a display grouping, NEVER a
    /// membership boundary), so a peer is never dropped for belonging to a
    /// different named cluster — that mistake (v24.29.1) deleted whole federated
    /// clusters down to a single node. `is_self` is always kept; the keeper for
    /// each duplicate group is the most trustworthy record
    /// (self > verified > online > usable-address). Returns the number of
    /// entries removed. Saves to disk only if something changed.
    pub fn prune_duplicate_nodes(&self) -> usize {
        let mut nodes = self.nodes.write().unwrap();
        let before = nodes.len();
        let entries: Vec<Node> = nodes.values().cloned().collect();
        let remove = Self::plan_prune(entries);
        for id in &remove {
            nodes.remove(id);
        }
        let removed = before.saturating_sub(nodes.len());
        drop(nodes);
        if removed > 0 {
            self.save_nodes();
        }
        removed
    }

    /// Pure decision core of `prune_duplicate_nodes`: given the node records,
    /// return the ids of duplicate records to remove (same global `self_id`, or
    /// same address+port). Cluster membership is never a reason to remove a peer.
    /// Split out so the data-loss-sensitive logic is unit-testable without disk
    /// or a live `ClusterState`.
    fn plan_prune(mut entries: Vec<Node>) -> Vec<String> {
        // Choose keepers deterministically: sort so the best record of each
        // duplicate group is visited first and therefore retained.
        entries.sort_by_key(|n| {
            (
                !n.is_self,                    // self first
                !n.join_verified,              // verified first
                !n.online,                     // online first
                !is_usable_addr(&n.address),   // usable address first
                n.id.clone(),                  // stable tiebreaker (HashMap order is not)
            )
        });

        let mut seen_self_ids: HashSet<String> = HashSet::new();
        let mut seen_addrs: HashSet<String> = HashSet::new();
        let mut remove: Vec<String> = Vec::new();
        for n in &entries {
            if n.is_self {
                continue;
            }
            let sid = n.self_id.as_deref().filter(|s| !s.is_empty());
            let addr_key = if is_usable_addr(&n.address) {
                Some(format!("{}:{}", n.address, n.port))
            } else {
                None
            };
            let dup = sid.map(|s| seen_self_ids.contains(s)).unwrap_or(false)
                || addr_key.as_ref().map(|a| seen_addrs.contains(a)).unwrap_or(false);
            if dup {
                remove.push(n.id.clone());
                continue;
            }
            if let Some(s) = sid {
                seen_self_ids.insert(s.to_string());
            }
            if let Some(a) = addr_key {
                seen_addrs.insert(a);
            }
        }
        remove
    }

    /// Drop every non-self peer and clear all tombstones in memory.
    /// Used by POST /api/cluster/leave so that — during the short window
    /// between the on-disk wipe and the scheduled service restart — any
    /// gossip-triggered `save_nodes()` writes an empty list instead of
    /// resurrecting the cluster we just left. Caller is responsible for
    /// wiping the on-disk files (`leave_wipe_membership_files`).
    pub fn clear_membership_in_memory(&self) {
        let self_id = self.self_id.clone();
        let mut nodes = self.nodes.write().unwrap();
        let keep_self = nodes.remove(&self_id);
        nodes.clear();
        if let Some(s) = keep_self {
            nodes.insert(self_id, s);
        }
        drop(nodes);
        self.deleted_ids.write().unwrap().clear();
    }

    /// Load tombstoned node IDs from disk
    fn load_deleted_ids(&self) {
        if let Ok(data) = std::fs::read_to_string(&Self::deleted_file()) {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&data) {
                let mut deleted = self.deleted_ids.write().unwrap();
                for id in ids {
                    deleted.insert(id);
                }

            }
        }
    }

    /// Save tombstoned node IDs to disk
    fn save_deleted_ids(&self) {
        let deleted = self.deleted_ids.read().unwrap();
        let ids: Vec<&String> = deleted.iter().collect();
        if let Ok(json) = serde_json::to_string_pretty(&ids) {
            let path = Self::deleted_file();
            if let Some(dir) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save deleted nodes: {}", e);
            }
        }
    }

    /// On startup, purge any legacy Proxmox-API entries from nodes.json.
    /// Backs the file up first so the user can recover if needed, then writes
    /// a small notice file the UI reads to render the deprecation banner.
    fn cleanup_proxmox_legacy(&self) {
        let proxmox_entries: Vec<Node> = {
            let nodes = self.nodes.read().unwrap();
            nodes.values().filter(|n| n.node_type == "proxmox").cloned().collect()
        };
        if proxmox_entries.is_empty() {
            return;
        }

        let nodes_path = Self::nodes_file();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let backup_path = format!("{}.proxmox-backup-{}", nodes_path, timestamp);
        if let Err(e) = std::fs::copy(&nodes_path, &backup_path) {
            warn!("Failed to back up nodes.json before Proxmox cleanup: {}", e);
            // Don't proceed with deletion if we can't back up.
            return;
        }

        {
            let mut nodes = self.nodes.write().unwrap();
            let mut deleted = self.deleted_ids.write().unwrap();
            for n in &proxmox_entries {
                nodes.remove(&n.id);
                deleted.insert(n.id.clone());
            }
        }
        self.save_nodes();
        self.save_deleted_ids();

        let addresses: Vec<String> = proxmox_entries.iter()
            .map(|n| {
                let label = n.pve_node_name.clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| n.hostname.clone());
                if label.is_empty() {
                    n.address.clone()
                } else {
                    format!("{} ({})", label, n.address)
                }
            })
            .collect();

        let notice = ProxmoxCleanupNotice {
            removed_count: proxmox_entries.len(),
            addresses,
            backup_path,
            timestamp,
        };
        if let Err(e) = notice.save() {
            warn!("Failed to write Proxmox cleanup notice: {}", e);
        }
        tracing::info!(
            "Removed {} legacy Proxmox-API entries from nodes.json (backed up to {})",
            notice.removed_count, notice.backup_path
        );
    }
}

/// Notice written once on startup when legacy Proxmox-API entries are auto-removed.
/// The UI reads this to render the deprecation banner; deleting the file dismisses it.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProxmoxCleanupNotice {
    pub removed_count: usize,
    pub addresses: Vec<String>,
    pub backup_path: String,
    pub timestamp: u64,
}

impl ProxmoxCleanupNotice {
    fn notice_file() -> String {
        let nodes_path = crate::paths::get().nodes_config.clone();
        // Sit alongside nodes.json: same directory, dedicated name.
        let dir = std::path::Path::new(&nodes_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/etc/wolfstack".to_string());
        format!("{}/proxmox-cleanup.json", dir)
    }

    pub fn load() -> Option<Self> {
        let data = std::fs::read_to_string(Self::notice_file()).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(&self) -> std::io::Result<()> {
        let path = Self::notice_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&path, json)
    }

    pub fn dismiss() -> std::io::Result<()> {
        let path = Self::notice_file();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl ClusterState {

    /// Update node settings (hostname, address, port, token, fingerprint, cluster name, site)
    pub fn update_node_settings(&self, id: &str, hostname: Option<String>, address: Option<String>, port: Option<u16>, pve_token: Option<String>, pve_fingerprint: Option<Option<String>>, cluster_name: Option<String>, login_disabled: Option<bool>, update_script: Option<String>, site: Option<String>) -> bool {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            if let Some(h) = hostname { node.hostname = h; }
            if let Some(a) = address { node.address = a; }
            if let Some(p) = port { node.port = p; }
            if let Some(token) = pve_token { node.pve_token = Some(token); }
            if let Some(fp) = pve_fingerprint { node.pve_fingerprint = fp; }
            if let Some(disabled) = login_disabled { node.login_disabled = disabled; }
            if let Some(script) = update_script { node.update_script = if script.is_empty() { None } else { Some(script) }; }
            if let Some(s) = site.as_ref() {
                // Empty string clears the explicit tag — effective_site
                // will fall back to the auto-derived value. Anything
                // non-empty is the operator's chosen label.
                node.site = if s.is_empty() { None } else { Some(s.clone()) };
            }
            if let Some(ref name) = cluster_name {
                // Update both cluster_name fields so sidebar grouping works
                node.cluster_name = Some(name.clone());
                if node.node_type == "proxmox" {
                    node.pve_cluster_name = Some(name.clone());
                }
            }
            // If updating self node's cluster name, persist it so it survives reinstalls
            let is_self = node.is_self;
            let final_cluster = node.cluster_name.clone();
            let final_site = node.site.clone();
            drop(nodes);
            self.save_nodes();
            if is_self {
                if let Some(ref name) = final_cluster {
                    Self::save_self_cluster_name(name);
                }
                // Persist site for self node — save_nodes skips self so
                // we need a dedicated file (same pattern as cluster_name
                // and login_disabled).
                if site.is_some() {
                    Self::save_self_site(final_site.as_deref().unwrap_or(""));
                }
                // Persist login_disabled for self node (since save_nodes skips self)
                if let Some(disabled) = login_disabled {
                    Self::save_login_disabled_file(disabled);
                }
            }
            true
        } else {
            false
        }
    }

    /// Load persisted self cluster_name from disk
    fn load_self_cluster_name() -> Option<String> {
        if let Ok(data) = std::fs::read_to_string(&Self::self_cluster_file()) {
            if let Ok(name) = serde_json::from_str::<String>(&data) {
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Persist self cluster_name to disk (survives reinstalls)
    pub fn save_self_cluster_name(name: &str) {
        let path = Self::self_cluster_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string(name) {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save self cluster name: {}", e);
            }
        }
    }

    /// Load persisted self site tag from disk. Same path/format as
    /// cluster_name persistence so the two are consistent. Returns
    /// `None` for missing/empty/malformed files; callers fall through
    /// to the auto-derived site.
    fn load_self_site() -> Option<String> {
        if let Ok(data) = std::fs::read_to_string(Self::self_site_file()) {
            if let Ok(name) = serde_json::from_str::<String>(&data) {
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Persist self site tag to disk (survives reinstalls). Empty
    /// string is treated as "clear the file" so the operator can
    /// remove an explicit tag and fall back to auto-derived.
    pub fn save_self_site(site: &str) {
        let path = Self::self_site_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if site.is_empty() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        if let Ok(json) = serde_json::to_string(site) {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save self site: {}", e);
            }
        }
    }

    /// Load persisted login_disabled for self node
    fn load_self_login_disabled() -> Option<bool> {
        if let Ok(data) = std::fs::read_to_string(Self::SELF_LOGIN_DISABLED_FILE) {
            let trimmed = data.trim();
            match trimmed {
                "true" | "1" => return Some(true),
                "false" | "0" => return Some(false),
                _ => {}
            }
        }
        None
    }

    /// Persist self login_disabled to disk
    pub fn save_login_disabled_file(disabled: bool) {
        let _ = std::fs::create_dir_all("/etc/wolfstack");
        if let Err(e) = std::fs::write(Self::SELF_LOGIN_DISABLED_FILE, if disabled { "true" } else { "false" }) {
            warn!("Failed to save self login_disabled: {}", e);
        }
    }

}

/// Message exchanged between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    /// "Hello, here's my status"
    StatusReport {
        node_id: String,
        hostname: String,
        metrics: SystemMetrics,
        components: Vec<ComponentStatus>,
        #[serde(default)]
        docker_count: u32,
        #[serde(default)]
        lxc_count: u32,
        #[serde(default)]
        vm_count: u32,
        #[serde(default)]
        public_ip: Option<String>,
        #[serde(default)]
        known_nodes: Vec<Node>,
        #[serde(default)]
        deleted_ids: Vec<String>,
        /// WolfNet IPs in use on this node (host IP first, then container/VM IPs)
        #[serde(default)]
        wolfnet_ips: Vec<String>,
        #[serde(default)]
        has_docker: bool,
        #[serde(default)]
        has_lxc: bool,
        #[serde(default)]
        has_kvm: bool,
        /// Workload subnets (CIDRs) on this peer — Docker / LXC / VM
        /// bridges. Consumed by the missing-route analyzer so peers see
        /// what subnet_routes need to point at this node. See
        /// `networking::collect_workload_subnets`.
        #[serde(default)]
        workload_subnets: Vec<String>,
        /// Operator-declared physical-location tag — see `Node::site`.
        /// `None` from older peers; the cluster-sync site decision
        /// falls back to auto-derive from address in that case.
        #[serde(default)]
        site: Option<String>,
        /// Enterprise license key — propagated to cluster nodes that don't have one
        #[serde(default)]
        license_key: Option<String>,
    },
    /// "Give me your status"
    StatusRequest,
    /// "Install this component"
    InstallRequest { component: String },
    /// "Start/stop/restart this service"
    ServiceAction { service: String, action: String },
    /// Response
    Response { success: bool, message: String },
}

/// Retroactive cluster-name sweep.
///
/// Background task that iterates every WolfStack peer in this node's
/// `nodes.json`. For each peer where THIS node knows the peer's
/// cluster_name (because we recorded it when add_node was called),
/// push that name to the peer's `/api/agent/cluster-name` endpoint.
///
/// **Why this exists.** The cluster-name push at join time (C1-Fix-2)
/// only helps NEW joins after that fix shipped. Every node joined
/// before the fix has no `/etc/wolfstack/self_cluster.json`, so its
/// per-node WolfRouter preflight reports "(not yet configured)". The
/// fixed gossip path can heal these, but only if specific conditions
/// align (the peer must be polling someone who has it with cluster_name
/// set, AND that someone's record must carry the peer's self_id). For
/// installs joined long ago, those conditions often don't.
///
/// Pushing periodically (every 5 minutes) makes the heal automatic:
/// admin node has the cluster_name on disk, peer receives the push,
/// peer writes self_cluster.json, peer's preflight goes green.
///
/// Idempotent — receiver writes whatever we send. Safe to call
/// repeatedly. No-ops for peers we don't have a cluster_name for, or
/// where the peer is offline (we don't want to retry-spam an
/// unreachable node). Cluster secret used for auth.
pub async fn sweep_push_cluster_names(cluster: Arc<ClusterState>, cluster_secret: String) {
    // Snapshot peers under read lock; release before any HTTP work.
    let peers: Vec<(String, u16, String)> = {
        let nodes = cluster.nodes.read().unwrap();
        nodes.values()
            .filter(|n| !n.is_self)
            .filter(|n| n.node_type == "wolfstack")
            .filter(|n| n.online)
            .filter_map(|n| {
                n.cluster_name.clone().map(|name| (n.address.clone(), n.port, name))
            })
            .collect()
    };
    if peers.is_empty() { return; }
    let client = crate::api::API_HTTP_CLIENT.clone();
    for (address, port, cluster_name) in peers {
        let urls = crate::api::build_node_urls(&address, port, "/api/agent/cluster-name");
        let payload = serde_json::json!({ "cluster_name": cluster_name });
        for url in &urls {
            let r = client.post(url)
                .timeout(std::time::Duration::from_secs(5))
                .header("X-WolfStack-Secret", &cluster_secret)
                .json(&payload)
                .send()
                .await;
            match r {
                Ok(resp) => {
                    let success = resp.status().is_success();
                    let _ = resp.bytes().await;
                    if success { break; }
                }
                Err(_) => { /* try next URL */ }
            }
        }
    }
}

// ─── Control-plane replication (cluster membership + users + auth) ───
//
// So that logging into ANY node shows the same fleet view and the same
// WolfStack users — not just the node the cluster was built on. Membership
// converges (re-injection-safe via tombstones); users.json + auth-config.json
// replicate last-write-wins by their logical version.

/// The replicable control-plane state a node pushes to its peers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlPlaneBundle {
    /// Sender's self_id (diagnostics only).
    #[serde(default)]
    pub from_id: String,
    /// Sender's view of cluster members (metrics stripped) — for convergence.
    #[serde(default)]
    pub members: Vec<Node>,
    /// Sender's tombstones — merged first so we never re-add a removed node.
    #[serde(default)]
    pub deleted_ids: Vec<String>,
    /// Raw users.json (UserStore) + its logical version.
    #[serde(default)]
    pub users_json: String,
    #[serde(default)]
    pub users_version: u64,
    /// Raw auth-config.json (AuthConfig) + its logical version.
    #[serde(default)]
    pub auth_json: String,
    #[serde(default)]
    pub auth_version: u64,
}

/// Build the local control-plane bundle to push to peers. Member metrics and
/// components are stripped — the receiver only needs the existence + address of
/// each peer; status is filled in by its own poll.
pub fn build_control_plane_bundle(cluster: &ClusterState) -> ControlPlaneBundle {
    let (users_json, users_version, auth_json, auth_version) =
        crate::auth::users::control_plane_snapshot();
    let self_id = cluster.self_id.clone();
    // Advertise the WHOLE fleet — control-plane replication is "log into any
    // node, see every cluster". `cluster_name` is a display grouping, not a
    // membership boundary; filtering it here is what severed federated clusters
    // (v24.29.1). The receiver dedups by stable self_id, so multi-homed records
    // can't pile up regardless of how many peers we advertise.
    let members = cluster.get_all_nodes().into_iter()
        .map(|mut n| {
            n.metrics = None;
            n.components = Vec::new();
            // The self-entry's self_id field is None by construction (its id IS
            // the self_id). Stamp it so the receiver can dedup us by the stable
            // global key instead of by address — without this, our hub entry
            // gets re-added under each address variant on every receiver.
            if n.is_self && n.self_id.as_deref().filter(|s| !s.is_empty()).is_none() {
                n.self_id = Some(self_id.clone());
            }
            n
        })
        .collect();
    ControlPlaneBundle {
        from_id: cluster.self_id.clone(),
        members,
        deleted_ids: cluster.get_deleted_ids(),
        users_json,
        users_version,
        auth_json,
        auth_version,
    }
}

/// Apply a received control-plane bundle: merge tombstones, converge
/// membership, then last-write-wins the users/auth blobs. `sender_addr` is the
/// source IP of the inbound connection — used to repair the sender's own
/// member entry, which carries its (unreachable) bind address (0.0.0.0). This
/// is how every other node learns the hub "main"'s real, reachable address.
/// Returns a one-line summary for logging.
pub fn apply_control_plane_bundle(cluster: &ClusterState, bundle: &ControlPlaneBundle, sender_addr: Option<String>) -> String {
    cluster.merge_tombstones(&bundle.deleted_ids);
    let mut members = bundle.members.clone();
    if let Some(addr) = sender_addr.filter(|a| is_usable_addr(a)) {
        // Repair the sender's self-entry (id/self_id == from_id) when it
        // advertised an unusable address — the connection source IP is how it
        // actually reached us, so it's reachable back on the LAN.
        for m in members.iter_mut() {
            let is_sender = m.id == bundle.from_id
                || m.self_id.as_deref() == Some(bundle.from_id.as_str());
            if is_sender && !is_usable_addr(&m.address) {
                m.address = addr.clone();
            }
        }
    }
    cluster.merge_member_refs(&members);
    let (users_updated, auth_updated) = crate::auth::users::control_plane_apply(
        &bundle.users_json,
        bundle.users_version,
        &bundle.auth_json,
        bundle.auth_version,
    );
    format!(
        "members={} users_updated={} auth_updated={}",
        bundle.members.len(), users_updated, auth_updated
    )
}

/// Push our control-plane bundle to every online WolfStack peer. Runs both as
/// a periodic sweep (heals nodes that were offline) and one-shot right after a
/// user/auth change (so edits land in seconds). Cluster-secret authed.
pub async fn sweep_replicate_control_plane(cluster: Arc<ClusterState>, cluster_secret: String) {
    // Emergency kill switch — set WOLFSTACK_DISABLE_CP_SYNC=1 to halt all
    // control-plane replication without a rebuild. A clean off-switch for any
    // future convergence storm.
    if std::env::var("WOLFSTACK_DISABLE_CP_SYNC").map(|v| v != "0" && !v.is_empty()).unwrap_or(false) {
        return;
    }
    // Replicate to every online WolfStack peer across the whole fleet. The CPU
    // storm was unbounded GROWTH of nodes.json (the same multi-homed node
    // re-added under each address forever), now fixed by self_id dedup — NOT the
    // count of distinct peers we push to, which is bounded by the real fleet.
    let peers: Vec<(String, u16)> = {
        let nodes = cluster.nodes.read().unwrap();
        nodes.values()
            .filter(|n| !n.is_self && n.node_type == "wolfstack" && n.online)
            .map(|n| (n.address.clone(), n.port))
            .collect()
    };
    if peers.is_empty() { return; }

    let payload = match serde_json::to_value(build_control_plane_bundle(&cluster)) {
        Ok(v) => v,
        Err(_) => return,
    };
    let client = crate::api::API_HTTP_CLIENT.clone();
    for (address, port) in peers {
        let urls = crate::api::build_node_urls(&address, port, "/api/cluster/control-plane");
        for url in &urls {
            match client.post(url)
                .timeout(std::time::Duration::from_secs(8))
                .header("X-WolfStack-Secret", &cluster_secret)
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let _ = resp.bytes().await;
                    if ok { break; } // delivered — don't try the next URL scheme
                }
                Err(_) => { /* try next URL */ }
            }
        }
    }
}

/// Poll remote nodes for their status
pub async fn poll_remote_nodes(cluster: Arc<ClusterState>, cluster_secret: String, ai_agent: Option<Arc<crate::ai::AiAgent>>) {
    // Snapshot previous online state BEFORE polling
    let previous_states: HashMap<String, (bool, String)> = {
        let nodes = cluster.nodes.read().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        nodes.values()
            .filter(|n| !n.is_self)
            .map(|n| (n.id.clone(), (now - n.last_seen < 60, n.hostname.clone())))
            .collect()
    };

    let nodes = cluster.get_all_nodes();
    // Collect subnet routes from all remote nodes' wolfnet_ips
    let mut subnet_routes: HashMap<String, String> = HashMap::new();
    for node in nodes {
        if node.is_self { continue; }

        if node.node_type == "proxmox" {
            // Deprecated: the standalone Proxmox API integration is no longer supported.
            // These entries are surfaced through the deprecation banner so the user can
            // remove them and re-add the hosts as full WolfStack nodes. Do not poll.
            continue;
        }

        // ── Poll WolfStack node via agent ──
        // v23.12: HTTPS-first via build_node_urls. CA-signed-cert peers no
        // longer bind the second listener, so the pre-v23.12 chain that
        // led with http://addr:port+1 silently dropped them. The shared
        // POLL_CLIENT below has danger_accept_invalid_certs so self-signed
        // peers still answer on HTTPS.
        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/agent/status");


        let client = {
            // Reuse a single client across all poll cycles for connection pooling & keep-alive
            static POLL_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
                crate::api::ipv4_only_client_builder()
                    .timeout(Duration::from_secs(10))
                    .danger_accept_invalid_certs(true)
                    // Aggressive pool tuning so cluster polling doesn't
                    // leave orphaned idle sockets in CLOSE_WAIT when
                    // peers close early. See api/mod.rs API_HTTP_CLIENT.
                    .pool_idle_timeout(Duration::from_secs(15))
                    .pool_max_idle_per_host(4)
                    .tcp_keepalive(Duration::from_secs(30))
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new())
            });
            &*POLL_CLIENT
        };

        let mut poll_ok = false;
        for url in &urls {
            match client.get(url)
                .header("X-WolfStack-Secret", &cluster_secret)
                .send().await
            {
                Ok(resp) => {
                    // Only treat a peer as "polled" when we actually
                    // parsed a StatusReport from its body. A 401 / 404 /
                    // 500 response from a misconfigured peer used to fall
                    // into the catch-all `poll_ok = true` below — the
                    // node looked successfully polled while we'd
                    // collected zero data, which then caused
                    // `replace_wolfnet_routes` to wipe that host's
                    // container/VM routes from `routes.json` (because
                    // its host wolfnet IP wasn't added to `fresh_hosts`
                    // and existing entries pointing at it were dropped
                    // from `final_routes`). klasSponsor 2026-05-13:
                    // intermittent container/VM WolfNet IP unreachability
                    // from the VPS while peer-to-peer ping kept working.
                    if !resp.status().is_success() {
                        continue;
                    }
                    if let Ok(msg) = resp.json::<AgentMessage>().await {
                        if let AgentMessage::StatusReport { node_id: peer_self_id, hostname, metrics, components, docker_count, lxc_count, vm_count, public_ip, known_nodes, deleted_ids, wolfnet_ips, has_docker, has_lxc, has_kvm, workload_subnets: peer_workload_subnets, site: peer_site, license_key } = msg {
                            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                            // Detect TLS by the URL scheme that actually
                            // answered. v23.12 chain is HTTPS → HTTP-over-
                            // WolfNet → legacy plaintext; only the last
                            // (plain http://addr:port) implies a `--no-tls`
                            // peer. The WolfNet HTTP overlay step is also
                            // a TLS peer (the peer binds the second
                            // listener only because it's self-signed).
                            let node_tls = url.starts_with("https://")
                                || !url.starts_with(&format!("http://{}:{}/", node.address, node.port));
                            // Capture fresh hostname + public_ip BEFORE the move into
                            // update_remote so we can pass them to the wolfnet endpoint
                            // reconciler below without re-locking cluster state.
                            let peer_hostname_for_reconcile = hostname.clone();
                            let peer_public_ip_for_reconcile = public_ip.clone();
                            cluster.update_remote(Node {
                                id: node.id.clone(),
                                hostname,
                                address: node.address.clone(),
                                port: node.port,
                                last_seen: now,
                                metrics: Some(metrics),
                                components,
                                online: true,
                                is_self: false,
                                docker_count,
                                lxc_count,
                                vm_count,
                                public_ip: public_ip.clone(),
                                node_type: "wolfstack".to_string(),
                                pve_token: None,
                                pve_fingerprint: None,
                                pve_node_name: None,
                                pve_cluster_name: None,
                                cluster_name: node.cluster_name.clone(),
                                join_verified: node.join_verified,
                                has_docker,
                                has_lxc,
                                has_kvm,
                                login_disabled: node.login_disabled,
                                tls: node_tls,
                                update_script: node.update_script.clone(),
                                // Capture the peer's own self_id from its
                                // status report so cross-node proxy calls
                                // that arrive with the self_id (topology,
                                // LAN records) resolve via the get_node
                                // self_id fallback.
                                //
                                // If the peer's report is anomalously empty
                                // (transient bug, partial config), preserve
                                // the previously-captured self_id rather
                                // than wiping it — otherwise a single bad
                                // poll re-opens the 404 window until the
                                // next good poll.
                                self_id: if peer_self_id.is_empty() {
                                    node.self_id.clone()
                                } else {
                                    Some(peer_self_id)
                                },
                                workload_subnets: peer_workload_subnets,
                                // Peer's own declared site (None for
                                // older peers and for nodes the
                                // operator hasn't tagged yet). We
                                // trust the peer's self-report —
                                // that's the source of truth for a
                                // node's own location.
                                site: peer_site,
                            });

                            // Reset fail count on success
                            POLL_FAIL_COUNTS.lock().unwrap().remove(&node.id);

                            // Hook B for WolfNet endpoint self-healing — cheap O(1)
                            // check against the local wolfnet config; only acts on
                            // the demonstrably-bad pattern (public self + RFC1918
                            // peer endpoint). See
                            // networking::reconcile_local_wolfnet_endpoint_if_needed
                            // for the conservative decision rule, and
                            // networking::decide_peer_endpoint for the five safety
                            // guards (wolfnet-subnet loop, self-loop,
                            // loopback/link-local, behind-NAT, no-public-ip). Runs
                            // in a blocking task to keep file I/O off the poll
                            // task.
                            {
                                let self_addr = cluster.self_address.clone();
                                let hn = peer_hostname_for_reconcile;
                                let plan = node.address.clone();
                                let pip = peer_public_ip_for_reconcile;
                                tokio::task::spawn_blocking(move || {
                                    crate::networking::reconcile_local_wolfnet_endpoint_if_needed(
                                        &self_addr,
                                        &hn,
                                        Some(&plan),
                                        pip.as_deref(),
                                    );
                                });
                            }

                            // Enterprise license propagation: if a remote node has a
                            // valid license and we don't, save it locally.
                            if let Some(ref lk) = license_key {
                                if !lk.is_empty() && !crate::compat::platform_ready() {
                                    let dm_path = crate::compat::dm_path();
                                    if std::fs::read_to_string(&dm_path).map(|s| s.trim().is_empty()).unwrap_or(true) {
                                        if let Some(parent) = std::path::Path::new(&dm_path).parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        if std::fs::write(&dm_path, lk).is_ok() {
                                            tracing::info!("Enterprise license received from cluster node '{}'", node.hostname);
                                        }
                                    }
                                }
                            }

                            // Merge tombstones first — so we don't re-add deleted nodes
                            cluster.merge_tombstones(&deleted_ids);

                            // Merge known_nodes (gossip) — mirror node settings from remote
                            let current_nodes = cluster.get_all_nodes();
                            let self_hostname = hostname::get()
                                .map(|h| h.to_string_lossy().to_string())
                                .unwrap_or_default();
                            for known in known_nodes {
                                // Self-identification in a gossip entry: match EITHER
                                // by the entry's id (only fires when a node gossips its
                                // OWN view, which is rare) OR by the entry's `self_id`
                                // field (populated from the remote's StatusReport.node_id,
                                // which is the canonical `ws-{uuid}` from /etc/wolfstack/
                                // node_id). Pre-fix this only checked `known.id` against
                                // `self_id`, but those live in disjoint ID namespaces —
                                // `id` is the LOCALLY-ASSIGNED `node-{uuid}` of the
                                // sending peer, while `self_id` is the global ws-{uuid}.
                                // The pre-fix condition never matched cross-node, so
                                // gossip-driven cluster-name adoption was dead code.
                                let is_self = known.id == cluster.self_id
                                    || known.self_id.as_deref() == Some(cluster.self_id.as_str());
                                if is_self {
                                    // Accept cluster_name updates from gossip (admin may have changed it on another node)
                                    if let Some(ref gossiped_cluster) = known.cluster_name {
                                        let current_cluster = {
                                            let nodes_r = cluster.nodes.read().unwrap();
                                            nodes_r.get(&cluster.self_id).and_then(|n| n.cluster_name.clone())
                                        };
                                        if current_cluster.as_deref() != Some(gossiped_cluster) {

                                            let mut nodes_w = cluster.nodes.write().unwrap();
                                            if let Some(n) = nodes_w.get_mut(&cluster.self_id) {
                                                n.cluster_name = Some(gossiped_cluster.clone());
                                            }
                                            drop(nodes_w);
                                            ClusterState::save_self_cluster_name(gossiped_cluster);
                                        }
                                    }
                                    continue;
                                }
                                // Also skip if this is us by hostname+port (gossip may report different address)
                                if known.node_type == "wolfstack" && known.hostname == self_hostname && known.port == cluster.port {
                                    continue;
                                }

                                // Skip tombstoned nodes
                                if cluster.is_tombstoned(&known.id) {
                                    continue;
                                }

                                // Check if this node is already known by ID
                                let existing_by_id = current_nodes.iter().find(|n| n.id == known.id);

                                if let Some(existing) = existing_by_id {
                                    // Node already known — update its settings to mirror the source.
                                    // A wildcard (0.0.0.0) gossiped address doesn't count as a
                                    // change — it's preserved below — so don't let it trigger a
                                    // spurious write on its own.
                                    if (is_usable_addr(&known.address) && existing.address != known.address)
                                        || existing.hostname != known.hostname
                                        || existing.port != known.port
                                        || existing.pve_token != known.pve_token
                                        || existing.pve_fingerprint != known.pve_fingerprint
                                        || existing.cluster_name != known.cluster_name
                                    {


                                        cluster.update_node_settings(
                                            &known.id,
                                            Some(known.hostname.clone()),
                                            // Never overwrite a real, reachable address with a
                                            // peer's unusable self-entry (0.0.0.0 bind address) —
                                            // that's what dropped the hub "main" from other nodes.
                                            if is_usable_addr(&known.address) {
                                                Some(known.address.clone())
                                            } else {
                                                Some(existing.address.clone())
                                            },
                                            Some(known.port),
                                            known.pve_token.clone(),
                                            if known.pve_fingerprint.is_some() || existing.pve_fingerprint.is_some() {
                                                Some(known.pve_fingerprint.clone())
                                            } else {
                                                None
                                            },
                                            known.cluster_name.clone(),
                                            None,  // don't propagate login_disabled via gossip
                                            None,  // don't propagate update_script via gossip
                                            None,  // site is propagated via StatusReport, not nested gossip
                                        );
                                    }
                                } else {
                                    // Dedup STRICTLY by the stable global self_id first
                                    // (mirrors merge_member_refs). A multi-homed node is
                                    // gossiped under its LAN IP, its WolfNet 10.x IP and
                                    // the v24.27 source-IP-repair variant — three different
                                    // addresses, ONE self_id. Keying only on address/hostname
                                    // (as before) let each variant be admitted as a fresh
                                    // record on successive polls, re-bloating nodes.json
                                    // between restarts — the same vector as the v24.27 storm.
                                    let known_sid = known.self_id.as_deref().filter(|s| !s.is_empty());
                                    let already_known = current_nodes.iter().any(|n| {
                                        (known_sid.is_some() && n.self_id.as_deref() == known_sid)
                                        || (n.address == known.address && n.port == known.port && n.pve_node_name == known.pve_node_name)
                                        || (n.hostname == known.hostname && n.port == known.port && n.node_type == known.node_type)
                                    });
                                    if !already_known {
                                        // Only auto-add nodes on private/local networks
                                        // Public-IP nodes must be added manually to prevent
                                        // machines from accidentally switching hosts
                                        if !is_private_address(&known.address) {

                                            continue;
                                        }

                                        let mut new_node = known.clone();
                                        new_node.online = false;
                                        new_node.is_self = false;
                                        cluster.update_remote(new_node);
                                        cluster.save_nodes();
                                    }
                                }
                            }
                            // Collect subnet routes from this node's wolfnet_ips.
                            // First IP = host WolfNet address, remaining =
                            // container/VM IPs. Validate the host entry
                            // before treating it as a gateway: if `wolfnet0`
                            // had no IP on the peer at the moment its
                            // status was built, `wolfnet_used_ips()`
                            // returns containers WITHOUT a host index 0,
                            // and the old code would happily map
                            // container_b → container_a — poisoning
                            // routes.json on receivers.
                            let self_cluster = cluster.get_self_cluster_name();
                            let peer_cluster = node.cluster_name.as_deref().unwrap_or("WolfStack");
                            if peer_cluster == self_cluster && wolfnet_ips.len() > 1 {
                                let host_wn_ip = &wolfnet_ips[0];
                                let host_ok = !host_wn_ip.is_empty()
                                    && host_wn_ip.parse::<std::net::Ipv4Addr>().is_ok();
                                if host_ok {
                                    for container_ip in &wolfnet_ips[1..] {
                                        if container_ip.is_empty() { continue; }
                                        if container_ip == host_wn_ip { continue; }
                                        if container_ip.parse::<std::net::Ipv4Addr>().is_err() { continue; }
                                        subnet_routes.insert(container_ip.clone(), host_wn_ip.clone());
                                    }
                                } else {
                                    tracing::warn!(
                                        "poll_remote_nodes: peer {} returned {} wolfnet_ips with no valid host IP at [0]; skipping container-route propagation for this peer",
                                        node.id, wolfnet_ips.len()
                                    );
                                }
                            }
                            // Cache the peer's host WolfNet IP so future
                            // build_node_urls calls can insert a
                            // HTTP-over-WolfNet attempt before falling
                            // back to plaintext on the public address.
                            // Same validity guard as above — never cache
                            // a bogus "host IP" that's actually a
                            // container address.
                            if let Some(host_wn_ip) = wolfnet_ips.first() {
                                if !host_wn_ip.is_empty()
                                    && host_wn_ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                    crate::api::record_node_wolfnet_ip(&node.address, host_wn_ip);
                                }
                            }
                            // Only mark this poll as successful when we
                            // actually parsed a StatusReport. A 200 with
                            // a non-StatusReport body (corrupt agent, mid-
                            // restart partial JSON, version mismatch)
                            // used to also set poll_ok=true and cause
                            // the route-merge phase to treat the peer as
                            // authoritative-but-empty, dropping its
                            // routes.
                            poll_ok = true;
                        }
                    }
                    if poll_ok { break; }
                    // Body wasn't a StatusReport — try the next URL in
                    // the fallback chain rather than declaring success.
                    continue;
                }
                Err(_) => {
                    continue; // Try next URL
                }
            }
        }

        if !poll_ok {

            // Increment fail count; keep node online until 2 consecutive failures
            let mut fails = POLL_FAIL_COUNTS.lock().unwrap();
            let count = fails.entry(node.id.clone()).or_insert(0);
            *count += 1;
            if *count < 2 {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let mut nodes = cluster.nodes.write().unwrap();
                if let Some(n) = nodes.get_mut(&node.id) {
                    n.last_seen = now;
                }
            }
        }
    }

    // Build updated route table. Strategy:
    // - Start from existing routes (preserves routes for nodes we couldn't reach)
    // - Remove entries for nodes we successfully polled AND got container
    //   routes from (we have fresh authoritative data for those hosts)
    // - Add all fresh routes (local + successfully polled remote nodes)
    //
    // IMPORTANT interaction with the push path:
    //   The push handler (wolfnet_routes_announce) modifies WOLFNET_ROUTES
    //   in-place between poll cycles. This replace_wolfnet_routes call is
    //   authoritative and overwrites the cache. Routes from the push are
    //   preserved IFF the poll ALSO collected routes for that host (they
    //   end up in subnet_routes). If the poll returned only the host IP
    //   (no containers), the host is NOT in fresh_hosts, so any routes
    //   the push delivered for that host survive the replace.
    //
    //   The one race: if a container was JUST created, the push fires
    //   instantly (WOLFNET_ROUTES_CHANGED), but the poll's StatusReport
    //   cache (5s TTL) may still be stale. The poll then overwrites the
    //   push-delivered route with stale data. This heals on the next
    //   poll cycle (10s) when the StatusReport cache refreshes.

    // 1. Add LOCAL container/VM/VIP IPs → this node's wolfnet IP
    let local_ips = crate::containers::wolfnet_used_ips_cached();
    let local_wn_ip = local_ips.first().cloned().unwrap_or_default();
    if local_ips.len() > 1 {
        let host_wn_ip = &local_ips[0];
        for ip in &local_ips[1..] {
            if !ip.is_empty() && ip != host_wn_ip {
                subnet_routes.insert(ip.clone(), host_wn_ip.clone());
            }
        }
    }

    // 2. subnet_routes now has: local container routes + remote container routes

    // 3. Build the safe replacement.
    //    Collect which host IPs we have AUTHORITATIVE fresh data for:
    //    - Our own local wolfnet IP (always authoritative — we just scanned)
    //    - Gateway IPs from subnet_routes (only populated when
    //      wolfnet_ips.len() > 1, i.e. the peer reported containers)
    //    A host NOT in this set keeps its existing routes — they came
    //    from either a previous poll or a push, both are valid.
    let mut fresh_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !local_wn_ip.is_empty() {
        fresh_hosts.insert(local_wn_ip);
    }
    for v in subnet_routes.values() {
        fresh_hosts.insert(v.clone());
    }

    // Start from existing routes, remove entries for hosts we have fresh data for
    // Also remove any entries with invalid (non-IP) gateway values (cleanup from past bug)
    let existing = crate::containers::WOLFNET_ROUTES.lock().unwrap().clone();
    let mut final_routes = std::collections::HashMap::new();
    for (k, v) in &existing {
        // Skip entries with invalid gateway values (e.g. "remote" from a past bug)
        if v.split('.').count() != 4 || v.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        if !fresh_hosts.contains(v) {
            // Keep routes for hosts we COULDN'T poll or that returned
            // no container data — stale/push-delivered but better than nothing
            final_routes.insert(k.clone(), v.clone());
        }
    }
    // Add all fresh routes (overwrites stale entries for the same container IP)
    final_routes.extend(subnet_routes);

    // Replace atomically
    crate::containers::replace_wolfnet_routes(final_routes);


    // After polling, detect state changes and send emails
    // Only the node with the lowest ID sends emails to avoid duplicates
    if let Some(ref ai) = ai_agent {
        let config = ai.config.lock().unwrap().clone();
        if config.email_enabled && !config.email_to.is_empty() {
            let current_nodes = cluster.get_all_nodes();
            // Determine if we are the primary alerter (lowest self_id among online nodes)
            let self_id = &cluster.self_id;
            let is_primary = current_nodes.iter()
                .filter(|n| n.online)
                .map(|n| &n.id)
                .min()
                .map(|min_id| min_id == self_id)
                .unwrap_or(true); // If no nodes online, we're it

            if is_primary {
                // Load alerting config for webhook channels
                let alert_config = crate::alerting::AlertConfig::load();

                for node in current_nodes.iter().filter(|n| !n.is_self) {
                    let (was_online, hostname) = previous_states.get(&node.id)
                        .cloned()
                        .unwrap_or((false, node.hostname.clone()));

                    let display_name = if hostname.is_empty() { &node.address } else { &hostname };

                    // Node offline / restored are Lifecycle events: visible
                    // on the dashboard, so Simple mode suppresses the push.
                    // Operators who want every flap by email switch to Verbose.
                    let lifecycle_allowed = crate::alerting::should_send(
                        &alert_config,
                        crate::alerting::AlertCategory::Lifecycle,
                    );
                    if was_online && !node.online {
                        // Node went OFFLINE
                        let raw_subject = format!("[WolfStack ALERT] {} has gone offline", display_name);
                        let raw_body = format!(
                            "⚠️ Node Offline Alert\n\n\
                             Hostname: {}\n\
                             Address: {}:{}\n\
                             Status: OFFLINE\n\
                             Time: {}\n\n\
                             This node is no longer responding to cluster health checks.\n\
                             Please investigate immediately.",
                            display_name, node.address, node.port,
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        // Decorate with the observer node's cluster + host so
                        // multi-cluster operators see WHICH primary detected
                        // the failure. The failing peer is named in the
                        // (un-prefixed) title text and the body's Hostname:
                        // line — between the two, recipients have both
                        // observer and subject context.
                        let (subject, body) = crate::alerting::decorate_local(&raw_subject, &raw_body);
                        if lifecycle_allowed {
                            if let Err(e) = crate::ai::send_alert_email(&config, &subject, &body) {
                                warn!("Failed to send node-offline email for {}: {}", display_name, e);
                            }
                        }
                        // Send to webhook channels
                        if alert_config.enabled && alert_config.alert_node_offline {
                            let ac = alert_config.clone();
                            let subj = subject.clone();
                            let b = body.clone();
                            tokio::spawn(async move {
                                crate::alerting::send_alert(
                                    &ac,
                                    crate::alerting::AlertCategory::Lifecycle,
                                    &subj, &b,
                                ).await;
                            });
                        }
                    } else if !was_online && node.online {
                        // Node came back ONLINE
                        let raw_subject = format!("[WolfStack OK] {} has been restored", display_name);
                        let raw_body = format!(
                            "✅ Node Restored\n\n\
                             Hostname: {}\n\
                             Address: {}:{}\n\
                             Status: ONLINE\n\
                             Time: {}\n\n\
                             This node is responding to cluster health checks again.",
                            display_name, node.address, node.port,
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        // Decorate with observer cluster + host — same shape as
                        // every other WolfStack alert.
                        let (subject, body) = crate::alerting::decorate_local(&raw_subject, &raw_body);
                        if lifecycle_allowed {
                            if let Err(e) = crate::ai::send_alert_email(&config, &subject, &body) {
                                warn!("Failed to send node-restored email for {}: {}", display_name, e);
                            }
                        }
                        // Send to webhook channels
                        if alert_config.enabled && alert_config.alert_node_restored {
                            let ac = alert_config.clone();
                            let subj = subject.clone();
                            let b = body.clone();
                            tokio::spawn(async move {
                                crate::alerting::send_alert(
                                    &ac,
                                    crate::alerting::AlertCategory::Lifecycle,
                                    &subj, &b,
                                ).await;
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod convergence_tests {
    use super::*;

    #[test]
    fn unusable_addresses_are_rejected() {
        // The wildcard bind address a node advertises for itself must never be
        // treated as reachable — this was why the hub "main" vanished from
        // every other node.
        assert!(!is_usable_addr("0.0.0.0"));
        assert!(!is_usable_addr("0.0.0.0:8553"));
        assert!(!is_usable_addr("::"));
        assert!(!is_usable_addr("[::]"));
        assert!(!is_usable_addr(""));
        assert!(!is_usable_addr("   "));
    }

    #[test]
    fn real_addresses_are_usable() {
        assert!(is_usable_addr("192.168.5.10"));
        assert!(is_usable_addr("10.2.0.153"));
        assert!(is_usable_addr("nas.lan"));
    }

    #[test]
    fn private_guard_allows_lan_and_hostnames_but_not_public() {
        assert!(is_private_address("192.168.5.10"));
        assert!(is_private_address("10.0.0.1"));
        assert!(is_private_address("127.0.0.1"));
        assert!(is_private_address("nas.lan"));       // hostname → treated local
        assert!(!is_private_address("8.8.8.8"));      // public → not auto-added
        assert!(!is_private_address("0.0.0.0"));       // wildcard → not private
    }

    #[test]
    fn exported_nodes_bundle_deserializes_as_array() {
        // nodes.json (and the config-export "nodes" key) is a JSON ARRAY of
        // Node — NOT a map. config_import::import_nodes used to parse it as a
        // map, so every restore failed with "invalid type: sequence, expected
        // a map" and the operator's whole fleet+cluster grouping couldn't be
        // restored. This shape matches a real v24.0.2 export (only `site` is
        // absent — it post-dates the export and has #[serde(default)]).
        let array_json = r#"[
            {"id":"node-233a2011","hostname":"wolf3","address":"wolf3.wolf.uk.com","port":8553,
             "last_seen":0,"metrics":null,"components":[],"online":true,"is_self":false,
             "node_type":"wolfstack","self_id":"ws-33548073","cluster_name":"WolfStack-Shannon"},
            {"id":"node-641fb254","hostname":"sophie","address":"sophie.wolfterritories.org","port":8553,
             "last_seen":0,"metrics":null,"components":[],"online":false,"is_self":false,
             "node_type":"wolfstack","self_id":"ws-286f90be","cluster_name":"Minio"}
        ]"#;
        let nodes: Vec<Node> = serde_json::from_str(array_json)
            .expect("exported nodes array must deserialize as Vec<Node>");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].cluster_name.as_deref(), Some("WolfStack-Shannon"));
        assert_eq!(nodes[1].cluster_name.as_deref(), Some("Minio"));

        // The legacy/hand-edited object/map form must still parse too (the
        // importer accepts both).
        let map_json = r#"{"node-233a2011":{"id":"node-233a2011","hostname":"wolf3",
            "address":"wolf3.wolf.uk.com","port":8553,"last_seen":0,"metrics":null,
            "components":[],"online":true,"is_self":false,"node_type":"wolfstack",
            "cluster_name":"WolfStack-Shannon"}}"#;
        let map: std::collections::HashMap<String, Node> = serde_json::from_str(map_json)
            .expect("legacy nodes map must still deserialize");
        assert_eq!(map.len(), 1);
    }

    // Build a Node with only the fields the prune logic reads; the rest take
    // their serde defaults.
    fn mk(
        id: &str,
        addr: &str,
        self_id: Option<&str>,
        cluster: Option<&str>,
        is_self: bool,
        verified: bool,
        online: bool,
    ) -> Node {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": id,
            "address": addr,
            "port": 8553,
            "last_seen": 0,
            "metrics": null,
            "components": [],
            "online": online,
            "is_self": is_self,
            "node_type": "wolfstack",
            "self_id": self_id,
            "cluster_name": cluster,
            "join_verified": verified,
        }))
        .unwrap()
    }

    #[test]
    fn prune_keeps_peers_from_other_clusters() {
        // Control-plane replication shows the WHOLE fleet across clusters —
        // `cluster_name` is a display grouping, never a membership boundary.
        // Peers in OTHER named clusters (and untagged peers) must be KEPT; the
        // v24.29.1 regression pruned them and deleted ~5 federated clusters
        // down to a single node.
        let nodes = vec![
            mk("self", "10.0.0.1", None, Some("HomeLab"), true, true, true),
            mk("a", "10.0.0.2", Some("ws-a"), Some("HomeLab"), false, true, true),
            mk("b", "10.0.0.3", Some("ws-b"), Some("Production"), false, true, true),
            mk("c", "10.0.0.4", Some("ws-c"), None, false, true, true),
        ];
        let remove = ClusterState::plan_prune(nodes);
        assert!(remove.is_empty(), "no peer may be pruned for cluster membership");
    }

    #[test]
    fn prune_collapses_multihomed_duplicates_by_self_id() {
        // The storm: one physical node seen under LAN, WolfNet, and source-IP
        // address variants — same self_id. Keep the best record, drop the rest.
        let nodes = vec![
            mk("self", "10.0.0.1", None, Some("HomeLab"), true, true, true),
            mk("a-lan", "192.168.1.5", Some("ws-a"), Some("HomeLab"), false, true, true),
            mk("a-wg", "10.10.10.5", Some("ws-a"), Some("HomeLab"), false, false, false),
            mk("a-src", "172.16.0.5", Some("ws-a"), Some("HomeLab"), false, false, false),
        ];
        let remove = ClusterState::plan_prune(nodes);
        assert_eq!(remove.len(), 2);
        assert!(!remove.contains(&"a-lan".to_string())); // verified+online keeper survives
    }

    #[test]
    fn prune_collapses_duplicates_by_address_when_no_self_id() {
        let nodes = vec![
            mk("self", "10.0.0.1", None, Some("HomeLab"), true, true, true),
            mk("x1", "192.168.1.9", None, Some("HomeLab"), false, true, true),
            mk("x2", "192.168.1.9", None, Some("HomeLab"), false, false, false),
        ];
        let remove = ClusterState::plan_prune(nodes);
        assert_eq!(remove.len(), 1);
        assert!(remove.contains(&"x2".to_string()));
    }
}
