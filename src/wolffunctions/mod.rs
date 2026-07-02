// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfFunctions — serverless functions-as-a-service across the cluster.
//!
//! The Lambda-shaped workload type: instead of provisioning an LXC/Docker/VM,
//! the operator writes (or AI-generates) a handler function, and WolfStack
//! keeps warm, sandboxed copies of it running on N nodes. Any node can accept
//! an invocation; node loss changes nothing because the definition is
//! replicated everywhere and the leader re-places warm instances.
//!
//! Execution isolation follows what the big providers actually run: gVisor's
//! `runsc` (Google Cloud Functions gen-1's sandbox) — a userspace kernel, one
//! static binary, works on any Linux without KVM. See `runtime.rs`. A
//! config-driven `docker` fallback exists for nodes where runsc can't run
//! (visibly labelled "reduced isolation" in the UI — never silent).
//!
//! Cluster model (cloned from the proven statuspage/wolfrun machinery):
//! - definitions replicate leaderless: every node holds the full JSON,
//!   changes broadcast to same-cluster peers, receivers replace-merge.
//! - the lowest-node-ID leader (`wolfrun::is_leader`) runs the reconciler:
//!   compute placements, create/destroy warm instances, fire schedules.
//! - invocation: serve from a local warm instance if placed here, otherwise
//!   forward to a placed node; cold-start locally as a last resort so a
//!   mid-failover invoke still succeeds.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use tracing::{info, warn};

pub mod runtime;

/// Shared pooled client for peer sync + invoke forwarding + the local shim
/// health poll. Built from `ipv4_only_client_builder()` (binds source to
/// IPv4 0.0.0.0) — WITHOUT this, on a multi-homed host with policy routing
/// (WolfNet overlay + bridges) reqwest picks a source/route that can't
/// reach `127.0.0.1:<shim port>` even though curl can, so every sandbox
/// health check failed with "error sending request" and no instance ever
/// went warm (diagnosed live 2026-07-02 — same class as the KO4BSR
/// curl-works-reqwest-doesn't report). Pooled to avoid the per-call
/// CLOSE_WAIT leak (the v25.1.43 FD-storm class of bug).
static FN_RPC_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            .connect_timeout(std::time::Duration::from_secs(3))
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Drain a response body so the socket returns to the keep-alive pool
/// (same helper statuspage/api keep privately).
async fn drain_response(resp: reqwest::Response) {
    let mut r = resp;
    while let Ok(Some(_)) = r.chunk().await {}
}

fn functions_dir() -> String { crate::paths::get().wolffunctions_dir }
fn functions_file() -> String { crate::paths::get().wolffunctions_functions }

// ═══════════════════════════════════════════════
// ─── Types ───
// ═══════════════════════════════════════════════

/// Language runtime for a function. Adding a runtime = one enum variant +
/// its image/shim/exec entries below (the abstraction the UI and rootfs
/// prep code work through).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionRuntime {
    Python312,
    Node22,
}

impl FunctionRuntime {
    /// OCI image whose exported filesystem becomes the sandbox rootfs.
    pub fn image(&self) -> &'static str {
        match self {
            FunctionRuntime::Python312 => "python:3.12-slim",
            FunctionRuntime::Node22 => "node:22-slim",
        }
    }
    /// Handler source filename inside the mounted /function dir.
    pub fn handler_file(&self) -> &'static str {
        match self {
            FunctionRuntime::Python312 => "handler.py",
            FunctionRuntime::Node22 => "handler.js",
        }
    }
    /// Shim filename inside the mounted /function dir.
    pub fn shim_file(&self) -> &'static str {
        match self {
            FunctionRuntime::Python312 => "shim.py",
            FunctionRuntime::Node22 => "shim.js",
        }
    }
    /// argv to start the shim inside the sandbox. The shim reads the
    /// listen port from the WOLFFN_PORT env var.
    pub fn shim_argv(&self) -> Vec<String> {
        match self {
            FunctionRuntime::Python312 => vec!["python3".into(), "/function/shim.py".into()],
            FunctionRuntime::Node22 => vec!["node".into(), "/function/shim.js".into()],
        }
    }
    pub fn display(&self) -> &'static str {
        match self {
            FunctionRuntime::Python312 => "Python 3.12",
            FunctionRuntime::Node22 => "Node.js 22",
        }
    }
}

/// Internal WolfStack events a function can subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerEvent {
    AlertFired,
    NodeOffline,
    NodeOnline,
    BackupCompleted,
    BackupFailed,
}

/// A schedule trigger. v1 is interval-based (fires every `interval_secs`,
/// minimum 60) — the same due-time-inside-a-tick model the backup
/// scheduler uses. Cron expressions are a runtime addition, not a schema
/// break: this struct grows an optional `cron` field later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSchedule {
    pub interval_secs: u64,
    /// Unix time this schedule last fired (leader-local bookkeeping,
    /// replicated so a leader change doesn't double-fire).
    #[serde(default)]
    pub last_fired: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfFunction {
    pub id: String,
    /// Unique per cluster; used in URLs and sandbox names. Validated to
    /// [a-z0-9-] at create time.
    pub name: String,
    /// Cluster scoping — same convention as status pages.
    pub cluster: String,
    pub runtime: FunctionRuntime,
    /// Handler source (single file in v1). Python: `def handler(event,
    /// context)`; Node: `exports.handler = async (event, context)`.
    pub code: String,
    #[serde(default)]
    pub description: String,
    /// Memory limit per instance, MB (OCI linux.resources.memory.limit).
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u32,
    /// Invocation timeout; on expiry the instance is destroyed and
    /// replaced (it may be wedged).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
    /// Number of NODES that keep warm instances (Lambda's provisioned
    /// concurrency, spread for HA). 0 = scale-from-zero on demand — the
    /// FIRST invocation on a cold node then pays the runtime cold start
    /// (sandbox launch + shim listen). That cold start is bounded by the
    /// invoke's own cold-start budget, NOT by `timeout_secs` (which bounds
    /// only the handler HTTP call), so a short `timeout_secs` won't abort a
    /// legitimate first-call warm-up. replicas >= 1 avoids the cold start
    /// entirely by pre-warming via the reconciler.
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Extra instances a node may spawn beyond the warm one when
    /// invocations arrive concurrently. Idle bursts are reaped.
    #[serde(default = "default_max_per_node")]
    pub max_per_node: u32,
    /// KEY=VALUE pairs injected into the sandbox environment.
    #[serde(default)]
    pub env: Vec<String>,
    /// Node IDs the leader placed warm instances on. Written by the
    /// leader's reconcile, replicated so every node routes invokes
    /// without asking around.
    #[serde(default)]
    pub placed_nodes: Vec<String>,
    /// Public no-auth HTTP trigger at /fn/{public_slug}. Off by default —
    /// public surfaces are opt-in, always.
    #[serde(default)]
    pub public_slug: Option<String>,
    #[serde(default)]
    pub schedules: Vec<FunctionSchedule>,
    #[serde(default)]
    pub events: Vec<TriggerEvent>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bumped on every code/config change; instances carry the version
    /// they were started with so the reconciler replaces stale ones.
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

fn default_memory_mb() -> u32 { 128 }
fn default_timeout_secs() -> u32 { 30 }
fn default_replicas() -> u32 { 2 }
fn default_max_per_node() -> u32 { 4 }
fn default_true() -> bool { true }

/// Clamp a function's numeric limits into the same ranges the create/update
/// handlers enforce. Applied to peer-supplied functions in `merge_cluster`
/// so the sync path can't smuggle out-of-range values past `validate_upsert`.
pub fn sanitize_function(f: &mut WolfFunction) {
    f.memory_mb = f.memory_mb.clamp(32, 8192);
    f.timeout_secs = f.timeout_secs.clamp(1, 900);
    f.replicas = f.replicas.min(64);
    f.max_per_node = f.max_per_node.clamp(1, 32);
    f.schedules.retain(|s| s.interval_secs >= 60);
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate a function name: DNS-label-ish, used in sandbox IDs and URLs.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

// ═══════════════════════════════════════════════
// ─── Local (non-replicated) instance state ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    Starting,
    Warm,
    Busy,
    Failed,
}

/// A warm sandbox on THIS node. Never replicated — each node owns its own
/// instance registry; the cluster only shares `placed_nodes`.
#[derive(Debug, Clone, Serialize)]
pub struct Instance {
    pub sandbox_id: String,
    pub function_id: String,
    pub function_version: u64,
    pub port: u16,
    pub status: InstanceStatus,
    pub started_at: u64,
    pub last_used: u64,
    /// True while an invocation is in flight (one request per instance at
    /// a time — Lambda semantics).
    #[serde(skip)]
    pub busy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvocationRecord {
    pub ts: u64,
    pub node: String,
    pub trigger: String,
    pub duration_ms: u64,
    pub ok: bool,
    pub error: Option<String>,
    /// Handler stdout/stderr captured by the shim (truncated).
    pub logs: String,
}

const INVOCATION_RING: usize = 200;

// ═══════════════════════════════════════════════
// ─── State ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionsConfig {
    #[serde(default)]
    pub functions: Vec<WolfFunction>,
}

/// Cluster-scoped sync payload. Carries the cluster name explicitly so an
/// EMPTY function list still propagates a deletion — the receiver clears
/// exactly `cluster` and replaces with `functions` (possibly none).
/// Without the explicit name, an empty broadcast can't tell the receiver
/// which cluster to clear (that was the "deleted function stays live on
/// peers" bug).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    pub cluster: String,
    #[serde(default)]
    pub functions: Vec<WolfFunction>,
}

pub struct WolfFunctionsState {
    pub config: RwLock<FunctionsConfig>,
    /// function_id -> local warm instances (this node only).
    pub instances: Mutex<HashMap<String, Vec<Instance>>>,
    /// function_id -> recent invocation records (this node only).
    pub invocations: Mutex<HashMap<String, VecDeque<InvocationRecord>>>,
    /// Cached node-eligibility probe result (runsc/docker availability).
    pub eligibility: Mutex<Option<runtime::NodeEligibility>>,
}

impl WolfFunctionsState {
    pub fn new() -> Self {
        let state = WolfFunctionsState {
            config: RwLock::new(FunctionsConfig::default()),
            instances: Mutex::new(HashMap::new()),
            invocations: Mutex::new(HashMap::new()),
            eligibility: Mutex::new(None),
        };
        state.load();
        state
    }

    pub fn load(&self) {
        if let Ok(data) = std::fs::read_to_string(functions_file()) {
            match serde_json::from_str::<FunctionsConfig>(&data) {
                Ok(cfg) => *self.config.write().unwrap() = cfg,
                Err(e) => warn!("WolfFunctions: functions.json unreadable ({}) — starting empty, file left untouched", e),
            }
        }
    }

    pub fn save(&self) {
        let cfg = self.config.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*cfg) {
            let _ = std::fs::create_dir_all(functions_dir());
            if let Err(e) = std::fs::write(functions_file(), json) {
                warn!("WolfFunctions: failed to save functions.json: {}", e);
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<WolfFunction> {
        self.config.read().unwrap().functions.iter().find(|f| f.id == id).cloned()
    }

    pub fn get_by_name(&self, cluster: &str, name: &str) -> Option<WolfFunction> {
        self.config.read().unwrap().functions.iter()
            .find(|f| f.cluster == cluster && f.name == name).cloned()
    }

    pub fn get_by_slug(&self, slug: &str) -> Option<WolfFunction> {
        self.config.read().unwrap().functions.iter()
            .find(|f| f.public_slug.as_deref() == Some(slug)).cloned()
    }

    pub fn upsert(&self, func: WolfFunction) {
        {
            let mut cfg = self.config.write().unwrap();
            if let Some(existing) = cfg.functions.iter_mut().find(|f| f.id == func.id) {
                *existing = func;
            } else {
                cfg.functions.push(func);
            }
        }
        self.save();
    }

    pub fn remove(&self, id: &str) -> bool {
        let removed = {
            let mut cfg = self.config.write().unwrap();
            let before = cfg.functions.len();
            cfg.functions.retain(|f| f.id != id);
            cfg.functions.len() != before
        };
        if removed { self.save(); }
        removed
    }

    /// Record an invocation in the per-function ring buffer.
    pub fn record_invocation(&self, function_id: &str, rec: InvocationRecord) {
        let mut map = self.invocations.lock().unwrap();
        let ring = map.entry(function_id.to_string()).or_default();
        ring.push_back(rec);
        while ring.len() > INVOCATION_RING {
            ring.pop_front();
        }
    }

    pub fn recent_invocations(&self, function_id: &str) -> Vec<InvocationRecord> {
        self.invocations.lock().unwrap()
            .get(function_id)
            .map(|r| r.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    /// Replace all functions for exactly `cluster` with `incoming` (which
    /// may be empty — that's how a deletion of the last function reaches
    /// peers). Preserves each schedule's `last_fired` at max(local, peer)
    /// so a sync arriving right after a fire can't rewind and double-fire.
    /// Incoming functions are sanitised (clamps mirror `validate_upsert`)
    /// so a peer can't push out-of-range limits past the create/update
    /// guard.
    pub fn merge_cluster(&self, cluster: &str, mut incoming: Vec<WolfFunction>) {
        {
            let mut cfg = self.config.write().unwrap();
            let local_fired: HashMap<String, Vec<u64>> = cfg.functions.iter()
                .filter(|f| f.cluster == cluster)
                .map(|f| (f.id.clone(), f.schedules.iter().map(|s| s.last_fired).collect()))
                .collect();
            for f in &mut incoming {
                sanitize_function(f);
                if let Some(local) = local_fired.get(&f.id) {
                    for (i, s) in f.schedules.iter_mut().enumerate() {
                        if let Some(lf) = local.get(i) {
                            s.last_fired = s.last_fired.max(*lf);
                        }
                    }
                }
            }
            cfg.functions.retain(|f| f.cluster != cluster);
            cfg.functions.extend(incoming);
        }
        self.save();
    }

    /// Merge function config from a cluster peer — statuspage semantics:
    /// per-cluster replace-all for the clusters present in the payload.
    /// Schedule `last_fired` is kept at the max of local/peer so a sync
    /// arriving right after a fire can't rewind the clock and double-fire.
    pub fn merge_from_peer(&self, peer: FunctionsConfig) {
        let peer_clusters: std::collections::HashSet<String> =
            peer.functions.iter().map(|f| f.cluster.clone()).collect();
        if peer_clusters.is_empty() { return; }

        {
            let mut cfg = self.config.write().unwrap();
            let local_fired: HashMap<String, Vec<u64>> = cfg.functions.iter()
                .map(|f| (f.id.clone(), f.schedules.iter().map(|s| s.last_fired).collect()))
                .collect();
            cfg.functions.retain(|f| !peer_clusters.contains(&f.cluster));
            let mut incoming = peer.functions;
            for f in &mut incoming {
                sanitize_function(f);
                if let Some(local) = local_fired.get(&f.id) {
                    for (i, s) in f.schedules.iter_mut().enumerate() {
                        if let Some(lf) = local.get(i) {
                            s.last_fired = s.last_fired.max(*lf);
                        }
                    }
                }
            }
            cfg.functions.extend(incoming);
        }
        self.save();
    }
}

// ═══════════════════════════════════════════════
// ─── Cluster sync (statuspage pattern) ───
// ═══════════════════════════════════════════════

pub fn self_cluster_name(cluster: &crate::agent::ClusterState) -> String {
    cluster.get_all_nodes().iter()
        .find(|n| n.is_self)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string())
}

/// Broadcast this cluster's function definitions to all online same-cluster
/// peers. Only sends our own cluster's functions so we never clobber another
/// cluster's data on the receiving end.
pub async fn broadcast_to_cluster(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) {
    let nodes = cluster.get_all_nodes();
    let self_cluster = self_cluster_name(cluster);

    // Cluster-scoped payload — sent EVEN WHEN EMPTY so a deletion of the
    // last function propagates (the receiver clears `self_cluster` and
    // replaces with these). Callers must only invoke this from an
    // authoritative context (an operator mutation, or the leader's periodic
    // tick gated on the node actually holding functions) so a fresh empty
    // node can't wipe the cluster.
    let payload = SyncPayload {
        cluster: self_cluster.clone(),
        functions: state.config.read().unwrap().functions.iter()
            .filter(|f| f.cluster == self_cluster)
            .cloned()
            .collect(),
    };

    let client = &*FN_RPC_CLIENT;
    for node in &nodes {
        if node.is_self || !node.online { continue; }
        if node.cluster_name.as_deref().unwrap_or("WolfStack") != self_cluster { continue; }

        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/wolffunctions/sync");
        let mut sent = false;
        for url in &urls {
            match client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&payload)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    drain_response(resp).await;
                    sent = true;
                    break;
                }
                Ok(resp) => { drain_response(resp).await; continue; }
                Err(_) => continue,
            }
        }
        if !sent {
            warn!("WolfFunctions sync: failed to reach {} (all URLs failed)", node.hostname);
        }
    }
}

/// Pull function config from peers if we have none for our cluster (fresh
/// node joining, or restored without the config dir).
pub async fn pull_from_peers(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) {
    let self_cluster = self_cluster_name(cluster);
    {
        let cfg = state.config.read().unwrap();
        if cfg.functions.iter().any(|f| f.cluster == self_cluster) { return; }
    }

    let client = &*FN_RPC_CLIENT;
    let nodes = cluster.get_all_nodes();
    for peer in nodes.iter().filter(|n| {
        !n.is_self && n.online
            && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster
    }) {
        let urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/wolffunctions/config");
        for url in &urls {
            match client.get(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(cfg) = resp.json::<FunctionsConfig>().await
                        && !cfg.functions.is_empty()
                    {
                        info!("WolfFunctions: pulled {} functions from {}", cfg.functions.len(), peer.hostname);
                        state.merge_from_peer(cfg);
                        return;
                    }
                }
                Ok(resp) => { drain_response(resp).await; }
                Err(_) => {}
            }
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Placement ───
// ═══════════════════════════════════════════════

/// Rank same-cluster online nodes for placement: eligible first (this
/// node's own eligibility is probed; peers are assumed docker-capable if
/// they report has_docker — the reconciler self-corrects when a placed
/// node can't actually start an instance), then by wolfrun's load score.
pub fn rank_nodes_for_placement(
    cluster: &crate::agent::ClusterState,
) -> Vec<String> {
    let self_cluster = self_cluster_name(cluster);
    let mut candidates: Vec<(f32, String)> = cluster.get_all_nodes().iter()
        .filter(|n| n.online
            && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster
            && (n.has_docker || n.is_self))
        .map(|n| {
            let score = n.metrics.as_ref()
                .map(|m| {
                    let disk = m.disks.iter().map(|d| d.usage_percent).fold(0.0_f32, f32::max);
                    m.cpu_usage_percent * 0.4 + m.memory_percent * 0.4 + disk * 0.2
                })
                .unwrap_or(f32::MAX);
            (score, n.id.clone())
        })
        .collect();
    candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
        .then(a.1.cmp(&b.1)));
    candidates.into_iter().map(|(_, id)| id).collect()
}

// ═══════════════════════════════════════════════
// ─── Event dispatch ───
// ═══════════════════════════════════════════════

/// Global hook so subsystems without AppState access (alerting, backup)
/// can fire trigger events with one call. Set once at startup.
static EVENT_HOOK: std::sync::OnceLock<(
    Arc<WolfFunctionsState>,
    Arc<crate::agent::ClusterState>,
    String,
)> = std::sync::OnceLock::new();

pub fn init_event_hook(
    state: Arc<WolfFunctionsState>,
    cluster: Arc<crate::agent::ClusterState>,
    cluster_secret: String,
) {
    let _ = EVENT_HOOK.set((state, cluster, cluster_secret));
}

/// Fire an event from anywhere (sync or async context). No-ops when
/// nothing subscribes, so hot paths pay one RwLock read. `force_local`
/// is used for events that originate on exactly one node (alerts,
/// backups) — leader gating would drop them on non-leader nodes.
pub fn fire_event_global(event: TriggerEvent, payload: serde_json::Value, force_local: bool) {
    let Some((state, cluster, secret)) = EVENT_HOOK.get() else { return; };
    let any_subscriber = state.config.read().unwrap().functions.iter()
        .any(|f| f.enabled && f.events.contains(&event));
    if !any_subscriber { return; }
    let (state, cluster, secret) = (state.clone(), cluster.clone(), secret.clone());
    // Works from spawn_blocking threads too — they carry the runtime context.
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                fire_event(&state, &cluster, &secret, event, payload, force_local).await;
            });
        }
        Err(_) => warn!("WolfFunctions: event {:?} dropped — no tokio runtime in this thread", event),
    }
}

/// Fire an internal event: invoke every enabled function subscribed to it.
/// Called from the alerting engine, the reconciler's node-transition
/// detector, and the backup runner. Runs only on the leader for cluster
/// events so a 5-node cluster doesn't invoke everything five times;
/// `force_local` bypasses that for events that are inherently node-local.
pub async fn fire_event(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
    event: TriggerEvent,
    payload: serde_json::Value,
    force_local: bool,
) {
    if !force_local && !crate::wolfrun::is_leader(cluster) { return; }
    let self_cluster = self_cluster_name(cluster);
    let subscribed: Vec<WolfFunction> = state.config.read().unwrap().functions.iter()
        .filter(|f| f.enabled && f.cluster == self_cluster && f.events.contains(&event))
        .cloned()
        .collect();
    for func in subscribed {
        let event_json = serde_json::json!({
            "trigger": "event",
            "event": event,
            "payload": payload,
        });
        let outcome = runtime::invoke_routed(
            state, cluster, cluster_secret, &func, event_json, "event",
        ).await;
        if let Err(e) = outcome {
            warn!("WolfFunctions: event {:?} → {} failed: {}", event, func.name, e);
        }
    }
}
