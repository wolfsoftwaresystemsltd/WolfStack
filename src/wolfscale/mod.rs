// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com
//
// WolfScale cluster manager — builds + manages WolfScale replication clusters
// (single-leader, WAL-based, lowest-node-id-wins) the same way the Galera
// manager builds Galera clusters. Each node is an LXC container running MariaDB
// fronted by the `wolfscale` binary; WolfScale replicates writes leader→follower
// over its own protocol (port 7654), exposes a MySQL proxy (8007) and an HTTP
// control API (8080). Cluster-scoped, host-aware (cross-host builds + ops route
// by the peer's stable self_id — same model the Galera manager uses).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::mpsc::Sender;

const WS_CONFIG_PATH: &str = "/etc/wolfstack/wolfscale.json";
const WS_SECRET_PURPOSE: &[u8] = b"wolfscale-cluster-secret-v1";
static WS_IO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Base URL for prebuilt `wolfscale`/`wolfctl` binaries — the rolling
/// `wolfscale-latest` GitHub release produced by WolfScale's release pipeline
/// (.github/workflows/wolfscale-release.yml). The installer appends
/// `/wolfscale-<arch>` (x86_64 / aarch64) and falls back to a slow in-container
/// source build only if the download fails.
const WS_BINARY_BASE: &str = "https://github.com/wolfsoftwaresystemsltd/WolfScale/releases/download/wolfscale-latest";

fn default_cluster_port() -> u16 { 7654 }
fn default_api_port() -> u16 { 8080 }
fn default_proxy_port() -> u16 { 8007 }
fn default_kind() -> String { "lxc".into() }
fn default_db_user() -> String { "wolfscale".into() }
fn default_distro() -> String { "debian".into() }
fn default_release() -> String { "bookworm".into() }

/// One node of a WolfScale cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfScaleNode {
    /// WolfStack host node id (stable self_id) that runs this container.
    #[serde(default)]
    pub node_id: String,
    /// Container name on that host.
    pub container: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    /// WolfNet IP the node binds its cluster/proxy/API ports on, and that peers
    /// reach it at.
    pub address: String,
    /// WolfScale node id (the deterministic-election key — lowest wins).
    #[serde(default)]
    pub ws_id: String,
}

/// A managed WolfScale cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfScaleCluster {
    pub id: String,
    /// WolfScale `cluster_name` (also the display name).
    pub name: String,
    /// WolfStack cluster this belongs to (scopes the UI), like the Galera manager.
    #[serde(default)]
    pub cluster: String,
    /// Host whose wolfscale.json stores this definition (auto-set on save).
    #[serde(default)]
    pub owner_node: String,
    #[serde(default)]
    pub nodes: Vec<WolfScaleNode>,
    #[serde(default = "default_cluster_port")]
    pub cluster_port: u16,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// DB user WolfScale uses to apply writes to each node's MariaDB.
    #[serde(default = "default_db_user")]
    pub db_user: String,
    /// AES-256-GCM encrypted DB password (never serialised in plaintext).
    #[serde(default)]
    pub db_password_enc: String,
    #[serde(default)]
    pub created_at: String,
    /// True for clusters WolfStack provisioned (vs adopted).
    #[serde(default)]
    pub provisioned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfScaleConfig {
    #[serde(default)]
    pub clusters: Vec<WolfScaleCluster>,
}

// ── Persistence ──────────────────────────────────────────────────────

pub fn load_config() -> WolfScaleConfig {
    match fs::read_to_string(WS_CONFIG_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => WolfScaleConfig::default(),
    }
}

pub fn save_config(cfg: &WolfScaleConfig) -> Result<(), String> {
    if let Some(parent) = Path::new(WS_CONFIG_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(WS_CONFIG_PATH, json).map_err(|e| format!("write {}: {}", WS_CONFIG_PATH, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(WS_CONFIG_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn get_cluster(id: &str) -> Option<WolfScaleCluster> {
    load_config().clusters.into_iter().find(|c| c.id == id)
}

/// Upsert a cluster. Re-encrypts a non-empty plaintext password; preserves the
/// stored ciphertext when none is given. Stamps owner_node = this node.
pub fn upsert_cluster(mut cluster: WolfScaleCluster, plain_password: Option<&str>) -> Result<WolfScaleCluster, String> {
    safe_token(&cluster.name)?;
    for n in &cluster.nodes {
        safe_token(&n.container)?;
        if !n.ws_id.trim().is_empty() { safe_token(&n.ws_id)?; }
        if !valid_address(&n.address) {
            return Err(format!("invalid node address '{}'", n.address));
        }
    }
    for n in cluster.nodes.iter_mut() {
        if n.ws_id.trim().is_empty() { n.ws_id = n.container.clone(); }
    }
    if cluster.owner_node.is_empty() {
        cluster.owner_node = crate::agent::self_node_id();
    }
    let _io = WS_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let existing_enc = cfg.clusters.iter().find(|c| c.id == cluster.id)
        .map(|c| c.db_password_enc.clone()).unwrap_or_default();
    cluster.db_password_enc = match plain_password {
        Some(pw) if !pw.is_empty() => enc_secret(pw),
        _ => existing_enc,
    };
    match cfg.clusters.iter_mut().find(|c| c.id == cluster.id) {
        Some(slot) => *slot = cluster.clone(),
        None => cfg.clusters.push(cluster.clone()),
    }
    save_config(&cfg)?;
    Ok(cluster)
}

pub fn delete_cluster(id: &str) -> Result<(), String> {
    let _io = WS_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c.id != id);
    if cfg.clusters.len() == before {
        return Err(format!("cluster '{}' not found", id));
    }
    save_config(&cfg)
}

/// Re-tag stored clusters when a WolfStack cluster is renamed
/// (case-insensitive; empty/unscoped tags untouched). Returns changes.
pub fn rename_wolfstack_cluster_tags(old_name: &str, new_name: &str) -> usize {
    let mut cfg = load_config();
    let mut n = 0;
    for c in cfg.clusters.iter_mut() {
        if !c.cluster.is_empty() && c.cluster.eq_ignore_ascii_case(old_name) {
            c.cluster = new_name.to_string();
            n += 1;
        }
    }
    if n > 0 { let _ = save_config(&cfg); }
    n
}

pub fn enc_secret(plain: &str) -> String {
    crate::at_rest_crypto::encrypt(plain.as_bytes(), WS_SECRET_PURPOSE).unwrap_or_default()
}

// ── Validation + container exec ──────────────────────────────────────

/// Allow only names/addresses that are safe to drop into a shell, a container
/// command, a TOML file, or a DOM attribute. Reject rather than escape.
fn safe_token(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64 {
        return Err(format!("'{}' must be 1–64 chars", s));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(format!("'{}' may only contain letters, digits, . _ -", s));
    }
    Ok(())
}

fn valid_address(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-'))
}

/// Run a command inside an LXC container (pct when present, else lxc-attach).
fn lxc_exec(container: &str, cmd: &str) -> Result<String, String> {
    let mut c = if std::process::Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut c = std::process::Command::new("pct");
        c.arg("exec").arg(container).arg("--").arg("sh").arg("-c").arg(cmd);
        c
    } else {
        let mut c = std::process::Command::new("lxc-attach");
        c.arg("-n").arg(container).arg("--").arg("sh").arg("-c").arg(cmd);
        c
    };
    let out = c.output().map_err(|e| format!("exec {}: {}", container, e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("[{}] command failed: {}", container, String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Like lxc_exec but STREAMS combined output to the SSE log line-by-line (so a
/// long install reads like a terminal). stderr merged into stdout.
fn lxc_exec_streamed(container: &str, cmd: &str, log: &Sender<String>) -> Result<(), String> {
    use std::io::{BufReader, Read};
    use std::process::Stdio;
    let merged = format!("{{ {} ; }} 2>&1", cmd);
    let mut command = if std::process::Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut c = std::process::Command::new("pct");
        c.arg("exec").arg(container).arg("--").arg("sh").arg("-c").arg(&merged);
        c
    } else {
        let mut c = std::process::Command::new("lxc-attach");
        c.arg("-n").arg(container).arg("--").arg("sh").arg("-c").arg(&merged);
        c
    };
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|e| format!("exec {}: {}", container, e))?;
    if let Some(out) = child.stdout.take() {
        let mut reader = BufReader::new(out);
        let mut byte = [0u8; 1];
        let mut line = String::new();
        while reader.read(&mut byte).unwrap_or(0) > 0 {
            let ch = byte[0] as char;
            if ch == '\n' || ch == '\r' {
                let t = line.trim_end();
                if !t.is_empty() { let _ = log.send(format!("  {}", t)); }
                line.clear();
            } else {
                line.push(ch);
            }
        }
        let t = line.trim_end();
        if !t.is_empty() { let _ = log.send(format!("  {}", t)); }
    }
    let status = child.wait().map_err(|e| format!("[{}] wait failed: {}", container, e))?;
    if status.success() { Ok(()) } else { Err(format!("[{}] command failed (see output above)", container)) }
}

fn logln(log: &Sender<String>, msg: impl Into<String>) {
    let _ = log.send(msg.into());
}

fn distro_family(distro: &str) -> &'static str {
    match distro.to_lowercase().as_str() {
        "debian" | "ubuntu" => "deb",
        "fedora" | "centos" | "rhel" | "rocky" | "almalinux" => "rhel",
        _ => "deb",
    }
}

/// Packages to install before WolfScale: MariaDB server/client + curl. WolfScale
/// ships only for Debian/Ubuntu + RHEL/Rocky here (it needs a build toolchain if
/// the prebuilt binary isn't reachable); refuse others rather than half-build.
fn base_install_cmd(distro: &str) -> Result<&'static str, String> {
    Ok(match distro_family(distro) {
        "deb" => "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y mariadb-server mariadb-client curl ca-certificates",
        "rhel" => "dnf install -y mariadb-server mariadb curl ca-certificates || yum install -y mariadb-server mariadb curl ca-certificates",
        other => return Err(format!("WolfScale build is supported on Debian/Ubuntu or RHEL/Rocky, not '{}'.", other)),
    })
}

/// In-container WolfScale install: fetch the prebuilt binary; on failure fall
/// back to a source build. Returns a single shell script.
fn wolfscale_install_cmd(distro: &str) -> String {
    let src_build = match distro_family(distro) {
        "rhel" => "dnf install -y git gcc gcc-c++ make openssl-devel pkgconfig || yum install -y git gcc gcc-c++ make openssl-devel pkgconfig",
        _ => "apt-get install -y git build-essential pkg-config libssl-dev",
    };
    format!(
        "a=$(uname -m); case \"$a\" in x86_64|amd64) a=x86_64;; aarch64|arm64) a=aarch64;; *) a=;; esac; \
         if [ -n \"$a\" ] && curl -fsSL {base}/wolfscale-$a -o /usr/local/bin/wolfscale && chmod +x /usr/local/bin/wolfscale && /usr/local/bin/wolfscale --version >/dev/null 2>&1; then \
           (curl -fsSL {base}/wolfctl-$a -o /usr/local/bin/wolfctl && chmod +x /usr/local/bin/wolfctl) 2>/dev/null || true; \
           echo 'wolfscale: installed prebuilt binary'; \
         else \
           echo 'wolfscale: prebuilt binary unavailable — building from source (this is slow)…'; \
           {src} && \
           (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y) && \
           . \"$HOME/.cargo/env\" && \
           rm -rf /opt/wolfscale-src && git clone --depth 1 https://github.com/wolfsoftwaresystemsltd/WolfScale /opt/wolfscale-src && \
           (cd /opt/wolfscale-src && cargo build --release) && \
           cp /opt/wolfscale-src/target/release/wolfscale /usr/local/bin/wolfscale && \
           (cp /opt/wolfscale-src/target/release/wolfctl /usr/local/bin/wolfctl 2>/dev/null || true) && \
           chmod +x /usr/local/bin/wolfscale; \
         fi",
        base = WS_BINARY_BASE, src = src_build)
}

/// Render a node's wolfscale.toml. `peers` is the full member address list
/// (each `ip:cluster_port`); the node ignores its own entry. Static peers are
/// used (not UDP broadcast) because broadcast doesn't cross a routed overlay.
#[allow(clippy::too_many_arguments)]
fn wolfscale_toml(ws_id: &str, bind: &str, peers: &[String], cluster_name: &str, db_user: &str, db_password: &str, cluster_port: u16, api_port: u16, proxy_port: u16) -> String {
    let peer_list = peers.iter().map(|p| format!("\"{}\"", p)).collect::<Vec<_>>().join(", ");
    format!(
        "[node]\n\
         id = \"{ws_id}\"\n\
         bind_address = \"{bind}:{cport}\"\n\
         advertise_address = \"{bind}:{cport}\"\n\
         data_dir = \"/var/lib/wolfscale\"\n\
         \n\
         [database]\n\
         host = \"127.0.0.1\"\n\
         port = 3306\n\
         user = \"{db_user}\"\n\
         password = \"{db_password}\"\n\
         \n\
         [cluster]\n\
         cluster_name = \"{cluster_name}\"\n\
         peers = [{peers}]\n\
         auto_discovery = true\n\
         \n\
         [api]\n\
         enabled = true\n\
         bind_address = \"0.0.0.0:{aport}\"\n\
         \n\
         [proxy]\n\
         enabled = true\n\
         bind_address = \"0.0.0.0:{pport}\"\n\
         \n\
         [replication]\n\
         mode = \"proxy\"\n",
        ws_id = ws_id, bind = bind, cport = cluster_port, db_user = db_user,
        db_password = db_password, cluster_name = cluster_name, peers = peer_list,
        aport = api_port, pport = proxy_port,
    )
}

/// A password safe to drop into BOTH a TOML string AND a SQL literal unescaped:
/// no quotes, backslash, whitespace or control chars. Restrictive by design.
fn valid_secret(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '%' | '+' | '=' | '!' | '~'))
}

// ── Live status (HTTP poll of each node's control API) ───────────────

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub container: String,
    pub address: String,
    pub reachable: bool,
    #[serde(default)]
    pub error: String,
    pub ws_id: String,
    pub is_leader: bool,
    pub leader_id: String,
    pub last_applied_lsn: u64,
    pub cluster_size: i64,
    pub has_quorum: bool,
    /// Entries behind the most-advanced node (0 for the furthest-ahead).
    pub lag: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterStatus {
    pub cluster_id: String,
    pub nodes: Vec<NodeStatus>,
    pub leader: String,
    pub healthy: bool,
    pub summary: String,
}

pub async fn cluster_status(cluster: &WolfScaleCluster) -> ClusterStatus {
    let mut nodes: Vec<NodeStatus> = futures::future::join_all(
        cluster.nodes.iter().map(|n| node_status(n, cluster.api_port))
    ).await;

    let max_lsn = nodes.iter().filter(|s| s.reachable).map(|s| s.last_applied_lsn).max().unwrap_or(0);
    for s in nodes.iter_mut() {
        if s.reachable { s.lag = max_lsn.saturating_sub(s.last_applied_lsn); }
    }

    let reachable: Vec<&NodeStatus> = nodes.iter().filter(|s| s.reachable).collect();
    // Leader: who the reachable nodes agree on. Split if they disagree.
    let leaders: HashSet<&str> = reachable.iter().map(|s| s.leader_id.as_str()).filter(|l| !l.is_empty()).collect();
    let leader = if leaders.len() == 1 { leaders.iter().next().map(|s| s.to_string()).unwrap_or_default() } else { String::new() };
    let all_quorum = !reachable.is_empty() && reachable.iter().all(|s| s.has_quorum);
    let healthy = all_quorum && leaders.len() == 1 && reachable.len() == cluster.nodes.len();

    let summary = if cluster.nodes.is_empty() {
        "No nodes registered".to_string()
    } else if reachable.is_empty() {
        "Down — no nodes reachable".to_string()
    } else if leaders.len() > 1 {
        "Split — reachable nodes disagree on the leader".to_string()
    } else if leader.is_empty() {
        format!("No leader elected — {}/{} nodes up", reachable.len(), cluster.nodes.len())
    } else if healthy {
        format!("Healthy — leader {}, {}/{} nodes up", leader, reachable.len(), cluster.nodes.len())
    } else {
        format!("Degraded — leader {}, {}/{} nodes up", leader, reachable.len(), cluster.nodes.len())
    };

    ClusterStatus { cluster_id: cluster.id.clone(), nodes, leader, healthy, summary }
}

async fn node_status(n: &WolfScaleNode, api_port: u16) -> NodeStatus {
    let mut st = NodeStatus {
        container: n.container.clone(),
        address: n.address.clone(),
        reachable: false,
        error: String::new(),
        ws_id: n.ws_id.clone(),
        is_leader: false,
        leader_id: String::new(),
        last_applied_lsn: 0,
        cluster_size: 0,
        has_quorum: false,
        lag: 0,
    };
    let url = format!("http://{}:{}/status", n.address, api_port);
    match crate::api::API_HTTP_CLIENT.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                let v: serde_json::Value = resp.json().await.unwrap_or_default();
                st.reachable = true;
                st.is_leader = v.get("is_leader").and_then(|x| x.as_bool()).unwrap_or(false);
                st.leader_id = v.get("leader_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                st.last_applied_lsn = v.get("last_applied_lsn").and_then(|x| x.as_u64()).unwrap_or(0);
                st.cluster_size = v.get("cluster_size").and_then(|x| x.as_i64()).unwrap_or(0);
                st.has_quorum = v.get("has_quorum").and_then(|x| x.as_bool()).unwrap_or(false);
                if st.ws_id.is_empty() {
                    st.ws_id = v.get("node_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                }
            } else {
                st.error = format!("HTTP {}", resp.status());
            }
        }
        Err(e) => st.error = e.to_string(),
    }
    st
}

// ── Host-aware op context (cross-host build + lifecycle routing) ─────

pub struct WolfScaleOpCtx {
    pub self_id: String,
    pub nodes: Vec<crate::agent::Node>,
    pub cluster_secret: String,
    pub rt: tokio::runtime::Handle,
}

impl WolfScaleOpCtx {
    /// Resolve a host ref by its local `node-{uuid}` key OR its stable self_id
    /// (cross-host calls arrive with the self_id). Mirrors the Galera manager.
    fn resolve_host(&self, host: &str) -> Option<&crate::agent::Node> {
        self.nodes.iter().find(|n| n.id == host || n.self_id.as_deref() == Some(host))
    }
    fn is_self_host(&self, host: &str) -> bool {
        host.is_empty()
            || host == self.self_id
            || self.nodes.iter().any(|n| n.is_self && (n.id == host || n.self_id.as_deref() == Some(host)))
    }
}

fn host_label(ctx: &WolfScaleOpCtx, host: &str) -> String {
    ctx.resolve_host(host)
        .map(|n| n.hostname.clone())
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| host.to_string())
}

// ── Provision (cross-host fresh cluster) ─────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub cluster_name: String,
    #[serde(default)]
    pub cluster: String,
    pub container_names: Vec<String>,
    /// Per-node target host (self_id), parallel to container_names; empty falls
    /// back to `node_id` (the home host).
    #[serde(default)]
    pub container_hosts: Vec<String>,
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
    /// Root/db password for each node's MariaDB + WolfScale's apply user.
    pub db_password: String,
    /// Home host the definition is stored on + orchestration runs on.
    #[serde(default)]
    pub node_id: String,
}

/// Provision a fresh WolfScale cluster. Each node's container is built on its
/// chosen host; a fresh cluster starts with empty, identical MariaDB on every
/// node (the "all nodes identical before start" rule is satisfied trivially),
/// so there's no seeding — they start, elect the lowest-id leader, and replicate
/// forward. Returns the persisted cluster.
pub fn provision_cluster(p: &ProvisionRequest, log: &Sender<String>, ctx: &WolfScaleOpCtx) -> Result<WolfScaleCluster, String> {
    let names: Vec<String> = p.container_names.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if names.is_empty() || names.len() > 9 {
        return Err("a cluster needs between 1 and 9 nodes".into());
    }
    if !valid_secret(&p.db_password) {
        return Err("db password must be 1–128 chars from letters, digits and . _ - @ % + = ! ~".into());
    }
    safe_token(&p.cluster_name)?;
    for cname in &names { safe_token(cname)?; }
    if names.iter().collect::<HashSet<_>>().len() != names.len() {
        return Err("container names must be unique".into());
    }
    let _ = base_install_cmd(&p.distribution)?; // validate distro up front

    let hosts: Vec<String> = (0..names.len()).map(|i| {
        p.container_hosts.get(i).map(|h| h.trim().to_string()).filter(|h| !h.is_empty())
            .unwrap_or_else(|| p.node_id.clone())
    }).collect();

    let ips = crate::containers::next_available_wolfnet_ips(names.len())
        .ok_or_else(|| format!("not enough free WolfNet IPs for {} node(s)", names.len()))?;
    logln(log, format!("Reserved {} WolfNet address(es): {}.", ips.len(), ips.join(", ")));

    let cluster_id = uuid::Uuid::new_v4().to_string();
    let nodes: Vec<WolfScaleNode> = names.iter().enumerate().map(|(i, cname)| WolfScaleNode {
        node_id: hosts[i].clone(),
        container: cname.clone(),
        kind: "lxc".into(),
        address: ips[i].clone(),
        ws_id: cname.clone(),
    }).collect();

    // Persist NOW so the cluster appears immediately and survives a mid-build
    // failure (status shows "unreachable" until WolfScale is up).
    let spread = hosts.iter().collect::<HashSet<_>>().len();
    logln(log, format!("Registered '{}' — building {} node(s) across {} host(s)…", p.cluster_name, nodes.len(), spread));
    let saved = upsert_cluster(WolfScaleCluster {
        id: cluster_id,
        name: p.cluster_name.clone(),
        cluster: p.cluster.clone(),
        owner_node: String::new(),
        nodes: nodes.clone(),
        cluster_port: default_cluster_port(),
        api_port: default_api_port(),
        proxy_port: default_proxy_port(),
        db_user: default_db_user(),
        db_password_enc: String::new(),
        created_at: chrono::Utc::now().to_rfc3339(),
        provisioned: true,
    }, Some(&p.db_password))?;

    // Full static peer list (every member's cluster endpoint).
    let peers: Vec<String> = nodes.iter().map(|n| format!("{}:{}", n.address, saved.cluster_port)).collect();
    // WolfScale elects the lexically-lowest node id as leader, so bootstrap that
    // node (not whichever the operator listed first) — otherwise the bootstrap
    // node loses leadership the moment the real lowest-id node joins.
    let bootstrap_ws = nodes.iter().map(|n| n.ws_id.as_str()).min().unwrap_or("").to_string();

    for n in nodes.iter() {
        let bootstrap = n.ws_id == bootstrap_ws;
        let spec = NodeSpec {
            container: n.container.clone(),
            distribution: p.distribution.clone(),
            release: p.release.clone(),
            address: n.address.clone(),
            ws_id: n.ws_id.clone(),
            cluster_name: saved.name.clone(),
            peers: peers.clone(),
            db_user: saved.db_user.clone(),
            db_password: p.db_password.clone(),
            cluster_port: saved.cluster_port,
            api_port: saved.api_port,
            proxy_port: saved.proxy_port,
            bootstrap,
        };
        if ctx.is_self_host(&n.node_id) {
            logln(log, format!("[{}] building node…", n.container));
            setup_node_local(&spec, n.address.as_str(), log)?;
        } else {
            logln(log, format!("[{}] building on {}…", n.container, host_label(ctx, &n.node_id)));
            setup_node_remote(ctx, &n.node_id, &spec, n.address.as_str(), log)
                .map_err(|e| format!("[{}] build on {} failed: {}", n.container, host_label(ctx, &n.node_id), e))?;
            logln(log, format!("[{}] built on {}.", n.container, host_label(ctx, &n.node_id)));
        }
    }

    logln(log, format!("All {} node(s) up — WolfScale will elect '{}' (lowest id) as the leader.", nodes.len(), bootstrap_ws));
    Ok(saved)
}

/// Everything one node's local build needs. Serialised to the build primitive
/// when the node lives on a peer host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSpec {
    pub container: String,
    pub distribution: String,
    pub release: String,
    pub address: String,
    pub ws_id: String,
    pub cluster_name: String,
    pub peers: Vec<String>,
    pub db_user: String,
    pub db_password: String,
    pub cluster_port: u16,
    pub api_port: u16,
    pub proxy_port: u16,
    pub bootstrap: bool,
}

/// Build + start one WolfScale node on THIS host: create the container, attach
/// the WolfNet IP, install MariaDB + WolfScale, set the DB user + root password,
/// write wolfscale.toml + a systemd unit, and start MariaDB then WolfScale.
fn setup_node_local(spec: &NodeSpec, address: &str, log: &Sender<String>) -> Result<(), String> {
    safe_token(&spec.container)?;
    if !valid_secret(&spec.db_password) {
        return Err("invalid db password".into());
    }
    crate::containers::lxc_create(&spec.container, &spec.distribution, &spec.release, "amd64", None, None)?;
    crate::containers::lxc_start(&spec.container)?;
    logln(log, format!("[{}] attaching WolfNet IP {}…", spec.container, address));
    let _ = crate::containers::lxc_attach_wolfnet(&spec.container, address);

    // Wait for init/network to settle before installing.
    let _ = lxc_exec(&spec.container,
        "cloud-init status --wait >/dev/null 2>&1; for i in $(seq 1 30); do command -v systemctl >/dev/null 2>&1 && systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done");

    logln(log, format!("[{}] installing MariaDB…", spec.container));
    let base = base_install_cmd(&spec.distribution)?;
    lxc_exec_streamed(&spec.container, base, log)?;
    logln(log, format!("[{}] installing WolfScale…", spec.container));
    lxc_exec_streamed(&spec.container, &wolfscale_install_cmd(&spec.distribution), log)?;

    // MariaDB up, then root password + the apply user (used by WolfScale on
    // 127.0.0.1). Password validated to a safe charset, so the SQL literal and
    // TOML value are both safe unescaped; still piped via base64 to avoid the shell.
    lxc_exec(&spec.container, "systemctl enable mariadb >/dev/null 2>&1 || true; systemctl start mariadb 2>/dev/null || systemctl start mysqld 2>/dev/null || true")?;
    let sql = format!(
        "ALTER USER 'root'@'localhost' IDENTIFIED BY '{pw}'; \
         CREATE USER IF NOT EXISTS '{u}'@'127.0.0.1' IDENTIFIED BY '{pw}'; \
         CREATE USER IF NOT EXISTS '{u}'@'localhost' IDENTIFIED BY '{pw}'; \
         GRANT ALL PRIVILEGES ON *.* TO '{u}'@'127.0.0.1' WITH GRANT OPTION; \
         GRANT ALL PRIVILEGES ON *.* TO '{u}'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;",
        u = spec.db_user, pw = spec.db_password);
    let sql_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(sql.as_bytes())
    };
    lxc_exec(&spec.container, &format!("printf %s '{}' | base64 -d | mysql", sql_b64))?;

    // Write wolfscale.toml (base64'd — the password never touches the shell).
    let toml = wolfscale_toml(&spec.ws_id, address, &spec.peers, &spec.cluster_name, &spec.db_user, &spec.db_password, spec.cluster_port, spec.api_port, spec.proxy_port);
    let toml_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(toml.as_bytes())
    };
    lxc_exec(&spec.container, &format!("mkdir -p /etc/wolfscale /var/lib/wolfscale && printf %s '{}' | base64 -d > /etc/wolfscale/wolfscale.toml && chmod 600 /etc/wolfscale/wolfscale.toml", toml_b64))?;

    // systemd unit (bootstrap flag on the initial leader only).
    let exec = if spec.bootstrap {
        "/usr/local/bin/wolfscale --config /etc/wolfscale/wolfscale.toml start --bootstrap"
    } else {
        "/usr/local/bin/wolfscale --config /etc/wolfscale/wolfscale.toml start"
    };
    let unit = format!(
        "[Unit]\nDescription=WolfScale\nAfter=network.target mariadb.service\nWants=mariadb.service\n\n\
         [Service]\nType=simple\nExecStart={exec}\nRestart=always\nRestartSec=5\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        exec = exec);
    let unit_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(unit.as_bytes())
    };
    lxc_exec(&spec.container, &format!("printf %s '{}' | base64 -d > /etc/systemd/system/wolfscale.service", unit_b64))?;

    logln(log, format!("[{}] starting WolfScale…", spec.container));
    lxc_exec(&spec.container, "systemctl daemon-reload >/dev/null 2>&1 || true; systemctl enable wolfscale >/dev/null 2>&1 || true; systemctl restart wolfscale")
        .map_err(|e| format!("[{}] WolfScale failed to start ({}). Console in and run 'journalctl -u wolfscale -n50'.", spec.container, e))?;
    Ok(())
}

/// Build primitive entry point (home host calls this on a peer for a node there).
pub fn local_setup_node(spec: &NodeSpec) -> Result<(), String> {
    // Log is intentionally discarded on the peer (sends fail silently, no
    // deadlock) — the home host streams coarse milestones via the SSE heartbeat;
    // only the final Err propagates back.
    let (tx, _rx) = std::sync::mpsc::channel();
    setup_node_local(spec, &spec.address.clone(), &tx)
}

/// Build a node on a peer host via its setup primitive (install can be slow when
/// the WolfScale binary is built from source, so the timeout is generous + we
/// heartbeat the SSE log to keep it from idling).
fn setup_node_remote(ctx: &WolfScaleOpCtx, host: &str, spec: &NodeSpec, _address: &str, log: &Sender<String>) -> Result<(), String> {
    let target = ctx.resolve_host(host).ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/wolfscale/local/setup/{}", spec.container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let body = serde_json::to_value(spec).map_err(|e| e.to_string())?;
    post_to_peer(ctx, &urls, &body, 2400, host, log, &format!("building {}", spec.container))
}

fn post_to_peer(ctx: &WolfScaleOpCtx, urls: &[String], body: &serde_json::Value, timeout_secs: u64, host: &str, log: &Sender<String>, label: &str) -> Result<(), String> {
    let secret = ctx.cluster_secret.clone();
    ctx.rt.block_on(async move {
        let mut last = format!("could not reach host '{}'", host);
        for url in urls {
            let req = crate::api::API_HTTP_CLIENT.post(url)
                .header("X-WolfStack-Secret", &secret)
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .json(body)
                .send();
            tokio::pin!(req);
            let mut beat = tokio::time::interval(std::time::Duration::from_secs(20));
            beat.tick().await;
            let resp = loop {
                tokio::select! {
                    r = &mut req => break r,
                    _ = beat.tick() => { let _ = log.send(format!("  …{}", label)); }
                }
            };
            match resp {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    if ok { return Ok(()); }
                    last = v.get("error").and_then(|e| e.as_str()).unwrap_or("remote error").to_string();
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
}

// ── Lifecycle (host-aware: start/stop/restart the WolfScale service) ──

#[derive(Clone, Copy, PartialEq)]
pub enum NodeOp { Start, Stop, Restart, Exists, Address }

impl NodeOp {
    fn as_str(self) -> &'static str {
        match self {
            NodeOp::Start => "start", NodeOp::Stop => "stop",
            NodeOp::Restart => "restart", NodeOp::Exists => "exists",
            NodeOp::Address => "address",
        }
    }
    pub fn from_str(s: &str) -> Option<NodeOp> {
        match s {
            "start" => Some(NodeOp::Start), "stop" => Some(NodeOp::Stop),
            "restart" => Some(NodeOp::Restart), "exists" => Some(NodeOp::Exists),
            "address" => Some(NodeOp::Address),
            _ => None,
        }
    }
}

/// Resolve an LXC container's reachable IP on THIS host (same source the Galera
/// adopt uses), so adopt doesn't make the operator type addresses.
fn node_address_local(container: &str) -> String {
    crate::containers::lxc_list_all_cached().iter()
        .find(|c| c.name == container)
        .map(|c| c.ip_address.clone())
        .unwrap_or_default()
}

fn container_exists_local(container: &str) -> bool {
    if std::process::Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        std::process::Command::new("pct").arg("status").arg(container).output()
            .map(|o| o.status.success()).unwrap_or(false)
    } else {
        std::process::Command::new("lxc-info").arg("-n").arg(container).output()
            .map(|o| o.status.success()).unwrap_or(false)
    }
}

/// Run one WolfScale node op on a container on THIS host.
pub fn local_node_op(container: &str, op: NodeOp) -> Result<String, String> {
    safe_token(container)?;
    if op == NodeOp::Exists {
        return Ok(if container_exists_local(container) { "yes".into() } else { "no".into() });
    }
    if op == NodeOp::Address {
        return Ok(node_address_local(container));
    }
    if !container_exists_local(container) {
        return Err(format!("container '{}' is not on this host", container));
    }
    let action = op.as_str();
    lxc_exec(container, &format!("systemctl {a} wolfscale", a = action))
}

/// Run a node op against `host` — local fast-path when it's this node.
fn run_op(ctx: &WolfScaleOpCtx, host: &str, container: &str, op: NodeOp) -> Result<String, String> {
    if ctx.is_self_host(host) {
        local_node_op(container, op)
    } else {
        remote_node_op(ctx, host, container, op)
    }
}

fn remote_node_op(ctx: &WolfScaleOpCtx, host: &str, container: &str, op: NodeOp) -> Result<String, String> {
    let target = ctx.resolve_host(host).ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/wolfscale/local/op/{}/{}", op.as_str(), container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let secret = ctx.cluster_secret.clone();
    ctx.rt.block_on(async move {
        let mut last = format!("could not reach host '{}'", host);
        for url in &urls {
            match crate::api::API_HTTP_CLIENT.post(url)
                .header("X-WolfStack-Secret", &secret)
                .timeout(std::time::Duration::from_secs(30))
                .send().await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    if ok { return Ok(v.get("output").and_then(|o| o.as_str()).unwrap_or("").to_string()); }
                    last = v.get("error").and_then(|e| e.as_str()).unwrap_or("remote error").to_string();
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
}

fn exists_on_host(ctx: &WolfScaleOpCtx, host: &str, container: &str) -> bool {
    if ctx.is_self_host(host) { return container_exists_local(container); }
    remote_node_op(ctx, host, container, NodeOp::Exists).map(|o| o.trim() == "yes").unwrap_or(false)
}

/// Find the host currently running `container` (recorded first, then self, then
/// every cluster node) so a migrated container is reached where it now lives.
fn locate_host(ctx: &WolfScaleOpCtx, container: &str, recorded: &str) -> Result<String, String> {
    let mut candidates: Vec<String> = Vec::new();
    for id in std::iter::once(recorded.to_string())
        .chain(std::iter::once(ctx.self_id.clone()))
        .chain(ctx.nodes.iter().map(|n| n.id.clone()))
    {
        if !id.is_empty() && !candidates.contains(&id) { candidates.push(id); }
    }
    for host in &candidates {
        if exists_on_host(ctx, host, container) { return Ok(host.clone()); }
    }
    Err(format!("container '{}' was not found on any node in this cluster", container))
}

pub fn node_service(cluster: &WolfScaleCluster, container: &str, action: &str, ctx: &WolfScaleOpCtx) -> Result<String, String> {
    let recorded = cluster.nodes.iter().find(|n| n.container == container)
        .map(|n| n.node_id.clone())
        .ok_or_else(|| format!("'{}' is not a node of this cluster", container))?;
    let op = NodeOp::from_str(action).ok_or("action must be start, stop or restart")?;
    let host = locate_host(ctx, container, &recorded)?;
    if ctx.is_self_host(&host) {
        local_node_op(container, op)
    } else {
        remote_node_op(ctx, &host, container, op)
    }
}

/// Promote/demote a node by hitting its WolfScale control API directly (network,
/// not host-aware). `action` is "promote" or "demote".
pub async fn node_admin(cluster: &WolfScaleCluster, container: &str, action: &str) -> Result<String, String> {
    if action != "promote" && action != "demote" {
        return Err("action must be promote or demote".into());
    }
    let n = cluster.nodes.iter().find(|n| n.container == container)
        .ok_or_else(|| format!("'{}' is not a node of this cluster", container))?;
    let url = format!("http://{}:{}/admin/{}", n.address, cluster.api_port, action);
    match crate::api::API_HTTP_CLIENT.post(&url).timeout(std::time::Duration::from_secs(10)).send().await {
        Ok(resp) if resp.status().is_success() => Ok(format!("{} ok", action)),
        Ok(resp) => Err(format!("HTTP {}", resp.status())),
        Err(e) => Err(e.to_string()),
    }
}

// ── Adopt existing WolfScale nodes ───────────────────────────────────

pub struct AdoptPick {
    pub node_id: String,
    pub container: String,
    pub ws_id: String,
}

/// Adopt existing WolfScale containers into a managed cluster. Each picked
/// container's reachable address is resolved ON ITS HOST (host-aware) — no IPs
/// to type, same as the Galera adopt.
#[allow(clippy::too_many_arguments)]
/// A node's reported address can be a comma/space-separated list when its
/// container has several NICs (the lxcbr0 bridge + a LAN/vSwitch NIC + a
/// WolfNet overlay NIC). Pick a single address usable for cross-host cluster
/// traffic: prefer any address that is NOT host-local (the lxcbr0 bridge
/// 10.0.3.0/24, loopback, or link-local), falling back to the first valid
/// candidate.
///
/// JJ 2026-06: adoption failed with "no reachable address found (got
/// 10.0.3.3, 10.10.10.3)" because the raw multi-IP string failed validation —
/// now we fall back to the reachable LAN address (10.10.10.3) when the WolfNet
/// overlay address isn't present (e.g. WolfNet partially down). This is the
/// requested LAN-fallback for adoption when WolfNet is unreachable.
fn pick_usable_address(raw: &str) -> Option<String> {
    let candidates: Vec<std::net::Ipv4Addr> = raw
        .split([',', ' ', '\t', '\n', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .collect();
    let host_local = |ip: &std::net::Ipv4Addr| {
        let o = ip.octets();
        ip.is_loopback()
            || ip.is_link_local()
            || (o[0] == 10 && o[1] == 0 && o[2] == 3) // lxcbr0 bridge — host-local
    };
    candidates.iter().find(|ip| !host_local(ip))
        .or_else(|| candidates.first())
        .map(|ip| ip.to_string())
}

pub fn adopt_cluster(
    ws_cluster: &str, name: &str, db_user: &str, db_password: &str,
    cluster_port: u16, api_port: u16, proxy_port: u16, picks: &[AdoptPick],
    ctx: &WolfScaleOpCtx,
) -> Result<WolfScaleCluster, String> {
    if picks.is_empty() {
        return Err("select at least one container".into());
    }
    safe_token(name)?;
    if !db_user.is_empty() { safe_token(db_user)?; }
    if !db_password.is_empty() && !valid_secret(db_password) {
        return Err("db password must be 1–128 chars from letters, digits and . _ - @ % + = ! ~".into());
    }
    let mut nodes: Vec<WolfScaleNode> = Vec::with_capacity(picks.len());
    for p in picks {
        safe_token(&p.container)?;
        // Always probe-locate (picked id is just a hint) so a peer self_id this
        // node hasn't directly polled still resolves — routing is by local key.
        let host = locate_host(ctx, &p.container, &p.node_id)?;
        let raw = run_op(ctx, &host, &p.container, NodeOp::Address)
            .map_err(|e| format!("[{}] couldn't resolve address: {}", p.container, e))?;
        // A container can report several NICs (lxcbr0 bridge + LAN + WolfNet
        // overlay); pick one reachable from other hosts, falling back to the
        // LAN address when the WolfNet overlay address isn't present (e.g.
        // WolfNet partially down). JJ 2026-06.
        let addr = pick_usable_address(&raw)
            .filter(|a| valid_address(a))
            .ok_or_else(|| format!(
                "[{}] no usable address found (got '{}') — give the container a reachable LAN or WolfNet IP and retry",
                p.container, raw.trim()))?;
        nodes.push(WolfScaleNode {
            node_id: host,
            container: p.container.clone(),
            kind: "lxc".into(),
            address: addr,
            ws_id: if p.ws_id.trim().is_empty() { p.container.clone() } else { p.ws_id.clone() },
        });
    }
    let cluster = WolfScaleCluster {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        cluster: ws_cluster.to_string(),
        owner_node: String::new(),
        nodes,
        cluster_port: if cluster_port == 0 { default_cluster_port() } else { cluster_port },
        api_port: if api_port == 0 { default_api_port() } else { api_port },
        proxy_port: if proxy_port == 0 { default_proxy_port() } else { proxy_port },
        db_user: if db_user.is_empty() { default_db_user() } else { db_user.to_string() },
        db_password_enc: String::new(),
        created_at: chrono::Utc::now().to_rfc3339(),
        provisioned: false,
    };
    let pw = if db_password.is_empty() { None } else { Some(db_password) };
    upsert_cluster(cluster, pw)
}

#[cfg(test)]
mod tests {
    use super::pick_usable_address;

    // JJ 2026-06: adoption got "10.0.3.3, 10.10.10.3" — the bridge IP first,
    // then the reachable LAN. We must pick the LAN (cross-host reachable), not
    // the host-local lxcbr0 bridge, and not reject the whole list.
    #[test]
    fn picks_lan_over_bridge() {
        assert_eq!(pick_usable_address("10.0.3.3, 10.10.10.3").as_deref(), Some("10.10.10.3"));
        assert_eq!(pick_usable_address("10.10.10.3 10.0.3.3").as_deref(), Some("10.10.10.3"));
    }

    #[test]
    fn single_or_only_bridge_falls_back() {
        assert_eq!(pick_usable_address("10.10.10.3").as_deref(), Some("10.10.10.3"));
        // only the bridge IP available → use it rather than failing
        assert_eq!(pick_usable_address("10.0.3.3").as_deref(), Some("10.0.3.3"));
    }

    #[test]
    fn rejects_loopback_linklocal_and_garbage() {
        // loopback/link-local are host-local; prefer the real LAN address
        assert_eq!(pick_usable_address("127.0.0.1, 169.254.1.2, 192.168.1.5").as_deref(), Some("192.168.1.5"));
        assert_eq!(pick_usable_address("not-an-ip").as_deref(), None);
        assert_eq!(pick_usable_address("").as_deref(), None);
    }
}
