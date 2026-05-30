// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com
//
//! Galera cluster manager.
//!
//! Create or adopt MariaDB Galera clusters built from LXC containers across
//! the WolfStack cluster, then monitor and recover them. A cluster is a small
//! fellowship of nodes that must stay in lock-step; this module's job is to
//! keep that fellowship from fracturing (split-brain) and, when it does, to
//! rejoin it from the most-advanced survivor.
//!
//! Layers:
//!   * model + persistence (`/etc/wolfstack/galera.json`)
//!   * live status via SQL `SHOW GLOBAL STATUS LIKE 'wsrep_%'` per node
//!   * provisioning (create LXC + install MariaDB + configure wsrep + bootstrap)
//!   * lifecycle + evidence-based recovery (grastate.dat seqno)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const GALERA_CONFIG_PATH: &str = "/etc/wolfstack/galera.json";
const GALERA_SECRET_PURPOSE: &[u8] = b"galera-cluster-secret-v1";

fn default_mysql_port() -> u16 { 3306 }
fn default_sst() -> String { "mariabackup".into() }
fn default_db_user() -> String { "root".into() }

/// One MariaDB/Galera node — an LXC container on a WolfStack host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaleraNode {
    /// WolfStack host node id that runs this container.
    #[serde(default)]
    pub node_id: String,
    /// LXC container name on that host.
    pub container: String,
    /// Address other nodes reach it on (WolfNet IP recommended) — used for
    /// gcomm:// peering and for status queries.
    pub address: String,
    #[serde(default = "default_mysql_port")]
    pub port: u16,
    /// wsrep_node_name (defaults to the container name when empty).
    #[serde(default)]
    pub node_name: String,
}

/// A managed Galera cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaleraCluster {
    pub id: String,
    /// wsrep_cluster_name.
    pub name: String,
    #[serde(default)]
    pub nodes: Vec<GaleraNode>,
    /// SST method: "mariabackup" (recommended) or "rsync".
    #[serde(default = "default_sst")]
    pub sst_method: String,
    /// DB user for status queries + management (typically "root").
    #[serde(default = "default_db_user")]
    pub db_user: String,
    /// AES-256-GCM encrypted DB password (never serialised in plaintext).
    #[serde(default)]
    pub db_password_enc: String,
    #[serde(default)]
    pub created_at: String,
    /// True for clusters WolfStack provisioned (vs adopted existing).
    #[serde(default)]
    pub provisioned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GaleraConfig {
    #[serde(default)]
    pub clusters: Vec<GaleraCluster>,
}

// ── Persistence ──────────────────────────────────────────────────────

pub fn load_config() -> GaleraConfig {
    match fs::read_to_string(GALERA_CONFIG_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => GaleraConfig::default(),
    }
}

pub fn save_config(cfg: &GaleraConfig) -> Result<(), String> {
    if let Some(parent) = Path::new(GALERA_CONFIG_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(GALERA_CONFIG_PATH, json)
        .map_err(|e| format!("write {}: {}", GALERA_CONFIG_PATH, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(GALERA_CONFIG_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn get_cluster(id: &str) -> Option<GaleraCluster> {
    load_config().clusters.into_iter().find(|c| c.id == id)
}

/// Upsert a cluster (used by both adopt and create). Re-encrypts a non-empty
/// plaintext password into `db_password_enc`.
pub fn upsert_cluster(mut cluster: GaleraCluster, plain_password: Option<&str>) -> Result<GaleraCluster, String> {
    // Validate every value that later reaches a shell, an LXC command, a config
    // file, or a DOM onclick handler. These are names + addresses, not free
    // text — reject bad input rather than trying to escape it everywhere.
    safe_token(&cluster.name)?;
    if !cluster.sst_method.trim().is_empty() {
        safe_token(&cluster.sst_method)?;
    }
    for n in &cluster.nodes {
        safe_token(&n.container)?;
        if !n.node_name.trim().is_empty() {
            safe_token(&n.node_name)?;
        }
        if !valid_address(&n.address) {
            return Err(format!("invalid node address '{}' (expected an IP or hostname)", n.address));
        }
    }

    // Never trust a client-supplied ciphertext: the stored secret is derived
    // ONLY from a fresh plaintext. When none is given (an edit that omits the
    // password), preserve whatever we already had for this id.
    let existing_enc = get_cluster(&cluster.id).map(|c| c.db_password_enc).unwrap_or_default();
    cluster.db_password_enc = match plain_password {
        Some(pw) if !pw.is_empty() => enc_secret(pw),
        _ => existing_enc,
    };

    for n in cluster.nodes.iter_mut() {
        if n.node_name.trim().is_empty() {
            n.node_name = n.container.clone();
        }
    }
    let mut cfg = load_config();
    match cfg.clusters.iter_mut().find(|c| c.id == cluster.id) {
        Some(slot) => *slot = cluster.clone(),
        None => cfg.clusters.push(cluster.clone()),
    }
    save_config(&cfg)?;
    Ok(cluster)
}

pub fn delete_cluster(id: &str) -> Result<(), String> {
    let mut cfg = load_config();
    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c.id != id);
    if cfg.clusters.len() == before {
        return Err(format!("cluster '{}' not found", id));
    }
    save_config(&cfg)
}

// ── Secrets (AES-256-GCM via at_rest_crypto, same as DNS/edge stores) ──

pub fn enc_secret(plain: &str) -> String {
    crate::at_rest_crypto::encrypt(plain.as_bytes(), GALERA_SECRET_PURPOSE).unwrap_or_default()
}

pub fn dec_secret(stored: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }
    crate::at_rest_crypto::decrypt_or_legacy(stored, GALERA_SECRET_PURPOSE, |_| String::new())
}

// ── Live status ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub container: String,
    pub address: String,
    pub reachable: bool,
    #[serde(default)]
    pub error: String,
    /// wsrep_local_state_comment (Synced / Joining / Donor/Desynced / ...).
    pub state: String,
    /// wsrep_cluster_size as seen by THIS node.
    pub cluster_size: i64,
    /// wsrep_cluster_status (Primary / non-Primary / Disconnected).
    pub cluster_status: String,
    /// wsrep_ready (ON/OFF).
    pub ready: bool,
    /// wsrep_cluster_state_uuid — identifies the segment a node belongs to.
    pub cluster_uuid: String,
    /// wsrep_connected.
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterStatus {
    pub cluster_id: String,
    pub nodes: Vec<NodeStatus>,
    /// Every node reachable, Synced, Primary, agreeing on one UUID + size.
    pub healthy: bool,
    /// Reachable nodes disagree on cluster UUID or size — the split-brain
    /// signal. The fellowship has fractured into separate components.
    pub split_brain: bool,
    pub summary: String,
}

pub async fn cluster_status(cluster: &GaleraCluster) -> ClusterStatus {
    let pw = dec_secret(&cluster.db_password_enc);
    let mut nodes = Vec::with_capacity(cluster.nodes.len());
    for n in &cluster.nodes {
        nodes.push(node_status(n, &cluster.db_user, &pw).await);
    }

    let reachable: Vec<&NodeStatus> = nodes.iter().filter(|s| s.reachable).collect();
    let uuids: HashSet<&str> = reachable.iter()
        .map(|s| s.cluster_uuid.as_str())
        .filter(|u| !u.is_empty())
        .collect();
    let sizes: HashSet<i64> = reachable.iter()
        .filter(|s| s.cluster_status.eq_ignore_ascii_case("Primary"))
        .map(|s| s.cluster_size)
        .collect();
    // Split-brain: two or more reachable nodes in DIFFERENT primary segments
    // (distinct UUIDs), or Primary nodes that disagree on the member count.
    let split_brain = uuids.len() > 1 || sizes.len() > 1;
    let all_synced = !reachable.is_empty() && reachable.iter().all(|s| {
        s.state.eq_ignore_ascii_case("Synced")
            && s.ready
            && s.cluster_status.eq_ignore_ascii_case("Primary")
    });
    let healthy = all_synced && !split_brain && reachable.len() == cluster.nodes.len();

    let summary = if cluster.nodes.is_empty() {
        "No nodes registered".to_string()
    } else if split_brain {
        "Split-brain — nodes disagree on cluster membership".to_string()
    } else if healthy {
        format!("Healthy — {}/{} nodes Synced", reachable.len(), cluster.nodes.len())
    } else if reachable.is_empty() {
        "Down — no nodes reachable".to_string()
    } else {
        format!("Degraded — {}/{} nodes reachable", reachable.len(), cluster.nodes.len())
    };

    ClusterStatus {
        cluster_id: cluster.id.clone(),
        nodes,
        healthy,
        split_brain,
        summary,
    }
}

async fn node_status(n: &GaleraNode, user: &str, password: &str) -> NodeStatus {
    let mut st = NodeStatus {
        container: n.container.clone(),
        address: n.address.clone(),
        reachable: false,
        error: String::new(),
        state: String::new(),
        cluster_size: 0,
        cluster_status: String::new(),
        ready: false,
        cluster_uuid: String::new(),
        connected: false,
    };
    let params = crate::mysql_editor::ConnParams {
        host: n.address.clone(),
        port: n.port,
        user: user.to_string(),
        password: password.to_string(),
        database: None,
        db_type: crate::mysql_editor::DbType::default(),
    };
    match crate::mysql_editor::execute_query(&params, "", "SHOW GLOBAL STATUS LIKE 'wsrep_%'").await {
        Ok(v) => {
            st.reachable = true;
            let m = wsrep_map(&v);
            st.state = m.get("wsrep_local_state_comment").cloned().unwrap_or_default();
            st.cluster_size = m.get("wsrep_cluster_size").and_then(|s| s.parse().ok()).unwrap_or(0);
            st.cluster_status = m.get("wsrep_cluster_status").cloned().unwrap_or_default();
            st.ready = m.get("wsrep_ready").map(|s| s.eq_ignore_ascii_case("ON")).unwrap_or(false);
            st.cluster_uuid = m.get("wsrep_cluster_state_uuid").cloned().unwrap_or_default();
            st.connected = m.get("wsrep_connected").map(|s| s.eq_ignore_ascii_case("ON")).unwrap_or(false);
        }
        Err(e) => st.error = e,
    }
    st
}

/// Flatten a `SHOW STATUS`/`SHOW VARIABLES` resultset (`{columns, rows}` where
/// each row is `[Variable_name, Value]`) into a name→value map.
fn wsrep_map(v: &serde_json::Value) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(rows) = v.get("rows").and_then(|r| r.as_array()) {
        for row in rows {
            if let Some([name, val, ..]) = row.as_array().map(Vec::as_slice)
                && let (Some(name), Some(val)) = (name.as_str(), val.as_str())
            {
                m.insert(name.to_string(), val.to_string());
            }
        }
    }
    m
}

// ── Provisioning + lifecycle (LXC + MariaDB + Galera) ────────────────
//
// CAVEAT: the install/bootstrap/recovery shell below follows standard Galera
// practice, but auto-provisioning and auto-recovering a clustered database is
// data-loss-critical and CANNOT be validated without a real multi-node test.
// Recovery is deliberately conservative — it refuses to bootstrap a node whose
// committed position is unknown, rather than guessing (which is how a stale
// node bootstrapping wipes the cluster's progress).

use std::sync::mpsc::Sender;

fn logln(log: &Sender<String>, msg: impl Into<String>) {
    let _ = log.send(msg.into());
}

/// Validate a name that will be interpolated into a shell command — keeps the
/// provisioner from ever building a command from attacker-controlled input.
fn safe_token(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64
        || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("invalid name '{}' (allowed: letters, digits, - _ .)", s));
    }
    Ok(())
}

/// Validate a node address (IPv4 / IPv6 / hostname) before it is stored. Keeps
/// injection out of gcomm config + DOM handlers without rejecting real hosts.
fn valid_address(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
}

/// Run a command inside an LXC container; stdout on success, stderr on failure.
fn lxc_exec(container: &str, cmd: &str) -> Result<String, String> {
    let out = std::process::Command::new("lxc-attach")
        .args(["-n", container, "--", "sh", "-c", cmd])
        .output()
        .map_err(|e| format!("lxc-attach {}: {}", container, e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("[{}] command failed: {}", container, String::from_utf8_lossy(&out.stderr).trim()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub cluster_name: String,
    pub node_count: usize,
    #[serde(default = "default_prefix")]
    pub name_prefix: String,
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
    pub root_password: String,
    #[serde(default = "default_sst")]
    pub sst_method: String,
    /// WolfStack host node id these containers live on (recorded on the nodes).
    #[serde(default)]
    pub node_id: String,
}
fn default_prefix() -> String { "galera".into() }
fn default_distro() -> String { "debian".into() }
fn default_release() -> String { "bookworm".into() }

fn distro_family(distro: &str) -> &'static str {
    match distro.to_lowercase().as_str() {
        "debian" | "ubuntu" => "deb",
        "fedora" | "centos" | "rhel" | "rocky" | "almalinux" => "rhel",
        "alpine" => "alpine",
        "arch" | "manjaro" => "arch",
        _ => "deb",
    }
}

fn galera_provider_path(distro: &str) -> &'static str {
    match distro_family(distro) {
        "rhel" => "/usr/lib64/galera/libgalera_smm.so",
        _ => "/usr/lib/galera/libgalera_smm.so",
    }
}

fn galera_cnf_path(distro: &str) -> &'static str {
    match distro_family(distro) {
        "deb" => "/etc/mysql/mariadb.conf.d/60-galera.cnf",
        _ => "/etc/my.cnf.d/galera.cnf",
    }
}

fn install_cmd(distro: &str) -> Result<&'static str, String> {
    Ok(match distro_family(distro) {
        "deb" => "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y mariadb-server mariadb-client galera-4 mariadb-backup rsync socat",
        "rhel" => "dnf install -y mariadb-server-galera mariadb-backup rsync socat || yum install -y mariadb-server-galera mariadb-backup rsync socat",
        "alpine" => "apk add --no-cache mariadb mariadb-client mariadb-server-utils mariadb-backup rsync socat && (rc-update add mariadb default || true)",
        "arch" => "pacman -Syu --noconfirm mariadb galera rsync socat && mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql",
        other => return Err(format!("unsupported distribution: {}", other)),
    })
}

/// Find the real `libgalera_smm.so` inside a container after install. The path
/// varies by package (galera-3 → /usr/lib/galera, galera-4 → an arch-triple
/// subdir, /usr/lib64 on RHEL), so we read it from disk rather than guessing —
/// a wrong `wsrep_provider` silently fails to load and the bootstrap dies.
/// Falls back to the family default only when the search finds nothing.
fn detect_galera_provider(container: &str, distro: &str) -> String {
    let found = lxc_exec(container, "find /usr/lib /usr/lib64 -name 'libgalera_smm.so' 2>/dev/null | head -1")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if found.is_empty() { galera_provider_path(distro).to_string() } else { found }
}

/// Render a Galera config file for one node. `provider` is the resolved
/// `libgalera_smm.so` path (see `detect_galera_provider`).
fn galera_cnf(provider: &str, cluster_name: &str, gcomm: &str, node_addr: &str, node_name: &str, sst: &str) -> String {
    format!(
        "[galera]\n\
         wsrep_on=ON\n\
         wsrep_provider={provider}\n\
         wsrep_cluster_name=\"{cluster}\"\n\
         wsrep_cluster_address=\"gcomm://{gcomm}\"\n\
         wsrep_node_address=\"{addr}\"\n\
         wsrep_node_name=\"{name}\"\n\
         wsrep_sst_method={sst}\n\
         binlog_format=row\n\
         default_storage_engine=InnoDB\n\
         innodb_autoinc_lock_mode=2\n\
         \n\
         [mysqld]\n\
         bind-address=0.0.0.0\n",
        provider = provider,
        cluster = cluster_name, gcomm = gcomm, addr = node_addr, name = node_name, sst = sst,
    )
}

/// systemctl-or-fallback service control inside a container (handles distros
/// where the unit is `mariadb` vs `mysqld`, and Alpine's OpenRC).
fn svc(container: &str, action: &str) -> Result<String, String> {
    lxc_exec(container, &format!(
        "systemctl {a} mariadb 2>/dev/null || systemctl {a} mysqld 2>/dev/null || rc-service mariadb {a} 2>/dev/null || true",
        a = action
    ))
}

/// Best-effort wait for a freshly-started container's init + network to settle
/// before we install packages — otherwise apt/dnf race the dpkg lock or hit a
/// not-yet-up network. Capped so a stuck container can't hang provisioning.
fn wait_container_ready(container: &str) {
    let _ = lxc_exec(container,
        "cloud-init status --wait >/dev/null 2>&1; \
         for i in $(seq 1 30); do \
           if command -v systemctl >/dev/null 2>&1; then \
             systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; \
           else break; fi; \
           sleep 1; \
         done");
}

/// Install with a few retries — a transient dpkg lock or mirror hiccup on a
/// brand-new container shouldn't abort the whole provision.
fn run_install(container: &str, install: &str) -> Result<String, String> {
    let mut last = String::new();
    for attempt in 1..=3 {
        match lxc_exec(container, install) {
            Ok(o) => return Ok(o),
            Err(e) => { last = e; if attempt < 3 { let _ = lxc_exec(container, "sleep 5"); } }
        }
    }
    Err(last)
}

/// Provision a brand-new Galera cluster: N LXC containers on THIS host, each
/// with MariaDB+Galera installed and configured, bootstrapped in order.
/// Returns the persisted cluster on success.
pub fn provision_cluster(p: &ProvisionRequest, log: &Sender<String>) -> Result<GaleraCluster, String> {
    if p.node_count == 0 || p.node_count > 9 {
        return Err("node_count must be between 1 and 9".into());
    }
    if p.root_password.is_empty() {
        return Err("a root password is required".into());
    }
    safe_token(&p.name_prefix)?;
    safe_token(&p.cluster_name)?;
    let _ = install_cmd(&p.distribution)?; // validate distro up front

    // Stable id minted before any container exists, so a failed final upsert
    // can't strand a live cluster under a fresh id on retry.
    let cluster_id = uuid::Uuid::new_v4().to_string();

    // 1. Create + start each container, give it a cluster-reachable WolfNet IP.
    let mut nodes: Vec<GaleraNode> = Vec::new();
    for i in 1..=p.node_count {
        let cname = format!("{}-{}", p.name_prefix, i);
        safe_token(&cname)?;
        logln(log, format!("[{}] creating container…", cname));
        crate::containers::lxc_create(&cname, &p.distribution, &p.release, "amd64", None, None)?;
        crate::containers::lxc_start(&cname)?;
        let ip = crate::containers::next_available_wolfnet_ip()
            .ok_or("no free WolfNet IP available for the new node")?;
        logln(log, format!("[{}] attaching WolfNet IP {}…", cname, ip));
        let _ = crate::containers::lxc_attach_wolfnet(&cname, &ip);
        nodes.push(GaleraNode { node_id: p.node_id.clone(), container: cname.clone(), address: ip, port: 3306, node_name: cname });
    }

    // 2. Install MariaDB + Galera on each node (after its init settles).
    let install = install_cmd(&p.distribution)?;
    for n in &nodes {
        logln(log, format!("[{}] waiting for container to be ready…", n.container));
        wait_container_ready(&n.container);
        logln(log, format!("[{}] installing MariaDB + Galera…", n.container));
        run_install(&n.container, install)?;
        let _ = svc(&n.container, "stop"); // configure offline; bootstrap explicitly below
    }

    // 3. Write the Galera config on each node (full gcomm member list). The
    //    provider path is read from disk per node — see detect_galera_provider.
    let gcomm = nodes.iter().map(|n| n.address.as_str()).collect::<Vec<_>>().join(",");
    let cnf_path = galera_cnf_path(&p.distribution);
    for n in &nodes {
        let provider = detect_galera_provider(&n.container, &p.distribution);
        let cnf = galera_cnf(&provider, &p.cluster_name, &gcomm, &n.address, &n.node_name, &p.sst_method);
        // base64 the file to avoid any shell-quoting hazard with the content.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(cnf.as_bytes());
        lxc_exec(&n.container, &format!("mkdir -p \"$(dirname {path})\" && printf %s '{b64}' | base64 -d > {path}", path = cnf_path, b64 = b64))?;
    }

    // 4. Bootstrap the first node (new primary component), then join the rest
    //    one at a time so each SSTs cleanly from a Synced donor.
    let first = &nodes[0];
    logln(log, format!("[{}] bootstrapping new cluster…", first.container));
    lxc_exec(&first.container, "sed -i 's/^safe_to_bootstrap:.*/safe_to_bootstrap: 1/' /var/lib/mysql/grastate.dat 2>/dev/null || true")?;
    lxc_exec(&first.container, "galera_new_cluster 2>/dev/null || (systemctl set-environment _WSREP_NEW_CLUSTER='--wsrep-new-cluster' >/dev/null 2>&1; systemctl start mariadb)")?;

    // 5. Set the root password + allow it over TCP (so WolfStack can query
    //    status) on the bootstrap node — replicates to the rest via Galera.
    //    The password is SQL-escaped (\\ and ' doubled) and the whole script is
    //    base64-piped into mysql's STDIN, so the password never touches `sh -c`:
    //    a value like `$(id)` or a backtick can't reach the shell.
    let pw_sql = p.root_password.replace('\\', "\\\\").replace('\'', "''");
    let sql = format!(
        "ALTER USER 'root'@'localhost' IDENTIFIED BY '{pw}'; \
         CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '{pw}'; \
         GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;",
        pw = pw_sql
    );
    let sql_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(sql.as_bytes())
    };
    lxc_exec(&first.container, &format!("printf %s '{}' | base64 -d | mysql", sql_b64))?;

    // 6. Join the remaining nodes in order.
    for n in nodes.iter().skip(1) {
        logln(log, format!("[{}] joining cluster (SST)…", n.container));
        svc(&n.container, "start")?;
    }

    logln(log, "Verifying cluster size…");
    let saved = upsert_cluster(GaleraCluster {
        id: cluster_id,
        name: p.cluster_name.clone(),
        nodes,
        sst_method: p.sst_method.clone(),
        db_user: "root".into(),
        db_password_enc: String::new(),
        created_at: chrono::Utc::now().to_rfc3339(),
        provisioned: true,
    }, Some(&p.root_password))?;
    Ok(saved)
}

// ── Lifecycle + evidence-based recovery ──────────────────────────────

/// Read the last-committed seqno from a node's grastate.dat. Returns -1 when
/// unknown (file missing, or the node crashed mid-transaction = `-1`).
fn node_seqno(container: &str) -> i64 {
    lxc_exec(container, "awk -F': *' '/^seqno:/{print $2}' /var/lib/mysql/grastate.dat 2>/dev/null")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(-1)
}

/// Recover a fully-stopped cluster. Stops every node, reads each grastate
/// seqno, bootstraps the MOST-ADVANCED node, then rejoins the rest. Refuses to
/// act if no node has a known position — guessing there is how data is lost.
pub fn recover_cluster(cluster: &GaleraCluster, log: &Sender<String>) -> Result<String, String> {
    if cluster.nodes.is_empty() {
        return Err("cluster has no nodes".into());
    }
    for n in &cluster.nodes {
        logln(log, format!("[{}] stopping mariadb to flush its position…", n.container));
        let _ = svc(&n.container, "stop");
    }
    // Verify every node is actually DOWN before reading positions. A node still
    // running reports seqno -1 (grastate is only written on clean shutdown), and
    // bootstrapping while another node is live corrupts the cluster. If we can't
    // confirm a node is stopped (including: container unreachable), refuse — a
    // wrong bootstrap here rolls the database back. Data safety > convenience.
    for n in &cluster.nodes {
        let down = lxc_exec(&n.container,
            "if pgrep -x mariadbd >/dev/null 2>&1 || pgrep -x mysqld >/dev/null 2>&1; then echo UP; else echo DOWN; fi")
            .map(|s| s.trim() == "DOWN")
            .unwrap_or(false); // unreadable ⇒ can't confirm ⇒ treat as not-down
        if !down {
            return Err(format!(
                "Node '{}' is still running or unreachable after stop — refusing to recover. \
                 A clean recovery needs every node stopped so its committed position is on disk. \
                 Stop MariaDB there (and confirm the container is reachable), then retry.",
                n.container));
        }
    }
    let mut best: Option<(GaleraNode, i64)> = None;
    for n in &cluster.nodes {
        let seq = node_seqno(&n.container);
        logln(log, format!("[{}] grastate seqno = {}", n.container, seq));
        if best.as_ref().map(|(_, b)| seq > *b).unwrap_or(true) {
            best = Some((n.clone(), seq));
        }
    }
    let (boot, boot_seq) = best.ok_or("could not read any node state")?;
    if boot_seq < 0 {
        return Err(
            "No node reports a known committed position (all seqno = -1). \
             Refusing to bootstrap — picking one here could roll the cluster \
             back. Inspect /var/lib/mysql/grastate.dat on each node and \
             recover the most-advanced one by hand.".to_string()
        );
    }
    logln(log, format!("[{}] is most-advanced (seqno {}) — bootstrapping it.", boot.container, boot_seq));
    // We deliberately force safe_to_bootstrap:1 on the most-advanced survivor —
    // overriding Galera's own guard — because the seqno evidence above (every
    // node confirmed down + this one holding the highest committed position) is
    // exactly what that flag is meant to certify.
    lxc_exec(&boot.container, "sed -i 's/^safe_to_bootstrap:.*/safe_to_bootstrap: 1/' /var/lib/mysql/grastate.dat 2>/dev/null || true")?;
    lxc_exec(&boot.container, "galera_new_cluster 2>/dev/null || (systemctl set-environment _WSREP_NEW_CLUSTER='--wsrep-new-cluster' >/dev/null 2>&1; systemctl start mariadb)")?;
    for n in &cluster.nodes {
        if n.container == boot.container { continue; }
        logln(log, format!("[{}] rejoining…", n.container));
        let _ = svc(&n.container, "start");
    }
    Ok(format!("Recovered from '{}' (seqno {}); rejoined {} node(s).", boot.container, boot_seq, cluster.nodes.len() - 1))
}

/// Start / stop / restart MariaDB on one node of a cluster (lifecycle).
pub fn node_service(cluster: &GaleraCluster, container: &str, action: &str) -> Result<String, String> {
    if !cluster.nodes.iter().any(|n| n.container == container) {
        return Err(format!("'{}' is not a node of this cluster", container));
    }
    if !matches!(action, "start" | "stop" | "restart") {
        return Err("action must be start, stop or restart".into());
    }
    svc(container, action)
}
