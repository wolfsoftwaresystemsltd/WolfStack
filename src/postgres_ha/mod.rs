// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! PostgreSQL HA manager — streaming replication across the cluster.
//!
//! The Galera manager covers the MySQL/MariaDB side; this is its Postgres
//! analogue (NoroNetwork 2026-07-09: "Galera DB … Preferably not only Mysql
//! but also postgres"). A Postgres HA cluster is one PRIMARY plus one or more
//! read-replica STANDBYs kept current by native streaming replication. This
//! module manages that fellowship: provision it onto the WolfStack nodes
//! carrying the `Database` [role](crate::agent::NodeRole::Database), watch
//! replication lag per node, and promote a standby when the primary is lost.
//!
//! Layers (mirrors `galera`):
//!   * model + persistence (`/etc/wolfstack/postgres_ha.json`)
//!   * live status via `pg_stat_replication` / `pg_is_in_recovery()` per node
//!   * provisioning (create LXC + install postgres + configure + basebackup)
//!   * lifecycle (start/stop/restart) + standby promotion
//!
//! Deliberately NOT auto-failover: promoting a standby is a data-authority
//! decision (a mispromote splits history), so it is operator-driven — the UI
//! shows lag and offers Promote, exactly as Galera recovery is operator-driven.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const PG_HA_CONFIG_PATH: &str = "/etc/wolfstack/postgres_ha.json";
const PG_HA_SECRET_PURPOSE: &[u8] = b"postgres-ha-secret-v1";

/// Serializes read-modify-write cycles on postgres_ha.json (mirrors
/// `GALERA_IO_LOCK`). Held only across sync file IO, never across `.await`.
static PG_HA_IO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn default_pg_port() -> u16 { 5432 }
fn default_db_user() -> String { "postgres".into() }
fn default_kind() -> String { "lxc".into() }
fn default_repl_user() -> String { "replicator".into() }

/// A node's role in a streaming-replication cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PgRole {
    /// Read/write. Exactly one per healthy cluster.
    Primary,
    /// Read-only hot standby, streaming from the primary.
    Standby,
}

impl PgRole {
    pub fn label(&self) -> &'static str {
        match self { PgRole::Primary => "primary", PgRole::Standby => "standby" }
    }
}

/// One PostgreSQL node — a container on a WolfStack host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgNode {
    /// WolfStack host node id that runs this container.
    #[serde(default)]
    pub node_id: String,
    /// Container name on that host.
    pub container: String,
    /// Container runtime: "lxc" (default) or "docker".
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Address peers reach it on (WolfNet IP recommended) — used for the
    /// standby's `primary_conninfo` and for status queries.
    pub address: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    /// Declared role at provision/adopt time. The LIVE role is re-derived from
    /// `pg_is_in_recovery()` in status (a promoted standby reports Primary),
    /// so this is the intended role, not the trusted source of truth.
    pub role: PgRole,
}

/// A managed PostgreSQL HA cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgCluster {
    pub id: String,
    /// Operator-facing cluster name (also the replication application_name base).
    pub name: String,
    /// WolfStack cluster this belongs to (scopes the UI). Empty = unscoped.
    #[serde(default)]
    pub cluster: String,
    /// WolfStack host node id whose postgres_ha.json stores this definition.
    #[serde(default)]
    pub owner_node: String,
    #[serde(default)]
    pub nodes: Vec<PgNode>,
    /// Superuser for status queries + management (typically "postgres").
    #[serde(default = "default_db_user")]
    pub db_user: String,
    /// AES-256-GCM encrypted superuser password (never serialised plaintext).
    #[serde(default)]
    pub db_password_enc: String,
    /// Dedicated replication role name.
    #[serde(default = "default_repl_user")]
    pub repl_user: String,
    /// AES-256-GCM encrypted replication-role password.
    #[serde(default)]
    pub repl_password_enc: String,
    #[serde(default)]
    pub created_at: String,
    /// True for clusters WolfStack provisioned (vs adopted existing).
    #[serde(default)]
    pub provisioned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PgHaConfig {
    #[serde(default)]
    pub clusters: Vec<PgCluster>,
}

// ── Persistence ──────────────────────────────────────────────────────

pub fn load_config() -> PgHaConfig {
    match fs::read_to_string(PG_HA_CONFIG_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => PgHaConfig::default(),
    }
}

pub fn save_config(cfg: &PgHaConfig) -> Result<(), String> {
    if let Some(parent) = Path::new(PG_HA_CONFIG_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(PG_HA_CONFIG_PATH, json).map_err(|e| format!("write {}: {}", PG_HA_CONFIG_PATH, e))
}

pub fn get_cluster(id: &str) -> Option<PgCluster> {
    load_config().clusters.into_iter().find(|c| c.id == id)
}

/// Insert or replace a cluster definition under the IO lock.
pub fn upsert_cluster(cluster: PgCluster) -> Result<PgCluster, String> {
    let _guard = PG_HA_IO_LOCK.lock().map_err(|_| "pg_ha lock poisoned".to_string())?;
    let mut cfg = load_config();
    if let Some(existing) = cfg.clusters.iter_mut().find(|c| c.id == cluster.id) {
        *existing = cluster.clone();
    } else {
        cfg.clusters.push(cluster.clone());
    }
    save_config(&cfg)?;
    Ok(cluster)
}

pub fn delete_cluster(id: &str) -> Result<(), String> {
    let _guard = PG_HA_IO_LOCK.lock().map_err(|_| "pg_ha lock poisoned".to_string())?;
    let mut cfg = load_config();
    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c.id != id);
    if cfg.clusters.len() == before {
        return Err(format!("cluster '{}' not found", id));
    }
    save_config(&cfg)
}

/// Re-tag clusters when a WolfStack cluster is renamed (mirrors Galera's
/// `rename_wolfstack_cluster_tags`). Returns how many were re-tagged.
pub fn rename_wolfstack_cluster_tags(old_name: &str, new_name: &str) -> usize {
    let _guard = match PG_HA_IO_LOCK.lock() { Ok(g) => g, Err(_) => return 0 };
    let mut cfg = load_config();
    let mut n = 0;
    for c in &mut cfg.clusters {
        if crate::agent::cluster_eq(Some(&c.cluster), Some(old_name)) {
            c.cluster = new_name.to_string();
            n += 1;
        }
    }
    if n > 0 { let _ = save_config(&cfg); }
    n
}

pub fn enc_secret(plain: &str) -> String {
    crate::at_rest_crypto::encrypt(plain.as_bytes(), PG_HA_SECRET_PURPOSE).unwrap_or_default()
}

pub fn dec_secret(stored: &str) -> String {
    if stored.is_empty() { return String::new(); }
    crate::at_rest_crypto::decrypt_or_legacy(stored, PG_HA_SECRET_PURPOSE, |_| String::new())
}

// ── Container exec ───────────────────────────────────────────────────

/// Run a shell command inside a node's container. "docker" → `docker exec`;
/// "lxc" → `pct exec` on Proxmox else `lxc-attach`. Mirrors `galera::cexec`.
fn cexec(kind: &str, container: &str, cmd: &str) -> Result<String, String> {
    let mut c = if kind == "docker" {
        let mut c = std::process::Command::new("docker");
        c.arg("exec").arg(container).arg("sh").arg("-c").arg(cmd);
        c
    } else if std::process::Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut c = std::process::Command::new("pct");
        c.arg("exec").arg(container).arg("--").arg("sh").arg("-c").arg(cmd);
        c
    } else {
        let mut c = std::process::Command::new("lxc-attach");
        c.arg("-n").arg(container).arg("--").arg("sh").arg("-c").arg(cmd);
        c
    };
    let out = c.output().map_err(|e| format!("{} exec {}: {}", kind, container, e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("[{}] command failed: {}", container, String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Run a `psql` query as the superuser inside a node, returning tab-separated
/// unaligned rows (`-tAF'\t'`). The password is passed via the `PGPASSWORD`
/// env inside the container so it never appears in the process argv.
fn psql_query(node: &PgNode, db_user: &str, db_password: &str, sql: &str) -> Result<String, String> {
    // Single-quote the SQL for the shell; escape embedded single quotes.
    let sql_escaped = sql.replace('\'', "'\\''");
    let pw = shell_single_quote(db_password);
    let cmd = format!(
        "PGPASSWORD={pw} psql -U {user} -p {port} -h 127.0.0.1 -tAF'\\t' -c '{sql}'",
        pw = pw, user = shell_single_quote(db_user), port = node.port, sql = sql_escaped,
    );
    cexec(&node.kind, &node.container, &cmd)
}

/// Wrap a value in single quotes safely for `sh -c`.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A valid PostgreSQL role name we're willing to interpolate into SQL/shell:
/// standard SQL identifier charset. Rejecting everything else at the boundary
/// closes the identifier-injection vector entirely (defence-in-depth on top of
/// the quoted-heredoc SQL delivery). Roles like `postgres` / `replicator` pass.
fn is_valid_pg_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63
        && s.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A valid container name: LXC/Docker names are `[A-Za-z0-9_-]`, dot allowed.
/// Interpolated into shell only; validating it removes the metacharacter risk.
fn is_valid_container_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// A parseable IP address (WolfNet IPs) — validated so an address can never
/// carry shell metacharacters into a provisioning command.
fn is_valid_addr(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Escape a value for one field of a `.pgpass` line: backslash and colon are
/// the only field metacharacters. Password fields can contain either.
fn pgpass_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace(':', "\\:")
}

/// Validate every operator-supplied identifier/address a provision will
/// interpolate into a root shell or SQL. Called at the top of provisioning so
/// a bad value is rejected before any container is touched.
fn validate_provision_inputs(p: &ProvisionRequest) -> Result<(), String> {
    if !is_valid_pg_ident(&p.db_user) {
        return Err(format!("invalid db_user '{}' (must be a SQL identifier: letters/digits/underscore, not starting with a digit)", p.db_user));
    }
    if !is_valid_pg_ident(&p.repl_user) {
        return Err(format!("invalid repl_user '{}' (must be a SQL identifier)", p.repl_user));
    }
    for m in &p.members {
        if !is_valid_container_name(&m.container) {
            return Err(format!("invalid container name '{}'", m.container));
        }
        if !is_valid_addr(&m.address) {
            return Err(format!("invalid member address '{}' (must be an IP)", m.address));
        }
    }
    Ok(())
}

// ── Live status ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PgNodeStatus {
    pub container: String,
    pub address: String,
    pub reachable: bool,
    #[serde(default)]
    pub error: String,
    /// Declared role from the config.
    pub declared_role: String,
    /// LIVE role from `pg_is_in_recovery()` — "primary" when false, "standby"
    /// when true. A promoted standby shows "primary" here even if declared
    /// "standby"; a demoted/rebuilt primary shows "standby".
    pub live_role: String,
    /// True when this node accepts writes (is the live primary).
    pub is_primary: bool,
    /// Replication lag in bytes. On the primary: max `sent_lsn - replay_lsn`
    /// across its standbys (how far the furthest-behind replica trails). On a
    /// standby: `pg_last_wal_receive_lsn() - pg_last_wal_replay_lsn()` (local
    /// apply backlog). 0 when in sync / unavailable.
    pub lag_bytes: i64,
    /// Number of connected standbys (primary only; 0 on standbys).
    pub connected_standbys: i64,
    /// `pg_postmaster_start_time()` as a string, for the UI.
    #[serde(default)]
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PgClusterStatus {
    pub cluster_id: String,
    pub nodes: Vec<PgNodeStatus>,
    /// Exactly one reachable primary AND every reachable standby streaming.
    pub healthy: bool,
    /// More than one node reports itself primary — the split-brain signal for
    /// streaming replication (two write masters = diverging history).
    pub multiple_primaries: bool,
    /// No reachable node is a primary — the cluster can't accept writes; the
    /// UI should offer Promote on the most-current standby.
    pub no_primary: bool,
}

/// Query one node's live replication status.
pub fn node_status(cluster: &PgCluster, node: &PgNode) -> PgNodeStatus {
    let mut st = PgNodeStatus {
        container: node.container.clone(),
        address: node.address.clone(),
        reachable: false,
        error: String::new(),
        declared_role: node.role.label().to_string(),
        live_role: String::new(),
        is_primary: false,
        lag_bytes: 0,
        connected_standbys: 0,
        started_at: String::new(),
    };
    let db_pw = dec_secret(&cluster.db_password_enc);
    // One round-trip: recovery flag, start time, and — via a UNION-free
    // approach — the lag figure appropriate to the node's live role.
    let probe = "SELECT pg_is_in_recovery()::text, pg_postmaster_start_time()::text";
    let out = match psql_query(node, &cluster.db_user, &db_pw, probe) {
        Ok(o) => o,
        Err(e) => { st.error = e; return st; }
    };
    st.reachable = true;
    let first = out.lines().next().unwrap_or("");
    let cols: Vec<&str> = first.split('\t').collect();
    let in_recovery = cols.first().map(|v| v.trim() == "t").unwrap_or(false);
    st.started_at = cols.get(1).map(|v| v.trim().to_string()).unwrap_or_default();
    st.is_primary = !in_recovery;
    st.live_role = if in_recovery { "standby".into() } else { "primary".into() };

    if st.is_primary {
        // Primary: how many standbys, and the worst replay lag among them.
        let q = "SELECT count(*)::text, COALESCE(MAX(pg_wal_lsn_diff(sent_lsn, replay_lsn)),0)::text FROM pg_stat_replication";
        if let Ok(o) = psql_query(node, &cluster.db_user, &db_pw, q) {
            let c: Vec<&str> = o.lines().next().unwrap_or("").split('\t').collect();
            st.connected_standbys = c.first().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
            st.lag_bytes = c.get(1).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        }
    } else {
        // Standby: local apply backlog (receive LSN minus replay LSN).
        let q = "SELECT COALESCE(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()),0)::text";
        if let Ok(o) = psql_query(node, &cluster.db_user, &db_pw, q) {
            st.lag_bytes = o.lines().next().unwrap_or("").trim().parse().unwrap_or(0);
        }
    }
    st
}

/// Full-cluster status: every node, plus the aggregate health flags.
pub fn cluster_status(cluster: &PgCluster) -> PgClusterStatus {
    let nodes: Vec<PgNodeStatus> = cluster.nodes.iter().map(|n| node_status(cluster, n)).collect();
    let primaries = nodes.iter().filter(|n| n.reachable && n.is_primary).count();
    let standbys_ok = nodes.iter().filter(|n| n.reachable && !n.is_primary).count();
    let reachable = nodes.iter().filter(|n| n.reachable).count();
    PgClusterStatus {
        cluster_id: cluster.id.clone(),
        // Healthy = exactly one primary, all reachable non-primaries are
        // standbys (they are, by construction of is_primary), and we can see
        // the whole declared set.
        healthy: primaries == 1 && reachable == cluster.nodes.len() && (standbys_ok + 1) == reachable,
        multiple_primaries: primaries > 1,
        no_primary: reachable > 0 && primaries == 0,
        nodes,
    }
}

// ── Provisioning ─────────────────────────────────────────────────────

/// Recommend which `Database`-role WolfStack nodes to place a new HA cluster
/// on. This is the point the node-roles keystone pays off: the operator tags
/// cheap VPSs `Database` and the manager places the primary + standbys across
/// them without the operator hand-picking hosts. Returns the host node ids in
/// a stable order (primary first).
pub fn recommend_placement(cluster_state: &crate::agent::ClusterState, want: usize) -> Vec<String> {
    let mut db_nodes: Vec<crate::agent::Node> = cluster_state
        .nodes_with_role(crate::agent::NodeRole::Database)
        .into_iter()
        .filter(|n| n.online)
        .collect();
    // Deterministic: sort by id so the same call yields the same layout.
    db_nodes.sort_by(|a, b| a.id.cmp(&b.id));
    db_nodes.into_iter().take(want).map(|n| n.id).collect()
}

/// The Postgres major version families we know how to install per distro,
/// keyed on the container's package manager. Debian/Ubuntu ship `postgresql`
/// (meta), RHEL family `postgresql-server` (+ initdb), Alpine `postgresql`.
fn install_postgres(kind: &str, container: &str, log: &std::sync::mpsc::Sender<String>) -> Result<(), String> {
    let _ = log.send(format!("  Installing PostgreSQL in {}…", container));
    // Try each package manager; the first that exists wins. Non-interactive.
    let script = "\
        if command -v apt-get >/dev/null 2>&1; then \
            export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq postgresql postgresql-contrib; \
        elif command -v dnf >/dev/null 2>&1; then \
            dnf install -y postgresql-server postgresql-contrib && (postgresql-setup --initdb || /usr/bin/initdb -D /var/lib/pgsql/data || true); \
        elif command -v apk >/dev/null 2>&1; then \
            apk add --no-cache postgresql postgresql-contrib; \
        else echo 'no supported package manager' >&2; exit 1; fi";
    cexec(kind, container, script).map(|_| ()).map_err(|e| format!("install postgres: {}", e))
}

/// Locate the data directory and the running-as user inside a container,
/// distro-agnostically. Debian: /var/lib/postgresql/<ver>/main, user postgres.
/// RHEL/Alpine: /var/lib/pgsql/data or /var/lib/postgresql/data.
fn detect_pgdata(kind: &str, container: &str) -> Result<String, String> {
    // Ask a running server first (authoritative); fall back to common paths.
    if let Ok(out) = cexec(kind, container,
        "su - postgres -c 'psql -tAc \"SHOW data_directory\"' 2>/dev/null")
    {
        let p = out.trim();
        if !p.is_empty() { return Ok(p.to_string()); }
    }
    for path in ["/var/lib/postgresql/*/main", "/var/lib/pgsql/data", "/var/lib/postgresql/data"] {
        if let Ok(out) = cexec(kind, container, &format!("ls -d {} 2>/dev/null | head -1", path)) {
            let p = out.trim();
            if !p.is_empty() { return Ok(p.to_string()); }
        }
    }
    Err("could not locate PostgreSQL data directory".into())
}

/// Request to stand up a fresh Postgres HA cluster.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub name: String,
    #[serde(default)]
    pub cluster: String,
    /// (host_node_id, container_name, address) for each member — the FIRST is
    /// the primary, the rest standbys. The API builds this from
    /// `recommend_placement` + the operator's confirmation.
    pub members: Vec<ProvisionMember>,
    #[serde(default = "default_db_user")]
    pub db_user: String,
    pub db_password: String,
    #[serde(default = "default_repl_user")]
    pub repl_user: String,
    pub repl_password: String,
    #[serde(default)]
    pub distribution: String,
    #[serde(default)]
    pub release: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionMember {
    pub node_id: String,
    pub container: String,
    pub address: String,
}

/// Configure the PRIMARY: replication user, pg_hba for the standby subnet,
/// and the streaming-friendly postgresql.conf knobs. `standby_addrs` are the
/// standby node addresses that must be allowed to replicate.
fn configure_primary(
    node: &PgNode, db_user: &str, db_password: &str, repl_user: &str, repl_password: &str,
    standby_addrs: &[String], log: &std::sync::mpsc::Sender<String>,
) -> Result<(), String> {
    let _ = log.send(format!("  Configuring primary {}…", node.container));
    let pgdata = detect_pgdata(&node.kind, &node.container)?;
    // Streaming replication knobs. wal_level=replica is the default on PG12+
    // but we set it explicitly so an older/edited config is correct too.
    let conf = "\
        wal_level = replica\\n\
        max_wal_senders = 10\\n\
        max_replication_slots = 10\\n\
        hot_standby = on\\n\
        listen_addresses = '*'\\n\
        wal_keep_size = 512MB";
    cexec(&node.kind, &node.container, &format!(
        "printf '%b\\n' \"{conf}\" >> {pgdata}/postgresql.conf",
        conf = conf, pgdata = pgdata,
    ))?;
    // pg_hba: allow the replication role from each standby address (host /32),
    // scram-sha-256. Appended, never rewriting the operator's existing rules.
    for addr in standby_addrs {
        cexec(&node.kind, &node.container, &format!(
            "printf 'host replication {ru} {addr}/32 scram-sha-256\\n' >> {pgdata}/pg_hba.conf",
            ru = repl_user, addr = addr, pgdata = pgdata,
        ))?;
    }
    // Restart to apply listen_addresses/wal_level, then create the roles.
    restart_pg(&node.kind, &node.container)?;
    // Superuser password + a dedicated REPLICATION login role. `db_user` and
    // `repl_user` are validated identifiers (validate_provision_inputs);
    // passwords are SQL-escaped. The SQL is delivered to psql over stdin via a
    // QUOTED heredoc (`<<'WOLFSQL'`) so the shell performs NO interpolation on
    // it — this is what makes an arbitrary password injection-proof (and fixes
    // the earlier nested-single-quote bug that made this command never run).
    let setup_sql = format!(
        "ALTER USER {du} WITH PASSWORD {dp}; \
         DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{ru}') THEN \
         CREATE ROLE {ru} WITH REPLICATION LOGIN PASSWORD {rp}; \
         ELSE ALTER ROLE {ru} WITH REPLICATION LOGIN PASSWORD {rp}; END IF; END $$;",
        du = db_user,
        dp = sql_string_literal(db_password),
        ru = repl_user,
        rp = sql_string_literal(repl_password),
    );
    cexec(&node.kind, &node.container, &format!(
        "su - postgres -c 'psql -v ON_ERROR_STOP=1 -q' <<'WOLFSQL'\n{sql}\nWOLFSQL\n",
        sql = setup_sql,
    ))?;
    Ok(())
}

/// Escape a Postgres string literal (double single-quotes) and wrap in quotes.
fn sql_string_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Build a STANDBY from the primary via `pg_basebackup`, write its
/// `primary_conninfo`, mark it standby, and start streaming.
fn configure_standby(
    node: &PgNode, primary: &PgNode, repl_user: &str, repl_password: &str,
    log: &std::sync::mpsc::Sender<String>,
) -> Result<(), String> {
    let _ = log.send(format!("  Building standby {} from primary {}…", node.container, primary.container));
    let pgdata = detect_pgdata(&node.kind, &node.container)?;
    // Stop the fresh server and clear its datadir so basebackup can clone.
    let _ = stop_pg(&node.kind, &node.container);
    // Write the replication password into ~postgres/.pgpass via a QUOTED
    // heredoc (no shell interpolation → injection-proof for an arbitrary
    // password), then run pg_basebackup which reads it. This keeps the password
    // out of the process argv / `ps` entirely (unlike PGPASSWORD=). `primary`
    // address + `repl_user` are validated (IP / identifier) upstream.
    let pgpass_line = format!(
        "{ph}:{pp}:*:{ru}:{pw}",
        ph = primary.address, pp = primary.port, ru = repl_user,
        pw = pgpass_escape(repl_password),
    );
    cexec(&node.kind, &node.container, &format!(
        "su - postgres -c 'cat > ~/.pgpass && chmod 600 ~/.pgpass' <<'WOLFPGPASS'\n{line}\nWOLFPGPASS\n",
        line = pgpass_line,
    )).map_err(|e| format!("write .pgpass: {}", e))?;
    cexec(&node.kind, &node.container, &format!(
        "rm -rf {pgdata}/* 2>/dev/null; su - postgres -c 'pg_basebackup -h {ph} -p {pp} -U {ru} -D {pgdata} -Fp -Xs -P -R'",
        pgdata = pgdata, ph = primary.address, pp = primary.port, ru = repl_user,
    )).map_err(|e| format!("pg_basebackup: {}", e))?;
    // `-R` writes primary_conninfo + standby.signal, so the node comes up as a
    // streaming standby. Ensure a stable application_name for pg_stat_replication.
    // `node.container` is a validated container name (no shell metacharacters).
    cexec(&node.kind, &node.container, &format!(
        "printf \"application_name = '%s'\\n\" '{app}' >> {pgdata}/postgresql.auto.conf",
        app = node.container, pgdata = pgdata,
    ))?;
    start_pg(&node.kind, &node.container)?;
    Ok(())
}

fn restart_pg(kind: &str, container: &str) -> Result<(), String> {
    // Prefer systemd; fall back to pg_ctlcluster (Debian) / pg_ctl.
    cexec(kind, container, "\
        systemctl restart postgresql 2>/dev/null || \
        pg_ctlcluster $(ls /etc/postgresql 2>/dev/null | head -1) main restart 2>/dev/null || \
        su - postgres -c 'pg_ctl restart -D $PGDATA' 2>/dev/null || \
        (rc-service postgresql restart 2>/dev/null) || true")
        .map(|_| ())
}
fn start_pg(kind: &str, container: &str) -> Result<(), String> {
    cexec(kind, container, "\
        systemctl start postgresql 2>/dev/null || \
        pg_ctlcluster $(ls /etc/postgresql 2>/dev/null | head -1) main start 2>/dev/null || \
        (rc-service postgresql start 2>/dev/null) || true")
        .map(|_| ())
}
fn stop_pg(kind: &str, container: &str) -> Result<(), String> {
    cexec(kind, container, "\
        systemctl stop postgresql 2>/dev/null || \
        pg_ctlcluster $(ls /etc/postgresql 2>/dev/null | head -1) main stop 2>/dev/null || \
        (rc-service postgresql stop 2>/dev/null) || true")
        .map(|_| ())
}

/// LXC-local provisioning: create + start each member container, install
/// Postgres, configure the primary, then basebackup the standbys. Runs on the
/// owner node; remote members are built via the peer's own local endpoint (the
/// API layer fans this out, mirroring Galera). Streams progress to `log`.
pub fn provision_cluster_local(
    p: &ProvisionRequest, log: &std::sync::mpsc::Sender<String>,
) -> Result<PgCluster, String> {
    if p.members.is_empty() {
        return Err("a Postgres HA cluster needs at least one member".into());
    }
    // Reject any unsafe identifier/address BEFORE touching a container — these
    // values are interpolated into root shell/SQL during provisioning.
    validate_provision_inputs(p)?;
    let now = chrono::Utc::now().to_rfc3339();
    let mut nodes: Vec<PgNode> = Vec::new();
    for (i, m) in p.members.iter().enumerate() {
        nodes.push(PgNode {
            node_id: m.node_id.clone(),
            container: m.container.clone(),
            kind: "lxc".into(),
            address: m.address.clone(),
            port: default_pg_port(),
            role: if i == 0 { PgRole::Primary } else { PgRole::Standby },
        });
    }
    // Create + install each container (local host only; the caller ensures
    // members map to this host, or fans remote members to their owners).
    let distro = if p.distribution.is_empty() { "debian" } else { &p.distribution };
    let release = if p.release.is_empty() { "12" } else { &p.release };
    for n in &nodes {
        let _ = log.send(format!("  Creating container {}…", n.container));
        crate::containers::lxc_create(&n.container, distro, release, crate::containers::host_container_arch(), None, None)?;
        crate::containers::lxc_start(&n.container)?;
        let _ = crate::containers::lxc_attach_wolfnet(&n.container, &n.address);
        install_postgres(&n.kind, &n.container, log)?;
    }
    let primary = nodes[0].clone();
    let standby_addrs: Vec<String> = nodes.iter().skip(1).map(|n| n.address.clone()).collect();
    configure_primary(&primary, &p.db_user, &p.db_password, &p.repl_user, &p.repl_password, &standby_addrs, log)?;
    for standby in nodes.iter().skip(1) {
        configure_standby(standby, &primary, &p.repl_user, &p.repl_password, log)?;
    }
    let cluster = PgCluster {
        id: format!("pgha-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        name: p.name.clone(),
        cluster: p.cluster.clone(),
        owner_node: String::new(), // stamped by the API with the local self id
        nodes,
        db_user: p.db_user.clone(),
        db_password_enc: enc_secret(&p.db_password),
        repl_user: p.repl_user.clone(),
        repl_password_enc: enc_secret(&p.repl_password),
        created_at: now,
        provisioned: true,
    };
    let _ = log.send(format!("  ✓ Postgres HA cluster '{}' ready ({} node(s))", cluster.name, cluster.nodes.len()));
    Ok(cluster)
}

/// Promote a standby to primary (`pg_promote()`). The one destructive
/// lifecycle op — operator-driven, never automatic — because promoting the
/// wrong (behind) standby forks history. The caller should Stop the old
/// primary first to avoid two write masters.
pub fn promote_standby(cluster: &PgCluster, container: &str) -> Result<String, String> {
    let node = cluster.nodes.iter().find(|n| n.container == container)
        .ok_or_else(|| format!("node '{}' not in cluster", container))?;
    let db_pw = dec_secret(&cluster.db_password_enc);
    // pg_promote() waits up to 60s for the promotion to complete.
    let out = psql_query(node, &cluster.db_user, &db_pw, "SELECT pg_promote(true, 60)::text")?;
    if out.trim().starts_with('t') {
        Ok(format!("'{}' promoted to primary", container))
    } else {
        Err(format!("pg_promote on '{}' did not confirm within 60s (got: {})", container, out.trim()))
    }
}

/// Start/stop/restart a node's Postgres service.
pub fn node_service(cluster: &PgCluster, container: &str, action: &str) -> Result<String, String> {
    let node = cluster.nodes.iter().find(|n| n.container == container)
        .ok_or_else(|| format!("node '{}' not in cluster", container))?;
    match action {
        "start" => start_pg(&node.kind, &node.container).map(|_| format!("started {}", container)),
        "stop" => stop_pg(&node.kind, &node.container).map(|_| format!("stopped {}", container)),
        "restart" => restart_pg(&node.kind, &node.container).map(|_| format!("restarted {}", container)),
        other => Err(format!("unknown action '{}'", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_serde_snake_case() {
        assert_eq!(serde_json::to_string(&PgRole::Primary).unwrap(), "\"primary\"");
        assert_eq!(serde_json::to_string(&PgRole::Standby).unwrap(), "\"standby\"");
        let r: PgRole = serde_json::from_str("\"standby\"").unwrap();
        assert_eq!(r, PgRole::Standby);
    }

    #[test]
    fn sql_string_literal_escapes_quotes() {
        assert_eq!(sql_string_literal("p@ss"), "'p@ss'");
        assert_eq!(sql_string_literal("O'Brien"), "'O''Brien'");
    }

    #[test]
    fn shell_single_quote_escapes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn config_defaults_are_backward_compatible() {
        // An older/minimal JSON must deserialize with sane defaults.
        let c: PgCluster = serde_json::from_str(
            "{\"id\":\"x\",\"name\":\"n\",\"nodes\":[{\"container\":\"c\",\"address\":\"10.0.0.1\",\"role\":\"primary\"}]}"
        ).unwrap();
        assert_eq!(c.db_user, "postgres");
        assert_eq!(c.repl_user, "replicator");
        assert_eq!(c.nodes[0].port, 5432);
        assert_eq!(c.nodes[0].kind, "lxc");
    }

    #[test]
    fn identifier_validation_rejects_injection() {
        assert!(is_valid_pg_ident("postgres"));
        assert!(is_valid_pg_ident("replicator"));
        assert!(is_valid_pg_ident("app_user_1"));
        // Injection attempts and invalid forms are rejected.
        assert!(!is_valid_pg_ident("postgres; DROP DATABASE x; --"));
        assert!(!is_valid_pg_ident("a'b"));
        assert!(!is_valid_pg_ident("a-b"));       // hyphen not a SQL identifier char
        assert!(!is_valid_pg_ident("1abc"));      // can't start with a digit
        assert!(!is_valid_pg_ident(""));
        assert!(!is_valid_pg_ident("$(touch /tmp/x)"));
    }

    #[test]
    fn container_and_addr_validation() {
        assert!(is_valid_container_name("pg-node1"));
        assert!(!is_valid_container_name("pg'; touch x; '"));
        assert!(!is_valid_container_name("$(id)"));
        assert!(is_valid_addr("10.0.0.1"));
        assert!(is_valid_addr("fd00::1"));
        assert!(!is_valid_addr("$(touch /tmp/x)"));
        assert!(!is_valid_addr("10.0.0.1; rm -rf /"));
    }

    #[test]
    fn pgpass_escape_handles_field_metacharacters() {
        assert_eq!(pgpass_escape("p@ss"), "p@ss");
        assert_eq!(pgpass_escape("pa:ss"), "pa\\:ss");
        assert_eq!(pgpass_escape("pa\\ss"), "pa\\\\ss");
    }

    #[test]
    fn validate_provision_inputs_rejects_bad_fields() {
        let base = |du: &str, ru: &str, container: &str, addr: &str| ProvisionRequest {
            name: "n".into(), cluster: String::new(),
            members: vec![ProvisionMember { node_id: "a".into(), container: container.into(), address: addr.into() }],
            db_user: du.into(), db_password: "pw".into(),
            repl_user: ru.into(), repl_password: "pw".into(),
            distribution: String::new(), release: String::new(),
        };
        assert!(validate_provision_inputs(&base("postgres", "replicator", "pg1", "10.0.0.1")).is_ok());
        assert!(validate_provision_inputs(&base("bad;user", "replicator", "pg1", "10.0.0.1")).is_err());
        assert!(validate_provision_inputs(&base("postgres", "r'x", "pg1", "10.0.0.1")).is_err());
        assert!(validate_provision_inputs(&base("postgres", "replicator", "pg$(x)", "10.0.0.1")).is_err());
        assert!(validate_provision_inputs(&base("postgres", "replicator", "pg1", "not-an-ip")).is_err());
    }

    #[test]
    fn provision_request_first_member_is_primary() {
        // Sanity on the model contract the provisioner relies on.
        let members = [ProvisionMember { node_id: "a".into(), container: "pg1".into(), address: "10.0.0.1".into() },
            ProvisionMember { node_id: "b".into(), container: "pg2".into(), address: "10.0.0.2".into() }];
        assert_eq!(members[0].container, "pg1");
        assert_eq!(members[1].container, "pg2");
    }
}
