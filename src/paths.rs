// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Centralised file location configuration.
//!
//! Every WolfStack path constant goes through this module so users can
//! override defaults via `/etc/wolfstack/paths.json` or the Settings UI.

use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};

const PATHS_CONFIG_FILE: &str = "/etc/wolfstack/paths.json";

/// All configurable file locations with their defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLocations {
    // ── Core config directory ─────────────────────
    #[serde(default = "default_config_dir")]
    pub config_dir: String,

    // ── Backup ────────────────────────────────────
    #[serde(default = "default_backup_config")]
    pub backup_config: String,
    #[serde(default = "default_backup_staging_dir")]
    pub backup_staging_dir: String,
    #[serde(default = "default_backup_received_dir")]
    pub backup_received_dir: String,
    // Where "Local" backups are written. Defaults to the WolfStack data dir,
    // but an operator can point it at any mount (e.g. an R2/S3 fuse mount) so
    // backups don't depend on the WolfStack folder structure.
    #[serde(default = "default_backup_local_dir")]
    pub backup_local_dir: String,

    // Where standalone Docker Compose stacks live (the Compose page). Point it
    // at an existing compose root and every `<name>/docker-compose.yml` under
    // it shows up as a managed stack — that's the "import existing compose
    // files" path. Default unchanged so existing stacks keep working.
    #[serde(default = "default_compose_dir")]
    pub compose_dir: String,

    // ── Storage ───────────────────────────────────
    #[serde(default = "default_storage_config")]
    pub storage_config: String,
    #[serde(default = "default_storage_mount_base")]
    pub storage_mount_base: String,
    #[serde(default = "default_s3_credentials_dir")]
    pub s3_credentials_dir: String,
    #[serde(default = "default_s3_cache_dir")]
    pub s3_cache_dir: String,

    // ── Cluster / Nodes ───────────────────────────
    #[serde(default = "default_nodes_config")]
    pub nodes_config: String,
    #[serde(default = "default_deleted_nodes_config")]
    pub deleted_nodes_config: String,
    #[serde(default = "default_self_cluster_config")]
    pub self_cluster_config: String,
    #[serde(default = "default_self_site_config")]
    pub self_site_config: String,
    #[serde(default = "default_self_display_name_config")]
    pub self_display_name_config: String,
    #[serde(default = "default_pending_identity_config")]
    pub pending_identity_config: String,
    #[serde(default = "default_node_id_file")]
    pub node_id_file: String,
    #[serde(default = "default_xo_pools_config")]
    pub xo_pools_config: String,
    #[serde(default = "default_truenas_config")]
    pub truenas_config: String,

    // ── Alerting ──────────────────────────────────
    #[serde(default = "default_alerts_config")]
    pub alerts_config: String,

    // ── Status pages ──────────────────────────────
    #[serde(default = "default_statuspage_config")]
    pub statuspage_config: String,
    #[serde(default = "default_statuspage_uptime")]
    pub statuspage_uptime: String,

    // ── AI Agent ──────────────────────────────────
    #[serde(default = "default_ai_config")]
    pub ai_config: String,
    #[serde(default = "default_ai_baseline")]
    pub ai_baseline: String,
    #[serde(default = "default_ai_suppress_secret")]
    pub ai_suppress_secret: String,

    // ── WolfRun ───────────────────────────────────
    #[serde(default = "default_wolfrun_dir")]
    pub wolfrun_dir: String,
    #[serde(default = "default_wolfrun_services")]
    pub wolfrun_services: String,
    #[serde(default = "default_wolfrun_failover_events")]
    pub wolfrun_failover_events: String,

    // ── WolfFlow ──────────────────────────────────
    #[serde(default = "default_wolfflow_dir")]
    pub wolfflow_dir: String,
    #[serde(default = "default_wolfflow_workflows")]
    pub wolfflow_workflows: String,
    #[serde(default = "default_wolfflow_runs")]
    pub wolfflow_runs: String,

    // ── Kubernetes ────────────────────────────────
    #[serde(default = "default_kubernetes_config")]
    pub kubernetes_config: String,

    // ── App Store ─────────────────────────────────
    #[serde(default = "default_appstore_dir")]
    pub appstore_dir: String,
    #[serde(default = "default_appstore_installed")]
    pub appstore_installed: String,
    #[serde(default = "default_appstore_pending_dir")]
    pub appstore_pending_dir: String,

    // ── Ceph ──────────────────────────────────────
    #[serde(default = "default_ceph_config")]
    pub ceph_config: String,

    // ── VMs ───────────────────────────────────────
    #[serde(default = "default_vms_dir")]
    pub vms_dir: String,

    // ── TLS ───────────────────────────────────────
    #[serde(default = "default_tls_cert")]
    pub tls_cert: String,
    #[serde(default = "default_tls_key")]
    pub tls_key: String,

    // ── Auth ──────────────────────────────────────
    #[serde(default = "default_cluster_secret")]
    pub cluster_secret: String,

    // ── Patreon ───────────────────────────────────
    #[serde(default = "default_patreon_config")]
    pub patreon_config: String,

    // ── IP Mappings ───────────────────────────────
    #[serde(default = "default_ip_mappings")]
    pub ip_mappings: String,

    // ── LXC Paths ─────────────────────────────────
    #[serde(default = "default_lxc_paths")]
    pub lxc_paths: String,

    // ── Containers ────────────────────────────────
    #[serde(default = "default_cluster_containers_dir")]
    pub cluster_containers_dir: String,

    // ── Icon Packs ────────────────────────────────
    #[serde(default = "default_icon_packs_dir")]
    pub icon_packs_dir: String,

    // ── PBS ───────────────────────────────────────
    #[serde(default = "default_pbs_config")]
    pub pbs_config: String,

    // ── WolfNote ───────────────────────────────────
    #[serde(default = "default_wolfnote_config")]
    pub wolfnote_config: String,

    // ── Web UI ────────────────────────────────────
    #[serde(default = "default_web_dir")]
    pub web_dir: String,

    // ── Ports ─────────────────────────────────────
    #[serde(default = "default_ports_config")]
    pub ports_config: String,

    // ── SQL Connections (agent + wolfflow) ────────
    #[serde(default = "default_sql_connections_config")]
    pub sql_connections_config: String,
    #[serde(default = "default_sql_audit_log")]
    pub sql_audit_log: String,
}

// ── Default value functions ──────────────────────────

fn default_config_dir() -> String { "/etc/wolfstack".into() }

fn default_backup_config() -> String { "/etc/wolfstack/backups.json".into() }
fn default_backup_staging_dir() -> String { "/tmp/wolfstack-backups".into() }
fn default_backup_received_dir() -> String { "/var/lib/wolfstack/backups/received".into() }
fn default_backup_local_dir() -> String { "/var/lib/wolfstack/backups".into() }
fn default_compose_dir() -> String { "/etc/wolfstack/compose".into() }

fn default_storage_config() -> String { "/etc/wolfstack/storage.json".into() }
fn default_storage_mount_base() -> String { "/mnt/wolfstack".into() }
fn default_s3_credentials_dir() -> String { "/etc/wolfstack/s3".into() }
fn default_s3_cache_dir() -> String { "/var/cache/wolfstack/s3".into() }

fn default_nodes_config() -> String { "/etc/wolfstack/nodes.json".into() }
fn default_deleted_nodes_config() -> String { "/etc/wolfstack/deleted_nodes.json".into() }
fn default_self_cluster_config() -> String { "/etc/wolfstack/self_cluster.json".into() }
fn default_self_site_config() -> String { "/etc/wolfstack/self_site.json".into() }
fn default_self_display_name_config() -> String { "/etc/wolfstack/self_display_name.json".into() }
fn default_pending_identity_config() -> String { "/etc/wolfstack/pending_identity.json".into() }
fn default_node_id_file() -> String { "/etc/wolfstack/node_id".into() }
fn default_xo_pools_config() -> String { "/etc/wolfstack/xo_pools.json".into() }
fn default_truenas_config() -> String { "/etc/wolfstack/truenas.json".into() }

fn default_alerts_config() -> String { "/etc/wolfstack/alerts.json".into() }

fn default_statuspage_config() -> String { "/etc/wolfstack/statuspage.json".into() }
fn default_statuspage_uptime() -> String { "/etc/wolfstack/statuspage-uptime.json".into() }

fn default_ai_config() -> String { "/etc/wolfstack/ai-config.json".into() }
fn default_ai_baseline() -> String { "/var/lib/wolfstack/ai-baseline.json".into() }
fn default_ai_suppress_secret() -> String { "/etc/wolfstack/ai-suppress-secret".into() }

fn default_wolfrun_dir() -> String { "/etc/wolfstack/wolfrun".into() }
fn default_wolfrun_services() -> String { "/etc/wolfstack/wolfrun/services.json".into() }
fn default_wolfrun_failover_events() -> String { "/etc/wolfstack/wolfrun/failover-events.json".into() }

fn default_wolfflow_dir() -> String { "/etc/wolfstack/wolfflow".into() }
fn default_wolfflow_workflows() -> String { "/etc/wolfstack/wolfflow/workflows.json".into() }
fn default_wolfflow_runs() -> String { "/etc/wolfstack/wolfflow/runs.json".into() }

fn default_kubernetes_config() -> String { "/etc/wolfstack/kubernetes.json".into() }

fn default_appstore_dir() -> String { "/etc/wolfstack/appstore".into() }
fn default_appstore_installed() -> String { "/etc/wolfstack/appstore/installed.json".into() }
fn default_appstore_pending_dir() -> String { "/etc/wolfstack/appstore/pending".into() }

fn default_ceph_config() -> String { "/etc/wolfstack/ceph.json".into() }

fn default_vms_dir() -> String { "/var/lib/wolfstack/vms".into() }

fn default_tls_cert() -> String { "/etc/wolfstack/cert.pem".into() }
fn default_tls_key() -> String { "/etc/wolfstack/key.pem".into() }

fn default_cluster_secret() -> String { "/etc/wolfstack/custom-cluster-secret".into() }

fn default_patreon_config() -> String { "/etc/wolfstack/patreon.json".into() }

fn default_ip_mappings() -> String { "/etc/wolfstack/ip-mappings.json".into() }

fn default_lxc_paths() -> String { "/etc/wolfstack/lxc-paths.json".into() }

fn default_cluster_containers_dir() -> String { "/etc/wolfstack/cluster-containers".into() }

fn default_icon_packs_dir() -> String { "/etc/wolfstack/icon-packs".into() }

fn default_pbs_config() -> String { "/etc/wolfstack/pbs/config.json".into() }

fn default_wolfnote_config() -> String { "/etc/wolfstack/wolfnote.json".into() }

fn default_web_dir() -> String { "/opt/wolfstack/web".into() }

fn default_ports_config() -> String { "/etc/wolfstack/ports.json".into() }

fn default_sql_connections_config() -> String { "/etc/wolfstack/sql-connections.json".into() }
fn default_sql_audit_log() -> String { "/var/log/wolfstack/sql-audit.log".into() }

impl Default for FileLocations {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

// ── Global singleton ─────────────────────────────────

static LOCATIONS: LazyLock<RwLock<FileLocations>> = LazyLock::new(|| {
    let locs = load_from_disk();
    RwLock::new(locs)
});

fn load_from_disk() -> FileLocations {
    match std::fs::read_to_string(PATHS_CONFIG_FILE) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => FileLocations::default(),
    }
}

/// Get a snapshot of the current file locations.
pub fn get() -> FileLocations {
    LOCATIONS.read().unwrap().clone()
}

/// Update file locations and persist to disk.
pub fn update(locs: FileLocations) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&locs)
        .map_err(|e| format!("Failed to serialize paths config: {}", e))?;
    // 0600 — this file decides where secrets get written. An attacker
    // who can edit paths.json can redirect write_secure targets to
    // attacker-controlled locations. harden_existing covers the old
    // file on upgrade; write_secure covers fresh writes.
    write_secure(PATHS_CONFIG_FILE, json)
        .map_err(|e| format!("Failed to write paths config: {}", e))?;
    *LOCATIONS.write().unwrap() = locs;
    Ok(())
}

// ── Secure-write helpers ─────────────────────────────────────────────
//
// Prior to v18.7.27 every `std::fs::write` in the codebase inherited
// the process umask (typically 022), so secrets like the cluster
// secret, PVE tokens in nodes.json, and the join-token were created
// world-readable (0644). Any unprivileged local user could read them.
// These helpers plug that hole for NEW writes; `harden_existing()`
// fixes installs that already have the bad permissions.

/// Write a file with mode 0600 (owner-only). Used for anything
/// carrying credentials or auth tokens — cluster secret, join-token,
/// nodes.json (which contains pve_token fields), license.key.
///
/// Creates parent directories with mode 0700 as needed. On non-Unix
/// platforms mode is ignored (WolfStack is Linux-only in practice
/// but the code stays portable).
pub fn write_secure(path: &str, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write;
    // Ensure parent exists. We don't chmod the parent here — that's
    // harden_existing()'s job, done once at startup, so we don't race
    // with other writers mid-operation.
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_ref())?;
        // If the file existed before with looser perms, the mode
        // argument above is ignored — explicitly enforce 0600 now.
        let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .open(path)?;
        f.write_all(contents.as_ref())
    }
}

/// One-shot: tighten permissions on `/etc/wolfstack` and any known
/// sensitive file that might already exist with 0644 from a pre-v18.7.27
/// install. Called once from main at startup. Silent on failure
/// (best-effort — not every install runs as root all the time, and a
/// failed chmod shouldn't block boot).
pub fn harden_existing() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locs = get();
        // Directory: 0700 on /etc/wolfstack so the directory listing is
        // owner-only. Files inside inherit nothing from dir mode, but
        // a readable dir makes targeted secret-file reads easier for
        // an attacker even when the files themselves are locked down.
        if let Ok(meta) = std::fs::metadata(&locs.config_dir) {
            let _ = std::fs::set_permissions(
                &locs.config_dir,
                std::fs::Permissions::from_mode(0o700),
            );
            let _ = meta; // silence unused on some toolchains
        }
        // Files known to hold credentials or cluster auth state.
        // Legacy paths are included because old installs may still
        // carry `/etc/wolfstack/cluster-secret` from v11.26.3 even
        // though current code writes `custom-cluster-secret`.
        //
        // Extended list (v18.7.30) covers every writer migrated to
        // write_secure — existing installs get permissions tightened
        // on the next restart without needing the file to be rewritten.
        let sensitive = [
            locs.cluster_secret.clone(),
            "/etc/wolfstack/cluster-secret".to_string(),
            locs.nodes_config.clone(),
            "/etc/wolfstack/join-token".to_string(),
            "/etc/wolfstack/license.key".to_string(),
            locs.tls_key.clone(),
            "/etc/wolfstack/users.json".to_string(),         // password hashes
            "/etc/wolfstack/auth-config.json".to_string(),   // auth tuning
            "/etc/wolfstack/oidc.json".to_string(),          // OIDC client secrets
            "/etc/wolfstack/ai-config.json".to_string(),     // LLM API keys + SMTP pass
            "/etc/wolfstack/pbs/config.json".to_string(),    // PBS tokens
            "/etc/wolfstack/paths.json".to_string(),         // path remap — if attacker-controlled, can redirect secret writers
            "/etc/ppp/chap-secrets".to_string(),             // PPPoE passwords (WAN)
            "/etc/ppp/pap-secrets".to_string(),
        ];
        for path in &sensitive {
            if std::path::Path::new(path).exists() {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        // Sensitive directories — /etc/wolfstack/s3 contains per-mount
        // credentials files; /etc/wolfstack/config-backups holds whole-config
        // snapshots that embed storage / AI / PBS credentials. Lock the
        // directory itself (0700) AND every file inside it (0600). The runtime
        // already sets these on write, but harden a dir that pre-existed at
        // looser perms (e.g. created by a manual restore).
        let sensitive_dirs = [
            "/etc/wolfstack/s3",
            "/etc/wolfstack/config-backups",
        ];
        for dir in &sensitive_dirs {
            let p = std::path::Path::new(dir);
            if p.exists() {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                if let Ok(entries) = std::fs::read_dir(p) {
                    for entry in entries.flatten() {
                        let _ = std::fs::set_permissions(
                            entry.path(),
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
            }
        }
    }
}
