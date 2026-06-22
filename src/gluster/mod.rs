// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! GlusterFS trusted-storage-pool management — the Gluster analogue of
//! `src/ceph/mod.rs`. Manages peers, volumes, bricks and self-heal by shelling
//! out to the `gluster` CLI.
//!
//! gluster's machine-readable output is XML (`--xml`) and WolfStack carries no
//! XML crate, so we parse gluster's stable human-readable text instead
//! (`gluster pool list`, `gluster volume info`, `gluster volume status`). Those
//! formats have been stable for many major releases; each parser is tolerant of
//! extra/missing lines so a format tweak degrades to "field unknown" rather
//! than an error.
//!
//! Gluster is inherently cluster-wide: any peer in the trusted pool can manage
//! the whole pool, so "by cluster" management works by talking to any one node
//! (the WolfStack node-proxy targets the chosen node). Import = adopt an
//! already-running glusterd with its existing peers/volumes (no destructive
//! bootstrap).

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::info;

// ─── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GlusterHealth {
    #[default]
    Unknown,
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlusterPeer {
    pub uuid: String,
    pub hostname: String,
    /// True when the peer is reachable / in the pool.
    pub connected: bool,
    /// Raw state string from gluster (e.g. "Peer in Cluster (Connected)").
    pub state: String,
    /// The node we're querying reports itself as "localhost" in `pool list`.
    pub is_localhost: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlusterBrick {
    /// Brick spec `host:/path` — the clean form (any " (arbiter)" annotation
    /// is stripped here and surfaced via `arbiter`), so it matches the brick
    /// identity used by `volume status` and accepted by remove-brick.
    pub spec: String,
    pub host: String,
    pub path: String,
    /// Arbiter brick (metadata only, no file data) in a replica+arbiter volume.
    pub arbiter: bool,
    pub online: bool,
    pub pid: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlusterVolume {
    pub name: String,
    pub volume_id: String,
    /// Replicate / Distribute / Distributed-Replicate / Disperse / ...
    pub vol_type: String,
    /// Started / Stopped / Created.
    pub status: String,
    pub started: bool,
    pub brick_count: u32,
    pub replica_count: u32,
    pub transport: String,
    pub bricks: Vec<GlusterBrick>,
    /// Reconfigured options as (key, value) pairs.
    pub options: Vec<(String, String)>,
    /// Entries pending self-heal (summed across bricks); best-effort.
    pub heal_pending: u64,
    pub size_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlusterStatus {
    pub installed: bool,
    pub glusterd_running: bool,
    /// WolfStack has adopted/created this pool (persisted in gluster.json).
    pub configured: bool,
    /// Operator-facing label scoping this pool to a WolfStack cluster.
    pub cluster_name: String,
    pub health: GlusterHealth,
    pub health_detail: String,
    pub version: String,
    /// Hostname of the node we queried.
    pub this_node: String,
    pub peers: Vec<GlusterPeer>,
    pub volumes: Vec<GlusterVolume>,
}

/// Persisted WolfStack-side state (paths::get().gluster_config). gluster itself
/// owns the real pool state; this only records that WolfStack manages it and
/// the operator's cluster label.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlusterConfig {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub cluster_name: String,
}

// ─── CLI helpers ─────────────────────────────────────────────────────

/// Run `gluster <args>` and return trimmed stdout, or an error carrying stderr.
/// `--mode=script` suppresses the interactive "Are you sure?" prompts so
/// destructive commands (stop/delete/detach) don't hang waiting on a TTY.
fn gluster(args: &[&str]) -> Result<String, String> {
    let mut full: Vec<&str> = vec!["--mode=script"];
    full.extend_from_slice(args);
    let output = Command::new("gluster")
        .args(&full)
        .output()
        .map_err(|e| format!("Failed to run gluster: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // gluster often prints the real reason to stdout, not stderr.
        let msg = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
        return Err(format!("gluster {} failed: {}", args.join(" "), msg));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `which gluster` — is the CLI present?
pub fn is_installed() -> bool {
    Command::new("which")
        .arg("gluster")
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
        || ["/usr/sbin/gluster", "/sbin/gluster", "/usr/bin/gluster", "/bin/gluster"]
            .iter()
            .any(|p| std::path::Path::new(p).exists())
}

/// Is the glusterd management daemon active? Without it every gluster command
/// fails, so the UI gates actions on this.
pub fn glusterd_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "glusterd"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

// ─── Config persistence ──────────────────────────────────────────────

pub fn load_config() -> GlusterConfig {
    let path = crate::paths::get().gluster_config;
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_config(cfg: &GlusterConfig) -> Result<(), String> {
    let path = crate::paths::get().gluster_config;
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("write {}: {}", path, e))
}

// ─── Validation (defence in depth — args go via execve, not a shell) ─

fn valid_volume_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
}

/// A brick spec is `host:/abs/path`. Validate both halves.
fn valid_brick(spec: &str) -> bool {
    match spec.split_once(":/") {
        // Reject `..` (defence in depth — gluster would reject it too) and
        // whitespace; require a non-empty path.
        Some((host, rest)) => {
            valid_host(host) && !rest.is_empty() && !rest.contains(['\n', ' ']) && !rest.contains("..")
        }
        None => false,
    }
}

// ─── Install / lifecycle ─────────────────────────────────────────────

/// Component/availability snapshot for the setup banner.
pub fn get_install_status() -> serde_json::Value {
    let installed = is_installed();
    let running = glusterd_running();
    let cfg = load_config();
    // A pool with >1 member (or any volume) is a sign there's an existing
    // cluster to import rather than start fresh.
    let (existing_peers, existing_volumes) = if installed && running {
        let st = get_status();
        let real_peers = st.peers.iter().filter(|p| !p.is_localhost).count();
        (real_peers, st.volumes.len())
    } else {
        (0, 0)
    };
    serde_json::json!({
        "installed": installed,
        "glusterd_running": running,
        "configured": cfg.configured,
        "cluster_name": cfg.cluster_name,
        // Importable = a live glusterd that already has peers or volumes but
        // WolfStack hasn't adopted yet.
        "importable": running && !cfg.configured && (existing_peers > 0 || existing_volumes > 0),
        "existing_peers": existing_peers,
        "existing_volumes": existing_volumes,
    })
}

/// Install glusterfs-server (cross-distro via the shared installer) and enable
/// the glusterd daemon. Idempotent.
pub fn install() -> Result<String, String> {
    if !is_installed() {
        crate::installer::packages::install("glusterfs")
            .map_err(|e| format!("Could not install glusterfs: {}", e))?;
    }
    start_glusterd()?;
    Ok("GlusterFS installed and glusterd started.".to_string())
}

/// Enable + start glusterd. Safe to call repeatedly.
fn start_glusterd() -> Result<String, String> {
    let _ = Command::new("systemctl").args(["enable", "glusterd"]).status();
    let out = Command::new("systemctl")
        .args(["start", "glusterd"])
        .output()
        .map_err(|e| format!("systemctl start glusterd: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "Could not start glusterd: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok("glusterd running".to_string())
}

/// "Bootstrap" a pool: ensure glusterd is up and record the WolfStack cluster
/// label. gluster forms a single-node pool the moment glusterd runs, so there's
/// no destructive cluster-create step like Ceph's — peers are added later.
pub fn bootstrap(cluster_name: &str) -> Result<String, String> {
    if !is_installed() {
        return Err("GlusterFS is not installed — install it first.".to_string());
    }
    start_glusterd()?;
    save_config(&GlusterConfig {
        configured: true,
        cluster_name: cluster_name.trim().to_string(),
    })?;
    info!("gluster: pool initialised (cluster label '{}')", cluster_name.trim());
    Ok("GlusterFS pool ready — add peers and create volumes.".to_string())
}

/// Adopt an already-running glusterd (with its existing peers/volumes) without
/// touching the pool. This is the "import an existing cluster" path.
pub fn import_existing(cluster_name: &str) -> Result<GlusterStatus, String> {
    if !is_installed() {
        return Err("GlusterFS is not installed on this node.".to_string());
    }
    if !glusterd_running() {
        return Err("glusterd is not running — nothing to import. Start it first.".to_string());
    }
    // Adopt the running pool (non-destructive) then read it back once so the
    // returned status reflects configured=true.
    save_config(&GlusterConfig {
        configured: true,
        cluster_name: cluster_name.trim().to_string(),
    })?;
    let status = get_status();
    info!(
        "gluster: imported existing pool ({} peer(s), {} volume(s))",
        status.peers.len(),
        status.volumes.len()
    );
    Ok(status)
}

// ─── Status assembly ─────────────────────────────────────────────────

pub fn get_status() -> GlusterStatus {
    let mut status = GlusterStatus {
        installed: is_installed(),
        ..Default::default()
    };
    let cfg = load_config();
    status.configured = cfg.configured;
    status.cluster_name = cfg.cluster_name;
    status.this_node = hostname();
    if !status.installed {
        return status;
    }
    status.glusterd_running = glusterd_running();
    // Version (`gluster --version` → first line "glusterfs 11.1").
    if let Ok(out) = Command::new("gluster").arg("--version").output() {
        if let Some(line) = String::from_utf8_lossy(&out.stdout).lines().next() {
            status.version = line.trim().to_string();
        }
    }
    if !status.glusterd_running {
        status.health = GlusterHealth::Error;
        status.health_detail = "glusterd is not running".to_string();
        return status;
    }

    status.peers = parse_peers(&gluster(&["pool", "list"]).unwrap_or_default());

    // Volumes: `volume info` for layout/options, then enrich with live brick
    // state from `volume status` and heal counts per volume.
    status.volumes = parse_volume_info(&gluster(&["volume", "info"]).unwrap_or_default());
    for vol in &mut status.volumes {
        if let Ok(st) = gluster(&["volume", "status", &vol.name, "detail"]) {
            apply_volume_status(vol, &st);
        }
        if vol.started {
            vol.heal_pending = heal_pending_count(&vol.name);
        }
    }

    let (health, detail) = compute_health(&status);
    status.health = health;
    status.health_detail = detail;
    status
}

/// Derive an overall health rollup + a human detail string.
fn compute_health(status: &GlusterStatus) -> (GlusterHealth, String) {
    let mut problems: Vec<String> = Vec::new();
    let disconnected: Vec<&str> = status
        .peers
        .iter()
        .filter(|p| !p.is_localhost && !p.connected)
        .map(|p| p.hostname.as_str())
        .collect();
    if !disconnected.is_empty() {
        problems.push(format!("peer(s) disconnected: {}", disconnected.join(", ")));
    }
    let mut heal_total = 0u64;
    for v in &status.volumes {
        let offline: Vec<&str> = v
            .bricks
            .iter()
            .filter(|b| !b.online)
            .map(|b| b.spec.as_str())
            .collect();
        if v.started && !offline.is_empty() {
            problems.push(format!("{}: brick(s) offline ({})", v.name, offline.join(", ")));
        }
        heal_total += v.heal_pending;
    }
    if heal_total > 0 {
        problems.push(format!("{} entr{} pending self-heal", heal_total, if heal_total == 1 { "y" } else { "ies" }));
    }
    let detail = problems.join("; ");
    let health = if problems.iter().any(|p| p.contains("offline") || p.contains("disconnected")) {
        GlusterHealth::Error
    } else if heal_total > 0 {
        GlusterHealth::Warn
    } else {
        GlusterHealth::Ok
    };
    (health, detail)
}

// ─── Text parsers ────────────────────────────────────────────────────

/// Parse `gluster pool list`:
/// ```text
/// UUID                                    Hostname        State
/// 1a2b...                                 node2           Connected
/// 9f8e...                                 localhost       Connected
/// ```
fn parse_peers(text: &str) -> Vec<GlusterPeer> {
    let mut peers = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let uuid = cols[0].to_string();
        // State is the trailing token(s); hostname is the middle. With exactly
        // 3 columns this is unambiguous; gluster pool list always uses 3.
        let state = cols[cols.len() - 1].to_string();
        let hostname = cols[1..cols.len() - 1].join(" ");
        let is_localhost = hostname == "localhost";
        peers.push(GlusterPeer {
            uuid,
            hostname,
            connected: state.eq_ignore_ascii_case("connected"),
            state,
            is_localhost,
        });
    }
    peers
}

/// Parse `gluster volume info` (all volumes). Volumes are separated by blank
/// lines; each is a block of `Key: Value` lines plus `Bricks:` and
/// `Options Reconfigured:` sub-sections.
fn parse_volume_info(text: &str) -> Vec<GlusterVolume> {
    let mut volumes = Vec::new();
    let mut cur: Option<GlusterVolume> = None;
    // Sub-section state: 0 = header, 1 = bricks, 2 = options.
    let mut section = 0u8;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(name) = line.strip_prefix("Volume Name:") {
            if let Some(v) = cur.take() {
                volumes.push(v);
            }
            cur = Some(GlusterVolume {
                name: name.trim().to_string(),
                ..Default::default()
            });
            section = 0;
            continue;
        }
        let Some(v) = cur.as_mut() else { continue };
        if line == "Bricks:" {
            section = 1;
            continue;
        }
        if line.starts_with("Options Reconfigured:") {
            section = 2;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        match section {
            1 => {
                // "Brick1: host:/path" — optionally suffixed " (arbiter)" /
                // " (thin-arbiter)". Strip the annotation so `spec` is the clean
                // host:/path that `volume status` reports and remove-brick wants.
                if let Some((_, rest)) = line.split_once(':') {
                    let rest = rest.trim();
                    let (spec, arbiter) = match rest.split_once(" (") {
                        Some((s, ann)) => (s.trim(), ann.contains("arbiter")),
                        None => (rest, false),
                    };
                    if let Some((host, path)) = spec.split_once(":/") {
                        v.bricks.push(GlusterBrick {
                            spec: spec.to_string(),
                            host: host.to_string(),
                            path: format!("/{}", path),
                            arbiter,
                            ..Default::default()
                        });
                    }
                }
            }
            2 => {
                if let Some((k, val)) = line.split_once(':') {
                    v.options.push((k.trim().to_string(), val.trim().to_string()));
                }
            }
            _ => {
                if let Some((k, val)) = line.split_once(':') {
                    let val = val.trim();
                    match k.trim() {
                        "Volume ID" => v.volume_id = val.to_string(),
                        "Type" => v.vol_type = val.to_string(),
                        "Status" => {
                            v.status = val.to_string();
                            v.started = val.eq_ignore_ascii_case("started");
                        }
                        "Transport-type" => v.transport = val.to_string(),
                        "Number of Bricks" => {
                            // "1 x 2 = 2" (replica) or "3" (distribute). Take the
                            // last number as the total; the replica factor is the
                            // middle "x N" term when present.
                            if let Some(total) = val.rsplit('=').next().and_then(|s| s.trim().parse::<u32>().ok()) {
                                v.brick_count = total;
                            } else if let Ok(n) = val.trim().parse::<u32>() {
                                v.brick_count = n;
                            }
                            if let Some(x_term) = val.split('x').nth(1) {
                                // After 'x': " 2 = 2" (replica) or " (2 + 1) = 3"
                                // (replica+arbiter). The data-replica factor is
                                // the FIRST integer either way.
                                let first_int: String = x_term
                                    .chars()
                                    .skip_while(|c| !c.is_ascii_digit())
                                    .take_while(|c| c.is_ascii_digit())
                                    .collect();
                                if let Ok(rep) = first_int.parse::<u32>() {
                                    v.replica_count = rep;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(v) = cur.take() {
        volumes.push(v);
    }
    volumes
}

/// Enrich a volume's bricks with live Online/Pid + size from
/// `gluster volume status <vol> detail`. The `detail` form prints a stanza per
/// brick with "Brick : host:/path", "Online : Y", "Pid : 1234",
/// "Total Disk Space : 100.0GB", "Disk Space Free : 80.0GB".
fn apply_volume_status(vol: &mut GlusterVolume, text: &str) {
    // First pass: collect each brick stanza's live state. (spec, online, pid,
    // total_bytes, free_bytes). A two-pass approach avoids holding a mutable
    // borrow of vol.bricks across the parse loop.
    let mut updates: Vec<(String, bool, String, u64, u64)> = Vec::new();
    let mut cur: Option<(String, bool, String, u64, u64)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        let Some((key, val)) = line.split_once(':') else { continue };
        let (key, val) = (key.trim(), val.trim());
        match key {
            "Brick" => {
                if let Some(u) = cur.take() {
                    updates.push(u);
                }
                // `volume status … detail` prints the value as "Brick host:/path"
                // — strip the leading "Brick " so the spec matches the clean
                // host:/path from `volume info`. Without this NO brick ever
                // matched, so every brick showed offline/no-size (caught against
                // a live replica+arbiter pool, 2026-06-22).
                let spec = val.strip_prefix("Brick ").unwrap_or(val).trim().to_string();
                cur = Some((spec, false, String::new(), 0, 0));
            }
            "Online" => {
                if let Some(u) = cur.as_mut() {
                    u.1 = val.eq_ignore_ascii_case("y") || val.eq_ignore_ascii_case("yes");
                }
            }
            "Pid" => {
                if let Some(u) = cur.as_mut() {
                    u.2 = val.to_string();
                }
            }
            "Total Disk Space" => {
                if let Some(u) = cur.as_mut() {
                    u.3 = parse_size(val);
                }
            }
            "Disk Space Free" => {
                if let Some(u) = cur.as_mut() {
                    u.4 = parse_size(val);
                }
            }
            _ => {}
        }
    }
    if let Some(u) = cur.take() {
        updates.push(u);
    }
    // Second pass: apply to matching bricks.
    for (spec, online, pid, total, free) in updates {
        if let Some(b) = vol.bricks.iter_mut().find(|b| b.spec == spec) {
            b.online = online;
            b.pid = pid;
            if total > 0 {
                b.size_bytes = total;
                b.used_bytes = total.saturating_sub(free);
            }
        }
    }
    // Roll brick sizes up to the volume (distributed total; replicas share, so
    // we sum distinct distribute-subvolumes — best-effort: sum unique sizes by
    // taking the max replica size per N bricks is complex, so report the sum of
    // online bricks divided by replica factor when known).
    // Exclude arbiter bricks: they store only metadata, so their disk total
    // would otherwise inflate the usable-size estimate of a replica+arbiter
    // volume. Sum the data bricks and divide by the replica factor.
    let data_bricks: Vec<&GlusterBrick> = vol.bricks.iter().filter(|b| b.size_bytes > 0 && !b.arbiter).collect();
    if !data_bricks.is_empty() {
        let sum_total: u64 = data_bricks.iter().map(|b| b.size_bytes).sum();
        let sum_used: u64 = data_bricks.iter().map(|b| b.used_bytes).sum();
        let rep = vol.replica_count.max(1) as u64;
        vol.size_bytes = sum_total / rep;
        vol.used_bytes = sum_used / rep;
    }
}

/// Parse a gluster size like "100.0GB" / "1.5TB" / "512MB" into bytes.
fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    let num: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let unit: String = s[num.len()..].trim().to_uppercase();
    let val: f64 = num.parse().unwrap_or(0.0);
    // gluster prints decimal-looking labels (KB/MB/GB/TB) but the values are
    // binary (1024-based); newer builds use the IEC labels (KiB/MiB/GiB/TiB).
    // Both map to the same binary multiplier here.
    let mult = match unit.as_str() {
        "B" | "BYTES" => 1.0,
        "KB" | "KIB" => 1024.0,
        "MB" | "MIB" => 1024.0 * 1024.0,
        "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "TB" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "PB" | "PIB" => 1024.0_f64.powi(5),
        _ => 1.0,
    };
    (val * mult) as u64
}

/// Count entries pending self-heal across a volume's bricks via
/// `gluster volume heal <vol> info`. Only meaningful for replicated/dispersed
/// volumes; on a pure-distribute volume gluster returns an error which we treat
/// as "0 pending".
fn heal_pending_count(volume: &str) -> u64 {
    let out = match gluster(&["volume", "heal", volume, "info"]) {
        Ok(o) => o,
        Err(_) => return 0,
    };
    let mut total = 0u64;
    for line in out.lines() {
        let line = line.trim();
        if let Some(n) = line.strip_prefix("Number of entries:") {
            total += n.trim().parse::<u64>().unwrap_or(0);
        }
    }
    total
}

// ─── Peer management ─────────────────────────────────────────────────

pub fn add_peer(host: &str) -> Result<String, String> {
    let host = host.trim();
    if !valid_host(host) {
        return Err(format!("Invalid peer host '{}'.", host));
    }
    gluster(&["peer", "probe", host])?;
    info!("gluster: probed peer {}", host);
    Ok(format!("Peer {} added to the pool.", host))
}

pub fn remove_peer(host: &str) -> Result<String, String> {
    let host = host.trim();
    if !valid_host(host) {
        return Err(format!("Invalid peer host '{}'.", host));
    }
    gluster(&["peer", "detach", host])?;
    info!("gluster: detached peer {}", host);
    Ok(format!("Peer {} detached from the pool.", host))
}

// ─── Volume management ───────────────────────────────────────────────

/// Create a volume. `vol_type` ∈ {distribute, replicate, disperse}. For
/// replicate `count` is the replica factor; for disperse it's the disperse
/// count (redundancy is derived by gluster). `force` is passed so bricks on a
/// shared/root filesystem are accepted (the common homelab case) — gluster
/// otherwise refuses them.
pub fn create_volume(name: &str, vol_type: &str, count: u32, bricks: &[String]) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err(format!("Invalid volume name '{}' (letters, digits, - and _).", name));
    }
    if bricks.is_empty() {
        return Err("At least one brick is required.".to_string());
    }
    for b in bricks {
        if !valid_brick(b) {
            return Err(format!("Invalid brick '{}' — expected host:/abs/path.", b));
        }
    }
    let mut args: Vec<String> = vec!["volume".into(), "create".into(), name.into()];
    match vol_type {
        "replicate" | "replica" => {
            if count < 2 {
                return Err("Replicate volumes need a replica count of at least 2.".to_string());
            }
            if bricks.len() as u32 % count != 0 {
                return Err(format!(
                    "Brick count ({}) must be a multiple of the replica count ({}).",
                    bricks.len(),
                    count
                ));
            }
            args.push("replica".into());
            args.push(count.to_string());
        }
        "disperse" => {
            args.push("disperse".into());
            args.push(count.to_string());
        }
        "distribute" | "" => {}
        other => return Err(format!("Unknown volume type '{}'.", other)),
    }
    for b in bricks {
        args.push(b.clone());
    }
    args.push("force".into());
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    gluster(&arg_refs)?;
    info!("gluster: created {} volume {} ({} brick(s))", vol_type, name, bricks.len());
    Ok(format!("Volume {} created. Start it to bring it online.", name))
}

pub fn start_volume(name: &str) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    gluster(&["volume", "start", name])?;
    Ok(format!("Volume {} started.", name))
}

pub fn stop_volume(name: &str) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    gluster(&["volume", "stop", name])?;
    Ok(format!("Volume {} stopped.", name))
}

pub fn delete_volume(name: &str) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    // gluster refuses to delete a started volume — stop it first (idempotent;
    // ignore the "already stopped" error).
    let _ = gluster(&["volume", "stop", name]);
    gluster(&["volume", "delete", name])?;
    info!("gluster: deleted volume {}", name);
    Ok(format!("Volume {} deleted.", name))
}

pub fn set_volume_option(name: &str, key: &str, value: &str) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    // Option keys are dotted identifiers (e.g. "performance.cache-size").
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
        return Err(format!("Invalid option key '{}'.", key));
    }
    if value.contains(['\n', ' ']) {
        return Err("Option value must not contain whitespace.".to_string());
    }
    gluster(&["volume", "set", name, key, value])?;
    Ok(format!("Set {} = {} on {}.", key, value, name))
}

/// Add bricks to a volume. When the volume is replicated, gluster requires the
/// number of new bricks to match the replica factor (or a multiple) — we pass
/// the bricks through and let gluster validate, surfacing its message.
pub fn add_brick(name: &str, bricks: &[String]) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    if bricks.is_empty() {
        return Err("At least one brick is required.".to_string());
    }
    for b in bricks {
        if !valid_brick(b) {
            return Err(format!("Invalid brick '{}'.", b));
        }
    }
    let mut args: Vec<String> = vec!["volume".into(), "add-brick".into(), name.into()];
    for b in bricks {
        args.push(b.clone());
    }
    args.push("force".into());
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    gluster(&arg_refs)?;
    Ok(format!("Added {} brick(s) to {}.", bricks.len(), name))
}

/// Remove bricks. Uses `remove-brick ... force` which commits immediately —
/// callers must have confirmed (the UI requires it). For replicated volumes the
/// brick set must respect the replica factor; gluster validates and we surface
/// its error.
pub fn remove_brick(name: &str, bricks: &[String]) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    if bricks.is_empty() {
        return Err("At least one brick is required.".to_string());
    }
    for b in bricks {
        if !valid_brick(b) {
            return Err(format!("Invalid brick '{}'.", b));
        }
    }
    let mut args: Vec<String> = vec!["volume".into(), "remove-brick".into(), name.into()];
    for b in bricks {
        args.push(b.clone());
    }
    args.push("force".into());
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    gluster(&arg_refs)?;
    Ok(format!("Removed {} brick(s) from {}.", bricks.len(), name))
}

/// Trigger a full self-heal on a volume.
pub fn heal_volume(name: &str) -> Result<String, String> {
    if !valid_volume_name(name) {
        return Err("Invalid volume name.".to_string());
    }
    gluster(&["volume", "heal", name, "full"])?;
    Ok(format!("Self-heal triggered on {}.", name))
}

/// List block devices that could host a brick (mounted filesystems + their
/// free space) so the UI can suggest brick paths. Mirrors ceph's device list:
/// returns lsblk JSON. The operator still types the brick directory path.
pub fn available_devices() -> Result<serde_json::Value, String> {
    let out = Command::new("lsblk")
        .args(["-J", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL"])
        .output()
        .map_err(|e| format!("Failed to run lsblk: {}", e))?;
    if !out.status.success() {
        return Err(format!("lsblk failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("lsblk JSON parse error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pool_list() {
        let txt = "UUID\t\t\t\t\tHostname  \tState\n\
                   1a2b3c4d-0000-0000-0000-000000000001\tnode2     \tConnected\n\
                   9f8e7d6c-0000-0000-0000-000000000002\tlocalhost \tConnected\n";
        let peers = parse_peers(txt);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].hostname, "node2");
        assert!(peers[0].connected);
        assert!(!peers[0].is_localhost);
        assert!(peers[1].is_localhost);
    }

    #[test]
    fn parses_volume_info_replicate() {
        let txt = "\nVolume Name: gv0\n\
                   Type: Replicate\n\
                   Volume ID: aaaa-bbbb\n\
                   Status: Started\n\
                   Snapshot Count: 0\n\
                   Number of Bricks: 1 x 2 = 2\n\
                   Transport-type: tcp\n\
                   Bricks:\n\
                   Brick1: node1:/data/brick1/gv0\n\
                   Brick2: node2:/data/brick1/gv0\n\
                   Options Reconfigured:\n\
                   transport.address-family: inet\n\
                   nfs.disable: on\n";
        let vols = parse_volume_info(txt);
        assert_eq!(vols.len(), 1);
        let v = &vols[0];
        assert_eq!(v.name, "gv0");
        assert_eq!(v.vol_type, "Replicate");
        assert!(v.started);
        assert_eq!(v.brick_count, 2);
        assert_eq!(v.replica_count, 2);
        assert_eq!(v.bricks.len(), 2);
        assert_eq!(v.bricks[0].spec, "node1:/data/brick1/gv0");
        assert_eq!(v.bricks[0].host, "node1");
        assert_eq!(v.bricks[0].path, "/data/brick1/gv0");
        assert_eq!(v.options.len(), 2);
        assert_eq!(v.options[1], ("nfs.disable".to_string(), "on".to_string()));
    }

    #[test]
    fn parses_real_arbiter_volume_and_status() {
        // Captured verbatim from a live replica-2 + arbiter pool (gluster 11.1).
        let info = "\nVolume Name: shared\nType: Replicate\nVolume ID: af82836a\n\
                    Status: Started\nSnapshot Count: 0\n\
                    Number of Bricks: 1 x (2 + 1) = 3\nTransport-type: tcp\nBricks:\n\
                    Brick1: 10.0.10.3:/data/glusterfs/shared/brick\n\
                    Brick2: 10.0.10.4:/data/glusterfs/shared/brick\n\
                    Brick3: 10.0.10.2:/data/glusterfs/shared/arbiter (arbiter)\n\
                    Options Reconfigured:\nnfs.disable: on\n";
        let mut vols = parse_volume_info(info);
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].brick_count, 3);
        assert_eq!(vols[0].replica_count, 2, "data-replica from '(2 + 1)'");
        assert_eq!(vols[0].bricks.len(), 3);
        // The " (arbiter)" annotation must be stripped from the spec.
        assert_eq!(vols[0].bricks[2].spec, "10.0.10.2:/data/glusterfs/shared/arbiter");
        assert!(vols[0].bricks[2].arbiter);
        assert!(!vols[0].bricks[0].arbiter);

        // `volume status … detail` prints the brick value WITH a "Brick " prefix.
        let detail = "Status of volume: shared\n\
            ------\n\
            Brick                : Brick 10.0.10.3:/data/glusterfs/shared/brick\n\
            Online               : Y\nPid                  : 2243\n\
            Disk Space Free      : 3.7TB\nTotal Disk Space     : 3.7TB\n\
            ------\n\
            Brick                : Brick 10.0.10.4:/data/glusterfs/shared/brick\n\
            Online               : Y\nPid                  : 2186\n\
            Disk Space Free      : 3.7TB\nTotal Disk Space     : 3.7TB\n\
            ------\n\
            Brick                : Brick 10.0.10.2:/data/glusterfs/shared/arbiter\n\
            Online               : Y\nPid                  : 479059\n\
            Disk Space Free      : 413.1GB\nTotal Disk Space     : 435.8GB\n";
        apply_volume_status(&mut vols[0], detail);
        // Every brick — including the arbiter — must match and come online.
        assert!(vols[0].bricks[0].online && vols[0].bricks[0].pid == "2243");
        assert!(vols[0].bricks[1].online);
        assert!(vols[0].bricks[2].online, "arbiter brick must match after stripping the 'Brick ' prefix");
        assert!(vols[0].bricks[0].size_bytes > 0);
        // Usable size = data bricks (2 × 3.7TB) / replica 2, arbiter excluded.
        assert_eq!(vols[0].size_bytes, parse_size("3.7TB"));
    }

    #[test]
    fn parses_distribute_brick_count() {
        let txt = "Volume Name: dist\nType: Distribute\nStatus: Created\n\
                   Number of Bricks: 3\nTransport-type: tcp\nBricks:\n\
                   Brick1: n1:/b/1\nBrick2: n2:/b/2\nBrick3: n3:/b/3\n";
        let vols = parse_volume_info(txt);
        assert_eq!(vols[0].brick_count, 3);
        assert_eq!(vols[0].replica_count, 0);
        assert!(!vols[0].started);
        assert_eq!(vols[0].bricks.len(), 3);
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("100.0GB"), 100 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512MB"), 512 * 1024 * 1024);
        // IEC labels (newer gluster) + space-separated — same binary value.
        assert_eq!(parse_size("100.0 GiB"), 100 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1.5 TiB"), (1.5 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(parse_size("2KiB"), 2048);
        assert_eq!(parse_size(""), 0);
    }

    #[test]
    fn validates_bricks_and_names() {
        assert!(valid_brick("node1:/data/brick"));
        assert!(!valid_brick("node1:data/brick")); // not absolute
        assert!(!valid_brick("/data/brick")); // no host
        assert!(valid_volume_name("gv0"));
        assert!(!valid_volume_name("bad name"));
        assert!(!valid_volume_name(""));
    }

    #[test]
    fn create_volume_rejects_bad_replica_geometry() {
        // 3 bricks can't form replica-2.
        let bricks = vec![
            "n1:/b/1".to_string(),
            "n2:/b/2".to_string(),
            "n3:/b/3".to_string(),
        ];
        let err = create_volume("gv", "replicate", 2, &bricks).unwrap_err();
        assert!(err.contains("multiple of the replica count"));
    }
}
