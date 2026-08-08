// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfHA — manual high availability for native LXC containers (Phase 1).
//!
//! Model: the container runs on ONE node (the primary). Each chosen
//! replica node holds a stopped copy with the SAME name, MAC, IP and
//! WolfNet marker — on a shared-L2 bridge (vSwitch) the copy can take
//! over the identity wholesale, so DNS never changes and no load
//! balancer is needed. The primary pushes incremental rootfs deltas to
//! every replica on a schedule (manifest diff over the agent HTTP
//! channel — no SSH provisioning). Failover and failback are OPERATOR
//! actions in this phase: promotion is a human decision, so the
//! split-brain class of automatic-failover bugs cannot occur.
//!
//! Replica hygiene rules (the difference between HA and self-inflicted
//! split-brain):
//! - replicas carry a `.wolfha-replica` marker and NEVER have
//!   `lxc.start.auto` — `lxc-autostart` at boot cannot start them;
//! - the PRIMARY's autostart flag is taken over by WolfHA
//!   (`autostart_managed`): stripped from the config and re-applied as
//!   a boot-time start that first asks every replica "did you take
//!   over while I was down?" (see [`boot_guard`]);
//! - after a failover the old primary's copy is marked stale and is
//!   only reused after a reverse sync (failback = promote on the
//!   original node once it has caught up).
//!
//! Phase 1 scope: native LXC on native nodes only (Proxmox-managed
//! containers have LVM/ZFS-backed rootfs that isn't a stable host dir).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

/// Marker file inside the container dir identifying an HA replica.
pub const REPLICA_MARKER: &str = ".wolfha-replica";

fn store_path() -> String {
    format!("{}/wolfha.json", crate::paths::get().config_dir)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaRole {
    Primary,
    Replica,
}

/// A peer node in an HA relationship. The id is authoritative; address
/// and port are the last-known values so replication still works when
/// the cluster registry is briefly missing the node (refreshed from
/// live cluster state whenever resolvable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaPeer {
    pub node_id: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaSyncStatus {
    pub at: u64,
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub files_sent: u64,
    #[serde(default)]
    pub bytes_sent: u64,
}

fn default_failover_after() -> u64 { 90 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaEntry {
    pub container: String,
    pub role: HaRole,
    /// Primary: minutes between delta syncs.
    #[serde(default)]
    pub interval_minutes: u64,
    /// ORDERED replica set — the order IS the failover priority (first =
    /// preferred takeover node). On a primary: its replicas. On a
    /// replica: the full set as told by the primary (via seed/delta
    /// metadata), so each standby can rank itself against its peers.
    #[serde(default)]
    pub replicas: Vec<HaPeer>,
    /// Replica: who currently owns the container.
    #[serde(default)]
    pub primary: Option<HaPeer>,
    /// Primary: WolfHA owns this container's boot because it had
    /// `lxc.start.auto = 1` when HA was enabled (the flag is stripped
    /// so `lxc-autostart` can't race the takeover check).
    #[serde(default)]
    pub autostart_managed: bool,
    /// Primary: per-replica-node-id result of the latest sync.
    #[serde(default)]
    pub last_sync: HashMap<String, HaSyncStatus>,
    /// Replica: when the last delta (or seed) was applied.
    #[serde(default)]
    pub last_delta_at: u64,
    /// This copy is known stale (a replica was promoted while we were
    /// the primary). A stale copy must never start; it becomes a
    /// replica of the new primary and catches up via reverse sync.
    #[serde(default)]
    pub stale: bool,
    /// Phase 2: standbys promote themselves when the primary NODE dies.
    /// Off by default — automatic promotion is opt-in per container.
    #[serde(default)]
    pub auto_failover: bool,
    /// External witness for auto mode — an IP the node must be able to
    /// ping before it may act (fence itself, or promote). The network
    /// gateway is the natural choice: a node that can't reach the
    /// gateway isn't serving anyone anyway. Replaces quorum, so 2-node
    /// clusters work.
    #[serde(default)]
    pub witness: String,
    /// Auto mode: how long the primary must be continuously unreachable
    /// before a standby promotes. The primary self-fences at HALF this
    /// (min 30s), so on a clean partition it is stopped well before any
    /// standby starts.
    #[serde(default = "default_failover_after")]
    pub failover_after_secs: u64,
    /// Primary only: this node's own peer identity. Travels to standbys
    /// inside HaMeta.primary so every delta re-teaches them who the
    /// CURRENT primary is — without it, a standby that survived a
    /// failover keeps watching the old dead primary forever.
    #[serde(default)]
    pub self_identity: Option<HaPeer>,
}

/// The HA settings a primary pushes to its replicas with every seed and
/// delta, so standbys always know the current priority order, witness
/// and timings — setting changes propagate with the next sync round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaMeta {
    pub interval_minutes: u64,
    pub replicas: Vec<HaPeer>,
    pub auto_failover: bool,
    pub witness: String,
    pub failover_after_secs: u64,
    /// The sender — i.e. the CURRENT primary. Standbys re-point their
    /// `primary` at this on every delta, so ownership changes propagate.
    #[serde(default)]
    pub primary: Option<HaPeer>,
}

impl HaMeta {
    pub fn from_entry(e: &HaEntry) -> Self {
        HaMeta {
            interval_minutes: e.interval_minutes,
            replicas: e.replicas.clone(),
            auto_failover: e.auto_failover,
            witness: e.witness.clone(),
            failover_after_secs: e.failover_after_secs,
            primary: e.self_identity.clone(),
        }
    }

    pub fn apply_to(&self, e: &mut HaEntry) {
        e.interval_minutes = self.interval_minutes;
        e.replicas = self.replicas.clone();
        e.auto_failover = self.auto_failover;
        e.witness = self.witness.clone();
        e.failover_after_secs = self.failover_after_secs;
        if e.role == HaRole::Replica
            && let Some(p) = &self.primary
        {
            e.primary = Some(p.clone());
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaStore {
    #[serde(default)]
    pub entries: Vec<HaEntry>,
}

impl HaStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(store_path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = store_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json).map_err(|e| format!("save wolfha store: {}", e))
    }

    pub fn get(&self, container: &str) -> Option<&HaEntry> {
        self.entries.iter().find(|e| e.container == container)
    }

    pub fn get_mut(&mut self, container: &str) -> Option<&mut HaEntry> {
        self.entries.iter_mut().find(|e| e.container == container)
    }

    pub fn remove(&mut self, container: &str) {
        self.entries.retain(|e| e.container != container);
    }
}

// ─── Manifest: the incremental-sync unit ───

/// One filesystem object in a rootfs manifest. Field names are single
/// letters because a container manifest is ~50k-200k entries and this
/// JSON crosses the wire on every sync round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestEntry {
    /// Path relative to the rootfs, e.g. `etc/hostname`.
    pub p: String,
    /// Kind: "f" file, "d" dir, "l" symlink, "o" other (device/fifo/socket).
    pub k: String,
    /// Size in bytes (files only; 0 otherwise).
    #[serde(default)]
    pub s: u64,
    /// mtime, unix seconds.
    #[serde(default)]
    pub m: i64,
    /// Symlink target (symlinks only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t: String,
}

/// Top-level rootfs dirs whose CONTENTS are volatile mount points, not
/// data — same exclusion set the export tar uses.
const SYNC_EXCLUDE_TOP: [&str; 3] = ["proc", "sys", "dev"];

/// Walk a rootfs and build its manifest. Symlinks are never followed.
pub fn build_manifest(rootfs: &str) -> Result<Vec<ManifestEntry>, String> {
    let root = std::path::Path::new(rootfs);
    if !root.is_dir() {
        return Err(format!("rootfs not found: {}", rootfs));
    }
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for de in rd.flatten() {
            let path = de.path();
            let Ok(rel) = path.strip_prefix(root) else { continue };
            let rel_str = rel.to_string_lossy().to_string();
            if rel_str.is_empty() || rel_str.contains('\n') {
                // Newlines can't ride in a NUL-free JSON-diff + tar -T
                // pipeline safely enough to be worth it — skip, they
                // don't occur in real rootfs content.
                continue;
            }
            // Excluded top-level dirs are listed as bare dirs (so they
            // exist on the replica) but never descended into.
            let top = rel_str.split('/').next().unwrap_or("");
            let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
            let ft = md.file_type();
            if ft.is_dir() {
                out.push(ManifestEntry { p: rel_str.clone(), k: "d".into(), s: 0, m: 0, t: String::new() });
                if !(rel.components().count() == 1 && SYNC_EXCLUDE_TOP.contains(&top)) {
                    stack.push(path);
                }
            } else if ft.is_file() {
                use std::os::unix::fs::MetadataExt;
                out.push(ManifestEntry {
                    p: rel_str, k: "f".into(), s: md.len(), m: md.mtime(), t: String::new(),
                });
            } else if ft.is_symlink() {
                let target = std::fs::read_link(&path)
                    .map(|t| t.to_string_lossy().to_string())
                    .unwrap_or_default();
                out.push(ManifestEntry { p: rel_str, k: "l".into(), s: 0, m: 0, t: target });
            } else {
                // Device nodes / fifos / sockets: tracked by presence
                // only. They only exist under /dev in practice (excluded)
                // but a rootfs can technically carry them elsewhere.
                out.push(ManifestEntry { p: rel_str, k: "o".into(), s: 0, m: 0, t: String::new() });
            }
        }
    }
    Ok(out)
}

/// Compare a local (primary) manifest against a remote (replica) one.
/// Returns (paths to ship, paths to delete on the replica). Pure.
///
/// A file is "changed" on size or mtime difference — the same quick
/// check rsync defaults to. Kind changes (file→dir etc.) ship the new
/// object AND delete the old one first so extraction can't collide.
pub fn manifest_diff(
    local: &[ManifestEntry],
    remote: &[ManifestEntry],
) -> (Vec<String>, Vec<String>) {
    let remote_map: HashMap<&str, &ManifestEntry> =
        remote.iter().map(|e| (e.p.as_str(), e)).collect();
    let local_set: std::collections::HashSet<&str> =
        local.iter().map(|e| e.p.as_str()).collect();

    let mut changed = Vec::new();
    let mut deletions = Vec::new();

    for le in local {
        match remote_map.get(le.p.as_str()) {
            None => changed.push(le.p.clone()),
            Some(re) => {
                if re.k != le.k {
                    // Kind flip: clear the old object, ship the new.
                    deletions.push(le.p.clone());
                    changed.push(le.p.clone());
                } else {
                    match le.k.as_str() {
                        "f" if le.s != re.s || le.m != re.m => changed.push(le.p.clone()),
                        "l" if le.t != re.t => changed.push(le.p.clone()),
                        _ => {} // unchanged, or dirs/others where presence is enough
                    }
                }
            }
        }
    }
    for re in remote {
        if !local_set.contains(re.p.as_str()) {
            deletions.push(re.p.clone());
        }
    }
    // Delete children before parents.
    deletions.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
    deletions.dedup();
    (changed, deletions)
}

/// Reject any relative path that could escape the rootfs when joined.
/// Applied to every deletion path a peer sends us and to extraction
/// prep — a compromised or buggy peer must not be able to touch the
/// host outside the replica's rootfs.
pub fn is_safe_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\0')
        && !p.split('/').any(|c| c == ".." || c.is_empty() || c == ".")
}

// ─── tar plumbing ───

/// Args ensuring a rootfs round-trips exactly between hosts: numeric
/// uids (an unprivileged container's shifted ids must not be remapped
/// through /etc/passwd name lookup), xattrs (file capabilities like
/// ping's CAP_NET_RAW) and ACLs.
const TAR_FIDELITY: [&str; 3] = ["--numeric-owner", "--xattrs", "--acls"];

/// Tar a set of rootfs-relative paths (NUL-separated list file) into
/// `archive`. Tolerates files changing mid-read — the source container
/// is running; a torn file is corrected by the next sync round.
fn tar_paths(rootfs: &str, list_file: &str, archive: &str) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["-czf", archive, "-C", rootfs];
    args.extend_from_slice(&TAR_FIDELITY);
    args.extend_from_slice(&[
        "--null", "--no-recursion", "-T", list_file,
        "--warning=no-file-changed", "--warning=no-file-removed", "--ignore-failed-read",
    ]);
    let out = Command::new("tar").args(&args).output()
        .map_err(|e| format!("tar failed to start: {}", e))?;
    // Exit 1 = "file changed as we read it" — expected on a live rootfs.
    match out.status.code() {
        Some(0) | Some(1) => Ok(()),
        _ => Err(format!("tar failed: {}", String::from_utf8_lossy(&out.stderr).trim())),
    }
}

/// Tar an entire live rootfs for the initial replica seed. Same
/// exclusions as lxc_export, plus the fidelity flags above.
pub fn tar_full_rootfs(rootfs: &str, archive: &str) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["-czf", archive, "-C", rootfs];
    args.extend_from_slice(&TAR_FIDELITY);
    args.extend_from_slice(&[
        "--exclude=./proc/*", "--exclude=./sys/*", "--exclude=./dev/*",
        "--warning=no-file-changed", "--warning=no-file-removed", "--ignore-failed-read",
        ".",
    ]);
    let out = Command::new("tar").args(&args).output()
        .map_err(|e| format!("tar failed to start: {}", e))?;
    match out.status.code() {
        Some(0) | Some(1) => Ok(()),
        _ => Err(format!("tar failed: {}", String::from_utf8_lossy(&out.stderr).trim())),
    }
}

/// Extract a delta/seed archive into a replica rootfs with the same
/// fidelity flags used on creation.
pub fn untar_into_rootfs(archive: &str, rootfs: &str) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["-xzf", archive, "-C", rootfs];
    args.extend_from_slice(&TAR_FIDELITY);
    let out = Command::new("tar").args(&args).output()
        .map_err(|e| format!("tar failed to start: {}", e))?;
    if !out.status.success() {
        return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

// ─── Replica-side operations (called from api handlers) ───

pub fn marker_path(container: &str) -> String {
    format!("{}/{}/{}", crate::containers::lxc_base_dir(container), container, REPLICA_MARKER)
}

pub fn is_replica(container: &str) -> bool {
    std::path::Path::new(&marker_path(container)).exists()
}

/// Apply a delta on a replica: extract changed files, then apply
/// deletions (children-first order is the caller's contract, enforced
/// again here by re-sorting). The container must be stopped.
pub fn apply_delta(
    container: &str,
    archive: &str,
    deletions: &[String],
    source_config: &str,
) -> Result<usize, String> {
    let base = crate::containers::lxc_base_dir(container);
    let container_dir = format!("{}/{}", base, container);
    let rootfs = format!("{}/rootfs", container_dir);
    if !std::path::Path::new(&rootfs).is_dir() {
        return Err(format!("replica rootfs missing: {}", rootfs));
    }
    if crate::containers::lxc_is_running(container) {
        return Err(format!("'{}' is running here — refusing to overwrite a live rootfs", container));
    }

    for d in deletions {
        if !is_safe_rel_path(d) {
            return Err(format!("unsafe deletion path rejected: {:?}", d));
        }
    }

    untar_into_rootfs(archive, &rootfs)?;

    let mut sorted: Vec<&String> = deletions.iter().collect();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
    let mut deleted = 0usize;
    for d in sorted {
        let target = format!("{}/{}", rootfs, d);
        let p = std::path::Path::new(&target);
        let Ok(md) = std::fs::symlink_metadata(p) else { continue };
        let res = if md.file_type().is_dir() {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_file(p)
        };
        if res.is_ok() {
            deleted += 1;
        }
    }

    write_replica_config(&container_dir, source_config);
    Ok(deleted)
}

/// Write a replica's LXC config from the primary's: identity keys
/// (uts.name, hwaddr, ipv4) stay EXACTLY as the primary has them —
/// that's the whole point — but rootfs.path is re-pointed at this
/// host's dir and `lxc.start.auto` is stripped so `lxc-autostart` can
/// never boot a standby into a split-brain.
fn write_replica_config(container_dir: &str, source_config: &str) {
    let name = container_dir.rsplit('/').next().unwrap_or("");
    let rewritten: Vec<String> = source_config
        .lines()
        .filter(|l| !l.trim_start().starts_with("lxc.start.auto"))
        .map(|l| {
            if l.trim_start().starts_with("lxc.rootfs.path") {
                format!("lxc.rootfs.path = dir:{}/rootfs", container_dir)
            } else {
                l.to_string()
            }
        })
        .collect();
    let mut out = rewritten.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    let _ = std::fs::write(format!("{}/config", container_dir), out);
    let _ = name; // container name only informs the path; uts.name is preserved
}

/// Refresh a replica's config from the primary's without touching the
/// rootfs — used by metadata-only heartbeats (quiet sync rounds).
pub fn refresh_replica_config(container: &str, source_config: &str) {
    if source_config.trim().is_empty() {
        return;
    }
    let dir = format!("{}/{}", crate::containers::lxc_base_dir(container), container);
    if std::path::Path::new(&dir).exists() {
        write_replica_config(&dir, source_config);
    }
}

/// Drop replica entries that are the same MACHINE under different
/// aliases. Registries know one node by different ids (and a node can
/// be reachable on several addresses — tailscale AND wolfnet, live-seen
/// 2026-08-08), so after a failover cycle a replica set can list the
/// same box twice → doubled delta shipping. Canonicalise through the
/// cluster registry (get_node resolves id aliases via self_id); fall
/// back to the address for nodes the registry doesn't know.
pub fn dedupe_replicas(container: &str, cluster: &crate::agent::ClusterState) {
    let mut store = HaStore::load();
    let Some(entry) = store.get_mut(container) else { return };
    let before = entry.replicas.len();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut kept: Vec<HaPeer> = Vec::new();
    for peer in entry.replicas.drain(..) {
        let key = cluster.get_node(&peer.node_id)
            .map(|n| n.id)
            .unwrap_or_else(|| peer.address.clone());
        if seen.insert(key) {
            kept.push(peer);
        }
    }
    entry.replicas = kept;
    if entry.replicas.len() != before {
        tracing::info!("wolfha: deduped '{}' replica set {} -> {}", container, before, entry.replicas.len());
        let _ = store.save();
    }
}

/// Install a full seed on this node: fresh container dir, extracted
/// rootfs, replica config, marker, optional WolfNet marker. Refuses to
/// clobber a real (non-replica) container of the same name.
pub fn install_seed(
    container: &str,
    archive: &str,
    source_config: &str,
    primary: HaPeer,
    wolfnet_ip: Option<&str>,
    meta: Option<&HaMeta>,
) -> Result<(), String> {
    let base = crate::containers::lxc_base_dir(container);
    let container_dir = format!("{}/{}", base, container);
    if std::path::Path::new(&container_dir).exists() {
        if !is_replica(container) {
            return Err(format!(
                "a container named '{}' already exists on this node and is NOT a WolfHA replica — refusing to overwrite it",
                container
            ));
        }
        // Re-seed of an existing replica: start clean.
        if crate::containers::lxc_is_running(container) {
            return Err(format!("replica '{}' is running here — stop it before re-seeding", container));
        }
        std::fs::remove_dir_all(&container_dir)
            .map_err(|e| format!("could not clear old replica dir: {}", e))?;
    }
    let rootfs = format!("{}/rootfs", container_dir);
    std::fs::create_dir_all(&rootfs).map_err(|e| format!("create replica dir: {}", e))?;

    if let Err(e) = untar_into_rootfs(archive, &rootfs) {
        let _ = std::fs::remove_dir_all(&container_dir);
        return Err(e);
    }
    write_replica_config(&container_dir, source_config);
    std::fs::write(marker_path(container), format!("primary={}\n", primary.node_id))
        .map_err(|e| format!("write replica marker: {}", e))?;
    if let Some(ip) = wolfnet_ip.filter(|s| !s.is_empty()) {
        let wn_dir = format!("{}/.wolfnet", container_dir);
        let _ = std::fs::create_dir_all(&wn_dir);
        let _ = std::fs::write(format!("{}/ip", wn_dir), ip);
    }

    let mut store = HaStore::load();
    store.remove(container);
    let mut entry = HaEntry {
        container: container.to_string(),
        role: HaRole::Replica,
        interval_minutes: 0,
        replicas: Vec::new(),
        primary: Some(primary),
        autostart_managed: false,
        last_sync: HashMap::new(),
        last_delta_at: now_unix(),
        stale: false,
        auto_failover: false,
        witness: String::new(),
        failover_after_secs: default_failover_after(),
        self_identity: None,
    };
    if let Some(m) = meta {
        m.apply_to(&mut entry);
    }
    store.entries.push(entry);
    store.save()
}

/// Promote this node's copy: drop the replica marker, flip the store
/// entry to primary (old primary + other replicas become this entry's
/// replica set, minus this node itself), start the container. The
/// caller has already handled (or accepted the absence of) the old
/// primary. `me` is this node's own peer identity — recorded so every
/// future delta re-teaches the standbys who owns the container now.
pub fn promote_local(container: &str, me: Option<HaPeer>) -> Result<(), String> {
    let mut store = HaStore::load();
    let entry = store
        .get_mut(container)
        .ok_or_else(|| format!("'{}' is not WolfHA-managed on this node", container))?;
    if entry.role == HaRole::Primary && !entry.stale {
        return Err(format!("'{}' is already the active primary here", container));
    }

    let old_primary = entry.primary.take();
    entry.role = HaRole::Primary;
    entry.stale = false;
    entry.last_sync = HashMap::new();
    if let Some(p) = old_primary
        && !entry.replicas.iter().any(|r| r.node_id == p.node_id)
    {
        entry.replicas.push(p);
    }
    // The replica set came from the old primary's meta and includes THIS
    // node — a primary must not list (and sync to) itself. Filter by id
    // AND by address: registries alias the same machine under different
    // ids, so the id check alone provably misses (live test 2026-08-08).
    if let Some(ref me) = me {
        entry.replicas.retain(|r| r.node_id != me.node_id);
    }
    entry.replicas.retain(|r| !peer_is_local(r));
    entry.self_identity = me;
    if entry.interval_minutes == 0 {
        entry.interval_minutes = 5;
    }
    // The promoted copy owns boot from now on, same as any HA primary.
    entry.autostart_managed = true;
    let _ = std::fs::remove_file(marker_path(container));
    store.save()?;

    crate::containers::lxc_start(container).map_err(|e| format!("started promotion but container failed to start: {}", e))?;

    // Same MAC as the old primary, so peers' ARP caches stay valid; the
    // switch learns the new port from the first outbound frame. Nudge
    // that along with a best-effort gateway ping from inside.
    let c = container.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let _ = Command::new("lxc-attach")
            .args(["-n", &c, "--", "sh", "-c",
                   "gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}'); [ -n \"$gw\" ] && ping -c1 -W2 \"$gw\" >/dev/null 2>&1"])
            .output();
    });
    Ok(())
}

/// Demote this node's copy: stop the container if running, mark the
/// copy stale, become a replica of `new_primary`, write the marker.
pub fn demote_local(container: &str, new_primary: HaPeer) -> Result<(), String> {
    if crate::containers::lxc_is_running(container) {
        crate::containers::lxc_stop(container)
            .map_err(|e| format!("could not stop '{}' for demotion: {}", container, e))?;
    }
    let base = crate::containers::lxc_base_dir(container);
    let container_dir = format!("{}/{}", base, container);
    if std::path::Path::new(&container_dir).exists() {
        let _ = std::fs::write(marker_path(container), format!("primary={}\n", new_primary.node_id));
        // A demoted copy must never autostart.
        if let Ok(cfg) = std::fs::read_to_string(format!("{}/config", container_dir)) {
            write_replica_config(&container_dir, &cfg);
        }
    }

    let mut store = HaStore::load();
    match store.get_mut(container) {
        Some(entry) => {
            entry.role = HaRole::Replica;
            entry.stale = true; // until the new primary syncs back over us
            entry.primary = Some(new_primary);
            entry.replicas.clear();
            entry.last_sync.clear();
            entry.self_identity = None;
        }
        None => {
            store.entries.push(HaEntry {
                container: container.to_string(),
                role: HaRole::Replica,
                interval_minutes: 0,
                replicas: Vec::new(),
                primary: Some(new_primary),
                autostart_managed: false,
                last_sync: HashMap::new(),
                last_delta_at: 0,
                stale: true,
                auto_failover: false,
                witness: String::new(),
                failover_after_secs: default_failover_after(),
                self_identity: None,
            });
        }
    }
    store.save()
}

// ─── Primary-side sync engine ───

/// One delta round from this (primary) node to one replica. Returns the
/// status to record. Blocking-free: all fs/tar work goes through
/// spawn_blocking; HTTP through the shared client.
pub async fn sync_one_replica(
    container: &str,
    peer: &HaPeer,
    secret: &str,
) -> HaSyncStatus {
    let started = now_unix();
    match sync_one_replica_inner(container, peer, secret).await {
        Ok((files, bytes)) => HaSyncStatus {
            at: started,
            ok: true,
            message: if files == 0 { "in sync — no changes".to_string() }
                     else { format!("{} files updated", files) },
            files_sent: files,
            bytes_sent: bytes,
        },
        Err(e) => HaSyncStatus {
            at: started,
            ok: false,
            message: e,
            files_sent: 0,
            bytes_sent: 0,
        },
    }
}

async fn sync_one_replica_inner(
    container: &str,
    peer: &HaPeer,
    secret: &str,
) -> Result<(u64, u64), String> {
    let client = &*crate::api::API_HTTP_CLIENT;
    let base = crate::containers::lxc_base_dir(container);
    let rootfs = format!("{}/{}/rootfs", base, container);
    let config_path = format!("{}/{}/config", base, container);

    // 1. Remote manifest.
    let manifest_urls = crate::api::build_node_urls(
        &peer.address, peer.port,
        &format!("/api/wolfha/manifest?container={}", container),
    );
    let mut remote: Option<Vec<ManifestEntry>> = None;
    let mut last_err = String::new();
    for url in &manifest_urls {
        match client.get(url)
            .header("X-WolfStack-Secret", secret.to_string())
            .timeout(std::time::Duration::from_secs(120))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                match r.json::<Vec<ManifestEntry>>().await {
                    Ok(m) => { remote = Some(m); break; }
                    Err(e) => { last_err = format!("bad manifest from {}: {}", url, e); }
                }
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("{}: HTTP {} {}", url, status, body.chars().take(200).collect::<String>());
            }
            Err(e) => { last_err = format!("{}: {}", url, e); }
        }
    }
    let remote = remote.ok_or_else(|| format!("replica manifest unavailable: {}", last_err))?;

    // 2. Local manifest + diff (fs walk off the async runtime).
    let rootfs_c = rootfs.clone();
    let local = tokio::task::spawn_blocking(move || build_manifest(&rootfs_c))
        .await
        .map_err(|e| format!("manifest task: {}", e))??;
    let (changed, deletions) = manifest_diff(&local, &remote);

    // A quiet round still ships a metadata-only heartbeat (no archive):
    // settings changes must reach standbys without waiting for a file to
    // change, and last_delta_at must keep advancing on an IDLE container
    // or the auto-failover freshness gate would wrongly refuse it.
    let archive_bytes: Vec<u8> = if changed.is_empty() && deletions.is_empty() {
        Vec::new()
    } else {
        // 3. Tar the changed paths.
        let stage_dir = "/var/lib/wolfstack/wolfha";
        std::fs::create_dir_all(stage_dir).map_err(|e| format!("staging dir: {}", e))?;
        let uniq = uuid::Uuid::new_v4();
        let list_file = format!("{}/delta-{}.list", stage_dir, uniq);
        let archive = format!("{}/delta-{}.tar.gz", stage_dir, uniq);
        {
            let mut buf: Vec<u8> = Vec::new();
            for p in &changed {
                buf.extend_from_slice(p.as_bytes());
                buf.push(0);
            }
            std::fs::write(&list_file, buf).map_err(|e| format!("write list: {}", e))?;
        }
        let (rootfs_c, list_c, archive_c) = (rootfs.clone(), list_file.clone(), archive.clone());
        let tar_res = tokio::task::spawn_blocking(move || tar_paths(&rootfs_c, &list_c, &archive_c))
            .await
            .map_err(|e| format!("tar task: {}", e));
        let _ = std::fs::remove_file(&list_file);
        tar_res??;
        let bytes = std::fs::read(&archive).map_err(|e| format!("read delta: {}", e))?;
        let _ = std::fs::remove_file(&archive);
        bytes
    };
    let bytes_len = archive_bytes.len() as u64;
    let config = std::fs::read_to_string(&config_path).unwrap_or_default();

    // 4. Ship it — settings metadata rides along so standbys always
    // know the current priority order / witness / timings.
    let ha_meta_json = HaStore::load().get(container)
        .filter(|e| e.role == HaRole::Primary)
        .map(|e| serde_json::to_string(&HaMeta::from_entry(e)).unwrap_or_default())
        .unwrap_or_default();
    let apply_urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/wolfha/apply-delta");
    let deletions_json = serde_json::to_string(&deletions).unwrap_or_else(|_| "[]".to_string());
    let mut last_err = String::new();
    for url in &apply_urls {
        let mut form = reqwest::multipart::Form::new()
            .text("container", container.to_string())
            .text("deletions", deletions_json.clone())
            .text("config", config.clone())
            .text("ha_meta", ha_meta_json.clone());
        if !archive_bytes.is_empty() {
            form = form.part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name("delta.tar.gz"));
        }
        match client.post(url)
            .header("X-WolfStack-Secret", secret.to_string())
            .timeout(std::time::Duration::from_secs(1800))
            .multipart(form)
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                return Ok((changed.len() as u64, bytes_len));
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("{}: HTTP {} {}", url, status, body.chars().take(300).collect::<String>());
            }
            Err(e) => { last_err = format!("{}: {}", url, e); }
        }
    }
    Err(format!("delta upload failed: {}", last_err))
}

/// Run a sync round for one primary entry: every replica, sequentially
/// (replicas share the primary's disk bandwidth; parallel rounds
/// double-read the rootfs for no wall-clock win on spinning disks).
/// Records per-replica status in the store.
pub async fn sync_container_now(container: &str) -> Result<(), String> {
    let store = HaStore::load();
    let entry = store.get(container)
        .ok_or_else(|| format!("'{}' is not WolfHA-managed here", container))?;
    if entry.role != HaRole::Primary {
        return Err(format!("'{}' is a replica on this node — syncs run on the primary", container));
    }
    if entry.stale {
        return Err(format!("'{}' is stale here (a replica was promoted) — it receives syncs now, it doesn't send them", container));
    }
    let peers = entry.replicas.clone();
    let secret = crate::auth::load_cluster_secret();

    for peer in &peers {
        // Defensive: never sync to ourselves — an aliased self-entry can
        // survive in stored replica lists from before the promote filter.
        if peer_is_local(peer) {
            tracing::debug!("wolfha: skipping self-aliased replica entry {} for '{}'", peer.node_id, container);
            continue;
        }
        let status = sync_one_replica(container, peer, &secret).await;
        let mut store = HaStore::load();
        let previous_ok = store.get(container)
            .and_then(|e| e.last_sync.get(&peer.node_id))
            .map(|s| s.ok);
        if let Some(e) = store.get_mut(container) {
            e.last_sync.insert(peer.node_id.clone(), status.clone());
            let _ = store.save();
        }
        if !status.ok {
            tracing::warn!("wolfha: sync of '{}' to {} failed: {}", container, peer.node_id, status.message);
        }
        // Alert on the TRANSITION, not every round: a replica that stops
        // receiving deltas is silently ageing your failover point — the
        // operator must hear about it once, and again when it heals.
        match (previous_ok, status.ok) {
            (Some(true), false) | (None, false) => {
                crate::alerting::send_local_alert(
                    crate::alerting::AlertCategory::Lifecycle,
                    &format!("WolfHA replica of '{}' is falling behind", container),
                    &format!(
                        "Delta sync to node {} failed: {}. The standby keeps its last good state — a failover to it loses everything since then. Fix the replica and use Sync now on the WolfHA page.",
                        peer.node_id, status.message
                    ),
                ).await;
            }
            (Some(false), true) => {
                crate::alerting::send_local_alert(
                    crate::alerting::AlertCategory::Lifecycle,
                    &format!("WolfHA replica of '{}' recovered", container),
                    &format!("Delta sync to node {} is working again ({}).", peer.node_id, status.message),
                ).await;
            }
            _ => {}
        }
    }
    Ok(())
}

// ─── Scheduler + boot guard (spawned from main.rs) ───

/// In-flight guard so a slow sync round and the scheduler can't overlap
/// on the same container.
static SYNC_IN_FLIGHT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

pub fn try_begin_sync(container: &str) -> bool {
    SYNC_IN_FLIGHT.lock().map(|mut s| s.insert(container.to_string())).unwrap_or(false)
}

pub fn end_sync(container: &str) {
    if let Ok(mut s) = SYNC_IN_FLIGHT.lock() {
        s.remove(container);
    }
}

/// Periodic replication driver: every minute, start a sync round for
/// each primary entry whose oldest replica status is older than its
/// interval. Runs forever; spawned once at startup.
pub async fn scheduler_forever() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let store = HaStore::load();
        let now = now_unix();
        for entry in &store.entries {
            if entry.role != HaRole::Primary || entry.stale {
                continue;
            }
            let interval_secs = entry.interval_minutes.max(1) * 60;
            let oldest = entry.replicas.iter()
                .map(|r| entry.last_sync.get(&r.node_id).map(|s| s.at).unwrap_or(0))
                .min()
                .unwrap_or(0);
            if now.saturating_sub(oldest) < interval_secs {
                continue;
            }
            let container = entry.container.clone();
            if !try_begin_sync(&container) {
                continue;
            }
            tokio::spawn(async move {
                if let Err(e) = sync_container_now(&container).await {
                    tracing::warn!("wolfha: scheduled sync of '{}': {}", container, e);
                }
                end_sync(&container);
            });
        }
    }
}

/// Boot-time start of WolfHA-managed primaries. `lxc-autostart` never
/// sees them (their `lxc.start.auto` was stripped when HA was enabled),
/// so a rebooted primary first asks every replica "did you take over
/// while I was down?" before starting anything.
///
/// If a replica reports the container ACTIVE, this copy demotes itself
/// (stale replica of the active node) instead of starting — that's the
/// post-failover recovery path. If replicas are unreachable, we start
/// anyway: in the manual-failover phase an unreachable replica most
/// likely simply isn't running the container, and refusing to start
/// would turn every full-cluster power cycle into an outage. This is
/// the documented split-brain window of Phase 1 (the operator performed
/// the failover by hand, so they know which copy is live).
pub async fn boot_guard() {
    // Same gate lxc_autostart_all uses: this must run after a MACHINE
    // boot, never after a mere wolfstack service restart — an HA primary
    // the operator deliberately stopped must stay stopped.
    if !crate::containers::host_recently_booted() {
        return;
    }
    let store = HaStore::load();
    let secret = crate::auth::load_cluster_secret();
    let client = &*crate::api::API_HTTP_CLIENT;

    for entry in &store.entries {
        if entry.role != HaRole::Primary || entry.stale || !entry.autostart_managed {
            continue;
        }
        let container = entry.container.clone();
        if crate::containers::lxc_is_running(&container) {
            continue;
        }

        let mut taken_over_by: Option<HaPeer> = None;
        for peer in &entry.replicas {
            let urls = crate::api::build_node_urls(
                &peer.address, peer.port,
                &format!("/api/wolfha/status?container={}", container),
            );
            for url in &urls {
                match client.get(url)
                    .header("X-WolfStack-Secret", secret.clone())
                    .timeout(std::time::Duration::from_secs(10))
                    .send().await
                {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(v) = r.json::<serde_json::Value>().await {
                            let active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                            let role_primary = v.get("role").and_then(|s| s.as_str()) == Some("primary");
                            if active || role_primary {
                                taken_over_by = Some(peer.clone());
                            }
                        }
                        break;
                    }
                    Ok(r) => { let _ = r.bytes().await; }
                    Err(_) => {}
                }
            }
            if taken_over_by.is_some() {
                break;
            }
        }

        match taken_over_by {
            Some(peer) => {
                tracing::warn!(
                    "wolfha: '{}' was taken over by node {} while this node was down — local copy demoted to stale replica, NOT started",
                    container, peer.node_id
                );
                if let Err(e) = demote_local(&container, peer) {
                    tracing::warn!("wolfha: demotion of '{}' failed: {}", container, e);
                }
            }
            None => {
                match crate::containers::lxc_start(&container) {
                    Ok(_) => tracing::info!("wolfha: started HA primary '{}' at boot", container),
                    Err(e) => tracing::warn!("wolfha: boot start of HA primary '{}' failed: {}", container, e),
                }
            }
        }
    }
}

// ─── Phase 2: automatic failover ───
//
// Design (Paul, 2026-08-08): NO quorum — 2-node clusters must work.
// Instead, three independent gates replace it:
//
// 1. WITNESS — a node may only ACT (fence itself, or promote) while it
//    can ping the configured witness IP (normally the gateway). A
//    partitioned node fails the ping and does nothing.
// 2. PRIORITY — the ordered replica list is the succession order. A
//    standby defers to any healthier standby listed before it.
// 3. THE BRIDGE ITSELF — before promoting, a standby pings the
//    container's own IP on the shared L2. If ANYTHING answers, the
//    container is alive somewhere and promotion aborts. On a shared
//    vSwitch the resource is its own lock.
//
// Timing contract: the primary self-fences after failover_after/2 (min
// 30s) of witness loss; standbys promote only after the FULL
// failover_after of primary unreachability — so on a clean partition
// the incumbent is stopped well before any standby starts.

/// Sustained-failure clocks, keyed "kind:container". Instant-based —
/// wall-clock jumps must not fake a timeout.
static FAIL_SINCE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn fail_elapsed(key: &str, failing: bool) -> u64 {
    let mut map = FAIL_SINCE.lock().unwrap();
    if !failing {
        map.remove(key);
        return 0;
    }
    let start = *map.entry(key.to_string()).or_insert_with(std::time::Instant::now);
    start.elapsed().as_secs()
}

/// One-shot alert latch so a persisting condition alerts once, not
/// every 15s cycle. Cleared when the condition clears.
static ALERT_LATCH: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

async fn alert_once(key: &str, title: &str, body: &str) {
    let fresh = ALERT_LATCH.lock().map(|mut s| s.insert(key.to_string())).unwrap_or(false);
    if fresh {
        crate::alerting::send_local_alert(crate::alerting::AlertCategory::Lifecycle, title, body).await;
    }
}

fn alert_clear(key: &str) {
    if let Ok(mut s) = ALERT_LATCH.lock() {
        s.remove(key);
    }
}

/// Can this node reach `host` right now? One packet, 2s ceiling.
fn ping_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    Command::new("ping").args(["-c", "1", "-W", "2", "-n", host]).output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The container's static IPv4 from its LXC config (CIDR stripped) —
/// the address the L2-aliveness probe pings before a promotion.
fn container_static_ip(container: &str) -> Option<String> {
    let path = format!("{}/{}/config", crate::containers::lxc_base_dir(container), container);
    let cfg = std::fs::read_to_string(path).ok()?;
    cfg.lines()
        .find(|l| l.trim().starts_with("lxc.net.0.ipv4.address"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().split('/').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

fn fence_secs(failover_after: u64) -> u64 {
    (failover_after / 2).max(30)
}

/// Is this peer actually THIS machine? Node ids alias across registries
/// (each node's registry may know the same machine under a different
/// id — live-tested 2026-08-08: a promoted standby's replica list
/// contained itself under the OLD primary's alias for it), so id
/// comparison is not enough. Addresses don't lie: compare against every
/// IP configured on this host.
pub fn peer_is_local(peer: &HaPeer) -> bool {
    let out = match Command::new("ip").args(["-j", "-o", "addr"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) else { return false };
    let Some(ifaces) = v.as_array() else { return false };
    for iface in ifaces {
        let Some(infos) = iface.get("addr_info").and_then(|a| a.as_array()) else { continue };
        for info in infos {
            if info.get("local").and_then(|l| l.as_str()) == Some(peer.address.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Ask a peer for its /api/wolfha/status of one container.
/// Ok(json) when ANY of its urls answered; Err when none did.
async fn peer_status(peer: &HaPeer, container: &str, secret: &str) -> Result<serde_json::Value, ()> {
    let client = &*crate::api::API_HTTP_CLIENT;
    let urls = crate::api::build_node_urls(
        &peer.address, peer.port,
        &format!("/api/wolfha/status?container={}", container),
    );
    for url in &urls {
        match client.get(url)
            .header("X-WolfStack-Secret", secret.to_string())
            .timeout(std::time::Duration::from_secs(5))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    return Ok(v);
                }
                return Err(());
            }
            Ok(r) => { let _ = r.bytes().await; }
            Err(_) => {}
        }
    }
    Err(())
}

/// The auto-failover monitor: every 15s, walk this node's HA entries
/// and apply the state machine. Spawned once at startup.
pub async fn failover_monitor_forever(cluster: std::sync::Arc<crate::agent::ClusterState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let store = HaStore::load();
        let secret = crate::auth::load_cluster_secret();
        let me: Option<HaPeer> = cluster.get_all_nodes().into_iter().find(|n| n.is_self)
            .and_then(|n| {
                // The registry self-entry often carries the LISTEN address
                // (0.0.0.0) — substitute our WolfNet IP so the identity we
                // hand out is actually callable by peers.
                let unusable = n.address.is_empty() || n.address == "0.0.0.0" || n.address.starts_with("127.");
                let address = if unusable {
                    crate::networking::detect_wolfnet_gateway_ip()?
                } else {
                    n.address
                };
                Some(HaPeer { node_id: n.id, address, port: n.port })
            });
        let my_id = me.as_ref().map(|p| p.node_id.clone());

        for entry in &store.entries {
            let c = entry.container.clone();
            match (entry.role, entry.stale) {
                // ── Active primary: self-fence when the witness vanishes ──
                (HaRole::Primary, false) => {
                    // Heal alias-duplicated replica sets left by earlier
                    // failover cycles (no-op when already clean).
                    dedupe_replicas(&c, &cluster);
                    let running = {
                        let cc = c.clone();
                        tokio::task::spawn_blocking(move || crate::containers::lxc_is_running(&cc))
                            .await.unwrap_or(false)
                    };
                    if !running {
                        // The container isn't running here. Usually that's
                        // an operator stop (not our business) — but it is
                        // also what a returned primary looks like after a
                        // standby promoted while this node was down WITHOUT
                        // a machine reboot (service restart / crash), which
                        // the boot guard never sees. If a peer is actively
                        // running the container, converge: become its
                        // replica instead of sitting here as a second
                        // "primary" whose syncs the real one refuses.
                        let mut active_peer: Option<HaPeer> = None;
                        for peer in &entry.replicas {
                            if let Ok(v) = peer_status(peer, &c, &secret).await {
                                let p_active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                                let p_role = v.get("role").and_then(|s| s.as_str()).unwrap_or("");
                                if p_active && p_role == "primary" {
                                    active_peer = Some(peer.clone());
                                    break;
                                }
                            }
                        }
                        if let Some(peer) = active_peer {
                            tracing::warn!("wolfha: '{}' is actively primary on {} — this returned copy demotes to replica", c, peer.node_id);
                            let cc = c.clone();
                            let _ = tokio::task::spawn_blocking(move || demote_local(&cc, peer.clone())).await;
                            alert_once(&format!("superseded:{}", c),
                                &format!("WolfHA '{}' was taken over while this node was away", c),
                                "The local copy was demoted to a stale replica of the new primary and will catch up automatically.").await;
                        }
                        fail_elapsed(&format!("witness:{}", c), false);
                        continue;
                    }
                    if !entry.auto_failover || entry.witness.is_empty() {
                        continue;
                    }
                    let witness = entry.witness.clone();
                    let ok = tokio::task::spawn_blocking(move || ping_host(&witness))
                        .await.unwrap_or(false);
                    let elapsed = fail_elapsed(&format!("witness:{}", c), !ok);
                    if ok {
                        alert_clear(&format!("witnessdown:{}", c));
                        continue;
                    }
                    if elapsed >= fence_secs(entry.failover_after_secs) {
                        // Witness gone — but fencing is only right when this
                        // node is truly ISOLATED. If any replica still
                        // answers, the network is alive and the witness
                        // itself died: stay up (the standbys can't promote
                        // either — their witness gate fails the same way).
                        let mut any_replica_reachable = false;
                        for peer in &entry.replicas {
                            if peer_status(peer, &c, &secret).await.is_ok() {
                                any_replica_reachable = true;
                                break;
                            }
                        }
                        if any_replica_reachable {
                            alert_once(&format!("witnessdown:{}", c),
                                &format!("WolfHA witness for '{}' is down", c),
                                &format!("The witness ({}) has been unreachable for {}s but the replica nodes still answer — the witness itself has failed, not this node. '{}' keeps running; automatic failover is effectively suspended until the witness returns.", entry.witness, elapsed, c)).await;
                            continue;
                        }
                        alert_clear(&format!("witnessdown:{}", c));
                        tracing::warn!("wolfha: witness {} unreachable {}s and no replica answers — SELF-FENCING '{}'", entry.witness, elapsed, c);
                        let cc = c.clone();
                        let _ = tokio::task::spawn_blocking(move || crate::containers::lxc_stop(&cc)).await;
                        let mut s = HaStore::load();
                        if let Some(e) = s.get_mut(&c) {
                            e.stale = true;
                            let _ = s.save();
                        }
                        fail_elapsed(&format!("witness:{}", c), false);
                        alert_once(&format!("fenced:{}", c),
                            &format!("WolfHA self-fenced '{}'", c),
                            &format!("This node lost its witness ({}) for {}s and stopped '{}' so a standby can take over safely. It rejoins as a replica automatically when connectivity returns.", entry.witness, elapsed, c)).await;
                    }
                }

                // ── Fenced / superseded primary: reconcile ──
                (HaRole::Primary, true) => {
                    let witness_ok = if entry.witness.is_empty() {
                        true
                    } else {
                        let w = entry.witness.clone();
                        tokio::task::spawn_blocking(move || ping_host(&w)).await.unwrap_or(false)
                    };
                    if !witness_ok {
                        continue;
                    }
                    let mut taken_over: Option<HaPeer> = None;
                    let mut all_reachable = true;
                    for peer in &entry.replicas {
                        match peer_status(peer, &c, &secret).await {
                            Ok(v) => {
                                let active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                                let their_role = v.get("role").and_then(|s| s.as_str()).unwrap_or("");
                                if active || their_role == "primary" {
                                    taken_over = Some(peer.clone());
                                    break;
                                }
                            }
                            Err(()) => { all_reachable = false; }
                        }
                    }
                    match taken_over {
                        Some(peer) => {
                            tracing::info!("wolfha: '{}' active on {} — this fenced copy becomes its replica", c, peer.node_id);
                            let cc = c.clone();
                            let _ = tokio::task::spawn_blocking(move || demote_local(&cc, peer)).await;
                            alert_clear(&format!("fenced:{}", c));
                        }
                        None if all_reachable && entry.auto_failover => {
                            // Nobody took over (they deferred, or the outage
                            // was shorter than their window) — the incumbent
                            // resumes.
                            tracing::info!("wolfha: no standby took over '{}' — resuming as primary", c);
                            let mut s = HaStore::load();
                            if let Some(e) = s.get_mut(&c) {
                                e.stale = false;
                                let _ = s.save();
                            }
                            let cc = c.clone();
                            let _ = tokio::task::spawn_blocking(move || crate::containers::lxc_start(&cc)).await;
                            alert_clear(&format!("fenced:{}", c));
                            alert_once(&format!("resumed:{}", c),
                                &format!("WolfHA '{}' resumed on its primary", c),
                                "Connectivity returned before any standby promoted — the container was restarted in place.").await;
                        }
                        None => {} // some standby unreachable — keep waiting
                    }
                }

                // ── Standby: watch the primary, promote through the gates ──
                (HaRole::Replica, false) => {
                    let Some(primary) = entry.primary.clone() else { continue };
                    let running_here = {
                        let cc = c.clone();
                        tokio::task::spawn_blocking(move || crate::containers::lxc_is_running(&cc))
                            .await.unwrap_or(false)
                    };
                    let pstat = peer_status(&primary, &c, &secret).await;

                    // Active-active self-heal: a standby that is somehow
                    // running while the primary also runs is a duplicate —
                    // the incumbent wins, this copy stops.
                    if running_here {
                        if let Ok(v) = &pstat {
                            let p_active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                            if p_active {
                                tracing::warn!("wolfha: BOTH '{}' copies running — stopping the standby copy", c);
                                let cc = c.clone();
                                let _ = tokio::task::spawn_blocking(move || crate::containers::lxc_stop(&cc)).await;
                                alert_once(&format!("dup:{}", c),
                                    &format!("WolfHA duplicate '{}' stopped", c),
                                    &format!("This standby was running at the same time as the primary on {} — the standby copy was stopped and stays a replica. Check how it was started.", primary.node_id)).await;
                            }
                        }
                        continue;
                    }
                    alert_clear(&format!("dup:{}", c));

                    if !entry.auto_failover {
                        continue;
                    }
                    let elapsed = fail_elapsed(&format!("primary:{}", c), pstat.is_err());
                    if pstat.is_ok() {
                        alert_clear(&format!("asym:{}", c));
                        alert_clear(&format!("toostale:{}", c));
                        continue;
                    }
                    if elapsed < entry.failover_after_secs {
                        continue;
                    }

                    // GATE 1 — witness: an isolated node must not act.
                    let witness_ok = if entry.witness.is_empty() {
                        false // auto mode without a witness never promotes
                    } else {
                        let w = entry.witness.clone();
                        tokio::task::spawn_blocking(move || ping_host(&w)).await.unwrap_or(false)
                    };
                    if !witness_ok {
                        tracing::warn!("wolfha: primary of '{}' unreachable {}s but witness is too — this node is the isolated one, holding", c, elapsed);
                        continue;
                    }

                    // GATE 2 — the cluster's aggregated view: if gossip says
                    // the primary node is alive, only MY path to it is broken.
                    //
                    // get_node() returns the STORED online flag, which can
                    // stay true long after a node dies — only get_all_nodes()
                    // recomputes it from last_seen (agent/mod.rs). Recompute
                    // here the same way (fresh within 60s = alive); trusting
                    // the stored flag blocked auto-failover for 30+ minutes
                    // in the 2026-08-08 live test.
                    if let Some(n) = cluster.get_node(&primary.node_id)
                        && n.online
                        && now_unix().saturating_sub(n.last_seen) < 60
                    {
                        alert_once(&format!("asym:{}", c),
                            &format!("WolfHA cannot verify primary of '{}'", c),
                            &format!("This standby cannot reach the primary node {} for '{}', but the cluster still sees that node online — refusing to promote over a one-sided network problem. Check routing between the two nodes.", primary.node_id, c)).await;
                        continue;
                    }

                    // GATE 3 — priority: defer to a healthier standby listed
                    // before me in the succession order.
                    let mut defer = false;
                    if let Some(my_id) = &my_id {
                        for peer in &entry.replicas {
                            // Alias-safe self match: id OR local address.
                            if &peer.node_id == my_id || peer_is_local(peer) {
                                break; // everyone before me has been checked
                            }
                            if peer.node_id == primary.node_id {
                                continue;
                            }
                            if let Ok(v) = peer_status(peer, &c, &secret).await {
                                let their_role = v.get("role").and_then(|s| s.as_str()).unwrap_or("");
                                let their_stale = v.get("stale").and_then(|s| s.as_bool()).unwrap_or(false);
                                if their_role == "primary" || (their_role == "replica" && !their_stale) {
                                    defer = true; // a healthier, higher-priority copy exists
                                    break;
                                }
                            }
                        }
                    }
                    if defer {
                        continue;
                    }

                    // GATE 4 — freshness: never auto-promote an ancient copy.
                    let max_age = (entry.interval_minutes.max(1) * 60 * 6).max(1800);
                    let age = now_unix().saturating_sub(entry.last_delta_at);
                    if age > max_age {
                        alert_once(&format!("toostale:{}", c),
                            &format!("WolfHA cannot auto-fail-over '{}'", c),
                            &format!("The primary looks dead but this standby's copy is {}m old (limit {}m) — replication had been failing. Promote manually from the WolfHA page if this state is acceptable.", age / 60, max_age / 60)).await;
                        continue;
                    }

                    // GATE 5 — the bridge itself: if the container's IP
                    // answers, it is alive SOMEWHERE. Abort.
                    if let Some(ip) = container_static_ip(&c) {
                        let alive = tokio::task::spawn_blocking(move || ping_host(&ip)).await.unwrap_or(false);
                        if alive {
                            tracing::warn!("wolfha: '{}' answers on the bridge — its node is unreachable but the container is alive; NOT promoting", c);
                            continue;
                        }
                    }

                    // All gates passed — take over.
                    tracing::warn!("wolfha: AUTO-FAILOVER of '{}' — primary {} unreachable {}s, all gates passed", c, primary.node_id, elapsed);
                    let cc = c.clone();
                    let me_c = me.clone();
                    let res = tokio::task::spawn_blocking(move || promote_local(&cc, me_c)).await;
                    fail_elapsed(&format!("primary:{}", c), false);
                    match res {
                        Ok(Ok(())) => {
                            crate::alerting::send_local_alert(
                                crate::alerting::AlertCategory::Lifecycle,
                                &format!("WolfHA auto-failover: '{}' promoted", c),
                                &format!("Primary node {} was unreachable for {}s. '{}' is now running on this node with the state of its last sync ({}m old). The old node rejoins as a stale replica when it returns.", primary.node_id, elapsed, c, age / 60),
                            ).await;
                        }
                        other => {
                            let err = match other {
                                Ok(Err(e)) => e,
                                Err(e) => e.to_string(),
                                Ok(Ok(())) => unreachable!(),
                            };
                            crate::alerting::send_local_alert(
                                crate::alerting::AlertCategory::Lifecycle,
                                &format!("WolfHA auto-failover of '{}' FAILED", c),
                                &format!("All gates passed but promotion failed: {}. Intervene manually on the WolfHA page.", err),
                            ).await;
                        }
                    }
                }

                // ── Stale replica: deltas from the active node heal it ──
                (HaRole::Replica, true) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(p: &str, s: u64, m: i64) -> ManifestEntry {
        ManifestEntry { p: p.into(), k: "f".into(), s, m, t: String::new() }
    }
    fn d(p: &str) -> ManifestEntry {
        ManifestEntry { p: p.into(), k: "d".into(), s: 0, m: 0, t: String::new() }
    }
    fn l(p: &str, t: &str) -> ManifestEntry {
        ManifestEntry { p: p.into(), k: "l".into(), s: 0, m: 0, t: t.into() }
    }

    #[test]
    fn diff_ships_new_changed_and_retargeted_symlinks_only() {
        let local = vec![
            d("etc"),
            f("etc/hostname", 8, 100),
            f("etc/hosts", 20, 100),
            f("var/log/app.log", 900, 555),
            l("etc/localtime", "/usr/share/zoneinfo/Europe/London"),
        ];
        let remote = vec![
            d("etc"),
            f("etc/hostname", 8, 100),          // identical — not shipped
            f("etc/hosts", 20, 90),             // mtime differs — shipped
            l("etc/localtime", "/usr/share/zoneinfo/UTC"), // target differs — shipped
        ];
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert_eq!(changed, vec!["etc/hosts", "var/log/app.log", "etc/localtime"]);
        assert!(deletions.is_empty());
    }

    #[test]
    fn diff_deletes_children_before_parents() {
        let local = vec![d("etc")];
        let remote = vec![
            d("etc"),
            d("opt"),
            d("opt/app"),
            f("opt/app/bin", 10, 1),
        ];
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert!(changed.is_empty());
        assert_eq!(deletions, vec!["opt/app/bin", "opt/app", "opt"]);
    }

    #[test]
    fn kind_flip_deletes_then_ships() {
        let local = vec![f("srv/data", 5, 1)];
        let remote = vec![d("srv/data")];
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert_eq!(changed, vec!["srv/data"]);
        assert_eq!(deletions, vec!["srv/data"]);
    }

    #[test]
    fn unsafe_rel_paths_are_rejected() {
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a/./b", "a\0b"] {
            assert!(!is_safe_rel_path(bad), "{:?} should be rejected", bad);
        }
        for good in ["etc/hostname", "var/log/app.log", "usr/share/x-y_z.1"] {
            assert!(is_safe_rel_path(good), "{:?} should be accepted", good);
        }
    }

    #[test]
    fn identical_manifests_are_a_noop() {
        let m = vec![d("etc"), f("etc/hostname", 8, 100)];
        let (changed, deletions) = manifest_diff(&m, &m.clone());
        assert!(changed.is_empty() && deletions.is_empty());
    }

    /// Full engine round-trip on a REAL filesystem with the REAL tar
    /// binary: seed a "replica" from a live "primary" rootfs, mutate the
    /// primary (edit / add / delete / retarget symlink), run one delta
    /// round exactly the way sync + apply do, and prove the replica is
    /// byte-identical afterwards. This is the closest a unit test gets
    /// to the wire path without a second node.
    #[test]
    fn seed_plus_delta_round_trip_converges_on_disk() {
        let base = std::env::temp_dir().join(format!("wolfha-test-{}", uuid::Uuid::new_v4()));
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(src.join("etc")).unwrap();
        std::fs::create_dir_all(src.join("var/log")).unwrap();
        std::fs::create_dir_all(src.join("proc")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("etc/hostname"), "legolas\n").unwrap();
        std::fs::write(src.join("etc/keepme.conf"), "stay\n").unwrap();
        std::fs::write(src.join("var/log/app.log"), "line1\n").unwrap();
        std::fs::write(src.join("var/log/old.log"), "obsolete\n").unwrap();
        // Contents of excluded top-level dirs must never travel.
        std::fs::write(src.join("proc/should-not-copy"), "x").unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/Europe/London", src.join("etc/localtime")).unwrap();

        // Seed.
        let seed = base.join("seed.tar.gz");
        tar_full_rootfs(src.to_str().unwrap(), seed.to_str().unwrap()).unwrap();
        untar_into_rootfs(seed.to_str().unwrap(), dst.to_str().unwrap()).unwrap();
        assert!(dst.join("etc/hostname").exists());
        assert!(!dst.join("proc/should-not-copy").exists(), "excluded dir contents leaked into the seed");

        // Mutate the primary. Content changes also change SIZE so the
        // size+mtime quick-check can't be defeated by same-second writes.
        std::fs::write(src.join("var/log/app.log"), "line1\nline2 appended\n").unwrap();
        std::fs::write(src.join("etc/new-file.conf"), "brand new\n").unwrap();
        std::fs::remove_file(src.join("var/log/old.log")).unwrap();
        std::fs::remove_file(src.join("etc/localtime")).unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", src.join("etc/localtime")).unwrap();

        // One delta round, exactly as sync_one_replica_inner + apply_delta do it.
        let local = build_manifest(src.to_str().unwrap()).unwrap();
        let remote = build_manifest(dst.to_str().unwrap()).unwrap();
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert!(changed.iter().any(|p| p == "var/log/app.log"));
        assert!(changed.iter().any(|p| p == "etc/new-file.conf"));
        assert!(changed.iter().any(|p| p == "etc/localtime"));
        assert!(deletions.iter().any(|p| p == "var/log/old.log"));
        assert!(!changed.iter().any(|p| p == "etc/keepme.conf"), "unchanged file shipped");

        let list = base.join("delta.list");
        let mut buf: Vec<u8> = Vec::new();
        for p in &changed {
            buf.extend_from_slice(p.as_bytes());
            buf.push(0);
        }
        std::fs::write(&list, buf).unwrap();
        let delta = base.join("delta.tar.gz");
        tar_paths(src.to_str().unwrap(), list.to_str().unwrap(), delta.to_str().unwrap()).unwrap();
        untar_into_rootfs(delta.to_str().unwrap(), dst.to_str().unwrap()).unwrap();
        let mut sorted: Vec<&String> = deletions.iter().collect();
        sorted.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
        for d in sorted {
            let t = dst.join(d);
            if let Ok(md) = std::fs::symlink_metadata(&t) {
                if md.file_type().is_dir() { let _ = std::fs::remove_dir_all(&t); }
                else { let _ = std::fs::remove_file(&t); }
            }
        }

        // Converged: manifests identical, content identical, symlink retargeted.
        let mut after_src = build_manifest(src.to_str().unwrap()).unwrap();
        let mut after_dst = build_manifest(dst.to_str().unwrap()).unwrap();
        after_src.sort_by(|a, b| a.p.cmp(&b.p));
        after_dst.sort_by(|a, b| a.p.cmp(&b.p));
        assert_eq!(after_src, after_dst, "replica did not converge to the primary");
        assert_eq!(std::fs::read_to_string(dst.join("var/log/app.log")).unwrap(), "line1\nline2 appended\n");
        assert_eq!(std::fs::read_to_string(dst.join("etc/new-file.conf")).unwrap(), "brand new\n");
        assert_eq!(std::fs::read_link(dst.join("etc/localtime")).unwrap().to_string_lossy(), "/usr/share/zoneinfo/UTC");
        assert!(!dst.join("var/log/old.log").exists());
        let (c2, d2) = manifest_diff(&after_src, &after_dst);
        assert!(c2.is_empty() && d2.is_empty(), "second diff should be a no-op");

        let _ = std::fs::remove_dir_all(&base);
    }
}
