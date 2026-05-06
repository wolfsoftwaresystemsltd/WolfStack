// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfRouter — native router/firewall/DHCP/DNS module.
//!
//! Replaces the OPNsense-in-a-VM pattern with a host-native stack built
//! on iptables (filter table for stateful rules, already-wired `nat`
//! table for DNAT/SNAT) plus dnsmasq (per-LAN DHCP + DNS).
//!
//! Three user-visible concepts:
//!   • **Zone** — named policy group (`Wan`, `Lan(N)`, `Dmz`, `Wolfnet`,
//!     `Trusted`, `Custom`). Every interface/bridge/VLAN gets a zone.
//!     Rules talk about zones, not interfaces.
//!   • **LAN segment** — a subnet served by WolfRouter. Bound to a
//!     bridge or interface; dnsmasq hands out DHCP leases and answers
//!     DNS with upstream forwarders.
//!   • **Firewall rule** — zone-to-zone or specific-endpoint allow/deny
//!     with state tracking. Translated to iptables atomically via
//!     `iptables-restore --test` then swap.
//!
//! All state persists to `/etc/wolfstack/router/` as JSON so it survives
//! restarts. Topology (live view of ports/bridges/wires/devices) is
//! computed on demand from system state — never persisted.

pub mod firewall;
pub mod dhcp;
pub mod dns;
pub mod topology;
pub mod api;
pub mod wan;
pub mod host_dns;
pub mod proxy;
pub mod health;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn, info};

pub const ROUTER_DIR: &str = "/etc/wolfstack/router";

/// Maximum number of rolling backup snapshots kept in `ROUTER_DIR`.
/// Each save() before atomic-rename copies the previous config.json
/// to `config.json.bak.<unix-seconds>` so a regression that mangles
/// the file leaves a clean rollback target. Ten is enough to span
/// "the last few days of edits" without ballooning the dir.
const MAX_BACKUPS: usize = 10;

/// Process-wide latch flipped by `load_with_status` whenever the
/// on-disk config fails to parse (or fails to read for any reason
/// other than "file not found"). Every `RouterConfig::save()`
/// consults it and refuses to write when set, so a fallback
/// `Default::default()` config can never atomic-rename over the
/// user's last-known-good file.
///
/// This is the load-bearing safety net: every existing endpoint
/// calls `RouterConfig::save()` directly, so gating inside save()
/// itself protects them all without per-endpoint churn. The latch
/// is cleared by `clear_load_failed()` after a successful recovery
/// rollback.
static LOAD_FAILED: AtomicBool = AtomicBool::new(false);

/// Returns true when the most recent `load_with_status` produced a
/// `ParseError` and the user has not yet recovered. While true,
/// every `save()` call returns an error without touching the file.
pub fn save_blocked_by_load_failure() -> bool {
    LOAD_FAILED.load(Ordering::SeqCst)
}

/// Clear the process-wide save-block latch. Called from the
/// recovery API after a successful snapshot restore (the disk file
/// is now known-good) and from unit tests.
pub fn clear_load_failed() {
    LOAD_FAILED.store(false, Ordering::SeqCst);
}

/// Named policy group. Interfaces and bridges belong to a zone; firewall
/// rules are written in terms of zones so admins don't have to remember
/// "is enp3s0 the LAN or the WAN today?".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum Zone {
    Wan,
    Lan(u32),
    Dmz,
    Wolfnet,
    Trusted,
    Custom(String),
}

#[allow(dead_code)]
impl Zone {
    /// Short slug used for ipset names and log tags. Must be <= 24 chars
    /// (ipset's limit minus our "wr-zone-" prefix).
    pub fn slug(&self) -> String {
        match self {
            Zone::Wan => "wan".into(),
            Zone::Lan(n) => format!("lan{}", n),
            Zone::Dmz => "dmz".into(),
            Zone::Wolfnet => "wolfnet".into(),
            Zone::Trusted => "trusted".into(),
            Zone::Custom(s) => {
                let clean: String = s.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .take(16)
                    .collect();
                if clean.is_empty() { "custom".into() } else { clean }
            }
        }
    }

    pub fn human(&self) -> String {
        match self {
            Zone::Wan => "WAN".into(),
            Zone::Lan(n) => format!("LAN {}", n),
            Zone::Dmz => "DMZ".into(),
            Zone::Wolfnet => "WolfNet".into(),
            Zone::Trusted => "Trusted".into(),
            Zone::Custom(s) => s.clone(),
        }
    }
}

/// A DHCP pool + static reservations + options bundle for one LAN.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpConfig {
    /// DHCP pool start (e.g. "192.168.10.100").
    pub pool_start: String,
    /// DHCP pool end (e.g. "192.168.10.250").
    pub pool_end: String,
    /// Lease time, e.g. "12h" or "1d".
    #[serde(default = "default_lease_time")]
    pub lease_time: String,
    /// Static MAC → IP (+ hostname) reservations.
    #[serde(default)]
    pub reservations: Vec<DhcpReservation>,
    /// DHCP options to push (3=gateway, 6=DNS, 42=NTP, etc.). Left blank
    /// by default because dnsmasq fills in gateway/DNS from the LAN's
    /// router_ip automatically.
    #[serde(default)]
    pub extra_options: Vec<String>,
    /// Whether DHCP is enabled. If false, the LAN still exists (routed,
    /// firewall applies) but clients must configure statically.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_lease_time() -> String { "12h".into() }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpReservation {
    pub mac: String,           // "aa:bb:cc:dd:ee:ff"
    pub ip: String,            // must be within the LAN subnet
    pub hostname: Option<String>,
}

/// Who actually serves DNS on this LAN. Default is WolfRouter's own
/// dnsmasq (the existing behaviour). `External` means the operator is
/// running their own DNS box on the LAN (AdGuard Home in a container,
/// Pi-hole on a Pi, etc.) and just wants WolfRouter's DHCP to point
/// clients there.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// WolfRouter's dnsmasq binds port `listen_port` on the LAN
    /// interface and DHCP option 6 advertises the router IP.
    WolfRouter,
    /// WolfRouter's dnsmasq runs DHCP only (port=0 = DNS off) and DHCP
    /// option 6 advertises `external_server` to clients.
    External,
}

impl Default for DnsMode {
    fn default() -> Self { DnsMode::WolfRouter }
}

/// DNS resolver config for one LAN. dnsmasq handles both DHCP and DNS,
/// so this is applied to the same per-LAN instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerConfig {
    /// How DNS is served on this LAN. `WolfRouter` (default) = dnsmasq
    /// answers on port 53; `External` = dnsmasq yields port 53 and
    /// DHCP points clients at the operator's DNS server.
    #[serde(default)]
    pub mode: DnsMode,
    /// Port dnsmasq binds for DNS on this LAN's interface when
    /// `mode = WolfRouter`. Default 53. Moving this to 5353 lets a
    /// containerised resolver (AdGuard Home, etc.) claim port 53 on
    /// the same interface — in that case set `external_server` too so
    /// DHCP option 6 still advertises a resolver clients can actually
    /// reach on the standard port. Ignored when `mode = External`
    /// (DNS is disabled there via `port=0`).
    #[serde(default = "default_dns_port")]
    pub listen_port: u16,
    /// DNS server advertised to DHCP clients (option 6). Required when
    /// `mode = External`. Optional when `mode = WolfRouter`: if set,
    /// takes precedence over the router IP (useful when `listen_port`
    /// isn't 53).
    #[serde(default)]
    pub external_server: Option<String>,
    /// Upstream forwarders. If empty, falls back to host's /etc/resolv.conf.
    #[serde(default)]
    pub forwarders: Vec<String>,
    /// Local A records (hostname → IP) served authoritatively to this LAN.
    /// Useful for giving VMs/services local DNS names without an external
    /// DNS server.
    #[serde(default)]
    pub local_records: Vec<LocalDnsRecord>,
    /// Enable DNS cache. dnsmasq caches by default; this toggle lets an
    /// admin disable it for debugging.
    #[serde(default = "default_true")]
    pub cache_enabled: bool,
    /// Block ad/tracker domains. Pulls from a pluggable hosts list.
    #[serde(default)]
    pub block_ads: bool,
    /// If true, dnsmasq logs every query to a per-LAN file at
    /// /var/lib/wolfstack-router/lan-<id>.log. Debug-only — leaves a
    /// growing log file on disk while enabled. The DNS Tools tab
    /// toggles this so admins can watch LAN clients' queries land (or
    /// not) in real time.
    #[serde(default)]
    pub query_log: bool,
    /// Forward the original client IP to upstream forwarders via EDNS
    /// Client Subnet (RFC 7871). Adds `add-subnet=32,128` to dnsmasq so
    /// upstreams like AdGuard, Pi-hole, or NextDNS can attribute queries
    /// to individual LAN clients instead of seeing them all come from
    /// the router. Off by default because ECS leaks client subnets to
    /// the upstream — enable only when you trust the upstream.
    #[serde(default)]
    pub forward_client_subnet: bool,
}

fn default_dns_port() -> u16 { 53 }

impl Default for DnsServerConfig {
    fn default() -> Self {
        DnsServerConfig {
            mode: DnsMode::WolfRouter,
            listen_port: 53,
            external_server: None,
            forwarders: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            local_records: vec![],
            cache_enabled: true,
            block_ads: false,
            query_log: false,
            forward_client_subnet: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDnsRecord {
    pub hostname: String,
    pub ip: String,
}

/// A LAN segment served by WolfRouter on one node. Bound to a bridge or
/// physical interface; dnsmasq listens on that interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanSegment {
    pub id: String,
    pub name: String,
    /// Node that hosts this LAN (serves DHCP/DNS from here).
    pub node_id: String,
    /// Interface/bridge name on that node (e.g. "br-lan0", "enp3s0",
    /// "eth0.100" for a VLAN).
    pub interface: String,
    pub zone: Zone,
    /// Subnet in CIDR form, e.g. "192.168.10.0/24".
    pub subnet_cidr: String,
    /// Router IP within the subnet (typically .1 or .254).
    pub router_ip: String,
    pub dhcp: DhcpConfig,
    pub dns: DnsServerConfig,
    #[serde(default)]
    pub description: String,
}

/// A subnet route for reaching remote networks via WolfNet or other tunnels.
/// Allows traffic destined for the subnet to be routed through a gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetRoute {
    pub id: String,
    /// Destination subnet in CIDR form (e.g. "10.20.0.0/16").
    pub subnet_cidr: String,
    /// Gateway IP — the next-hop to reach this subnet (typically a WolfNet tunnel endpoint).
    pub gateway: String,
    /// Node that owns this route. If None, applied cluster-wide.
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

/// Firewall rule action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Log,
}

/// Which chain does this rule apply to?
///   • `Forward` — traffic between interfaces (99% of home firewall rules)
///   • `Input`   — traffic destined for the WolfStack host itself
///   • `Output`  — traffic originating from the WolfStack host
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Forward,
    Input,
    Output,
}

/// What the rule matches at the "from" or "to" end.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Endpoint {
    Any,
    Zone { zone: Zone },
    Interface { name: String },
    Ip { cidr: String },       // single IP or CIDR
    Vm { name: String },       // resolved at apply-time to the VM's IP
    Container { name: String },
    Lan { id: String },        // resolves to the LAN's subnet
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol { Any, Tcp, Udp, Icmp, Tcpudp }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSpec {
    /// Single port ("80") or range ("8000-8100").
    pub port: String,
    /// Dst (the common case) or Src side of the match.
    #[serde(default)]
    pub side: PortSide,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PortSide { #[default] Dst, Src }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub order: i32,
    pub action: Action,
    pub direction: Direction,
    pub from: Endpoint,
    pub to: Endpoint,
    pub protocol: Protocol,
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// Add `-m conntrack --ctstate NEW` (with ESTABLISHED,RELATED a single
    /// jump-accept rule installed by the engine, users don't write this).
    #[serde(default = "default_true")]
    pub state_track: bool,
    /// Copy matches to NFLOG so they show up in the Logs view.
    #[serde(default)]
    pub log_match: bool,
    #[serde(default)]
    pub comment: String,
    /// Node that owns this rule. Rules can be cluster-scoped (applied
    /// to every node) by setting node_id = None; typically rules are
    /// node-scoped because they reference node-local interfaces.
    #[serde(default)]
    pub node_id: Option<String>,
}

/// Which interface/bridge on which node belongs to which zone. Used by
/// the firewall engine to build ipsets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZoneAssignments {
    /// (node_id, interface_name) → Zone
    #[serde(default)]
    pub assignments: HashMap<String, HashMap<String, Zone>>,
}

impl ZoneAssignments {
    pub fn get(&self, node_id: &str, iface: &str) -> Option<&Zone> {
        self.assignments.get(node_id).and_then(|m| m.get(iface))
    }

    pub fn set(&mut self, node_id: &str, iface: &str, zone: Zone) {
        self.assignments
            .entry(node_id.to_string())
            .or_default()
            .insert(iface.to_string(), zone);
    }

    pub fn remove(&mut self, node_id: &str, iface: &str) {
        if let Some(m) = self.assignments.get_mut(node_id) {
            m.remove(iface);
        }
    }

    /// All (node_id, iface) pairs that are members of a given zone on a
    /// given node — used to populate the zone's ipset.
    pub fn members_for_zone_on_node(&self, node_id: &str, zone: &Zone) -> Vec<String> {
        self.assignments
            .get(node_id)
            .map(|m| m.iter().filter(|(_, z)| *z == zone).map(|(n, _)| n.clone()).collect())
            .unwrap_or_default()
    }
}

// ─── Persistence ───

/// Router config on disk. A single file so atomic writes are simple.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouterConfig {
    #[serde(default)]
    pub zones: ZoneAssignments,
    #[serde(default)]
    pub lans: Vec<LanSegment>,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    /// WAN uplink configurations — DHCP, static, or PPPoE per port.
    #[serde(default)]
    pub wan_connections: Vec<wan::WanConnection>,
    /// Global setting: apply rules immediately or require explicit "Apply".
    /// Homelabbers will want immediate; sysadmins will want explicit so
    /// they can stage changes.
    #[serde(default = "default_true")]
    pub auto_apply: bool,
    /// Safe-mode rollback window. If > 0, every firewall apply starts a
    /// timer — if the user doesn't confirm before the timer fires, rules
    /// are reverted. Prevents lockout. 0 disables.
    #[serde(default = "default_safe_mode_seconds")]
    pub safe_mode_seconds: u32,
    /// Reverse-proxy entries. Each one maps an incoming domain to a
    /// backend (custom IP:port, a VM, or a container). The runtime
    /// generates one nginx site config per entry on the node that
    /// owns it. See `proxy::apply_for_node` for the generator.
    #[serde(default)]
    pub proxies: Vec<proxy::ProxyEntry>,
    /// Subnet routes for reaching remote networks via WolfNet or other tunnels.
    /// Each entry defines a destination subnet and the gateway to reach it.
    #[serde(default)]
    pub subnet_routes: Vec<SubnetRoute>,
}

fn default_safe_mode_seconds() -> u32 { 30 }

/// Outcome of `RouterConfig::load_with_status`. Distinguishes the
/// three real-world cases so callers can decide whether it's safe to
/// re-save the in-memory config back to disk:
///
/// * `Loaded` — file existed and parsed cleanly. Safe to save.
/// * `Fresh` — file did not exist (first run, fresh install). Safe
///   to save once the user actually edits something.
/// * `ParseError` — file existed but failed to deserialize. The
///   on-disk JSON is preserved (via quarantine) and the in-memory
///   config falls back to `Default`. **Must NOT save** — doing so
///   would atomic-rename the empty default over the user's last
///   known-good config and lose it forever. The original silent
///   `unwrap_or_default()` did exactly that on every update where a
///   field/enum representation drifted, wiping WolfRouter configs
///   (PapaSchlumpf 2026-05-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadOutcome {
    Loaded,
    Fresh,
    ParseError {
        /// Absolute path the original (broken) file was copied to so
        /// the user can recover it. Empty on quarantine failure.
        quarantine_path: String,
        /// Serde's error string — surfaced in logs and via the
        /// recovery API so the operator can see exactly which field
        /// or enum variant tripped the parser.
        error: String,
    },
}

impl RouterConfig {
    pub fn path() -> String { format!("{}/config.json", ROUTER_DIR) }

    /// Backwards-compatible loader. Use `load_with_status` instead
    /// when you need to know whether the load was clean — every new
    /// caller does, but a couple of legacy unit-test paths still rely
    /// on the swallow-and-default shape so we keep this stub.
    pub fn load() -> Self {
        Self::load_with_status().0
    }

    /// Load the persisted config and report what happened. The
    /// caller is responsible for setting `RouterState::loaded_clean`
    /// to `false` whenever the outcome is `ParseError` so every
    /// downstream `save()` refuses to run until the user explicitly
    /// resolves the error (rollback to a backup or re-edit the file).
    pub fn load_with_status() -> (Self, LoadOutcome) {
        let path = Self::path();
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => {
                // File exists and is readable — clear any prior
                // failure latch (e.g. set during a previous start).
                LOAD_FAILED.store(false, Ordering::SeqCst);
                s
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                LOAD_FAILED.store(false, Ordering::SeqCst);
                return (Self::default(), LoadOutcome::Fresh);
            }
            Err(e) => {
                // Permission denied / I/O error: refuse to silently
                // wipe by treating it the same as a parse error —
                // we have no proof the file is gone, only that we
                // couldn't read it. Saving over it would be reckless.
                error!(
                    "WolfRouter: cannot read {} ({}). Refusing to start with \
                     a default config — this would overwrite the existing \
                     file the moment anything calls save(). Resolve the I/O \
                     error and restart, or use `--wolfrouter-recover` to \
                     pick a backup.",
                    path, e,
                );
                LOAD_FAILED.store(true, Ordering::SeqCst);
                return (
                    Self::default(),
                    LoadOutcome::ParseError {
                        quarantine_path: String::new(),
                        error: format!("read failed: {}", e),
                    },
                );
            }
        };

        match serde_json::from_str::<Self>(&raw) {
            Ok(cfg) => {
                LOAD_FAILED.store(false, Ordering::SeqCst);
                (cfg, LoadOutcome::Loaded)
            }
            Err(e) => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let quarantine = format!("{}/config.json.broken-{}", ROUTER_DIR, ts);
                LOAD_FAILED.store(true, Ordering::SeqCst);
                let quarantine_path = match std::fs::write(&quarantine, &raw) {
                    Ok(()) => {
                        error!(
                            "WolfRouter: {} failed to deserialize ({}). \
                             Original file copied to {} for recovery. \
                             Refusing to apply, save, or auto-rewrite — use \
                             `--wolfrouter-recover` (CLI) or the rollback \
                             banner in the WolfRouter UI to pick a known-good \
                             snapshot.",
                            path, e, quarantine,
                        );
                        quarantine
                    }
                    Err(qe) => {
                        error!(
                            "WolfRouter: {} failed to deserialize ({}). \
                             COULD NOT QUARANTINE the original file ({}). \
                             The on-disk file is left untouched — DO NOT \
                             trigger any save() until you've copied {} to \
                             a safe location manually.",
                            path, e, qe, path,
                        );
                        String::new()
                    }
                };
                (
                    Self::default(),
                    LoadOutcome::ParseError {
                        quarantine_path,
                        error: e.to_string(),
                    },
                )
            }
        }
    }

    /// Atomic-rename save with rolling backup.
    ///
    /// Before writing the new file we copy the existing
    /// `config.json` to `config.json.bak.<unix-seconds>`. Old
    /// backups beyond `MAX_BACKUPS` are pruned oldest-first so the
    /// directory stays bounded. The backup is best-effort — a
    /// failure to create it does NOT block the save (we'd rather
    /// lose a backup than refuse a legitimate config write), but it
    /// IS logged at warn so cluster-validation can surface it.
    pub fn save(&self) -> Result<(), String> {
        // Hard gate: refuse to write when the most recent load
        // failed. This is the single point that prevents a default
        // fallback config from overwriting the user's last-known-
        // good file. The latch is cleared by `clear_load_failed()`
        // after a successful recovery rollback.
        if save_blocked_by_load_failure() {
            return Err(
                "WolfRouter config not persisted: startup load failed and the \
                 process is in recovery mode. Pick a backup or quarantined \
                 snapshot from the rollback panel (or `--wolfrouter-recover`) \
                 before edits will persist.".to_string()
            );
        }
        std::fs::create_dir_all(ROUTER_DIR)
            .map_err(|e| format!("Failed to create router dir: {}", e))?;

        // Best-effort rolling backup of the previous file. Skipped
        // when the file doesn't exist yet (first save on a fresh
        // install).
        let path = Self::path();
        if std::path::Path::new(&path).exists() {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let bak = format!("{}.bak.{}", path, ts);
            if let Err(e) = std::fs::copy(&path, &bak) {
                warn!(
                    "WolfRouter: rolling backup to {} failed ({}). Save \
                     proceeding without a backup — recovery options will \
                     be reduced if the new write is bad.",
                    bak, e,
                );
            } else {
                prune_old_backups(MAX_BACKUPS);
            }
        }

        let tmp = format!("{}.tmp", path);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize failed: {}", e))?;
        std::fs::write(&tmp, json)
            .map_err(|e| format!("Write failed: {}", e))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| format!("Atomic rename failed: {}", e))?;
        Ok(())
    }
}

/// Keep at most `keep` `config.json.bak.*` snapshots in
/// `ROUTER_DIR`, deleting the oldest first by the unix-second
/// suffix in the filename. `config.json.broken-*` quarantine files
/// are NEVER pruned — they're how the user recovers from a parse
/// error and may need to outlive routine backup rotation.
fn prune_old_backups(keep: usize) {
    let dir = match std::fs::read_dir(ROUTER_DIR) {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut backups: Vec<(u64, std::path::PathBuf)> = Vec::new();
    for entry in dir.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if let Some(ts_str) = name.strip_prefix("config.json.bak.") {
            if let Ok(ts) = ts_str.parse::<u64>() {
                backups.push((ts, entry.path()));
            }
        }
    }
    if backups.len() <= keep { return; }
    backups.sort_by_key(|(ts, _)| *ts);
    let drop_count = backups.len() - keep;
    for (_, path) in backups.into_iter().take(drop_count) {
        let _ = std::fs::remove_file(path);
    }
}

/// Return every recovery target currently available on disk —
/// `.bak.<ts>` rolling backups and `.broken-<ts>` quarantine
/// snapshots — newest first. Surfaced via the recovery API so the
/// frontend can render a per-snapshot "Rollback to..." button.
pub fn list_recovery_snapshots() -> Vec<RecoverySnapshot> {
    let dir = match std::fs::read_dir(ROUTER_DIR) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut snaps: Vec<RecoverySnapshot> = Vec::new();
    for entry in dir.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let (kind, ts_str) = if let Some(s) = name.strip_prefix("config.json.bak.") {
            ("backup", s)
        } else if let Some(s) = name.strip_prefix("config.json.broken-") {
            ("broken", s)
        } else {
            continue;
        };
        let ts: u64 = ts_str.parse().unwrap_or(0);
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        // Cheap sanity check: is the snapshot actually parseable?
        // Not authoritative (it's just a hint for the UI to flag
        // "this one's broken too"), so we tolerate failures silently.
        let parses = std::fs::read_to_string(entry.path())
            .ok()
            .and_then(|s| serde_json::from_str::<RouterConfig>(&s).ok())
            .is_some();
        snaps.push(RecoverySnapshot {
            kind: kind.to_string(),
            timestamp: ts,
            path: entry.path().to_string_lossy().to_string(),
            size_bytes: size,
            parses,
        });
    }
    snaps.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    snaps
}

/// One recovery target: either a rolling `.bak.<ts>` from a normal
/// save or a `.broken-<ts>` quarantined unparseable file.
#[derive(Debug, Clone, Serialize)]
pub struct RecoverySnapshot {
    /// "backup" (rolling save backup) or "broken" (quarantined parse
    /// failure). The frontend uses this to label the chip.
    pub kind: String,
    /// Unix seconds when the snapshot was created.
    pub timestamp: u64,
    /// Absolute path on disk. Used as the opaque token the frontend
    /// passes back to `restore_recovery_snapshot`.
    pub path: String,
    pub size_bytes: u64,
    /// True when the snapshot deserializes cleanly with the current
    /// binary — flagged in the UI so users don't restore a known-bad
    /// snapshot and fall straight back into the parse-error state.
    pub parses: bool,
}

/// Restore a recovery snapshot to be the live `config.json`. Path
/// is validated to live inside `ROUTER_DIR` (no `..` escapes) and to
/// match one of the two snapshot prefixes — anything else is
/// rejected as an injection attempt.
///
/// The currently-live `config.json` is rotated to a new
/// `.bak.<ts>` before the restore so a bad rollback is itself
/// rollback-able.
pub fn restore_recovery_snapshot(snapshot_path: &str) -> Result<(), String> {
    let canon = std::path::Path::new(snapshot_path);
    let file_name = canon.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "snapshot path has no filename component".to_string())?;
    let parent = canon.parent()
        .and_then(|p| p.to_str())
        .ok_or_else(|| "snapshot path has no parent directory".to_string())?;
    if parent != ROUTER_DIR {
        return Err(format!(
            "snapshot path is outside {} — refusing to restore",
            ROUTER_DIR
        ));
    }
    if !file_name.starts_with("config.json.bak.")
        && !file_name.starts_with("config.json.broken-")
    {
        return Err(format!(
            "snapshot {} is not a recognised backup or quarantine file",
            file_name
        ));
    }
    if !canon.exists() {
        return Err(format!("snapshot {} no longer exists", snapshot_path));
    }
    // Sanity-check the snapshot parses before swapping it in. A
    // quarantined `broken-*` file may not — fine, the user can
    // explicitly opt to restore it anyway, but we surface the error
    // either way.
    let raw = std::fs::read_to_string(snapshot_path)
        .map_err(|e| format!("could not read snapshot {}: {}", snapshot_path, e))?;
    let parses = serde_json::from_str::<RouterConfig>(&raw).is_ok();

    // Rotate the live file so the rollback is itself reversible.
    let live = RouterConfig::path();
    if std::path::Path::new(&live).exists() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bak = format!("{}.bak.{}", live, ts);
        if let Err(e) = std::fs::copy(&live, &bak) {
            warn!(
                "WolfRouter recovery: pre-rollback backup of {} to {} \
                 failed ({}) — proceeding anyway because the user \
                 explicitly chose to restore. The previous live file is \
                 about to be replaced and won't be recoverable.",
                live, bak, e,
            );
        }
    }
    // Restoration goes through the lower-level write rather than
    // RouterConfig::save() because the save() latch is currently
    // *blocking* persistence — that's the whole reason we're in
    // the recovery flow. We bypass deliberately, write the verified
    // snapshot, then clear the latch so subsequent normal saves
    // are accepted again.
    std::fs::write(&live, &raw)
        .map_err(|e| format!("could not write live config {}: {}", live, e))?;
    if parses {
        clear_load_failed();
    } else {
        warn!(
            "WolfRouter recovery: restored {} to live but the snapshot did \
             NOT parse with the current binary. Save-block remains set; the \
             user must edit and re-restore (or fix the file) before edits \
             will persist again.",
            snapshot_path,
        );
    }
    info!(
        "WolfRouter recovery: restored {} to {} (parses={}). Restart the \
         service or POST /api/router/apply-startup to bring the rolled-back \
         config into the running ruleset.",
        snapshot_path, live, parses,
    );
    Ok(())
}

/// In-memory state, wrapped in AppState. RwLock because topology reads
/// are frequent (every poll) and writes are rare (user edits).
pub struct RouterState {
    pub config: RwLock<RouterConfig>,
    /// Last committed ruleset's iptables dump — used for safe-mode rollback.
    pub last_applied_rules: RwLock<Option<String>>,
    /// Live pending-rollback timer: when a user applies rules with safe-mode
    /// on, this is set to the epoch second at which we auto-revert if they
    /// haven't confirmed.
    pub rollback_deadline: RwLock<Option<u64>>,
    /// Per-node topology snapshots populated by the agent tick. Keyed by
    /// node_id. The local node is computed on demand, not cached here.
    pub remote_topologies: RwLock<HashMap<String, topology::NodeTopology>>,
    /// Last cluster-wide config-validation report. Populated by
    /// `validate_local_configs` at startup and on every watchdog tick.
    /// Surfaced via /api/router/validation so operators see what was
    /// flagged at the most recent boot/scan.
    pub last_validation: RwLock<Option<ValidationReport>>,
    /// `true` when the on-disk config loaded cleanly (or didn't exist
    /// yet on a fresh install). `false` when load() hit a parse or
    /// I/O error. Used by the recovery API and the UI banner to
    /// drive the rollback flow; the actual save-block enforcement
    /// is the process-wide `LOAD_FAILED` latch consulted inside
    /// `RouterConfig::save()`. Saving a default-fallback config
    /// over the user's last-known-good file is exactly how
    /// WolfRouter configs got wiped on update before 2026-05-06.
    pub loaded_clean: AtomicBool,
    /// Populated when `load_with_status` returns a `ParseError`.
    /// Exposed via `/api/router/recovery` so the UI can render a
    /// banner with the serde error and a list of rollback targets.
    pub load_error: RwLock<Option<LoadError>>,
}

/// Persisted-on-load failure detail — mirror of `LoadOutcome::ParseError`
/// minus the variant wrapper, ready for the recovery API to serialise.
#[derive(Debug, Clone, Serialize)]
pub struct LoadError {
    /// Where the unparseable original was copied (empty if quarantine
    /// also failed — in that case the original was left untouched).
    pub quarantine_path: String,
    /// Serde error text — e.g. `"missing field 'foo' at line 3 column 1"`.
    /// Verbatim so support can paste it into a bug report.
    pub error: String,
    /// Unix seconds when the failure was observed (process start
    /// time, since `load_with_status` runs once per process).
    pub observed_at: u64,
}

/// Snapshot of a per-node config-validation pass. One row per
/// validation finding across LANs/WANs/zones. Stored in RouterState
/// so the UI can render "what happened at startup" without re-running
/// the checks every page load.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ValidationReport {
    /// Unix seconds when this report was generated.
    pub generated_at: u64,
    /// Node that produced this report (this node).
    pub node_id: String,
    /// Total counts derived from `findings` for the UI summary chip.
    pub ok_count: u32,
    pub warning_count: u32,
    pub error_count: u32,
    /// Per-finding details. Each finding is scoped to a config item
    /// (LAN id, WAN id, etc.) so the UI can group them.
    pub findings: Vec<ValidationFinding>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationFinding {
    /// "lan" | "wan" | "zone" | "subnet_route" | "firewall"
    pub category: &'static str,
    /// Identifier of the config item the finding refers to (LAN id,
    /// WAN id, etc.) — empty when the finding is global to a category.
    pub item_id: String,
    /// Display name (LAN name, WAN name) — for the UI chip.
    pub item_name: String,
    /// "ok" | "warning" | "error".
    pub severity: &'static str,
    pub message: String,
}

impl RouterState {
    pub fn new() -> Self {
        let (cfg, outcome) = RouterConfig::load_with_status();
        let (clean, load_err) = match outcome {
            LoadOutcome::Loaded => (true, None),
            LoadOutcome::Fresh => (true, None), // First run — saves are fine.
            LoadOutcome::ParseError { quarantine_path, error } => (
                false,
                Some(LoadError {
                    quarantine_path,
                    error,
                    observed_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                }),
            ),
        };
        RouterState {
            config: RwLock::new(cfg),
            last_applied_rules: RwLock::new(None),
            rollback_deadline: RwLock::new(None),
            remote_topologies: RwLock::new(HashMap::new()),
            last_validation: RwLock::new(None),
            loaded_clean: AtomicBool::new(clean),
            load_error: RwLock::new(load_err),
        }
    }

    /// Mark this state as freshly clean — used after a successful
    /// recovery rollback or after the user has explicitly resolved
    /// the parse-error condition through the recovery UI. Also
    /// clears the process-wide save-block latch so subsequent
    /// `RouterConfig::save()` calls are accepted again.
    pub fn mark_clean(&self) {
        self.loaded_clean.store(true, Ordering::SeqCst);
        if let Ok(mut e) = self.load_error.write() {
            *e = None;
        }
        clear_load_failed();
    }

    /// Returns true when callers may legitimately persist the
    /// in-memory config back to disk. The actual gate lives inside
    /// `RouterConfig::save()` so existing call sites get the
    /// protection automatically; this helper is here for callers
    /// (currently `topology::ensure_default_zones`) that want to
    /// short-circuit BEFORE building a save snapshot, since failing
    /// inside save() would still log a refusal even when the caller
    /// already knows the latch is set.
    pub fn may_save(&self) -> bool {
        self.loaded_clean.load(Ordering::SeqCst)
    }
}

impl Default for RouterState {
    fn default() -> Self { Self::new() }
}

/// Reconstruct a best-effort RouterConfig from on-disk artefacts
/// that survive independently of `config.json` — the dnsmasq
/// per-LAN config snippets in `<ROUTER_DIR>/dnsmasq.d/`, PPPoE
/// peer files in `/etc/ppp/peers/wolfrouter-*`, and the current
/// in-kernel iptables state. Used when the user has lost
/// `config.json` entirely (e.g. wiped by the pre-fix silent-default
/// regression) and there are no `.bak.*` snapshots to roll back to.
///
/// This is explicit recovery, not auto-recovery: it never writes
/// anything on its own. The reconstructed config is returned to
/// the caller, who renders it in the UI for the user to review
/// (since artefacts may be partial or stale) and explicitly
/// commit. The committed config goes through the normal
/// `RouterConfig::save()` path so it benefits from the rolling-backup
/// safety net going forward.
///
/// What we can recover:
///   * **LANs** — from `dnsmasq.d/lan-<id>.conf`. Each file is
///     written with deterministic key=value lines, so we parse
///     `interface=`, `dhcp-range=`, `dhcp-option=3,…`,
///     `dhcp-option=6,…` and reconstruct the LanSegment.
///   * **WAN/PPPoE** — from `/etc/ppp/peers/wolfrouter-<id>`.
///     `plugin rp-pppoe.so <iface>`, `user "<name>"`, MTU/MRU,
///     LCP echo settings. Password lives in chap-secrets at 0600,
///     readable as root — we copy it verbatim, never log it.
///   * **Firewall rules** — NOT reconstructable from iptables-save
///     in a useful way (the engine generates iptables from rules,
///     not the other way around — chain ordering, ipset names,
///     comment metadata can't be reversed). We surface this gap to
///     the user explicitly so they don't think it succeeded.
///   * **Zones, proxies, subnet-routes, etc.** — only persisted in
///     `config.json`. Lost is lost; we leave the defaults.
pub fn reconstruct_from_artifacts() -> ArtifactReconstruction {
    use std::fs;

    let mut cfg = RouterConfig::default();
    let mut notes: Vec<String> = Vec::new();
    let mut recovered: Vec<String> = Vec::new();

    // ── LANs from dnsmasq snippets ──
    let dnsmasq_dir = format!("{}/dnsmasq.d", ROUTER_DIR);
    match fs::read_dir(&dnsmasq_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = match entry.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let id = match name.strip_prefix("lan-").and_then(|s| s.strip_suffix(".conf")) {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => continue,
                };
                let body = match fs::read_to_string(entry.path()) {
                    Ok(b) => b,
                    Err(e) => {
                        notes.push(format!(
                            "could not read dnsmasq snippet {}: {}",
                            entry.path().display(), e
                        ));
                        continue;
                    }
                };
                if let Some(seg) = parse_lan_from_dnsmasq(&id, &body) {
                    recovered.push(format!("LAN '{}' (interface {})", seg.name, seg.interface));
                    cfg.lans.push(seg);
                } else {
                    notes.push(format!(
                        "dnsmasq snippet {} did not contain enough fields to \
                         reconstruct a LAN (need at least interface= and \
                         dhcp-range=) — skipped",
                        entry.path().display()
                    ));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            notes.push(format!(
                "no dnsmasq snippets at {} — no LANs were recovered \
                 (this is expected on a host that never had WolfRouter \
                 LANs configured; if you DID have LANs, the snippet \
                 directory was wiped along with config.json)",
                dnsmasq_dir
            ));
        }
        Err(e) => {
            notes.push(format!(
                "could not read {}: {} — no LANs recovered",
                dnsmasq_dir, e
            ));
        }
    }

    // ── WAN/PPPoE from /etc/ppp/peers ──
    match fs::read_dir("/etc/ppp/peers") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = match entry.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let id = match name.strip_prefix("wolfrouter-") {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => continue,
                };
                let body = match fs::read_to_string(entry.path()) {
                    Ok(b) => b,
                    Err(e) => {
                        notes.push(format!(
                            "could not read peer file {}: {}",
                            entry.path().display(), e
                        ));
                        continue;
                    }
                };
                if let Some(conn) = parse_pppoe_from_peer(&id, &body) {
                    recovered.push(format!(
                        "WAN PPPoE '{}' on interface {}",
                        conn.name, conn.interface
                    ));
                    cfg.wan_connections.push(conn);
                } else {
                    notes.push(format!(
                        "peer file {} did not parse as a PPPoE config \
                         (missing plugin rp-pppoe.so or user line) — skipped",
                        entry.path().display()
                    ));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            notes.push("no /etc/ppp/peers directory — no PPPoE WANs were recovered".to_string());
        }
        Err(e) => {
            notes.push(format!(
                "could not read /etc/ppp/peers: {} — no PPPoE WANs recovered",
                e
            ));
        }
    }

    notes.push(
        "Firewall rules cannot be reconstructed from iptables — the engine \
         generates iptables from rules, not the other way around. Any custom \
         rules you had will need to be re-entered manually.".to_string()
    );
    notes.push(
        "Zones, reverse proxies, and subnet routes only live in config.json \
         and were not recoverable. Default zone assignments (Wan / Wolfnet \
         based on interface name) will be re-derived on the next topology \
         poll AFTER you commit the recovered config.".to_string()
    );

    ArtifactReconstruction {
        config: cfg,
        recovered_items: recovered,
        notes,
    }
}

/// Parse the WolfRouter dnsmasq.d snippet for one LAN. Returns
/// `None` if the snippet is missing the bare-minimum fields we
/// need to identify the LAN — caller logs a note rather than
/// fabricating values from thin air. We deliberately read ONLY
/// the fields that the WolfRouter dnsmasq writer emits — anything
/// the user added by hand into the snippet is preserved on disk
/// (the writer doesn't overwrite hand-edits) but not roundtripped
/// into the in-memory config.
fn parse_lan_from_dnsmasq(id: &str, body: &str) -> Option<LanSegment> {
    let mut interface: Option<String> = None;
    let mut dhcp_start: Option<String> = None;
    let mut dhcp_end: Option<String> = None;
    let mut dhcp_lease: Option<String> = None;
    let mut router_ip: Option<String> = None;
    let mut dns_servers: Vec<String> = Vec::new();

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some(v) = line.strip_prefix("interface=") {
            interface = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("dhcp-range=") {
            // dhcp-range=<start>,<end>,<lease>
            let parts: Vec<&str> = v.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                dhcp_start = Some(parts[0].to_string());
                dhcp_end = Some(parts[1].to_string());
            }
            if parts.len() >= 3 {
                dhcp_lease = Some(parts[2].to_string());
            }
        } else if let Some(v) = line.strip_prefix("dhcp-option=") {
            // option 3 = router (gateway IP); option 6 = DNS
            let parts: Vec<&str> = v.splitn(2, ',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                match parts[0] {
                    "3" => router_ip = Some(parts[1].to_string()),
                    "6" => {
                        for ip in parts[1].split(',') {
                            let ip = ip.trim();
                            if !ip.is_empty() {
                                dns_servers.push(ip.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let iface = interface?;
    let pool_start = dhcp_start.unwrap_or_default();
    let pool_end = dhcp_end.unwrap_or_default();
    if pool_start.is_empty() || pool_end.is_empty() {
        return None;
    }
    let lease_time = dhcp_lease.unwrap_or_else(|| "12h".to_string());
    let router = router_ip.clone().unwrap_or_default();

    let dns_cfg = DnsServerConfig {
        forwarders: dns_servers,
        ..DnsServerConfig::default()
    };
    Some(LanSegment {
        id: id.to_string(),
        name: format!("LAN {} (recovered)", id),
        node_id: String::new(), // operator must set this in the UI before commit
        interface: iface,
        zone: Zone::Lan(id.parse::<u32>().unwrap_or(0)),
        subnet_cidr: derive_subnet_cidr(&router, &pool_start),
        router_ip: router,
        dhcp: DhcpConfig {
            pool_start,
            pool_end,
            lease_time,
            reservations: Vec::new(),
            extra_options: Vec::new(),
            enabled: true,
        },
        dns: dns_cfg,
        description: "Reconstructed from dnsmasq.d snippet — review before committing".into(),
    })
}

/// Best-effort /24 derivation. We don't have the original CIDR in
/// the dnsmasq snippet — only the gateway IP and DHCP pool — so we
/// fall back to /24 when the gateway and pool start agree on the
/// first three octets. The user is expected to verify and adjust
/// in the UI before committing the recovered config.
fn derive_subnet_cidr(router_ip: &str, pool_start: &str) -> String {
    let r: Vec<&str> = router_ip.split('.').collect();
    let p: Vec<&str> = pool_start.split('.').collect();
    if r.len() == 4 && p.len() == 4 && r[..3] == p[..3] {
        format!("{}.{}.{}.0/24", r[0], r[1], r[2])
    } else {
        String::new()
    }
}

/// Parse a `/etc/ppp/peers/wolfrouter-<id>` peer file back into a
/// WanConnection. Returns `None` when the file isn't actually a
/// PPPoE peer (no `plugin rp-pppoe.so`) or doesn't have a username
/// — those are required fields and we will not invent them.
///
/// The chap-secrets password is intentionally NOT read here: that
/// file is mode 0600 root-only and we keep the password out of any
/// reconstruction artefact the recovery API surfaces. The user
/// re-enters it during commit. Until they do, the WAN is created
/// disabled so it doesn't try to dial with an empty password.
fn parse_pppoe_from_peer(id: &str, body: &str) -> Option<wan::WanConnection> {
    let mut interface: Option<String> = None;
    let mut username: Option<String> = None;
    let mut mtu: u32 = 1492;
    let mut mru: u32 = 1492;
    let mut lcp_interval: u32 = 30;
    let mut lcp_failure: u32 = 4;
    let mut use_default_route = false;
    let mut use_peer_dns = false;
    let mut persist = true;
    let mut is_pppoe = false;
    let mut service_name = String::new();

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some(v) = line.strip_prefix("plugin rp-pppoe.so") {
            is_pppoe = true;
            let iface = v.trim();
            if !iface.is_empty() {
                interface = Some(iface.to_string());
            }
        } else if let Some(v) = line.strip_prefix("user ") {
            // `user "name"` or `user name`
            let unquoted = v.trim().trim_matches('"');
            if !unquoted.is_empty() {
                username = Some(unquoted.to_string());
            }
        } else if let Some(v) = line.strip_prefix("mtu ") {
            if let Ok(n) = v.trim().parse::<u32>() { mtu = n; }
        } else if let Some(v) = line.strip_prefix("mru ") {
            if let Ok(n) = v.trim().parse::<u32>() { mru = n; }
        } else if let Some(v) = line.strip_prefix("lcp-echo-interval ") {
            if let Ok(n) = v.trim().parse::<u32>() { lcp_interval = n; }
        } else if let Some(v) = line.strip_prefix("lcp-echo-failure ") {
            if let Ok(n) = v.trim().parse::<u32>() { lcp_failure = n; }
        } else if line == "defaultroute" {
            use_default_route = true;
        } else if line == "usepeerdns" {
            use_peer_dns = true;
        } else if line == "nopersist" {
            persist = false;
        } else if let Some(v) = line.strip_prefix("rp_pppoe_service ") {
            service_name = v.trim().trim_matches('"').to_string();
        }
    }

    if !is_pppoe { return None; }
    let user = username?;
    let iface = interface.unwrap_or_default();

    Some(wan::WanConnection {
        id: id.to_string(),
        name: format!("WAN {} (recovered)", id),
        node_id: String::new(), // operator sets in UI
        interface: iface,
        mode: wan::WanMode::Pppoe(wan::PppoeConfig {
            username: user,
            password: String::new(), // re-enter in UI; stored in chap-secrets
            service_name,
            mtu,
            mru,
            persist,
            lcp_echo_interval: lcp_interval,
            lcp_echo_failure: lcp_failure,
            use_default_route,
            use_peer_dns,
        }),
        enabled: false, // disabled until user re-enters password
        description: "Reconstructed from /etc/ppp/peers — review and re-enter password before enabling".into(),
    })
}

/// Result of `reconstruct_from_artifacts`. The frontend renders
/// `recovered_items` and `notes` in the rollback panel so the user
/// can see exactly what we found and what's still missing.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactReconstruction {
    pub config: RouterConfig,
    /// Human-readable list of items we successfully reconstructed
    /// (e.g. "LAN 'home' (interface br0)"). Empty when nothing was
    /// recoverable — the frontend uses the empty case to show the
    /// "nothing to recover" message instead of a misleading
    /// "recovery succeeded".
    pub recovered_items: Vec<String>,
    /// Caveats and gaps the user must read before committing —
    /// missing rules/zones/proxies, partial fields, password
    /// re-entry needed.
    pub notes: Vec<String>,
}

/// Apply the persisted router config on startup. Before this existed,
/// a host booting with WolfStack-as-router lost its WAN link, LAN
/// DHCP, and firewall rules every reboot — Docker and Proxmox both
/// autostart their payloads, but WolfStack only *loaded* the router
/// config on startup and required a human to click Apply in the UI
/// before anything came back up. Clients got leases but no internet.
///
/// Runs each subsystem best-effort: a WAN that fails to dial still
/// lets the LAN come up; a broken firewall rule still lets WAN and
/// LAN stand. Order matters:
///   1. WAN first — PPPoE ip-up hooks install MASQUERADE on the
///      dynamic ppp iface, and LAN/firewall may reference WAN zones.
///   2. LAN dnsmasq next — can only bind once its interface exists.
///   3. Firewall last — rules reference interfaces from 1+2.
///   4. Subnet routes — kernel route entries on consumer nodes,
///      forwarding plumbing (ip_forward / FORWARD ACCEPT / MASQUERADE
///      / rp_filter loose) on gateway nodes. Runs even when no other
///      router config is bound to this node, so a pure-gateway VPS
///      gets its plumbing reinstalled after every restart/update.
/// Safe-mode is explicitly OFF: unattended boot has no human to
/// confirm rules within the 30s window, and auto-reverting on every
/// reboot would be worse than "rules applied with no rollback".
/// Detect and remove default routes whose next-hop is one of THIS
/// host's own IPv4 addresses. Such routes can never deliver a packet
/// — the kernel can't ARP itself — and emit ICMP host-unreachable
/// from a local IP, producing the classic `traceroute` `!H`-on-hop-1
/// symptom. There is no legitimate setup that ships a default route
/// pointing at your own IP.
///
/// Real failure mode (PapaSchlumpf, April 2026): a router box had its
/// LAN gateway IP (10.10.10.1) configured as the LAN segment's
/// dnsmasq-served gateway AND someone added `gateway 10.10.10.1` on
/// the SAME box's `/etc/network/interfaces` LAN stanza. ifup
/// installed `default via 10.10.10.1 dev ens1 proto static` (metric
/// 0). Because 10.10.10.1 was a secondary IP on ens1 (the box itself
/// answers as that gateway for LAN clients), every packet originated
/// by the router got rejected with ICMP host-unreachable from
/// 10.10.10.2 — including LAN clients masqueraded out toward the
/// internet. Starlink's DHCP-installed working default at metric 100
/// lost to the metric-0 garbage every time.
///
/// This runs once per process start, gated to nodes that are actually
/// doing WolfRouter work (`applies_here` in apply_on_startup). One-
/// shot — we don't fight a misconfigured /etc/network/interfaces on
/// every network reload. The operator still has to remove the
/// persistent source, which the pre-flight UI surfaces with a
/// copy-paste fix.
///
/// Returns the list of deleted route lines for logging.
pub(super) fn purge_self_loop_defaults() -> Vec<String> {
    use std::process::Command;

    let mut removed = Vec::new();

    // Step 1: collect every non-loopback, non-host-scope IPv4 address
    // on this machine. These are the addresses that could never serve
    // as a legitimate next-hop in a default route on THIS box.
    let addr_out = match Command::new("ip").args(["-j", "-4", "addr"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return removed, // ip(8) missing or failed — nothing to do
    };
    let mut local_ips: Vec<String> = Vec::new();
    if let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&addr_out.stdout) {
        for entry in arr {
            if let Some(addrs) = entry.get("addr_info").and_then(|v| v.as_array()) {
                for ai in addrs {
                    if ai.get("family").and_then(|v| v.as_str()) != Some("inet") { continue; }
                    if ai.get("scope").and_then(|v| v.as_str()) == Some("host") { continue; }
                    if let Some(ip) = ai.get("local").and_then(|v| v.as_str()) {
                        local_ips.push(ip.to_string());
                    }
                }
            }
        }
    }
    if local_ips.is_empty() { return removed; }

    // Step 2: walk every default route and check its `via` next-hop
    // against the local-IP set. Only routes whose next-hop is a local
    // IP are deleted — anything else is left strictly alone.
    let route_out = match Command::new("ip").args(["-4", "route", "show", "default"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return removed,
    };
    let route_text = String::from_utf8_lossy(&route_out.stdout).to_string();

    for line in route_text.lines() {
        let line = line.trim();
        if !line.starts_with("default") { continue; }
        let via = line.split_whitespace()
            .skip_while(|t| *t != "via")
            .nth(1)
            .unwrap_or("");
        if via.is_empty() { continue; } // `default dev X` (point-to-point) — never local-IP-bogus
        if !local_ips.iter().any(|ip| ip == via) { continue; }

        // Self-loop confirmed. Build `ip route del <full args>` so we
        // delete THIS exact route (matched on dev/proto/metric) rather
        // than a similar one. Pass tokens individually — Command takes
        // care of escaping; line never contains shell metacharacters
        // because it came straight from `ip` output.
        //
        // Filter output-only annotations that `ip route show` emits but
        // `ip route del` rejects as unknown arguments. `linkdown` is
        // the one we actually see in the wild; the list is defensive.
        let mut args: Vec<&str> = vec!["route", "del"];
        args.extend(
            line.split_whitespace()
                .filter(|t| !matches!(*t, "linkdown" | "onlink"))
        );
        match Command::new("ip").args(&args).output() {
            Ok(o) if o.status.success() => {
                removed.push(line.to_string());
            }
            Ok(o) => {
                tracing::warn!(
                    "WolfRouter startup: failed to delete self-loop default route '{}': {}",
                    line, String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "WolfRouter startup: failed to spawn ip route del for '{}': {}",
                    line, e
                );
            }
        }
    }
    removed
}

pub fn apply_on_startup(state: std::sync::Arc<RouterState>, self_node_id: &str) {
    let cfg = state.config.read().unwrap().clone();

    // Skip entirely when the user hasn't configured WolfRouter on this
    // node. firewall::build_ruleset + apply would still produce a valid
    // "empty" ruleset, but applying it flushes the built-in INPUT /
    // FORWARD / OUTPUT chains and with them any jumps that Docker / VM
    // managers / other subsystems installed for their own forwarding.
    // Those subsystems re-install their rules on their own events, but
    // doing that pointless churn on every reboot isn't free. If this
    // node has nothing to say about routing, stay out of the way.
    let applies_here = cfg.wan_connections.iter()
        .any(|c| c.enabled && c.node_id == self_node_id)
        || cfg.lans.iter().any(|l| l.node_id == self_node_id)
        || cfg.rules.iter().any(|r| r.enabled
            && r.node_id.as_deref().map(|n| n == self_node_id).unwrap_or(true))
        || cfg.proxies.iter().any(|p| p.enabled && p.node_id == self_node_id);

    // WAN/DHCP/firewall/proxy work — only when this node owns at least
    // one of those. Subnet-route plumbing is handled below regardless,
    // because a node can be a pure subnet-route gateway (e.g. a VPS
    // forwarding a remote LAN onto WolfNet) with no WolfRouter LAN /
    // WAN / firewall config of its own. Sponsor klasSponsor 2026-04-28:
    // pre-fix, a reinstall on a pure-gateway node returned early here
    // and never re-applied ip_forward / FORWARD / MASQUERADE — the
    // route survived but the forwarding plumbing didn't.
    if applies_here {
        // Self-loop default routes — kill any `default via <local-ip>`
        // before WAN apply so by the time WolfRouter is "up", the
        // routing table doesn't have a metric-0 self-loop hijacking
        // egress. Strictly bounded: deletes ONLY routes whose next-hop
        // is one of this host's own IPv4 addresses. Such routes are
        // unambiguous misconfig — they cannot deliver a packet. Routes
        // with a real off-box next-hop are never touched.
        let purged = purge_self_loop_defaults();
        for r in &purged {
            tracing::warn!(
                "WolfRouter startup: removed self-loop default route '{}' \
                 (next-hop is one of this host's own IPv4 addresses — could \
                 never deliver packets, was producing ICMP host-unreachable \
                 on every egress attempt). Persistent source is likely a \
                 `gateway <local-ip>` line in /etc/network/interfaces, \
                 /etc/netplan/*.yaml, or a NetworkManager profile — remove \
                 it to prevent reinstall on next boot.",
                r
            );
        }

        let mut wan_ok = 0usize;
        let mut wan_err = 0usize;
        for conn in &cfg.wan_connections {
            if conn.node_id != self_node_id { continue; }
            if !conn.enabled { continue; }
            match wan::apply(conn) {
                Ok(()) => { wan_ok += 1; }
                Err(e) => {
                    wan_err += 1;
                    tracing::error!(
                        "WolfRouter startup: WAN '{}' apply failed: {}",
                        conn.name, e
                    );
                }
            }
        }
        if wan_ok + wan_err > 0 {
            tracing::info!(
                "WolfRouter startup: {} WAN connection(s) applied, {} failed",
                wan_ok, wan_err
            );
        }

        // dhcp::start_all_for_node already skips LANs bound to other
        // nodes and logs per-LAN failures. No return value to aggregate.
        dhcp::start_all_for_node(&cfg, self_node_id);

        // Firewall — only if the user actually has rules. On a fresh
        // install with empty rules the build produces an empty chain
        // dump that's technically valid but emitting an info line just
        // so sysadmins see activity at boot.
        let ruleset = firewall::build_ruleset(&cfg, self_node_id);
        match firewall::apply(&ruleset, false) {
            Ok(prev) => {
                *state.last_applied_rules.write().unwrap() = Some(prev);
                tracing::info!(
                    "WolfRouter startup: firewall rules applied ({} user rule(s))",
                    cfg.rules.len()
                );
            }
            Err(e) => {
                tracing::error!("WolfRouter startup: firewall apply failed: {}", e);
            }
        }

        // Reverse-proxy vhosts — regenerate nginx site configs for every
        // proxy bound to this node. Skip entirely when no proxies target
        // this node, so a bare install without nginx doesn't log scary
        // "nginx not installed" warnings on every boot.
        if cfg.proxies.iter().any(|p| p.enabled && p.node_id == self_node_id) {
            let warnings = proxy::apply_for_node(&cfg.proxies, self_node_id);
            if warnings.is_empty() {
                tracing::info!(
                    "WolfRouter startup: {} reverse-proxy vhost(s) regenerated",
                    cfg.proxies.iter().filter(|p| p.enabled && p.node_id == self_node_id).count()
                );
            } else {
                for w in &warnings {
                    tracing::warn!("WolfRouter startup: proxy apply: {}", w);
                }
            }
        }
    } else {
        tracing::debug!(
            "WolfRouter startup: no LAN/WAN/firewall/proxy bound here — skipping those (subnet routes still checked below)"
        );
    }

    // Subnet routes — apply kernel routing entries for remote subnets
    // accessible via WolfNet or other tunnels.
    //
    // Filter through node_handles_route so the gateway node is included
    // even when the user pinned the route to a specific consumer node:
    // apply_subnet_route inspects each role internally and installs only
    // what's needed (kernel route on the consumer, forwarding plumbing
    // on the gateway). v20.11.6 fix — pre-fix the gateway was excluded
    // and never got the iptables/sysctl rules required for forwarding.
    let subnet_routes: Vec<_> = cfg.subnet_routes.iter()
        .filter(|r| r.enabled && node_handles_route(r, self_node_id))
        .collect();

    if !subnet_routes.is_empty() {
        for route in subnet_routes {
            // Startup: we don't carry "previous gateway" state across
            // process restart, so pass None. Idempotent if the kernel
            // already has our route; refuses if the kernel has someone
            // else's route for the same CIDR.
            match apply_subnet_route(route, None) {
                Ok(()) => {
                    tracing::info!(
                        "WolfRouter startup: subnet route applied: {} via {}",
                        route.subnet_cidr, route.gateway
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "WolfRouter startup: subnet route failed: {} via {}: {}",
                        route.subnet_cidr, route.gateway, e
                    );
                }
            }
        }
    }

    // Always sync the WolfNet CIDR table — even on nodes where this
    // node is neither consumer nor gateway, wolfnetd needs to know how
    // to encapsulate locally-originated traffic toward advertised
    // subnets (e.g. an app running on this box pinging into a remote
    // LAN exposed through another peer).
    sync_subnet_routes_to_wolfnet(&cfg.subnet_routes);

    // Final pass: validate every config item this node owns and stash
    // the report in router state. The Health tab's "Last validation"
    // banner reads from this; the watchdog refreshes it every 5 minutes.
    // Runs unconditionally — a node that "doesn't apply WolfRouter
    // here" still benefits from having an authoritative "yes, your
    // configs are sane" snapshot, especially when it's a pure subnet-
    // route gateway whose only WolfRouter config is the route itself.
    run_validation_and_store(&state, self_node_id);
}

/// Walk every config item this node owns and produce a [`ValidationReport`].
/// Called from `apply_on_startup` (at boot) and from the watchdog (every
/// 5 minutes). Read-only with respect to user data — never mutates
/// config; only inspects it against host state.
///
/// For LANs: defers to `health::lan_health` so we use the same checks
/// the per-LAN UI shows. Self-heal side effects (`ip addr add`, log
/// "bound to actual iface") DO run here — they're the same idempotent
/// safe fixes we'd do at apply time, and running them at startup means
/// `interface=br-lan / router_ip on ens1` configs come up healthy on
/// the very first boot after upgrade instead of waiting for the next
/// watchdog tick.
///
/// For WANs: link state, MASQUERADE rule presence (matches the
/// preflight checks at GET /api/router/preflight).
///
/// For zones: that the assigned interfaces exist on this host.
///
/// For firewall rules pinned to this node: that referenced LAN/Zone/VM
/// endpoints resolve (otherwise the rule no-ops silently in iptables).
pub fn validate_local_configs(state: &RouterState, self_node_id: &str) -> ValidationReport {
    let cfg = state.config.read().unwrap().clone();
    let mut findings: Vec<ValidationFinding> = Vec::new();

    // ── Host-level baseline checks ──────────────────────────────────
    // Run regardless of whether WolfRouter has any config items on this
    // node — without these, a fresh Proxmox node (has its own bridges
    // and routes but no WolfRouter LAN segments yet) would show as
    // "nothing to validate" which is misleading. These mirror the
    // checks GET /api/router/preflight runs but in `ValidationFinding`
    // shape so the cluster panel can show them in one place.
    //
    // Adam Cogswell 2026-04-29: "how can there be no lans configured?
    // even proxmox clusters have lans" — answer: Proxmox manages its
    // own bridges, and WolfRouter is the SDN layer on top. Until the
    // operator creates a WolfRouter LAN segment, there's nothing
    // WolfRouter-specific to validate. Showing host-level info here
    // makes the panel useful from the very first boot.
    {
        // IPv4 forwarding — required for any LAN/firewall routing to
        // do useful work. Proxmox/libvirt/Docker all need this on too.
        let forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        findings.push(ValidationFinding {
            category: "host",
            item_id: "ip_forward".into(),
            item_name: "IPv4 forwarding".into(),
            severity: if forward { "ok" } else { "warning" },
            message: if forward {
                "net.ipv4.ip_forward = 1 — host can route between interfaces.".into()
            } else {
                "net.ipv4.ip_forward = 0 — without this, ANY LAN segment, firewall rule, or container bridge that needs to route traffic between interfaces will silently drop packets.".into()
            },
        });

        // Default IPv4 route presence.
        let default_route = std::process::Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let first_route = default_route.lines().next().unwrap_or("").trim().to_string();
        findings.push(ValidationFinding {
            category: "host",
            item_id: "default_route".into(),
            item_name: "Default IPv4 route".into(),
            severity: if first_route.is_empty() { "warning" } else { "ok" },
            message: if first_route.is_empty() {
                "No default IPv4 route — this node can't reach the internet, and any LAN clients masqueraded through it will get host-unreachable.".into()
            } else {
                format!("Present: {}", first_route)
            },
        });

        // Non-loopback network interfaces. Useful presence signal for
        // a fresh node — confirms the host has its kernel networking
        // even before any WolfRouter config exists.
        let iface_count = std::fs::read_dir("/sys/class/net")
            .map(|d| d.filter_map(|e| e.ok())
                 .filter(|e| e.file_name() != "lo")
                 .count())
            .unwrap_or(0);
        let iface_names: Vec<String> = std::fs::read_dir("/sys/class/net")
            .map(|d| d.filter_map(|e| e.ok())
                 .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                 .filter(|n| n != "lo")
                 .collect())
            .unwrap_or_default();
        findings.push(ValidationFinding {
            category: "host",
            item_id: "interfaces".into(),
            item_name: "Network interfaces".into(),
            severity: if iface_count == 0 { "error" } else { "ok" },
            message: if iface_count == 0 {
                "No non-loopback interfaces found. This node has no usable networking.".into()
            } else {
                format!("{} non-loopback interface(s): {}", iface_count, iface_names.join(", "))
            },
        });

        // /etc/hosts — minimal sanity. Without a 127.0.0.1 line, every
        // local API call routed through "localhost" fails.
        let hosts_ok = std::fs::read_to_string("/etc/hosts")
            .map(|c| c.lines().any(|l| {
                let t = l.trim();
                !t.starts_with('#') && (t.starts_with("127.0.0.1") || t.starts_with("::1"))
            }))
            .unwrap_or(false);
        findings.push(ValidationFinding {
            category: "host",
            item_id: "hosts_loopback".into(),
            item_name: "/etc/hosts loopback entry".into(),
            severity: if hosts_ok { "ok" } else { "error" },
            message: if hosts_ok {
                "Loopback entry present.".into()
            } else {
                "/etc/hosts has no `127.0.0.1 localhost` line — local API calls through `localhost` will fail.".into()
            },
        });
    }

    // ── LANs ────────────────────────────────────────────────────────
    for lan in &cfg.lans {
        if lan.node_id != self_node_id { continue; }
        let report = health::lan_health(lan, self_node_id);
        let mut had_issue = false;
        for c in &report.checks {
            if c.ok { continue; }
            had_issue = true;
            findings.push(ValidationFinding {
                category: "lan",
                item_id: lan.id.clone(),
                item_name: lan.name.clone(),
                severity: match c.severity { "error" => "error", "warning" => "warning", _ => "warning" },
                message: format!("[{}] {}", c.name, c.message),
            });
        }
        if !had_issue {
            findings.push(ValidationFinding {
                category: "lan",
                item_id: lan.id.clone(),
                item_name: lan.name.clone(),
                severity: "ok",
                message: format!(
                    "All checks pass on '{}'.", lan.interface
                ),
            });
        }
    }

    // ── WAN connections ─────────────────────────────────────────────
    for w in &cfg.wan_connections {
        if w.node_id != self_node_id || !w.enabled { continue; }
        let iface_status = match &w.mode {
            wan::WanMode::Pppoe(_) => match wan::pppoe_status(w) {
                Some((iface, ip)) => Ok(format!("PPPoE up: {} ({})", iface, ip)),
                None => Err(format!("PPPoE link '{}' on {} is not up — pppd not running.", w.name, w.interface)),
            },
            wan::WanMode::Dhcp | wan::WanMode::Static(_) => {
                let assigned = dhcp::interface_addresses(&w.interface);
                if assigned.is_empty() {
                    Err(format!(
                        "WAN '{}': interface {} has no IPv4 address. Host's DHCP/static config didn't assign one.",
                        w.name, w.interface
                    ))
                } else {
                    Ok(format!("Link up: {} ({})", w.interface, assigned.join(",")))
                }
            }
        };
        match iface_status {
            Ok(msg) => findings.push(ValidationFinding {
                category: "wan", item_id: w.id.clone(), item_name: w.name.clone(),
                severity: "ok", message: msg,
            }),
            Err(msg) => findings.push(ValidationFinding {
                category: "wan", item_id: w.id.clone(), item_name: w.name.clone(),
                severity: "error", message: msg,
            }),
        }
    }

    // ── Zones ───────────────────────────────────────────────────────
    if let Some(node_zones) = cfg.zones.assignments.get(self_node_id) {
        for (iface, _zone) in node_zones {
            let exists = std::path::Path::new(&format!("/sys/class/net/{}", iface)).exists();
            if !exists {
                findings.push(ValidationFinding {
                    category: "zone",
                    item_id: iface.clone(),
                    item_name: iface.clone(),
                    severity: "warning",
                    message: format!(
                        "Zone assignment references interface '{}' which doesn't exist on this host. Firewall rules referencing this zone no-op silently.",
                        iface
                    ),
                });
            }
        }
    }

    // ── Firewall rules ──────────────────────────────────────────────
    // Cheap parse: only flag rules pinned to this node whose endpoints
    // can't resolve. Compiled rule output already includes a `# skipped`
    // comment in those cases, but operators rarely look at iptables-save
    // output — surfacing it here means they see the issue at boot.
    for rule in cfg.rules.iter().filter(|r|
        r.enabled && r.node_id.as_deref() == Some(self_node_id)
    ) {
        for (label, ep) in [("from", &rule.from), ("to", &rule.to)] {
            match ep {
                Endpoint::Lan { id } => {
                    if !cfg.lans.iter().any(|l| &l.id == id) {
                        findings.push(ValidationFinding {
                            category: "firewall",
                            item_id: rule.id.clone(),
                            item_name: rule.comment.clone(),
                            severity: "warning",
                            message: format!(
                                "Firewall rule '{}' references LAN id '{}' on its `{}` endpoint, but no such LAN exists. Rule no-ops.",
                                rule.id, id, label
                            ),
                        });
                    }
                }
                Endpoint::Interface { name } => {
                    if !std::path::Path::new(&format!("/sys/class/net/{}", name)).exists() {
                        findings.push(ValidationFinding {
                            category: "firewall",
                            item_id: rule.id.clone(),
                            item_name: rule.comment.clone(),
                            severity: "warning",
                            message: format!(
                                "Firewall rule '{}' references interface '{}' on its `{}` endpoint, but no such interface exists on this host.",
                                rule.id, name, label
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    let mut ok_count = 0u32;
    let mut warning_count = 0u32;
    let mut error_count = 0u32;
    for f in &findings {
        match f.severity {
            "ok" => ok_count += 1,
            "warning" => warning_count += 1,
            "error" => error_count += 1,
            _ => {}
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ValidationReport {
        generated_at: now,
        node_id: self_node_id.to_string(),
        ok_count, warning_count, error_count,
        findings,
    }
}

/// Run validation, store the result in router state, and log a summary
/// line. Idempotent — safe to call from startup and from the watchdog.
pub fn run_validation_and_store(state: &RouterState, self_node_id: &str) {
    let report = validate_local_configs(state, self_node_id);
    if report.error_count > 0 || report.warning_count > 0 {
        tracing::warn!(
            "WolfRouter validation: {} ok / {} warnings / {} errors across this node's configs",
            report.ok_count, report.warning_count, report.error_count
        );
        for f in &report.findings {
            if f.severity == "error" {
                tracing::error!(
                    "WolfRouter validation [{}/{}]: {}",
                    f.category, f.item_name, f.message
                );
            } else if f.severity == "warning" {
                tracing::warn!(
                    "WolfRouter validation [{}/{}]: {}",
                    f.category, f.item_name, f.message
                );
            }
        }
    } else {
        tracing::info!(
            "WolfRouter validation: all {} config item(s) on this node look healthy",
            report.ok_count
        );
    }
    *state.last_validation.write().unwrap() = Some(report);
}

/// Background dnsmasq watchdog. Every 60s, walks the LANs owned by this
/// node and re-applies any whose dnsmasq isn't running OR whose DNS port
/// isn't bound to router_ip. Per-LAN circuit breaker (see health::Breaker)
/// stops us looping on a permanently broken LAN.
///
/// Why this exists: WolfRouter dnsmasq is spawned by `dhcp::start` as a
/// detached daemon — there's no systemd unit to auto-restart it. Before
/// this watchdog, any silent crash of the per-LAN dnsmasq (kernel OOM,
/// iface flap that confuses bind-interfaces, an admin's `pkill dnsmasq`)
/// left the LAN with no DHCP/DNS until the next manual save-and-apply.
/// PapaSchlumpf's "DHCP works on Wednesday, broken on Friday" reports
/// were almost certainly a flavour of this.
pub fn spawn_dnsmasq_watchdog(state: std::sync::Arc<RouterState>, self_node_id: String) {
    std::thread::spawn(move || {
        // Stagger first tick: let apply_on_startup finish so we don't
        // race it on a fresh boot. 90s = first tick well after the
        // 3s-delayed startup apply has had a chance to settle.
        std::thread::sleep(std::time::Duration::from_secs(90));
        let mut tick: u64 = 0;
        loop {
            let lans: Vec<LanSegment> = {
                let cfg = state.config.read().unwrap();
                cfg.lans.iter()
                    .filter(|l| l.node_id == self_node_id)
                    .cloned()
                    .collect()
            };
            for lan in &lans {
                // Cheap probe: if both the process is alive AND :listen_port
                // is bound to router_ip, do nothing. The bind check uses
                // the same `ss -ulnp` parser the health endpoint uses.
                let healthy = health::dnsmasq_is_serving(lan);
                if healthy {
                    health::breaker_record_success(&lan.id);
                    continue;
                }
                if !health::breaker_allow_attempt(&lan.id) {
                    // Open breaker: skip until cooldown expires. The
                    // health panel surfaces the open state so the
                    // operator knows we've given up trying.
                    continue;
                }
                tracing::warn!(
                    "WolfRouter watchdog: LAN '{}' dnsmasq isn't serving — restarting.",
                    lan.name
                );
                match dhcp::start(lan) {
                    Ok(_) => {
                        health::breaker_record_success(&lan.id);
                        tracing::info!(
                            "WolfRouter watchdog: LAN '{}' dnsmasq restarted.",
                            lan.name
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "WolfRouter watchdog: LAN '{}' restart failed: {}",
                            lan.name, e
                        );
                        health::breaker_record_failure(&lan.id, &e);
                    }
                }
            }
            // Every 5th tick (~5 min) re-run the full config validation
            // pass and refresh `state.last_validation`. The cluster-wide
            // health endpoint reads this so operators see "configs are
            // still sane" / "this node has drifted" without each page
            // load triggering its own scan.
            tick = tick.wrapping_add(1);
            if tick % 5 == 0 {
                run_validation_and_store(&state, &self_node_id);
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
}

/// Background safe-mode tick — checks whether the rollback deadline has
/// elapsed without the user confirming, and reverts the firewall if so.
/// Spawn this once per process from main; it sleeps 1s between checks.
pub fn spawn_rollback_watcher(state: std::sync::Arc<RouterState>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            let deadline = *state.rollback_deadline.read().unwrap();
            if let Some(d) = deadline {
                if now >= d {
                    // Time's up — revert and clear the deadline.
                    let prev = state.last_applied_rules.read().unwrap().clone();
                    if let Some(p) = prev {
                        if let Err(e) = firewall::revert(&p) {
                            tracing::error!("WolfRouter safe-mode revert failed: {}", e);
                        } else {
                            tracing::warn!("WolfRouter safe-mode triggered: rules reverted");
                        }
                    }
                    *state.rollback_deadline.write().unwrap() = None;
                }
            }
        }
    });
}

// ─── Helpers used across submodules ───

/// Generate a short random ID for new rules/segments.
pub fn gen_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    format!("{}-{:x}", prefix, nanos & 0xFFFFFFFF)
}

/// Parse a CIDR into (network, prefix). Returns None on malformed input.
pub fn parse_cidr(cidr: &str) -> Option<(String, u32)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 { return None; }
    // Rough validation: four dotted octets.
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return None; }
    for p in &parts {
        let n: u32 = p.parse().ok()?;
        if n > 255 { return None; }
    }
    Some((ip.to_string(), prefix))
}

/// Apply a single subnet route to the kernel.
///
/// `previous_gateway`: when this is an UPDATE/edit, pass the gateway value
/// that WolfStack previously installed for this CIDR. The kernel doesn't
/// track ownership, so we use this to distinguish "the existing route is
/// ours, swap it" from "someone else owns the existing route, leave it
/// alone" (Codex P1, v20.11.2). Pass `None` for fresh creates and for
/// startup.
///
/// Behaviour:
///   • No existing kernel route → `ip route add`.
///   • Existing route's gateway == our new gateway → no-op (idempotent).
///   • Existing route's gateway == `previous_gateway` (ours, edited) →
///     `ip route replace` — atomic swap.
///   • Existing route's gateway is anything else → REFUSE. That route was
///     installed outside WolfStack (a VPN client, admin static, another
///     routing daemon); silently replacing it would break the operator.
///
/// `pub` because the API handlers (create/update) and the cluster replication
/// handler (config_receive) all need to apply at runtime — not just at
/// process startup. Prior to v20.11.2 only the startup path applied routes,
/// so newly-created routes never reached the kernel.
pub fn apply_subnet_route(route: &SubnetRoute, previous_gateway: Option<&str>) -> Result<(), String> {
    use std::process::Command;

    if parse_cidr(&route.subnet_cidr).is_none() {
        return Err(format!("Invalid subnet CIDR: {}", route.subnet_cidr));
    }
    if route.gateway.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("Invalid gateway IP: {}", route.gateway));
    }

    // Gateway-side dispatch (sponsor klasSponsor 2026-04-27, v20.11.6):
    // when this node OWNS the route's gateway IP, it's the forwarder —
    // packets arrive on its wolfnet0 from peers and need to be NAT'd out
    // to the LAN. Installing the route entry on this node would mean
    // `ip route add 10.10.0.0/16 via <my-own-wolfnet0-ip>`, which the
    // kernel rejects (and even if it accepted it, the route would loop
    // back into the same interface). All this node needs is the
    // forwarding plumbing — ip_forward, FORWARD ACCEPT, MASQUERADE.
    //
    // The previous version installed plumbing only on the configured
    // node (route_targets_self) — which is the consumer, where the
    // plumbing is a no-op. The gateway never got it, so packets reached
    // the LAN host but replies couldn't make it back. That's why
    // klasSponsor saw a green health check but `ping 10.10.10.10` failed.
    if node_is_route_gateway(route) {
        return enable_subnet_route_forwarding(route);
    }

    let existing = read_kernel_route_gateway(&route.subnet_cidr)
        .map_err(|e| format!("Failed to inspect existing route: {}", e))?;

    let route_result: Result<(), String> = match existing {
        // No route currently — install ours.
        None => {
            let output = Command::new("ip")
                .arg("route").arg("add")
                .arg(&route.subnet_cidr).arg("via").arg(&route.gateway)
                .output()
                .map_err(|e| format!("Failed to execute ip command: {}", e))?;
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // "File exists" here means the destination IS routed but
                // `read_kernel_route_gateway` couldn't parse the entry into
                // a `<dest> via <gw>` form — connected `dev` routes,
                // blackhole/unreachable, or a multipath. Refuse with a
                // clear error rather than recursing (Codex P1, v20.11.2).
                // A naive retry-on-File-exists would loop forever because
                // the parser would keep returning None.
                if stderr.contains("File exists") {
                    Err(format!(
                        "Route to {} already exists in an unsupported form (e.g. dev/blackhole/multipath). Inspect with `ip route show {}` and resolve before WolfStack can manage it.",
                        route.subnet_cidr, route.subnet_cidr
                    ))
                } else {
                    Err(format!("ip route add failed: {}", stderr.trim()))
                }
            }
        }
        // Already exactly what we want — no-op.
        Some(gw) if gw == route.gateway => Ok(()),
        // It's our previous entry — atomic swap with `ip route replace`.
        Some(gw) if previous_gateway.map_or(false, |pgw| pgw == gw) => {
            let output = Command::new("ip")
                .arg("route").arg("replace")
                .arg(&route.subnet_cidr).arg("via").arg(&route.gateway)
                .output()
                .map_err(|e| format!("Failed to execute ip command: {}", e))?;
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("ip route replace failed: {}", stderr.trim()))
            }
        }
        // Someone else owns this destination. Refuse.
        Some(gw) => Err(format!(
            "Route to {} already exists via {} (installed outside WolfStack). Refusing to overwrite — remove the existing route first if you want WolfStack to manage it.",
            route.subnet_cidr, gw
        )),
    };

    // Consumer role only here (gateway role short-circuited at top of
    // function). The consumer doesn't forward — it's just the source —
    // so it needs the kernel route entry but NO iptables/sysctl
    // plumbing. v20.11.5 installed plumbing on consumers too: it was
    // a harmless no-op (consumer's egress src IP is already wolfnet0's
    // IP, so MASQUERADE rewrites src to itself) but it caused a race on
    // gateway-changed updates where remove(old) would strip rules that
    // apply(new) had just put back. Plumbing belongs only on the gateway.
    route_result
}

/// Install the kernel-forwarding plumbing required for a subnet route to
/// actually pass traffic. Idempotent: every step checks for the existing
/// state before mutating, so calling this on every `apply_subnet_route`
/// is safe.
///
/// Steps:
///   1. sysctl ip_forward=1 (global) — kernel won't forward without it.
///   2. sysctl rp_filter=0 on wolfnet iface + all — loose mode so
///      WolfNet-sourced packets aren't dropped by reverse-path checks.
///   3. iptables FORWARD ACCEPT both ways between wolfnet iface and the
///      subnet — Docker/firewalld DROP defaults are otherwise fatal.
///   4. iptables NAT POSTROUTING MASQUERADE for traffic destined to the
///      subnet — so LAN hosts reply via their normal gateway instead of
///      trying to route back to a WolfNet peer they can't reach.
pub fn enable_subnet_route_forwarding(route: &SubnetRoute) -> Result<(), String> {
    use std::process::Command;

    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());

    // 1. ip_forward — fire-and-forget; sysctl returns non-zero in some
    //    locked-down containers, but if it's already 1 we don't care.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    // 2. rp_filter loose mode on wolfnet + all. /proc writes don't error
    //    if the file is already at the target value.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/rp_filter", wn_iface),
        "0",
    );
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    // Per-iface forwarding flag — global ip_forward implies all but some
    // distros gate per-iface via /proc/sys/net/ipv4/conf/<iface>/forwarding.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/forwarding", wn_iface),
        "1",
    );

    // 3. FORWARD ACCEPT both ways. We use -C to test for an existing
    //    rule before -I, so we don't duplicate on every reconcile. Errors
    //    on the -I are reported back to the caller (which logs them).
    let mut errors: Vec<String> = Vec::new();
    let forward_rules: [&[&str]; 2] = [
        &["-i", &wn_iface, "-d", &route.subnet_cidr, "-j", "ACCEPT"],
        &["-s", &route.subnet_cidr, "-o", &wn_iface, "-j", "ACCEPT"],
    ];
    for rule in &forward_rules {
        let mut check_args: Vec<&str> = vec!["-C", "FORWARD"];
        check_args.extend_from_slice(rule);
        let exists = Command::new("iptables")
            .args(&check_args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !exists {
            let mut add_args: Vec<&str> = vec!["-I", "FORWARD"];
            add_args.extend_from_slice(rule);
            let out = Command::new("iptables")
                .args(&add_args)
                .output()
                .map_err(|e| format!("iptables FORWARD insert exec failed: {}", e))?;
            if !out.status.success() {
                errors.push(format!(
                    "FORWARD {}: {}",
                    rule.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
    }

    // 4. POSTROUTING MASQUERADE for traffic destined into the subnet.
    //    We deliberately don't pin -o <egress>: the kernel routes the
    //    packet first, MASQUERADE then picks the egress iface's primary
    //    IP for the new source. -d <subnet> scopes the rule so we never
    //    masquerade unrelated traffic.
    let masq_check = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !masq_check {
        let out = Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"])
            .output()
            .map_err(|e| format!("iptables MASQUERADE exec failed: {}", e))?;
        if !out.status.success() {
            errors.push(format!(
                "POSTROUTING -d {} MASQUERADE: {}",
                route.subnet_cidr,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Snapshot of the kernel forwarding plumbing for a single subnet route —
/// inspected by the diagnostics endpoint so the operator can see WHY a
/// route is in the table but traffic isn't passing. Sponsor klasSponsor
/// (2026-04-27) reported "health says OK but ping doesn't work" because
/// pre-v20.11.4 we only checked the route entry, not the forwarding
/// plumbing it depends on.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForwardingState {
    /// Global net.ipv4.ip_forward value as a string ("1" / "0").
    pub ip_forward: Option<String>,
    /// rp_filter on the wolfnet iface (and on `all`); strict mode (1)
    /// silently drops WolfNet-sourced traffic in some topologies.
    pub rp_filter_wolfnet: Option<String>,
    pub rp_filter_all: Option<String>,
    /// True when iptables FORWARD has an ACCEPT rule for traffic from
    /// the wolfnet iface destined to the subnet.
    pub forward_in: bool,
    /// True when iptables FORWARD has an ACCEPT rule for return traffic
    /// from the subnet going back out the wolfnet iface.
    pub forward_out: bool,
    /// True when iptables NAT POSTROUTING has the MASQUERADE rule that
    /// rewrites WolfNet source IPs so the LAN host can reply normally.
    pub masquerade: bool,
    /// Wolfnet iface name we inspected against (for the operator to
    /// double-check the right interface was probed).
    pub wolfnet_iface: String,
    /// Egress interface the kernel would use to send a packet INTO the
    /// subnet from this node — derived from `ip route get <first IP in
    /// subnet>`. On the gateway this MUST be a LAN-side iface that's
    /// physically connected to the subnet; if it's the wolfnet iface
    /// we'd loop, and if it's the default-route iface the gateway has
    /// no actual path to the LAN. v22.0.2 — added after sponsor
    /// klasSponsor's diagnostics page went all-green but pings still
    /// failed because the gateway VPS had no LAN-side route to
    /// 10.10.0.0/16 (the WolfStack plumbing was correct; the gateway
    /// box itself wasn't physically wired into the LAN).
    pub subnet_egress_iface: Option<String>,
    /// Source IP the kernel would pick for that egress.
    pub subnet_egress_src: Option<String>,
}

/// Inspect the kernel forwarding state for a given subnet route. Pure
/// read — never mutates. Each field corresponds to one of the four
/// plumbing requirements `enable_subnet_route_forwarding` installs.
pub fn read_forwarding_state(route: &SubnetRoute) -> ForwardingState {
    use std::process::Command;
    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());

    let read = |path: &str| std::fs::read_to_string(path).ok().map(|s| s.trim().to_string());
    let ip_forward = read("/proc/sys/net/ipv4/ip_forward");
    let rp_filter_all = read("/proc/sys/net/ipv4/conf/all/rp_filter");
    let rp_filter_wolfnet = read(&format!("/proc/sys/net/ipv4/conf/{}/rp_filter", wn_iface));

    let check = |args: &[&str]| -> bool {
        Command::new("iptables")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    let forward_in = check(&["-C", "FORWARD", "-i", &wn_iface, "-d", &route.subnet_cidr, "-j", "ACCEPT"]);
    let forward_out = check(&["-C", "FORWARD", "-s", &route.subnet_cidr, "-o", &wn_iface, "-j", "ACCEPT"]);
    let masquerade = check(&["-t", "nat", "-C", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"]);

    // Probe how the kernel would actually send a packet into the subnet.
    // We run `ip route get` against a representative address (the network
    // address + 1, which is in-range for any sensible CIDR). The result
    // tells us the real egress iface and source IP — on the gateway,
    // anything other than a LAN-facing iface is a problem WolfStack's
    // four other checks can't detect.
    let (subnet_egress_iface, subnet_egress_src) = inspect_subnet_egress(&route.subnet_cidr);

    ForwardingState {
        ip_forward,
        rp_filter_wolfnet,
        rp_filter_all,
        forward_in,
        forward_out,
        masquerade,
        wolfnet_iface: wn_iface,
        subnet_egress_iface,
        subnet_egress_src,
    }
}

/// First usable address in a CIDR, suitable as a probe target for
/// `ip route get`. Returns None on malformed CIDR. For /24+ the network
/// address has a 0 last octet, so +1 is the conventional first host;
/// for narrower prefixes we'd hit edge cases, but those subnets
/// (a /31 or /32) aren't realistic destinations for subnet routing.
pub fn first_addr_in_cidr(cidr: &str) -> Option<String> {
    let (net, _prefix) = parse_cidr(cidr)?;
    let parts: Vec<u8> = net.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 { return None; }
    let last = parts[3].saturating_add(1);
    Some(format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], last))
}

/// Write the cluster's enabled SubnetRoutes to
/// /var/run/wolfnet/subnet-routes.json so wolfnetd can do longest-prefix
/// matching for packets it reads off the TUN. WITHOUT this file, the
/// kernel route on the consumer (`ip route add 10.10.0.0/16 via
/// <gw> dev wolfnet0`) is meaningless to userspace — TUN devices have
/// no link layer, so the kernel's "next-hop" hint is invisible to
/// wolfnetd, and packets destined for the advertised LAN either get
/// dropped (no peer matches the LAN IP) or sent to the first
/// auto-gateway peer (often the wrong one). Sponsor klasSponsor
/// 2026-04-28 hit exactly this — diagnostics all-green at the OS
/// level, but no ping replies because wolfnetd was dropping the
/// packets at the consumer side before encapsulation.
///
/// File format: { "<cidr>": "<gateway-wolfnet-ip>", ... }. Replaces
/// the file atomically (write + rename pattern not needed: small map,
/// single writer, wolfnetd reads on SIGHUP or 15s tick).
///
/// Sends SIGHUP to wolfnetd so the new map takes effect immediately
/// (same pattern as containers/mod.rs::flush_routes_to_disk).
pub fn sync_subnet_routes_to_wolfnet(routes: &[SubnetRoute]) {
    use std::process::Command;

    let map: std::collections::HashMap<String, String> = routes.iter()
        .filter(|r| r.enabled)
        .map(|r| (r.subnet_cidr.clone(), r.gateway.clone()))
        .collect();

    let path = "/var/run/wolfnet/subnet-routes.json";
    if let Err(e) = std::fs::create_dir_all("/var/run/wolfnet") {
        tracing::warn!("Failed to create /var/run/wolfnet: {}", e);
        return;
    }
    let json = match serde_json::to_string_pretty(&map) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("Failed to serialize subnet-routes.json: {}", e);
            return;
        }
    };
    if let Err(e) = std::fs::write(path, &json) {
        tracing::warn!("Failed to write {}: {}", path, e);
        return;
    }

    // SIGHUP wolfnetd so it reloads. Best-effort: if wolfnet isn't
    // running yet (e.g. we're applying config during early boot), the
    // 15s periodic reload will pick the file up later.
    if let Ok(output) = Command::new("pidof").arg("wolfnet").output() {
        let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !pid_str.is_empty() {
            let _ = Command::new("kill").args(["-HUP", &pid_str]).output();
        }
    }
}

/// Run `ip -4 route get <first-in-subnet>` and pull out the egress iface
/// + source IP. Returns (None, None) if anything failed (parse error,
/// command error, kernel said unreachable). Pure read.
fn inspect_subnet_egress(cidr: &str) -> (Option<String>, Option<String>) {
    use std::process::Command;
    let probe_ip = match first_addr_in_cidr(cidr) {
        Some(ip) => ip,
        None => return (None, None),
    };
    let out = Command::new("ip")
        .args(["-4", "route", "get", &probe_ip])
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return (None, None),
    };
    let text = String::from_utf8_lossy(&stdout);
    // Format examples:
    //   "10.10.0.1 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0 \n    cache"
    //   "10.10.0.1 dev wolfnet0 src 10.100.10.30 uid 0 \n    cache"
    // We walk tokens looking for "dev <X>" and "src <Y>".
    let mut iface = None;
    let mut src = None;
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        match tok {
            "dev" => iface = tokens.next().map(|s| s.to_string()),
            "src" => src = tokens.next().map(|s| s.to_string()),
            _ => {}
        }
    }
    (iface, src)
}

/// Tear down the iptables rules that `enable_subnet_route_forwarding`
/// installed. Idempotent: missing rules are not an error. We deliberately
/// leave sysctl knobs (ip_forward, rp_filter) alone — other WolfStack
/// features (wolfrun, WolfNet proxies, VM bridges) depend on them and
/// flipping them back to defaults would break unrelated traffic.
pub fn disable_subnet_route_forwarding(route: &SubnetRoute) -> Result<(), String> {
    use std::process::Command;

    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());

    // Loop on -D for each rule so duplicates (from older buggy versions
    // that lacked the -C guard) all get cleaned up. Cap the loop so a
    // pathological state can't spin forever.
    let forward_rules: [&[&str]; 2] = [
        &["-i", &wn_iface, "-d", &route.subnet_cidr, "-j", "ACCEPT"],
        &["-s", &route.subnet_cidr, "-o", &wn_iface, "-j", "ACCEPT"],
    ];
    for rule in &forward_rules {
        for _ in 0..16 {
            let mut args: Vec<&str> = vec!["-D", "FORWARD"];
            args.extend_from_slice(rule);
            let out = Command::new("iptables").args(&args).output();
            match out {
                Ok(o) if o.status.success() => continue, // try again — may be a duplicate
                _ => break,
            }
        }
    }

    for _ in 0..16 {
        let out = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"])
            .output();
        match out {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }

    Ok(())
}

/// Read the gateway of an existing kernel route for the given CIDR, if any.
/// Parses the first non-empty line of `ip route show <cidr>` looking for
/// `via <ip>`. Returns Ok(None) if no route exists, or if the format is
/// not the simple `<dest> via <ip> ...` shape we install ourselves
/// (multi-path routes, blackhole, unreachable, etc. — caller treats the
/// unparseable case conservatively).
fn read_kernel_route_gateway(cidr: &str) -> Result<Option<String>, String> {
    let raw = read_kernel_route_raw(cidr)?;
    Ok(parse_route_gateway(&raw))
}

/// Capture the raw stdout of `ip route show <cidr>`. Used both by the
/// gateway-extracting helper above and by the diagnostics endpoint, which
/// shows operators the unparsed output so they can reason about routes
/// that don't fit our `<dest> via <gw>` shape (dev-only, blackhole,
/// multipath).
pub fn read_kernel_route_raw(cidr: &str) -> Result<String, String> {
    use std::process::Command;
    let out = Command::new("ip")
        .arg("route")
        .arg("show")
        .arg(cidr)
        .output()
        .map_err(|e| format!("ip route show: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("ip route show failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Capture the entire IPv4 routing table — what `ip route` prints with
/// no arguments. Used by diagnostics so operators can see the full
/// kernel state when a configured route is missing.
pub fn read_kernel_route_table() -> Result<String, String> {
    use std::process::Command;
    let out = Command::new("ip")
        .arg("route")
        .output()
        .map_err(|e| format!("ip route: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("ip route failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Public alias for the parser so the diagnostics API can compose the
/// raw `ip route show` capture with our gateway-extraction logic without
/// re-running the command.
pub fn parse_kernel_route_gateway_for_diagnostics(raw: &str) -> Option<String> {
    parse_route_gateway(raw)
}

/// One kernel routing-table entry that *might* be a WolfStack route.
/// Used by orphan detection.
#[derive(Debug, Clone, Serialize)]
pub struct KernelRouteEntry {
    pub cidr: String,
    pub gateway: String,
    pub iface: String,
    pub raw: String,
}

/// Scan the kernel routing table for routes via the WolfNet interface
/// (or via a gateway in the WolfNet subnet) and return entries that
/// are NOT in the supplied configured-route set. These are "orphans"
/// — Klas's report (2026-05-04 13:50): "There is no way to remove an
/// orphaned subnet route".
///
/// How orphans happen:
///   * A route was installed by an older WolfStack version that didn't
///     remove it on subsequent config changes.
///   * The config replicated to a peer mid-edit and a later remove
///     never reached this node.
///   * An operator manually `ip route add`-ed something and forgot.
///   * A route was applied here but the config row was deleted via a
///     different node; the propagation arrived AFTER the apply path
///     ran on this node.
///
/// Match keys: (cidr, gateway). A configured route with the same
/// (cidr, gateway) cancels out the kernel entry from the orphan list.
/// Disabled routes and routes whose `node_id` doesn't match this node
/// still cancel — the operator turning a route off shouldn't surface
/// it as an orphan; if it's still in the kernel that's the apply
/// path's bug, not an orphan.
pub fn list_orphan_subnet_routes(configured: &[SubnetRoute]) -> Vec<KernelRouteEntry> {
    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".into());

    let configured_set: std::collections::HashSet<(String, String)> = configured.iter()
        .map(|r| (r.subnet_cidr.trim().to_string(), r.gateway.trim().to_string()))
        .collect();

    let raw = match read_kernel_route_table() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut orphans: Vec<KernelRouteEntry> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }

        // First whitespace-separated token is the destination — either
        // "default" or "<cidr>". We only care about CIDR-shaped dests
        // because WolfStack subnet routes always have a /N.
        let mut tokens = line.split_whitespace();
        let cidr = match tokens.next() {
            Some("default") => continue,
            Some(t) if t.contains('/') => t.to_string(),
            _ => continue,
        };

        let mut gw: Option<String> = None;
        let mut iface: Option<String> = None;
        let mut iter = tokens;
        while let Some(t) = iter.next() {
            match t {
                "via" => gw = iter.next().map(|s| s.to_string()),
                "dev" => iface = iter.next().map(|s| s.to_string()),
                _ => {}
            }
        }

        // Only consider routes that go through wolfnet — anything else
        // isn't WolfStack's concern.
        let is_wolfnet_route = iface.as_deref() == Some(wn_iface.as_str());
        if !is_wolfnet_route { continue; }

        let gw = match gw {
            Some(g) => g,
            None => continue, // dev-only route (no via) — not an orphan we'd touch
        };

        // Cancel against config.
        if configured_set.contains(&(cidr.clone(), gw.clone())) { continue; }

        orphans.push(KernelRouteEntry {
            cidr,
            gateway: gw,
            iface: iface.unwrap_or_default(),
            raw: line.to_string(),
        });
    }
    orphans
}

/// Force-remove a kernel route by `ip route del <cidr> via <gateway>`.
/// Used by the orphan-cleanup endpoint. Verifies the kernel route
/// matches what the caller asked for before deleting — if a different
/// gateway has taken over since the orphan was listed, refuse the
/// delete and let the operator see the conflict.
pub fn remove_orphan_kernel_route(cidr: &str, expected_gateway: &str) -> Result<(), String> {
    use std::process::Command;

    // Sanity-check the inputs — they came from operator input via the
    // API, even if filtered through `list_orphan_subnet_routes`.
    // Reject anything that isn't a plain CIDR / IPv4.
    if !cidr.contains('/') {
        return Err(format!("not a CIDR: {}", cidr));
    }
    if expected_gateway.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("not an IPv4 gateway: {}", expected_gateway));
    }

    // Re-read the current kernel route — refuse if it doesn't match
    // the expected gateway. Same defence as remove_subnet_route uses
    // for the configured-route path; we won't blindly delete a route
    // whose gateway has been replaced under us.
    match read_kernel_route_gateway(cidr) {
        Ok(None) => return Ok(()), // already gone, idempotent
        Ok(Some(gw)) if gw != expected_gateway => {
            return Err(format!(
                "kernel route for {} currently uses gateway {} (expected {}); refusing to delete to avoid breaking another tool's route",
                cidr, gw, expected_gateway
            ));
        }
        Ok(Some(_)) => {}
        Err(e) => return Err(format!("could not read kernel state for {}: {}", cidr, e)),
    }

    let out = Command::new("ip")
        .args(["route", "del", cidr])
        .output()
        .map_err(|e| format!("ip route del: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // "No such process" is the kernel saying the route is already
        // gone — idempotent success.
        if stderr.contains("No such process") || stderr.contains("does not exist") {
            return Ok(());
        }
        return Err(format!("ip route del {} failed: {}", cidr, stderr));
    }
    Ok(())
}

/// Extract the `via <gw>` from the first non-empty line of an `ip route
/// show` capture. Returns None when the format is not our simple `<dest>
/// via <ip> ...` shape (dev-only, blackhole, multipath).
fn parse_route_gateway(raw: &str) -> Option<String> {
    let line = raw.lines().find(|l| !l.trim().is_empty())?;
    let mut tokens = line.split_whitespace();
    while let Some(t) = tokens.next() {
        if t == "via" {
            if let Some(gw) = tokens.next() {
                if gw.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Some(gw.to_string());
                }
            }
        }
    }
    None
}

/// Remove a subnet route from the kernel via `ip route del`.
///
/// Idempotent: "No such process" / "does not exist" are treated as success.
///
/// Codex P1 (v20.11.2): we ALSO check that the kernel route's gateway still
/// matches `route.gateway` before deleting. If the kernel currently has a
/// different gateway for the same destination, that route was installed by
/// something outside WolfStack (or replaced after our state diverged) — we
/// must not delete it, or we'd break the operator's connectivity.
pub fn remove_subnet_route(route: &SubnetRoute) -> Result<(), String> {
    use std::process::Command;

    // Gateway-side dispatch (mirrors apply_subnet_route, v20.11.6): if
    // this node OWNS the gateway IP we never installed a kernel route
    // entry — only the forwarding plumbing. Strip that and we're done.
    if node_is_route_gateway(route) {
        return disable_subnet_route_forwarding(route);
    }

    // Consumer role: only a kernel route entry to remove. We never
    // installed plumbing on the consumer (post-v20.11.6) so there's
    // nothing to clean on the iptables side. Older versions (v20.11.5)
    // did install plumbing here — the next gateway-side apply will
    // replace those rules and any leftover consumer rules are harmless
    // (MASQUERADE -d <subnet> on a non-forwarding node is a no-op).
    match read_kernel_route_gateway(&route.subnet_cidr) {
        Ok(None) => return Ok(()),
        Ok(Some(gw)) if gw != route.gateway => {
            tracing::warn!(
                "remove_subnet_route: kernel route for {} now uses gateway {} (we expected {}); leaving it in place",
                route.subnet_cidr, gw, route.gateway
            );
            return Ok(());
        }
        Ok(Some(_)) => { /* matches — proceed with del */ }
        Err(e) => {
            // If the inspect failed, fall through to a conservative del
            // attempt with explicit `via` so we only target our entry.
            tracing::warn!("remove_subnet_route: pre-check failed: {} — attempting targeted del", e);
        }
    }

    let output = Command::new("ip")
        .arg("route")
        .arg("del")
        .arg(&route.subnet_cidr)
        .arg("via")
        .arg(&route.gateway)
        .output()
        .map_err(|e| format!("Failed to execute ip command: {}", e))?;

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such process") || stderr.contains("does not exist") {
        return Ok(());
    }
    Err(format!("ip route del failed: {}", stderr.trim()))
}

/// True when this node owns the wolfnet0 address listed as the route's
/// gateway. The gateway-owning node is the forwarder — its wolfnet0
/// receives packets from peers, and its LAN interface delivers them to
/// the destination subnet. We install iptables/sysctl plumbing on the
/// forwarder rather than a kernel route entry (an `ip route add ... via
/// <my-own-ip>` is rejected by the kernel and would loop anyway).
///
/// Implementation: shells out to `ip -4 addr show <wolfnet-iface>` and
/// scans for `inet <addr>/...` lines. We don't cache because wolfnet0
/// addresses can change at runtime when WolfNet reconfigures, and this
/// is called only from apply/remove paths and the diagnostics endpoint.
pub fn node_is_route_gateway(route: &SubnetRoute) -> bool {
    use std::process::Command;
    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());
    let out = match Command::new("ip")
        .args(["-4", "addr", "show", &wn_iface])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        let rest = match trimmed.strip_prefix("inet ") {
            Some(r) => r,
            None => continue,
        };
        let addr_with_prefix = match rest.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let addr = addr_with_prefix.split('/').next().unwrap_or("");
        if addr == route.gateway {
            return true;
        }
    }
    false
}

/// True when this node has any role to play in installing a subnet route
/// — either as a configured target (it gets the kernel route entry) or
/// as the gateway (it gets the forwarding plumbing). All apply/remove
/// call sites filter through this so the gateway never gets skipped.
pub fn node_handles_route(route: &SubnetRoute, self_node_id: &str) -> bool {
    route_targets_self(route, self_node_id) || node_is_route_gateway(route)
}

/// True when the route should be installed on the node identified by
/// `self_node_id`. Encapsulates the "None == cluster-wide, Some(id) == that
/// node only" rule so all callers (startup, create, update, config_receive)
/// agree.
pub fn route_targets_self(route: &SubnetRoute, self_node_id: &str) -> bool {
    route.node_id.is_none() || route.node_id.as_deref() == Some(self_node_id)
}
