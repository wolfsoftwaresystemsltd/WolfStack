// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Cluster-wide HTTP service discovery.
//!
//! Walks every WolfNet IP that the cluster routes to (the keys of
//! /var/run/wolfnet/routes.json plus the local host's WolfNet IP) and
//! probes a curated list of common HTTP/HTTPS ports. For every endpoint
//! that responds, sniffs the page title and Server header to identify
//! well-known apps (PBS, Plex, *arr, Grafana, Portainer, Home Assistant,
//! WolfStack itself, etc.) and persists the result to
//! /etc/wolfstack/cluster-services.json.
//!
//! The Cluster Browser feature uses this list to render its homepage —
//! so the user lands in a browser running inside the cluster with a
//! grid of click-to-open service cards.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Auto-discovered services — shared across all WolfStack users on this
/// node. Rewritten by every sweep.
const DISCOVERED_FILE: &str = "/etc/wolfstack/cluster-services-discovered.json";
/// Per-user pinned URLs go under this dir as `<sanitised-username>.json`.
/// Splitting from the discovery file means a user's pinned services
/// don't show up in another user's UI, and it survives discovery sweeps
/// rewriting the discovered list.
const MANUAL_DIR: &str = "/etc/wolfstack/cluster-services-by-user";

/// Backwards-compat: pre-v17.0.6 wrote everything (discovered +
/// manual) into one shared file. Read it once on first sweep so an
/// upgrade doesn't lose anyone's pinned URLs — they get migrated into
/// a special "_legacy" user file the first time the sweep runs.
const LEGACY_SHARED_FILE: &str = "/etc/wolfstack/cluster-services.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    /// Stable ID computed from host:port — used as URL fragment in the UI.
    pub id: String,
    /// Friendly display name, identified from the response or generic.
    pub name: String,
    /// Full URL — what the cluster browser opens when the user clicks.
    pub url: String,
    pub host_ip: String,
    pub port: u16,
    pub scheme: String,           // "http" or "https"
    /// Loose category for UI grouping (e.g. "Backup", "Media", "Monitoring").
    pub category: String,
    /// Emoji icon. Plain unicode keeps the homepage HTML cheap.
    pub icon: String,
    /// Whether this entry was added manually by an admin (won't be removed
    /// by the auto-discovery sweep when no longer responding).
    #[serde(default)]
    pub manual: bool,
    /// Unix epoch seconds of the last successful probe.
    pub last_seen: u64,
}

/// Curated probe list. Picked for high signal — well-known web apps that
/// people actually run on a homelab cluster. Add liberally; each port
/// adds one TCP attempt per WolfNet IP per discovery pass (cheap with a
/// 2 s timeout).
const PROBE_PORTS: &[(u16, &str)] = &[
    (80,    "http"),
    (443,   "https"),
    (3000,  "http"),   // Grafana, Outline
    (3001,  "http"),   // Uptime Kuma
    (5000,  "http"),   // dev / Synology Web Station
    (5601,  "http"),   // Kibana
    (7474,  "http"),   // Neo4j browser
    (7878,  "http"),   // Radarr
    (8000,  "http"),   // generic dev
    (8006,  "https"),  // Proxmox VE
    (8007,  "https"),  // Proxmox Backup Server
    (8080,  "http"),   // Tomcat / Jenkins / many
    (8081,  "http"),   // Sonarr alt / Nexus
    (8090,  "http"),   // Confluence
    (8096,  "http"),   // Jellyfin
    (8112,  "http"),   // Deluge
    (8123,  "http"),   // Home Assistant
    (8200,  "http"),   // Vault
    (8443,  "https"),  // generic HTTPS
    (8553,  "https"),  // WolfStack itself
    (8888,  "http"),   // Jupyter
    (8989,  "http"),   // Sonarr
    (9000,  "http"),   // Portainer
    (9090,  "http"),   // Prometheus / Cockpit
    (9443,  "https"),  // Portainer HTTPS
    (9696,  "http"),   // Prowlarr
    (32400, "http"),   // Plex
];

/// In-memory cache of the most recent auto-discovery sweep.
/// Manual per-user entries are NOT cached here — they're loaded from
/// disk on demand so we don't need a per-user cache invalidation path.
static LAST_DISCOVERED: Mutex<Vec<DiscoveredService>> = Mutex::new(Vec::new());

/// Auto-discovered services only (shared). Doesn't include any user's
/// pinned manual URLs — call list_for_user for that.
pub fn cached() -> Vec<DiscoveredService> {
    LAST_DISCOVERED.lock().unwrap().clone()
}

pub fn load_discovered_from_disk() -> Vec<DiscoveredService> {
    std::fs::read_to_string(DISCOVERED_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_discovered(services: &[DiscoveredService]) {
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    if let Ok(json) = serde_json::to_string_pretty(services) {
        let _ = std::fs::write(DISCOVERED_FILE, json);
    }
}

fn sanitise_user(user: &str) -> String {
    user.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

fn manual_file_for(user: &str) -> String {
    format!("{}/{}.json", MANUAL_DIR, sanitise_user(user))
}

fn load_manual_for(user: &str) -> Vec<DiscoveredService> {
    std::fs::read_to_string(manual_file_for(user))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_manual_for(user: &str, services: &[DiscoveredService]) -> Result<(), String> {
    std::fs::create_dir_all(MANUAL_DIR).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(services).map_err(|e| e.to_string())?;
    std::fs::write(manual_file_for(user), json).map_err(|e| e.to_string())
}

/// Discovered services + the given user's pinned manual URLs.
/// Used by the WolfStack UI when an authenticated user lists services.
pub fn list_for_user(user: &str) -> Vec<DiscoveredService> {
    let mut out = cached();
    out.extend(load_manual_for(user));
    out
}

pub fn id_for(ip: &str, port: u16) -> String {
    format!("{}-{}", ip.replace('.', "-"), port)
}

/// All WolfNet IPs we know about, gathered from three sources:
///  1. routes.json keys: container/VM WolfNet IPs known to wolfnetd
///  2. routes.json values: host WolfNet IPs that own those containers
///  3. /etc/wolfnet/config.toml peers: every WolfNet member, including
///     hosts that have no containers (would otherwise be invisible to
///     discovery — bare WolfStack nodes running services natively, NAS
///     boxes joined as WolfNet satellites, etc.)
///  4. The local host's own WolfNet IP
fn all_wolfnet_ips() -> HashSet<String> {
    let mut ips = HashSet::new();
    if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json") {
        if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&content) {
            for (k, v) in map {
                ips.insert(k);
                ips.insert(v);
            }
        }
    }
    // WolfNet peer table — covers hosts even when they have no containers.
    if let Ok(content) = std::fs::read_to_string("/etc/wolfnet/config.toml") {
        if let Ok(toml_val) = content.parse::<toml::Value>() {
            if let Some(peers) = toml_val.get("peers").and_then(|p| p.as_array()) {
                for peer in peers {
                    if let Some(ip) = peer.get("allowed_ip").and_then(|v| v.as_str()) {
                        if !ip.is_empty() {
                            ips.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }
    if let Some(local) = local_wolfnet_ip() {
        ips.insert(local);
    }
    ips
}

fn local_wolfnet_ip() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "wolfnet0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.contains("inet "))
        .and_then(|l| l.trim().split_whitespace().nth(1))
        .and_then(|s| s.split('/').next())
        .map(|s| s.to_string())
}

/// Sniff the response body's <title> tag. Limited to first 64 KB so a
/// huge JS-app payload doesn't make us read megabytes per probe.
fn extract_title(body: &str) -> Option<String> {
    let body = if body.len() > 65_536 { &body[..65_536] } else { body };
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = &body[start..];
    let close_open = after.find('>')?;
    let rest = &after[close_open + 1..];
    let end = rest.to_ascii_lowercase().find("</title>")?;
    let title = rest[..end].trim().to_string();
    if title.is_empty() { None } else { Some(title) }
}

/// Identify a service from its title + Server header. Returns
/// (friendly_name, icon, category). Falls back to a generic
/// "Web service" when nothing matches.
fn identify(title: Option<&str>, server: Option<&str>) -> (String, &'static str, &'static str) {
    let hay = format!(
        "{} {}",
        title.unwrap_or("").to_ascii_lowercase(),
        server.unwrap_or("").to_ascii_lowercase()
    );
    let m = |needle: &str| hay.contains(needle);

    if m("proxmox backup") { return ("Proxmox Backup Server".into(), "💾", "Backup"); }
    if m("proxmox virtual environment") || m("proxmox ve") {
        return ("Proxmox VE".into(), "🖥️", "Virtualisation");
    }
    if m("plex") { return ("Plex".into(), "🎬", "Media"); }
    if m("jellyfin") { return ("Jellyfin".into(), "🎬", "Media"); }
    if m("sonarr") { return ("Sonarr".into(), "📺", "Media"); }
    if m("radarr") { return ("Radarr".into(), "🎞️", "Media"); }
    if m("prowlarr") { return ("Prowlarr".into(), "🔎", "Media"); }
    if m("lidarr") { return ("Lidarr".into(), "🎵", "Media"); }
    if m("readarr") { return ("Readarr".into(), "📚", "Media"); }
    if m("bazarr") { return ("Bazarr".into(), "💬", "Media"); }
    if m("grafana") { return ("Grafana".into(), "📊", "Monitoring"); }
    if m("prometheus") { return ("Prometheus".into(), "📈", "Monitoring"); }
    if m("uptime kuma") { return ("Uptime Kuma".into(), "🟢", "Monitoring"); }
    if m("portainer") { return ("Portainer".into(), "🐳", "Containers"); }
    if m("home assistant") { return ("Home Assistant".into(), "🏠", "Home"); }
    if m("vaultwarden") || m("bitwarden") { return ("Vaultwarden".into(), "🔐", "Security"); }
    if m("nextcloud") { return ("Nextcloud".into(), "☁️", "Productivity"); }
    if m("gitea") || m("forgejo") { return ("Gitea/Forgejo".into(), "🐙", "Dev"); }
    if m("jenkins") { return ("Jenkins".into(), "🤖", "Dev"); }
    if m("nexus repository") { return ("Nexus".into(), "📦", "Dev"); }
    if m("kibana") { return ("Kibana".into(), "🔍", "Monitoring"); }
    if m("neo4j") { return ("Neo4j".into(), "🕸️", "Database"); }
    if m("jupyter") { return ("Jupyter".into(), "📓", "Dev"); }
    if m("vault") { return ("HashiCorp Vault".into(), "🔐", "Security"); }
    if m("wolfstack") { return ("WolfStack".into(), "🐺", "WolfStack"); }
    if m("cockpit") { return ("Cockpit".into(), "⚙️", "Server"); }
    if m("deluge") { return ("Deluge".into(), "🌧️", "Media"); }
    if m("transmission") { return ("Transmission".into(), "📥", "Media"); }
    if m("qbittorrent") || m("qbt") { return ("qBittorrent".into(), "📥", "Media"); }
    if m("synology") { return ("Synology DSM".into(), "📦", "Storage"); }

    // Generic fallback — at least we know it's a web service.
    ("Web service".into(), "🌐", "Other")
}

/// Probe a single host:port. 2 s timeout — most responsive services
/// answer in under 100 ms; missing services timeout but don't pile up.
fn probe(ip: &str, port: u16, scheme: &str) -> Option<DiscoveredService> {
    let url = format!("{}://{}:{}/", scheme, crate::netaddr::bracket_host(ip), port);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        // Cluster web apps almost always have self-signed or PVE certs.
        // Skip verification — we're just identifying, not transferring secrets.
        .danger_accept_invalid_certs(true)
        // Don't follow redirects — many apps redirect / to a long path
        // we don't care about; we just need any non-error response.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let resp = client.get(&url).send().ok()?;
    let status = resp.status().as_u16();
    // Treat 2xx, 3xx, 401, 403 as "service is here" — auth-protected
    // endpoints and redirects still mean something is listening that
    // we want to render as a card.
    let serving = (200..400).contains(&status) || status == 401 || status == 403;
    if !serving { return None; }
    let server = resp.headers().get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = resp.text().unwrap_or_default();
    let title = extract_title(&body);

    let (name, icon, category) = identify(title.as_deref(), server.as_deref());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    Some(DiscoveredService {
        id: id_for(ip, port),
        name: name.clone(),
        url: format!("{}://{}:{}", scheme, crate::netaddr::bracket_host(ip), port),
        host_ip: ip.to_string(),
        port,
        scheme: scheme.to_string(),
        category: category.to_string(),
        icon: icon.to_string(),
        manual: false,
        last_seen: now,
    })
}

/// Run one full discovery sweep across every known WolfNet IP × the
/// curated port list. Persists results to the shared discovered file
/// (manual per-user entries live separately and aren't touched here).
pub fn run_sweep() {
    migrate_legacy_if_present();

    let ips = all_wolfnet_ips();
    if ips.is_empty() {
        debug!("services_discovery: no WolfNet IPs known yet, skipping sweep");
        return;
    }
    info!("services_discovery: sweeping {} WolfNet IPs × {} ports", ips.len(), PROBE_PORTS.len());

    let mut found: Vec<DiscoveredService> = Vec::new();
    for ip in &ips {
        for (port, scheme) in PROBE_PORTS {
            if let Some(svc) = probe(ip, *port, scheme) {
                found.push(svc);
            }
        }
    }

    info!("services_discovery: found {} auto-discovered services", found.len());
    save_discovered(&found);
    *LAST_DISCOVERED.lock().unwrap() = found;
}

/// One-shot upgrade path: if pre-v17.0.6 cluster-services.json exists,
/// split it into the new auto-discovered + a "_legacy" user manual file
/// so admins don't lose their pinned URLs across the upgrade. The
/// legacy file is renamed to `.migrated` so we don't re-run this every
/// sweep.
fn migrate_legacy_if_present() {
    let legacy = std::path::Path::new(LEGACY_SHARED_FILE);
    if !legacy.exists() { return; }
    let content = match std::fs::read_to_string(legacy) {
        Ok(c) => c,
        Err(_) => return,
    };
    let entries: Vec<DiscoveredService> = match serde_json::from_str(&content) {
        Ok(e) => e,
        Err(_) => return,
    };
    let (auto, manual): (Vec<_>, Vec<_>) = entries.into_iter().partition(|s| !s.manual);
    if !auto.is_empty() { save_discovered(&auto); }
    if !manual.is_empty() {
        // Park them under a "_legacy" user — admins can copy/re-add to
        // their own account from there. Doesn't auto-attribute, since
        // the old file had no user info.
        let _ = save_manual_for("_legacy", &manual);
    }
    let renamed = format!("{}.migrated", LEGACY_SHARED_FILE);
    let _ = std::fs::rename(legacy, renamed);
    info!("services_discovery: migrated legacy cluster-services.json — manual entries parked under user '_legacy'");
}

/// Pin a manual entry against `user`. Stored at
/// /etc/wolfstack/cluster-services-by-user/<user>.json so other users
/// don't see this user's pinned URLs in their lists.
pub fn add_manual_for_user(user: &str, name: String, url: String, icon: String, category: String) -> Result<DiscoveredService, String> {
    let parsed = reqwest::Url::parse(&url).map_err(|e| format!("Invalid URL: {}", e))?;
    let host = parsed.host_str().ok_or("URL has no host")?.to_string();
    let port = parsed.port_or_known_default().ok_or("URL has no port")?;
    let scheme = parsed.scheme().to_string();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let svc = DiscoveredService {
        id: id_for(&host, port),
        name,
        url,
        host_ip: host,
        port,
        scheme,
        category,
        icon: if icon.is_empty() { "🌐".to_string() } else { icon },
        manual: true,
        last_seen: now,
    };
    let mut current = load_manual_for(user);
    current.retain(|s| s.id != svc.id);
    current.push(svc.clone());
    save_manual_for(user, &current)?;
    Ok(svc)
}

/// Remove a pinned entry from `user`'s file. Won't touch other users'
/// pinned entries with the same id, and won't touch auto-discovered
/// entries (those come back on the next sweep anyway).
pub fn remove_manual_for_user(user: &str, id: &str) -> bool {
    let mut current = load_manual_for(user);
    let before = current.len();
    current.retain(|s| s.id != id);
    if current.len() == before { return false; }
    save_manual_for(user, &current).ok();
    true
}

/// Restore the on-disk cache into memory at daemon startup so the first
/// API call after a restart returns the previous sweep's results
/// immediately, rather than an empty list. Discovery now runs purely on
/// demand (triggered by the Cluster Browser page load via the /sweep
/// endpoint), so there's no periodic loop to spawn.
pub fn restore_cache() {
    let initial = load_discovered_from_disk();
    *LAST_DISCOVERED.lock().unwrap() = initial;
}

/// Group services by category. Pass the requesting user to include
/// their pinned manual entries; pass an empty string for auto-discovered
/// only (used by the unauth /cluster-home renderer when no user
/// query-param was provided).
pub fn grouped_for(user: &str) -> Vec<(String, Vec<DiscoveredService>)> {
    let services = if user.is_empty() {
        cached()
    } else {
        list_for_user(user)
    };
    if services.is_empty() {
        return Vec::new();
    }
    let mut order: Vec<String> = Vec::new();
    let mut buckets: HashMap<String, Vec<DiscoveredService>> = HashMap::new();
    for s in services {
        if !buckets.contains_key(&s.category) {
            order.push(s.category.clone());
        }
        buckets.entry(s.category.clone()).or_default().push(s);
    }
    order.into_iter()
        .map(|cat| {
            let mut entries = buckets.remove(&cat).unwrap_or_default();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            (cat, entries)
        })
        .collect()
}

#[allow(dead_code)]
fn warn_unused() { warn!("unused"); }
