// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Status Page — built-in uptime monitoring with public-facing status pages
//!
//! Supports **multiple status pages**, each with:
//! - A unique slug (e.g. `/status/wolfgrid`, `/status/wolfterritories`)
//! - Its own title, branding, and set of services
//! - Global pool of monitors (HTTP, TCP, Ping, Container) shared across pages
//! - Automatic incident management per page
//! - 90-day uptime history with daily aggregation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

const CONFIG_FILE: &str = "/etc/wolfstack/statuspage.json";

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckType {
    Http {
        url: String,
        #[serde(default = "default_expected_status")]
        expected_status: u16,
    },
    Tcp {
        host: String,
        port: u16,
    },
    Ping {
        host: String,
    },
    Container {
        runtime: String, // "docker" or "lxc"
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<String>,
    },
    Wolfrun {
        service_id: String,
        #[serde(default)]
        service_name: String,
        #[serde(default = "default_min_healthy")]
        min_healthy: u32,
        #[serde(default = "default_health_check")]
        health_check: String,
    },
}

fn default_min_healthy() -> u32 { 1 }
fn default_health_check() -> String { "running".to_string() }

fn default_expected_status() -> u16 { 200 }
fn default_interval() -> u64 { 60 }
fn default_timeout() -> u64 { 10 }

/// A health check monitor — shared globally, referenced by services across pages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Monitor {
    pub id: String,
    pub name: String,
    pub check: CheckType,
    pub cluster: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Investigating,
    Identified,
    Monitoring,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentUpdate {
    pub timestamp: String,
    pub status: IncidentStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub status: IncidentStatus,
    pub cluster: String,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub service_ids: Vec<String>,
    #[serde(default)]
    pub updates: Vec<IncidentUpdate>,
    pub created_at: String,
    #[serde(default)]
    pub resolved_at: Option<String>,
    #[serde(default)]
    pub auto_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub timestamp: u64,
    pub success: bool,
    pub latency_ms: u32,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUptime {
    pub date: String, // YYYY-MM-DD
    pub total_checks: u32,
    pub successful_checks: u32,
    pub uptime_percent: f32,
}

/// A single status page — one of potentially many
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPage {
    pub id: String,
    /// URL slug — the page is served at /status/{slug}
    pub slug: String,
    pub title: String,
    pub cluster: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub footer_text: Option<String>,
    /// Theme for the public status page (dark, light, midnight, datacenter, forest, amber, glass, deepred)
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub monitor_ids: Vec<String>,
    #[serde(default)]
    pub incident_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ═══════════════════════════════════════════════
// ─── Configuration ───
// ═══════════════════════════════════════════════

/// Top-level configuration: global monitors + multiple status pages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPageConfig {
    /// Global pool of monitors (shared across all pages)
    #[serde(default)]
    pub monitors: Vec<Monitor>,
    /// Global pool of incidents (shared across all pages)
    #[serde(default)]
    pub incidents: Vec<Incident>,
    /// Multiple status pages, each with their own slug, monitors, incidents
    #[serde(default)]
    pub pages: Vec<StatusPage>,
}

impl Default for StatusPageConfig {
    fn default() -> Self {
        Self {
            monitors: Vec::new(),
            incidents: Vec::new(),
            pages: Vec::new(),
        }
    }
}

impl StatusPageConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_FILE) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let _ = std::fs::create_dir_all("/etc/wolfstack");
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_FILE, json).map_err(|e| e.to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── Shared State ───
// ═══════════════════════════════════════════════

/// Maximum recent results to keep per monitor (1440 = ~24h at 1/min)
const MAX_RESULTS: usize = 1440;
/// Maximum daily uptime entries (90 days)
const MAX_DAILY_ENTRIES: usize = 90;

pub struct StatusPageState {
    pub config: RwLock<StatusPageConfig>,
    /// Recent check results per monitor ID
    pub results: RwLock<HashMap<String, VecDeque<CheckResult>>>,
    /// Daily uptime aggregation per monitor ID
    pub daily_uptime: RwLock<HashMap<String, VecDeque<DailyUptime>>>,
}

impl StatusPageState {
    pub fn new() -> Self {
        let config = StatusPageConfig::load();
        let daily_uptime = Self::load_daily_uptime();

        Self {
            config: RwLock::new(config),
            results: RwLock::new(HashMap::new()),
            daily_uptime: RwLock::new(daily_uptime),
        }
    }

    /// Get current status for a specific monitor
    pub fn monitor_status(&self, monitor_id: &str) -> MonitorStatus {
        let results = self.results.read().unwrap();
        match results.get(monitor_id) {
            Some(deque) if !deque.is_empty() => {
                let last = deque.back().unwrap();
                if last.success {
                    MonitorStatus::Up
                } else {
                    let recent_failures = deque.iter().rev().take(3).filter(|r| !r.success).count();
                    if recent_failures >= 3 {
                        MonitorStatus::Down
                    } else {
                        MonitorStatus::Degraded
                    }
                }
            }
            _ => MonitorStatus::Unknown,
        }
    }

    /// Get overall status for a specific page by aggregating its monitors
    pub fn page_overall_status(&self, page: &StatusPage) -> MonitorStatus {
        if page.monitor_ids.is_empty() {
            return MonitorStatus::Unknown;
        }
        let mut worst = MonitorStatus::Up;
        for mid in &page.monitor_ids {
            worst = worst.worst(self.monitor_status(mid));
        }
        worst
    }

    /// Get the latest check result for a monitor
    pub fn latest_result(&self, monitor_id: &str) -> Option<CheckResult> {
        let results = self.results.read().unwrap();
        results.get(monitor_id).and_then(|d| d.back().cloned())
    }

    /// Record a check result
    pub fn record_result(&self, monitor_id: &str, result: CheckResult) {
        {
            let mut results = self.results.write().unwrap();
            let deque = results.entry(monitor_id.to_string()).or_insert_with(|| VecDeque::with_capacity(MAX_RESULTS));
            if deque.len() >= MAX_RESULTS {
                deque.pop_front();
            }
            deque.push_back(result.clone());
        }
        self.update_daily_uptime(monitor_id, &result);
    }

    /// Update daily uptime stats
    fn update_daily_uptime(&self, monitor_id: &str, result: &CheckResult) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut daily = self.daily_uptime.write().unwrap();
        let deque = daily.entry(monitor_id.to_string()).or_insert_with(|| VecDeque::with_capacity(MAX_DAILY_ENTRIES));

        if let Some(entry) = deque.back_mut().filter(|e| e.date == today) {
            entry.total_checks += 1;
            if result.success {
                entry.successful_checks += 1;
            }
            entry.uptime_percent = if entry.total_checks > 0 {
                (entry.successful_checks as f32 / entry.total_checks as f32) * 100.0
            } else {
                100.0
            };
        } else {
            if deque.len() >= MAX_DAILY_ENTRIES {
                deque.pop_front();
            }
            deque.push_back(DailyUptime {
                date: today,
                total_checks: 1,
                successful_checks: if result.success { 1 } else { 0 },
                uptime_percent: if result.success { 100.0 } else { 0.0 },
            });
        }

        Self::save_daily_uptime_data(&daily);
    }

    fn save_daily_uptime_data(data: &HashMap<String, VecDeque<DailyUptime>>) {
        let _ = std::fs::create_dir_all("/etc/wolfstack");
        if let Ok(json) = serde_json::to_string(data) {
            let _ = std::fs::write("/etc/wolfstack/statuspage-uptime.json", json);
        }
    }

    fn load_daily_uptime() -> HashMap<String, VecDeque<DailyUptime>> {
        match std::fs::read_to_string("/etc/wolfstack/statuspage-uptime.json") {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    /// Get 90-day uptime data for a monitor
    pub fn get_daily_uptime(&self, monitor_id: &str) -> Vec<DailyUptime> {
        let daily = self.daily_uptime.read().unwrap();
        daily.get(monitor_id).map(|d| d.iter().cloned().collect()).unwrap_or_default()
    }

    /// Calculate overall uptime percentage for a monitor (last 90 days)
    pub fn uptime_percent(&self, monitor_id: &str) -> f32 {
        let daily = self.daily_uptime.read().unwrap();
        match daily.get(monitor_id) {
            Some(deque) if !deque.is_empty() => {
                let total: u32 = deque.iter().map(|d| d.total_checks).sum();
                let success: u32 = deque.iter().map(|d| d.successful_checks).sum();
                if total > 0 { (success as f32 / total as f32) * 100.0 } else { 100.0 }
            }
            _ => 100.0,
        }
    }

    /// Find a page by slug, restricted to a specific cluster
    pub fn find_page_by_slug_and_cluster(&self, slug: &str, cluster: &str) -> Option<StatusPage> {
        let config = self.config.read().unwrap();
        config.pages.iter().find(|p| p.slug == slug && p.cluster == cluster).cloned()
    }

    /// List page slugs + titles for a specific cluster only
    pub fn list_pages_for_cluster(&self, cluster: &str) -> Vec<(String, String, bool)> {
        let config = self.config.read().unwrap();
        config.pages.iter()
            .filter(|p| p.cluster == cluster)
            .map(|p| (p.slug.clone(), p.title.clone(), p.enabled))
            .collect()
    }

}

// ═══════════════════════════════════════════════
// ─── Monitor Status ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Up,
    Degraded,
    Down,
    Unknown,
}

impl MonitorStatus {
    pub fn worst(self, other: MonitorStatus) -> MonitorStatus {
        match (self, other) {
            (MonitorStatus::Down, _) | (_, MonitorStatus::Down) => MonitorStatus::Down,
            (MonitorStatus::Degraded, _) | (_, MonitorStatus::Degraded) => MonitorStatus::Degraded,
            (MonitorStatus::Unknown, _) | (_, MonitorStatus::Unknown) => MonitorStatus::Unknown,
            _ => MonitorStatus::Up,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            MonitorStatus::Up => "Operational",
            MonitorStatus::Degraded => "Degraded",
            MonitorStatus::Down => "Major Outage",
            MonitorStatus::Unknown => "Unknown",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            MonitorStatus::Up => "🟢",
            MonitorStatus::Degraded => "🟡",
            MonitorStatus::Down => "🔴",
            MonitorStatus::Unknown => "⚪",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            MonitorStatus::Up => "#22c55e",
            MonitorStatus::Degraded => "#eab308",
            MonitorStatus::Down => "#ef4444",
            MonitorStatus::Unknown => "#6b7280",
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Check Runner ───
// ═══════════════════════════════════════════════

/// Run all enabled monitors and record results.
/// Called periodically by the background task in main.rs.
pub async fn run_checks(state: &Arc<StatusPageState>) {
    let (monitors, has_pages) = {
        let config = state.config.read().unwrap();
        let has_pages = config.pages.iter().any(|p| p.enabled);
        let monitors = config.monitors.iter()
            .filter(|m| m.enabled)
            .cloned()
            .collect::<Vec<_>>();
        (monitors, has_pages)
    };

    // Only run checks if there's at least one enabled page
    if !has_pages || monitors.is_empty() {
        return;
    }

    for monitor in &monitors {
        let timeout = std::time::Duration::from_secs(monitor.timeout_secs);
        let start = std::time::Instant::now();

        let (success, error) = match &monitor.check {
            CheckType::Http { url, expected_status } => {
                run_http_check(url, *expected_status, timeout).await
            }
            CheckType::Tcp { host, port } => {
                run_tcp_check(host, *port, timeout).await
            }
            CheckType::Ping { host } => {
                run_ping_check(host, timeout).await
            }
            CheckType::Container { runtime, name, node_id: _ } => {
                run_container_check(runtime, name)
            }
            CheckType::Wolfrun { service_id, min_healthy, health_check, .. } => {
                run_wolfrun_check(service_id, *min_healthy, health_check).await
            }
        };

        let latency_ms = start.elapsed().as_millis() as u32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        state.record_result(&monitor.id, CheckResult {
            timestamp: now,
            success,
            latency_ms,
            error,
        });
    }

    // Auto-create/resolve incidents on each page
    auto_manage_incidents(state);
}

async fn run_http_check(url: &str, expected_status: u16, timeout: std::time::Duration) -> (bool, Option<String>) {
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return (false, Some(format!("Client error: {}", e))),
    };

    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == expected_status {
                (true, None)
            } else {
                (false, Some(format!("Expected {}, got {}", expected_status, status)))
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, Some("Timeout".to_string()))
            } else if e.is_connect() {
                (false, Some("Connection refused".to_string()))
            } else {
                (false, Some(format!("{}", e)))
            }
        }
    }
}

async fn run_tcp_check(host: &str, port: u16, timeout: std::time::Duration) -> (bool, Option<String>) {
    let addr = format!("{}:{}", host, port);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => (true, None),
        Ok(Err(e)) => (false, Some(format!("Connection failed: {}", e))),
        Err(_) => (false, Some("Timeout".to_string())),
    }
}

async fn run_ping_check(host: &str, timeout: std::time::Duration) -> (bool, Option<String>) {
    let timeout_secs = timeout.as_secs().max(1).to_string();
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", &timeout_secs, host])
        .output()
        .await;

    match output {
        Ok(out) => {
            if out.status.success() {
                (true, None)
            } else {
                (false, Some("Host unreachable".to_string()))
            }
        }
        Err(e) => (false, Some(format!("Ping failed: {}", e))),
    }
}

fn run_container_check(runtime: &str, name: &str) -> (bool, Option<String>) {
    match runtime {
        "docker" => {
            let output = std::process::Command::new("docker")
                .args(["inspect", "-f", "{{.State.Running}}", name])
                .output();
            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if stdout == "true" {
                        (true, None)
                    } else {
                        (false, Some(format!("Container not running (state: {})", stdout)))
                    }
                }
                Err(e) => (false, Some(format!("Docker error: {}", e))),
            }
        }
        "lxc" => {
            let output = std::process::Command::new("lxc-info")
                .args(["-n", name, "-s"])
                .output();
            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if stdout.contains("RUNNING") {
                        (true, None)
                    } else {
                        (false, Some("Container not running".to_string()))
                    }
                }
                Err(e) => (false, Some(format!("LXC error: {}", e))),
            }
        }
        _ => (false, Some(format!("Unknown runtime: {}", runtime))),
    }
}

/// Check WolfRun service health by counting running instances
async fn run_wolfrun_check(service_id: &str, min_healthy: u32, _health_check: &str) -> (bool, Option<String>) {
    // Try to read WolfRun services from the local file
    let wolfrun_path = std::path::Path::new("data/wolfrun.json");
    if !wolfrun_path.exists() {
        return (false, Some("WolfRun not configured".to_string()));
    }
    
    let content = match std::fs::read_to_string(wolfrun_path) {
        Ok(c) => c,
        Err(e) => return (false, Some(format!("Failed to read WolfRun config: {}", e))),
    };
    
    let services: Vec<serde_json::Value> = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(e) => return (false, Some(format!("Failed to parse WolfRun config: {}", e))),
    };
    
    // Find the service
    let service = match services.iter().find(|s| s.get("id").and_then(|v| v.as_str()) == Some(service_id)) {
        Some(s) => s,
        None => return (false, Some(format!("Service {} not found", service_id))),
    };
    
    // Count running instances
    let instances = service.get("instances").and_then(|v| v.as_array()).map(|a| a.to_vec()).unwrap_or_default();
    let running_count = instances.iter().filter(|i| {
        i.get("status").and_then(|v| v.as_str()) == Some("running")
    }).count() as u32;
    
    if running_count >= min_healthy {
        (true, None)
    } else {
        (false, Some(format!("Only {}/{} instances running", running_count, min_healthy)))
    }
}

/// Auto-create incidents when monitors go down, auto-resolve when back up.
fn auto_manage_incidents(state: &Arc<StatusPageState>) {
    let mut config = state.config.write().unwrap();
    let now_str = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Iterate over all monitors in the global pool that are enabled
    let active_monitors: Vec<_> = config.monitors.iter().filter(|m| m.enabled).cloned().collect();

    for monitor in active_monitors {
        let status = compute_monitor_status(state, &monitor.id);

        let cluster = monitor.cluster.clone();
        
        // Find existing auto-incident for this monitor
        let existing = config.incidents.iter_mut().find(|i| {
            i.auto_created && i.status != IncidentStatus::Resolved && i.service_ids.contains(&monitor.id)
        });

        match status {
            MonitorStatus::Down | MonitorStatus::Degraded => {
                if existing.is_none() {
                    config.incidents.push(Incident {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: format!("{} — {}", monitor.name, status.label()),
                        status: IncidentStatus::Investigating,
                        cluster,
                        impact: Some(if status == MonitorStatus::Down { "critical".to_string() } else { "minor".to_string() }),
                        service_ids: vec![monitor.id.clone()],
                        updates: vec![IncidentUpdate {
                            timestamp: now_str.clone(),
                            status: IncidentStatus::Investigating,
                            message: format!("Automated detection: {} is {}", monitor.name, status.label().to_lowercase()),
                        }],
                        created_at: now_str.clone(),
                        resolved_at: None,
                        auto_created: true,
                    });
                }
            }
            MonitorStatus::Up => {
                if let Some(incident) = existing {
                    incident.status = IncidentStatus::Resolved;
                    incident.resolved_at = Some(now_str.clone());
                    incident.updates.push(IncidentUpdate {
                        timestamp: now_str.clone(),
                        status: IncidentStatus::Resolved,
                        message: format!("{} has recovered and is operational", monitor.name),
                    });
                }
            }
            _ => {}
        }
    }

    let _ = config.save();
}

/// Compute monitor status from check results (uses state.results directly to avoid RwLock issues)
fn compute_monitor_status(state: &Arc<StatusPageState>, monitor_id: &str) -> MonitorStatus {
    let results = state.results.read().unwrap();
    match results.get(monitor_id) {
        Some(deque) if !deque.is_empty() => {
            let last = deque.back().unwrap();
            if last.success {
                MonitorStatus::Up
            } else {
                let recent_failures = deque.iter().rev().take(3).filter(|r| !r.success).count();
                if recent_failures >= 3 { MonitorStatus::Down } else { MonitorStatus::Degraded }
            }
        }
        _ => MonitorStatus::Unknown,
    }
}

// ═══════════════════════════════════════════════
// ─── Public Status Page HTML Renderer ───
// ═══════════════════════════════════════════════

/// Theme color palette for public status pages
struct ThemeColors {
    body_bg: &'static str,
    text: &'static str,
    heading: &'static str,
    card_bg: &'static str,
    card_border: &'static str,
    muted: &'static str,
    secondary: &'static str,
    divider: &'static str,
    bar_empty: &'static str,
}

fn theme_colors(theme: Option<&str>) -> ThemeColors {
    match theme {
        Some("light") => ThemeColors {
            body_bg: "#f5f6fa", text: "#1a1d2e", heading: "#0f1118", card_bg: "#ffffff",
            card_border: "#e2e4ea", muted: "#8b90a0", secondary: "#5a5f72",
            divider: "#e2e4ea", bar_empty: "#e2e4ea",
        },
        Some("midnight") => ThemeColors {
            body_bg: "#000000", text: "#e4e4f0", heading: "#f0f0ff", card_bg: "#111118",
            card_border: "#1e1e2e", muted: "#555570", secondary: "#8888a8",
            divider: "#1e1e2e", bar_empty: "#111118",
        },
        Some("datacenter") => ThemeColors {
            body_bg: "#1d2733", text: "#dce3eb", heading: "#eef2f7", card_bg: "#2a3849",
            card_border: "#374b5e", muted: "#607588", secondary: "#8fa4b8",
            divider: "#374b5e", bar_empty: "#2a3849",
        },
        Some("forest") => ThemeColors {
            body_bg: "#0c1a10", text: "#d8eedc", heading: "#e8ffe8", card_bg: "#1a3020",
            card_border: "#264030", muted: "#5a7868", secondary: "#88b098",
            divider: "#264030", bar_empty: "#1a3020",
        },
        Some("amber") => ThemeColors {
            body_bg: "#0a0800", text: "#f0d890", heading: "#ffe8a0", card_bg: "#1a1610",
            card_border: "#2e2818", muted: "#786840", secondary: "#b8a060",
            divider: "#2e2818", bar_empty: "#1a1610",
        },
        Some("glass") => ThemeColors {
            body_bg: "#020512", text: "#c8e0ff", heading: "#e0f0ff", card_bg: "#0a1840",
            card_border: "rgba(55,110,220,0.20)", muted: "#2e4d78", secondary: "#5a88c0",
            divider: "rgba(55,110,220,0.20)", bar_empty: "#0a1840",
        },
        Some("deepred") => ThemeColors {
            body_bg: "#100408", text: "#f0dde2", heading: "#fff0f2", card_bg: "#240c14",
            card_border: "#3a1420", muted: "#704858", secondary: "#b08090",
            divider: "#3a1420", bar_empty: "#240c14",
        },
        _ => ThemeColors { // dark (default)
            body_bg: "#0f172a", text: "#e2e8f0", heading: "#f8fafc", card_bg: "#1e293b",
            card_border: "#334155", muted: "#64748b", secondary: "#94a3b8",
            divider: "#1e293b", bar_empty: "#1e293b",
        },
    }
}

/// Render the public status page for a specific page slug (only if it belongs to this cluster)
pub fn render_public_page(state: &Arc<StatusPageState>, slug: &str, local_cluster: &str) -> Option<String> {
    let page = state.find_page_by_slug_and_cluster(slug, local_cluster)?;

    if !page.enabled {
        return Some(not_enabled_html());
    }

    let overall = state.page_overall_status(&page);
    let tc = theme_colors(page.theme.as_deref());

    let config = state.config.read().unwrap();

    // Build monitors HTML
    let mut services_html = String::new();
    for mid in &page.monitor_ids {
        if let Some(monitor) = config.monitors.iter().find(|m| m.id == *mid) {
            let m_status = state.monitor_status(mid);
            let uptime = state.uptime_percent(mid);

            let daily = state.get_daily_uptime(mid);
            let bars_html = build_uptime_bars(&daily, tc.bar_empty);

            services_html.push_str(&format!(
                r#"<div class="service-row">
                    <div class="service-header">
                        <div class="service-name">{name}</div>
                        <div class="service-status" style="color:{color}">{emoji} {label}</div>
                    </div>
                    <div class="uptime-section">
                        <div class="uptime-bars">{bars}</div>
                        <div class="uptime-legend">
                            <span>90 days ago</span>
                            <span class="uptime-pct">{uptime:.2}% uptime</span>
                            <span>Today</span>
                        </div>
                    </div>
                </div>"#,
                name = html_escape(&monitor.name),
                color = m_status.color(),
                emoji = m_status.emoji(),
                label = m_status.label(),
                bars = bars_html,
                uptime = uptime,
            ));
        }
    }

    // Build incidents HTML (last 14 days)
    let mut incidents_html = String::new();
    let cutoff = chrono::Utc::now() - chrono::Duration::days(14);
    
    let mut recent_incidents: Vec<&Incident> = config.incidents.iter()
        .filter(|i| page.incident_ids.contains(&i.id))
        .filter(|i| {
            chrono::DateTime::parse_from_rfc3339(&format!("{}+00:00", i.created_at.replace('Z', "")))
                .map(|dt| dt > cutoff)
                .unwrap_or(true)
        })
        .collect();
    recent_incidents.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    if recent_incidents.is_empty() {
        incidents_html.push_str(r#"<p class="no-incidents">No incidents reported in the last 14 days.</p>"#);
    } else {
        for incident in &recent_incidents {
            let status_badge = match incident.status {
                IncidentStatus::Investigating => r#"<span class="badge badge-red">Investigating</span>"#,
                IncidentStatus::Identified => r#"<span class="badge badge-orange">Identified</span>"#,
                IncidentStatus::Monitoring => r#"<span class="badge badge-yellow">Monitoring</span>"#,
                IncidentStatus::Resolved => r#"<span class="badge badge-green">Resolved</span>"#,
            };

            let impact_badge = match incident.impact.as_deref() {
                Some("critical") => r#" <span class="badge badge-red">Critical</span>"#,
                Some("major") => r#" <span class="badge badge-orange">Major</span>"#,
                Some("minor") => r#" <span class="badge badge-yellow">Minor</span>"#,
                _ => "",
            };

            let mut updates_html = String::new();
            for update in incident.updates.iter().rev() {
                updates_html.push_str(&format!(
                    r#"<div class="incident-update">
                        <div class="update-time">{}</div>
                        <div class="update-msg">{}</div>
                    </div>"#,
                    html_escape(&update.timestamp),
                    html_escape(&update.message),
                ));
            }

            incidents_html.push_str(&format!(
                r#"<div class="incident">
                    <div class="incident-header">
                        <div class="incident-title">{title}</div>
                        <div>{badge}{impact}</div>
                    </div>
                    <div class="incident-date">{date}</div>
                    <div class="incident-updates">{updates}</div>
                </div>"#,
                title = html_escape(&incident.title),
                badge = status_badge,
                impact = impact_badge,
                date = html_escape(&incident.created_at),
                updates = updates_html,
            ));
        }
    }

    let logo_html = page.logo_url.as_ref()
        .map(|url| format!(r#"<img src="{}" alt="Logo" class="logo">"#, html_escape(url)))
        .unwrap_or_default();

    let footer_text = page.footer_text.as_deref().unwrap_or("Powered by WolfStack");

    Some(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="{title} — Current system status and uptime">
    <title>{title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <meta http-equiv="refresh" content="60">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: {body_bg};
            color: {text};
            min-height: 100vh;
        }}
        .container {{ max-width: 720px; margin: 0 auto; padding: 2rem 1.5rem; }}
        .header {{ text-align: center; margin-bottom: 2rem; }}
        .logo {{ max-height: 60px; margin-bottom: 1rem; }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; color: {heading}; }}
        .overall-status {{
            text-align: center; padding: 1.25rem; margin-bottom: 2rem;
            border-radius: 12px; font-size: 1.1rem; font-weight: 600;
            background: {overall_bg};
            border: 1px solid {overall_border};
            color: {overall_color};
        }}
        .section-title {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.05em; color: {secondary}; margin-bottom: 0.75rem; }}
        .service-row {{
            background: {card_bg}; border: 1px solid {card_border}; border-radius: 10px;
            padding: 1.25rem; margin-bottom: 0.75rem;
        }}
        .service-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }}
        .service-name {{ font-weight: 600; font-size: 0.95rem; }}
        .service-status {{ font-size: 0.85rem; font-weight: 500; }}
        .uptime-section {{ margin-top: 0.5rem; }}
        .uptime-bars {{ display: flex; gap: 1px; height: 28px; border-radius: 4px; overflow: hidden; }}
        .uptime-bar {{ flex: 1; min-width: 2px; transition: opacity 0.2s; cursor: default; }}
        .uptime-bar:hover {{ opacity: 0.8; }}
        .uptime-legend {{ display: flex; justify-content: space-between; font-size: 0.7rem; color: {muted}; margin-top: 4px; }}
        .uptime-pct {{ font-weight: 600; color: {secondary}; }}
        .incidents-section {{ margin-top: 2rem; }}
        .incident {{
            background: {card_bg}; border: 1px solid {card_border}; border-radius: 10px;
            padding: 1.25rem; margin-bottom: 0.75rem;
        }}
        .incident-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}
        .incident-title {{ font-weight: 600; font-size: 0.95rem; }}
        .incident-date {{ font-size: 0.75rem; color: {muted}; margin-bottom: 0.75rem; }}
        .badge {{ padding: 3px 10px; border-radius: 100px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
        .badge-red {{ background: rgba(239,68,68,0.15); color: #ef4444; }}
        .badge-orange {{ background: rgba(249,115,22,0.15); color: #f97316; }}
        .badge-yellow {{ background: rgba(234,179,8,0.15); color: #eab308; }}
        .badge-green {{ background: rgba(34,197,94,0.15); color: #22c55e; }}
        .incident-update {{ padding: 0.5rem 0; border-top: 1px solid {card_border}; }}
        .incident-update:first-child {{ border-top: none; }}
        .update-time {{ font-size: 0.7rem; color: {muted}; margin-bottom: 2px; }}
        .update-msg {{ font-size: 0.85rem; color: {secondary}; }}
        .no-incidents {{ color: {muted}; font-size: 0.9rem; text-align: center; padding: 1rem; }}
        .footer {{ text-align: center; margin-top: 3rem; padding-top: 1.5rem;
            border-top: 1px solid {divider}; font-size: 0.75rem; color: {muted}; }}
        .footer a {{ color: {secondary}; text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {logo}
            <h1>{title}</h1>
        </div>
        <div class="overall-status">{overall_emoji} {overall_label}</div>
        <div class="section-title">Services</div>
        {services}
        <div class="incidents-section">
            <div class="section-title">Recent Incidents</div>
            {incidents}
        </div>
        <div class="footer">
            <p>{footer} &bull; <a href="https://wolfscale.org" target="_blank">wolfscale.org</a></p>
        </div>
    </div>
</body>
</html>"#,
        title = html_escape(&page.title),
        logo = logo_html,
        body_bg = tc.body_bg,
        text = tc.text,
        heading = tc.heading,
        card_bg = tc.card_bg,
        card_border = tc.card_border,
        muted = tc.muted,
        secondary = tc.secondary,
        divider = tc.divider,
        overall_bg = overall_status_bg(overall),
        overall_border = overall_status_border(overall),
        overall_color = overall.color(),
        overall_emoji = overall.emoji(),
        overall_label = match overall {
            MonitorStatus::Up => "All Systems Operational",
            MonitorStatus::Degraded => "Some Systems Degraded",
            MonitorStatus::Down => "Major System Outage",
            MonitorStatus::Unknown => "Status Unknown",
        },
        services = services_html,
        incidents = incidents_html,
        footer = html_escape(footer_text),
    ))
}

/// Render a status page index listing all available pages for this cluster
pub fn render_index_page(state: &Arc<StatusPageState>, local_cluster: &str) -> String {
    let pages = state.list_pages_for_cluster(local_cluster);
    let enabled_pages: Vec<_> = pages.iter().filter(|(_, _, enabled)| *enabled).collect();

    if enabled_pages.is_empty() {
        return not_enabled_html();
    }

    // If only one page, redirect to it
    if enabled_pages.len() == 1 {
        return format!(
            r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/status/{}"></head><body></body></html>"#,
            html_escape(&enabled_pages[0].0)
        );
    }

    let mut links_html = String::new();
    for (slug, title, _) in &enabled_pages {
        links_html.push_str(&format!(
            r#"<a href="/status/{slug}" class="page-link">
                <div class="page-title">{title}</div>
                <div class="page-url">/status/{slug}</div>
            </a>"#,
            slug = html_escape(slug),
            title = html_escape(title),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Status Pages</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh;
            display: flex; align-items: center; justify-content: center; }}
        .container {{ max-width: 480px; width: 100%; padding: 2rem; }}
        h1 {{ text-align: center; font-size: 1.3rem; margin-bottom: 1.5rem; color: #f8fafc; }}
        .page-link {{ display: block; background: #1e293b; border: 1px solid #334155; border-radius: 10px;
            padding: 1.25rem; margin-bottom: 0.75rem; text-decoration: none; color: #e2e8f0;
            transition: all 0.2s; }}
        .page-link:hover {{ border-color: #22c55e; transform: translateY(-2px); }}
        .page-title {{ font-weight: 600; font-size: 1rem; }}
        .page-url {{ font-size: 0.8rem; color: #64748b; margin-top: 4px; }}
        .footer {{ text-align: center; margin-top: 2rem; font-size: 0.75rem; color: #475569; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Status Pages</h1>
        {links}
        <div class="footer">Powered by WolfStack</div>
    </div>
</body>
</html>"#,
        links = links_html,
    )
}

fn not_enabled_html() -> String {
    r#"<!DOCTYPE html><html><head><title>Status</title></head><body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;"><p>Status page is not enabled.</p></body></html>"#.to_string()
}

fn build_uptime_bars(daily: &[DailyUptime], bar_empty: &str) -> String {
    let mut bars = String::new();
    let target: usize = 90;
    let pad_count = target.saturating_sub(daily.len());

    for _ in 0..pad_count {
        bars.push_str(&format!(r#"<div class="uptime-bar" style="background:{};" title="No data"></div>"#, bar_empty));
    }
    for day in daily {
        let color = if day.uptime_percent >= 99.5 {
            "#22c55e"
        } else if day.uptime_percent >= 95.0 {
            "#eab308"
        } else {
            "#ef4444"
        };
        bars.push_str(&format!(
            r#"<div class="uptime-bar" style="background:{};" title="{}: {:.1}% uptime"></div>"#,
            color, day.date, day.uptime_percent
        ));
    }
    bars
}

fn overall_status_bg(status: MonitorStatus) -> &'static str {
    match status {
        MonitorStatus::Up => "rgba(34,197,94,0.1)",
        MonitorStatus::Degraded => "rgba(234,179,8,0.1)",
        MonitorStatus::Down => "rgba(239,68,68,0.1)",
        MonitorStatus::Unknown => "rgba(107,114,128,0.1)",
    }
}

fn overall_status_border(status: MonitorStatus) -> &'static str {
    match status {
        MonitorStatus::Up => "rgba(34,197,94,0.3)",
        MonitorStatus::Degraded => "rgba(234,179,8,0.3)",
        MonitorStatus::Down => "rgba(239,68,68,0.3)",
        MonitorStatus::Unknown => "rgba(107,114,128,0.3)",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_incident_deser() {
        // With impact field
        let json = r#"{"id":"i1","title":"Test","status":"investigating","cluster":"WolfStack","impact":"critical","service_ids":[],"updates":[],"created_at":"2025-01-01T00:00:00Z"}"#;
        let result: Result<Incident, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "with impact failed: {:?}", result.err());
        assert_eq!(result.unwrap().impact, Some("critical".to_string()));

        // Without impact field (should default to None)
        let json = r#"{"id":"i2","title":"Test","status":"investigating","cluster":"WolfStack","created_at":"2025-01-01T00:00:00Z"}"#;
        let result: Result<Incident, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "without impact failed: {:?}", result.err());
        assert_eq!(result.unwrap().impact, None);

        // Without service_ids (should default to empty vec)
        let json = r#"{"id":"i3","title":"Test","status":"resolved","cluster":"WolfStack","created_at":"2025-01-01T00:00:00Z"}"#;
        let result: Result<Incident, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "without service_ids failed: {:?}", result.err());
        assert!(result.unwrap().service_ids.is_empty());
    }

    #[test]
    fn test_monitor_deser() {
        let cases = vec![
            ("http", r#"{"id":"t1","name":"HTTP","cluster":"WolfStack","check":{"type":"http","url":"https://google.com","expected_status":200},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("tcp", r#"{"id":"t2","name":"TCP","cluster":"WolfStack","check":{"type":"tcp","host":"1.2.3.4","port":80},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("ping", r#"{"id":"t3","name":"Ping","cluster":"WolfStack","check":{"type":"ping","host":"1.2.3.4"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("container", r#"{"id":"t4","name":"Container","cluster":"WolfStack","check":{"type":"container","runtime":"docker","name":"nginx"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("container+node", r#"{"id":"t5","name":"Container","cluster":"WolfStack","check":{"type":"container","runtime":"docker","name":"nginx","node_id":"abc"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("wolfrun", r#"{"id":"t6","name":"WR","cluster":"WolfStack","check":{"type":"wolfrun","service_id":"s1","service_name":"Svc","min_healthy":1,"health_check":"running"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
        ];
        for (label, json) in cases {
            let result: Result<Monitor, _> = serde_json::from_str(json);
            assert!(result.is_ok(), "{} failed: {:?}", label, result.err());
        }
    }
}
