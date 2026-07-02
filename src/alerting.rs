use chrono::{Datelike, Timelike};
use serde::{Deserialize, Serialize};
use tracing::warn;
use std::collections::HashMap;
use std::time::Instant;

fn alerts_config_file() -> String { crate::paths::get().alerts_config }

/// Shared HTTP client for every outbound alert notification (Discord
/// webhook, Slack webhook, Telegram bot API). Same pattern as
/// src/wolfrun/mod.rs (v19.8.1 fix) and the new shared clients in
/// src/statuspage/mod.rs and src/networking/router/api.rs: one pool
/// for the lifetime of the process. Alerts are event-driven, so the
/// per-call leak rate was lower than the statuspage tick loops — but
/// during an incident storm (many alerts firing back-to-back) the
/// same CLOSE_WAIT pile-up still applied.
static ALERT_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Legacy cooldown constant — kept ONLY as the default `cooldown_secs`
/// returned by `default_cooldown_secs()`. v24.0.0+ lifts this to the
/// `AlertConfig.cooldown_secs` field so noisy environments can stretch
/// it and quiet ones can shorten. Direct use of this constant is
/// discouraged; pass the config-derived value to `is_in_cooldown_secs`
/// instead.
#[allow(dead_code)]
const ALERT_COOLDOWN_SECS_DEFAULT: u64 = 900; // 15 minutes.

/// Per-process ring of dispatch timestamps used by the hourly
/// rate-limit gate (`max_alerts_per_hour`). One entry per fired
/// notification — purged automatically on each check to whatever
/// falls inside the trailing 60-minute window. Bounded by the
/// purge step; max size = max_alerts_per_hour * (purge granularity).
static DISPATCH_TIMES: std::sync::LazyLock<std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::VecDeque::new()));

/// Per-process rolling history of every alert this node has
/// dispatched. v24.0.0 introduces the unified Alerts page → History
/// view; before this, the only `alert_log` in `AppState` was written
/// at three specific sites (array health, AI critical-issues,
/// gateway audit), missing >80% of actual alert traffic. Logging
/// here at the `send_node_alert` entry point captures every
/// threshold / lifecycle / posture / brute-force / compromise alert
/// once it's passed the verbosity + quiet-hours gate (i.e. once
/// it's actually being sent, not just attempted).
///
/// Capped at 500 entries — older rows drop off the front. The /api
/// /alerts/history endpoint merges this with `state.alert_log` so
/// the operator sees the unified view.
static ALERT_HISTORY: std::sync::LazyLock<std::sync::RwLock<std::collections::VecDeque<HistoryRow>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::VecDeque::new()));

const ALERT_HISTORY_CAP: usize = 500;

/// One row in the dispatched-alerts history ring. Shape mirrors the
/// existing `api::AlertLogEntry` with an extra `category` field so
/// the History UI can filter on AlertCategory directly.
#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: u64,
    pub timestamp: String,
    /// "critical" | "warning" | "info" — derived from AlertCategory
    /// via `category_to_severity`.
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub hostname: String,
    pub cluster: String,
    /// AlertCategory::as_str (snake_case).
    pub category: String,
}

/// Map an AlertCategory to the severity string the History UI uses
/// (matches the existing AlertLogEntry severity convention).
fn category_to_severity(c: AlertCategory) -> &'static str {
    match c {
        AlertCategory::Compromise => "critical",
        AlertCategory::BruteForce | AlertCategory::Posture => "warning",
        AlertCategory::Threshold | AlertCategory::Lifecycle => "info",
    }
}

/// Push a fired-alert record into the rolling history. Called by
/// `send_node_alert` AFTER the verbosity + quiet-hours gate — we log
/// what actually went out, not what was suppressed.
pub fn record_history(
    cluster: &str,
    host: &str,
    category: AlertCategory,
    title: &str,
    detail: &str,
) {
    let mut log = match ALERT_HISTORY.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let id = log.back().map(|r| r.id + 1).unwrap_or(1);
    log.push_back(HistoryRow {
        id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        severity: category_to_severity(category).to_string(),
        title: title.to_string(),
        detail: detail.to_string(),
        hostname: host.to_string(),
        cluster: cluster.to_string(),
        category: category.as_str().to_string(),
    });
    while log.len() > ALERT_HISTORY_CAP { log.pop_front(); }
}

/// Snapshot of the in-memory history for the /api/alerts/history
/// endpoint. Returns rows newest-LAST (push_back order); the API
/// handler reverses for display.
pub fn history_snapshot() -> Vec<HistoryRow> {
    let log = match ALERT_HISTORY.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    log.iter().cloned().collect()
}

/// A threshold alert that was triggered
#[derive(Debug, Clone)]
pub struct ThresholdAlert {
    pub alert_type: String,   // "cpu", "memory", "disk"
    pub current: f32,         // current percentage
    pub threshold: f32,       // configured threshold
}

/// A container-level memory alert
#[derive(Debug, Clone)]
pub struct ContainerAlert {
    pub container_name: String,
    pub runtime: String,       // "docker" or "lxc"
    pub memory_percent: f64,
    pub memory_usage: u64,
    pub memory_limit: u64,
    pub threshold: f32,
}

/// Check if a specific alert is in cooldown given a configured
/// cooldown duration. Returns true if it should be suppressed.
/// v24.0.0: replaces the hardcoded 15-minute constant with an
/// operator-tunable value from `AlertConfig.cooldown_secs`.
pub fn is_in_cooldown_secs(
    cooldowns: &HashMap<String, Instant>,
    node_id: &str,
    alert_type: &str,
    cooldown_secs: u64,
) -> bool {
    let key = format!("{}:{}", node_id, alert_type);
    if let Some(last) = cooldowns.get(&key) {
        last.elapsed().as_secs() < cooldown_secs
    } else {
        false
    }
}

/// Back-compat shim — keeps the v23 signature alive so any third-party
/// callers (unlikely but possible) don't break. Uses the default
/// cooldown duration; new code should call `is_in_cooldown_secs`.
#[allow(dead_code)]
pub fn is_in_cooldown(cooldowns: &HashMap<String, Instant>, node_id: &str, alert_type: &str) -> bool {
    is_in_cooldown_secs(cooldowns, node_id, alert_type, ALERT_COOLDOWN_SECS_DEFAULT)
}

/// True if firing one more alert would stay within the
/// `max_alerts_per_hour` cap. `max == 0` means "no cap" — always
/// allowed. Records the current instant in the dispatch ring so the
/// caller doesn't need to do it separately. Trims the ring to the
/// trailing 60-minute window on every call so it can't grow without
/// bound.
pub fn try_acquire_hourly_slot(max_alerts_per_hour: u32) -> bool {
    if max_alerts_per_hour == 0 { return true; }
    let now = std::time::Instant::now();
    let cutoff = now - std::time::Duration::from_secs(3600);
    let mut deque = match DISPATCH_TIMES.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    while let Some(&front) = deque.front() {
        if front < cutoff { deque.pop_front(); } else { break; }
    }
    if deque.len() as u32 >= max_alerts_per_hour {
        return false;
    }
    deque.push_back(now);
    true
}

/// Record that an alert was just sent (sets cooldown timer)
pub fn record_alert(cooldowns: &mut HashMap<String, Instant>, node_id: &str, alert_type: &str) {
    let key = format!("{}:{}", node_id, alert_type);
    cooldowns.insert(key, Instant::now());
}

/// Remove cooldown entry (for recovery notifications)
pub fn clear_cooldown(cooldowns: &mut HashMap<String, Instant>, node_id: &str, alert_type: &str) {
    let key = format!("{}:{}", node_id, alert_type);
    cooldowns.remove(&key);
}

/// Check if a node+type was previously in an alerted state (has a cooldown entry)
pub fn was_alerted(cooldowns: &HashMap<String, Instant>, node_id: &str, alert_type: &str) -> bool {
    let key = format!("{}:{}", node_id, alert_type);
    cooldowns.contains_key(&key)
}

/// Alerting configuration — persisted to /etc/wolfstack/alerts.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    #[serde(default)]
    pub enabled: bool,

    // ── Notification channels ──
    #[serde(default)]
    pub discord_webhook: String,
    #[serde(default)]
    pub slack_webhook: String,
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,

    /// Discord *bot* token — distinct from `discord_webhook`. Used by
    /// the Discord receiver to log in as a bot, receive messages in
    /// bound channels, and reply on behalf of WolfAgents. Never send
    /// this to anyone — it grants full bot-account control. Masked
    /// in the frontend via `to_masked_json()`.
    #[serde(default)]
    pub discord_bot_token: String,

    /// Enable the Telegram receiver loop. The bot token from
    /// `telegram_bot_token` has been there for outbound alerts for
    /// ages — we gate inbound behind this separate flag so existing
    /// installs don't suddenly start long-polling messages without
    /// operator consent.
    #[serde(default)]
    pub telegram_receiver_enabled: bool,

    /// Twilio account SID — used for WhatsApp replies. Twilio's
    /// inbound webhook delivers messages to /api/whatsapp/webhook,
    /// outbound replies go through the REST API with these creds.
    #[serde(default)]
    pub twilio_account_sid: String,
    /// Twilio auth token — signed HMAC header on inbound webhooks is
    /// validated against this. Masked in `to_masked_json()`.
    #[serde(default)]
    pub twilio_auth_token: String,
    /// Twilio-registered WhatsApp sender in E.164 form with the
    /// `whatsapp:` prefix — e.g. `whatsapp:+14155238886` (the
    /// Twilio sandbox number). Used as the "From" on replies.
    #[serde(default)]
    pub twilio_whatsapp_from: String,

    // ── Threshold rules ──
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: f32,     // percentage (0-100)
    #[serde(default = "default_mem_threshold")]
    pub memory_threshold: f32,
    #[serde(default = "default_disk_threshold")]
    pub disk_threshold: f32,

    // ── Feature toggles ──
    #[serde(default = "default_true")]
    pub alert_node_offline: bool,
    #[serde(default = "default_true")]
    pub alert_node_restored: bool,
    #[serde(default = "default_true")]
    pub alert_cpu: bool,
    #[serde(default = "default_true")]
    pub alert_memory: bool,
    #[serde(default = "default_true")]
    pub alert_disk: bool,

    // ── Container monitoring ──
    #[serde(default = "default_true")]
    pub alert_containers: bool,
    #[serde(default = "default_container_mem_threshold")]
    pub container_memory_threshold: f32,  // percentage (0-100)

    // ── Check interval ──
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,  // how often to check thresholds (seconds)

    /// How often the security scanner re-runs (SSH brute-force,
    /// crypto miners, world-readable secrets, etc). Separate from
    /// `check_interval_secs` because security scans are heavier
    /// (journalctl, lsof, port scans) and don't benefit from sub-hour
    /// cadences — an attacker who got in 15 minutes ago vs 4 hours ago
    /// gets the same forensic outcome. Defaults to 4 h to keep the
    /// per-node duty cycle low at cluster scale.
    #[serde(default = "default_security_scan_interval")]
    pub security_scan_interval_secs: u64,

    /// Notification verbosity. Default `Simple` — only fires for
    /// `AlertCategory::Compromise` (crypto miners, suspicious /tmp
    /// binaries, outbound scans from this host). Operators repeatedly
    /// reported being drowned by "we just blocked another scanner" and
    /// SSH brute-force chatter when their public servers are under the
    /// usual internet-background noise — Simple silences all of that
    /// while keeping the alerts that mean "your host is compromised".
    /// Verbose restores the firehose (threshold breaches, posture
    /// findings, every IP-blocked event, etc).
    #[serde(default)]
    pub alert_verbosity: AlertVerbosity,

    // ── Schedule (v24.0.0) ──────────────────────────────────────────
    // The Alerts page → Schedule sub-tab consolidates quiet-hours,
    // cooldown, grouping, and recovery settings — previously spread
    // across hardcoded constants and one-off toggles.

    /// Quiet hours window — when set + enabled, alerts whose category
    /// is in `quiet_hours.suppress_categories` are dropped during the
    /// window. Compromise alerts always fire regardless of quiet
    /// hours (they're the "wake me up" signals by definition).
    #[serde(default)]
    pub quiet_hours: Option<QuietHours>,

    /// Per-(node, alert-type) cooldown in seconds. Hard-coded to 900
    /// (15 min) before v24; lifted to config so noisy environments
    /// can stretch it and quiet ones can shorten. Floor of 60 enforced
    /// at the API layer to keep the cooldown meaningful.
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,

    /// Global rate limit. 0 = no limit. When non-zero, any dispatch
    /// past this count within the trailing 60-minute window is
    /// dropped. Operators on flaky links use this to cap blast radius
    /// during incident storms.
    #[serde(default)]
    pub max_alerts_per_hour: u32,

    /// Smart grouping — alerts within `grouping_window_secs` get
    /// batched into a single notification per `grouping_strategy`.
    /// 0 = grouping off (fire immediately, the v23 behaviour).
    #[serde(default)]
    pub grouping_window_secs: u64,

    /// How to bucket alerts in the grouping window.
    #[serde(default)]
    pub grouping_strategy: GroupingStrategy,

    /// Send a follow-up "recovered" notification when an alert clears.
    /// Default true (the v23 implicit behaviour for offline/restored
    /// + threshold-recovery). Operators who don't want the noise can
    /// flip this off without untangling individual per-rule toggles.
    #[serde(default = "default_true")]
    pub recovery_notifications: bool,
}

/// Quiet-hours window. When `enabled` is true and the current time
/// falls inside (start_hhmm, end_hhmm) on a selected weekday, any
/// alert whose category is in `suppress_categories` is dropped.
/// Compromise alerts are NEVER suppressed regardless — same product
/// invariant as `AlertVerbosity::Simple`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    #[serde(default)]
    pub enabled: bool,
    /// `HH:MM` 24-hour. Range-crossing midnight is allowed; if
    /// start > end the window is treated as wrapping (e.g. 22:00 →
    /// 06:00 means quiet from 10pm through 6am).
    #[serde(default = "default_quiet_start")]
    pub start_hhmm: String,
    #[serde(default = "default_quiet_end")]
    pub end_hhmm: String,
    /// IANA timezone name, e.g. `Europe/Berlin`. UTC fallback if the
    /// string doesn't parse — defensive against operator typos.
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// 7-bit mask, Monday = bit 0 through Sunday = bit 6. 0x7F = all
    /// days. Frontend renders as M T W T F S S chip buttons.
    #[serde(default = "default_quiet_days")]
    pub days_of_week: u8,
    /// Which AlertCategory variants are silenced during the window.
    /// Compromise is intentionally absent from the allowed set —
    /// even if an operator ticks every box, real-compromise alerts
    /// always fire.
    #[serde(default)]
    pub suppress_categories: Vec<String>,
}

fn default_quiet_start() -> String { "22:00".into() }
fn default_quiet_end() -> String { "08:00".into() }
fn default_timezone() -> String { "UTC".into() }
fn default_quiet_days() -> u8 { 0x7F } // Mon-Sun

impl Default for QuietHours {
    fn default() -> Self {
        Self {
            enabled: false,
            start_hhmm: default_quiet_start(),
            end_hhmm: default_quiet_end(),
            timezone: default_timezone(),
            days_of_week: default_quiet_days(),
            suppress_categories: Vec::new(),
        }
    }
}

/// How alerts inside the grouping window get bucketed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupingStrategy {
    /// All alerts within the window collapse into one notification
    /// per host — typical for "CPU + memory both pegged on pve3".
    #[default]
    ByNode,
    /// All alerts within the window collapse into one notification
    /// per guest (VM / container) — typical for app-level incidents
    /// where a single misbehaving container produces a cascade.
    ByGuest,
}

/// How chatty alert notifications are. Granularity is intentionally
/// two-level — operators told us they don't want to manage 12 toggles,
/// they want either "tell me when something's actually broken" or
/// "everything". See `AlertCategory` for what falls in each bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlertVerbosity {
    /// Only `AlertCategory::Compromise` fires. Default for new and
    /// existing installs (existing JSON without the field deserializes
    /// to this via `#[serde(default)]` + `Default` derive).
    #[default]
    Simple,
    /// Every category fires (subject to the existing per-rule toggles
    /// like `alert_cpu`).
    Verbose,
}

/// What kind of event an alert represents. Determines whether the
/// notification is sent under `AlertVerbosity::Simple`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertCategory {
    /// Host compromise indicators — these ALWAYS fire (Simple AND
    /// Verbose). Crypto miner running, freshly-dropped executable in
    /// /tmp or /dev/shm, outbound port-scan originating from this
    /// node. Operators told us these are the only signals worth waking
    /// them up at 3am.
    Compromise,
    /// Failed-auth / brute-force chatter. Public boxes get this 24/7
    /// from internet background scanners — noisy by nature.
    BruteForce,
    /// Posture / configuration findings: fail2ban missing, sshd
    /// PermitRootLogin, world-readable cluster_secret, duplicate IPs,
    /// listening services. Recommendations, not "something's actively
    /// on fire".
    Posture,
    /// CPU / memory / disk / container thresholds. Already visible on
    /// the dashboard — Simple mode suppresses the push notification.
    Threshold,
    /// Node offline/restored, reboot detection. Lifecycle noise visible
    /// on the dashboard.
    Lifecycle,
}

fn default_cpu_threshold() -> f32 { 90.0 }
fn default_mem_threshold() -> f32 { 90.0 }
fn default_disk_threshold() -> f32 { 90.0 }
fn default_true() -> bool { true }
fn default_container_mem_threshold() -> f32 { 90.0 }
fn default_check_interval() -> u64 { 60 }
fn default_security_scan_interval() -> u64 { 4 * 60 * 60 }
fn default_cooldown_secs() -> u64 { 900 }

impl AlertCategory {
    /// Lowercase tag used when (de)serialising the `suppress_categories`
    /// list inside `QuietHours`. The list is `Vec<String>` rather than
    /// `Vec<AlertCategory>` because the frontend stores it as plain
    /// strings already (`"threshold"`, `"lifecycle"`, ...), so we
    /// translate at the gate.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertCategory::Compromise => "compromise",
            AlertCategory::BruteForce => "brute_force",
            AlertCategory::Posture    => "posture",
            AlertCategory::Threshold  => "threshold",
            AlertCategory::Lifecycle  => "lifecycle",
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discord_webhook: String::new(),
            slack_webhook: String::new(),
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            cpu_threshold: 90.0,
            memory_threshold: 90.0,
            disk_threshold: 90.0,
            alert_node_offline: true,
            alert_node_restored: true,
            alert_cpu: true,
            alert_memory: true,
            alert_disk: true,
            alert_containers: true,
            container_memory_threshold: 90.0,
            check_interval_secs: 60,
            security_scan_interval_secs: 4 * 60 * 60,
            alert_verbosity: AlertVerbosity::Simple,
            quiet_hours: None,
            cooldown_secs: default_cooldown_secs(),
            max_alerts_per_hour: 0,
            grouping_window_secs: 0,
            grouping_strategy: GroupingStrategy::ByNode,
            recovery_notifications: true,
            discord_bot_token: String::new(),
            telegram_receiver_enabled: false,
            twilio_account_sid: String::new(),
            twilio_auth_token: String::new(),
            twilio_whatsapp_from: String::new(),
        }
    }
}

impl AlertConfig {
    /// Load config from disk or return defaults
    pub fn load() -> Self {
        let path = alerts_config_file();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save config to disk. Sets 0o600 on the file because it can
    /// carry secrets (Discord/Slack webhook URLs, Telegram bot token,
    /// SMTP password, and — once wired — a Discord *bot* token that's
    /// vastly more sensitive than a webhook). /etc/wolfstack defaults
    /// to 755, so without this the file would be world-readable.
    pub fn save(&self) -> Result<(), String> {
        let path = alerts_config_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("Failed to write alerts config: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }
        Ok(())
    }

    /// Whether an alert of the given category should be dispatched
    /// under the current verbosity setting. Simple mode only allows
    /// `Compromise`; Verbose allows everything.
    pub fn allows(&self, category: AlertCategory) -> bool {
        match self.alert_verbosity {
            AlertVerbosity::Verbose => true,
            AlertVerbosity::Simple => matches!(category, AlertCategory::Compromise),
        }
    }

    /// Whether an alert of the given category should fire at the
    /// supplied UTC instant, considering quiet-hours suppression.
    /// `Compromise` is NEVER suppressed — same invariant as Simple
    /// mode: the "wake me up" signals always wake. Other categories
    /// are dropped when (a) quiet-hours is enabled AND (b) the
    /// supplied time falls within the window on a quiet-day AND
    /// (c) the category is in `suppress_categories`.
    ///
    /// `now_utc` is a parameter so tests can pin the clock; production
    /// callers pass `chrono::Utc::now()`. Returns true iff the alert
    /// is allowed to dispatch.
    pub fn allows_at(&self, category: AlertCategory, now_utc: chrono::DateTime<chrono::Utc>) -> bool {
        if !self.allows(category) { return false; }
        // Compromise is never suppressed even when explicitly listed —
        // belt and suspenders.
        if category == AlertCategory::Compromise { return true; }
        let Some(q) = self.quiet_hours.as_ref() else { return true; };
        if !q.enabled { return true; }
        if !q.suppress_categories.iter().any(|s| s == category.as_str()) {
            return true;
        }
        q.includes(now_utc)
            .map(|in_window| !in_window) // in-window == suppressed
            .unwrap_or(true)             // timezone parse fail → fail-open
    }

    /// Check if any notification channel is configured
    pub fn has_channels(&self) -> bool {
        !self.discord_webhook.is_empty()
            || !self.slack_webhook.is_empty()
            || (!self.telegram_bot_token.is_empty() && !self.telegram_chat_id.is_empty())
    }

    /// Return a JSON representation with secrets masked
    pub fn to_masked_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "discord_webhook": mask_secret(&self.discord_webhook),
            "slack_webhook": mask_secret(&self.slack_webhook),
            "telegram_bot_token": mask_secret(&self.telegram_bot_token),
            "telegram_chat_id": self.telegram_chat_id,
            "has_discord": !self.discord_webhook.is_empty(),
            "has_slack": !self.slack_webhook.is_empty(),
            "has_telegram": !self.telegram_bot_token.is_empty() && !self.telegram_chat_id.is_empty(),
            "cpu_threshold": self.cpu_threshold,
            "memory_threshold": self.memory_threshold,
            "disk_threshold": self.disk_threshold,
            "alert_node_offline": self.alert_node_offline,
            "alert_node_restored": self.alert_node_restored,
            "alert_cpu": self.alert_cpu,
            "alert_memory": self.alert_memory,
            "alert_disk": self.alert_disk,
            "alert_containers": self.alert_containers,
            "container_memory_threshold": self.container_memory_threshold,
            "check_interval_secs": self.check_interval_secs,
            "security_scan_interval_secs": self.security_scan_interval_secs,
            "alert_verbosity": match self.alert_verbosity {
                AlertVerbosity::Simple => "simple",
                AlertVerbosity::Verbose => "verbose",
            },
            "quiet_hours": self.quiet_hours,
            "cooldown_secs": self.cooldown_secs,
            "max_alerts_per_hour": self.max_alerts_per_hour,
            "grouping_window_secs": self.grouping_window_secs,
            "grouping_strategy": match self.grouping_strategy {
                GroupingStrategy::ByNode => "by_node",
                GroupingStrategy::ByGuest => "by_guest",
            },
            "recovery_notifications": self.recovery_notifications,
            "has_discord_bot": !self.discord_bot_token.is_empty(),
            "telegram_receiver_enabled": self.telegram_receiver_enabled,
            "twilio_account_sid": self.twilio_account_sid,
            "has_twilio_auth": !self.twilio_auth_token.is_empty(),
            "twilio_whatsapp_from": self.twilio_whatsapp_from,
        })
    }
}

impl QuietHours {
    /// True if `when` falls within the configured quiet-hours window
    /// AND on a day-of-week selected in the bitmask. Returns `None`
    /// if the timezone string fails to parse — the gate callers
    /// fail-open in that case to avoid silently swallowing alerts on
    /// a typo'd timezone.
    pub fn includes(&self, when: chrono::DateTime<chrono::Utc>) -> Option<bool> {
        let tz: chrono_tz::Tz = self.timezone.parse().ok()?;
        let local = when.with_timezone(&tz);
        // Day-of-week: Monday=0..Sunday=6 to match the bitmask.
        let dow_idx = local.weekday().num_days_from_monday();
        let day_bit = 1u8 << dow_idx;
        if self.days_of_week & day_bit == 0 {
            return Some(false);
        }
        let now_min = local.hour() * 60 + local.minute();
        let start_min = parse_hhmm(&self.start_hhmm)?;
        let end_min = parse_hhmm(&self.end_hhmm)?;
        if start_min == end_min {
            // Zero-length window — treat as off rather than 24-hour
            // suppression, which would be a foot-gun.
            return Some(false);
        }
        let inside = if start_min < end_min {
            // Same-day window e.g. 09:00 → 17:00.
            now_min >= start_min && now_min < end_min
        } else {
            // Overnight window e.g. 22:00 → 08:00 (wraps midnight).
            // We accept the window when the START-day bit is set;
            // operators picking weekdays for an overnight window
            // almost always mean "from these weekday evenings into
            // the next morning."
            now_min >= start_min || now_min < end_min
        };
        Some(inside)
    }
}

/// Parse a `HH:MM` string into minutes-since-midnight. Returns None
/// for any malformed input; callers fail-open (treat as not-in-window)
/// rather than silently swallowing alerts on operator typos.
fn parse_hhmm(s: &str) -> Option<u32> {
    let mut parts = s.split(':');
    let h: u32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || h > 23 || m > 59 { return None; }
    Some(h * 60 + m)
}

fn mask_secret(s: &str) -> String {
    if s.is_empty() { return String::new(); }
    if s.len() <= 8 { return "********".to_string(); }
    format!("{}…{}", &s[..4], &s[s.len()-4..])
}

// ═══════════════════════════════════════════════
// ─── Send notifications to configured channels ───
// ═══════════════════════════════════════════════

/// Send a security alert that's stamped with the operator's cluster
/// name and hostname, then dispatched through every configured
/// channel — Discord, Slack, Telegram (via the standard webhook
/// AlertConfig), AND email (via the AiConfig SMTP settings).
///
/// Operators with multiple clusters need to know WHICH node fired
/// the alert at a glance. Title prefix is `[<cluster> / <host>]`;
/// body has a stable header block so the operator can sort/filter
/// across an inbox of alerts from a fleet of 14 nodes.
///
/// Best-effort — channels are tried independently; one failing
/// doesn't block the others. Returns nothing because the operator
/// would never act on a "channel X failed" notice — the warning
/// goes to journald instead.
pub async fn send_node_alert(
    cluster_name: &str,
    hostname: &str,
    category: AlertCategory,
    title: &str,
    body: &str,
) {
    // WolfFunctions alert_fired trigger — BEFORE the human-channel gate:
    // quiet hours silence pages, but automation (auto-remediation
    // functions) should run at 3am precisely when nobody is watching.
    crate::wolffunctions::fire_event_global(
        crate::wolffunctions::TriggerEvent::AlertFired,
        serde_json::json!({
            "cluster": cluster_name,
            "hostname": hostname,
            "category": format!("{:?}", category),
            "title": title,
            "body": body,
        }),
        true,
    );

    let alert_cfg = AlertConfig::load();
    let now = chrono::Utc::now();
    if !alert_cfg.allows_at(category, now) {
        // Captures verbosity AND quiet-hours suppression in one
        // gate — same contract as `should_send_at`.
        return;
    }

    // Record into the in-memory dispatch history so the Alerts page →
    // History view sees this fire. We log AFTER the gate so suppressed
    // alerts don't pollute the history with phantom entries — operators
    // looking at History want to see what actually went out.
    record_history(cluster_name, hostname, category, title, body);

    let when = now.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let full_title = format!("[{} / {}] {}", cluster_name, hostname, title);
    let full_body = format!(
        "Cluster:  {}\n\
         Host:     {}\n\
         When:     {}\n\n\
         {}",
        cluster_name, hostname, when, body,
    );

    // Webhook channels (Discord / Slack / Telegram).
    if alert_cfg.enabled && alert_cfg.has_channels() {
        send_alert(&alert_cfg, category, &full_title, &full_body).await;
    }

    // Email — sync function, run on the blocking pool so we don't
    // stall the async runtime over SMTP handshakes.
    let email_cfg = crate::ai::AiConfig::load();
    if email_cfg.email_enabled && !email_cfg.email_to.is_empty() {
        let t = full_title.clone();
        let b = full_body.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = crate::ai::send_alert_email(&email_cfg, &t, &b) {
                warn!("alert email failed: {}", e);
            }
        }).await.ok();
    }
}

/// True if an alert of the given category should fire given the loaded
/// config — combined `enabled` + verbosity + quiet-hours check. Use
/// this at fan-out sites that dispatch to BOTH webhooks (via
/// `send_alert`) AND email (via `ai::send_alert_email`) so the email
/// path is also gated by the same rules.
pub fn should_send(config: &AlertConfig, category: AlertCategory) -> bool {
    should_send_at(config, category, chrono::Utc::now())
}

/// Time-parameterised variant of `should_send` — exists primarily so
/// tests can pin the clock to a known instant and verify the
/// quiet-hours window behaviour without sleeping the test suite.
pub fn should_send_at(
    config: &AlertConfig,
    category: AlertCategory,
    now_utc: chrono::DateTime<chrono::Utc>,
) -> bool {
    config.enabled && config.allows_at(category, now_utc)
}

/// Resolve the local node's cluster name + hostname and dispatch an
/// alert with the standard `[<cluster> / <host>]` title prefix and
/// `Cluster:/Host:/When:` body header. Use this from any background
/// task that wants to fire an alert but doesn't already have a
/// `ClusterState` handle nearby — predictive orchestrator, threshold
/// watchers, lifecycle observers, etc. Operators on multi-cluster
/// setups need to know WHICH cluster + node a push notification came
/// from at a glance; before this helper existed the title was raw and
/// the body would say things like `Scope: ws-784bcbe6` (the internal
/// slug), which is unhelpful in Discord/email.
///
/// Cluster name reads `self_cluster.json` (same source the agent and
/// threat-intel modules use); hostname comes from the `hostname` crate.
/// Both are cheap enough to resolve on every call — no caching needed.
///
/// Category gating, channel-fan-out, and the dual webhook+email
/// dispatch are all inherited from `send_node_alert`.
pub async fn send_local_alert(category: AlertCategory, title: &str, body: &str) {
    let (cluster_name, hostname) = local_identity();
    send_node_alert(&cluster_name, &hostname, category, title, body).await;
}

/// Decorate a `(title, body)` pair with the local cluster + hostname,
/// returning the formatted pair without sending anything. Use this at
/// call sites that fan out to BOTH webhook (`send_alert`) AND email
/// (`ai::send_alert_email`) themselves — apply this once, pass the
/// result to both paths. Title gets the same `[<cluster> / <host>]`
/// prefix as `send_node_alert`, body gets the same Cluster/Host/When
/// header. Operators on multi-cluster setups can identify the
/// originating node at a glance.
pub fn decorate_local(title: &str, body: &str) -> (String, String) {
    let (cluster_name, hostname) = local_identity();
    let when = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let full_title = format!("[{} / {}] {}", cluster_name, hostname, title);
    let full_body = format!(
        "Cluster:  {}\n\
         Host:     {}\n\
         When:     {}\n\n\
         {}",
        cluster_name, hostname, when, body,
    );
    (full_title, full_body)
}

/// (cluster_name, hostname) for the local node. Shared by every
/// alerting helper so the resolution stays identical — operators see
/// the same labels whether the alert came from predictive, threshold,
/// lifecycle, or anywhere else.
fn local_identity() -> (String, String) {
    let cluster_name = crate::predictive::threat_intel::this_node_cluster();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    (cluster_name, hostname)
}

/// Send alert to all configured channels (non-blocking, best-effort).
/// `category` controls Simple/Verbose gating — see [`AlertCategory`].
pub async fn send_alert(config: &AlertConfig, category: AlertCategory, title: &str, message: &str) {
    if !config.enabled || !config.has_channels()
        || !config.allows_at(category, chrono::Utc::now())
    {
        return;
    }
    // Hourly rate-limit. Compromise alerts bypass the cap — we never
    // want a flood of failed-auth events to silence a "miner running"
    // signal. Same invariant as Simple verbosity + quiet-hours
    // suppression.
    if category != AlertCategory::Compromise
        && !try_acquire_hourly_slot(config.max_alerts_per_hour)
    {
        warn!(
            "alert dispatch suppressed by max_alerts_per_hour={} cap (category={:?})",
            config.max_alerts_per_hour, category,
        );
        return;
    }

    // Discord
    if !config.discord_webhook.is_empty() {
        if let Err(e) = send_discord(&config.discord_webhook, title, message).await {
            warn!("Discord alert failed: {}", e);
        }
    }

    // Slack
    if !config.slack_webhook.is_empty() {
        if let Err(e) = send_slack(&config.slack_webhook, title, message).await {
            warn!("Slack alert failed: {}", e);
        }
    }

    // Telegram
    if !config.telegram_bot_token.is_empty() && !config.telegram_chat_id.is_empty() {
        if let Err(e) = send_telegram(&config.telegram_bot_token, &config.telegram_chat_id, title, message).await {
            warn!("Telegram alert failed: {}", e);
        }
    }
}

/// Send a test notification to all configured channels
pub async fn send_test(config: &AlertConfig) -> Vec<(String, Result<(), String>)> {
    let mut results = Vec::new();
    let title = "🧪 WolfStack Test Alert";
    let message = "This is a test notification from WolfStack. If you received this, your alerting is configured correctly!";

    if !config.discord_webhook.is_empty() {
        let r = send_discord(&config.discord_webhook, title, message).await;
        results.push(("discord".to_string(), r));
    }
    if !config.slack_webhook.is_empty() {
        let r = send_slack(&config.slack_webhook, title, message).await;
        results.push(("slack".to_string(), r));
    }
    if !config.telegram_bot_token.is_empty() && !config.telegram_chat_id.is_empty() {
        let r = send_telegram(&config.telegram_bot_token, &config.telegram_chat_id, title, message).await;
        results.push(("telegram".to_string(), r));
    }

    results
}

// ── Discord webhook ──
async fn send_discord(webhook_url: &str, title: &str, message: &str) -> Result<(), String> {
    let client = &*ALERT_CLIENT;

    let payload = serde_json::json!({
        "embeds": [{
            "title": title,
            "description": message,
            "color": if title.contains("ALERT") || title.contains("⚠") { 16711680 } else if title.contains("OK") || title.contains("✅") { 65280 } else { 5793266 },
            "footer": { "text": "WolfStack Alerting" },
            "timestamp": chrono::Utc::now().to_rfc3339()
        }]
    });

    let resp = client.post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    let is_ok = status.is_success() || status.as_u16() == 204;
    // Drain the body so the socket returns to the keep-alive pool.
    // Discord's 204 ack and error bodies both carry content that
    // reqwest won't release the connection for until consumed.
    let _ = resp.bytes().await;
    if is_ok {
        Ok(())
    } else {
        Err(format!("Discord HTTP {}", status))
    }
}

// ── Slack webhook ──
async fn send_slack(webhook_url: &str, title: &str, message: &str) -> Result<(), String> {
    let client = &*ALERT_CLIENT;

    let payload = serde_json::json!({
        "blocks": [
            { "type": "header", "text": { "type": "plain_text", "text": title } },
            { "type": "section", "text": { "type": "mrkdwn", "text": message } },
            { "type": "context", "elements": [{ "type": "mrkdwn", "text": format!("_WolfStack Alerting — {}_", chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")) }] }
        ]
    });

    let resp = client.post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    let _ = resp.bytes().await;
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("Slack HTTP {}", status))
    }
}

// ── Telegram bot ──
async fn send_telegram(bot_token: &str, chat_id: &str, title: &str, message: &str) -> Result<(), String> {
    let client = &*ALERT_CLIENT;

    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let text = format!("*{}*\n\n{}", title, message);

    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": true
    });

    let resp = client.post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    // `.text()` fully consumes the body, so this path already drains
    // the socket properly for both success and failure.
    if resp.status().is_success() {
        let _ = resp.text().await;
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Telegram error: {}", body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple mode is the new default; the regression we are most
    /// worried about is a future edit changing which categories pass
    /// the gate. Lock the contract explicitly:
    ///
    ///   Simple   → only `Compromise` fires
    ///   Verbose  → every category fires
    ///
    /// If any of these assertions ever flip, operators either get
    /// silently flooded (Simple too permissive) or silently miss real
    /// compromise alerts (Simple too strict). Either is a P0 regression.
    #[test]
    fn simple_mode_only_allows_compromise() {
        let mut cfg = AlertConfig::default();
        cfg.alert_verbosity = AlertVerbosity::Simple;
        assert!(cfg.allows(AlertCategory::Compromise));
        assert!(!cfg.allows(AlertCategory::BruteForce));
        assert!(!cfg.allows(AlertCategory::Posture));
        assert!(!cfg.allows(AlertCategory::Threshold));
        assert!(!cfg.allows(AlertCategory::Lifecycle));
    }

    #[test]
    fn verbose_mode_allows_every_category() {
        let mut cfg = AlertConfig::default();
        cfg.alert_verbosity = AlertVerbosity::Verbose;
        assert!(cfg.allows(AlertCategory::Compromise));
        assert!(cfg.allows(AlertCategory::BruteForce));
        assert!(cfg.allows(AlertCategory::Posture));
        assert!(cfg.allows(AlertCategory::Threshold));
        assert!(cfg.allows(AlertCategory::Lifecycle));
    }

    /// `Default` for `AlertConfig` MUST land on Simple — existing
    /// installs whose `/etc/wolfstack/alerts.json` predates this field
    /// deserialize via `#[serde(default)]` and Default, and the
    /// operator's expectation is that the upgrade quiets the firehose,
    /// not amplifies it.
    #[test]
    fn default_alert_config_is_simple() {
        let cfg = AlertConfig::default();
        assert_eq!(cfg.alert_verbosity, AlertVerbosity::Simple);
    }

    /// AlertVerbosity must round-trip through serde as the lowercase
    /// strings the frontend posts ("simple" / "verbose"). Anything
    /// else and the radio breaks silently across upgrades.
    #[test]
    fn verbosity_serde_round_trip() {
        let simple_json = serde_json::to_string(&AlertVerbosity::Simple).unwrap();
        let verbose_json = serde_json::to_string(&AlertVerbosity::Verbose).unwrap();
        assert_eq!(simple_json, "\"simple\"");
        assert_eq!(verbose_json, "\"verbose\"");
        let parsed_simple: AlertVerbosity = serde_json::from_str("\"simple\"").unwrap();
        let parsed_verbose: AlertVerbosity = serde_json::from_str("\"verbose\"").unwrap();
        assert_eq!(parsed_simple, AlertVerbosity::Simple);
        assert_eq!(parsed_verbose, AlertVerbosity::Verbose);
    }

    /// `should_send` must combine `enabled` AND verbosity. A site that
    /// only checks one of those two would either leak alerts past a
    /// disabled config or push alerts past Simple — both regressions.
    #[test]
    fn should_send_requires_enabled_and_category_allowed() {
        let mut cfg = AlertConfig::default();
        // Disabled + Simple: nothing fires.
        cfg.enabled = false;
        cfg.alert_verbosity = AlertVerbosity::Simple;
        assert!(!should_send(&cfg, AlertCategory::Compromise));
        assert!(!should_send(&cfg, AlertCategory::Lifecycle));
        // Enabled + Simple: only Compromise.
        cfg.enabled = true;
        assert!(should_send(&cfg, AlertCategory::Compromise));
        assert!(!should_send(&cfg, AlertCategory::Lifecycle));
        // Enabled + Verbose: everything.
        cfg.alert_verbosity = AlertVerbosity::Verbose;
        assert!(should_send(&cfg, AlertCategory::Compromise));
        assert!(should_send(&cfg, AlertCategory::Lifecycle));
        // Disabled + Verbose: still nothing.
        cfg.enabled = false;
        assert!(!should_send(&cfg, AlertCategory::Compromise));
    }

    // ── v24.0.0: Schedule tests ────────────────────────────────────

    /// Defaults must keep existing installs running as before — no
    /// quiet hours, cooldown unchanged (900s), no rate limit, no
    /// grouping, recovery on. New JSON without these fields
    /// deserialises into the same defaults.
    #[test]
    fn schedule_defaults_match_v23_behaviour() {
        let cfg = AlertConfig::default();
        assert!(cfg.quiet_hours.is_none());
        assert_eq!(cfg.cooldown_secs, 900);
        assert_eq!(cfg.max_alerts_per_hour, 0);
        assert_eq!(cfg.grouping_window_secs, 0);
        assert_eq!(cfg.grouping_strategy, GroupingStrategy::ByNode);
        assert!(cfg.recovery_notifications);
    }

    /// Existing JSON (pre-v24) lacking the schedule fields MUST
    /// round-trip into the defaults without erroring. Locks the
    /// `#[serde(default)]` contract on every new field.
    #[test]
    fn pre_v24_json_deserialises_with_schedule_defaults() {
        let body = r#"{"enabled":true,"cpu_threshold":80.0}"#;
        let cfg: AlertConfig = serde_json::from_str(body).unwrap();
        assert!(cfg.quiet_hours.is_none());
        assert_eq!(cfg.cooldown_secs, 900);
        assert!(cfg.recovery_notifications);
        assert_eq!(cfg.grouping_strategy, GroupingStrategy::ByNode);
    }

    /// GroupingStrategy serialises snake-case — matches the convention
    /// the frontend already uses everywhere else.
    #[test]
    fn grouping_strategy_serde_snake_case() {
        let json = serde_json::to_string(&GroupingStrategy::ByNode).unwrap();
        assert_eq!(json, "\"by_node\"");
        let parsed: GroupingStrategy = serde_json::from_str("\"by_guest\"").unwrap();
        assert_eq!(parsed, GroupingStrategy::ByGuest);
    }

    /// AlertCategory::as_str must round-trip with the strings the
    /// frontend stores in `quiet_hours.suppress_categories`.
    #[test]
    fn alert_category_as_str_round_trip() {
        for cat in [
            AlertCategory::Compromise,
            AlertCategory::BruteForce,
            AlertCategory::Posture,
            AlertCategory::Threshold,
            AlertCategory::Lifecycle,
        ] {
            assert!(!cat.as_str().is_empty());
            assert_eq!(cat.as_str().chars().next().unwrap().is_lowercase(), true);
        }
    }

    /// Quiet-hours window: same-day window 09:00 → 17:00 Europe/Berlin,
    /// weekday mask = M-F only.
    #[test]
    fn quiet_hours_same_day_window() {
        let mut q = QuietHours::default();
        q.enabled = true;
        q.start_hhmm = "09:00".into();
        q.end_hhmm = "17:00".into();
        q.timezone = "Europe/Berlin".into();
        q.days_of_week = 0x1F; // Mon-Fri only

        // 2026-05-19 is Tuesday — selected weekday.
        // 13:00 Europe/Berlin == 11:00 UTC (summer time = UTC+2).
        let inside = chrono::DateTime::parse_from_rfc3339("2026-05-19T11:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(inside), Some(true));

        // 08:30 Europe/Berlin == 06:30 UTC — before the window.
        let before = chrono::DateTime::parse_from_rfc3339("2026-05-19T06:30:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(before), Some(false));

        // 18:30 Europe/Berlin == 16:30 UTC — after.
        let after = chrono::DateTime::parse_from_rfc3339("2026-05-19T16:30:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(after), Some(false));

        // 2026-05-23 is Saturday — NOT a selected day.
        let sat = chrono::DateTime::parse_from_rfc3339("2026-05-23T11:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(sat), Some(false));
    }

    /// Quiet-hours window: overnight 22:00 → 06:00 Europe/Berlin
    /// crosses midnight. Operator picks Mon-Fri evenings.
    #[test]
    fn quiet_hours_overnight_window() {
        let mut q = QuietHours::default();
        q.enabled = true;
        q.start_hhmm = "22:00".into();
        q.end_hhmm = "06:00".into();
        q.timezone = "Europe/Berlin".into();
        q.days_of_week = 0x1F;

        // 23:00 Tue local == 21:00 UTC.
        let late_evening = chrono::DateTime::parse_from_rfc3339("2026-05-19T21:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(late_evening), Some(true));

        // 03:00 Tue local == 01:00 UTC Tue.
        let early_morning = chrono::DateTime::parse_from_rfc3339("2026-05-19T01:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(early_morning), Some(true));

        // 12:00 Tue local == 10:00 UTC — outside the overnight window.
        let noon = chrono::DateTime::parse_from_rfc3339("2026-05-19T10:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert_eq!(q.includes(noon), Some(false));
    }

    /// `allows_at` MUST suppress only the listed categories, MUST NOT
    /// suppress Compromise even when explicitly listed, MUST be fully
    /// transparent outside the window.
    #[test]
    fn allows_at_respects_quiet_hours_and_protects_compromise() {
        let mut cfg = AlertConfig::default();
        cfg.enabled = true;
        cfg.alert_verbosity = AlertVerbosity::Verbose;
        cfg.quiet_hours = Some(QuietHours {
            enabled: true,
            start_hhmm: "09:00".into(),
            end_hhmm: "17:00".into(),
            timezone: "Europe/Berlin".into(),
            days_of_week: 0x1F,
            // Operator silences Threshold + Lifecycle, AND tries to
            // silence Compromise — but Compromise must still fire.
            suppress_categories: vec![
                "threshold".into(), "lifecycle".into(), "compromise".into(),
            ],
        });

        // Inside the window, Tuesday 13:00 Berlin == 11:00 UTC.
        let inside = chrono::DateTime::parse_from_rfc3339("2026-05-19T11:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert!(!cfg.allows_at(AlertCategory::Threshold, inside),
            "Threshold should be suppressed inside the window");
        assert!(!cfg.allows_at(AlertCategory::Lifecycle, inside),
            "Lifecycle should be suppressed inside the window");
        assert!(cfg.allows_at(AlertCategory::Compromise, inside),
            "Compromise must fire even when listed as suppressed");
        assert!(cfg.allows_at(AlertCategory::BruteForce, inside),
            "BruteForce not listed → allowed");

        // Outside the window — everything except Simple-mode rules fires.
        let outside = chrono::DateTime::parse_from_rfc3339("2026-05-19T18:00:00Z")
            .unwrap().with_timezone(&chrono::Utc);
        assert!(cfg.allows_at(AlertCategory::Threshold, outside));
        assert!(cfg.allows_at(AlertCategory::Lifecycle, outside));
    }

    /// `is_in_cooldown_secs` uses the supplied duration — locking
    /// the new v24 contract. v23 hardcoded 900s; v24 reads from
    /// config so this is now operator-tunable.
    #[test]
    fn cooldown_uses_supplied_duration() {
        let mut map: HashMap<String, Instant> = HashMap::new();
        record_alert(&mut map, "n1", "cpu");

        // With a 1-hour cooldown, the just-recorded alert IS in cooldown.
        assert!(is_in_cooldown_secs(&map, "n1", "cpu", 3600));
        // With a 0-second cooldown, nothing is in cooldown.
        assert!(!is_in_cooldown_secs(&map, "n1", "cpu", 0));
        // Unrelated key never matches.
        assert!(!is_in_cooldown_secs(&map, "n1", "memory", 3600));
    }

    /// `try_acquire_hourly_slot` MUST allow unlimited dispatches
    /// when max == 0 (the v23 default), and MUST block past the cap
    /// once configured. The ring is process-wide so isolate via a
    /// generous cap that nothing else in the suite will exhaust.
    #[test]
    fn hourly_slot_cap_enforced() {
        // max == 0 → unlimited.
        for _ in 0..50 { assert!(try_acquire_hourly_slot(0)); }

        // Bump to a small cap and confirm the (50+1)th call blocks.
        // We can't reset the deque without affecting other tests; use
        // a cap LOW enough that the existing 50 entries exceed it.
        // Each `try_acquire_hourly_slot(0)` above did NOT add to the
        // deque (max == 0 short-circuits before push), so the deque
        // is still empty from a fresh perspective. Run 5 with cap=5,
        // then expect the 6th to fail.
        for _ in 0..5 { assert!(try_acquire_hourly_slot(5)); }
        assert!(!try_acquire_hourly_slot(5),
            "6th call should hit the cap of 5");
    }

    /// Bad timezone string fails OPEN — the alert fires anyway rather
    /// than being silently swallowed. Caught in production on an
    /// operator typing "GMT+1" instead of "Etc/GMT-1".
    #[test]
    fn quiet_hours_bad_timezone_fails_open() {
        let q = QuietHours {
            enabled: true,
            start_hhmm: "00:00".into(),
            end_hhmm: "23:59".into(),
            timezone: "Not/A/Real/Tz".into(),
            days_of_week: 0x7F,
            suppress_categories: vec!["threshold".into()],
        };
        // includes() returns None on bad tz; allows_at maps None to "allowed".
        assert_eq!(q.includes(chrono::Utc::now()), None);

        let mut cfg = AlertConfig::default();
        cfg.enabled = true;
        cfg.alert_verbosity = AlertVerbosity::Verbose;
        cfg.quiet_hours = Some(q);
        assert!(cfg.allows_at(AlertCategory::Threshold, chrono::Utc::now()),
            "bad timezone must not silently swallow alerts");
    }
}
