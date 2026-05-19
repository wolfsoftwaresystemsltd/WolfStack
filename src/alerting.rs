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

/// Cooldown duration — same alert type for the same node won't re-fire within this window
const ALERT_COOLDOWN_SECS: u64 = 900; // 15 minutes = 900 seconds.

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

/// Check if a specific alert is in cooldown. Returns true if it should be suppressed.
pub fn is_in_cooldown(cooldowns: &HashMap<String, Instant>, node_id: &str, alert_type: &str) -> bool {
    let key = format!("{}:{}", node_id, alert_type);
    if let Some(last) = cooldowns.get(&key) {
        last.elapsed().as_secs() < ALERT_COOLDOWN_SECS
    } else {
        false
    }
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
            "has_discord_bot": !self.discord_bot_token.is_empty(),
            "telegram_receiver_enabled": self.telegram_receiver_enabled,
            "twilio_account_sid": self.twilio_account_sid,
            "has_twilio_auth": !self.twilio_auth_token.is_empty(),
            "twilio_whatsapp_from": self.twilio_whatsapp_from,
        })
    }
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
    let alert_cfg = AlertConfig::load();
    if !alert_cfg.allows(category) {
        return;
    }

    let when = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
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
/// config — combined `enabled` and verbosity check. Use this at fan-out
/// sites that dispatch to BOTH webhooks (via `send_alert`) AND email
/// (via `ai::send_alert_email`) so the email path is also gated.
pub fn should_send(config: &AlertConfig, category: AlertCategory) -> bool {
    config.enabled && config.allows(category)
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
    if !config.enabled || !config.has_channels() || !config.allows(category) {
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
}
