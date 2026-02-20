use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use std::collections::HashMap;
use std::time::Instant;

const ALERTS_CONFIG_FILE: &str = "/etc/wolfstack/alerts.json";

/// Cooldown duration — same alert type for the same node won't re-fire within this window
const ALERT_COOLDOWN_SECS: u64 = 15 * 60; // 15 minutes

/// A threshold alert that was triggered
#[derive(Debug, Clone)]
pub struct ThresholdAlert {
    pub alert_type: String,   // "cpu", "memory", "disk"
    pub current: f32,         // current percentage
    pub threshold: f32,       // configured threshold
}

/// Check a node's metrics against alerting thresholds.
/// Returns a list of triggered alerts.
pub fn check_thresholds(config: &AlertConfig, cpu_pct: f32, mem_pct: f32, disk_pct: f32) -> Vec<ThresholdAlert> {
    let mut alerts = Vec::new();
    if config.alert_cpu && cpu_pct >= config.cpu_threshold {
        alerts.push(ThresholdAlert { alert_type: "cpu".into(), current: cpu_pct, threshold: config.cpu_threshold });
    }
    if config.alert_memory && mem_pct >= config.memory_threshold {
        alerts.push(ThresholdAlert { alert_type: "memory".into(), current: mem_pct, threshold: config.memory_threshold });
    }
    if config.alert_disk && disk_pct >= config.disk_threshold {
        alerts.push(ThresholdAlert { alert_type: "disk".into(), current: disk_pct, threshold: config.disk_threshold });
    }
    alerts
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

    // ── Check interval ──
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,  // how often to check thresholds (seconds)
}

fn default_cpu_threshold() -> f32 { 90.0 }
fn default_mem_threshold() -> f32 { 90.0 }
fn default_disk_threshold() -> f32 { 90.0 }
fn default_true() -> bool { true }
fn default_check_interval() -> u64 { 60 }

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
            check_interval_secs: 60,
        }
    }
}

impl AlertConfig {
    /// Load config from disk or return defaults
    pub fn load() -> Self {
        match std::fs::read_to_string(ALERTS_CONFIG_FILE) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save config to disk
    pub fn save(&self) -> Result<(), String> {
        let _ = std::fs::create_dir_all("/etc/wolfstack");
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(ALERTS_CONFIG_FILE, json).map_err(|e| format!("Failed to write alerts config: {}", e))
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
            "check_interval_secs": self.check_interval_secs,
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

/// Send alert to all configured channels (non-blocking, best-effort)
pub async fn send_alert(config: &AlertConfig, title: &str, message: &str) {
    if !config.enabled || !config.has_channels() {
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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

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

    if resp.status().is_success() || resp.status().as_u16() == 204 {
        info!("Discord alert sent: {}", title);
        Ok(())
    } else {
        Err(format!("Discord HTTP {}", resp.status()))
    }
}

// ── Slack webhook ──
async fn send_slack(webhook_url: &str, title: &str, message: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

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

    if resp.status().is_success() {
        info!("Slack alert sent: {}", title);
        Ok(())
    } else {
        Err(format!("Slack HTTP {}", resp.status()))
    }
}

// ── Telegram bot ──
async fn send_telegram(bot_token: &str, chat_id: &str, title: &str, message: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

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

    if resp.status().is_success() {
        info!("Telegram alert sent: {}", title);
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Telegram error: {}", body))
    }
}
