//! AI Agent — LLM-powered monitoring and chat assistant
//!
//! Each WolfStack node runs an AI agent that:
//! - Answers questions about WolfStack, WolfNet, WolfDisk, WolfProxy, WolfServe
//! - Monitors server health hourly and alerts on issues
//! - Coordinates with agents on other cluster nodes
//! - Supports Claude and Gemini as LLM backends

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tracing::{info, warn};

const AI_CONFIG_PATH: &str = "/etc/wolfstack/ai-config.json";
const KNOWLEDGE_DIR: &str = "/opt/wolfscale/web";
const KNOWLEDGE_DIR_DEV: &str = "../wolfscale/web";

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider: String,         // "claude" or "gemini"
    pub claude_api_key: String,
    pub gemini_api_key: String,
    pub model: String,            // e.g. "claude-sonnet-4-20250514", "gemini-2.0-flash"
    pub email_enabled: bool,
    pub email_to: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub check_interval_minutes: u32,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: "claude".to_string(),
            claude_api_key: String::new(),
            gemini_api_key: String::new(),
            model: "claude-sonnet-4-20250514".to_string(),
            email_enabled: false,
            email_to: String::new(),
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_user: String::new(),
            smtp_pass: String::new(),
            check_interval_minutes: 60,
        }
    }
}

impl AiConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(AI_CONFIG_PATH) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = std::path::Path::new(AI_CONFIG_PATH).parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(AI_CONFIG_PATH, json).map_err(|e| e.to_string())
    }

    /// Return config with API keys masked for frontend display
    pub fn masked(&self) -> serde_json::Value {
        serde_json::json!({
            "provider": self.provider,
            "claude_api_key": mask_key(&self.claude_api_key),
            "gemini_api_key": mask_key(&self.gemini_api_key),
            "model": self.model,
            "email_enabled": self.email_enabled,
            "email_to": self.email_to,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user,
            "smtp_pass": mask_key(&self.smtp_pass),
            "check_interval_minutes": self.check_interval_minutes,
            "has_claude_key": !self.claude_api_key.is_empty(),
            "has_gemini_key": !self.gemini_api_key.is_empty(),
            "has_smtp_pass": !self.smtp_pass.is_empty(),
        })
    }

    fn active_key(&self) -> &str {
        match self.provider.as_str() {
            "gemini" => &self.gemini_api_key,
            _ => &self.claude_api_key,
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.active_key().is_empty()
    }
}

fn mask_key(key: &str) -> String {
    if key.len() <= 8 {
        return if key.is_empty() { String::new() } else { "••••••••".to_string() };
    }
    format!("{}••••{}", &key[..4], &key[key.len()-4..])
}

// ─── Chat Messages ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,     // "user" or "assistant"
    pub content: String,
    pub timestamp: i64,
}

// ─── Alerts ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAlert {
    pub timestamp: i64,
    pub severity: String,  // "info", "warning", "critical"
    pub message: String,
    pub hostname: String,
}

// ─── AI Agent State ───

pub struct AiAgent {
    pub config: Mutex<AiConfig>,
    pub chat_history: Mutex<Vec<ChatMessage>>,
    pub alerts: Mutex<Vec<AiAlert>>,
    pub last_health_check: Mutex<Option<String>>,
    pub knowledge_base: String,
    client: reqwest::Client,
}

impl AiAgent {
    pub fn new() -> Self {
        let config = AiConfig::load();
        let knowledge_base = load_knowledge_base();
        info!("  AI Agent: Knowledge base loaded ({} chars)", knowledge_base.len());

        Self {
            config: Mutex::new(config),
            chat_history: Mutex::new(Vec::new()),
            alerts: Mutex::new(Vec::new()),
            last_health_check: Mutex::new(None),
            knowledge_base,
            client: reqwest::Client::new(),
        }
    }

    /// Chat with the AI — sends user message, returns assistant response
    pub async fn chat(&self, user_message: &str, system_context: &str) -> Result<String, String> {
        let config = self.config.lock().unwrap().clone();
        if !config.is_configured() {
            return Err("AI not configured — please add an API key in AI Settings".to_string());
        }

        // Build conversation history
        let history: Vec<ChatMessage> = {
            let h = self.chat_history.lock().unwrap();
            h.iter().rev().take(20).cloned().collect::<Vec<_>>().into_iter().rev().collect()
        };

        let system_prompt = build_system_prompt(&self.knowledge_base, system_context);

        let response = match config.provider.as_str() {
            "gemini" => {
                call_gemini(&self.client, &config.gemini_api_key, &config.model, &system_prompt, &history, user_message).await?
            }
            _ => {
                call_claude(&self.client, &config.claude_api_key, &config.model, &system_prompt, &history, user_message).await?
            }
        };

        // Store messages in history
        {
            let mut h = self.chat_history.lock().unwrap();
            let now = chrono::Utc::now().timestamp();
            h.push(ChatMessage { role: "user".to_string(), content: user_message.to_string(), timestamp: now });
            h.push(ChatMessage { role: "assistant".to_string(), content: response.clone(), timestamp: now });
            // Keep last 100 messages
            if h.len() > 100 { let drain = h.len() - 100; h.drain(..drain); }
        }

        Ok(response)
    }

    /// Run a health check — analyze system metrics and return findings  
    pub async fn health_check(&self, metrics_summary: &str) -> Option<String> {
        let config = self.config.lock().unwrap().clone();
        if !config.is_configured() { return None; }

        let prompt = format!(
            "You are a server monitoring AI for WolfStack. Analyze these metrics and report ONLY if there are concerns. \
             If everything looks healthy, respond with exactly 'ALL_OK'. \
             If there are issues, list them concisely with severity (INFO/WARNING/CRITICAL).\n\n\
             Current server metrics:\n{}",
            metrics_summary
        );

        let system = "You are a WolfStack server health monitoring agent. Be concise and technical. Only flag genuine issues.";

        let result = match config.provider.as_str() {
            "gemini" => call_gemini(&self.client, &config.gemini_api_key, &config.model, system, &[], &prompt).await,
            _ => call_claude(&self.client, &config.claude_api_key, &config.model, system, &[], &prompt).await,
        };

        match result {
            Ok(response) => {
                // Update last health check
                {
                    let mut lhc = self.last_health_check.lock().unwrap();
                    *lhc = Some(response.clone());
                }

                if response.trim() != "ALL_OK" {
                    let hostname = hostname::get()
                        .map(|h| h.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    // Parse severity from response
                    let severity = if response.contains("CRITICAL") {
                        "critical"
                    } else if response.contains("WARNING") {
                        "warning"
                    } else {
                        "info"
                    };

                    let alert = AiAlert {
                        timestamp: chrono::Utc::now().timestamp(),
                        severity: severity.to_string(),
                        message: response.clone(),
                        hostname: hostname.clone(),
                    };

                    // Store alert
                    {
                        let mut alerts = self.alerts.lock().unwrap();
                        alerts.push(alert);
                        // Keep last 200 alerts
                        if alerts.len() > 200 { let drain = alerts.len() - 200; alerts.drain(..drain); }
                    }

                    // Send email if configured
                    if config.email_enabled && !config.email_to.is_empty() {
                        let subject = format!("[WolfStack {}] {} Alert on {}", severity.to_uppercase(), severity.to_uppercase(), hostname);
                        if let Err(e) = send_alert_email(&config, &subject, &response) {
                            warn!("Failed to send alert email: {}", e);
                        }
                    }

                    Some(response)
                } else {
                    info!("AI health check: all OK");
                    None
                }
            }
            Err(e) => {
                warn!("AI health check failed: {}", e);
                None
            }
        }
    }
}

// ─── Knowledge Base ───

fn load_knowledge_base() -> String {
    let mut knowledge = String::new();

    // Try multiple locations for the wolfscale web files
    let dirs = [KNOWLEDGE_DIR, KNOWLEDGE_DIR_DEV, "wolfscale/web", "../wolfscale/web"];
    let mut found_dir = None;

    for dir in &dirs {
        let path = std::path::Path::new(dir);
        if path.exists() && path.is_dir() {
            found_dir = Some(dir.to_string());
            break;
        }
    }

    let dir = match found_dir {
        Some(d) => d,
        None => {
            warn!("AI knowledge base directory not found, AI will have limited knowledge");
            return "WolfStack is a server management platform by Wolf Software Systems Ltd.".to_string();
        }
    };

    // Read all HTML files and extract text
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "html").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let filename = path.file_stem().unwrap_or_default().to_string_lossy();
                    let text = strip_html_tags(&content);
                    let trimmed = text.trim();
                    if !trimmed.is_empty() && trimmed.len() > 50 {
                        knowledge.push_str(&format!("\n\n=== {} ===\n{}", filename.to_uppercase(), trimmed));
                    }
                }
            }
        }
    }

    if knowledge.is_empty() {
        "WolfStack is a server management platform by Wolf Software Systems Ltd.".to_string()
    } else {
        // Truncate to ~80KB to stay within context limits
        if knowledge.len() > 80_000 {
            knowledge.truncate(80_000);
        }
        knowledge
    }
}

/// Strip HTML tags and return plain text
fn strip_html_tags(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    let mut i = 0;
    while i < chars.len() {
        if !in_tag && i + 7 < lower_chars.len() {
            let slice: String = lower_chars[i..i+7].iter().collect();
            if slice == "<script" { in_script = true; }
            if slice == "<style " || (i + 6 < lower_chars.len() && lower_chars[i..i+6].iter().collect::<String>() == "<style") {
                in_style = true;
            }
        }

        if chars[i] == '<' {
            // Check for end of script/style
            if in_script && i + 9 < lower_chars.len() {
                let slice: String = lower_chars[i..i+9].iter().collect();
                if slice == "</script>" { in_script = false; }
            }
            if in_style && i + 8 < lower_chars.len() {
                let slice: String = lower_chars[i..i+8].iter().collect();
                if slice == "</style>" { in_style = false; }
            }
            in_tag = true;
        } else if chars[i] == '>' {
            in_tag = false;
        } else if !in_tag && !in_script && !in_style {
            result.push(chars[i]);
        }
        i += 1;
    }

    // Clean up excessive whitespace
    let mut cleaned = String::new();
    let mut last_was_space = false;
    let mut newline_count = 0;
    for c in result.chars() {
        if c == '\n' || c == '\r' {
            newline_count += 1;
            if newline_count <= 2 {
                cleaned.push('\n');
            }
            last_was_space = true;
        } else if c.is_whitespace() {
            if !last_was_space {
                cleaned.push(' ');
            }
            last_was_space = true;
            newline_count = 0;
        } else {
            cleaned.push(c);
            last_was_space = false;
            newline_count = 0;
        }
    }

    // Decode common HTML entities
    cleaned
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–")
        .replace("&nbsp;", " ")
        .replace("&rsquo;", "'")
        .replace("&lsquo;", "'")
        .replace("&rdquo;", "\u{201d}")
        .replace("&ldquo;", "\u{201c}")
}

// ─── System Prompt Builder ───

fn build_system_prompt(knowledge: &str, server_context: &str) -> String {
    format!(
        "You are the AI operations assistant for a WolfStack server node. You are knowledgeable, helpful, and concise.\n\n\
         ## Your Capabilities\n\
         - Answer questions about WolfStack, WolfNet, WolfDisk, WolfProxy, WolfServe, and WolfScale\n\
         - Help with server administration, container management, networking, and storage\n\
         - Explain technical concepts in plain language\n\
         - Help troubleshoot issues based on the current server state\n\n\
         ## Current Server State\n{}\n\n\
         ## Wolf Software Knowledge Base\n\
         Below is comprehensive documentation about the Wolf software suite:\n{}",
        server_context, knowledge
    )
}

// ─── LLM API Calls ───

async fn call_claude(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    system: &str,
    history: &[ChatMessage],
    user_msg: &str,
) -> Result<String, String> {
    let mut messages = Vec::new();

    // Add conversation history
    for msg in history {
        messages.push(serde_json::json!({
            "role": msg.role,
            "content": msg.content
        }));
    }

    // Add current user message
    messages.push(serde_json::json!({
        "role": "user",
        "content": user_msg
    }));

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 2048,
        "system": system,
        "messages": messages,
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Claude API error: {}", e))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("Claude response error: {}", e))?;

    if !status.is_success() {
        return Err(format!("Claude API {} — {}", status, text));
    }

    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Claude JSON error: {}", e))?;

    json["content"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Unexpected Claude response format: {}", text))
}

async fn call_gemini(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    system: &str,
    history: &[ChatMessage],
    user_msg: &str,
) -> Result<String, String> {
    // Map model name — default for Gemini
    let model_name = if model.starts_with("gemini") { model } else { "gemini-2.0-flash" };

    let mut contents = Vec::new();

    // Add conversation history
    for msg in history {
        let role = if msg.role == "assistant" { "model" } else { "user" };
        contents.push(serde_json::json!({
            "role": role,
            "parts": [{"text": msg.content}]
        }));
    }

    // Add current user message
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{"text": user_msg}]
    }));

    let body = serde_json::json!({
        "system_instruction": {
            "parts": [{"text": system}]
        },
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": 2048,
        }
    });

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        model_name, api_key
    );

    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Gemini API error: {}", e))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("Gemini response error: {}", e))?;

    if !status.is_success() {
        return Err(format!("Gemini API {} — {}", status, text));
    }

    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Gemini JSON error: {}", e))?;

    json["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Unexpected Gemini response format: {}", text))
}

// ─── Email Alerts ───

fn send_alert_email(config: &AiConfig, subject: &str, body: &str) -> Result<(), String> {
    use lettre::{Message, SmtpTransport, Transport};
    use lettre::transport::smtp::authentication::Credentials;

    let email = Message::builder()
        .from(format!("WolfStack AI <{}>", config.smtp_user).parse().map_err(|e| format!("Email from: {}", e))?)
        .to(config.email_to.parse().map_err(|e| format!("Email to: {}", e))?)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| format!("Email build: {}", e))?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let mailer = SmtpTransport::relay(&config.smtp_host)
        .map_err(|e| format!("SMTP relay: {}", e))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    mailer.send(&email).map_err(|e| format!("SMTP send: {}", e))?;
    info!("Alert email sent to {}", config.email_to);
    Ok(())
}

// ─── Metrics Summary Builder ───

pub fn build_metrics_summary(
    hostname: &str,
    cpu_percent: f32,
    memory_used_gb: f64,
    memory_total_gb: f64,
    disk_used_gb: f64,
    disk_total_gb: f64,
    docker_count: u32,
    lxc_count: u32,
    vm_count: u32,
    uptime_secs: u64,
) -> String {
    let mem_percent = if memory_total_gb > 0.0 { (memory_used_gb / memory_total_gb * 100.0) as u32 } else { 0 };
    let disk_percent = if disk_total_gb > 0.0 { (disk_used_gb / disk_total_gb * 100.0) as u32 } else { 0 };
    let uptime_hours = uptime_secs / 3600;
    let uptime_days = uptime_hours / 24;

    format!(
        "Hostname: {}\n\
         CPU Usage: {:.1}%\n\
         Memory: {:.1}/{:.1} GB ({}%)\n\
         Disk: {:.1}/{:.1} GB ({}%)\n\
         Docker Containers: {}\n\
         LXC Containers: {}\n\
         Virtual Machines: {}\n\
         Uptime: {} days {} hours",
        hostname,
        cpu_percent,
        memory_used_gb, memory_total_gb, mem_percent,
        disk_used_gb, disk_total_gb, disk_percent,
        docker_count,
        lxc_count,
        vm_count,
        uptime_days, uptime_hours % 24,
    )
}
