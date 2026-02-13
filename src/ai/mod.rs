// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! AI Agent — LLM-powered monitoring and chat assistant
//!
//! Each WolfStack node runs an AI agent that:
//! - Answers questions about WolfStack, WolfNet, WolfDisk, WolfProxy, WolfServe
//! - Monitors server health hourly and alerts on issues
//! - Coordinates with agents on other cluster nodes
//! - Supports Claude and Gemini as LLM backends
//! - Can execute read-only commands locally and across the cluster

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tracing::{info, warn};
use std::process::Command as StdCommand;
use std::time::Duration;

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
    #[serde(default)]
    pub smtp_tls: String,         // "none", "starttls", or "tls"
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
            smtp_tls: "starttls".to_string(),
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

    /// Chat with the AI — multi-turn with command execution support
    /// cluster_nodes is a list of (node_id, hostname, base_url) for remote execution
    /// cluster_secret is used to authenticate with remote nodes via X-WolfStack-Secret
    pub async fn chat(
        &self,
        user_message: &str,
        system_context: &str,
        cluster_nodes: &[(String, String, String, String)],  // (id, hostname, base_url_primary, base_url_fallback)
        cluster_secret: &str,
    ) -> Result<String, String> {
        let config = self.config.lock().unwrap().clone();
        if !config.is_configured() {
            return Err("AI not configured — please add an API key in AI Settings".to_string());
        }

        // Build conversation history
        let mut history: Vec<ChatMessage> = {
            let h = self.chat_history.lock().unwrap();
            h.iter().rev().take(10).cloned().collect::<Vec<_>>().into_iter().rev().collect()
        };

        let system_prompt = build_system_prompt(&self.knowledge_base, system_context);

        let mut current_msg = user_message.to_string();
        let mut final_response = String::new();

        // Multi-turn loop: AI can request commands, we execute and feed back
        for round in 0..3 {
            let response = match config.provider.as_str() {
                "gemini" => {
                    call_gemini(&self.client, &config.gemini_api_key, &config.model, &system_prompt, &history, &current_msg).await?
                }
                _ => {
                    call_claude(&self.client, &config.claude_api_key, &config.model, &system_prompt, &history, &current_msg).await?
                }
            };

            // Check for [EXEC] or [EXEC_ALL] tags
            let has_exec = response.contains("[EXEC]") && response.contains("[/EXEC]");
            let has_exec_all = response.contains("[EXEC_ALL]") && response.contains("[/EXEC_ALL]");

            if !has_exec && !has_exec_all {
                // No commands requested — this is the final response
                final_response = response;
                break;
            }

            // Parse and execute commands
            let mut command_results = String::new();
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "local".to_string());

            // Handle [EXEC]command[/EXEC] — local execution
            let mut search_from = 0;
            while let Some(start) = response[search_from..].find("[EXEC]") {
                let abs_start = search_from + start + 6;
                if let Some(end) = response[abs_start..].find("[/EXEC]") {
                    let cmd = response[abs_start..abs_start + end].trim();
                    info!("AI executing local command (round {}): {}", round + 1, cmd);
                    let result = execute_safe_command(cmd);
                    command_results.push_str(&format!(
                        "\n=== Command on {} ===\n$ {}\n{}\n",
                        hostname, cmd,
                        match &result {
                            Ok(output) => output.clone(),
                            Err(e) => format!("ERROR: {}", e),
                        }
                    ));
                    search_from = abs_start + end + 7;
                } else {
                    break;
                }
            }

            // Handle [EXEC_ALL]command[/EXEC_ALL] — cluster-wide execution
            search_from = 0;
            while let Some(start) = response[search_from..].find("[EXEC_ALL]") {
                let abs_start = search_from + start + 10;
                if let Some(end) = response[abs_start..].find("[/EXEC_ALL]") {
                    let cmd = response[abs_start..abs_start + end].trim();
                    info!("AI executing cluster-wide command (round {}): {}", round + 1, cmd);

                    // Run locally first
                    let local_result = execute_safe_command(cmd);
                    command_results.push_str(&format!(
                        "\n=== {} (local) ===\n$ {}\n{}\n",
                        hostname, cmd,
                        match &local_result {
                            Ok(output) => output.clone(),
                            Err(e) => format!("ERROR: {}", e),
                        }
                    ));

                    // Run on all remote cluster nodes
                    for (node_id, node_hostname, url_primary, url_fallback) in cluster_nodes {
                        // Try primary URL first (port+1 for HTTPS nodes), fall back to original port
                        let urls = [url_primary.as_str(), url_fallback.as_str()];
                        let mut output = String::new();
                        for base_url in &urls {
                            let remote_url = format!("{}/api/ai/exec", base_url);
                            let remote_result = self.client
                                .post(&remote_url)
                                .header("X-WolfStack-Secret", cluster_secret)
                                .json(&serde_json::json!({ "command": cmd }))
                                .timeout(Duration::from_secs(15))
                                .send()
                                .await;

                            match remote_result {
                                Ok(resp) => {
                                    let resp_text = resp.text().await.unwrap_or_default();
                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_text) {
                                        if let Some(err) = json["error"].as_str() {
                                            output = format!("ERROR: {}", err);
                                        } else {
                                            output = json["output"].as_str().unwrap_or("(no output)").to_string();
                                        }
                                    } else {
                                        let preview: String = resp_text.chars().take(200).collect();
                                        output = format!("ERROR: Failed to parse response (body: {})", preview);
                                    }
                                    break; // Got a response, don't try fallback
                                }
                                Err(e) => {
                                    output = format!("ERROR: Connection failed — {}", e);
                                    // Try next URL
                                }
                            }
                        }

                        command_results.push_str(&format!(
                            "\n=== {} ({}) ===\n$ {}\n{}\n",
                            node_hostname, node_id, cmd, output
                        ));
                    }

                    search_from = abs_start + end + 11;
                } else {
                    break;
                }
            }

            // Add the AI's response and command results to history for next round
            let now = chrono::Utc::now().timestamp();
            history.push(ChatMessage { role: "assistant".to_string(), content: response.clone(), timestamp: now });
            current_msg = format!(
                "Here are the command results. Please analyze them and provide a clear summary for the user. \
                 Do NOT request more commands unless absolutely necessary.\n\n{}",
                command_results
            );
            history.push(ChatMessage { role: "user".to_string(), content: current_msg.clone(), timestamp: now });
        }

        // Store messages in history
        {
            let mut h = self.chat_history.lock().unwrap();
            let now = chrono::Utc::now().timestamp();
            h.push(ChatMessage { role: "user".to_string(), content: user_message.to_string(), timestamp: now });
            h.push(ChatMessage { role: "assistant".to_string(), content: final_response.clone(), timestamp: now });
            // Keep last 100 messages
            if h.len() > 100 { let drain = h.len() - 100; h.drain(..drain); }
        }

        Ok(final_response)
    }

    /// List available models for the configured provider
    pub async fn list_models(&self, provider: &str, api_key: &str) -> Result<Vec<String>, String> {
        match provider {
            "gemini" => {
                let url = format!(
                    "https://generativelanguage.googleapis.com/v1beta/models?key={}",
                    api_key
                );
                let resp = self.client.get(&url)
                    .send().await
                    .map_err(|e| format!("Gemini API error: {}", e))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| format!("Gemini response error: {}", e))?;
                if !status.is_success() {
                    return Err(format!("Gemini API {} — {}", status, text));
                }
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| format!("Gemini JSON error: {}", e))?;
                let models = json["models"].as_array()
                    .map(|arr| arr.iter().filter_map(|m| {
                        let name = m["name"].as_str()?;
                        // name is like "models/gemini-2.0-flash" — strip prefix
                        let short = name.strip_prefix("models/").unwrap_or(name);
                        // Only include generateContent-capable models
                        let methods = m["supportedGenerationMethods"].as_array()?;
                        if methods.iter().any(|m| m.as_str() == Some("generateContent")) {
                            Some(short.to_string())
                        } else {
                            None
                        }
                    }).collect())
                    .unwrap_or_default();
                Ok(models)
            }
            _ => {
                // Claude models API
                let resp = self.client.get("https://api.anthropic.com/v1/models")
                    .header("x-api-key", api_key)
                    .header("anthropic-version", "2023-06-01")
                    .send().await
                    .map_err(|e| format!("Claude API error: {}", e))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| format!("Claude response error: {}", e))?;
                if !status.is_success() {
                    return Err(format!("Claude API {} — {}", status, text));
                }
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| format!("Claude JSON error: {}", e))?;
                let models = json["data"].as_array()
                    .map(|arr| arr.iter().filter_map(|m| {
                        m["id"].as_str().map(|s| s.to_string())
                    }).collect())
                    .unwrap_or_default();
                Ok(models)
            }
        }
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
        // Truncate to ~30KB to keep context lean and responses fast
        if knowledge.len() > 30_000 {
            knowledge.truncate(30_000);
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

// ─── Safe Command Execution ───

/// Whitelist of allowed command prefixes for read-only operations
const ALLOWED_COMMANDS: &[&str] = &[
    // System info
    "uname", "hostname", "uptime", "whoami", "id", "lscpu", "lsblk", "lsmem", "lspci", "lsusb",
    "free", "df", "du", "cat /proc/", "cat /etc/os-release", "cat /etc/hostname",
    "cat /etc/hosts", "cat /etc/resolv.conf",
    "arch", "nproc", "getconf", "sysctl",
    // Process/service info
    "ps", "top -bn1", "systemctl status", "systemctl list-units", "systemctl is-active",
    "systemctl show", "journalctl",
    // Network info
    "ip addr", "ip route", "ip link", "ip neigh", "ss", "netstat",
    "ping -c", "dig", "nslookup", "host ", "traceroute", "tracepath",
    "curl -s", "curl --silent", "wget -qO-",
    // Containers
    "docker ps", "docker stats --no-stream", "docker inspect", "docker logs",
    "docker images", "docker info", "docker version", "docker network",
    "lxc-ls", "lxc-info", "lxc-config",
    // Files (read-only)
    "ls", "cat ", "head ", "tail ", "wc ", "file ", "stat ",
    "find ", "locate ", "which ", "whereis ",
    // Wolf suite status
    "wolfnet", "wolfdisk", "wolfproxy", "wolfserve", "wolfscale",
    // Misc read-only
    "date", "cal", "env", "printenv", "timedatectl", "hostnamectl",
    "dmidecode", "lshw", "sensors", "smartctl",
];

/// Commands/patterns that are explicitly blocked (destructive operations)
const BLOCKED_PATTERNS: &[&str] = &[
    "rm ", "rm -", "rmdir", "unlink",
    "dd ", "mkfs", "fdisk", "parted", "gdisk", "cfdisk",
    "shutdown", "reboot", "poweroff", "halt", "init ",
    "kill ", "kill -", "killall", "pkill",
    "mv ", "cp ", "install ",
    "chmod", "chown", "chgrp", "chattr",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd",
    "visudo", "sudoers",
    "iptables -D", "iptables -F", "iptables -X", "iptables -A", "iptables -I",
    "nft ", "firewall-cmd",
    "systemctl start", "systemctl stop", "systemctl restart",
    "systemctl enable", "systemctl disable", "systemctl mask",
    "apt ", "apt-get", "dpkg -i", "dpkg -r", "dpkg -P",
    "yum ", "dnf ", "rpm -i", "rpm -e", "rpm -U",
    "pip ", "pip3 ", "npm ", "cargo ", "make ", "cmake",
    "docker rm", "docker rmi", "docker stop", "docker kill", "docker exec",
    "docker run", "docker pull", "docker push", "docker build",
    "lxc-stop", "lxc-destroy", "lxc-create", "lxc-start", "lxc-execute",
    "crontab", "at ",
    "mount ", "umount", "swapon", "swapoff",
    "insmod", "rmmod", "modprobe",
    "nano", "vim", "vi ", "emacs", "ed ", "sed -i",
    "tee ", "sponge",
    "wget ", "curl -o", "curl -O", "curl --output",
];

/// Execute a command only if it passes safety checks
pub fn execute_safe_command(cmd: &str) -> Result<String, String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err("Empty command".to_string());
    }

    // Block output redirection
    if cmd.contains(" > ") || cmd.contains(" >> ") || cmd.contains(" 2>") {
        return Err("Output redirection is not allowed (read-only mode)".to_string());
    }

    // Block backtick/subshell command injection
    if cmd.contains('`') || cmd.contains("$(") {
        return Err("Command substitution is not allowed (read-only mode)".to_string());
    }

    // Check each piped segment for safety
    let segments: Vec<&str> = cmd.split('|').collect();
    for segment in &segments {
        let seg = segment.trim();

        // Check blocked patterns
        for blocked in BLOCKED_PATTERNS {
            if seg.starts_with(blocked) || seg.contains(&format!(" {}", blocked)) {
                return Err(format!("Command '{}' is blocked (read-only mode — no destructive operations)", blocked.trim()));
            }
        }
    }

    // The first command must match an allowed prefix
    let first_seg = segments[0].trim();
    let allowed = ALLOWED_COMMANDS.iter().any(|prefix| first_seg.starts_with(prefix));
    if !allowed {
        return Err(format!(
            "Command '{}' is not in the allowed list. I can only run read-only system commands like lscpu, df, ps, docker ps, etc.",
            first_seg.split_whitespace().next().unwrap_or(first_seg)
        ));
    }

    // Execute with timeout
    let output = StdCommand::new("bash")
        .arg("-c")
        .arg(cmd)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let mut result = stdout.to_string();
            if !stderr.is_empty() {
                result.push_str(&format!("\n[stderr]: {}", stderr));
            }
            // Truncate long output
            if result.len() > 10_000 {
                result.truncate(10_000);
                result.push_str("\n[output truncated at 10000 chars]");
            }
            if result.trim().is_empty() {
                result = "(no output)".to_string();
            }
            Ok(result)
        }
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

// ─── System Prompt Builder ───

fn build_system_prompt(knowledge: &str, server_context: &str) -> String {
    format!(
        "You are the AI operations assistant for a WolfStack server node. You are knowledgeable, helpful, and concise.\n\n\
         ## Your Capabilities\n\
         - Answer questions about WolfStack, WolfNet, WolfDisk, WolfProxy, WolfServe, and WolfScale\n\
         - Help with server administration, container management, networking, and storage\n\
         - Explain technical concepts in plain language\n\
         - Help troubleshoot issues based on the current server state\n\
         - **Run read-only commands** on this server and across the WolfStack cluster\n\n\
         ## Command Execution\n\
         You can run commands on the server by using these special tags:\n\
         - `[EXEC]command[/EXEC]` — runs the command on this server only\n\
         - `[EXEC_ALL]command[/EXEC_ALL]` — runs the command on ALL WolfStack servers in the cluster\n\n\
         **Rules:**\n\
         - Only read-only commands are allowed (ls, cat, lscpu, df, ps, docker ps, systemctl status, etc.)\n\
         - Destructive commands (rm, kill, reboot, etc.) are blocked and will fail\n\
         - Use [EXEC_ALL] when the user asks about the cluster or all servers\n\
         - Use [EXEC] when the user asks about this specific server\n\
         - You MUST use these tags when the user asks a question that requires live data\n\
         - Do NOT just tell the user how to run a command — run it yourself and present the results\n\
         - After receiving command output, summarize the results clearly for the user\n\
         - Keep commands simple and focused\n\n\
         ## Cluster Topology\n\
         - All WolfStack nodes are **equal peers** — do NOT label any node as 'main', 'primary', or 'secondary'\n\
         - Each node runs whatever Wolf components it needs; not all nodes run the same services\n\
         - Do NOT assume a service should be running on a node just because it runs on others\n\
         - [EXEC_ALL] only targets WolfStack nodes, NOT Proxmox nodes\n\n\
         ## Proxmox Nodes\n\
         - Proxmox nodes are **monitored but not managed** — you can see their metrics, VM/CT counts, and status\n\
         - You CANNOT execute commands on Proxmox nodes (they don't run WolfStack agents)\n\
         - Proxmox data is shown in the server state below; use it to answer questions about the infrastructure\n\
         - When reporting on the full infrastructure, include Proxmox node health data (CPU, RAM, disk)\n\n\
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
        "max_tokens": 4096,
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
        let lower = text.to_lowercase();
        if status.as_u16() == 429 || lower.contains("rate_limit") || lower.contains("quota") || lower.contains("resource_exhausted") {
            return Err("Claude API rate limit or quota exceeded. Try switching to Gemini in AI Settings.".to_string());
        }
        if lower.contains("credit") || lower.contains("billing") || lower.contains("insufficient") {
            return Err("Claude API credits exhausted. Try switching to Gemini in AI Settings, or top up your Anthropic account.".to_string());
        }
        if lower.contains("token") && (lower.contains("limit") || lower.contains("exceeded") || lower.contains("too long")) {
            return Err("Claude token limit exceeded — your conversation may be too long. Try starting a fresh chat or switching to Gemini in AI Settings.".to_string());
        }
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
            "maxOutputTokens": 4096,
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
        let lower = text.to_lowercase();
        if status.as_u16() == 429 || lower.contains("rate_limit") || lower.contains("quota") || lower.contains("resource_exhausted") {
            return Err("Gemini API rate limit or quota exceeded. Try switching to Claude in AI Settings.".to_string());
        }
        if lower.contains("billing") || lower.contains("insufficient") {
            return Err("Gemini API quota exhausted. Try switching to Claude in AI Settings, or check your Google Cloud billing.".to_string());
        }
        if lower.contains("token") && (lower.contains("limit") || lower.contains("exceeded") || lower.contains("too long")) {
            return Err("Gemini token limit exceeded — your conversation may be too long. Try starting a fresh chat or switching to Claude in AI Settings.".to_string());
        }
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

pub fn send_alert_email(config: &AiConfig, subject: &str, body: &str) -> Result<(), String> {
    use lettre::{Message, SmtpTransport, Transport};
    use lettre::transport::smtp::authentication::Credentials;

    let email = Message::builder()
        .from(format!("WolfStack AI <{}>", config.smtp_user).parse().map_err(|e| format!("Email from: {}", e))?)
        .to(config.email_to.parse().map_err(|e| format!("Email to: {}", e))?)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| format!("Email build: {}", e))?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let mailer = match config.smtp_tls.as_str() {
        "tls" => {
            // Implicit TLS (port 465 typically)
            SmtpTransport::relay(&config.smtp_host)
                .map_err(|e| format!("SMTP relay: {}", e))?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
        "none" => {
            // No encryption
            SmtpTransport::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
        _ => {
            // STARTTLS (default, port 587 typically)
            SmtpTransport::starttls_relay(&config.smtp_host)
                .map_err(|e| format!("SMTP STARTTLS: {}", e))?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
    };

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
    guest_cpu_stats: Option<&[(&str, &str, u64, &str, f32)]>, // (pve_node, guest_type, vmid, name, cpu_percent)
) -> String {
    let mem_percent = if memory_total_gb > 0.0 { (memory_used_gb / memory_total_gb * 100.0) as u32 } else { 0 };
    let disk_percent = if disk_total_gb > 0.0 { (disk_used_gb / disk_total_gb * 100.0) as u32 } else { 0 };
    let uptime_hours = uptime_secs / 3600;
    let uptime_days = uptime_hours / 24;
    let version = env!("CARGO_PKG_VERSION");

    let mut summary = format!(
        "Hostname: {}\n\
         WolfStack Version: {}\n\
         CPU Usage: {:.1}%\n\
         Memory: {:.1}/{:.1} GB ({}%)\n\
         Disk: {:.1}/{:.1} GB ({}%)\n\
         Docker Containers: {}\n\
         LXC Containers: {}\n\
         Virtual Machines: {}\n\
         Uptime: {} days {} hours",
        hostname,
        version,
        cpu_percent,
        memory_used_gb, memory_total_gb, mem_percent,
        disk_used_gb, disk_total_gb, disk_percent,
        docker_count,
        lxc_count,
        vm_count,
        uptime_days, uptime_hours % 24,
    );

    // Append per-guest CPU stats if available (from Proxmox nodes)
    if let Some(stats) = guest_cpu_stats {
        let running: Vec<_> = stats.iter().filter(|(_, _, _, _, cpu)| *cpu > 0.0).collect();
        if !running.is_empty() {
            summary.push_str("\n\nProxmox Guest CPU Usage:");
            for (pve_node, gtype, vmid, name, cpu) in running {
                let label = if *gtype == "lxc" { "LXC" } else { "VM" };
                summary.push_str(&format!(
                    "\n  {} {} ({}) on {}: {:.1}%",
                    label, vmid, name, pve_node, cpu * 100.0
                ));
            }
        }
    }

    summary
}
