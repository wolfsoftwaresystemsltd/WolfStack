// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfNote Integration — connect to WolfNote (https://app.wolfnote.org)
//!
//! Allows WolfStack users to:
//! - Authenticate with their WolfNote account
//! - Create notes and folders from the WolfStack dashboard
//! - Use the AI chat to create notes automatically
//! - Toggle integration features on/off

use serde::{Deserialize, Serialize};

fn wolfnote_config_path() -> String { crate::paths::get().wolfnote_config }

/// Shared HTTP client for every WolfNote API call. Replaces the
/// per-`WolfNoteClient::new` + per-`login()` fresh Client that was
/// leaking a connection pool on every note/folder list/create.
static WOLFNOTE_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(15))
            .use_rustls_tls()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Default WolfNote instance URL
const DEFAULT_WOLFNOTE_URL: &str = "https://app.wolfnote.org";

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteConfig {
    #[serde(default = "default_url")]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub company: String,
    /// Feature toggles
    #[serde(default)]
    pub features: WolfNoteFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteFeatures {
    /// Allow AI chat to create notes
    #[serde(default = "default_true")]
    pub ai_create_notes: bool,
    #[serde(default)]
    pub ai_folder_id: String,
    /// Auto-log server events as notes
    #[serde(default)]
    pub auto_log_events: bool,
    #[serde(default)]
    pub events_folder_id: String,
    /// Auto-create incident notes from status page incidents
    #[serde(default)]
    pub incident_notes: bool,
    #[serde(default)]
    pub incidents_folder_id: String,
    /// Auto-log backup results as notes
    #[serde(default)]
    pub backup_notes: bool,
    #[serde(default)]
    pub backups_folder_id: String,
    /// Auto-log alert events as notes
    #[serde(default)]
    pub alert_notes: bool,
    #[serde(default)]
    pub alerts_folder_id: String,
}

impl Default for WolfNoteFeatures {
    fn default() -> Self {
        Self {
            ai_create_notes: true,
            ai_folder_id: String::new(),
            auto_log_events: false,
            events_folder_id: String::new(),
            incident_notes: false,
            incidents_folder_id: String::new(),
            backup_notes: false,
            backups_folder_id: String::new(),
            alert_notes: false,
            alerts_folder_id: String::new(),
        }
    }
}

fn default_url() -> String { DEFAULT_WOLFNOTE_URL.to_string() }
fn default_true() -> bool { true }

impl Default for WolfNoteConfig {
    fn default() -> Self {
        Self {
            url: default_url(),
            token: String::new(),
            username: String::new(),
            company: String::new(),
            features: WolfNoteFeatures::default(),
        }
    }
}

impl WolfNoteConfig {
    pub fn load() -> Self {
        let path = wolfnote_config_path();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = wolfnote_config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }

    pub fn is_connected(&self) -> bool {
        !self.token.is_empty()
    }
}

// ─── WolfNote API Client ───

/// Login response from WolfNote
#[derive(Debug, Deserialize)]
pub struct WolfNoteLoginResponse {
    pub token: String,
    pub user: WolfNoteUser,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct WolfNoteUser {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email: String,
}

/// Folder from WolfNote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteFolder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

/// Note from WolfNote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteNote {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub note_type: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// WolfNote API client — all calls go through WolfStack backend to avoid CORS
pub struct WolfNoteClient {
    client: reqwest::Client,
    base_url: String,
    token: String,
}

impl WolfNoteClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        // Cheap Arc clone of the shared pool — see WOLFNOTE_CLIENT.
        Self {
            client: reqwest::Client::clone(&WOLFNOTE_CLIENT),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    /// Login to WolfNote and get a JWT token
    pub async fn login(base_url: &str, username: &str, password: &str, company: &str) -> Result<WolfNoteLoginResponse, String> {
        let client = &*WOLFNOTE_CLIENT;

        let url = format!("{}/api/auth/login", base_url.trim_end_matches('/'));
        let resp = client.post(&url)
            .json(&serde_json::json!({
                "username": username,
                "password": password,
                "company": company,
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to connect to WolfNote: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote login failed ({}): {}", status, body));
        }

        resp.json::<WolfNoteLoginResponse>()
            .await
            .map_err(|e| format!("Invalid WolfNote response: {}", e))
    }

    /// List folders
    pub async fn list_folders(&self) -> Result<Vec<WolfNoteFolder>, String> {
        let url = format!("{}/api/folders", self.base_url);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;  // drain → socket back to pool
            return Err(format!("WolfNote error: {}", status));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// List notes (optionally filtered by folder)
    pub async fn list_notes(&self) -> Result<Vec<WolfNoteNote>, String> {
        let url = format!("{}/api/notes", self.base_url);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;
            return Err(format!("WolfNote error: {}", status));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// Create a note
    pub async fn create_note(&self, title: &str, content: &str, folder_id: Option<&str>) -> Result<WolfNoteNote, String> {
        let url = format!("{}/api/notes", self.base_url);
        let mut body = serde_json::json!({
            "title": title,
            "content": content,
        });
        if let Some(fid) = folder_id {
            body["folder_id"] = serde_json::Value::String(fid.to_string());
        }

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote error ({}): {}", status, body));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// Get a single note by ID (returns full content)
    pub async fn get_note(&self, note_id: &str) -> Result<WolfNoteNote, String> {
        let url = format!("{}/api/notes/{}", self.base_url, note_id);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;
            return Err(format!("WolfNote error: {}", status));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// Update a note (any combination of title, content, folder_id, note_type)
    pub async fn update_note(&self, note_id: &str, body: &serde_json::Value) -> Result<(), String> {
        let url = format!("{}/api/notes/{}", self.base_url, note_id);
        let resp = self.client.put(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(body)
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote error ({}): {}", status, body));
        }
        Ok(())
    }

    /// Add an alert as a todo item to the "Alerts" tasklist in the given folder.
    /// Creates the tasklist if it doesn't exist yet.
    /// `alert_title` is the summary line, `alert_body` contains the full details.
    pub async fn add_alert_todo(&self, alert_title: &str, alert_body: &str, folder_id: Option<&str>) -> Result<(), String> {
        // 1. List notes to find an existing "Alerts" tasklist in the folder
        let notes = self.list_notes().await?;
        let existing = notes.iter().find(|n| {
            n.title == "Alerts"
                && n.note_type.as_deref() == Some("tasklist")
                && n.folder_id.as_deref() == folder_id
        });

        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        // Build detail lines from body — convert newlines to <br> for HTML
        let detail_html = if alert_body.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="task-detail" style="font-size:0.85em;color:#888;margin-top:4px;white-space:pre-wrap;">{}</div>"#,
                html_escape(alert_body)
            )
        };
        let new_item = format!(
            r#"<div class="task-item"><div class="task-check"></div><div class="task-text">{} — {}{}</div></div>"#,
            html_escape(alert_title), timestamp, detail_html
        );

        if let Some(note) = existing {
            // 2a. Append to existing tasklist
            let full = self.get_note(&note.id).await?;
            let updated_content = format!("{}{}", full.content, new_item);
            self.update_note(&note.id, &serde_json::json!({
                "content": updated_content,
            })).await
        } else {
            // 2b. Create new "Alerts" tasklist
            let url = format!("{}/api/notes", self.base_url);
            let mut body = serde_json::json!({
                "title": "Alerts",
                "content": new_item,
                "note_type": "tasklist",
            });
            if let Some(fid) = folder_id {
                body["folder_id"] = serde_json::Value::String(fid.to_string());
            }
            let resp = self.client.post(&url)
                .header("Authorization", format!("Bearer {}", self.token))
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("WolfNote request failed: {}", e))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("WolfNote error ({}): {}", status, body));
            }
            Ok(())
        }
    }

    /// Create a folder
    pub async fn create_folder(&self, name: &str, parent_id: Option<&str>, color: Option<&str>) -> Result<WolfNoteFolder, String> {
        let url = format!("{}/api/folders", self.base_url);
        let mut body = serde_json::json!({ "name": name });
        if let Some(pid) = parent_id {
            body["parent_id"] = serde_json::Value::String(pid.to_string());
        }
        if let Some(c) = color {
            body["color"] = serde_json::Value::String(c.to_string());
        }

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote error ({}): {}", status, body));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }
}

/// Minimal HTML escaping for alert text inserted into task items
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Log an alert to WolfNote as a todo item if alert_notes is enabled.
/// Call from background tasks — failures are logged and swallowed.
/// `body` contains the full alert details (hostname, metric values, AI recommendations, etc.)
pub async fn log_alert_to_wolfnote(title: &str, body: &str) {
    let config = WolfNoteConfig::load();
    if !config.is_connected() || !config.features.alert_notes {
        return;
    }
    let folder_id = if config.features.alerts_folder_id.is_empty() {
        None
    } else {
        Some(config.features.alerts_folder_id.as_str())
    };
    let client = WolfNoteClient::new(&config.url, &config.token);
    if let Err(e) = client.add_alert_todo(title, body, folder_id).await {
        tracing::warn!("WolfNote alert todo failed: {}", e);
    }
}
