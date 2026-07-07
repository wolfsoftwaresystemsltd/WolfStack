use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::RwLock;

const CONFIG_PATH: &str = "/etc/wolfstack/plugins/wolfhost/config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branding {
    #[serde(default = "default_company")]
    pub company_name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub logo_url: String,
    #[serde(default = "default_icon")]
    pub favicon_emoji: String,
    #[serde(default = "default_accent")]
    pub accent_color: String,
    #[serde(default)]
    pub accent_light: String,
    #[serde(default)]
    pub support_email: String,
    #[serde(default)]
    pub support_url: String,
    #[serde(default)]
    pub terms_url: String,
    #[serde(default)]
    pub footer_text: String,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub custom_css: String,
    #[serde(default)]
    pub ns1: String,
    #[serde(default)]
    pub ns2: String,
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            company_name: default_company(),
            tagline: String::new(),
            logo_url: String::new(),
            favicon_emoji: default_icon(),
            accent_color: default_accent(),
            accent_light: String::new(),
            support_email: String::new(),
            support_url: String::new(),
            terms_url: String::new(),
            footer_text: String::new(),
            currency: default_currency(),
            custom_css: String::new(),
            ns1: String::new(),
            ns2: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_db_host")]
    pub host: String,
    #[serde(default = "default_db_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_db_name")]
    pub database: String,
}

fn default_db_host() -> String { "127.0.0.1".to_string() }
fn default_db_port() -> u16 { 3306 }
fn default_db_name() -> String { "wolfhost".to_string() }

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_db_host(),
            port: default_db_port(),
            username: String::new(),
            password: String::new(),
            database: default_db_name(),
        }
    }
}

impl DatabaseConfig {
    pub fn connection_url(&self) -> String {
        format!(
            "mysql://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfHostConfig {
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_portal_port")]
    pub portal_port: u16,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_portal_dir")]
    pub portal_web_dir: String,
    #[serde(default)]
    pub branding: Branding,
    #[serde(default)]
    pub database: DatabaseConfig,
}

fn default_api_port() -> u16 { 9200 }
fn default_portal_port() -> u16 { 8443 }
fn default_company() -> String { "My Hosting".to_string() }
fn default_currency() -> String { "USD".to_string() }
fn default_icon() -> String { "🌐".to_string() }
fn default_accent() -> String { "#dc2626".to_string() }
fn default_data_dir() -> String { "/etc/wolfstack/plugins/wolfhost/data".to_string() }
fn default_portal_dir() -> String { "/etc/wolfstack/plugins/wolfhost/web/portal".to_string() }

impl Default for WolfHostConfig {
    fn default() -> Self {
        Self {
            api_port: default_api_port(),
            portal_port: default_portal_port(),
            data_dir: default_data_dir(),
            portal_web_dir: default_portal_dir(),
            branding: Branding::default(),
            database: DatabaseConfig::default(),
        }
    }
}

impl WolfHostConfig {
    pub fn load() -> Self {
        if Path::new(CONFIG_PATH).exists() {
            match std::fs::read_to_string(CONFIG_PATH) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            Self::default()
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize error: {}", e))?;
        let tmp = format!("{}.tmp", CONFIG_PATH);
        std::fs::write(&tmp, &json)
            .map_err(|e| format!("Write error: {}", e))?;
        std::fs::rename(&tmp, CONFIG_PATH)
            .map_err(|e| format!("Rename error: {}", e))?;
        Ok(())
    }
}

/// Thread-safe mutable config holder
pub struct ConfigStore {
    inner: RwLock<WolfHostConfig>,
}

impl ConfigStore {
    pub fn new(config: WolfHostConfig) -> Self {
        Self { inner: RwLock::new(config) }
    }

    pub fn get(&self) -> WolfHostConfig {
        self.inner.read().unwrap().clone()
    }

    pub fn get_branding(&self) -> Branding {
        self.inner.read().unwrap().branding.clone()
    }

    pub fn update_branding(&self, branding: Branding) -> Result<(), String> {
        let mut config = self.inner.write().unwrap();
        config.branding = branding;
        config.save()
    }

    pub fn get_database(&self) -> DatabaseConfig {
        self.inner.read().unwrap().database.clone()
    }

    pub fn update_database(&self, db: DatabaseConfig) -> Result<(), String> {
        let mut config = self.inner.write().unwrap();
        config.database = db;
        config.save()
    }
}
