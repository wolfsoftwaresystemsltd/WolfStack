use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectAdminInstance {
    pub id: String,
    /// Human-readable label (e.g. "DA Server 1")
    pub name: String,
    /// DirectAdmin URL including port (e.g. "https://10.0.0.50:2222")
    pub url: String,
    /// DA admin username
    pub admin_user: String,
    /// DA admin password — stored base64-obfuscated (not plaintext)
    #[serde(default)]
    pub admin_password_enc: String,
    /// WolfStack node ID this DA runs on (optional)
    #[serde(default)]
    pub node_id: String,
    pub status: DirectAdminStatus,
    #[serde(default)]
    pub last_sync: String,
    #[serde(default)]
    pub user_count: u32,
    #[serde(default)]
    pub domain_count: u32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DirectAdminStatus {
    Online,
    Offline,
    Syncing,
    Error,
}

#[derive(Debug, Deserialize)]
pub struct CreateDirectAdminRequest {
    pub name: String,
    pub url: String,
    pub admin_user: String,
    pub admin_password: String,
    #[serde(default)]
    pub node_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDirectAdminRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
    pub node_id: Option<String>,
}
