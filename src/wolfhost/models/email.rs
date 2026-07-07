use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAccount {
    pub id: String,
    pub service_id: String,
    pub customer_id: String,
    pub address: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default = "default_quota")]
    pub quota_mb: u64,
    #[serde(default)]
    pub forwarding: Vec<String>,
    pub status: EmailStatus,
    pub created_at: String,
}

fn default_quota() -> u64 { 500 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EmailStatus {
    Active,
    Disabled,
}

#[derive(Debug, Deserialize)]
pub struct CreateEmailRequest {
    pub service_id: String,
    pub address: String,
    pub password: String,
    #[serde(default = "default_quota")]
    pub quota_mb: u64,
    #[serde(default)]
    pub forwarding: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEmailRequest {
    pub password: Option<String>,
    pub quota_mb: Option<u64>,
    pub forwarding: Option<Vec<String>>,
    pub status: Option<EmailStatus>,
}
