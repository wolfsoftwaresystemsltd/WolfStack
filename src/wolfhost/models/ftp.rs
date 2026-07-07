use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpAccount {
    pub id: String,
    pub service_id: String,
    pub customer_id: String,
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default)]
    pub home_dir: String,
    #[serde(default = "default_quota")]
    pub quota_mb: u64,
    pub status: FtpStatus,
    pub created_at: String,
}

fn default_quota() -> u64 { 1024 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FtpStatus {
    Active,
    Disabled,
}

#[derive(Debug, Deserialize)]
pub struct CreateFtpRequest {
    pub service_id: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub home_dir: String,
    #[serde(default = "default_quota")]
    pub quota_mb: u64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFtpRequest {
    pub password: Option<String>,
    pub home_dir: Option<String>,
    pub quota_mb: Option<u64>,
    pub status: Option<FtpStatus>,
}
