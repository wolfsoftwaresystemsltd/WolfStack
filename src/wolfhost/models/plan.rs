use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub price_monthly: f64,
    #[serde(default)]
    pub price_yearly: f64,
    pub disk_mb: u64,
    pub bandwidth_mb: u64,
    #[serde(default = "default_limit")]
    pub domains: u32,
    #[serde(default = "default_limit")]
    pub subdomains: u32,
    #[serde(default = "default_limit")]
    pub ftp_accounts: u32,
    #[serde(default = "default_limit")]
    pub email_accounts: u32,
    #[serde(default = "default_small")]
    pub databases: u32,
    #[serde(default = "default_limit")]
    pub ssl_certificates: u32,
    #[serde(default = "default_true")]
    pub backups: bool,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub sort_order: u32,
    #[serde(default = "default_true")]
    pub active: bool,
    pub created_at: String,
}

fn default_limit() -> u32 { 5 }
fn default_small() -> u32 { 3 }
fn default_true() -> bool { true }

#[derive(Debug, Deserialize)]
pub struct CreatePlanRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub price_monthly: f64,
    #[serde(default)]
    pub price_yearly: f64,
    pub disk_mb: u64,
    pub bandwidth_mb: u64,
    #[serde(default = "default_limit")]
    pub domains: u32,
    #[serde(default = "default_limit")]
    pub subdomains: u32,
    #[serde(default = "default_limit")]
    pub ftp_accounts: u32,
    #[serde(default = "default_limit")]
    pub email_accounts: u32,
    #[serde(default = "default_small")]
    pub databases: u32,
    #[serde(default = "default_limit")]
    pub ssl_certificates: u32,
    #[serde(default = "default_true")]
    pub backups: bool,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub sort_order: u32,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePlanRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price_monthly: Option<f64>,
    pub price_yearly: Option<f64>,
    pub disk_mb: Option<u64>,
    pub bandwidth_mb: Option<u64>,
    pub domains: Option<u32>,
    pub subdomains: Option<u32>,
    pub ftp_accounts: Option<u32>,
    pub email_accounts: Option<u32>,
    pub databases: Option<u32>,
    pub ssl_certificates: Option<u32>,
    pub backups: Option<bool>,
    pub features: Option<Vec<String>>,
    pub sort_order: Option<u32>,
    pub active: Option<bool>,
}
