use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceUsage {
    #[serde(default)]
    pub disk_mb: u64,
    #[serde(default)]
    pub bandwidth_mb: u64,
}

impl Default for ServiceUsage {
    fn default() -> Self {
        Self { disk_mb: 0, bandwidth_mb: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostingService {
    pub id: String,
    pub customer_id: String,
    pub plan_id: String,
    #[serde(default)]
    pub domain: String,
    pub status: ServiceStatus,
    #[serde(default = "default_monthly")]
    pub billing_cycle: BillingCycle,
    #[serde(default)]
    pub next_billing: String,
    #[serde(default)]
    pub server_node: String,
    #[serde(default)]
    pub home_dir: String,
    #[serde(default)]
    pub container_name: String,
    #[serde(default)]
    pub container_ip: String,
    #[serde(default)]
    pub host_ip: String,
    #[serde(default)]
    pub host_hostname: String,
    #[serde(default)]
    pub ftp_port: u16,
    #[serde(default)]
    pub usage: ServiceUsage,
    /// Backend: "native" (WolfHost manages directly) or "directadmin" (proxied to DA)
    #[serde(default = "default_native")]
    pub backend: ServiceBackend,
    /// DirectAdmin instance ID (only set when backend = directadmin)
    #[serde(default)]
    pub da_instance_id: String,
    /// DirectAdmin username for this service (the DA user account)
    #[serde(default)]
    pub da_username: String,
    pub created_at: String,
    #[serde(default)]
    pub expires_at: String,
}

fn default_monthly() -> BillingCycle { BillingCycle::Monthly }
fn default_native() -> ServiceBackend { ServiceBackend::Native }

/// Whether the service is managed natively by WolfHost or proxied through DirectAdmin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceBackend {
    /// WolfHost manages nginx, postfix, mariadb, FTP directly
    Native,
    /// Operations proxied to a DirectAdmin instance
    DirectAdmin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Active,
    Suspended,
    Pending,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BillingCycle {
    Monthly,
    Yearly,
}

#[derive(Debug, Deserialize)]
pub struct CreateServiceRequest {
    pub customer_id: String,
    pub plan_id: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default = "default_monthly")]
    pub billing_cycle: BillingCycle,
    #[serde(default)]
    pub server_node: String,
    #[serde(default = "default_native")]
    pub backend: ServiceBackend,
    #[serde(default)]
    pub da_instance_id: String,
    /// Existing DA username to link — if empty and backend=directadmin, a new DA user is created
    #[serde(default)]
    pub da_username: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServiceRequest {
    pub domain: Option<String>,
    pub status: Option<ServiceStatus>,
    pub billing_cycle: Option<BillingCycle>,
    pub plan_id: Option<String>,
    pub server_node: Option<String>,
}
