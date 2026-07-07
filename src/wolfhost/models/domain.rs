use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_ttl() -> u32 { 3600 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: String,
    pub service_id: String,
    pub customer_id: String,
    pub name: String,
    #[serde(default = "default_domain_type")]
    pub domain_type: DomainType,
    #[serde(default)]
    pub document_root: String,
    #[serde(default)]
    pub dns_records: Vec<DnsRecord>,
    pub status: DomainStatus,
    pub created_at: String,
}

fn default_domain_type() -> DomainType { DomainType::Primary }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DomainType {
    Primary,
    Addon,
    Subdomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    Active,
    PendingDns,
    Suspended,
}

#[derive(Debug, Deserialize)]
pub struct CreateDomainRequest {
    pub service_id: String,
    pub name: String,
    #[serde(default = "default_domain_type")]
    pub domain_type: DomainType,
    #[serde(default)]
    pub document_root: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDomainRequest {
    pub document_root: Option<String>,
    pub dns_records: Option<Vec<DnsRecord>>,
    pub status: Option<DomainStatus>,
}
