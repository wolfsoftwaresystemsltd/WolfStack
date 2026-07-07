use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub service_id: String,
    pub customer_id: String,
    pub domain: String,
    #[serde(default = "default_cert_type")]
    pub cert_type: CertificateType,
    pub status: CertificateStatus,
    #[serde(default)]
    pub issued_at: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    pub created_at: String,
}

fn default_cert_type() -> CertificateType { CertificateType::LetsEncrypt }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CertificateType {
    LetsEncrypt,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Active,
    Pending,
    Expired,
    Failed,
}

#[derive(Debug, Deserialize)]
pub struct CreateCertificateRequest {
    pub service_id: String,
    pub domain: String,
    #[serde(default = "default_cert_type")]
    pub cert_type: CertificateType,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
}
