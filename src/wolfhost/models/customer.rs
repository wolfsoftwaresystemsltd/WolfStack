use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    #[serde(default)]
    pub line1: String,
    #[serde(default)]
    pub line2: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub zip: String,
    #[serde(default)]
    pub country: String,
}

impl Default for Address {
    fn default() -> Self {
        Self {
            line1: String::new(),
            line2: String::new(),
            city: String::new(),
            state: String::new(),
            zip: String::new(),
            country: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub address: Address,
    pub status: CustomerStatus,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CustomerStatus {
    Active,
    Suspended,
    Pending,
    Cancelled,
}

#[derive(Debug, Deserialize)]
pub struct CreateCustomerRequest {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub address: Option<Address>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCustomerRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
    pub notes: Option<String>,
    pub status: Option<CustomerStatus>,
}
