use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub customer_id: String,
    #[serde(default)]
    pub service_id: String,
    pub amount: f64,
    #[serde(default = "default_currency")]
    pub currency: String,
    pub status: InvoiceStatus,
    #[serde(default)]
    pub description: String,
    pub issued_at: String,
    pub due_at: String,
    #[serde(default)]
    pub paid_at: Option<String>,
}

fn default_currency() -> String { "USD".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InvoiceStatus {
    Paid,
    Pending,
    Overdue,
    Cancelled,
}

#[derive(Debug, Deserialize)]
pub struct CreateInvoiceRequest {
    pub customer_id: String,
    #[serde(default)]
    pub service_id: String,
    pub amount: f64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub description: String,
    pub due_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInvoiceRequest {
    pub status: Option<InvoiceStatus>,
    pub amount: Option<f64>,
    pub description: Option<String>,
    pub due_at: Option<String>,
    pub paid_at: Option<String>,
}
