use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketMessage {
    pub id: String,
    pub author: MessageAuthor,
    pub author_name: String,
    pub content: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageAuthor {
    Customer,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub customer_id: String,
    #[serde(default)]
    pub service_id: String,
    pub subject: String,
    pub status: TicketStatus,
    #[serde(default = "default_priority")]
    pub priority: TicketPriority,
    #[serde(default)]
    pub messages: Vec<TicketMessage>,
    pub created_at: String,
    pub updated_at: String,
}

fn default_priority() -> TicketPriority { TicketPriority::Medium }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TicketStatus {
    Open,
    InProgress,
    Waiting,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TicketPriority {
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Deserialize)]
pub struct CreateTicketRequest {
    #[serde(default)]
    pub service_id: String,
    pub subject: String,
    #[serde(default = "default_priority")]
    pub priority: TicketPriority,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTicketRequest {
    pub status: Option<TicketStatus>,
    pub priority: Option<TicketPriority>,
}

#[derive(Debug, Deserialize)]
pub struct TicketReplyRequest {
    pub content: String,
    pub author: MessageAuthor,
    pub author_name: String,
}
