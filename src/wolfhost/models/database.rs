use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerDatabase {
    pub id: String,
    pub service_id: String,
    pub customer_id: String,
    pub name: String,
    #[serde(default = "default_db_type")]
    pub db_type: DatabaseType,
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default)]
    pub size_mb: u64,
    pub status: DatabaseStatus,
    pub created_at: String,
}

fn default_db_type() -> DatabaseType { DatabaseType::MariaDB }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    MariaDB,
    #[serde(alias = "mysql")]
    MySQL, // Treated identically to MariaDB; retained for legacy records.
    PostgreSQL,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseStatus {
    Active,
    Suspended,
}

#[derive(Debug, Deserialize)]
pub struct CreateDatabaseRequest {
    pub service_id: String,
    pub name: String,
    #[serde(default = "default_db_type")]
    pub db_type: DatabaseType,
    pub username: String,
    pub password: String,
}

