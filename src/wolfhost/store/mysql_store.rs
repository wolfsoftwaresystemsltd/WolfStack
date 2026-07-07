use serde::{de::DeserializeOwned, Serialize};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;

/// Connect to MariaDB/MySQL and return a pool
pub async fn connect(url: &str) -> Result<MySqlPool, String> {
    MySqlPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))
}

/// Test a database connection
pub async fn test_connection(url: &str) -> Result<String, String> {
    let pool = connect(url).await?;
    let row: (String,) = sqlx::query_as("SELECT VERSION()")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("Query failed: {}", e))?;
    pool.close().await;
    Ok(row.0)
}

/// Create all required tables if they don't exist
pub async fn run_migrations(pool: &MySqlPool) -> Result<(), String> {
    let tables = [
        ("customers", r#"CREATE TABLE IF NOT EXISTS customers (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("plans", r#"CREATE TABLE IF NOT EXISTS plans (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("services", r#"CREATE TABLE IF NOT EXISTS services (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("invoices", r#"CREATE TABLE IF NOT EXISTS invoices (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("tickets", r#"CREATE TABLE IF NOT EXISTS tickets (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("domains", r#"CREATE TABLE IF NOT EXISTS domains (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("ftp_accounts", r#"CREATE TABLE IF NOT EXISTS ftp_accounts (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("certificates", r#"CREATE TABLE IF NOT EXISTS certificates (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("databases", r#"CREATE TABLE IF NOT EXISTS customer_databases (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
        ("email_accounts", r#"CREATE TABLE IF NOT EXISTS email_accounts (
            id VARCHAR(36) PRIMARY KEY,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"#),
    ];

    for (name, sql) in &tables {
        sqlx::query(sql)
            .execute(pool)
            .await
            .map_err(|e| format!("Failed to create table '{}': {}", name, e))?;
        log::info!("Table '{}' ready", name);
    }
    Ok(())
}

/// Load all rows from a table, deserializing from JSON data column
pub async fn load_all<T: DeserializeOwned>(pool: &MySqlPool, table: &str) -> Result<Vec<T>, String> {
    let query = format!("SELECT data FROM `{}`", sanitize_table(table));
    let rows = sqlx::query(&query)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("Failed to load from '{}': {}", table, e))?;

    let mut items = Vec::new();
    for row in rows {
        let json: String = row.try_get("data")
            .map_err(|e| format!("Failed to read data column: {}", e))?;
        let item: T = serde_json::from_str(&json)
            .map_err(|e| format!("Failed to deserialize row: {}", e))?;
        items.push(item);
    }
    Ok(items)
}

/// Save all items to a table (replace all rows)
pub async fn save_all<T: Serialize>(pool: &MySqlPool, table: &str, items: &[T], id_fn: fn(&T) -> String) -> Result<(), String> {
    let table = sanitize_table(table);

    let mut tx = pool.begin().await.map_err(|e| format!("Transaction begin failed: {}", e))?;

    // Delete all existing
    sqlx::query(&format!("DELETE FROM `{}`", table))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Delete failed: {}", e))?;

    // Insert all
    for item in items {
        let id = id_fn(item);
        let json = serde_json::to_string(item)
            .map_err(|e| format!("Serialize error: {}", e))?;
        sqlx::query(&format!("INSERT INTO `{}` (id, data) VALUES (?, ?)", table))
            .bind(&id)
            .bind(&json)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Insert failed: {}", e))?;
    }

    tx.commit().await.map_err(|e| format!("Commit failed: {}", e))?;
    Ok(())
}

fn sanitize_table(name: &str) -> String {
    name.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect()
}
