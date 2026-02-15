// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! MySQL Database Editor — detection, connection, and query execution

use mysql_async::prelude::*;
use mysql_async::{Opts, OptsBuilder, Pool, Row, Value};
use serde::{Deserialize, Serialize};

/// Connection parameters sent from the frontend
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnParams {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    /// Optional: which database to USE
    #[serde(default)]
    pub database: Option<String>,
}

fn default_port() -> u16 {
    3306
}

impl ConnParams {
    fn to_opts(&self) -> Opts {
        let mut builder = OptsBuilder::default()
            .ip_or_hostname(&self.host)
            .tcp_port(self.port)
            .user(Some(&self.user))
            .pass(Some(&self.password));
        if let Some(db) = &self.database {
            if !db.is_empty() {
                builder = builder.db_name(Some(db));
            }
        }
        builder.into()
    }
}

/// Detect if MySQL server or client binaries are installed on this machine
pub fn detect_mysql() -> serde_json::Value {
    let paths_to_check = [
        "/usr/bin/mysql",
        "/usr/sbin/mysqld",
        "/usr/bin/mariadb",
        "/usr/sbin/mariadbd",
        "/usr/local/bin/mysql",
        "/usr/local/sbin/mysqld",
    ];

    let mut found = Vec::new();
    for path in &paths_to_check {
        if std::path::Path::new(path).exists() {
            found.push(*path);
        }
    }

    // Also check PATH via `which`
    for bin in &["mysql", "mysqld", "mariadb", "mariadbd"] {
        if let Ok(output) = std::process::Command::new("which").arg(bin).output() {
            if output.status.success() {
                let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !found.iter().any(|f| *f == p.as_str()) {
                    found.push(Box::leak(p.into_boxed_str()));
                }
            }
        }
    }

    // Try to get version if mysql client is available
    let version = std::process::Command::new("mysql")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        });

    // Check if mysqld service is running
    let service_running = std::process::Command::new("systemctl")
        .args(["is-active", "mysql"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
        || std::process::Command::new("systemctl")
            .args(["is-active", "mariadb"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);

    serde_json::json!({
        "installed": !found.is_empty(),
        "binaries": found,
        "version": version,
        "service_running": service_running,
    })
}

/// Test a MySQL connection — returns the server version string on success
pub async fn test_connection(params: &ConnParams) -> Result<String, String> {
    let pool = Pool::new(params.to_opts());
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    let version: Option<String> = conn
        .query_first("SELECT VERSION()")
        .await
        .map_err(|e| format!("Query failed: {}", e))?;

    pool.disconnect().await.map_err(|e| format!("Disconnect error: {}", e))?;

    Ok(version.unwrap_or_else(|| "unknown".into()))
}

/// List all databases
pub async fn list_databases(params: &ConnParams) -> Result<Vec<String>, String> {
    let pool = Pool::new(params.to_opts());
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    let databases: Vec<String> = conn
        .query("SHOW DATABASES")
        .await
        .map_err(|e| format!("Query failed: {}", e))?;

    pool.disconnect().await.ok();
    Ok(databases)
}

/// List tables in a specific database
pub async fn list_tables(params: &ConnParams, database: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut p = params.clone();
    p.database = Some(database.to_string());

    let pool = Pool::new(p.to_opts());
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    // Get table names and types
    let rows: Vec<Row> = conn
        .query(format!(
            "SELECT TABLE_NAME, TABLE_TYPE, TABLE_ROWS, DATA_LENGTH \
             FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}'",
            database.replace('\'', "''")
        ))
        .await
        .map_err(|e| format!("Query failed: {}", e))?;

    let mut tables = Vec::new();
    for row in rows {
        let name: String = row.get(0).unwrap_or_default();
        let table_type: String = row.get(1).unwrap_or_default();
        let row_count: Option<u64> = row.get(2);
        let data_length: Option<u64> = row.get(3);

        tables.push(serde_json::json!({
            "name": name,
            "type": table_type,
            "rows": row_count,
            "data_length": data_length,
        }));
    }

    pool.disconnect().await.ok();
    Ok(tables)
}

/// Get table structure (columns, types, keys)
pub async fn table_structure(
    params: &ConnParams,
    database: &str,
    table: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let mut p = params.clone();
    p.database = Some(database.to_string());

    let pool = Pool::new(p.to_opts());
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    let rows: Vec<Row> = conn
        .query(format!(
            "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA \
             FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{}' \
             ORDER BY ORDINAL_POSITION",
            database.replace('\'', "''"),
            table.replace('\'', "''")
        ))
        .await
        .map_err(|e| format!("Query failed: {}", e))?;

    let mut columns = Vec::new();
    for row in rows {
        let name: String = row.get(0).unwrap_or_default();
        let col_type: String = row.get(1).unwrap_or_default();
        let nullable: String = row.get(2).unwrap_or_default();
        let key: String = row.get(3).unwrap_or_default();
        let default: Option<String> = row.get(4);
        let extra: String = row.get(5).unwrap_or_default();

        columns.push(serde_json::json!({
            "name": name,
            "type": col_type,
            "nullable": nullable == "YES",
            "key": key,
            "default": default,
            "extra": extra,
        }));
    }

    pool.disconnect().await.ok();
    Ok(columns)
}

/// Get paginated table data
pub async fn table_data(
    params: &ConnParams,
    database: &str,
    table: &str,
    page: u64,
    page_size: u64,
) -> Result<serde_json::Value, String> {
    let mut p = params.clone();
    p.database = Some(database.to_string());

    let pool = Pool::new(p.to_opts());
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    // Sanitize table name (backtick-quote it)
    let safe_table = format!("`{}`.`{}`",
        database.replace('`', "``"),
        table.replace('`', "``")
    );

    // Get total row count
    let count_row: Option<u64> = conn
        .query_first(format!("SELECT COUNT(*) FROM {}", safe_table))
        .await
        .map_err(|e| format!("Count query failed: {}", e))?;
    let total_rows = count_row.unwrap_or(0);

    // Get column names
    let col_rows: Vec<Row> = conn
        .query(format!(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{}' \
             ORDER BY ORDINAL_POSITION",
            database.replace('\'', "''"),
            table.replace('\'', "''")
        ))
        .await
        .map_err(|e| format!("Column query failed: {}", e))?;

    let columns: Vec<String> = col_rows.iter().map(|r| r.get::<String, _>(0).unwrap_or_default()).collect();

    // Get data page
    let offset = page * page_size;
    let data_rows: Vec<Row> = conn
        .query(format!(
            "SELECT * FROM {} LIMIT {} OFFSET {}",
            safe_table, page_size, offset
        ))
        .await
        .map_err(|e| format!("Data query failed: {}", e))?;

    let rows = rows_to_json(&data_rows, &columns);

    pool.disconnect().await.ok();

    Ok(serde_json::json!({
        "columns": columns,
        "rows": rows,
        "total_rows": total_rows,
        "page": page,
        "page_size": page_size,
        "total_pages": (total_rows + page_size - 1) / page_size,
    }))
}

/// Execute an arbitrary SQL query
pub async fn execute_query(
    params: &ConnParams,
    database: &str,
    query: &str,
) -> Result<serde_json::Value, String> {
    let mut p = params.clone();
    if !database.is_empty() {
        p.database = Some(database.to_string());
    }

    let pool = Pool::new(p.to_opts());
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    // Determine if it's a SELECT-like query (returns rows) or a modification
    let trimmed = query.trim_start().to_uppercase();
    let is_select = trimmed.starts_with("SELECT")
        || trimmed.starts_with("SHOW")
        || trimmed.starts_with("DESCRIBE")
        || trimmed.starts_with("DESC ")
        || trimmed.starts_with("EXPLAIN");

    if is_select {
        let rows: Vec<Row> = conn
            .query(query)
            .await
            .map_err(|e| format!("Query error: {}", e))?;

        // Extract column names from the first row
        let columns: Vec<String> = if let Some(first) = rows.first() {
            first.columns_ref().iter().map(|c| c.name_str().to_string()).collect()
        } else {
            Vec::new()
        };

        let json_rows = rows_to_json(&rows, &columns);

        pool.disconnect().await.ok();

        Ok(serde_json::json!({
            "type": "resultset",
            "columns": columns,
            "rows": json_rows,
            "row_count": json_rows.len(),
        }))
    } else {
        let result = conn
            .query_iter(query)
            .await
            .map_err(|e| format!("Query error: {}", e))?;

        let affected = result.affected_rows();
        let last_insert_id = result.last_insert_id();

        // Drop the result to release the connection
        drop(result);
        pool.disconnect().await.ok();

        Ok(serde_json::json!({
            "type": "modification",
            "affected_rows": affected,
            "last_insert_id": last_insert_id,
            "message": format!("{} row(s) affected", affected),
        }))
    }
}

/// Convert mysql_async Rows to JSON arrays
fn rows_to_json(rows: &[Row], columns: &[String]) -> Vec<Vec<serde_json::Value>> {
    rows.iter()
        .map(|row| {
            (0..columns.len())
                .map(|i| {
                    match row.as_ref(i) {
                        Some(Value::NULL) | None => serde_json::Value::Null,
                        Some(Value::Int(v)) => serde_json::json!(*v),
                        Some(Value::UInt(v)) => serde_json::json!(*v),
                        Some(Value::Float(v)) => serde_json::json!(*v),
                        Some(Value::Double(v)) => serde_json::json!(*v),
                        Some(Value::Bytes(b)) => {
                            // Try UTF-8 string first, fall back to hex for binary data
                            match String::from_utf8(b.clone()) {
                                Ok(s) => serde_json::Value::String(s),
                                Err(_) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
                            }
                        }
                        Some(Value::Date(y, m, d, h, mi, s, _us)) => {
                            serde_json::Value::String(format!(
                                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                                y, m, d, h, mi, s
                            ))
                        }
                        Some(Value::Time(neg, d, h, m, s, _us)) => {
                            let sign = if *neg { "-" } else { "" };
                            if *d > 0 {
                                serde_json::Value::String(format!(
                                    "{}{} {:02}:{:02}:{:02}",
                                    sign, d, h, m, s
                                ))
                            } else {
                                serde_json::Value::String(format!(
                                    "{}{:02}:{:02}:{:02}",
                                    sign, h, m, s
                                ))
                            }
                        }
                    }
                })
                .collect()
        })
        .collect()
}
