// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Structured TOML editor for WolfDisk and WolfScale configuration

use crate::installer::Component;
use super::ExecTarget;

/// Parse a TOML config file into a JSON value for form rendering
pub fn parse_config(target: &ExecTarget, component: &str) -> Result<serde_json::Value, String> {
    let comp = match component.to_lowercase().as_str() {
        "wolfdisk" => Component::WolfDisk,
        "wolfscale" => Component::WolfScale,
        _ => return Err(format!("Unsupported component: {}", component)),
    };

    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;

    let content = target.read_file(config_path)?;

    let toml_value: toml::Value = content.parse()
        .map_err(|e| format!("Failed to parse TOML: {}", e))?;

    // Convert TOML value to JSON value
    let json = toml_to_json(&toml_value);
    Ok(json)
}

/// Save a structured JSON config back as TOML
pub fn save_config(target: &ExecTarget, component: &str, data: &serde_json::Value) -> Result<String, String> {
    let comp = match component.to_lowercase().as_str() {
        "wolfdisk" => Component::WolfDisk,
        "wolfscale" => Component::WolfScale,
        _ => return Err(format!("Unsupported component: {}", component)),
    };

    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;

    // Convert JSON to TOML
    let toml_value = json_to_toml(data)
        .ok_or_else(|| "Failed to convert config to TOML format".to_string())?;

    let toml_string = toml::to_string_pretty(&toml_value)
        .map_err(|e| format!("Failed to serialize TOML: {}", e))?;

    target.write_file(config_path, &toml_string)?;

    Ok(format!("Configuration saved to {}. Restart {} to apply changes.",
        config_path, comp.service_name()))
}

/// Bootstrap a default TOML config for a component — never overwrites existing files
pub fn bootstrap_config(target: &ExecTarget, component: &str) -> Result<String, String> {
    let comp = match component.to_lowercase().as_str() {
        "wolfdisk" => Component::WolfDisk,
        "wolfscale" => Component::WolfScale,
        _ => return Err(format!("Unsupported component: {}", component)),
    };

    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;

    // Never overwrite existing config
    if target.path_exists(config_path).unwrap_or(false) {
        return Ok(format!("Configuration already exists at {}. Not overwriting.", config_path));
    }

    // Create parent directory
    if let Some(parent) = std::path::Path::new(config_path).parent() {
        let _ = target.exec(&format!("mkdir -p '{}'", parent.display()));
    }

    let default_config = match comp {
        Component::WolfDisk => r#"# WolfDisk Configuration
# Auto-generated default — edit as needed

[node]
id = "node-1"
role = "auto"
bind = "0.0.0.0:9500"
data_dir = "/var/lib/wolfdisk"

[cluster]
peers = []
discovery = "udp://0.0.0.0:9501"

[replication]
mode = "shared"
factor = 3
chunk_size = 4194304

[mount]
path = "/mnt/wolfdisk"
allow_other = true
"#,
        Component::WolfScale => r#"# WolfScale Configuration
# Auto-generated default — edit as needed

[node]
id = "node-1"
bind_address = "0.0.0.0:7654"
data_dir = "/var/lib/wolfscale"

[database]
host = "localhost"
port = 3306
user = "wolfscale"
password = ""
pool_size = 10
connect_timeout_secs = 30

[wal]
batch_size = 1000
flush_interval_ms = 100
compression = true
segment_size_mb = 64
retention_hours = 168
fsync = true

[cluster]
peers = []
heartbeat_interval_ms = 500
election_timeout_ms = 2000
max_batch_entries = 1000

[api]
enabled = true
bind_address = "0.0.0.0:8080"
cors_enabled = false

[logging]
level = "info"
format = "pretty"
"#,
        _ => return Err(format!("No default config template for {}", component)),
    };

    target.write_file(config_path, default_config)?;
    Ok(format!("Default configuration created at {}. Edit the values and save.", config_path))
}

/// Validate a TOML string (parse it and check for errors)
pub fn validate_toml(content: &str) -> Result<(), String> {
    let _: toml::Value = content.parse()
        .map_err(|e| format!("Invalid TOML: {}", e))?;
    Ok(())
}

/// Convert a TOML value to a JSON value
fn toml_to_json(value: &toml::Value) -> serde_json::Value {
    match value {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::json!(*i),
        toml::Value::Float(f) => serde_json::json!(*f),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => {
            let mut map = serde_json::Map::new();
            for (k, v) in table {
                map.insert(k.clone(), toml_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

/// Convert a JSON value to a TOML value
fn json_to_toml(value: &serde_json::Value) -> Option<toml::Value> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(b) => Some(toml::Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(toml::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Some(toml::Value::Float(f))
            } else {
                None
            }
        }
        serde_json::Value::String(s) => Some(toml::Value::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items: Vec<toml::Value> = arr.iter()
                .filter_map(json_to_toml)
                .collect();
            Some(toml::Value::Array(items))
        }
        serde_json::Value::Object(obj) => {
            let mut table = toml::map::Map::new();
            for (k, v) in obj {
                if let Some(tv) = json_to_toml(v) {
                    table.insert(k.clone(), tv);
                }
            }
            Some(toml::Value::Table(table))
        }
    }
}
