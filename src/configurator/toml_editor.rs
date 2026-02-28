// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Structured TOML editor for WolfDisk and WolfScale configuration

use std::process::Command;
use crate::installer::Component;

/// Parse a TOML config file into a JSON value for form rendering
pub fn parse_config(component: &str) -> Result<serde_json::Value, String> {
    let comp = match component.to_lowercase().as_str() {
        "wolfdisk" => Component::WolfDisk,
        "wolfscale" => Component::WolfScale,
        _ => return Err(format!("Unsupported component: {}", component)),
    };

    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;

    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path, e))?;

    let toml_value: toml::Value = content.parse()
        .map_err(|e| format!("Failed to parse TOML: {}", e))?;

    // Convert TOML value to JSON value
    let json = toml_to_json(&toml_value);
    Ok(json)
}

/// Save a structured JSON config back as TOML
pub fn save_config(component: &str, data: &serde_json::Value) -> Result<String, String> {
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

    // Write via sudo tee
    let mut child = Command::new("sudo")
        .args(["tee", config_path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to write config: {}", e))?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin.write_all(toml_string.as_bytes())
            .map_err(|e| format!("Failed to write config content: {}", e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("Failed to wait for write: {}", e))?;

    if output.status.success() {
        Ok(format!("Configuration saved to {}. Restart {} to apply changes.",
            config_path, comp.service_name()))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
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
