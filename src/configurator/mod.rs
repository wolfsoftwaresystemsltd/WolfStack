// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Configurator — structured configuration management for Wolf suite components
//!
//! Provides form-based configuration UIs for:
//! - WolfProxy (nginx site management)
//! - WolfServe (Apache2 vhost and module management)
//! - WolfDisk / WolfScale (TOML config editing)

pub mod exec_target;
pub mod nginx;
pub mod apache;
pub mod toml_editor;

pub use exec_target::ExecTarget;

use serde::{Deserialize, Serialize};

/// A site/vhost configuration entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteEntry {
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_content: Option<String>,
}

/// Result of a configuration test (nginx -t / apachectl configtest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTestResult {
    pub success: bool,
    pub output: String,
}

/// Validate a site/config file name to prevent path traversal
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".to_string());
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("Name contains invalid characters".to_string());
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err("Name may only contain letters, numbers, dots, hyphens, and underscores".to_string());
    }
    Ok(())
}
