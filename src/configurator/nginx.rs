// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Nginx site management for WolfProxy configurator

use std::path::Path;
use std::process::Command;
use serde::Deserialize;
use super::{SiteEntry, ConfigTestResult, validate_name};

const SITES_AVAILABLE: &str = "/etc/nginx/sites-available";
const SITES_ENABLED: &str = "/etc/nginx/sites-enabled";

/// Parameters for generating an nginx site config
#[derive(Debug, Deserialize)]
pub struct NginxSiteParams {
    pub server_name: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub ssl: bool,
    pub ssl_cert: Option<String>,
    pub ssl_key: Option<String>,
    pub proxy_pass: Option<String>,
    pub root: Option<String>,
}

fn default_listen_port() -> u16 { 80 }

/// List all sites in sites-available with enabled status
pub fn list_sites() -> Result<Vec<SiteEntry>, String> {
    let avail = Path::new(SITES_AVAILABLE);
    if !avail.exists() {
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(avail)
        .map_err(|e| format!("Failed to read {}: {}", SITES_AVAILABLE, e))?;

    let mut sites = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let enabled_path = Path::new(SITES_ENABLED).join(&name);
        let enabled = enabled_path.exists() || enabled_path.is_symlink();
        sites.push(SiteEntry {
            name,
            enabled,
            config_content: None,
        });
    }
    sites.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(sites)
}

/// Read a single site config
pub fn read_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let path = Path::new(SITES_AVAILABLE).join(name);
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))
}

/// Create or update a site config file
pub fn save_site(name: &str, content: &str) -> Result<String, String> {
    validate_name(name)?;
    let path = format!("{}/{}", SITES_AVAILABLE, name);

    // Write via sudo tee
    let mut child = Command::new("sudo")
        .args(["tee", &path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to write config: {}", e))?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write config content: {}", e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("Failed to wait for write: {}", e))?;

    if output.status.success() {
        Ok(format!("Site {} saved", name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Delete a site config (removes from both available and enabled)
pub fn delete_site(name: &str) -> Result<String, String> {
    validate_name(name)?;

    // Remove from enabled first
    let enabled_path = format!("{}/{}", SITES_ENABLED, name);
    if Path::new(&enabled_path).exists() || Path::new(&enabled_path).is_symlink() {
        let _ = Command::new("sudo").args(["rm", "-f", &enabled_path]).output();
    }

    // Remove from available
    let avail_path = format!("{}/{}", SITES_AVAILABLE, name);
    let output = Command::new("sudo")
        .args(["rm", "-f", &avail_path])
        .output()
        .map_err(|e| format!("Failed to delete: {}", e))?;

    if output.status.success() {
        Ok(format!("Site {} deleted", name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Enable a site (create symlink in sites-enabled)
pub fn enable_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let avail = format!("{}/{}", SITES_AVAILABLE, name);
    let enabled = format!("{}/{}", SITES_ENABLED, name);

    if !Path::new(&avail).exists() {
        return Err(format!("Site {} not found in sites-available", name));
    }

    let output = Command::new("sudo")
        .args(["ln", "-sf", &avail, &enabled])
        .output()
        .map_err(|e| format!("Failed to enable site: {}", e))?;

    if output.status.success() {
        Ok(format!("Site {} enabled", name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Disable a site (remove symlink from sites-enabled)
pub fn disable_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let enabled = format!("{}/{}", SITES_ENABLED, name);

    let output = Command::new("sudo")
        .args(["rm", "-f", &enabled])
        .output()
        .map_err(|e| format!("Failed to disable site: {}", e))?;

    if output.status.success() {
        Ok(format!("Site {} disabled", name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Run nginx -t to test configuration
pub fn test_config() -> ConfigTestResult {
    let output = Command::new("sudo")
        .args(["nginx", "-t"])
        .output();

    match output {
        Ok(o) => {
            // nginx -t outputs to stderr
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let combined = if stdout.is_empty() { stderr } else { format!("{}\n{}", stdout, stderr) };
            ConfigTestResult {
                success: o.status.success(),
                output: combined.trim().to_string(),
            }
        }
        Err(e) => ConfigTestResult {
            success: false,
            output: format!("Failed to run nginx -t: {}", e),
        },
    }
}

/// Reload nginx — runs test first, only reloads if test passes
pub fn reload() -> Result<String, String> {
    let test = test_config();
    if !test.success {
        return Err(format!("Config test failed, not reloading:\n{}", test.output));
    }

    let output = Command::new("sudo")
        .args(["systemctl", "reload", "nginx"])
        .output()
        .map_err(|e| format!("Failed to reload nginx: {}", e))?;

    if output.status.success() {
        Ok("Nginx reloaded successfully".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Read recent nginx error log lines
pub fn error_log(lines: usize) -> Vec<String> {
    let n = lines.min(500).to_string();
    let output = Command::new("sudo")
        .args(["tail", "-n", &n, "/var/log/nginx/error.log"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Generate a basic nginx site config from form parameters
pub fn generate_site_config(params: &NginxSiteParams) -> String {
    let mut config = String::new();

    config.push_str("server {\n");

    if params.ssl && params.listen_port == 80 {
        config.push_str("    listen 443 ssl;\n");
        config.push_str("    listen [::]:443 ssl;\n");
    } else if params.ssl {
        config.push_str(&format!("    listen {} ssl;\n", params.listen_port));
        config.push_str(&format!("    listen [::]{} ssl;\n",
            if params.listen_port == 443 { String::new() } else { format!(":{}", params.listen_port) }));
    } else {
        config.push_str(&format!("    listen {};\n", params.listen_port));
        config.push_str(&format!("    listen [::]{};\n",
            if params.listen_port == 80 { String::new() } else { format!(":{}", params.listen_port) }));
    }

    config.push_str(&format!("    server_name {};\n", params.server_name));
    config.push('\n');

    if params.ssl {
        if let Some(ref cert) = params.ssl_cert {
            config.push_str(&format!("    ssl_certificate {};\n", cert));
        }
        if let Some(ref key) = params.ssl_key {
            config.push_str(&format!("    ssl_certificate_key {};\n", key));
        }
        config.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n");
        config.push_str("    ssl_ciphers HIGH:!aNULL:!MD5;\n");
        config.push('\n');
    }

    if let Some(ref proxy) = params.proxy_pass {
        config.push_str("    location / {\n");
        config.push_str(&format!("        proxy_pass {};\n", proxy));
        config.push_str("        proxy_set_header Host $host;\n");
        config.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
        config.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
        config.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
        config.push_str("        proxy_http_version 1.1;\n");
        config.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
        config.push_str("        proxy_set_header Connection \"upgrade\";\n");
        config.push_str("    }\n");
    } else if let Some(ref root) = params.root {
        config.push_str(&format!("    root {};\n", root));
        config.push_str("    index index.html index.htm;\n");
        config.push('\n');
        config.push_str("    location / {\n");
        config.push_str("        try_files $uri $uri/ =404;\n");
        config.push_str("    }\n");
    }

    config.push_str("}\n");

    // Add HTTP->HTTPS redirect if SSL is enabled
    if params.ssl {
        config.push('\n');
        config.push_str("server {\n");
        config.push_str("    listen 80;\n");
        config.push_str("    listen [::]:80;\n");
        config.push_str(&format!("    server_name {};\n", params.server_name));
        config.push_str("    return 301 https://$host$request_uri;\n");
        config.push_str("}\n");
    }

    config
}
