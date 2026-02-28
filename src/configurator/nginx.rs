// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Nginx site management for WolfProxy configurator

use serde::Deserialize;
use super::{SiteEntry, ConfigTestResult, validate_name, ExecTarget};

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
pub fn list_sites(target: &ExecTarget) -> Result<Vec<SiteEntry>, String> {
    if !target.path_exists(SITES_AVAILABLE).unwrap_or(false) {
        return Ok(Vec::new());
    }

    let names = target.list_dir(SITES_AVAILABLE)?;

    let mut sites = Vec::new();
    for name in names {
        if name.starts_with('.') {
            continue;
        }
        let enabled_path = format!("{}/{}", SITES_ENABLED, name);
        let enabled = target.path_exists(&enabled_path).unwrap_or(false)
            || target.is_symlink(&enabled_path).unwrap_or(false);
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
pub fn read_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let path = format!("{}/{}", SITES_AVAILABLE, name);
    target.read_file(&path)
}

/// Create or update a site config file
pub fn save_site(target: &ExecTarget, name: &str, content: &str) -> Result<String, String> {
    validate_name(name)?;
    let path = format!("{}/{}", SITES_AVAILABLE, name);
    target.write_file(&path, content)?;
    Ok(format!("Site {} saved", name))
}

/// Delete a site config (removes from both available and enabled)
pub fn delete_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;

    // Remove from enabled first
    let enabled_path = format!("{}/{}", SITES_ENABLED, name);
    if target.path_exists(&enabled_path).unwrap_or(false)
        || target.is_symlink(&enabled_path).unwrap_or(false)
    {
        let _ = target.remove_file(&enabled_path);
    }

    // Remove from available
    let avail_path = format!("{}/{}", SITES_AVAILABLE, name);
    target.remove_file(&avail_path)?;
    Ok(format!("Site {} deleted", name))
}

/// Enable a site (create symlink in sites-enabled)
pub fn enable_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let avail = format!("{}/{}", SITES_AVAILABLE, name);
    let enabled = format!("{}/{}", SITES_ENABLED, name);

    if !target.path_exists(&avail).unwrap_or(false) {
        return Err(format!("Site {} not found in sites-available", name));
    }

    target.symlink(&avail, &enabled)?;
    Ok(format!("Site {} enabled", name))
}

/// Disable a site (remove symlink from sites-enabled)
pub fn disable_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let enabled = format!("{}/{}", SITES_ENABLED, name);
    target.remove_file(&enabled)?;
    Ok(format!("Site {} disabled", name))
}

/// Run nginx -t to test configuration
pub fn test_config(target: &ExecTarget) -> ConfigTestResult {
    match target.exec_full("nginx -t 2>&1") {
        Ok((output, stderr, success)) => {
            let combined = if stderr.is_empty() { output } else { format!("{}\n{}", output, stderr) };
            ConfigTestResult {
                success,
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
pub fn reload(target: &ExecTarget) -> Result<String, String> {
    let test = test_config(target);
    if !test.success {
        return Err(format!("Config test failed, not reloading:\n{}", test.output));
    }

    target.exec("systemctl reload nginx || nginx -s reload")?;
    Ok("Nginx reloaded successfully".to_string())
}

/// Read recent nginx error log lines
pub fn error_log(target: &ExecTarget, lines: usize) -> Vec<String> {
    let n = lines.min(500);
    match target.exec(&format!("tail -n {} /var/log/nginx/error.log 2>/dev/null", n)) {
        Ok(output) => output.lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
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
