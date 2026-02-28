// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Nginx site management for WolfProxy configurator

use serde::Deserialize;
use crate::installer::DistroFamily;
use super::{SiteEntry, ConfigTestResult, validate_name, ExecTarget};

/// Distro-specific nginx paths
struct NginxPaths {
    sites_available: &'static str,
    sites_enabled: Option<&'static str>,
    is_debian: bool,
}

fn nginx_paths(target: &ExecTarget) -> NginxPaths {
    // Check if Debian-style sites-available exists
    let has_sites_available = target.path_exists("/etc/nginx/sites-available").unwrap_or(false);
    if has_sites_available {
        return NginxPaths {
            sites_available: "/etc/nginx/sites-available",
            sites_enabled: Some("/etc/nginx/sites-enabled"),
            is_debian: true,
        };
    }

    // Check distro as secondary signal
    match target.detect_distro() {
        DistroFamily::Debian => NginxPaths {
            sites_available: "/etc/nginx/sites-available",
            sites_enabled: Some("/etc/nginx/sites-enabled"),
            is_debian: true,
        },
        _ => NginxPaths {
            sites_available: "/etc/nginx/conf.d",
            sites_enabled: None,
            is_debian: false,
        },
    }
}

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

/// List all sites with enabled status
pub fn list_sites(target: &ExecTarget) -> Result<Vec<SiteEntry>, String> {
    let paths = nginx_paths(target);

    if !target.path_exists(paths.sites_available).unwrap_or(false) {
        return Ok(Vec::new());
    }

    let names = target.list_dir(paths.sites_available)?;

    let mut sites = Vec::new();
    for name in names {
        if name.starts_with('.') {
            continue;
        }

        let enabled = if paths.is_debian {
            // Debian: check for symlink in sites-enabled
            if let Some(enabled_dir) = paths.sites_enabled {
                let enabled_path = format!("{}/{}", enabled_dir, name);
                target.path_exists(&enabled_path).unwrap_or(false)
                    || target.is_symlink(&enabled_path).unwrap_or(false)
            } else {
                false
            }
        } else {
            // RHEL/conf.d: all .conf files are enabled, .conf.disabled are not
            if name.ends_with(".disabled") {
                sites.push(SiteEntry {
                    name: name.trim_end_matches(".disabled").to_string(),
                    enabled: false,
                    config_content: None,
                });
                continue;
            }
            name.ends_with(".conf")
        };

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
    let paths = nginx_paths(target);

    let path = format!("{}/{}", paths.sites_available, name);
    if target.path_exists(&path).unwrap_or(false) {
        return target.read_file(&path);
    }

    // Try .disabled suffix (conf.d style)
    let disabled_path = format!("{}/{}.disabled", paths.sites_available, name);
    if target.path_exists(&disabled_path).unwrap_or(false) {
        return target.read_file(&disabled_path);
    }

    Err(format!("Site {} not found", name))
}

/// Create or update a site config file
pub fn save_site(target: &ExecTarget, name: &str, content: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = nginx_paths(target);
    let path = format!("{}/{}", paths.sites_available, name);
    target.write_file(&path, content)?;
    Ok(format!("Site {} saved", name))
}

/// Delete a site config (removes from both available and enabled)
pub fn delete_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = nginx_paths(target);

    // Remove from enabled first (Debian)
    if let Some(enabled_dir) = paths.sites_enabled {
        let enabled_path = format!("{}/{}", enabled_dir, name);
        if target.path_exists(&enabled_path).unwrap_or(false)
            || target.is_symlink(&enabled_path).unwrap_or(false)
        {
            let _ = target.remove_file(&enabled_path);
        }
    }

    // Remove from available/conf.d
    let avail_path = format!("{}/{}", paths.sites_available, name);
    let disabled_path = format!("{}.disabled", avail_path);
    let _ = target.remove_file(&avail_path);
    let _ = target.remove_file(&disabled_path);
    Ok(format!("Site {} deleted", name))
}

/// Enable a site
pub fn enable_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = nginx_paths(target);

    if paths.is_debian {
        let avail = format!("{}/{}", paths.sites_available, name);
        let enabled_dir = paths.sites_enabled.unwrap_or("/etc/nginx/sites-enabled");
        let enabled = format!("{}/{}", enabled_dir, name);

        if !target.path_exists(&avail).unwrap_or(false) {
            return Err(format!("Site {} not found in sites-available", name));
        }
        target.symlink(&avail, &enabled)?;
        Ok(format!("Site {} enabled", name))
    } else {
        // conf.d: rename .conf.disabled -> .conf
        let disabled = format!("{}/{}.disabled", paths.sites_available, name);
        let enabled = format!("{}/{}", paths.sites_available, name);
        if target.path_exists(&disabled).unwrap_or(false) {
            target.exec(&format!("mv '{}' '{}'",
                disabled.replace('\'', "'\\''"),
                enabled.replace('\'', "'\\''")))?;
            Ok(format!("Site {} enabled", name))
        } else {
            Ok(format!("Site {} is already enabled", name))
        }
    }
}

/// Disable a site
pub fn disable_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = nginx_paths(target);

    if paths.is_debian {
        let enabled_dir = paths.sites_enabled.unwrap_or("/etc/nginx/sites-enabled");
        let enabled = format!("{}/{}", enabled_dir, name);
        target.remove_file(&enabled)?;
        Ok(format!("Site {} disabled", name))
    } else {
        // conf.d: rename .conf -> .conf.disabled
        let enabled = format!("{}/{}", paths.sites_available, name);
        let disabled = format!("{}.disabled", enabled);
        if target.path_exists(&enabled).unwrap_or(false) {
            target.exec(&format!("mv '{}' '{}'",
                enabled.replace('\'', "'\\''"),
                disabled.replace('\'', "'\\''")))?;
            Ok(format!("Site {} disabled", name))
        } else {
            Ok(format!("Site {} is already disabled", name))
        }
    }
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
