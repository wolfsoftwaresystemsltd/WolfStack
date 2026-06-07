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
        // Sites dir doesn't exist yet — create it and return empty
        let _ = target.exec(&format!("mkdir -p '{}'", paths.sites_available));
        if let Some(enabled) = paths.sites_enabled {
            let _ = target.exec(&format!("mkdir -p '{}'", enabled));
        }
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

/// Run config test — tries whichever of nginx/wolfproxy is actually
/// installed on the target. The earlier version returned the
/// `nginx: not found` message verbatim because `exec_full` returns
/// Ok even when the shell reports a missing binary (exit 127). We
/// now `which` first so a host with only wolfproxy installed reaches
/// the wolfproxy test path.
pub fn test_config(target: &ExecTarget) -> ConfigTestResult {
    let nginx_present = target.exec("which nginx 2>/dev/null")
        .map(|s| !s.trim().is_empty()).unwrap_or(false);
    let wolfproxy_present = target.exec("which wolfproxy 2>/dev/null")
        .map(|s| !s.trim().is_empty()).unwrap_or(false);

    // Try nginx -t when nginx is actually installed.
    if nginx_present {
        if let Ok((output, stderr, success)) = target.exec_full("nginx -t 2>&1") {
            let combined = if stderr.is_empty() { output }
                           else { format!("{}\n{}", output, stderr) };
            // If success, we're done. If failure AND the error is the
            // classic "command not found" race (binary disappeared
            // between `which` and exec — e.g. mid-uninstall), fall
            // through to wolfproxy. Otherwise return the real nginx
            // failure to the user.
            if success || !looks_like_command_not_found(&combined) {
                return ConfigTestResult { success, output: combined.trim().to_string() };
            }
        }
    }

    if wolfproxy_present {
        // `--config` points the test at the deployed config (the test runs in
        // an arbitrary cwd, and wolfproxy reads ./wolfproxy.toml by default).
        // `timeout` is a hard safety net for pre-v0.4.7 wolfproxy binaries that
        // ignored argv and started a *full server* on `--test` — when the
        // service was down that bound :80 and orphaned a listener (klasSponsor
        // 2026-06). On a fixed binary `--test` validates and exits in <1s; on an
        // old one timeout TERMs the stray instead of letting it hang/orphan.
        if let Ok((output, stderr, success)) = target.exec_full(
            "timeout 10 wolfproxy --test --config /opt/wolfproxy/wolfproxy.toml 2>&1"
        ) {
            let combined = if stderr.is_empty() { output }
                           else { format!("{}\n{}", output, stderr) };
            return ConfigTestResult { success, output: combined.trim().to_string() };
        }
    }

    // Neither installed — surface a clear message rather than the
    // shell's raw `command not found` so the operator knows what to do.
    let hint = match (nginx_present, wolfproxy_present) {
        (false, false) => "Neither nginx nor wolfproxy is installed on this node. Install one before running a config test.",
        (true,  _)     => "nginx is installed but `nginx -t` could not be executed. Check service permissions.",
        (false, true)  => "wolfproxy is installed but `wolfproxy --test` could not be executed. Check binary permissions.",
    };
    ConfigTestResult {
        success: false,
        output: hint.to_string(),
    }
}

/// Heuristic: did the shell output indicate the requested binary
/// wasn't found? Different shells phrase this slightly differently —
/// dash says "sh: 1: nginx: not found", bash says "nginx: command
/// not found", busybox says "nginx: not found". All include "not
/// found".
fn looks_like_command_not_found(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("not found") || lower.contains("no such file or directory")
}

/// Reload nginx/wolfproxy — runs test first, only reloads if test passes
pub fn reload(target: &ExecTarget) -> Result<String, String> {
    let test = test_config(target);
    if !test.success {
        return Err(format!("Config test failed, not reloading:\n{}", test.output));
    }

    // Try nginx first, then wolfproxy
    let reload_result = target.exec("systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || systemctl reload wolfproxy 2>/dev/null || systemctl restart wolfproxy");
    match reload_result {
        Ok(_) => Ok("Configuration reloaded successfully".to_string()),
        Err(e) => Err(format!("Failed to reload: {}", e)),
    }
}

/// Read recent nginx error log lines
pub fn error_log(target: &ExecTarget, lines: usize) -> Vec<String> {
    let n = lines.min(500);
    match target.exec(&format!("tail -n {} /var/log/nginx/error.log 2>/dev/null", n)) {
        Ok(output) => output.lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Bootstrap nginx — create directories and a default site config if not present
pub fn bootstrap_nginx(target: &ExecTarget) -> Result<String, String> {
    // Ensure directories exist
    let paths = nginx_paths(target);
    let _ = target.exec(&format!("mkdir -p '{}'", paths.sites_available));
    if let Some(enabled) = paths.sites_enabled {
        let _ = target.exec(&format!("mkdir -p '{}'", enabled));
    }

    // Create a default site config only if no configs exist yet
    let existing = target.list_dir(paths.sites_available).unwrap_or_default();
    let has_configs = existing.iter().any(|f| !f.starts_with('.'));
    if !has_configs {
        let default_config = "server {\n    listen 80 default_server;\n    listen [::]:80 default_server;\n    server_name _;\n\n    root /var/www/html;\n    index index.html index.htm;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n";
        let config_name = if paths.is_debian { "default" } else { "default.conf" };
        let config_path = format!("{}/{}", paths.sites_available, config_name);
        target.write_file(&config_path, default_config)?;

        // Enable on Debian
        if paths.is_debian {
            if let Some(enabled_dir) = paths.sites_enabled {
                let enabled_path = format!("{}/{}", enabled_dir, config_name);
                let _ = target.symlink(&config_path, &enabled_path);
            }
        }

        Ok("Default site configuration created".to_string())
    } else {
        Ok("Configuration already exists — not overwriting".to_string())
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
