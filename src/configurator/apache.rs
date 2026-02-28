// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Apache2 vhost and module management for WolfServe configurator

use serde::{Deserialize, Serialize};
use crate::installer::DistroFamily;
use super::{SiteEntry, ConfigTestResult, validate_name, ExecTarget};

/// Distro-specific Apache paths and commands
#[allow(dead_code)]
struct ApachePaths {
    sites_available: &'static str,
    sites_enabled: &'static str,
    mods_available: Option<&'static str>,
    mods_enabled: Option<&'static str>,
    config_test_cmd: &'static str,
    service_name: &'static str,
    is_debian: bool,
}

fn apache_paths(target: &ExecTarget) -> ApachePaths {
    match target.detect_distro() {
        DistroFamily::Debian | DistroFamily::Unknown => ApachePaths {
            sites_available: "/etc/apache2/sites-available",
            sites_enabled: "/etc/apache2/sites-enabled",
            mods_available: Some("/etc/apache2/mods-available"),
            mods_enabled: Some("/etc/apache2/mods-enabled"),
            config_test_cmd: "apache2ctl",
            service_name: "apache2",
            is_debian: true,
        },
        DistroFamily::RedHat | DistroFamily::Suse => ApachePaths {
            sites_available: "/etc/httpd/conf.d",
            sites_enabled: "/etc/httpd/conf.d",
            mods_available: Some("/etc/httpd/conf.modules.d"),
            mods_enabled: None,
            config_test_cmd: "apachectl",
            service_name: "httpd",
            is_debian: false,
        },
    }
}

/// An Apache module entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub name: String,
    pub enabled: bool,
}

/// Parameters for generating an Apache vhost config
#[derive(Debug, Deserialize)]
pub struct ApacheVhostParams {
    pub server_name: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    pub document_root: Option<String>,
    pub server_admin: Option<String>,
    pub proxy_pass: Option<String>,
    #[serde(default)]
    pub ssl: bool,
    pub ssl_cert: Option<String>,
    pub ssl_key: Option<String>,
}

fn default_listen_port() -> u16 { 80 }

/// Check if Apache is installed on the target
pub fn is_apache_installed(target: &ExecTarget) -> bool {
    let (_, _, success) = target.exec_full("which apache2 2>/dev/null || which httpd 2>/dev/null || command -v apache2 2>/dev/null || command -v httpd 2>/dev/null")
        .unwrap_or((String::new(), String::new(), false));
    if success { return true; }
    target.path_exists("/etc/apache2").unwrap_or(false)
        || target.path_exists("/etc/httpd").unwrap_or(false)
}

/// List all sites/vhosts with enabled status
pub fn list_sites(target: &ExecTarget) -> Result<Vec<SiteEntry>, String> {
    if !is_apache_installed(target) {
        return Err("Apache is not installed. Install Apache (apache2/httpd) first, then use the configurator to manage virtual hosts.".to_string());
    }

    let paths = apache_paths(target);

    if !target.path_exists(paths.sites_available).unwrap_or(false) {
        return Ok(Vec::new());
    }

    let names = target.list_dir(paths.sites_available)?;

    let mut sites = Vec::new();
    for name in names {
        if name.starts_with('.') {
            continue;
        }
        // On RHEL, skip disabled files (*.conf.disabled)
        if name.ends_with(".disabled") {
            sites.push(SiteEntry {
                name: name.trim_end_matches(".disabled").to_string(),
                enabled: false,
                config_content: None,
            });
            continue;
        }
        // On Debian, check if symlink exists in sites-enabled
        let enabled = if paths.is_debian {
            let enabled_path = format!("{}/{}", paths.sites_enabled, name);
            target.path_exists(&enabled_path).unwrap_or(false)
                || target.is_symlink(&enabled_path).unwrap_or(false)
        } else {
            // On RHEL, all .conf files in conf.d are enabled
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
    let paths = apache_paths(target);

    // Try the name directly first, then with .disabled suffix
    let path = format!("{}/{}", paths.sites_available, name);
    if target.path_exists(&path).unwrap_or(false) {
        return target.read_file(&path);
    }

    let disabled_path = format!("{}/{}.disabled", paths.sites_available, name);
    if target.path_exists(&disabled_path).unwrap_or(false) {
        return target.read_file(&disabled_path);
    }

    Err(format!("Site {} not found", name))
}

/// Create or update a site config file
pub fn save_site(target: &ExecTarget, name: &str, content: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths(target);
    let path = format!("{}/{}", paths.sites_available, name);
    target.write_file(&path, content)?;
    Ok(format!("Site {} saved", name))
}

/// Delete a site config
pub fn delete_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths(target);

    // Disable first on Debian
    if paths.is_debian {
        let _ = target.exec(&format!("a2dissite '{}' 2>/dev/null", name.replace('\'', "'\\''")));
    }

    let avail_path = format!("{}/{}", paths.sites_available, name);
    let disabled_path = format!("{}.disabled", avail_path);
    let _ = target.remove_file(&avail_path);
    let _ = target.remove_file(&disabled_path);

    Ok(format!("Site {} deleted", name))
}

/// Enable a site
pub fn enable_site(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths(target);

    if paths.is_debian {
        target.exec(&format!("a2ensite '{}'", name.replace('\'', "'\\''")))?;
        Ok(format!("Site {} enabled", name))
    } else {
        // RHEL: rename .conf.disabled back to .conf
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
    let paths = apache_paths(target);

    if paths.is_debian {
        target.exec(&format!("a2dissite '{}'", name.replace('\'', "'\\''")))?;
        Ok(format!("Site {} disabled", name))
    } else {
        // RHEL: rename .conf to .conf.disabled
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

/// List Apache modules with enabled status
pub fn list_modules(target: &ExecTarget) -> Result<Vec<ModuleEntry>, String> {
    let paths = apache_paths(target);
    if paths.is_debian {
        list_modules_debian(target)
    } else {
        list_modules_rhel(target, &paths)
    }
}

fn list_modules_debian(target: &ExecTarget) -> Result<Vec<ModuleEntry>, String> {
    let mods_avail = "/etc/apache2/mods-available";
    let mods_enabled = "/etc/apache2/mods-enabled";

    if !target.path_exists(mods_avail).unwrap_or(false) {
        return Ok(Vec::new());
    }

    let entries = target.list_dir(mods_avail)?;

    let mut modules = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for fname in entries {
        // Module files are name.load and name.conf; we track by base name
        let base = if let Some(b) = fname.strip_suffix(".load") {
            b.to_string()
        } else if let Some(b) = fname.strip_suffix(".conf") {
            b.to_string()
        } else {
            continue;
        };

        if seen.contains(&base) {
            continue;
        }
        seen.insert(base.clone());

        let load_path = format!("{}/{}.load", mods_enabled, base);
        let conf_path = format!("{}/{}.conf", mods_enabled, base);
        let enabled = target.path_exists(&load_path).unwrap_or(false)
            || target.path_exists(&conf_path).unwrap_or(false);

        modules.push(ModuleEntry {
            name: base,
            enabled,
        });
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(modules)
}

fn list_modules_rhel(target: &ExecTarget, paths: &ApachePaths) -> Result<Vec<ModuleEntry>, String> {
    // On RHEL, list loaded modules via apachectl -M
    let output = target.exec(&format!("{} -M 2>&1", paths.config_test_cmd))?;

    let mut modules = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_suffix("_module (shared)") {
            modules.push(ModuleEntry {
                name: name.trim().to_string(),
                enabled: true,
            });
        } else if let Some(name) = trimmed.strip_suffix("_module (static)") {
            modules.push(ModuleEntry {
                name: name.trim().to_string(),
                enabled: true,
            });
        }
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(modules)
}

/// Enable an Apache module
pub fn enable_module(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths(target);
    if paths.is_debian {
        target.exec(&format!("a2enmod '{}'", name.replace('\'', "'\\''")))?;
        Ok(format!("Module {} enabled", name))
    } else {
        Err("Module management on RHEL requires manual editing of conf.modules.d files".to_string())
    }
}

/// Disable an Apache module
pub fn disable_module(target: &ExecTarget, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths(target);
    if paths.is_debian {
        target.exec(&format!("a2dismod '{}'", name.replace('\'', "'\\''")))?;
        Ok(format!("Module {} disabled", name))
    } else {
        Err("Module management on RHEL requires manual editing of conf.modules.d files".to_string())
    }
}

/// Run apachectl configtest
pub fn test_config(target: &ExecTarget) -> ConfigTestResult {
    let paths = apache_paths(target);
    match target.exec_full(&format!("{} configtest 2>&1", paths.config_test_cmd)) {
        Ok((output, stderr, success)) => {
            let combined = if stderr.is_empty() { output } else { format!("{}\n{}", output, stderr) };
            ConfigTestResult {
                success,
                output: combined.trim().to_string(),
            }
        }
        Err(e) => ConfigTestResult {
            success: false,
            output: format!("Failed to run {} configtest: {}", paths.config_test_cmd, e),
        },
    }
}

/// Reload Apache — runs test first, only reloads if test passes
pub fn reload(target: &ExecTarget) -> Result<String, String> {
    let test = test_config(target);
    if !test.success {
        return Err(format!("Config test failed, not reloading:\n{}", test.output));
    }

    let paths = apache_paths(target);
    target.exec(&format!("systemctl reload {} || {} -k graceful",
        paths.service_name, paths.config_test_cmd))?;
    Ok(format!("{} reloaded successfully", paths.service_name))
}

/// Read recent Apache error log lines
pub fn error_log(target: &ExecTarget, lines: usize) -> Vec<String> {
    let n = lines.min(500);
    // Try common log locations
    let log_paths = [
        "/var/log/apache2/error.log",
        "/var/log/httpd/error_log",
    ];

    for log_path in &log_paths {
        if target.path_exists(log_path).unwrap_or(false) {
            if let Ok(output) = target.exec(&format!("tail -n {} '{}' 2>/dev/null", n, log_path)) {
                return output.lines().map(|l| l.to_string()).collect();
            }
        }
    }
    Vec::new()
}

/// Generate a basic Apache vhost config from form parameters
pub fn generate_vhost_config(params: &ApacheVhostParams) -> String {
    let mut config = String::new();

    let port = if params.ssl && params.listen_port == 80 { 443 } else { params.listen_port };

    config.push_str(&format!("<VirtualHost *:{}>\n", port));
    config.push_str(&format!("    ServerName {}\n", params.server_name));

    if let Some(ref admin) = params.server_admin {
        config.push_str(&format!("    ServerAdmin {}\n", admin));
    }

    if let Some(ref root) = params.document_root {
        config.push_str(&format!("    DocumentRoot {}\n", root));
        config.push('\n');
        config.push_str(&format!("    <Directory {}>\n", root));
        config.push_str("        Options Indexes FollowSymLinks\n");
        config.push_str("        AllowOverride All\n");
        config.push_str("        Require all granted\n");
        config.push_str("    </Directory>\n");
    }

    if let Some(ref proxy) = params.proxy_pass {
        config.push('\n');
        config.push_str("    ProxyPreserveHost On\n");
        config.push_str(&format!("    ProxyPass / {}\n", proxy));
        config.push_str(&format!("    ProxyPassReverse / {}\n", proxy));
    }

    if params.ssl {
        config.push('\n');
        config.push_str("    SSLEngine on\n");
        if let Some(ref cert) = params.ssl_cert {
            config.push_str(&format!("    SSLCertificateFile {}\n", cert));
        }
        if let Some(ref key) = params.ssl_key {
            config.push_str(&format!("    SSLCertificateKeyFile {}\n", key));
        }
    }

    config.push('\n');
    config.push_str(&format!("    ErrorLog ${{APACHE_LOG_DIR}}/{}-error.log\n",
        params.server_name.replace('.', "_")));
    config.push_str(&format!("    CustomLog ${{APACHE_LOG_DIR}}/{}-access.log combined\n",
        params.server_name.replace('.', "_")));

    config.push_str("</VirtualHost>\n");

    config
}
