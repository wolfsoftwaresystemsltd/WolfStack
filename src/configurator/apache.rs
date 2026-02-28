// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Apache2 vhost and module management for WolfServe configurator

use std::path::Path;
use std::process::Command;
use serde::{Deserialize, Serialize};
use crate::installer::{detect_distro, DistroFamily};
use super::{SiteEntry, ConfigTestResult, validate_name};

/// Distro-specific Apache paths and commands
#[allow(dead_code)]
struct ApachePaths {
    sites_available: &'static str,
    sites_enabled: &'static str,
    mods_available: Option<&'static str>,
    mods_enabled: Option<&'static str>,
    config_test_cmd: &'static str,
    service_name: &'static str,
}

fn apache_paths() -> ApachePaths {
    match detect_distro() {
        DistroFamily::Debian | DistroFamily::Unknown => ApachePaths {
            sites_available: "/etc/apache2/sites-available",
            sites_enabled: "/etc/apache2/sites-enabled",
            mods_available: Some("/etc/apache2/mods-available"),
            mods_enabled: Some("/etc/apache2/mods-enabled"),
            config_test_cmd: "apache2ctl",
            service_name: "apache2",
        },
        DistroFamily::RedHat | DistroFamily::Suse => ApachePaths {
            sites_available: "/etc/httpd/conf.d",
            sites_enabled: "/etc/httpd/conf.d",
            mods_available: Some("/etc/httpd/conf.modules.d"),
            mods_enabled: None,
            config_test_cmd: "apachectl",
            service_name: "httpd",
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

/// Check if we're on a Debian-based system (has a2ensite/a2dissite)
fn is_debian() -> bool {
    matches!(detect_distro(), DistroFamily::Debian | DistroFamily::Unknown)
}

/// List all sites/vhosts with enabled status
pub fn list_sites() -> Result<Vec<SiteEntry>, String> {
    let paths = apache_paths();
    let avail = Path::new(paths.sites_available);
    if !avail.exists() {
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(avail)
        .map_err(|e| format!("Failed to read {}: {}", paths.sites_available, e))?;

    let mut sites = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
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
        let enabled = if is_debian() {
            let enabled_path = Path::new(paths.sites_enabled).join(&name);
            enabled_path.exists() || enabled_path.is_symlink()
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
pub fn read_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths();

    // Try the name directly first, then with .disabled suffix
    let path = Path::new(paths.sites_available).join(name);
    if path.exists() {
        return std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e));
    }

    let disabled_path = Path::new(paths.sites_available).join(format!("{}.disabled", name));
    if disabled_path.exists() {
        return std::fs::read_to_string(&disabled_path)
            .map_err(|e| format!("Failed to read {}: {}", disabled_path.display(), e));
    }

    Err(format!("Site {} not found", name))
}

/// Create or update a site config file
pub fn save_site(name: &str, content: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths();
    let path = format!("{}/{}", paths.sites_available, name);

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

/// Delete a site config
pub fn delete_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths();

    // Disable first on Debian
    if is_debian() {
        let _ = Command::new("sudo").args(["a2dissite", name]).output();
    }

    let avail_path = format!("{}/{}", paths.sites_available, name);
    let disabled_path = format!("{}.disabled", avail_path);
    let _ = Command::new("sudo").args(["rm", "-f", &avail_path]).output();
    let _ = Command::new("sudo").args(["rm", "-f", &disabled_path]).output();

    Ok(format!("Site {} deleted", name))
}

/// Enable a site
pub fn enable_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths();

    if is_debian() {
        let output = Command::new("sudo")
            .args(["a2ensite", name])
            .output()
            .map_err(|e| format!("Failed to enable site: {}", e))?;

        if output.status.success() {
            Ok(format!("Site {} enabled", name))
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    } else {
        // RHEL: rename .conf.disabled back to .conf
        let disabled = format!("{}/{}.disabled", paths.sites_available, name);
        let enabled = format!("{}/{}", paths.sites_available, name);
        if Path::new(&disabled).exists() {
            let output = Command::new("sudo")
                .args(["mv", &disabled, &enabled])
                .output()
                .map_err(|e| format!("Failed to enable site: {}", e))?;
            if output.status.success() {
                Ok(format!("Site {} enabled", name))
            } else {
                Err(String::from_utf8_lossy(&output.stderr).to_string())
            }
        } else {
            Ok(format!("Site {} is already enabled", name))
        }
    }
}

/// Disable a site
pub fn disable_site(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let paths = apache_paths();

    if is_debian() {
        let output = Command::new("sudo")
            .args(["a2dissite", name])
            .output()
            .map_err(|e| format!("Failed to disable site: {}", e))?;

        if output.status.success() {
            Ok(format!("Site {} disabled", name))
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    } else {
        // RHEL: rename .conf to .conf.disabled
        let enabled = format!("{}/{}", paths.sites_available, name);
        let disabled = format!("{}.disabled", enabled);
        if Path::new(&enabled).exists() {
            let output = Command::new("sudo")
                .args(["mv", &enabled, &disabled])
                .output()
                .map_err(|e| format!("Failed to disable site: {}", e))?;
            if output.status.success() {
                Ok(format!("Site {} disabled", name))
            } else {
                Err(String::from_utf8_lossy(&output.stderr).to_string())
            }
        } else {
            Ok(format!("Site {} is already disabled", name))
        }
    }
}

/// List Apache modules with enabled status
pub fn list_modules() -> Result<Vec<ModuleEntry>, String> {
    if is_debian() {
        list_modules_debian()
    } else {
        list_modules_rhel()
    }
}

fn list_modules_debian() -> Result<Vec<ModuleEntry>, String> {
    let mods_avail = Path::new("/etc/apache2/mods-available");
    let mods_enabled = Path::new("/etc/apache2/mods-enabled");

    if !mods_avail.exists() {
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(mods_avail)
        .map_err(|e| format!("Failed to read modules: {}", e))?;

    let mut modules = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        // Module files are name.load and name.conf; we track by base name
        let base = if fname.ends_with(".load") {
            fname.trim_end_matches(".load").to_string()
        } else if fname.ends_with(".conf") {
            fname.trim_end_matches(".conf").to_string()
        } else {
            continue;
        };

        if seen.contains(&base) {
            continue;
        }
        seen.insert(base.clone());

        let enabled = mods_enabled.join(format!("{}.load", base)).exists()
            || mods_enabled.join(format!("{}.conf", base)).exists();

        modules.push(ModuleEntry {
            name: base,
            enabled,
        });
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(modules)
}

fn list_modules_rhel() -> Result<Vec<ModuleEntry>, String> {
    // On RHEL, list loaded modules via apachectl -M
    let output = Command::new("sudo")
        .args(["apachectl", "-M"])
        .output()
        .map_err(|e| format!("Failed to list modules: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut modules = Vec::new();
    for line in stdout.lines() {
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
pub fn enable_module(name: &str) -> Result<String, String> {
    validate_name(name)?;
    if is_debian() {
        let output = Command::new("sudo")
            .args(["a2enmod", name])
            .output()
            .map_err(|e| format!("Failed to enable module: {}", e))?;
        if output.status.success() {
            Ok(format!("Module {} enabled", name))
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    } else {
        Err("Module management on RHEL requires manual editing of conf.modules.d files".to_string())
    }
}

/// Disable an Apache module
pub fn disable_module(name: &str) -> Result<String, String> {
    validate_name(name)?;
    if is_debian() {
        let output = Command::new("sudo")
            .args(["a2dismod", name])
            .output()
            .map_err(|e| format!("Failed to disable module: {}", e))?;
        if output.status.success() {
            Ok(format!("Module {} disabled", name))
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    } else {
        Err("Module management on RHEL requires manual editing of conf.modules.d files".to_string())
    }
}

/// Run apachectl configtest
pub fn test_config() -> ConfigTestResult {
    let paths = apache_paths();
    let output = Command::new("sudo")
        .args([paths.config_test_cmd, "configtest"])
        .output();

    match output {
        Ok(o) => {
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
            output: format!("Failed to run {} configtest: {}", paths.config_test_cmd, e),
        },
    }
}

/// Reload Apache — runs test first, only reloads if test passes
pub fn reload() -> Result<String, String> {
    let test = test_config();
    if !test.success {
        return Err(format!("Config test failed, not reloading:\n{}", test.output));
    }

    let paths = apache_paths();
    let output = Command::new("sudo")
        .args(["systemctl", "reload", paths.service_name])
        .output()
        .map_err(|e| format!("Failed to reload {}: {}", paths.service_name, e))?;

    if output.status.success() {
        Ok(format!("{} reloaded successfully", paths.service_name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Read recent Apache error log lines
pub fn error_log(lines: usize) -> Vec<String> {
    let n = lines.min(500).to_string();
    // Try common log locations
    let log_paths = [
        "/var/log/apache2/error.log",
        "/var/log/httpd/error_log",
    ];

    for log_path in &log_paths {
        if Path::new(log_path).exists() {
            let output = Command::new("sudo")
                .args(["tail", "-n", &n, log_path])
                .output();

            if let Ok(o) = output {
                if o.status.success() {
                    return String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(|l| l.to_string())
                        .collect();
                }
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
