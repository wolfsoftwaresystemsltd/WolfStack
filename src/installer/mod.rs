// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Installer — manages installation and status of Wolf suite components

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::info;

/// All available Wolf suite components
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    WolfNet,
    WolfProxy,
    WolfServe,
    WolfDisk,
    WolfScale,
    MariaDB,
    Certbot,
}

impl Component {
    pub fn name(&self) -> &'static str {
        match self {
            Component::WolfNet => "WolfNet",
            Component::WolfProxy => "WolfProxy",
            Component::WolfServe => "WolfServe",
            Component::WolfDisk => "WolfDisk",
            Component::WolfScale => "WolfScale",
            Component::MariaDB => "MariaDB",
            Component::Certbot => "Certbot",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Component::WolfNet => "Mesh VPN with automatic peer discovery",
            Component::WolfProxy => "Reverse proxy with built-in firewall",
            Component::WolfServe => "Web server",
            Component::WolfDisk => "Distributed filesystem",
            Component::WolfScale => "MariaDB-compatible distributed database",
            Component::MariaDB => "MariaDB relational database server",
            Component::Certbot => "Let's Encrypt certificate manager",
        }
    }

    pub fn service_name(&self) -> &'static str {
        match self {
            Component::WolfNet => "wolfnet",
            Component::WolfProxy => "wolfproxy",
            Component::WolfServe => "wolfserve",
            Component::WolfDisk => "wolfdisk",
            Component::WolfScale => "wolfscale",
            Component::MariaDB => "mariadb",
            Component::Certbot => "certbot",
        }
    }

    pub fn config_path(&self) -> Option<&'static str> {
        match self {
            Component::WolfNet => Some("/etc/wolfnet/config.toml"),
            Component::WolfProxy => Some("/etc/wolfproxy/config.toml"),
            Component::WolfServe => Some("/etc/wolfserve/config.toml"),
            Component::WolfDisk => Some("/etc/wolfdisk/config.toml"),
            Component::WolfScale => Some("/etc/wolfscale/config.toml"),
            Component::MariaDB => Some("/etc/mysql/mariadb.conf.d/50-server.cnf"),
            Component::Certbot => None,
        }
    }

    pub fn all() -> &'static [Component] {
        &[
            Component::WolfNet,
            Component::WolfProxy,
            Component::WolfServe,
            Component::WolfDisk,
            Component::WolfScale,
            Component::MariaDB,
            Component::Certbot,
        ]
    }
}

/// Status of a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub component: Component,
    pub installed: bool,
    pub running: bool,
    pub enabled: bool,
    pub version: Option<String>,
}

/// Detected distro family
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DistroFamily {
    Debian,  // Debian, Ubuntu, etc.
    RedHat,  // RHEL, Fedora, CentOS, etc.
    Suse,    // SLES, openSUSE (IBM Power SLES)
    Unknown,
}

/// Detect the current distro family
pub fn detect_distro() -> DistroFamily {
    if std::path::Path::new("/etc/debian_version").exists() {
        DistroFamily::Debian
    } else if std::path::Path::new("/etc/redhat-release").exists()
        || std::path::Path::new("/etc/fedora-release").exists()
    {
        DistroFamily::RedHat
    } else if std::path::Path::new("/etc/SuSE-release").exists()
        || std::path::Path::new("/etc/SUSE-brand").exists()
        || std::path::Path::new("/usr/bin/zypper").exists()
    {
        DistroFamily::Suse
    } else {
        // Try os-release as final fallback
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let lower = content.to_lowercase();
            if lower.contains("suse") || lower.contains("sles") {
                return DistroFamily::Suse;
            }
            if lower.contains("rhel") || lower.contains("centos") || lower.contains("fedora") || lower.contains("red hat") {
                return DistroFamily::RedHat;
            }
        }
        DistroFamily::Unknown
    }
}

/// Get the package manager command for the current distro
fn pkg_install_cmd(distro: DistroFamily) -> (&'static str, &'static str) {
    match distro {
        DistroFamily::Debian => ("apt-get", "install -y"),
        DistroFamily::RedHat => ("dnf", "install -y"),
        DistroFamily::Suse => ("zypper", "install -y"),
        DistroFamily::Unknown => ("apt-get", "install -y"),
    }
}

/// Check if a systemd service exists and its status
pub fn check_service(service: &str) -> (bool, bool, bool) {
    let installed = Command::new("systemctl")
        .args(["cat", service])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let running = Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let enabled = Command::new("systemctl")
        .args(["is-enabled", "--quiet", service])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    (installed, running, enabled)
}

/// Check if a binary exists on PATH
fn binary_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get version of a component
fn get_version(component: Component) -> Option<String> {
    let (cmd, args): (&str, &[&str]) = match component {
        Component::MariaDB => ("mariadb", &["--version"]),
        Component::Certbot => ("certbot", &["--version"]),
        Component::WolfNet => ("wolfnet", &["--version"]),
        Component::WolfProxy => ("wolfproxy", &["--version"]),
        Component::WolfServe => ("wolfserve", &["--version"]),
        Component::WolfDisk => ("wolfdisk", &["--version"]),
        Component::WolfScale => ("wolfscale", &["--version"]),
    };

    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

/// Get status of all components
pub fn get_all_status() -> Vec<ComponentStatus> {
    Component::all().iter().map(|comp| {
        let (installed, running, enabled) = check_service(comp.service_name());
        let bin_exists = binary_exists(comp.service_name());
        ComponentStatus {
            component: *comp,
            installed: installed || bin_exists,
            running,
            enabled,
            version: get_version(*comp),
        }
    }).collect()
}

/// Install a component
pub fn install_component(component: Component) -> Result<String, String> {
    let distro = detect_distro();
    info!("Installing {} on {:?}", component.name(), distro);

    match component {
        Component::MariaDB => install_mariadb(distro),
        Component::Certbot => install_certbot(distro),
        Component::WolfNet | Component::WolfProxy | Component::WolfServe
        | Component::WolfDisk | Component::WolfScale => install_wolf_component(component, distro),
    }
}

fn install_mariadb(distro: DistroFamily) -> Result<String, String> {
    let (pkg_mgr, install_flag) = pkg_install_cmd(distro);
    let pkg_name = match distro {
        DistroFamily::Debian => "mariadb-server",
        DistroFamily::RedHat => "mariadb-server",
        DistroFamily::Suse => "mariadb",
        DistroFamily::Unknown => "mariadb-server",
    };

    let output = Command::new("sudo")
        .args([pkg_mgr])
        .args(install_flag.split_whitespace())
        .arg(pkg_name)
        .output()
        .map_err(|e| format!("Failed to run package manager: {}", e))?;

    if output.status.success() {
        // Enable and start
        let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "mariadb"]).output();
        Ok(format!("{} installed and started", pkg_name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn install_certbot(distro: DistroFamily) -> Result<String, String> {
    let (pkg_mgr, install_flag) = pkg_install_cmd(distro);
    let output = Command::new("sudo")
        .args([pkg_mgr])
        .args(install_flag.split_whitespace())
        .arg("certbot")
        .output()
        .map_err(|e| format!("Failed to run package manager: {}", e))?;

    if output.status.success() {
        Ok("Certbot installed".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn install_wolf_component(component: Component, _distro: DistroFamily) -> Result<String, String> {
    // Wolf components are installed from GitHub releases
    let repo = match component {
        Component::WolfNet | Component::WolfDisk | Component::WolfScale =>
            "wolfsoftwaresystemsltd/WolfScale",
        Component::WolfProxy => "wolfsoftwaresystemsltd/WolfProxy",
        Component::WolfServe => "wolfsoftwaresystemsltd/WolfServe",
        _ => return Err("Unknown component".to_string()),
    };

    info!("Would install {} from github.com/{}", component.name(), repo);
    // TODO: Download and install from GitHub releases
    Ok(format!("{} installation queued from {}", component.name(), repo))
}

/// Start a service
pub fn start_service(service: &str) -> Result<String, String> {
    let output = Command::new("sudo")
        .args(["systemctl", "start", service])
        .output()
        .map_err(|e| format!("Failed to start {}: {}", service, e))?;

    if output.status.success() {
        Ok(format!("{} started", service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Stop a service
pub fn stop_service(service: &str) -> Result<String, String> {
    let output = Command::new("sudo")
        .args(["systemctl", "stop", service])
        .output()
        .map_err(|e| format!("Failed to stop {}: {}", service, e))?;

    if output.status.success() {
        Ok(format!("{} stopped", service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Restart a service
pub fn restart_service(service: &str) -> Result<String, String> {
    let output = Command::new("sudo")
        .args(["systemctl", "restart", service])
        .output()
        .map_err(|e| format!("Failed to restart {}: {}", service, e))?;

    if output.status.success() {
        Ok(format!("{} restarted", service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Request a certificate via certbot
pub fn request_certificate(domain: &str, email: &str) -> Result<String, String> {
    if !binary_exists("certbot") {
        info!("Certbot not found, installing automatically...");
        install_certbot(detect_distro())?;
    }

    let output = Command::new("sudo")
        .args([
            "certbot", "certonly", "--standalone",
            "-d", domain,
            "--email", email,
            "--agree-tos", "--non-interactive",
        ])
        .output()
        .map_err(|e| format!("Failed to run certbot: {}", e))?;

    if output.status.success() {
        Ok(format!("Certificate obtained for {}. Restart WolfStack to enable HTTPS.", domain))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Parse `sudo certbot certificates` output into structured cert info
/// Returns Vec of (domains, cert_path, key_path, expiry)
fn parse_certbot_certificates() -> Vec<(String, String, String, String)> {
    let output = Command::new("sudo")
        .args(["certbot", "certificates"])
        .output()
        .ok();

    let stdout = match output {
        Some(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Some(ref o) => {
            // certbot might output to stderr too
            let stderr = String::from_utf8_lossy(&o.stderr);
            tracing::debug!("certbot certificates failed (exit {}): {}", o.status, stderr);
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&o.stdout),
                stderr
            );
            combined
        }
        _ => {
            tracing::debug!("Failed to execute 'sudo certbot certificates'");
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    let mut current_domains = String::new();
    let mut current_cert = String::new();
    let mut current_key = String::new();
    let mut current_expiry = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Domains:") {
            // Save previous entry if complete
            if !current_domains.is_empty() && !current_cert.is_empty() && !current_key.is_empty() {
                results.push((
                    current_domains.clone(), current_cert.clone(),
                    current_key.clone(), current_expiry.clone(),
                ));
            }
            current_domains = trimmed.strip_prefix("Domains:").unwrap_or("").trim().to_string();
            current_cert.clear();
            current_key.clear();
            current_expiry.clear();
        } else if trimmed.starts_with("Certificate Path:") {
            current_cert = trimmed.strip_prefix("Certificate Path:").unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("Private Key Path:") {
            current_key = trimmed.strip_prefix("Private Key Path:").unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("Expiry Date:") {
            current_expiry = trimmed.strip_prefix("Expiry Date:").unwrap_or("").trim().to_string();
        }
    }
    // Don't forget the last entry
    if !current_domains.is_empty() && !current_cert.is_empty() && !current_key.is_empty() {
        results.push((current_domains, current_cert, current_key, current_expiry));
    }

    results
}

/// Directly scan /etc/letsencrypt/live/ for certificate directories
/// This works even when certbot CLI isn't available or sudo fails
/// Returns Vec of (domain, cert_path, key_path)
fn scan_letsencrypt_live() -> Vec<(String, String, String)> {
    let live_dir = std::path::Path::new("/etc/letsencrypt/live");
    if !live_dir.exists() {
        return Vec::new();
    }

    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(live_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Skip the README directory that certbot creates
            if path.file_name().map(|n| n == "README").unwrap_or(false) {
                continue;
            }

            let cert = path.join("fullchain.pem");
            let key = path.join("privkey.pem");
            if cert.exists() && key.exists() {
                let domain = path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                results.push((
                    domain,
                    cert.to_string_lossy().to_string(),
                    key.to_string_lossy().to_string(),
                ));
            }
        }
    }

    results
}

/// Find TLS certificate files for a domain (Let's Encrypt or /etc/wolfstack/)
/// Returns (cert_path, key_path) if both exist
pub fn find_tls_certificate(domain: Option<&str>) -> Option<(String, String)> {
    // Check explicit /etc/wolfstack/ paths first
    let ws_cert = "/etc/wolfstack/cert.pem";
    let ws_key = "/etc/wolfstack/key.pem";
    if std::path::Path::new(ws_cert).exists() && std::path::Path::new(ws_key).exists() {
        return Some((ws_cert.to_string(), ws_key.to_string()));
    }

    // Try certbot CLI first
    let certs = parse_certbot_certificates();

    // If a specific domain was requested, look for it
    if let Some(d) = domain {
        if let Some((_domains, cert, key, _expiry)) = certs.iter().find(|(domains, _, _, _)| {
            domains.split_whitespace().any(|dom| dom == d)
        }) {
            return Some((cert.clone(), key.clone()));
        }
    }

    // Return first certbot result if any
    if let Some((_domains, cert, key, _expiry)) = certs.first() {
        return Some((cert.clone(), key.clone()));
    }

    // Fallback: directly scan /etc/letsencrypt/live/
    let live_certs = scan_letsencrypt_live();
    if let Some(d) = domain {
        if let Some((_dom, cert, key)) = live_certs.iter().find(|(dom, _, _)| dom == d) {
            return Some((cert.clone(), key.clone()));
        }
    }
    if let Some((_dom, cert, key)) = live_certs.first() {
        info!("Found Let's Encrypt certificate via filesystem scan: {}", cert);
        return Some((cert.clone(), key.clone()));
    }

    None
}

/// List ALL TLS certificates on this server
/// Uses the same discovery methods as find_tls_certificate but collects everything
pub fn list_certificates() -> serde_json::Value {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. Check /etc/wolfstack/ custom certs
    let ws_cert = "/etc/wolfstack/cert.pem";
    let ws_key = "/etc/wolfstack/key.pem";
    if std::path::Path::new(ws_cert).exists() && std::path::Path::new(ws_key).exists() {
        seen.insert(ws_cert.to_string());
        results.push(serde_json::json!({
            "domain": "wolfstack (custom)",
            "cert_path": ws_cert,
            "key_path": ws_key,
            "source": "custom",
            "valid": true,
        }));
    }

    // 2. Certbot CLI
    let certbot_certs = parse_certbot_certificates();
    for (domains, cert_path, key_path, expiry) in &certbot_certs {
        if seen.contains(cert_path) { continue; }
        seen.insert(cert_path.clone());
        results.push(serde_json::json!({
            "domain": domains,
            "cert_path": cert_path,
            "key_path": key_path,
            "expiry": expiry,
            "source": "certbot",
            "valid": true,
        }));
    }

    // 3. Filesystem scan of /etc/letsencrypt/live/
    let fs_certs = scan_letsencrypt_live();
    for (domain, cert_path, key_path) in &fs_certs {
        if seen.contains(cert_path) { continue; }
        seen.insert(cert_path.clone());
        results.push(serde_json::json!({
            "domain": domain,
            "cert_path": cert_path,
            "key_path": key_path,
            "source": "filesystem",
            "valid": true,
        }));
    }

    serde_json::json!({
        "certs": results,
        "diagnostics": if results.is_empty() {
            vec!["ℹ️ No TLS certificates found on this server".to_string()]
        } else {
            vec![format!("✅ Found {} certificate(s)", results.len())]
        },
    })
}
