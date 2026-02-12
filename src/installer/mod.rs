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
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let running = Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let enabled = Command::new("systemctl")
        .args(["is-enabled", "--quiet", service])
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

/// Find TLS certificate files for a domain (Let's Encrypt or /etc/wolfstack/)
/// Returns (cert_path, key_path) if both exist
pub fn find_tls_certificate(domain: Option<&str>) -> Option<(String, String)> {
    // Check explicit /etc/wolfstack/ paths first
    let ws_cert = "/etc/wolfstack/cert.pem";
    let ws_key = "/etc/wolfstack/key.pem";
    if std::path::Path::new(ws_cert).exists() && std::path::Path::new(ws_key).exists() {
        return Some((ws_cert.to_string(), ws_key.to_string()));
    }

    // Check Let's Encrypt for specific domain
    if let Some(d) = domain {
        let le_cert = format!("/etc/letsencrypt/live/{}/fullchain.pem", d);
        let le_key = format!("/etc/letsencrypt/live/{}/privkey.pem", d);
        if std::path::Path::new(&le_cert).exists() && std::path::Path::new(&le_key).exists() {
            return Some((le_cert, le_key));
        }
    }

    // Auto-detect: scan /etc/letsencrypt/live/ for any domain
    if let Ok(entries) = std::fs::read_dir("/etc/letsencrypt/live") {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir = entry.path();
                let cert = dir.join("fullchain.pem");
                let key = dir.join("privkey.pem");
                if cert.exists() && key.exists() {
                    return Some((
                        cert.to_string_lossy().to_string(),
                        key.to_string_lossy().to_string(),
                    ));
                }
            }
        }
    }

    None
}

/// List all domains with Let's Encrypt certificates
pub fn list_certificates() -> Vec<serde_json::Value> {
    let mut certs = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/etc/letsencrypt/live") {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "README" { continue; }
                let dir = entry.path();
                let cert_exists = dir.join("fullchain.pem").exists();
                let key_exists = dir.join("privkey.pem").exists();
                certs.push(serde_json::json!({
                    "domain": name,
                    "cert_path": dir.join("fullchain.pem").to_string_lossy(),
                    "key_path": dir.join("privkey.pem").to_string_lossy(),
                    "valid": cert_exists && key_exists,
                }));
            }
        }
    }

    // Also check /etc/wolfstack/
    let ws_cert = std::path::Path::new("/etc/wolfstack/cert.pem");
    let ws_key = std::path::Path::new("/etc/wolfstack/key.pem");
    if ws_cert.exists() && ws_key.exists() {
        certs.push(serde_json::json!({
            "domain": "wolfstack (custom)",
            "cert_path": "/etc/wolfstack/cert.pem",
            "key_path": "/etc/wolfstack/key.pem",
            "valid": true,
        }));
    }

    certs
}
