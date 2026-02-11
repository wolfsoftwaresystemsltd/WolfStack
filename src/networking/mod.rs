//! Networking — System network interface and VLAN management
//!
//! Provides read/write access to:
//! - Network interfaces (ip link/addr)
//! - VLANs (802.1Q)
//! - DNS configuration
//! - WolfNet overlay status

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, warn};

/// Network interface info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub state: String,         // up, down, unknown
    pub mtu: u32,
    pub addresses: Vec<InterfaceAddress>,
    pub is_vlan: bool,
    pub vlan_id: Option<u32>,
    pub parent: Option<String>, // parent interface for VLANs
    pub speed: Option<String>,  // link speed (1000Mb/s etc)
    pub driver: Option<String>,
}

/// IP address on an interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub address: String,   // e.g. 192.168.1.10
    pub prefix: u32,       // e.g. 24
    pub family: String,    // inet or inet6
    pub scope: String,     // global, link, host
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub method: String,       // how DNS is managed: "systemd-resolved", "networkmanager", "netplan", "resolv.conf"
    pub editable: bool,       // whether we can edit DNS
}

/// Which DNS management method is active
#[derive(Debug, Clone, PartialEq)]
enum DnsMethod {
    SystemdResolved, // Ubuntu 18+, some Debian, Fedora 33+
    NetworkManager,  // Fedora, RHEL, CentOS, IBM Power (RHEL)
    Netplan,         // Ubuntu 18+ server (configures systemd-resolved or NM)
    ResolvConf,      // Direct /etc/resolv.conf (Debian, older systems, IBM Power SLES)
}

impl DnsMethod {
    fn as_str(&self) -> &'static str {
        match self {
            DnsMethod::SystemdResolved => "systemd-resolved",
            DnsMethod::NetworkManager => "networkmanager",
            DnsMethod::Netplan => "netplan",
            DnsMethod::ResolvConf => "resolv.conf",
        }
    }
}

/// Detect how this system manages DNS
fn detect_dns_method() -> DnsMethod {
    // 1. Check for netplan (Ubuntu server)
    if std::path::Path::new("/etc/netplan").exists() {
        let has_files = std::fs::read_dir("/etc/netplan")
            .map(|entries| entries.filter_map(|e| e.ok())
                .any(|e| e.path().extension().map_or(false, |ext| ext == "yaml" || ext == "yml")))
            .unwrap_or(false);
        if has_files {
            return DnsMethod::Netplan;
        }
    }

    // 2. Check for NetworkManager FIRST — on Fedora/RHEL, both NM and
    //    systemd-resolved are active, but NM is the actual DNS manager.
    //    systemd-resolved is just a stub resolver forwarding to NM's DNS.
    if Command::new("systemctl")
        .args(["is-active", "NetworkManager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
    {
        return DnsMethod::NetworkManager;
    }

    // 3. Check for systemd-resolved (standalone, without NM)
    if Command::new("systemctl")
        .args(["is-active", "systemd-resolved"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
    {
        return DnsMethod::SystemdResolved;
    }

    // 4. Fallback: direct resolv.conf
    DnsMethod::ResolvConf
}

/// Get DNS configuration — reads from the correct source for the detected method
pub fn get_dns() -> DnsConfig {
    let method = detect_dns_method();
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    // Read effective DNS — resolvectl for systemd-resolved/netplan, resolv.conf for others
    match method {
        DnsMethod::SystemdResolved | DnsMethod::Netplan => {
            // Netplan on Ubuntu typically uses systemd-resolved as its backend,
            // so /etc/resolv.conf shows 127.0.0.53 (the stub listener) — not useful.
            // Use resolvectl to get the actual configured nameservers.
            if let Ok(out) = Command::new("resolvectl").arg("status").output() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let line = line.trim();
                    if line.starts_with("DNS Servers:") || line.starts_with("DNS Server:") {
                        let servers = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                        for s in servers.split_whitespace() {
                            if !s.is_empty() && !nameservers.contains(&s.to_string()) {
                                nameservers.push(s.to_string());
                            }
                        }
                    }
                    if line.starts_with("DNS Domain:") {
                        let domains = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                        for d in domains.split_whitespace() {
                            if !d.is_empty() && !search_domains.contains(&d.to_string()) {
                                search_domains.push(d.to_string());
                            }
                        }
                    }
                }
            }

            // If resolvectl gave nothing, try reading the WolfStack override file
            if nameservers.is_empty() && method == DnsMethod::Netplan {
                let override_path = "/etc/netplan/99-wolfstack-dns.yaml";
                if let Ok(content) = std::fs::read_to_string(override_path) {
                    // Simple YAML parsing: extract addresses: [...] and search: [...]
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("addresses:") {
                            let bracket_part = trimmed.trim_start_matches("addresses:").trim();
                            let inner = bracket_part.trim_start_matches('[').trim_end_matches(']');
                            for addr in inner.split(',') {
                                let addr = addr.trim().trim_matches('"').trim();
                                if !addr.is_empty() && !nameservers.contains(&addr.to_string()) {
                                    nameservers.push(addr.to_string());
                                }
                            }
                        }
                        if trimmed.starts_with("search:") {
                            let bracket_part = trimmed.trim_start_matches("search:").trim();
                            let inner = bracket_part.trim_start_matches('[').trim_end_matches(']');
                            for domain in inner.split(',') {
                                let domain = domain.trim().trim_matches('"').trim();
                                if !domain.is_empty() && !search_domains.contains(&domain.to_string()) {
                                    search_domains.push(domain.to_string());
                                }
                            }
                        }
                    }
                }
            }

            // Final fallback: resolv.conf (filter out 127.0.0.53 stub)
            if nameservers.is_empty() {
                read_resolv_conf(&mut nameservers, &mut search_domains);
                nameservers.retain(|ns| ns != "127.0.0.53");
            }
        }
        DnsMethod::NetworkManager => {
            // On RHEL/Fedora/IBM Power, read DNS from the primary NM connection
            // (ethernet or wifi), not from ALL devices which includes Tailscale etc.
            if let Some(conn_name) = find_primary_nm_connection() {
                if let Ok(out) = Command::new("nmcli")
                    .args(["-t", "-f", "IP4.DNS,IP4.DOMAIN", "connection", "show", &conn_name])
                    .output()
                {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with("IP4.DNS") {
                            if let Some(dns) = line.splitn(2, ':').nth(1) {
                                let dns = dns.trim();
                                if !dns.is_empty() && !nameservers.contains(&dns.to_string()) {
                                    nameservers.push(dns.to_string());
                                }
                            }
                        }
                        if line.starts_with("IP4.DOMAIN") {
                            if let Some(domain) = line.splitn(2, ':').nth(1) {
                                let domain = domain.trim();
                                if !domain.is_empty() && !search_domains.contains(&domain.to_string()) {
                                    search_domains.push(domain.to_string());
                                }
                            }
                        }
                    }
                }
            }
            // Fallback to resolv.conf if nmcli gave nothing
            if nameservers.is_empty() {
                read_resolv_conf(&mut nameservers, &mut search_domains);
                nameservers.retain(|ns| ns != "127.0.0.53");
            }
        }
        DnsMethod::ResolvConf => {
            read_resolv_conf(&mut nameservers, &mut search_domains);
        }
    }

    DnsConfig {
        nameservers,
        search_domains,
        method: method.as_str().to_string(),
        editable: true,
    }
}

/// Parse /etc/resolv.conf
fn read_resolv_conf(nameservers: &mut Vec<String>, search_domains: &mut Vec<String>) {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                let ns = line[11..].trim().to_string();
                if !ns.is_empty() && !nameservers.contains(&ns) {
                    nameservers.push(ns);
                }
            } else if line.starts_with("search ") {
                *search_domains = line[7..].split_whitespace().map(|s| s.to_string()).collect();
            }
        }
    }
}

/// Set DNS nameservers and search domains — writes to the correct config
pub fn set_dns(nameservers: Vec<String>, search_domains: Vec<String>) -> Result<String, String> {
    let method = detect_dns_method();
    info!("Setting DNS via {:?} — nameservers: {:?}, search: {:?}", method.as_str(), nameservers, search_domains);

    match method {
        DnsMethod::Netplan => set_dns_netplan(&nameservers, &search_domains),
        DnsMethod::SystemdResolved => set_dns_systemd_resolved(&nameservers, &search_domains),
        DnsMethod::NetworkManager => set_dns_networkmanager(&nameservers, &search_domains),
        DnsMethod::ResolvConf => set_dns_resolv_conf(&nameservers, &search_domains),
    }
}

/// Set DNS via netplan (Ubuntu server)
fn set_dns_netplan(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Find existing netplan config
    let netplan_dir = "/etc/netplan";
    let files: Vec<_> = std::fs::read_dir(netplan_dir)
        .map_err(|e| format!("Cannot read {}: {}", netplan_dir, e))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".yaml") || name.ends_with(".yml")
        })
        .collect();

    if files.is_empty() {
        return Err("No netplan config files found".to_string());
    }

    // Read the first config file
    let config_path = files[0].path();
    let _content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Cannot read {}: {}", config_path.display(), e))?;

    // Simple YAML manipulation: find the nameservers block and update it
    // For safety, use a WolfStack-specific override file instead
    let override_path = format!("{}/99-wolfstack-dns.yaml", netplan_dir);

    // Detect the primary ethernet interface
    let primary_iface = detect_primary_interface();

    let mut yaml = String::from("# Managed by WolfStack — DNS configuration\nnetwork:\n  version: 2\n  ethernets:\n");
    yaml.push_str(&format!("    {}:\n", primary_iface));
    yaml.push_str("      nameservers:\n");
    yaml.push_str(&format!("        addresses: [{}]\n",
        nameservers.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ")));
    if !search_domains.is_empty() {
        yaml.push_str(&format!("        search: [{}]\n",
            search_domains.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ")));
    }

    std::fs::write(&override_path, &yaml)
        .map_err(|e| format!("Cannot write {}: {}", override_path, e))?;

    // Apply netplan
    let output = Command::new("netplan")
        .arg("apply")
        .output()
        .map_err(|e| format!("Failed to run netplan apply: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        // Clean up on failure
        let _ = std::fs::remove_file(&override_path);
        return Err(format!("netplan apply failed: {}", stderr));
    }

    info!("DNS updated via netplan: {:?}", nameservers);
    Ok("DNS updated via netplan".to_string())
}

/// Set DNS via systemd-resolved
fn set_dns_systemd_resolved(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Write a resolved.conf drop-in
    let dropin_dir = "/etc/systemd/resolved.conf.d";
    std::fs::create_dir_all(dropin_dir)
        .map_err(|e| format!("Cannot create {}: {}", dropin_dir, e))?;

    let dropin_path = format!("{}/wolfstack-dns.conf", dropin_dir);
    let mut conf = String::from("# Managed by WolfStack\n[Resolve]\n");
    if !nameservers.is_empty() {
        conf.push_str(&format!("DNS={}\n", nameservers.join(" ")));
    }
    if !search_domains.is_empty() {
        conf.push_str(&format!("Domains={}\n", search_domains.join(" ")));
    }
    conf.push_str("DNSStubListener=yes\n");

    std::fs::write(&dropin_path, &conf)
        .map_err(|e| format!("Cannot write {}: {}", dropin_path, e))?;

    // Restart systemd-resolved
    let output = Command::new("systemctl")
        .args(["restart", "systemd-resolved"])
        .output()
        .map_err(|e| format!("Failed to restart resolved: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    info!("DNS updated via systemd-resolved: {:?}", nameservers);
    Ok("DNS updated via systemd-resolved".to_string())
}

/// Find the primary NetworkManager connection (ethernet or wifi)
fn find_primary_nm_connection() -> Option<String> {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "NAME,DEVICE,TYPE", "connection", "show", "--active"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Prefer ethernet, then wifi — skip tun/bridge/loopback
    let primary_types = ["802-3-ethernet", "ethernet", "802-11-wireless", "wifi"];
    for ptype in &primary_types {
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[2] == *ptype {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

/// Set DNS via NetworkManager (Fedora, RHEL, IBM Power RHEL)
fn set_dns_networkmanager(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Find the primary active connection (ethernet or wifi)
    let conn_name = find_primary_nm_connection()
        .ok_or_else(|| "No active NetworkManager ethernet/wifi connection found".to_string())?;

    // Set DNS via nmcli
    let dns_str = nameservers.join(" ");
    let dns_search_str = search_domains.join(" ");

    let output = Command::new("nmcli")
        .args(["connection", "modify", &conn_name,
              "ipv4.dns", &dns_str,
              "ipv4.dns-search", &dns_search_str])
        .output()
        .map_err(|e| format!("nmcli modify failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("nmcli modify failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Reload connection
    let _ = Command::new("nmcli")
        .args(["connection", "up", &conn_name])
        .output();

    info!("DNS updated via NetworkManager (connection: {}): {:?}", conn_name, nameservers);
    Ok(format!("DNS updated via NetworkManager (connection: {})", conn_name))
}

/// Set DNS via direct /etc/resolv.conf (Debian, IBM Power SLES, older systems)
fn set_dns_resolv_conf(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Check if resolv.conf is a symlink (managed by another tool)
    let resolv_path = std::path::Path::new("/etc/resolv.conf");
    if resolv_path.is_symlink() {
        // Read what it points to
        if let Ok(target) = std::fs::read_link(resolv_path) {
            let target_str = target.to_string_lossy();
            if target_str.contains("systemd") {
                return Err("Cannot edit /etc/resolv.conf: it's managed by systemd-resolved. Use resolvectl instead.".to_string());
            }
        }
    }

    // Preserve comments and non-nameserver/non-search lines
    let existing = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut output = String::new();

    // Keep comments and options
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("options ") {
            output.push_str(line);
            output.push('\n');
        }
    }

    // Add search domains
    if !search_domains.is_empty() {
        output.push_str(&format!("search {}\n", search_domains.join(" ")));
    }

    // Add nameservers
    for ns in nameservers {
        output.push_str(&format!("nameserver {}\n", ns));
    }

    std::fs::write("/etc/resolv.conf", &output)
        .map_err(|e| format!("Cannot write /etc/resolv.conf: {}", e))?;

    info!("DNS updated via /etc/resolv.conf: {:?}", nameservers);
    Ok("DNS updated via /etc/resolv.conf".to_string())
}

/// Detect primary network interface
fn detect_primary_interface() -> String {
    // Use `ip route` to find the default route interface
    if let Ok(out) = Command::new("ip").args(["route", "show", "default"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(idx) = parts.iter().position(|&p| p == "dev") {
                if let Some(iface) = parts.get(idx + 1) {
                    return iface.to_string();
                }
            }
        }
    }
    "eth0".to_string()
}

/// WolfNet interface status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNetStatus {
    pub installed: bool,
    pub running: bool,
    pub interface: Option<String>,  // tun interface name (e.g. wn0)
    pub ip: Option<String>,
    pub peers: Vec<WolfNetPeer>,
}

/// A WolfNet peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNetPeer {
    pub name: String,
    pub endpoint: String,
    pub ip: String,
    pub connected: bool,
}

/// List all network interfaces with their addresses
pub fn list_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();

    // Use `ip -j addr show` for JSON output
    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let json_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                for entry in entries {
                    let name = entry["ifname"].as_str().unwrap_or("").to_string();
                    if name == "lo" { continue; } // skip loopback

                    let mac = entry["address"].as_str().unwrap_or("").to_string();
                    let state = entry["operstate"].as_str().unwrap_or("unknown").to_lowercase();
                    let mtu = entry["mtu"].as_u64().unwrap_or(1500) as u32;

                    // Parse addresses
                    let mut addresses = Vec::new();
                    if let Some(addr_info) = entry["addr_info"].as_array() {
                        for addr in addr_info {
                            let family = addr["family"].as_str().unwrap_or("").to_string();
                            let local = addr["local"].as_str().unwrap_or("").to_string();
                            let prefix = addr["prefixlen"].as_u64().unwrap_or(0) as u32;
                            let scope = addr["scope"].as_str().unwrap_or("").to_string();
                            if !local.is_empty() {
                                addresses.push(InterfaceAddress {
                                    address: local,
                                    prefix,
                                    family,
                                    scope,
                                });
                            }
                        }
                    }

                    // Check if it's a VLAN
                    let (is_vlan, vlan_id, parent) = detect_vlan(&name, &entry);

                    // Get speed
                    let speed = get_link_speed(&name);
                    let driver = get_driver(&name);

                    interfaces.push(NetworkInterface {
                        name,
                        mac,
                        state,
                        mtu,
                        addresses,
                        is_vlan,
                        vlan_id,
                        parent,
                        speed,
                        driver,
                    });
                }
            }
        }
        _ => {
            warn!("Failed to run `ip -j addr show`");
        }
    }

    interfaces
}

/// Detect if an interface is a VLAN
fn detect_vlan(name: &str, entry: &serde_json::Value) -> (bool, Option<u32>, Option<String>) {
    // Check link_info for VLAN
    if let Some(linkinfo) = entry.get("linkinfo") {
        if let Some(info_kind) = linkinfo.get("info_kind").and_then(|v| v.as_str()) {
            if info_kind == "vlan" {
                let vlan_id = linkinfo.get("info_data")
                    .and_then(|d| d.get("id"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let parent = entry.get("link").and_then(|v| v.as_str()).map(|s| s.to_string());
                return (true, vlan_id, parent);
            }
        }
    }

    // Fallback: check if name contains a dot (e.g. eth0.100)
    if let Some(dot_pos) = name.rfind('.') {
        if let Ok(vid) = name[dot_pos + 1..].parse::<u32>() {
            let parent = name[..dot_pos].to_string();
            return (true, Some(vid), Some(parent));
        }
    }

    (false, None, None)
}

/// Get link speed for an interface
fn get_link_speed(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/speed", name);
    std::fs::read_to_string(&path).ok()
        .and_then(|s| {
            let speed = s.trim().parse::<i64>().ok()?;
            if speed <= 0 { return None; }
            if speed >= 1000 {
                Some(format!("{}Gb/s", speed / 1000))
            } else {
                Some(format!("{}Mb/s", speed))
            }
        })
}

/// Get driver for an interface
fn get_driver(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/device/driver", name);
    std::fs::read_link(&path).ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
}

/// Get WolfNet status
pub fn get_wolfnet_status() -> WolfNetStatus {
    // Check if wolfnet service exists
    let installed = Command::new("systemctl")
        .args(["cat", "wolfnet"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !installed {
        return WolfNetStatus {
            installed: false,
            running: false,
            interface: None,
            ip: None,
            peers: Vec::new(),
        };
    }

    let running = Command::new("systemctl")
        .args(["is-active", "wolfnet"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    // Try to get WolfNet IP from the tun interface
    let mut wn_interface = None;
    let mut wn_ip = None;
    let interfaces = list_interfaces();
    for iface in &interfaces {
        if iface.name.starts_with("wn") || iface.name.starts_with("wolfnet") {
            wn_interface = Some(iface.name.clone());
            if let Some(addr) = iface.addresses.iter().find(|a| a.family == "inet") {
                wn_ip = Some(format!("{}/{}", addr.address, addr.prefix));
            }
            break;
        }
    }

    // Try to parse peers from wolfnet config
    let peers = get_wolfnet_peers();

    WolfNetStatus {
        installed,
        running,
        interface: wn_interface,
        ip: wn_ip,
        peers,
    }
}

/// Read WolfNet peers from config.toml
fn get_wolfnet_peers() -> Vec<WolfNetPeer> {
    let config_path = "/etc/wolfnet/config.toml";
    let mut peers = Vec::new();

    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return peers,
    };

    // Simple TOML parsing for [[peers]] sections
    let mut current_name = String::new();
    let mut current_endpoint = String::new();
    let mut current_ip = String::new();
    let mut in_peer = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[peers]]" {
            if in_peer && !current_name.is_empty() {
                peers.push(WolfNetPeer {
                    name: current_name.clone(),
                    endpoint: current_endpoint.clone(),
                    ip: current_ip.clone(),
                    connected: false,
                });
            }
            in_peer = true;
            current_name.clear();
            current_endpoint.clear();
            current_ip.clear();
        } else if in_peer {
            if let Some(val) = line.strip_prefix("name") {
                let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                current_name = val.to_string();
            } else if let Some(val) = line.strip_prefix("endpoint") {
                let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                current_endpoint = val.to_string();
            } else if let Some(val) = line.strip_prefix("ip") {
                let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                current_ip = val.to_string();
            }
        }
    }
    // Push last peer
    if in_peer && !current_name.is_empty() {
        peers.push(WolfNetPeer {
            name: current_name,
            endpoint: current_endpoint,
            ip: current_ip,
            connected: false,
        });
    }

    // Check connectivity via ping (non-blocking, fast)
    for peer in &mut peers {
        if !peer.ip.is_empty() {
            let ip = peer.ip.split('/').next().unwrap_or(&peer.ip);
            peer.connected = Command::new("ping")
                .args(["-c", "1", "-W", "1", ip])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        }
    }

    peers
}

/// Read the raw WolfNet config file
pub fn get_wolfnet_config() -> Result<String, String> {
    std::fs::read_to_string("/etc/wolfnet/config.toml")
        .map_err(|e| format!("Failed to read WolfNet config: {}", e))
}

/// Get local WolfNet node info (public key, address, port) from runtime status
pub fn get_wolfnet_local_info() -> Option<serde_json::Value> {
    let status_path = "/var/run/wolfnet/status.json";
    let content = std::fs::read_to_string(status_path).ok()?;
    let status: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(serde_json::json!({
        "hostname": status["hostname"],
        "address": status["address"],
        "public_key": status["public_key"],
        "listen_port": status["listen_port"],
        "interface": status["interface"],
    }))
}

/// Save the raw WolfNet config file
pub fn save_wolfnet_config(content: &str) -> Result<String, String> {
    std::fs::write("/etc/wolfnet/config.toml", content)
        .map_err(|e| format!("Failed to write WolfNet config: {}", e))?;
    info!("WolfNet config saved");
    Ok("Configuration saved".to_string())
}

/// Add a peer to WolfNet config
pub fn add_wolfnet_peer(name: &str, endpoint: &str, ip: &str, public_key: Option<&str>) -> Result<String, String> {
    let config_path = "/etc/wolfnet/config.toml";
    let mut content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;

    // Check for duplicate
    if content.contains(&format!("name = \"{}\"", name)) {
        return Err(format!("Peer '{}' already exists", name));
    }

    // Append peer section
    content.push_str(&format!("\n\n[[peers]]\nname = \"{}\"\n", name));
    if !endpoint.is_empty() {
        content.push_str(&format!("endpoint = \"{}\"\n", endpoint));
    }
    if !ip.is_empty() {
        content.push_str(&format!("ip = \"{}\"\n", ip));
    }
    if let Some(pk) = public_key {
        if !pk.is_empty() {
            content.push_str(&format!("public_key = \"{}\"\n", pk));
        }
    }

    std::fs::write(config_path, &content)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    info!("Added WolfNet peer: {} ({})", name, ip);

    // Restart WolfNet to apply
    let _ = Command::new("systemctl").args(["restart", "wolfnet"]).output();

    Ok(format!("Peer '{}' added and WolfNet restarted", name))
}

/// Remove a peer from WolfNet config by name
pub fn remove_wolfnet_peer(name: &str) -> Result<String, String> {
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;

    let mut result_lines: Vec<String> = Vec::new();
    let mut in_target_peer = false;
    let mut found = false;
    let mut i = 0;
    let lines: Vec<&str> = content.lines().collect();

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "[[peers]]" {
            // Check if the next few lines contain our target peer name
            let mut is_target = false;
            for j in (i + 1)..std::cmp::min(i + 10, lines.len()) {
                let check = lines[j].trim();
                if check.starts_with('[') && check != "[[peers]]" { break; }
                if check == "[[peers]]" { break; }
                if check.starts_with("name") {
                    let val = check.split('=').nth(1).unwrap_or("").trim().trim_matches('"');
                    if val == name {
                        is_target = true;
                        found = true;
                    }
                    break;
                }
            }
            if is_target {
                in_target_peer = true;
                // Skip blank lines before this [[peers]] block
                while result_lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
                    result_lines.pop();
                }
                i += 1;
                continue;
            }
        }

        if in_target_peer {
            if trimmed.starts_with('[') || (trimmed.is_empty() && i + 1 < lines.len() && lines[i + 1].trim().starts_with('[')) {
                in_target_peer = false;
                if !trimmed.is_empty() {
                    result_lines.push(lines[i].to_string());
                }
            }
            i += 1;
            continue;
        }

        result_lines.push(lines[i].to_string());
        i += 1;
    }

    if !found {
        return Err(format!("Peer '{}' not found in config", name));
    }

    let new_content = result_lines.join("\n");
    std::fs::write(config_path, &new_content)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    info!("Removed WolfNet peer: {}", name);

    // Restart WolfNet to apply
    let _ = Command::new("systemctl").args(["restart", "wolfnet"]).output();

    Ok(format!("Peer '{}' removed and WolfNet restarted", name))
}

/// Restart or start WolfNet service
pub fn wolfnet_service_action(action: &str) -> Result<String, String> {
    let output = Command::new("systemctl")
        .args([action, "wolfnet"])
        .output()
        .map_err(|e| format!("Failed to {} wolfnet: {}", action, e))?;

    if output.status.success() {
        info!("WolfNet {}: success", action);
        Ok(format!("WolfNet {}", action))
    } else {
        Err(format!("Failed to {} WolfNet: {}", action,
            String::from_utf8_lossy(&output.stderr)))
    }
}

/// Generate an invite token for a new peer to join this WolfNet network.
/// Replicates `wolfnet invite` CLI command logic.
pub fn generate_wolfnet_invite() -> Result<serde_json::Value, String> {
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read WolfNet config: {}", e))?;
    
    // Parse config to get network settings
    let get_val = |key: &str| -> String {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(key) {
                if let Some(eq_pos) = trimmed.find('=') {
                    return trimmed[eq_pos+1..].trim().trim_matches('"').trim_matches('\'').to_string();
                }
            }
        }
        String::new()
    };
    
    let address = get_val("address");
    let subnet: u8 = get_val("subnet").parse().unwrap_or(24);
    let listen_port: u16 = get_val("listen_port").parse().unwrap_or(9600);
    
    if address.is_empty() {
        return Err("WolfNet address not configured".to_string());
    }
    
    
    // Read the public key via wolfnet CLI
    let pubkey_output = Command::new("wolfnet")
        .args(["--config", config_path, "pubkey"])
        .output()
        .map_err(|e| format!("Failed to get WolfNet public key: {}", e))?;
    
    if !pubkey_output.status.success() {
        return Err("Failed to read WolfNet public key — is wolfnet installed?".to_string());
    }
    let public_key = String::from_utf8_lossy(&pubkey_output.stdout).trim().to_string();
    
    // Auto-detect public IP 
    let public_ip = detect_public_ip();
    let endpoint = match &public_ip {
        Some(ip) => format!("{}:{}", ip, listen_port),
        None => format!("{}:{}", address, listen_port),
    };
    
    // Build invite token as JSON → base64
    let invite = serde_json::json!({
        "pk": public_key,
        "ep": endpoint,
        "ip": address,
        "sn": subnet,
        "pt": listen_port,
    });
    
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(invite.to_string().as_bytes());
    
    Ok(serde_json::json!({
        "token": token,
        "public_key": public_key,
        "endpoint": endpoint,
        "address": address,
        "subnet": subnet,
        "listen_port": listen_port,
        "public_ip": public_ip,
        "join_command": format!("sudo wolfnet --config /etc/wolfnet/config.toml join {}", token),
    }))
}

/// Detect public IP address (used for invite tokens)
fn detect_public_ip() -> Option<String> {
    // Try curl to ipify  
    let output = Command::new("curl")
        .args(["-s", "--connect-timeout", "5", "https://api.ipify.org"])
        .output()
        .ok()?;
    
    if output.status.success() {
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some(ip);
        }
    }
    None
}

/// Get full WolfNet status including live peer data from status.json
pub fn get_wolfnet_status_full() -> serde_json::Value {
    let status = get_wolfnet_status();
    
    // Also read live peer data from status.json (richer info than config)
    let live_peers = match std::fs::read_to_string("/var/run/wolfnet/status.json") {
        Ok(content) => {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(v) => v.get("peers").cloned().unwrap_or(serde_json::json!([])),
                Err(_) => serde_json::json!([]),
            }
        }
        Err(_) => serde_json::json!([]),
    };
    
    serde_json::json!({
        "installed": status.installed,
        "running": status.running,
        "interface": status.interface,
        "ip": status.ip,
        "peers": status.peers,
        "live_peers": live_peers,
    })
}

/// Add an IP address to an interface
pub fn add_ip(interface: &str, address: &str, prefix: u32) -> Result<String, String> {
    let cidr = format!("{}/{}", address, prefix);
    let output = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", interface])
        .output()
        .map_err(|e| format!("Failed to run ip addr add: {}", e))?;

    if output.status.success() {
        info!("Added {} to {}", cidr, interface);
        Ok(format!("Added {} to {}", cidr, interface))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Remove an IP address from an interface
pub fn remove_ip(interface: &str, address: &str, prefix: u32) -> Result<String, String> {
    let cidr = format!("{}/{}", address, prefix);
    let output = Command::new("ip")
        .args(["addr", "del", &cidr, "dev", interface])
        .output()
        .map_err(|e| format!("Failed to run ip addr del: {}", e))?;

    if output.status.success() {
        info!("Removed {} from {}", cidr, interface);
        Ok(format!("Removed {} from {}", cidr, interface))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Set interface up or down
pub fn set_interface_state(interface: &str, up: bool) -> Result<String, String> {
    let state = if up { "up" } else { "down" };
    let output = Command::new("ip")
        .args(["link", "set", interface, state])
        .output()
        .map_err(|e| format!("Failed to set interface state: {}", e))?;

    if output.status.success() {
        info!("Set {} {}", interface, state);
        Ok(format!("Interface {} set {}", interface, state))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Create a VLAN interface
pub fn create_vlan(parent: &str, vlan_id: u32, name: Option<&str>) -> Result<String, String> {
    let vlan_name = name.map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}.{}", parent, vlan_id));

    let output = Command::new("ip")
        .args(["link", "add", "link", parent, "name", &vlan_name, "type", "vlan", "id", &vlan_id.to_string()])
        .output()
        .map_err(|e| format!("Failed to create VLAN: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    // Bring up the VLAN interface
    let _ = Command::new("ip")
        .args(["link", "set", &vlan_name, "up"])
        .output();

    info!("Created VLAN {} on {} (ID {})", vlan_name, parent, vlan_id);
    Ok(format!("Created VLAN {} (ID {}) on {}", vlan_name, vlan_id, parent))
}

/// Delete a VLAN interface
pub fn delete_vlan(name: &str) -> Result<String, String> {
    let output = Command::new("ip")
        .args(["link", "delete", name])
        .output()
        .map_err(|e| format!("Failed to delete VLAN: {}", e))?;

    if output.status.success() {
        info!("Deleted VLAN {}", name);
        Ok(format!("Deleted VLAN {}", name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Set interface MTU
pub fn set_mtu(interface: &str, mtu: u32) -> Result<String, String> {
    let output = Command::new("ip")
        .args(["link", "set", interface, "mtu", &mtu.to_string()])
        .output()
        .map_err(|e| format!("Failed to set MTU: {}", e))?;

    if output.status.success() {
        info!("Set {} MTU to {}", interface, mtu);
        Ok(format!("MTU set to {} on {}", mtu, interface))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

