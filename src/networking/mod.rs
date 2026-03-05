// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Networking — System network interface and VLAN management
//!
//! Provides read/write access to:
//! - Network interfaces (ip link/addr)
//! - VLANs (802.1Q)
//! - DNS configuration
//! - WolfNet overlay status
//! - WireGuard bridge (VPN access to WolfNet from external clients)

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::warn;

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
pub fn get_wolfnet_peers_list() -> Vec<WolfNetPeer> {
    get_wolfnet_peers()
}

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
            } else if let Some(val) = line.strip_prefix("allowed_ip").or_else(|| line.strip_prefix("ip")) {
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

    Ok("Configuration saved".to_string())
}

/// Add or update a peer in WolfNet config (upsert).
/// If a peer with the same name, public key, or allowed IP already exists,
/// its name and endpoint are updated. Otherwise a new peer is appended.
pub fn add_wolfnet_peer(name: &str, endpoint: &str, ip: &str, public_key: Option<&str>) -> Result<String, String> {
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;

    // Fix any `ip = ` entries to `allowed_ip = ` before parsing
    let fixed: String = content.lines().map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with("ip = ") && !trimmed.starts_with("ip_") {
            line.replace("ip = ", "allowed_ip = ")
        } else {
            line.to_string()
        }
    }).collect::<Vec<_>>().join("\n");

    let mut doc: toml::Value = toml::from_str(&fixed)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    let peers = doc.get_mut("peers")
        .and_then(|v| v.as_array_mut());

    // Find existing peer by name, public key, or IP
    let existing_idx = peers.as_ref().and_then(|arr| {
        arr.iter().position(|p| {
            // Match by name
            if let Some(pname) = p.get("name").and_then(|v| v.as_str()) {
                if pname == name { return true; }
            }
            // Match by public key
            if let Some(pk) = public_key {
                if !pk.is_empty() {
                    if let Some(ppk) = p.get("public_key").and_then(|v| v.as_str()) {
                        if ppk == pk { return true; }
                    }
                }
            }
            // Match by IP
            if !ip.is_empty() {
                if let Some(pip) = p.get("allowed_ip").and_then(|v| v.as_str()) {
                    if pip == ip { return true; }
                }
            }
            false
        })
    });

    let result_msg;

    if let Some(idx) = existing_idx {
        let peers_arr = doc.get_mut("peers").unwrap().as_array_mut().unwrap();
        let peer = &mut peers_arr[idx];
        let _old_name = peer.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let _old_endpoint = peer.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let mut changed = false;
        if peer.get("name").and_then(|v| v.as_str()) != Some(name) {
            peer.as_table_mut().unwrap().insert("name".to_string(), toml::Value::String(name.to_string()));
            changed = true;
        }
        if !endpoint.is_empty() && peer.get("endpoint").and_then(|v| v.as_str()) != Some(endpoint) {
            peer.as_table_mut().unwrap().insert("endpoint".to_string(), toml::Value::String(endpoint.to_string()));
            changed = true;
        }

        if !changed {
            return Err(format!("Peer '{}' already exists (no changes needed)", name));
        }


        result_msg = format!("Peer '{}' updated and WolfNet restarted", name);
    } else {
        // Add new peer
        let mut new_peer = toml::map::Map::new();
        new_peer.insert("name".to_string(), toml::Value::String(name.to_string()));
        if let Some(pk) = public_key {
            if !pk.is_empty() {
                new_peer.insert("public_key".to_string(), toml::Value::String(pk.to_string()));
            }
        }
        if !endpoint.is_empty() {
            new_peer.insert("endpoint".to_string(), toml::Value::String(endpoint.to_string()));
        }
        if !ip.is_empty() {
            new_peer.insert("allowed_ip".to_string(), toml::Value::String(ip.to_string()));
        }

        if let Some(arr) = doc.get_mut("peers").and_then(|v| v.as_array_mut()) {
            arr.push(toml::Value::Table(new_peer));
        } else {
            doc.as_table_mut().unwrap().insert(
                "peers".to_string(),
                toml::Value::Array(vec![toml::Value::Table(new_peer)]),
            );
        }


        result_msg = format!("Peer '{}' added and WolfNet restarted", name);
    }

    // Write back
    let output = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(config_path, &output)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Apply config: try SIGHUP hot-reload, fall back to restart for older wolfnet
    reload_or_restart_wolfnet();

    Ok(result_msg)
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



    // Apply config: try SIGHUP hot-reload, fall back to restart for older wolfnet
    reload_or_restart_wolfnet();

    Ok(format!("Peer '{}' removed and WolfNet reloaded", name))
}

/// Try SIGHUP hot-reload first; if wolfnet dies (old version without handler),
/// fall back to systemctl restart.
fn reload_or_restart_wolfnet() {
    // Check if wolfnet is currently running
    let was_running = Command::new("pgrep").arg("wolfnet")
        .output().map(|o| o.status.success()).unwrap_or(false);

    if !was_running {
        // Not running at all — just start it

        let _ = Command::new("systemctl").args(["start", "wolfnet"]).output();
        return;
    }

    // Send SIGHUP for hot-reload
    let _ = Command::new("pkill").args(["-HUP", "wolfnet"]).output();

    // Brief pause to let signal be processed
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if it survived (old versions without SIGHUP handler will die)
    let still_running = Command::new("pgrep").arg("wolfnet")
        .output().map(|o| o.status.success()).unwrap_or(false);

    if !still_running {
        warn!("WolfNet died after SIGHUP (old version?) — restarting via systemctl");
        let _ = Command::new("systemctl").args(["restart", "wolfnet"]).output();
    } else {

    }
}

/// Restart or start WolfNet service
pub fn wolfnet_service_action(action: &str) -> Result<String, String> {
    let output = Command::new("systemctl")
        .args([action, "wolfnet"])
        .output()
        .map_err(|e| format!("Failed to {} wolfnet: {}", action, e))?;

    if output.status.success() {

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


    Ok(format!("Created VLAN {} (ID {}) on {}", vlan_name, vlan_id, parent))
}

/// Delete a VLAN interface
pub fn delete_vlan(name: &str) -> Result<String, String> {
    let output = Command::new("ip")
        .args(["link", "delete", name])
        .output()
        .map_err(|e| format!("Failed to delete VLAN: {}", e))?;

    if output.status.success() {

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

        Ok(format!("MTU set to {} on {}", mtu, interface))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ─── Public IP → WolfNet IP Mapping ───

const IP_MAPPINGS_PATH: &str = "/etc/wolfstack/ip-mappings.json";

/// A mapping from a public IP to a WolfNet IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpMapping {
    pub id: String,
    pub public_ip: String,
    pub wolfnet_ip: String,
    pub ports: Option<String>,      // None = all ports, Some("80,443") = specific source ports
    pub dest_ports: Option<String>, // None = same as source, Some("80") = different dest port
    pub protocol: String,           // "all", "tcp", "udp"
    pub label: String,
    pub enabled: bool,
}

/// Persistent config for IP mappings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IpMappingConfig {
    mappings: Vec<IpMapping>,
}

fn load_ip_mapping_config() -> IpMappingConfig {
    match std::fs::read_to_string(IP_MAPPINGS_PATH) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => IpMappingConfig::default(),
    }
}

fn save_ip_mapping_config(config: &IpMappingConfig) -> Result<(), String> {
    let dir = std::path::Path::new(IP_MAPPINGS_PATH).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(IP_MAPPINGS_PATH, json)
        .map_err(|e| format!("Failed to write {}: {}", IP_MAPPINGS_PATH, e))
}

/// List all IP mappings
pub fn list_ip_mappings() -> Vec<IpMapping> {
    load_ip_mapping_config().mappings
}

/// Ports that must NEVER be mapped — doing so can lock users out of critical services.
const BLOCKED_PORTS: &[(u16, &str)] = &[
    (22,   "SSH"),
    (111,  "NFS portmapper"),
    (2049, "NFS"),
    (3128, "Proxmox CONNECT proxy"),
    (5900, "Proxmox VNC console"),
    (5901, "Proxmox VNC console"),
    (5902, "Proxmox VNC console"),
    (5903, "Proxmox VNC console"),
    (5999, "Proxmox SPICE console"),
    (8006, "Proxmox Web UI"),
    (8007, "Proxmox Spiceproxy"),
    (8443, "Proxmox API"),
    (8552, "WolfStack API"),
    (8553, "WolfStack cluster"),
    (9600, "WolfNet"),
];

/// Parse a port specification string into individual port numbers.
/// Accepts: "80", "80,443", "8000:8100", "80,443,8000:8100"
fn parse_port_list(ports_str: &str) -> Result<Vec<u16>, String> {
    let mut result = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if part.contains(':') {
            // Range like 8000:8100
            let bounds: Vec<&str> = part.split(':').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range: '{}'", part));
            }
            let lo: u16 = bounds[0].trim().parse()
                .map_err(|_| format!("Invalid port number: '{}'", bounds[0].trim()))?;
            let hi: u16 = bounds[1].trim().parse()
                .map_err(|_| format!("Invalid port number: '{}'", bounds[1].trim()))?;
            if lo > hi {
                return Err(format!("Invalid port range: {} > {}", lo, hi));
            }
            if hi - lo > 1000 {
                return Err(format!("Port range {}:{} is too large (max 1000 ports)", lo, hi));
            }
            for p in lo..=hi { result.push(p); }
        } else {
            let p: u16 = part.parse()
                .map_err(|_| format!("Invalid port number: '{}'", part))?;
            result.push(p);
        }
    }
    Ok(result)
}

/// Add a new IP mapping and apply iptables rules
pub fn add_ip_mapping(
    public_ip: &str,
    wolfnet_ip: &str,
    ports: Option<&str>,
    dest_ports: Option<&str>,
    protocol: &str,
    label: &str,
) -> Result<IpMapping, String> {
    // Validate IPs
    if public_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("Invalid public IP: {}", public_ip));
    }
    if wolfnet_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("Invalid WolfNet IP: {}", wolfnet_ip));
    }

    // Self-mapping guard: don't route traffic to yourself
    if let Some(gw) = detect_wolfnet_gateway_ip() {
        if wolfnet_ip == gw {
            return Err("Cannot map to this server's own WolfNet IP — this would create a routing loop".to_string());
        }
    }

    // Protocol validation
    if !["all", "tcp", "udp"].contains(&protocol) {
        return Err(format!("Invalid protocol '{}' — must be 'all', 'tcp', or 'udp'", protocol));
    }

    // Port validation & blocked port check
    if let Some(port_str) = ports {
        let trimmed = port_str.trim();
        if !trimmed.is_empty() {
            // Protocol must be tcp or udp when specific ports are used (iptables requirement)
            if protocol == "all" {
                return Err("When specifying ports, you must select TCP or UDP (not 'All'). \
                    iptables --dport requires a specific protocol.".to_string());
            }

            let port_list = parse_port_list(trimmed)?;

            // Check against blocked ports (hardcoded safety list)
            for &port in &port_list {
                for &(blocked, service) in BLOCKED_PORTS {
                    if port == blocked {
                        return Err(format!(
                            "Port {} is used by {} and cannot be mapped. \
                             Redirecting this port would break critical system access.",
                            port, service
                        ));
                    }
                }
            }

            // Live scan: warn (but don't block) if ports are in use on this server
            // DNAT rules are IP-specific so they won't necessarily conflict
            let listening = get_listening_ports();
            for &port in &port_list {
                if let Some(entry) = listening.iter().find(|e| e["port"].as_u64() == Some(port as u64)) {
                    let proc_name = entry["process"].as_str().unwrap_or("unknown");
                    if BLOCKED_PORTS.iter().any(|&(bp, _)| bp == port) { continue; }
                    warn!("Source port {} is in use by '{}' — mapping will use DNAT on public IP only", port, proc_name);
                }
            }
        }
    }

    // Validate dest_ports if provided
    let dest_ports_clean: Option<&str> = match dest_ports {
        Some(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    };
    if let Some(dp_str) = dest_ports_clean {
        if ports.map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err("Destination ports require source ports to be specified too.".to_string());
        }
        if protocol == "all" {
            return Err("When specifying ports, you must select TCP or UDP (not 'All').".to_string());
        }
        let dp_list = parse_port_list(dp_str)?;
        let sp_list = parse_port_list(ports.unwrap())?;
        if dp_list.len() != sp_list.len() {
            return Err(format!(
                "Source ports ({}) and destination ports ({}) must have the same count.",
                sp_list.len(), dp_list.len()
            ));
        }
    }

    let mut config = load_ip_mapping_config();

    // Check for duplicate
    if config.mappings.iter().any(|m| m.public_ip == public_ip && m.wolfnet_ip == wolfnet_ip
        && m.ports == ports.map(|s| s.to_string()) && m.protocol == protocol)
    {
        return Err(format!("{} → {} already mapped with these ports/protocol", public_ip, wolfnet_ip));
    }

    let mapping = IpMapping {
        id: format!("{:x}", rand_id()),
        public_ip: public_ip.to_string(),
        wolfnet_ip: wolfnet_ip.to_string(),
        ports: ports.map(|s| s.to_string()),
        dest_ports: dest_ports_clean.map(|s| s.to_string()),
        protocol: protocol.to_string(),
        label: label.to_string(),
        enabled: true,
    };

    // Apply iptables rules
    apply_mapping_rules(&mapping)?;

    config.mappings.push(mapping.clone());
    save_ip_mapping_config(&config)?;


    Ok(mapping)
}

/// Get list of TCP/UDP ports currently listening on this server (for conflict detection)
pub fn get_listening_ports() -> Vec<serde_json::Value> {
    let output = Command::new("ss")
        .args(["-tlnp"])  // TCP listening, numeric, show processes
        .output();

    let mut ports = Vec::new();

    if let Ok(o) = output {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                // Format: State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 5 {
                    let local = cols[3];
                    // Extract port from the last colon-separated part
                    if let Some(port_str) = local.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let process = if cols.len() >= 6 { cols[5..].join(" ") } else { String::new() };
                            // Extract process name from users:(("name",pid=N,fd=N))
                            let proc_name = process.split('"').nth(1).unwrap_or("").to_string();
                            ports.push(serde_json::json!({
                                "port": port,
                                "protocol": "tcp",
                                "process": proc_name,
                            }));
                        }
                    }
                }
            }
        }
    }

    // Also get UDP
    let output = Command::new("ss")
        .args(["-ulnp"])
        .output();

    if let Ok(o) = output {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 5 {
                    let local = cols[4];
                    if let Some(port_str) = local.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let process = if cols.len() >= 6 { cols[5..].join(" ") } else { String::new() };
                            let proc_name = process.split('"').nth(1).unwrap_or("").to_string();
                            ports.push(serde_json::json!({
                                "port": port,
                                "protocol": "udp",
                                "process": proc_name,
                            }));
                        }
                    }
                }
            }
        }
    }

    // De-duplicate by port+protocol
    ports.sort_by_key(|p| (p["port"].as_u64().unwrap_or(0), p["protocol"].as_str().unwrap_or("").to_string()));
    ports.dedup_by(|a, b| a["port"] == b["port"] && a["protocol"] == b["protocol"]);
    ports
}

/// Get the list of blocked ports (for frontend display)
pub fn get_blocked_ports() -> Vec<serde_json::Value> {
    BLOCKED_PORTS.iter().map(|&(port, service)| {
        serde_json::json!({ "port": port, "service": service })
    }).collect()
}

/// Remove an IP mapping by ID and clean up iptables rules
pub fn remove_ip_mapping(id: &str) -> Result<String, String> {
    let mut config = load_ip_mapping_config();
    let idx = config.mappings.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mapping '{}' not found", id))?;

    let mapping = config.mappings.remove(idx);
    remove_mapping_rules(&mapping);
    save_ip_mapping_config(&config)?;


    Ok(format!("Removed mapping {} → {}", mapping.public_ip, mapping.wolfnet_ip))
}

/// Update an existing IP mapping by ID
pub fn update_ip_mapping(
    id: &str,
    public_ip: &str,
    wolfnet_ip: &str,
    ports: Option<&str>,
    dest_ports: Option<&str>,
    protocol: &str,
    label: &str,
) -> Result<IpMapping, String> {
    let mut config = load_ip_mapping_config();
    let idx = config.mappings.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mapping '{}' not found", id))?;

    // Remove old iptables rules
    remove_mapping_rules(&config.mappings[idx]);

    // Validate protocol
    let protocol = if protocol.is_empty() { "all" } else { protocol };
    if !["all", "tcp", "udp"].contains(&protocol) {
        return Err(format!("Invalid protocol '{}'. Must be 'all', 'tcp', or 'udp'.", protocol));
    }

    // Validate ports
    if let Some(port_str) = ports {
        if !port_str.trim().is_empty() {
            if protocol == "all" {
                return Err("When specifying ports, you must select TCP or UDP (not 'All').".to_string());
            }
            parse_port_list(port_str)?;
        }
    }

    // Validate dest_ports
    let dest_ports_clean: Option<&str> = match dest_ports {
        Some(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    };
    if let Some(dp_str) = dest_ports_clean {
        if ports.map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err("Destination ports require source ports to be specified too.".to_string());
        }
        let dp_list = parse_port_list(dp_str)?;
        let sp_list = parse_port_list(ports.unwrap())?;
        if dp_list.len() != sp_list.len() {
            return Err(format!(
                "Source ports ({}) and destination ports ({}) must have the same count.",
                sp_list.len(), dp_list.len()
            ));
        }
    }

    // Update the mapping in-place
    let mapping = &mut config.mappings[idx];
    mapping.public_ip = public_ip.to_string();
    mapping.wolfnet_ip = wolfnet_ip.to_string();
    mapping.ports = ports.map(|s| s.to_string());
    mapping.dest_ports = dest_ports_clean.map(|s| s.to_string());
    mapping.protocol = protocol.to_string();
    mapping.label = label.to_string();

    // Apply new rules
    apply_mapping_rules(mapping)?;

    let result = mapping.clone();
    save_ip_mapping_config(&config)?;


    Ok(result)
}

/// Build iptables port-match arguments.
/// For a single port or range: `--dport <port>`
/// For multiple comma-separated ports: `-m multiport --dports <ports>`
fn build_port_args(ports: &str) -> Vec<String> {
    if ports.contains(',') {
        // Multiple ports — must use the multiport extension
        vec!["-m".into(), "multiport".into(), "--dports".into(), ports.to_string()]
    } else {
        // Single port or range — plain --dport works
        vec!["--dport".into(), ports.to_string()]
    }
}

/// Apply iptables rules for a single mapping
fn apply_mapping_rules(m: &IpMapping) -> Result<(), String> {
    if !m.enabled { return Ok(()); }

    // Detect gateway WolfNet IP for SNAT
    let gateway_ip = detect_wolfnet_gateway_ip()
        .ok_or_else(|| "Cannot detect WolfNet gateway IP — is WolfNet running?".to_string())?;

    // Build port/protocol args
    let proto_args: Vec<String> = if m.protocol != "all" {
        vec!["-p".into(), m.protocol.clone()]
    } else {
        vec![]
    };

    // Source port args (for matching incoming traffic in PREROUTING)
    let src_port_args: Vec<String> = if let Some(ref ports) = m.ports {
        if !ports.is_empty() && m.protocol != "all" {
            build_port_args(ports)
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Check if target is a WolfRun VIP with backends
    if let Some((backends, lb_policy)) = resolve_wolfrun_vip(&m.wolfnet_ip) {
        if !backends.is_empty() {
            return apply_vip_mapping_rules(m, &backends, &lb_policy, &gateway_ip, &proto_args, &src_port_args);
        }
    }

    // Standard mapping (non-VIP target)

    // Determine if port translation is needed (dest_ports differs from source ports)
    let has_port_translation = m.dest_ports.as_ref()
        .map(|dp| !dp.is_empty() && m.ports.as_ref().map(|sp| sp != dp).unwrap_or(true))
        .unwrap_or(false);

    // When port translation involves multiple ports, we must emit separate rules
    // per port pair because --to-destination only accepts a single port.
    // When ports aren't being translated, omit port from DNAT target (iptables preserves it).
    if has_port_translation && m.dest_ports.as_ref().map(|dp| dp.contains(',')).unwrap_or(false) {
        // Multi-port translation: one rule per source→dest port pair
        let sp_list = parse_port_list(m.ports.as_deref().unwrap_or(""))?;
        let dp_list = parse_port_list(m.dest_ports.as_deref().unwrap_or(""))?;

        for (sp, dp) in sp_list.iter().zip(dp_list.iter()) {
            let sp_str = sp.to_string();
            let dp_str = dp.to_string();
            let per_src = vec!["--dport".into(), sp_str];
            let per_dest = vec!["--dport".into(), dp_str.clone()];
            let dnat_target = format!("{}:{}", m.wolfnet_ip, dp);

            // DNAT PREROUTING
            run_iptables(&[
                "-t", "nat", "-A", "PREROUTING", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target])?;

            // DNAT OUTPUT
            run_iptables(&[
                "-t", "nat", "-A", "OUTPUT", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target])?;

            // SNAT
            run_iptables(&[
                "-t", "nat", "-A", "POSTROUTING", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-j", "SNAT", "--to-source", &gateway_ip])?;

            // FORWARD
            run_iptables(&[
                "-I", "FORWARD", "1", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"])?;
        }
    } else {
        // Single rule path: either no port translation, single port, or no ports at all
        let dnat_dest = if has_port_translation {
            // Single dest port translation
            format!("{}:{}", m.wolfnet_ip, m.dest_ports.as_ref().unwrap())
        } else {
            // No translation — iptables preserves original port
            m.wolfnet_ip.clone()
        };

        // Dest port args (for matching translated traffic in POSTROUTING/FORWARD)
        let dest_port_args: Vec<String> = {
            let effective_ports = m.dest_ports.as_ref().or(m.ports.as_ref());
            if let Some(ports) = effective_ports {
                if !ports.is_empty() && m.protocol != "all" {
                    build_port_args(ports)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };

        // DNAT: redirect incoming traffic to WolfNet IP (with optional port translation)
        run_iptables(&[
            "-t", "nat", "-A", "PREROUTING", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest])?;

        // OUTPUT DNAT: also redirect traffic originating FROM this server (e.g. wget from localhost)
        run_iptables(&[
            "-t", "nat", "-A", "OUTPUT", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest])?;

        // SNAT: ensure return traffic goes back through this gateway
        run_iptables(&[
            "-t", "nat", "-A", "POSTROUTING", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-j", "SNAT", "--to-source", &gateway_ip])?;

        // FORWARD: allow DNAT'd traffic (must be at top before Docker chains DROP it)
        run_iptables(&[
            "-I", "FORWARD", "1", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"])?;
    }

    Ok(())
}

/// Resolve a WolfRun VIP to its backend IPs and LB policy.
/// Returns None if the IP is not a WolfRun service VIP.
fn resolve_wolfrun_vip(ip: &str) -> Option<(Vec<String>, String)> {
    let data = std::fs::read_to_string("/etc/wolfstack/wolfrun/services.json").ok()?;
    let services: Vec<serde_json::Value> = serde_json::from_str(&data).ok()?;
    for svc in &services {
        if svc.get("service_ip").and_then(|v| v.as_str()) == Some(ip) {
            let lb_policy = svc.get("lb_policy").and_then(|v| v.as_str())
                .unwrap_or("round_robin").to_string();
            let backends: Vec<String> = svc.get("instances")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|i| i.get("status").and_then(|s| s.as_str()) == Some("running"))
                        .filter_map(|i| i.get("wolfnet_ip").and_then(|v| v.as_str()).map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            return Some((backends, lb_policy));
        }
    }
    None
}

/// Apply mapping rules for a WolfRun VIP — DNAT directly to backends
/// with round-robin or ip_hash distribution (same as WolfRun's own LB logic).
/// This avoids DNAT'ing to the VIP which is a local route (kernel → INPUT → RST).
fn apply_vip_mapping_rules(
    m: &IpMapping,
    backends: &[String],
    lb_policy: &str,
    gateway_ip: &str,
    proto_args: &[String],
    src_port_args: &[String],
) -> Result<(), String> {
    let n = backends.len();
    let dest_port = m.dest_ports.as_ref().or(m.ports.as_ref())
        .map(|s| s.as_str()).unwrap_or("");

    let comment = format!("wolfstack-vip-map-{}", m.id);

    for chain in &["PREROUTING", "OUTPUT"] {
        for (i, backend) in backends.iter().enumerate() {
            let remaining = n - i;

            let mut args: Vec<String> = vec![
                "-t".into(), "nat".into(), "-A".into(), chain.to_string(),
                "-d".into(), m.public_ip.clone(),
            ];

            // Add protocol + port matching
            for a in proto_args { args.push(a.clone()); }
            for a in src_port_args { args.push(a.clone()); }

            // Distribution mode
            if remaining > 1 {
                if lb_policy == "ip_hash" {
                    let prob = 1.0 / remaining as f64;
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "random".into(),
                        "--probability".into(), format!("{:.6}", prob),
                    ]);
                } else {
                    // round_robin
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "nth".into(),
                        "--every".into(), remaining.to_string(),
                        "--packet".into(), "0".into(),
                    ]);
                }
            }

            // DNAT target — include dest port if specified
            let dnat_dest = if !dest_port.is_empty() {
                format!("{}:{}", backend, dest_port)
            } else {
                backend.clone()
            };

            args.extend_from_slice(&[
                "-j".into(), "DNAT".into(),
                "--to-destination".into(), dnat_dest,
                "-m".into(), "comment".into(),
                "--comment".into(), comment.clone(),
            ]);

            run_iptables_vec(&args)?;
        }
    }

    // SNAT + FORWARD for each backend
    for backend in backends {
        // SNAT
        let mut snat_args = vec![
            "-t".into(), "nat".into(), "-A".into(), "POSTROUTING".into(),
            "-d".into(), backend.clone(),
        ];
        for a in proto_args { snat_args.push(a.clone()); }
        snat_args.extend_from_slice(&[
            "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
            "-j".into(), "SNAT".into(), "--to-source".into(), gateway_ip.to_string(),
        ]);
        run_iptables_vec(&snat_args)?;

        // FORWARD (insert at top)
        let mut fwd_args = vec![
            "-I".into(), "FORWARD".into(), "1".into(),
            "-d".into(), backend.clone(),
        ];
        for a in proto_args { fwd_args.push(a.clone()); }
        fwd_args.extend_from_slice(&[
            "-m".into(), "conntrack".into(), "--ctstate".into(), "DNAT".into(),
            "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
            "-j".into(), "ACCEPT".into(),
        ]);
        run_iptables_vec(&fwd_args)?;
    }


    Ok(())
}

/// Run iptables with a Vec<String> of args
fn run_iptables_vec(args: &[String]) -> Result<(), String> {
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("iptables")
        .args(&str_args)
        .output()
        .map_err(|e| format!("Failed to run iptables: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("iptables {} failed: {}", str_args.join(" "), stderr));
    }
    Ok(())
}

/// Remove iptables rules for a mapping (best-effort, uses -D instead of -A)
fn remove_mapping_rules(m: &IpMapping) {
    let gateway_ip = detect_wolfnet_gateway_ip().unwrap_or_default();

    // Try VIP comment-based cleanup first (handles round-robin/ip_hash rules)
    let vip_comment = format!("wolfstack-vip-map-{}", m.id);
    let _removed_vip = remove_rules_by_comment(&vip_comment);

    // Also remove standard (non-VIP) rules
    let proto_args: Vec<String> = if m.protocol != "all" {
        vec!["-p".into(), m.protocol.clone()]
    } else {
        vec![]
    };

    let src_port_args: Vec<String> = if let Some(ref ports) = m.ports {
        if !ports.is_empty() && m.protocol != "all" {
            build_port_args(ports)
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Determine if port translation was used
    let has_port_translation = m.dest_ports.as_ref()
        .map(|dp| !dp.is_empty() && m.ports.as_ref().map(|sp| sp != dp).unwrap_or(true))
        .unwrap_or(false);

    // Best-effort removal — ignore errors
    if has_port_translation && m.dest_ports.as_ref().map(|dp| dp.contains(',')).unwrap_or(false) {
        // Multi-port translation: remove per-port rules
        let sp_list = parse_port_list(m.ports.as_deref().unwrap_or("")).unwrap_or_default();
        let dp_list = parse_port_list(m.dest_ports.as_deref().unwrap_or("")).unwrap_or_default();

        for (sp, dp) in sp_list.iter().zip(dp_list.iter()) {
            let sp_str = sp.to_string();
            let dp_str = dp.to_string();
            let per_src = vec!["--dport".into(), sp_str];
            let per_dest = vec!["--dport".into(), dp_str.clone()];
            let dnat_target = format!("{}:{}", m.wolfnet_ip, dp);

            let _ = run_iptables(&[
                "-t", "nat", "-D", "PREROUTING", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target]);
            let _ = run_iptables(&[
                "-t", "nat", "-D", "OUTPUT", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target]);
            let _ = run_iptables(&[
                "-t", "nat", "-D", "POSTROUTING", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-j", "SNAT", "--to-source", &gateway_ip]);
            let _ = run_iptables(&[
                "-D", "FORWARD", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"]);
        }
    } else {
        // Standard removal path
        let dnat_dest = if has_port_translation {
            format!("{}:{}", m.wolfnet_ip, m.dest_ports.as_ref().unwrap())
        } else {
            m.wolfnet_ip.clone()
        };

        let dest_port_args: Vec<String> = {
            let effective_ports = m.dest_ports.as_ref().or(m.ports.as_ref());
            if let Some(ports) = effective_ports {
                if !ports.is_empty() && m.protocol != "all" {
                    build_port_args(ports)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };

        let _ = run_iptables(&[
            "-t", "nat", "-D", "PREROUTING", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest]);

        let _ = run_iptables(&[
            "-t", "nat", "-D", "OUTPUT", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest]);

        let _ = run_iptables(&[
            "-t", "nat", "-D", "POSTROUTING", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-j", "SNAT", "--to-source", &gateway_ip]);

        let _ = run_iptables(&[
            "-D", "FORWARD", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"]);
    }

}

/// Remove all iptables rules matching a comment string (used for VIP cleanup)
fn remove_rules_by_comment(comment: &str) -> usize {
    let mut removed = 0;
    for (table, chains) in &[
        ("nat", vec!["PREROUTING", "OUTPUT", "POSTROUTING"]),
        ("filter", vec!["FORWARD"]),
    ] {
        for chain in chains {
            loop {
                let output = Command::new("iptables")
                    .args(["-t", table, "-L", chain, "--line-numbers", "-n"])
                    .output();
                let text = match output {
                    Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                    _ => break,
                };
                // Find first rule with our comment (search from bottom to avoid index shift)
                let mut found = None;
                for line in text.lines().rev() {
                    if line.contains(comment) {
                        if let Some(num) = line.split_whitespace().next().and_then(|n| n.parse::<u32>().ok()) {
                            found = Some(num);
                            break;
                        }
                    }
                }
                match found {
                    Some(num) => {
                        let _ = Command::new("iptables")
                            .args(["-t", table, "-D", chain, &num.to_string()])
                            .output();
                        removed += 1;
                    }
                    None => break,
                }
            }
        }
    }
    removed
}

/// Run an iptables command with base args + protocol + port + tail args
fn run_iptables(base: &[&str], proto: &[String], port: &[String], tail: &[&str]) -> Result<(), String> {
    let mut args: Vec<&str> = base.to_vec();
    for p in proto { args.push(p.as_str()); }
    for p in port { args.push(p.as_str()); }
    args.extend_from_slice(tail);

    let output = Command::new("iptables")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run iptables: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("iptables {} failed: {}", args.join(" "), stderr));
    }
    Ok(())
}

/// Restore all IP mappings on startup (called once from main.rs)
pub fn apply_ip_mappings() {
    // Enable IP forwarding
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    // Apply conntrack ESTABLISHED,RELATED rule (idempotent — check first)
    let existing = Command::new("iptables")
        .args(["-C", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        .output();
    if existing.map(|o| !o.status.success()).unwrap_or(true) {
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .output();
    }

    let config = load_ip_mapping_config();
    let count = config.mappings.len();
    for mapping in &config.mappings {
        if let Err(e) = apply_mapping_rules(mapping) {
            warn!("Failed to restore IP mapping {} → {}: {}", mapping.public_ip, mapping.wolfnet_ip, e);
        }
    }
    if count > 0 {

    }
}

/// Detect this node's WolfNet IP address (for SNAT source)
fn detect_wolfnet_gateway_ip() -> Option<String> {
    let interfaces = list_interfaces();
    for iface in &interfaces {
        if iface.name.starts_with("wn") || iface.name.starts_with("wolfnet") {
            if let Some(addr) = iface.addresses.iter().find(|a| a.family == "inet") {
                return Some(addr.address.clone());
            }
        }
    }
    None
}

/// Detect the best reachable LAN IP for this node.
/// Returns the first private (RFC1918) IPv4 address found on a real interface,
/// skipping loopback, docker, wolfnet, veth, and bridge interfaces.
/// Used when the node is bound to 0.0.0.0 or 127.0.0.1 and we need a real
/// endpoint for WolfNet peers to connect to.
pub fn detect_lan_ip() -> Option<String> {
    let interfaces = list_interfaces();
    for iface in &interfaces {
        if iface.name == "lo" || iface.name.starts_with("docker")
            || iface.name.starts_with("br-") || iface.name.starts_with("veth")
            || iface.name.starts_with("wn") || iface.name.starts_with("wolfnet")
            || iface.name.starts_with("virbr")
        {
            continue;
        }
        for addr in &iface.addresses {
            if addr.family == "inet" {
                if let Ok(ip) = addr.address.parse::<std::net::Ipv4Addr>() {
                    if is_private_ip(ip) && !ip.is_loopback() {
                        return Some(addr.address.clone());
                    }
                }
            }
        }
    }
    None
}

/// Detect public (non-RFC1918) IPs on all interfaces
pub fn detect_public_ips() -> Vec<String> {
    let mut public_ips = Vec::new();
    let interfaces = list_interfaces();
    for iface in &interfaces {
        // Skip loopback, docker, wolfnet, veth
        if iface.name == "lo" || iface.name.starts_with("docker")
            || iface.name.starts_with("br-") || iface.name.starts_with("veth")
            || iface.name.starts_with("wn") || iface.name.starts_with("wolfnet")
            || iface.name.starts_with("virbr")
        {
            continue;
        }
        for addr in &iface.addresses {
            if addr.family == "inet" {
                if let Ok(ip) = addr.address.parse::<std::net::Ipv4Addr>() {
                    if !is_private_ip(ip) {
                        public_ips.push(addr.address.clone());
                    }
                }
            }
        }
    }
    public_ips
}

/// Check if an IPv4 address is RFC1918 private
fn is_private_ip(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    if octets[0] == 10 { return true; }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) { return true; }
    if octets[0] == 192 && octets[1] == 168 { return true; }
    if octets[0] == 127 || (octets[0] == 169 && octets[1] == 254) { return true; }
    false
}

/// Collect WolfNet IPs in use (peers + this node)
pub fn detect_wolfnet_ips() -> Vec<serde_json::Value> {
    let mut ips = Vec::new();

    // This node's WolfNet IP
    if let Some(gw) = detect_wolfnet_gateway_ip() {
        ips.push(serde_json::json!({ "ip": gw, "source": "this-node (gateway)" }));
    }

    // Peers from config
    let peers = get_wolfnet_peers();
    for peer in &peers {
        let ip = peer.ip.split('/').next().unwrap_or(&peer.ip).to_string();
        if !ip.is_empty() {
            ips.push(serde_json::json!({ "ip": ip, "source": format!("peer: {}", peer.name) }));
        }
    }

    // Docker containers with WolfNet IPs (label wolfnet.ip)
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}|{{.Label \"wolfnet.ip\"}}"])
        .output()
    {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(2, '|').collect();
                if parts.len() == 2 {
                    let name = parts[0].trim();
                    let wip = parts[1].trim();
                    if !wip.is_empty() && wip != "<no value>" {
                        if wip.parse::<std::net::Ipv4Addr>().is_ok() {
                            ips.push(serde_json::json!({
                                "ip": wip,
                                "source": format!("docker: {}", name)
                            }));
                        }
                    }
                }
            }
        }
    }

    // LXC containers with WolfNet IPs — scan all registered storage paths
    for lxc_path in crate::containers::lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&lxc_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let ip_file = entry.path().join(".wolfnet/ip");
                if let Ok(ip) = std::fs::read_to_string(&ip_file) {
                    let ip = ip.trim().to_string();
                    if !ip.is_empty() && ip.parse::<std::net::Ipv4Addr>().is_ok() {
                        ips.push(serde_json::json!({
                            "ip": ip,
                            "source": format!("lxc: {}", name)
                        }));
                    }
                }
            }
        }
    }

    // Proxmox LXC containers — check pct configs for wn0 IPs
    if std::path::Path::new("/etc/pve").exists() {
        if let Ok(entries) = std::fs::read_dir("/etc/pve/lxc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "conf").unwrap_or(false) {
                    let vmid = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                    if let Ok(conf) = std::fs::read_to_string(&path) {
                        for line in conf.lines() {
                            // net lines look like: net1: name=wn0,bridge=lxcbr0,ip=10.10.10.x/24,...
                            if line.contains("name=wn0") {
                                if let Some(ip_part) = line.split(',').find(|p| p.starts_with("ip=")) {
                                    let ip = ip_part.trim_start_matches("ip=")
                                        .split('/')
                                        .next()
                                        .unwrap_or("")
                                        .to_string();
                                    if !ip.is_empty() && ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                        ips.push(serde_json::json!({
                                            "ip": ip,
                                            "source": format!("pve-lxc: CT{}", vmid)
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Remote container/VIP IPs from the WolfNet routes cache
    let routes = crate::containers::WOLFNET_ROUTES.lock().unwrap().clone();
    for (container_ip, gateway_ip) in &routes {
        if container_ip.parse::<std::net::Ipv4Addr>().is_ok() {
            ips.push(serde_json::json!({
                "ip": container_ip,
                "source": format!("remote via {}", gateway_ip)
            }));
        }
    }

    // De-duplicate by IP
    let mut seen = std::collections::HashSet::new();
    ips.retain(|v| {
        let ip = v["ip"].as_str().unwrap_or("").to_string();
        seen.insert(ip)
    });

    ips
}

/// Simple random ID generator
fn rand_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos as u64) ^ (std::process::id() as u64) ^ 0xdeadbeef
}

// ─── WireGuard Bridge ──────────────────────────────────────────────────────
//
// Provides VPN access to WolfNet overlay networks from external clients.
// Each cluster gets a unique WireGuard bridge subnet (10.20.X.0/24) with
// NAT bridging into the actual WolfNet subnet — allowing simultaneous
// connections to multiple clusters without IP conflicts.

const WG_BRIDGE_CONFIG: &str = "/etc/wolfstack/wireguard-bridge.json";

/// WireGuard bridge configuration for a single cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardBridge {
    pub cluster: String,
    pub enabled: bool,
    pub listen_port: u16,
    pub private_key: String,
    pub public_key: String,
    /// Third octet for bridge subnet, e.g. 1 → 10.20.1.0/24
    pub bridge_octet: u8,
    pub server_ip: String,
    /// WolfNet subnet prefix, e.g. "10.0.10"
    #[serde(default)]
    pub wolfnet_subnet: String,
    #[serde(default)]
    pub clients: Vec<WireGuardClient>,
}

/// A WireGuard client (external user) connected via the bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardClient {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key: String,
    pub assigned_ip: String,
    pub created_at: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

impl WireGuardBridge {
    /// Interface name for this bridge (e.g. "wg-prod")
    pub fn interface_name(&self) -> String {
        let safe: String = self.cluster.chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .take(12)
            .collect();
        format!("wg-{}", if safe.is_empty() { "bridge".to_string() } else { safe })
    }

    /// Full bridge subnet CIDR (e.g. "10.20.1.0/24")
    pub fn bridge_subnet(&self) -> String {
        format!("10.20.{}.0/24", self.bridge_octet)
    }
}

/// Check if WireGuard tools are installed
pub fn wireguard_installed() -> bool {
    Command::new("which").arg("wg")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Attempt to install wireguard-tools for the current distro
pub fn install_wireguard_tools() -> Result<String, String> {
    // Detect distro
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id = os_release.lines()
        .find(|l| l.starts_with("ID="))
        .map(|l| l.trim_start_matches("ID=").trim_matches('"').to_lowercase())
        .unwrap_or_default();
    let id_like = os_release.lines()
        .find(|l| l.starts_with("ID_LIKE="))
        .map(|l| l.trim_start_matches("ID_LIKE=").trim_matches('"').to_lowercase())
        .unwrap_or_default();

    let (cmd, args): (&str, Vec<&str>) = if id == "ubuntu" || id == "debian" || id_like.contains("debian") {
        ("apt", vec!["install", "-y", "wireguard-tools"])
    } else if id == "fedora" || id_like.contains("fedora") || id_like.contains("rhel") {
        ("dnf", vec!["install", "-y", "wireguard-tools"])
    } else if id == "centos" || id == "rhel" || id_like.contains("centos") {
        ("yum", vec!["install", "-y", "wireguard-tools"])
    } else if id == "opensuse" || id == "sles" || id_like.contains("suse") {
        ("zypper", vec!["install", "-y", "wireguard-tools"])
    } else {
        return Err(format!("Unsupported distro '{}' — install wireguard-tools manually", id));
    };

    let output = Command::new(cmd).args(&args).output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if output.status.success() {
        Ok("wireguard-tools installed".to_string())
    } else {
        Err(format!("Package install failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

/// Load all WireGuard bridge configs from disk
pub fn load_wireguard_bridges() -> std::collections::HashMap<String, WireGuardBridge> {
    match std::fs::read_to_string(WG_BRIDGE_CONFIG) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    }
}

/// Save all WireGuard bridge configs to disk
pub fn save_wireguard_bridges(bridges: &std::collections::HashMap<String, WireGuardBridge>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(bridges)
        .map_err(|e| format!("Failed to serialize WireGuard config: {}", e))?;
    std::fs::write(WG_BRIDGE_CONFIG, json)
        .map_err(|e| format!("Failed to write {}: {}", WG_BRIDGE_CONFIG, e))
}

/// Initialize a WireGuard bridge for a cluster
pub fn init_wireguard_bridge(cluster: &str, listen_port: u16) -> Result<WireGuardBridge, String> {
    // Install wireguard-tools if needed
    if !wireguard_installed() {
        install_wireguard_tools()?;
        if !wireguard_installed() {
            return Err("wireguard-tools installation failed — 'wg' not found".to_string());
        }
    }

    let mut bridges = load_wireguard_bridges();
    if bridges.contains_key(cluster) {
        return Err(format!("Bridge already exists for cluster '{}'", cluster));
    }

    // Check port not already in use by another bridge
    for (name, b) in &bridges {
        if b.listen_port == listen_port {
            return Err(format!("Port {} already in use by cluster '{}'", listen_port, name));
        }
    }

    // Generate server keypair
    let priv_key = wg_genkey()?;
    let pub_key = wg_pubkey(&priv_key)?;

    // Auto-assign bridge octet (1, 2, 3, ...)
    let used_octets: Vec<u8> = bridges.values().map(|b| b.bridge_octet).collect();
    let octet = (1u8..=254).find(|o| !used_octets.contains(o))
        .ok_or("No available bridge subnets (all 254 in use)")?;

    // Detect WolfNet subnet
    let wolfnet_subnet = detect_wolfnet_subnet().unwrap_or_else(|| "10.0.10".to_string());

    let bridge = WireGuardBridge {
        cluster: cluster.to_string(),
        enabled: true,
        listen_port,
        private_key: priv_key,
        public_key: pub_key,
        bridge_octet: octet,
        server_ip: format!("10.20.{}.1/24", octet),
        wolfnet_subnet,
        clients: Vec::new(),
    };

    bridges.insert(cluster.to_string(), bridge.clone());
    save_wireguard_bridges(&bridges)?;

    // Apply the interface
    apply_wireguard_bridge(&bridge)?;

    Ok(bridge)
}

/// Add a client to a cluster's WireGuard bridge
pub fn add_wireguard_client(cluster: &str, name: &str) -> Result<(WireGuardClient, String), String> {
    let mut bridges = load_wireguard_bridges();
    let bridge = bridges.get_mut(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;

    // Check name uniqueness
    if bridge.clients.iter().any(|c| c.name == name) {
        return Err(format!("Client '{}' already exists", name));
    }

    // Generate client keypair
    let priv_key = wg_genkey()?;
    let pub_key = wg_pubkey(&priv_key)?;

    // Assign next available IP (.2, .3, .4, ...)
    let used_hosts: Vec<u8> = bridge.clients.iter()
        .filter_map(|c| {
            c.assigned_ip.split('.').nth(3)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse::<u8>().ok())
        })
        .collect();
    let host = (2u8..=254).find(|h| !used_hosts.contains(h))
        .ok_or("No available client IPs in bridge subnet")?;

    let client = WireGuardClient {
        id: format!("{:016x}", rand_id()),
        name: name.to_string(),
        public_key: pub_key,
        private_key: priv_key,
        assigned_ip: format!("10.20.{}.{}/32", bridge.bridge_octet, host),
        created_at: chrono_now(),
        enabled: true,
    };

    // Generate the .conf content before adding to bridge (need bridge data)
    let conf = generate_client_config(bridge, &client)?;

    bridge.clients.push(client.clone());
    save_wireguard_bridges(&bridges)?;

    // Apply the peer to the live interface
    let bridge_ref = bridges.get(cluster).unwrap();
    let _ = wg_set_peer(bridge_ref, &client);

    Ok((client, conf))
}

/// Remove a client from a cluster's WireGuard bridge
pub fn remove_wireguard_client(cluster: &str, client_id: &str) -> Result<String, String> {
    let mut bridges = load_wireguard_bridges();
    let bridge = bridges.get_mut(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;

    let idx = bridge.clients.iter().position(|c| c.id == client_id)
        .ok_or(format!("Client '{}' not found", client_id))?;

    let client = bridge.clients.remove(idx);

    // Remove from live interface
    let _ = Command::new("wg")
        .args(["set", &bridge.interface_name(), "peer", &client.public_key, "remove"])
        .output();

    save_wireguard_bridges(&bridges)?;
    Ok(format!("Client '{}' removed", client.name))
}

/// Get a client's .conf content (for re-download)
pub fn get_client_config(cluster: &str, client_id: &str) -> Result<String, String> {
    let bridges = load_wireguard_bridges();
    let bridge = bridges.get(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;
    let client = bridge.clients.iter().find(|c| c.id == client_id)
        .ok_or(format!("Client '{}' not found", client_id))?;
    generate_client_config(bridge, client)
}

/// Generate the WireGuard client .conf file content
fn generate_client_config(bridge: &WireGuardBridge, client: &WireGuardClient) -> Result<String, String> {
    // Detect the server's public/reachable IP for the Endpoint field
    let server_endpoint = detect_server_endpoint(bridge.listen_port);

    Ok(format!(
        "# WolfStack WireGuard Bridge — Cluster: {cluster}\n\
         # Client: {name}\n\
         # Generated: {date}\n\
         \n\
         [Interface]\n\
         PrivateKey = {priv_key}\n\
         Address = {addr}\n\
         \n\
         [Peer]\n\
         PublicKey = {pub_key}\n\
         Endpoint = {endpoint}\n\
         AllowedIPs = {subnet}\n\
         PersistentKeepalive = 25\n",
        cluster = bridge.cluster,
        name = client.name,
        date = &chrono_now()[..10],
        priv_key = client.private_key,
        addr = client.assigned_ip,
        pub_key = bridge.public_key,
        endpoint = server_endpoint,
        subnet = bridge.bridge_subnet(),
    ))
}

/// Enable or disable a WireGuard bridge
pub fn toggle_wireguard_bridge(cluster: &str, enabled: bool) -> Result<String, String> {
    let mut bridges = load_wireguard_bridges();
    let bridge = bridges.get_mut(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;

    bridge.enabled = enabled;
    let bridge_clone = bridge.clone();
    save_wireguard_bridges(&bridges)?;

    if enabled {
        apply_wireguard_bridge(&bridge_clone)?;
        Ok("Bridge enabled".to_string())
    } else {
        teardown_wireguard_bridge(cluster)?;
        Ok("Bridge disabled".to_string())
    }
}

/// Delete a WireGuard bridge entirely
pub fn delete_wireguard_bridge(cluster: &str) -> Result<String, String> {
    let mut bridges = load_wireguard_bridges();
    if bridges.remove(cluster).is_none() {
        return Err(format!("No WireGuard bridge for cluster '{}'", cluster));
    }
    let _ = teardown_wireguard_bridge(cluster);
    save_wireguard_bridges(&bridges)?;
    Ok(format!("Bridge for cluster '{}' deleted", cluster))
}

/// Create/configure the WireGuard interface, add all peers, set up NAT
pub fn apply_wireguard_bridge(bridge: &WireGuardBridge) -> Result<(), String> {
    let iface = bridge.interface_name();

    // Create interface if it doesn't exist
    let exists = Command::new("ip").args(["link", "show", &iface]).output()
        .map(|o| o.status.success()).unwrap_or(false);
    if !exists {
        run_cmd("ip", &["link", "add", &iface, "type", "wireguard"])?;
    }

    // Write private key to temp file for wg setconf
    let key_path = format!("/tmp/wg-{}-key", iface);
    std::fs::write(&key_path, &bridge.private_key)
        .map_err(|e| format!("Failed to write key: {}", e))?;

    // Set private key and listen port
    run_cmd("wg", &["set", &iface, "private-key", &key_path, "listen-port", &bridge.listen_port.to_string()])?;

    // Clean up key file
    let _ = std::fs::remove_file(&key_path);

    // Set IP address (flush first to avoid duplicates)
    let _ = Command::new("ip").args(["addr", "flush", "dev", &iface]).output();
    run_cmd("ip", &["addr", "add", &bridge.server_ip, "dev", &iface])?;

    // Bring up
    run_cmd("ip", &["link", "set", &iface, "up"])?;

    // Add all enabled client peers
    for client in &bridge.clients {
        if client.enabled {
            let _ = wg_set_peer(bridge, client);
        }
    }

    // Set up NAT/forwarding rules
    setup_bridge_nat(bridge)?;

    Ok(())
}

/// Remove WireGuard interface and NAT rules for a cluster
pub fn teardown_wireguard_bridge(cluster: &str) -> Result<(), String> {
    let bridges = load_wireguard_bridges();
    if let Some(bridge) = bridges.get(cluster) {
        let iface = bridge.interface_name();
        let _ = Command::new("ip").args(["link", "set", &iface, "down"]).output();
        let _ = Command::new("ip").args(["link", "delete", &iface]).output();
        cleanup_bridge_nat(bridge);
    }
    Ok(())
}

/// Re-apply all enabled bridges (called on startup)
pub fn apply_all_wireguard_bridges() {
    let bridges = load_wireguard_bridges();
    for (cluster, bridge) in &bridges {
        if bridge.enabled {
            if let Err(e) = apply_wireguard_bridge(bridge) {
                warn!("Failed to apply WireGuard bridge for cluster '{}': {}", cluster, e);
            }
        }
    }
}

// ─── WireGuard helpers ──────────────────────────────────────────────────────

/// Generate a WireGuard private key
fn wg_genkey() -> Result<String, String> {
    let output = Command::new("wg").arg("genkey").output()
        .map_err(|e| format!("wg genkey failed: {}", e))?;
    if !output.status.success() {
        return Err("wg genkey failed".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Derive public key from a private key
fn wg_pubkey(private_key: &str) -> Result<String, String> {
    use std::io::Write;
    let mut child = Command::new("wg").arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("wg pubkey failed: {}", e))?;
    child.stdin.take().unwrap().write_all(private_key.as_bytes())
        .map_err(|e| format!("wg pubkey stdin: {}", e))?;
    let output = child.wait_with_output()
        .map_err(|e| format!("wg pubkey wait: {}", e))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Add a peer to a live WireGuard interface
fn wg_set_peer(bridge: &WireGuardBridge, client: &WireGuardClient) -> Result<(), String> {
    let iface = bridge.interface_name();
    run_cmd("wg", &[
        "set", &iface,
        "peer", &client.public_key,
        "allowed-ips", &client.assigned_ip,
    ])
}

/// Set up iptables NAT rules for a bridge
fn setup_bridge_nat(bridge: &WireGuardBridge) -> Result<(), String> {
    let iface = bridge.interface_name();
    let subnet = bridge.bridge_subnet();

    // Detect WolfNet interface name
    let wn_iface = detect_wolfnet_iface().unwrap_or_else(|| "wolfnet0".to_string());

    // Enable IP forwarding
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();

    // Clean up any existing rules for this bridge first
    cleanup_bridge_nat(bridge);

    // MASQUERADE traffic from bridge subnet going to WolfNet
    let _ = Command::new("iptables").args([
        "-t", "nat", "-A", "POSTROUTING",
        "-s", &subnet, "-o", &wn_iface, "-j", "MASQUERADE",
    ]).output();

    // Allow forwarding between WG and WolfNet
    let _ = Command::new("iptables").args([
        "-A", "FORWARD", "-i", &iface, "-o", &wn_iface, "-j", "ACCEPT",
    ]).output();
    let _ = Command::new("iptables").args([
        "-A", "FORWARD", "-i", &wn_iface, "-o", &iface,
        "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
    ]).output();

    Ok(())
}

/// Remove iptables NAT rules for a bridge
fn cleanup_bridge_nat(bridge: &WireGuardBridge) {
    let iface = bridge.interface_name();
    let subnet = bridge.bridge_subnet();
    let wn_iface = detect_wolfnet_iface().unwrap_or_else(|| "wolfnet0".to_string());

    let _ = Command::new("iptables").args([
        "-t", "nat", "-D", "POSTROUTING",
        "-s", &subnet, "-o", &wn_iface, "-j", "MASQUERADE",
    ]).output();
    let _ = Command::new("iptables").args([
        "-D", "FORWARD", "-i", &iface, "-o", &wn_iface, "-j", "ACCEPT",
    ]).output();
    let _ = Command::new("iptables").args([
        "-D", "FORWARD", "-i", &wn_iface, "-o", &iface,
        "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
    ]).output();
}

/// Detect WolfNet interface name (wn0 or wolfnet0)
fn detect_wolfnet_iface() -> Option<String> {
    let interfaces = list_interfaces();
    interfaces.iter()
        .find(|i| i.name.starts_with("wn") || i.name.starts_with("wolfnet"))
        .map(|i| i.name.clone())
}

/// Detect the WolfNet subnet prefix (e.g. "10.0.10")
fn detect_wolfnet_subnet() -> Option<String> {
    if let Some(info) = get_wolfnet_local_info() {
        if let Some(addr) = info["address"].as_str() {
            let parts: Vec<&str> = addr.split('.').collect();
            if parts.len() >= 3 {
                return Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]));
            }
        }
    }
    None
}

/// Detect the best endpoint address for clients to connect to
fn detect_server_endpoint(port: u16) -> String {
    // Try public IP first
    if let Ok(output) = Command::new("curl")
        .args(["-s", "--connect-timeout", "3", "https://ifconfig.me/ip"])
        .output()
    {
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !ip.is_empty() && output.status.success() {
            return format!("{}:{}", ip, port);
        }
    }

    // Fall back to LAN IP
    if let Some(lan_ip) = detect_lan_ip() {
        return format!("{}:{}", lan_ip, port);
    }

    format!("YOUR_SERVER_IP:{}", port)
}

/// Run a command, return Ok(()) on success or Err with stderr
fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(cmd).args(args).output()
        .map_err(|e| format!("{} failed: {}", cmd, e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{} {}: {}", cmd, args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()))
    }
}

/// Get current ISO 8601 timestamp
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // Simple UTC timestamp without chrono dependency
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since 1970-01-01
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let year_days = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if remaining < year_days { break; }
        remaining -= year_days;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    while m < 12 && remaining >= month_days[m] {
        remaining -= month_days[m];
        m += 1;
    }

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m + 1, remaining + 1, hours, minutes, seconds)
}
