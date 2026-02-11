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

/// Get DNS configuration from /etc/resolv.conf
pub fn get_dns() -> DnsConfig {
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                nameservers.push(line[11..].trim().to_string());
            } else if line.starts_with("search ") {
                search_domains = line[7..].split_whitespace().map(|s| s.to_string()).collect();
            }
        }
    }

    DnsConfig { nameservers, search_domains }
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
