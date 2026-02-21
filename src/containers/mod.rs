// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Container management — Docker and LXC support for WolfStack
//!
//! Docker: communicates via /var/run/docker.sock REST API
//! LXC: communicates via lxc-* CLI commands
//! WolfNet: Optional overlay network integration for container networking

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use tracing::{info, error, warn};

/// One-time WolfNet networking initialization — called at WolfStack startup.
/// Sets kernel parameters needed for container traffic to flow through wolfnet0.
pub fn wolfnet_init() {
    // Check if wolfnet0 exists
    let exists = Command::new("ip").args(["link", "show", "wolfnet0"]).output()
        .map(|o| o.status.success()).unwrap_or(false);
    if !exists {
        info!("wolfnet0 not found — skipping WolfNet init");
        return;
    }

    info!("WolfNet init: setting up kernel networking for container routing");

    // Enable IP forwarding (required for routing between wolfnet0 and lxcbr0)
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();

    // Disable reverse path filtering on wolfnet0 (packets arrive from tunnel,
    // source IPs don't match wolfnet0's directly-connected subnet)
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.rp_filter=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.rp_filter=0"]).output();

    // Disable ICMP redirects on wolfnet0 (we ARE the router for remote containers,
    // the kernel shouldn't tell peers to "go direct")
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.send_redirects=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.send_redirects=0"]).output();

    // FORWARD chain: allow traffic between wolfnet0 and lxcbr0 in both directions
    let check = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
    if check.map(|o| !o.status.success()).unwrap_or(true) {
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "lxcbr0", "-o", "wolfnet0", "-j", "ACCEPT"]).output();
        info!("WolfNet init: added FORWARD rules for wolfnet0 ↔ lxcbr0");
    }

    info!("WolfNet init: kernel networking ready");
}

// ─── WolfNet Route Cache ───
// Keep container→host route map in memory; only flush to disk when it changes.
pub static WOLFNET_ROUTES: std::sync::LazyLock<Mutex<std::collections::HashMap<String, String>>> =
    std::sync::LazyLock::new(|| {
        // Seed from existing routes file on startup
        let mut map = std::collections::HashMap::new();
        if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json") {
            if let Ok(existing) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
                map = existing;
            }
        }
        Mutex::new(map)
    });

/// Merge new routes into the in-memory cache and flush to disk only if anything changed.
/// Returns true if routes were updated.
pub fn update_wolfnet_routes(new_routes: &std::collections::HashMap<String, String>) -> bool {
    let mut cache = WOLFNET_ROUTES.lock().unwrap();
    let file_exists = std::path::Path::new("/var/run/wolfnet/routes.json").exists();
    let mut changed = false;
    for (k, v) in new_routes {
        if cache.get(k) != Some(v) {
            cache.insert(k.clone(), v.clone());
            changed = true;
        }
    }
    if changed || !file_exists {
        flush_routes_to_disk(&cache);
    }
    changed
}

/// Replace the entire route table with the given complete set of routes.
/// Unlike update_wolfnet_routes (which merges), this is authoritative —
/// it ensures stale routes are removed and the file reflects current reality.
pub fn replace_wolfnet_routes(complete_routes: std::collections::HashMap<String, String>) {
    let mut cache = WOLFNET_ROUTES.lock().unwrap();
    let file_exists = std::path::Path::new("/var/run/wolfnet/routes.json").exists();
    if *cache == complete_routes && file_exists {
        return; // No change and file exists — skip disk write + SIGHUP
    }
    *cache = complete_routes;
    flush_routes_to_disk(&cache);
}

/// Write the route map to /var/run/wolfnet/routes.json and signal WolfNet to reload.
fn flush_routes_to_disk(routes: &std::collections::HashMap<String, String>) {
    let routes_path = "/var/run/wolfnet/routes.json";
    if let Err(e) = std::fs::create_dir_all("/var/run/wolfnet") {
        warn!("Failed to create /var/run/wolfnet: {}", e);
        return;
    }
    match serde_json::to_string_pretty(routes) {
        Ok(json) => {
            match std::fs::write(routes_path, &json) {
                Ok(_) => {
                    info!("Routes — wrote {} route(s) to {}", routes.len(), routes_path);
                    // Signal WolfNet to reload (SIGHUP)
                    if let Ok(output) = Command::new("pidof").arg("wolfnet").output() {
                        let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !pid_str.is_empty() {
                            let _ = Command::new("kill").args(["-HUP", &pid_str]).output();
                            info!("Sent SIGHUP to WolfNet (pid {})", pid_str);
                        } else {
                            info!("WolfNet not running — routes.json written but no SIGHUP sent");
                        }
                    }
                }
                Err(e) => warn!("Failed to write {}: {}", routes_path, e),
            }
        }
        Err(e) => warn!("Failed to serialize routes: {}", e),
    }
}

/// Clean up stale /32 kernel routes for WolfNet IPs that don't belong to local containers.
/// Stale routes (from deleted/moved containers) override the wolfnet0 /24 route and
/// prevent cross-node container routing through the WolfNet tunnel.
pub fn cleanup_stale_wolfnet_routes() {
    let local_ips: std::collections::HashSet<String> = wolfnet_used_ips().into_iter().collect();

    // Get all kernel routes in the 10.10.10.0/24 range
    let output = match Command::new("ip").args(["route", "show"]).output() {
        Ok(o) => o,
        Err(_) => return,
    };
    let text = String::from_utf8_lossy(&output.stdout);

    let mut removed = 0;
    for line in text.lines() {
        // Match lines like: "10.10.10.X via 10.0.3.Y dev lxcbr0" or "10.10.10.X dev docker0 scope link"
        let ip = match line.split_whitespace().next() {
            Some(ip) if ip.starts_with("10.10.10.") && !ip.contains('/') => ip,
            _ => continue,
        };

        // Skip the subnet route (10.10.10.0/24 dev wolfnet0)
        if ip.contains('/') { continue; }

        // If this IP is NOT in our local used IPs, it's stale — remove the kernel route
        if !local_ips.contains(ip) {
            let del_result = Command::new("ip")
                .args(["route", "del", &format!("{}/32", ip)])
                .output();
            // Also try without /32 in case the route was added without it
            let del_result2 = Command::new("ip")
                .args(["route", "del", ip])
                .output();
            if del_result.map(|o| o.status.success()).unwrap_or(false)
                || del_result2.map(|o| o.status.success()).unwrap_or(false)
            {
                info!("Removed stale kernel route for WolfNet IP {}", ip);
                removed += 1;
            }
        }
    }
    if removed > 0 {
        info!("Cleaned up {} stale WolfNet kernel route(s)", removed);
    }

    // Ensure Docker containers with wolfnet.ip labels have correct host routes
    // (route via docker0, not lxcbr0 or missing entirely)
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            if let Ok(inspect) = Command::new("docker")
                .args(["inspect", "--format", "{{index .Config.Labels \"wolfnet.ip\"}}", name])
                .output()
            {
                let label = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
                if label.is_empty() || label == "<no value>" { continue; }

                // Check if the container is running (needs a PID for nsenter)
                let pid_out = Command::new("docker")
                    .args(["inspect", "--format", "{{.State.Pid}}", name])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                if pid_out.is_empty() || pid_out == "0" { continue; }

                // Ensure host route via docker0 (idempotent — replace if exists)
                let _ = Command::new("ip")
                    .args(["route", "replace", &format!("{}/32", label), "dev", "docker0"])
                    .output();

                // Ensure static ARP entry (get MAC via docker inspect)
                if let Ok(mac_out) = Command::new("docker")
                    .args(["inspect", "--format", "{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}", name])
                    .output()
                {
                    let mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();
                    if !mac.is_empty() {
                        let _ = Command::new("ip")
                            .args(["neigh", "replace", &label, "lladdr", &mac, "dev", "docker0", "nud", "permanent"])
                            .output();
                    }
                }
            }
        }
    }
}

// ─── WolfNet Integration ───

/// WolfNet status for container networking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNetStatus {
    pub available: bool,
    pub interface: String,
    pub ip: String,
    pub subnet: String,
    pub next_available_ip: String,
}

/// Check if WolfNet is running and get network info
pub fn wolfnet_status(extra_used: &[u8]) -> WolfNetStatus {
    // Check if wolfnet0 interface exists
    let output = Command::new("ip")
        .args(["addr", "show", "wolfnet0"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            // Parse IP: look for inet 10.10.10.X/24
            let ip = text.lines()
                .find(|l| l.contains("inet "))
                .and_then(|l| l.trim().split_whitespace().nth(1))
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .to_string();

            let subnet = if !ip.is_empty() {
                // Derive subnet from IP (e.g., 10.10.10.0/24)
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() == 4 {
                    format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
                } else {
                    "10.10.10.0/24".to_string()
                }
            } else {
                String::new()
            };

            let next_ip = wolfnet_allocate_ip(&ip, extra_used);

            WolfNetStatus {
                available: !ip.is_empty(),
                interface: "wolfnet0".to_string(),
                ip,
                subnet,
                next_available_ip: next_ip,
            }
        }
        _ => WolfNetStatus {
            available: false,
            interface: String::new(),
            ip: String::new(),
            subnet: String::new(),
            next_available_ip: String::new(),
        },
    }
}

/// Allocate the next available WolfNet IP for a container
/// Scans existing containers and picks the next free IP in 10.10.10.100-254 range
pub fn wolfnet_allocate_ip(host_ip: &str, extra_used: &[u8]) -> String {
    let parts: Vec<&str> = host_ip.split('.').collect();
    if parts.len() != 4 {
        return "10.10.10.100".to_string();
    }
    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    // Get all IPs currently in use on the wolfnet0 subnet
    let mut used_ips = std::collections::HashSet::new();

    // Host IP
    if let Ok(last) = parts[3].parse::<u8>() {
        used_ips.insert(last);
    }

    // Add extra IPs from remote cluster nodes
    for &ip in extra_used {
        used_ips.insert(ip);
    }

    // Check cluster-wide route cache (populated by poll_remote_nodes)
    // This catches container IPs from ALL nodes in the cluster
    {
        let cache = WOLFNET_ROUTES.lock().unwrap();
        for ip_str in cache.keys() {
            let ip_parts: Vec<&str> = ip_str.split('.').collect();
            if ip_parts.len() == 4 {
                if let Ok(last) = ip_parts[3].parse::<u8>() {
                    used_ips.insert(last);
                }
            }
        }
    }

    // Also check routes.json as fallback
    if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json") {
        if let Ok(routes) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
            for ip_str in routes.keys() {
                let ip_parts: Vec<&str> = ip_str.split('.').collect();
                if ip_parts.len() == 4 {
                    if let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
                }
            }
        }
    }

    // Check Docker containers with wolfnet.ip labels
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            if let Ok(inspect) = Command::new("docker")
                .args(["inspect", "--format", "{{index .Config.Labels \"wolfnet.ip\"}}", name])
                .output()
            {
                let label = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
                if !label.is_empty() && label != "<no value>" {
                    let ip_parts: Vec<&str> = label.split('.').collect();
                    if ip_parts.len() == 4 {
                        if let Ok(last) = ip_parts[3].parse::<u8>() {
                            used_ips.insert(last);
                        }
                    }
                }
            }
        }
    }

    // Check LXC containers with .wolfnet/ip marker files
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let ip_file = entry.path().join(".wolfnet/ip");
            if let Ok(ip_str) = std::fs::read_to_string(&ip_file) {
                let ip_str = ip_str.trim();
                let ip_parts: Vec<&str> = ip_str.split('.').collect();
                if ip_parts.len() == 4 {
                    if let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
                }
            }
        }
    }

    // Check VM configs for wolfnet_ip
    let vm_dir = std::path::Path::new("/var/lib/wolfstack/vms");
    if let Ok(entries) = std::fs::read_dir(vm_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(vm) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(ip_str) = vm.get("wolfnet_ip").and_then(|v| v.as_str()) {
                            let ip_parts: Vec<&str> = ip_str.split('.').collect();
                            if ip_parts.len() == 4 {
                                if let Ok(last) = ip_parts[3].parse::<u8>() {
                                    used_ips.insert(last);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check ARP table on wolfnet0 for any other IPs in use
    if let Ok(output) = Command::new("ip")
        .args(["neigh", "show", "dev", "wolfnet0"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(ip) = line.split_whitespace().next() {
                let ip_parts: Vec<&str> = ip.split('.').collect();
                if ip_parts.len() == 4 {
                    if let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
                }
            }
        }
    }

    // WolfRun service VIPs — reserve these so containers don't collide
    if let Ok(data) = std::fs::read_to_string("/etc/wolfstack/wolfrun/services.json") {
        if let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
            for svc in &services {
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str()) {
                    let ip_parts: Vec<&str> = vip.split('.').collect();
                    if ip_parts.len() == 4 {
                        if let Ok(last) = ip_parts[3].parse::<u8>() {
                            used_ips.insert(last);
                        }
                    }
                }
            }
        }
    }

    // Allocate from 100-254 range (reserving 1-99 for hosts)
    for i in 100..=254u8 {
        if !used_ips.contains(&i) {
            return format!("{}.{}", prefix, i);
        }
    }

    format!("{}.100", prefix) // Fallback
}

/// Get list of WolfNet IPs currently in use on this node (for cluster-wide dedup)
pub fn wolfnet_used_ips() -> Vec<String> {
    let mut ips = Vec::new();

    // Host IP from wolfnet0
    if let Ok(output) = Command::new("ip")
        .args(["addr", "show", "wolfnet0"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && !text.is_empty() {
            if let Some(ip) = text.lines()
                .find(|l| l.contains("inet "))
                .and_then(|l| l.trim().split_whitespace().nth(1))
                .and_then(|s| s.split('/').next())
            {
                ips.push(ip.to_string());
            } else {
                warn!("wolfnet0 interface exists but has NO IP address — WolfNet may have lost its IP. Routes and connectivity will be broken.");
            }
        }
    }

    // Docker containers on a "wolfnet" Docker network (if it exists)
    if let Ok(output) = Command::new("docker")
        .args(["network", "inspect", "wolfnet", "--format",
               "{{range .Containers}}{{.IPv4Address}} {{end}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for addr in text.split_whitespace() {
            if let Some(ip) = addr.split('/').next() {
                if !ip.is_empty() && !ips.contains(&ip.to_string()) {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    // Docker containers with wolfnet.ip labels (host-routed WolfNet — primary method)
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            if let Ok(inspect) = Command::new("docker")
                .args(["inspect", "--format", "{{index .Config.Labels \"wolfnet.ip\"}}", name])
                .output()
            {
                let label = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
                if !label.is_empty() && label != "<no value>" && !ips.contains(&label) {
                    ips.push(label);
                }
            }
        }
    }

    // LXC containers (from .wolfnet/ip marker files — authoritative source)
    let lxc_base = std::path::Path::new("/var/lib/lxc");
    if let Ok(entries) = std::fs::read_dir(lxc_base) {
        for entry in entries.flatten() {
            let ip_file = entry.path().join(".wolfnet/ip");
            if let Ok(contents) = std::fs::read_to_string(&ip_file) {
                let ip = contents.trim().to_string();
                if !ip.is_empty() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }

    // VM WolfNet IPs
    let vm_dir = std::path::Path::new("/var/lib/wolfstack/vms");
    if let Ok(entries) = std::fs::read_dir(vm_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(vm) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(ip_str) = vm.get("wolfnet_ip").and_then(|v| v.as_str()) {
                            ips.push(ip_str.to_string());
                        }
                    }
                }
            }
        }
    }
    // WolfRun service VIPs (load-balanced virtual IPs)
    if let Ok(data) = std::fs::read_to_string("/etc/wolfstack/wolfrun/services.json") {
        if let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
            for svc in &services {
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str()) {
                    if !vip.is_empty() && !ips.contains(&vip.to_string()) {
                        ips.push(vip.to_string());
                    }
                }
            }
        }
    }

    ips
}

/// Sync container routes from all WolfNet peers.
/// Reads /etc/wolfnet/config.toml to discover peers, calls each peer's
/// WolfStack API for their container IPs, builds routes.json, and
/// signals WolfNet to reload. Works without WolfStack cluster membership.
pub async fn sync_wolfnet_peer_routes() {
    // Load cluster secret for authenticating API requests
    let cluster_secret = crate::auth::load_cluster_secret();

    // Read WolfNet config to find peers
    let config_path = "/etc/wolfnet/config.toml";
    let config_str = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(_) => return, // No WolfNet config
    };

    // Parse the TOML to extract peer info
    let config: toml::Value = match config_str.parse() {
        Ok(v) => v,
        Err(_) => return,
    };

    let peers = match config.get("peers").and_then(|p| p.as_array()) {
        Some(p) => p,
        None => return,
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut subnet_routes: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for peer in peers {
        let allowed_ip = match peer.get("allowed_ip").and_then(|v| v.as_str()) {
            Some(ip) => ip.to_string(),
            None => continue,
        };
        let endpoint = match peer.get("endpoint").and_then(|v| v.as_str()) {
            Some(e) => e.to_string(),
            None => continue,
        };

        // Extract hostname from endpoint (e.g., "cynthia.wolfterritories.org:9600" → "cynthia.wolfterritories.org")
        let hostname = endpoint.split(':').next().unwrap_or(&endpoint);

        // Try calling the peer's WolfStack API for used IPs
        // Try common WolfStack ports: 8553 (default), 8552
        let mut used_ips: Vec<String> = Vec::new();
        for port in &[8553, 8552] {
            for scheme in &["https", "http"] {
                let url = format!("{}://{}:{}/api/wolfnet/used-ips", scheme, hostname, port);
                if let Ok(resp) = client.get(&url)
                    .header("X-WolfStack-Secret", &cluster_secret)
                    .send().await {
                    if let Ok(ips) = resp.json::<Vec<String>>().await {
                        if !ips.is_empty() {
                            used_ips = ips;
                            break;
                        }
                    }
                }
            }
            if !used_ips.is_empty() { break; }
        }

        // Also try via WolfNet IP directly (in case DNS doesn't resolve but WolfNet tunnel works)
        if used_ips.is_empty() {
            for port in &[8553, 8552] {
                let url = format!("http://{}:{}/api/wolfnet/used-ips", allowed_ip, port);
                if let Ok(resp) = client.get(&url)
                    .header("X-WolfStack-Secret", &cluster_secret)
                    .send().await {
                    if let Ok(ips) = resp.json::<Vec<String>>().await {
                        if !ips.is_empty() {
                            used_ips = ips;
                            break;
                        }
                    }
                }
            }
        }

        if used_ips.is_empty() { continue; }

        // First IP is the host WolfNet address, rest are container/VM IPs
        // Map each container IP → host WolfNet IP (for routing)
        let host_wn_ip = &used_ips[0];
        for container_ip in &used_ips[1..] {
            if !container_ip.is_empty() && container_ip != host_wn_ip {
                subnet_routes.insert(container_ip.clone(), host_wn_ip.clone());
            }
        }
    }

    // Update in-memory route cache; only flushes to disk + SIGHUP if anything changed
    if !subnet_routes.is_empty() {
        update_wolfnet_routes(&subnet_routes);
    }
    // Note: do NOT delete routes.json when no routes found — poll_remote_nodes may have written valid routes
}

/// Ensure the Docker 'wolfnet' network exists (macvlan on wolfnet0)
/// Ensure networking requirements (just forwarding)
pub fn ensure_docker_wolfnet_network() -> Result<(), String> {
    // Enable forwarding so containers can route to WolfNet
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();
    Ok(())
}

/// Connect a Docker container to WolfNet via host routing (IP alias)
pub fn docker_connect_wolfnet(container: &str, ip: &str) -> Result<String, String> {
    ensure_docker_wolfnet_network()?;

    info!("Configuring Docker container {} for WolfNet routing with IP {}", container, ip);

    // 1. Get Docker Bridge Gateway IP (usually 172.17.0.1)
    let gateway = Command::new("docker")
        .args(["network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "172.17.0.1".to_string());

    let gateway = if gateway.is_empty() { "172.17.0.1".to_string() } else { gateway };

    // 2. Get the container's bridge IP
    let container_bridge_ip = Command::new("docker")
        .args(["inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    if container_bridge_ip.is_empty() {
        return Err(format!("Container '{}' has no bridge IP — is it running?", container));
    }

    // 3. Get the container's MAC address (inside the per-network settings)
    let container_mac = Command::new("docker")
        .args(["inspect", "--format", "{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}", container])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    info!("Container {} bridge IP: {}, MAC: {:?}, WolfNet IP: {}", container, container_bridge_ip, container_mac, ip);

    // 4. Configure Container Side — use nsenter to avoid requiring 'ip' inside the container.
    //    Many images (e.g. official nginx) don't ship iproute2, so `docker exec ip ...` silently fails.
    //    nsenter enters the container's network namespace using the host's /sbin/ip binary.
    let container_pid = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Pid}}", container])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    if container_pid.is_empty() || container_pid == "0" {
        info!("Cannot get PID for container {} — is it running?", container);
    } else {
        info!("Container {} PID: {} — using nsenter for network config", container, container_pid);

        // Add IP alias /32 (idempotent — ignore EEXIST)
        let alias_result = Command::new("nsenter")
            .args(["--target", &container_pid, "--net", "ip", "addr", "add", &format!("{}/32", ip), "dev", "eth0"])
            .output();
        match &alias_result {
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if o.status.success() {
                    info!("Added {}/32 to container {} eth0 (via nsenter)", ip, container);
                } else if stderr.contains("EEXIST") || stderr.contains("File exists") {
                    info!("{}/32 already on container {} eth0", ip, container);
                } else {
                    info!("ip addr add warning: {}", stderr.trim());
                }
            }
            Err(e) => info!("ip addr add (nsenter) failed: {}", e),
        }

        // Add route to WolfNet subnet via gateway so container can reach other WolfNet hosts
        let subnet = "10.10.10.0/24";
        let _ = Command::new("nsenter")
            .args(["--target", &container_pid, "--net", "ip", "route", "replace", subnet, "via", &gateway])
            .output();
    }

    // 5. Configure Host Side
    // Enable forwarding
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.docker0.proxy_arp=1"]).output();

    // iptables FORWARD rules (idempotent — check before adding)
    let check = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", "docker0", "-j", "ACCEPT"]).output();
    if check.map(|o| !o.status.success()).unwrap_or(true) {
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "wolfnet0", "-o", "docker0", "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "docker0", "-o", "wolfnet0", "-j", "ACCEPT"]).output();
    }

    // 6. Add static ARP entry so the host can reach the WolfNet IP without ARP resolution.
    if !container_mac.is_empty() {
        let neigh_result = Command::new("ip")
            .args(["neigh", "replace", ip, "lladdr", &container_mac, "dev", "docker0", "nud", "permanent"])
            .output();
        match &neigh_result {
            Ok(o) if o.status.success() => info!("Static ARP: {} -> {} on docker0", ip, container_mac),
            Ok(o) => info!("neigh replace warning: {}", String::from_utf8_lossy(&o.stderr).trim()),
            Err(e) => info!("neigh replace failed: {}", e),
        }
    } else {
        // Fallback: if we can't get the MAC, look up the container's bridge IP in the ARP table
        // and use that MAC for the WolfNet IP
        info!("MAC not found via inspect, trying ARP table for {}", container_bridge_ip);
        // Ping the bridge IP to populate ARP table
        let _ = Command::new("ping").args(["-c", "1", "-W", "1", &container_bridge_ip]).output();
        if let Ok(output) = Command::new("ip").args(["neigh", "show", &container_bridge_ip, "dev", "docker0"]).output() {
            let line = String::from_utf8_lossy(&output.stdout);
            // Parse: "172.17.0.2 lladdr 02:42:ac:11:00:02 REACHABLE"
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "lladdr" {
                let mac = parts[2];
                info!("Found MAC via ARP: {} -> {}", container_bridge_ip, mac);
                let _ = Command::new("ip")
                    .args(["neigh", "replace", ip, "lladdr", mac, "dev", "docker0", "nud", "permanent"])
                    .output();
                info!("Static ARP (via fallback): {} -> {} on docker0", ip, mac);
            } else {
                info!("Could not find MAC for {} in ARP table: {:?}", container_bridge_ip, line.trim());
            }
        }
    }

    // 7. Route traffic for this WolfNet IP to docker0
    let _ = Command::new("ip").args(["route", "del", &format!("{}/32", ip)]).output();
    let route_result = Command::new("ip")
        .args(["route", "add", &format!("{}/32", ip), "dev", "docker0"])
        .output();

    match route_result {
        Ok(o) if o.status.success() => {
            info!("Host route added: {}/32 dev docker0", ip);
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            info!("Route add note: {}", err.trim());
        }
        Err(e) => {
            return Err(format!("Failed to add host route: {}", e));
        }
    }

    Ok(format!("Container '{}' routed to WolfNet at {}", container, ip))
}

/// Ensure lxcbr0 bridge exists for default LXC container networking (with DHCP/NAT)
pub fn ensure_lxc_bridge() {
    // 1. Try standard systemd service first
    let _ = Command::new("systemctl").args(["enable", "--now", "lxc-net"]).output();
    
    // Wait briefly for service to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if lxcbr0 exists and has an IP
    let bridge_ok = if let Ok(output) = Command::new("ip").args(["addr", "show", "lxcbr0"]).output() {
        if output.status.success() { 
            // Check if dnsmasq is running on it
            let ps = Command::new("pgrep").args(["-f", "dnsmasq.*lxcbr0"]).output();
            ps.map(|p| p.status.success()).unwrap_or(false)
        } else { false }
    } else { false };

    if !bridge_ok {
        info!("Manually configuring lxcbr0 bridge and DHCP");

        // Create bridge (idempotent)
        let _ = Command::new("ip").args(["link", "add", "lxcbr0", "type", "bridge"]).output();
        let _ = Command::new("ip").args(["addr", "add", "10.0.3.1/24", "dev", "lxcbr0"]).output();
        let _ = Command::new("ip").args(["link", "set", "lxcbr0", "up"]).output();

        // Start dnsmasq for DHCP
        let _ = std::fs::create_dir_all("/run/lxc");
        let _ = Command::new("dnsmasq")
            .args([
                "--strict-order",
                "--bind-interfaces",
                "--pid-file=/run/lxc/dnsmasq.pid",
                "--listen-address", "10.0.3.1",
                "--dhcp-range", "10.0.3.2,10.0.3.254",
                "--dhcp-lease-max=253",
                "--dhcp-no-override",
                "--except-interface=lo",
                "--interface=lxcbr0",
                "--conf-file=" // avoid reading /etc/dnsmasq.conf
            ])
            .spawn(); // Run in background
    }

    // ALWAYS force the bridge UP (it can exist but be DOWN if no interfaces are attached yet)
    let _ = Command::new("ip").args(["link", "set", "lxcbr0", "up"]).output();

    // ALWAYS ensure NAT + forwarding for internet access (even if lxc-net is running)
    let _ = Command::new("sh").args(["-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]).output();
    let nat_check = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-s", "10.0.3.0/24", "!", "-d", "10.0.3.0/24", "-j", "MASQUERADE"])
        .output();
    if nat_check.map(|o| !o.status.success()).unwrap_or(true) {
        info!("Adding NAT masquerade for lxcbr0 -> internet");
        let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.0.3.0/24", "!", "-d", "10.0.3.0/24", "-j", "MASQUERADE"]).output();
    }
    let fwd_check = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", "lxcbr0", "-j", "ACCEPT"])
        .output();
    if fwd_check.map(|o| !o.status.success()).unwrap_or(true) {
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "lxcbr0", "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-o", "lxcbr0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();
    }
}

/// Configure an LXC container's network to use WolfNet
pub fn lxc_attach_wolfnet(container: &str, ip: &str) -> Result<String, String> {
    info!("Configuring LXC container {} for wolfnet with IP {}", container, ip);

    // wolfnet0 is a TUN device — can't be bridged.
    // Instead, save the WolfNet IP as a marker; it will be applied inside the
    // container at start time via lxc-attach + host routing.
    let marker_dir = format!("/var/lib/lxc/{}/.wolfnet", container);
    let _ = std::fs::create_dir_all(&marker_dir);
    if let Err(e) = std::fs::write(format!("{}/ip", marker_dir), ip) {
        return Err(format!("Failed to save WolfNet IP: {}", e));
    }

    // If the container is already running, apply immediately (no restart needed)
    let running = Command::new("lxc-info")
        .args(["-n", container, "-sH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
        .unwrap_or(false);

    if running {
        info!("Container {} is running — applying WolfNet IP {} immediately", container, ip);
        lxc_apply_wolfnet(container);
        Ok(format!("LXC container '{}' now using WolfNet IP {} (applied live)", container, ip))
    } else {
        Ok(format!("LXC container '{}' will use WolfNet IP {} on start", container, ip))
    }
}

/// Get the bridge IP assigned to a container's interface (e.g. wn0)
fn get_container_bridge_ip(container: &str, iface: &str) -> String {
    if let Ok(output) = Command::new("lxc-attach")
        .args(["-n", container, "--", "ip", "-4", "addr", "show", iface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "inet 10.0.3.x/24" from ip addr output
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("inet ") {
                if let Some(addr) = rest.split('/').next() {
                    if addr.starts_with("10.0.3.") {
                        return addr.to_string();
                    }
                }
            }
        }
    }
    // Fallback: assign a fresh bridge IP
    warn!("Could not detect bridge IP for {}:{}, assigning new one", container, iface);
    let last = find_free_bridge_ip();
    format!("10.0.3.{}", last)
}

/// Re-apply host routes for all running LXC containers with WolfNet IPs.
/// Called on WolfStack startup to restore routes that were lost since
/// `lxc_apply_wolfnet` only runs at container start time.
pub fn reapply_wolfnet_routes() {
    let lxc_base = std::path::Path::new("/var/lib/lxc");
    let entries = match std::fs::read_dir(lxc_base) {
        Ok(e) => e,
        Err(_) => return, // No LXC containers at all
    };

    for entry in entries.flatten() {
        let container = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Check if this container has a WolfNet IP
        let ip_file = entry.path().join(".wolfnet/ip");
        let ip = match std::fs::read_to_string(&ip_file) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => continue,
        };

        // Check if the container is actually running
        let running = Command::new("lxc-info")
            .args(["-n", &container, "-sH"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
            .unwrap_or(false);
        if !running { continue; }

        info!("Re-applying WolfNet config for running container {} (ip={})", container, ip);

        // Re-apply the WolfNet IP and routes INSIDE the container.
        // This is critical: lxc-autostart and host reboots don't call lxc_apply_wolfnet(),
        // so the container's WolfNet IP (/32 secondary on wn0/eth0) is lost after restart.
        // lxc_apply_wolfnet handles: bring up wn0, add WolfNet IP, add host route, iptables.
        lxc_apply_wolfnet(&container);
    }

    // Ensure forwarding is on
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.forwarding=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.proxy_arp=1"]).output();
}

/// Apply WolfNet IP inside a running container (called after lxc-start)
fn lxc_apply_wolfnet(container: &str) {
    let ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", container);
    if let Ok(ip) = std::fs::read_to_string(&ip_file) {
        let ip = ip.trim();
        if ip.is_empty() { return; }
        info!("Applying WolfNet IP {} to container {}", ip, container);

        // Wait for container to be ready
        std::thread::sleep(std::time::Duration::from_secs(2));

        // On Proxmox, WolfNet uses wn0 on lxcbr0 (eth0 stays on vmbr0).
        // On standalone LXC, WolfNet uses a secondary IP on eth0 via lxcbr0.
        let is_pve = is_proxmox();
        let wolfnet_iface = if is_pve { "wn0" } else { "eth0" };

        if is_pve {
            // Proxmox: wn0 is on lxcbr0 with NO IP/gateway in pct config.
            // We assign a 10.0.3.x bridge IP for host routing and the WolfNet IP
            // as a secondary /32. No gateway is set on wn0, so eth0's default
            // route via vmbr0 stays intact.
            let bridge_ip = get_container_bridge_ip(container, "wn0");
            info!("Container {} → wn0 bridge={}, wolfnet={}", container, bridge_ip, ip);

            // Bring wn0 up
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "link", "set", "wn0", "up"])
                .output();

            // Assign bridge IP on wn0 for host-side routing (idempotent — addr add ignores dups)
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/24", bridge_ip), "dev", "wn0"])
                .output();

            // Add WolfNet IP as secondary /32 on wn0
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/32", ip), "dev", "wn0"])
                .output();

            // Route WolfNet subnet through wn0 via lxcbr0 gateway — without this,
            // 10.10.10.x traffic goes out via eth0/vmbr0 where WolfNet is unreachable.
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "route", "replace", "10.10.10.0/24", "via", "10.0.3.1", "dev", "wn0"])
                .output();

            // Host route — via bridge IP so traffic for WolfNet IP reaches container
            let _ = Command::new("ip").args(["route", "del", &format!("{}/32", ip)]).output();
            let out = Command::new("ip")
                .args(["route", "add", &format!("{}/32", ip), "via", &bridge_ip, "dev", "lxcbr0"])
                .output();
            if let Ok(ref o) = out {
                if o.status.success() {
                    info!("Host route: {}/32 via {} dev lxcbr0", ip, bridge_ip);
                } else {
                    error!("Host route failed: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
        } else {
            // Standalone LXC: original approach — bridge IP on eth0, WolfNet IP as secondary
            let bridge_ip = assign_container_bridge_ip(container);
            info!("Container {} → bridge={}, wolfnet={}", container, bridge_ip, ip);

            // 1. Write network config files FIRST (assign_container_bridge_ip already did this)
            //    so the restart below picks up the correct IP.

            // 2. Restart networking (try all methods for distro compat)
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "sh", "-c",
                    "systemctl restart systemd-networkd 2>/dev/null; \
                     netplan apply 2>/dev/null; \
                     /etc/init.d/networking restart 2>/dev/null; \
                     true"])
                .output();

            // 3. Flush ALL addresses on eth0 to clear stale IPs from DHCP, NetworkManager,
            //    or old configs. Then re-add exactly the ones we want.
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "addr", "flush", "dev", "eth0"])
                .output();

            // 4. Add bridge IP + wolfnet IP + default route
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/24", bridge_ip), "dev", "eth0"])
                .output();
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/32", ip), "dev", "eth0"])
                .output();
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "route", "replace", "default", "via", "10.0.3.1"])
                .output();

            // Host route — via bridge IP so ARP resolves on lxcbr0
            let _ = Command::new("ip").args(["route", "del", &format!("{}/32", ip)]).output();
            let out = Command::new("ip")
                .args(["route", "add", &format!("{}/32", ip), "via", &bridge_ip, "dev", "lxcbr0"])
                .output();
            if let Ok(ref o) = out {
                if o.status.success() {
                    info!("Host route: {}/32 via {} dev lxcbr0", ip, bridge_ip);
                } else {
                    error!("Host route failed: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
        }

        // Forwarding + iptables (common to both paths)
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.forwarding=1"]).output();
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.proxy_arp=1"]).output();
        let check = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
        if check.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
            let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "lxcbr0", "-o", "wolfnet0", "-j", "ACCEPT"]).output();
        }

        info!("WolfNet ready: {} → wolfnet={}, iface={}", container, ip, wolfnet_iface);
    }
}

/// Find a free IP in 10.0.3.100-254 by checking ALL containers, LXCs, VMs, Docker
fn find_free_bridge_ip() -> u8 {
    let mut used: Vec<u8> = Vec::new();

    // 1. Scan LXC config files (covers stopped containers too)
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            // systemd-networkd
            let net_file = entry.path().join("rootfs/etc/systemd/network/eth0.network");
            if let Ok(content) = std::fs::read_to_string(&net_file) {
                for line in content.lines() {
                    if let Some(addr) = line.strip_prefix("Address=10.0.3.") {
                        if let Some(last) = addr.split('/').next().and_then(|s| s.parse::<u8>().ok()) {
                            used.push(last);
                        }
                    }
                }
            }
            // Netplan
            let netplan_file = entry.path().join("rootfs/etc/netplan/50-wolfstack.yaml");
            if let Ok(content) = std::fs::read_to_string(&netplan_file) {
                for line in content.lines() {
                    let trimmed = line.trim().trim_start_matches("- ");
                    if let Some(addr) = trimmed.strip_prefix("10.0.3.") {
                        if let Some(last) = addr.split('/').next().and_then(|s| s.parse::<u8>().ok()) {
                            used.push(last);
                        }
                    }
                }
            }
            // /etc/network/interfaces
            let ifaces_file = entry.path().join("rootfs/etc/network/interfaces");
            if let Ok(content) = std::fs::read_to_string(&ifaces_file) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("address 10.0.3.") {
                        if let Some(addr) = trimmed.strip_prefix("address 10.0.3.") {
                            if let Ok(last) = addr.trim().parse::<u8>() {
                                used.push(last);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Scan running LXC containers' actual IPs
    for c in lxc_list_all() {
        for ip_str in c.ip_address.split(',') {
            let ip = ip_str.trim().replace(" (lxcbr0)", "").replace(" (eth0)", "");
            if let Some(last) = ip.strip_prefix("10.0.3.") {
                if let Ok(n) = last.trim().parse::<u8>() {
                    used.push(n);
                }
            }
        }
    }

    // 3. Scan Docker containers' IPs
    for c in docker_list_all() {
        for ip_str in c.ip_address.split(',') {
            let ip = ip_str.trim();
            if let Some(last) = ip.strip_prefix("10.0.3.") {
                if let Ok(n) = last.trim().parse::<u8>() {
                    used.push(n);
                }
            }
        }
    }

    // 4. GLOBAL: Scan cluster container cache (all remote nodes' containers)
    //    The heartbeat sync writes container data to /etc/wolfstack/cluster-containers/
    if let Ok(entries) = std::fs::read_dir("/etc/wolfstack/cluster-containers") {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(containers) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                    for c in &containers {
                        if let Some(ips) = c.get("ip_address").and_then(|v| v.as_str()) {
                            for ip_str in ips.split(',') {
                                let ip = ip_str.trim()
                                    .replace(" (lxcbr0)", "").replace(" (eth0)", "");
                                if let Some(last) = ip.strip_prefix("10.0.3.") {
                                    if let Ok(n) = last.trim().parse::<u8>() {
                                        used.push(n);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 5. GLOBAL: Scan WolfRun services for all instance IPs across the cluster
    if let Ok(content) = std::fs::read_to_string("/etc/wolfstack/wolfrun/services.json") {
        if let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            for svc in &services {
                if let Some(instances) = svc.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        // Check bridge_ip field if tracked
                        if let Some(ip) = inst.get("bridge_ip").and_then(|v| v.as_str()) {
                            if let Some(last) = ip.strip_prefix("10.0.3.") {
                                if let Ok(n) = last.trim().parse::<u8>() {
                                    used.push(n);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 6. GLOBAL: Scan IP mappings (port forward destinations may use bridge IPs)
    if let Ok(content) = std::fs::read_to_string("/etc/wolfstack/ip-mappings.json") {
        if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(mappings) = wrapper.get("mappings").and_then(|v| v.as_array()) {
                for m in mappings {
                    // Check all IP fields for bridge IPs
                    for key in &["container_ip", "bridge_ip", "ip"] {
                        if let Some(ip) = m.get(*key).and_then(|v| v.as_str()) {
                            if let Some(last) = ip.strip_prefix("10.0.3.") {
                                if let Ok(n) = last.trim().parse::<u8>() {
                                    used.push(n);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 7. Randomize and check for collision, retry if needed
    used.sort();
    used.dedup();
    for _ in 0..200 {
        let candidate = 100 + (rand_byte() % 155); // 100-254
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    // Fallback: sequential scan
    (100u8..=254).find(|i| !used.contains(i)).unwrap_or(100)
}

/// Assign a bridge IP to a container. If a WolfNet IP is provided, derives the
/// bridge IP from its last octet (10.10.10.101 → 10.0.3.101). Otherwise allocates
/// the next free bridge IP. Writes network config in either case.
fn assign_container_bridge_ip(container: &str) -> String {
    // Try to derive from wolfnet IP (deterministic — no allocation needed)
    let wolfnet_ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", container);
    if let Ok(wolfnet_ip) = std::fs::read_to_string(&wolfnet_ip_file) {
        let wolfnet_ip = wolfnet_ip.trim();
        if let Some(last_octet) = wolfnet_ip.rsplit('.').next() {
            let ip = format!("10.0.3.{}", last_octet);
            write_container_network_config(container, &ip);
            return ip;
        }
    }

    // Fallback: allocate next free bridge IP (for containers without WolfNet)
    let last = find_free_bridge_ip();
    let ip = format!("10.0.3.{}", last);
    write_container_network_config(container, &ip);
    ip
}

/// Write network config to container rootfs — supports systemd-networkd, Netplan,
/// and /etc/network/interfaces for maximum distro compatibility
fn write_container_network_config(container: &str, bridge_ip: &str) {
    let rootfs = format!("/var/lib/lxc/{}/rootfs", container);

    // Method 1: systemd-networkd (Debian Trixie, Arch, etc.)
    let networkd_dir = format!("{}/etc/systemd/network", rootfs);
    if std::path::Path::new(&networkd_dir).exists() {
        let conf = format!(
            "[Match]\nName=eth0\n\n[Network]\nAddress={}/24\nGateway=10.0.3.1\nDNS=10.0.3.1\nDNS=8.8.8.8\n",
            bridge_ip
        );
        let _ = std::fs::write(format!("{}/eth0.network", networkd_dir), &conf);
    }

    // Method 2: Netplan (Ubuntu 18.04+)
    let netplan_dir = format!("{}/etc/netplan", rootfs);
    if std::path::Path::new(&netplan_dir).exists() {
        let conf = format!(
            "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - {}/24\n      routes:\n        - to: default\n          via: 10.0.3.1\n      nameservers:\n        addresses: [10.0.3.1, 8.8.8.8]\n",
            bridge_ip
        );
        // Remove conflicting configs
        if let Ok(entries) = std::fs::read_dir(&netplan_dir) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let _ = std::fs::write(format!("{}/50-wolfstack.yaml", netplan_dir), &conf);
    }

    // Method 3: /etc/network/interfaces (Debian Bullseye/Bookworm, Alpine)
    let ifaces_path = format!("{}/etc/network/interfaces", rootfs);
    if std::path::Path::new(&ifaces_path).exists() {
        let conf = format!(
            "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n    address {}\n    netmask 255.255.255.0\n    gateway 10.0.3.1\n    dns-nameservers 10.0.3.1 8.8.8.8\n",
            bridge_ip
        );
        let _ = std::fs::write(&ifaces_path, &conf);
    }

    // Always write resolv.conf as a fallback
    let resolv_path = format!("{}/etc/resolv.conf", rootfs);
    let _ = std::fs::remove_file(&resolv_path); // might be a symlink
    let _ = std::fs::write(&resolv_path, "nameserver 10.0.3.1\nnameserver 8.8.8.8\n");
}

// ─── Common types ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,    // running, stopped, paused, etc.
    pub created: String,
    pub ports: Vec<String>,
    pub runtime: String,  // "docker" or "lxc"
    pub ip_address: String,
    pub autostart: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStats {
    pub id: String,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_usage: u64,
    pub memory_limit: u64,
    pub memory_percent: f64,
    pub net_input: u64,
    pub net_output: u64,
    pub block_read: u64,
    pub block_write: u64,
    pub pids: u32,
    pub runtime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub name: String,
    pub installed: bool,
    pub running: bool,
    pub version: String,
    pub container_count: usize,
    pub running_count: usize,
}

// ─── Detection ───

/// Check if KVM/QEMU is installed
pub fn kvm_installed() -> bool {
    // Check for qemu-system-x86_64 or virsh
    Command::new("which")
        .arg("qemu-system-x86_64")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    || Command::new("which")
        .arg("virsh")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if Docker is installed and running
pub fn docker_status() -> RuntimeStatus {
    let installed = Command::new("which")
        .arg("docker")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let running = if installed {
        Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        false
    };

    let version = if installed {
        Command::new("docker")
            .args(["--version"])
            .output()
            .ok()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                // "Docker version 24.0.7, build ..." -> "24.0.7"
                s.split("version ").nth(1)
                    .and_then(|v| v.split(',').next())
                    .unwrap_or(&s)
                    .to_string()
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (container_count, running_count) = if running {
        let total = docker_list_all().len();
        let running_c = docker_list_running().len();
        (total, running_c)
    } else {
        (0, 0)
    };

    RuntimeStatus {
        name: "Docker".to_string(),
        installed,
        running,
        version,
        container_count,
        running_count,
    }
}

/// Check if LXC is installed and running
pub fn lxc_status() -> RuntimeStatus {
    let installed = Command::new("which")
        .arg("lxc-ls")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let running = installed; // LXC doesn't have a daemon — it's always "available" if installed

    let version = if installed {
        Command::new("lxc-ls")
            .arg("--version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (container_count, running_count) = if installed {
        let all = lxc_list_all();
        let running_c = all.iter().filter(|c| c.state == "running").count();
        (all.len(), running_c)
    } else {
        (0, 0)
    };

    RuntimeStatus {
        name: "LXC".to_string(),
        installed,
        running,
        version,
        container_count,
        running_count,
    }
}

// ─── Docker operations ───

/// List all Docker containers
pub fn docker_list_all() -> Vec<ContainerInfo> {
    docker_list(true)
}

/// List running Docker containers
pub fn docker_list_running() -> Vec<ContainerInfo> {
    docker_list(false)
}

fn docker_list(all: bool) -> Vec<ContainerInfo> {
    let mut cmd = Command::new("docker");
    cmd.args(["ps", "--format", "{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.State}}\\t{{.CreatedAt}}\\t{{.Ports}}\\t{{.Networks}}", "--no-trunc"]);
    if all {
        cmd.arg("-a");
    }

    cmd.output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    let name = parts.get(1).unwrap_or(&"").to_string();
                    let state = parts.get(4).unwrap_or(&"").to_string();

                    // Get WolfNet IP label and network IPs in one inspect call
                    let inspect_fmt = "{{index .Config.Labels \"wolfnet.ip\"}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}";
                    let inspect_out = Command::new("docker")
                        .args(["inspect", "-f", inspect_fmt, &name])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();

                    let inspect_parts: Vec<&str> = inspect_out.splitn(2, '|').collect();
                    let wolfnet_label = inspect_parts.first().unwrap_or(&"").trim();
                    let raw_net_ips = inspect_parts.get(1).unwrap_or(&"").trim();

                    // Parse WolfNet IP from label (valid even when container is not running)
                    let wolfnet_ip = if !wolfnet_label.is_empty() && wolfnet_label != "<no value>" {
                        let wparts: Vec<&str> = wolfnet_label.split('.').collect();
                        if wparts.len() == 4 && wparts.iter().all(|p| p.parse::<u8>().is_ok()) {
                            Some(wolfnet_label.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Parse bridge/network IP (only valid when running)
                    let bridge_ip = raw_net_ips.split_whitespace()
                        .find(|s| {
                            let iparts: Vec<&str> = s.split('.').collect();
                            iparts.len() == 4 && iparts.iter().all(|p| p.parse::<u8>().is_ok())
                        })
                        .unwrap_or("")
                        .to_string();

                    // Display logic: WolfNet IP is primary if set
                    let ip = if let Some(ref wip) = wolfnet_ip {
                        if state == "running" && !bridge_ip.is_empty() && bridge_ip != *wip {
                            format!("{} (wolfnet)", wip)
                        } else {
                            wip.clone()
                        }
                    } else {
                        bridge_ip
                    };
                    // Parse autostart (RestartPolicy)
                    let restart_policy = Command::new("docker")
                        .args(["inspect", "--format", "{{.HostConfig.RestartPolicy.Name}}", &name])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();
                    let autostart = !restart_policy.is_empty() && restart_policy != "no";

                    // Get Docker storage info
                    let docker_rootfs = Command::new("docker")
                        .args(["inspect", "--format", "{{.GraphDriver.Data.MergedDir}}", &name])
                        .output()
                        .ok()
                        .and_then(|o| {
                            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            if s.is_empty() || s.contains("no value") { None } else { Some(s) }
                        });
                    let (du, dt, ft) = docker_rootfs.as_ref()
                        .map(|p| get_path_disk_usage(p))
                        .unwrap_or((None, None, None));

                    ContainerInfo {
                        id: parts.first().unwrap_or(&"").to_string(),
                        name,
                        image: parts.get(2).unwrap_or(&"").to_string(),
                        status: parts.get(3).unwrap_or(&"").to_string(),
                        state: parts.get(4).unwrap_or(&"").to_string(),
                        created: parts.get(5).unwrap_or(&"").to_string(),
                        ports: parts.get(6).unwrap_or(&"")
                            .split(", ")
                            .filter(|p| !p.is_empty())
                            .map(|p| p.to_string())
                            .collect(),
                        runtime: "docker".to_string(),
                        ip_address: ip,
                        autostart,
                        hostname: String::new(),
                        storage_path: docker_rootfs,
                        disk_usage: du,
                        disk_total: dt,
                        fs_type: ft,
                        version: None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Get Docker container stats (one-shot)
pub fn docker_stats() -> Vec<ContainerStats> {
    Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{.ID}}\\t{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.MemPerc}}\\t{{.NetIO}}\\t{{.BlockIO}}\\t{{.PIDs}}"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    let cpu_str = parts.get(2).unwrap_or(&"0%").trim_end_matches('%');
                    let mem_usage = parse_docker_mem(parts.get(3).unwrap_or(&"0B / 0B"));
                    let mem_perc = parts.get(4).unwrap_or(&"0%").trim_end_matches('%');
                    let net_io = parse_docker_io(parts.get(5).unwrap_or(&"0B / 0B"));
                    let block_io = parse_docker_io(parts.get(6).unwrap_or(&"0B / 0B"));

                    ContainerStats {
                        id: parts.first().unwrap_or(&"").to_string(),
                        name: parts.get(1).unwrap_or(&"").to_string(),
                        cpu_percent: cpu_str.parse().unwrap_or(0.0),
                        memory_usage: mem_usage.0,
                        memory_limit: mem_usage.1,
                        memory_percent: mem_perc.parse().unwrap_or(0.0),
                        net_input: net_io.0,
                        net_output: net_io.1,
                        block_read: block_io.0,
                        block_write: block_io.1,
                        pids: parts.get(7).unwrap_or(&"0").parse().unwrap_or(0),
                        runtime: "docker".to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Get Docker container logs
pub fn docker_logs(container: &str, lines: u32) -> Vec<String> {
    Command::new("docker")
        .args(["logs", "--tail", &lines.to_string(), "--timestamps", container])
        .output()
        .ok()
        .map(|o| {
            let mut logs: Vec<String> = Vec::new();
            // Docker logs go to both stdout and stderr
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            logs.extend(stdout.lines().map(|l| l.to_string()));
            logs.extend(stderr.lines().map(|l| l.to_string()));
            logs
        })
        .unwrap_or_default()
}

/// Start a Docker container
pub fn docker_start(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["start", container])?;

    // Re-apply WolfNet IP if configured
    // Check if container has a wolfnet label
    if let Ok(output) = Command::new("docker")
        .args(["inspect", "--format", "{{index .Config.Labels \"wolfnet.ip\"}}", container])
        .output()
    {
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !ip.is_empty() && ip != "<no value>" {
            info!("Re-applying WolfNet IP {} to Docker container {}", ip, container);
            std::thread::sleep(std::time::Duration::from_secs(1));
            if let Err(e) = docker_connect_wolfnet(container, &ip) {
                info!("WolfNet re-apply warning: {}", e);
            }
        }
    }

    Ok(result)
}

/// Stop a Docker container
pub fn docker_stop(container: &str) -> Result<String, String> {
    run_docker_cmd(&["stop", container])
}

/// Restart a Docker container
pub fn docker_restart(container: &str) -> Result<String, String> {
    run_docker_cmd(&["restart", container])
}

/// Remove a Docker container
pub fn docker_remove(container: &str) -> Result<String, String> {
    run_docker_cmd(&["rm", "-f", container])
}

/// Pause a Docker container
pub fn docker_pause(container: &str) -> Result<String, String> {
    run_docker_cmd(&["pause", container])
}

/// Unpause a Docker container
pub fn docker_unpause(container: &str) -> Result<String, String> {
    run_docker_cmd(&["unpause", container])
}

/// List Docker images
pub fn docker_images() -> Vec<ContainerImage> {
    Command::new("docker")
        .args(["images", "--format", "{{.ID}}\\t{{.Repository}}\\t{{.Tag}}\\t{{.Size}}\\t{{.CreatedAt}}"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    ContainerImage {
                        id: parts.first().unwrap_or(&"").to_string(),
                        repository: parts.get(1).unwrap_or(&"").to_string(),
                        tag: parts.get(2).unwrap_or(&"").to_string(),
                        size: parts.get(3).unwrap_or(&"").to_string(),
                        created: parts.get(4).unwrap_or(&"").to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Update Docker container configuration
pub fn docker_update_config(container: &str, autostart: Option<bool>, memory_mb: Option<u64>, cpus: Option<f32>) -> Result<String, String> {
    let mut args = vec!["update"];
    
    // Autostart policy
    let policy_str;
    if let Some(autostart) = autostart {
        policy_str = if autostart { "unless-stopped" } else { "no" };
        args.push("--restart");
        args.push(policy_str);
    }

    // Memory limit
    let mem_str;
    if let Some(mem) = memory_mb {
        mem_str = format!("{}m", mem);
        args.push("--memory");
        args.push(&mem_str);
    }

    // CPU limit
    let cpus_str;
    if let Some(c) = cpus {
        cpus_str = format!("{}", c);
        args.push("--cpus");
        args.push(&cpus_str);
    }

    if args.len() == 1 {
        return Ok("No changes requested".to_string());
    }

    args.push(container);
    run_docker_cmd(&args)
}

/// Inspect a Docker container and return raw JSON
pub fn docker_inspect(container: &str) -> Result<serde_json::Value, String> {
    let output = Command::new("docker")
        .args(["inspect", container])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    // docker inspect returns an array, take the first element if possible
    if let Some(arr) = json.as_array() {
        if let Some(obj) = arr.first() {
            return Ok(obj.clone());
        }
    }
    
    // If not array or empty array
    Ok(json)
}

/// Remove a Docker image by ID or name
pub fn docker_remove_image(image: &str) -> Result<String, String> {
    info!("Removing Docker image: {}", image);
    run_docker_cmd(&["rmi", image])
}

fn run_docker_cmd(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run docker: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

// ─── LXC operations ───

/// List all LXC containers
pub fn lxc_list_all() -> Vec<ContainerInfo> {
    // Detect if Proxmox is available (pct command exists)
    let is_proxmox = Command::new("which").arg("pct").output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if is_proxmox {
        // Use pct list for Proxmox — only lists containers Proxmox knows about
        return pct_list_all();
    }

    // Fallback: native LXC
    Command::new("lxc-ls")
        .args(["-f", "-F", "NAME,STATE,PID,RAM,IPV4"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .skip(1) // Skip header
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let name = parts.first().unwrap_or(&"").to_string();
                    let state = parts.get(1).unwrap_or(&"STOPPED").to_lowercase();
                    let status = if state == "running" {
                        format!("Running (PID {})", parts.get(2).unwrap_or(&"-"))
                    } else {
                        "Stopped".to_string()
                    };

                    // IP address: try multiple methods
                    let mut ip = String::new();

                    if state == "running" {
                        // Method 1: Use lxc-info which reliably reports IP
                        if let Ok(info_out) = Command::new("lxc-info")
                            .args(["-n", &name, "-iH"])
                            .output()
                        {
                            let info_ip = String::from_utf8_lossy(&info_out.stdout)
                                .lines()
                                .filter(|l| !l.contains(':')) // Filter out IPv6 addresses
                                .collect::<Vec<_>>()
                                .join(", ");
                            if !info_ip.is_empty() && info_ip != "-" {
                                ip = info_ip;
                            }
                        }
                    }

                    // Method 2: If still no IP, try from lxc-ls output (after RAM column)
                    if ip.is_empty() {
                        // Skip NAME(0), STATE(1), PID(2), RAM(3), rest is IPV4
                        let lxc_ip = parts.get(4..).map(|p| p.join(" ")).unwrap_or_default()
                            .replace("-", "");
                        if !lxc_ip.trim().is_empty() {
                            ip = lxc_ip.trim().to_string();
                        }
                    }

                    // Method 3: Check for WolfNet IP marker
                    let wolfnet_ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", name);
                    let wolfnet_ip = std::fs::read_to_string(&wolfnet_ip_file)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if !wolfnet_ip.is_empty() {
                        if ip.is_empty() {
                            ip = format!("{} (wolfnet)", wolfnet_ip);
                        } else if !ip.contains(&wolfnet_ip) {
                            ip = format!("{}, {} (wolfnet)", ip, wolfnet_ip);
                        }
                    }

                    // Read config for autostart and hostname
                    let config_path = format!("/var/lib/lxc/{}/config", name);
                    let config_content = std::fs::read_to_string(&config_path).unwrap_or_default();
                    let autostart = config_content.lines().any(|l| l.trim() == "lxc.start.auto = 1");
                    let hostname = config_content.lines()
                        .find(|l| l.trim().starts_with("lxc.uts.name"))
                        .and_then(|l| l.split('=').nth(1))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();

                    // Get LXC rootfs path and disk usage
                    let rootfs_path = format!("/var/lib/lxc/{}/rootfs", name);
                    let storage_path = if std::path::Path::new(&rootfs_path).exists() {
                        Some(rootfs_path.clone())
                    } else { None };
                    let (du, dt, ft) = get_path_disk_usage(&rootfs_path);

                    let version = lxc_read_os_version(&rootfs_path);

                    ContainerInfo {
                        id: name.clone(),
                        name,
                        image: "lxc".to_string(),
                        status,
                        state,
                        created: String::new(),
                        ports: vec![],
                        runtime: "lxc".to_string(),
                        ip_address: ip,
                        autostart,
                        hostname,
                        storage_path,
                        disk_usage: du,
                        disk_total: dt,
                        fs_type: ft,
                        version,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// List LXC containers using Proxmox's pct command (filters out stale containers)
fn pct_list_all() -> Vec<ContainerInfo> {
    let output = match Command::new("pct").arg("list").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };

    output.lines()
        .skip(1) // Skip header: VMID       Status     Lock         Name
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let vmid = parts.first()?.to_string();
            let state = parts.get(1).unwrap_or(&"stopped").to_lowercase();
            let pct_name = parts.get(2..).map(|p| p.join(" ")).unwrap_or_default();

            let status = if state == "running" {
                // Get PID from lxc-info
                let pid = Command::new("lxc-info")
                    .args(["-n", &vmid, "-pH"])
                    .output().ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or("-".to_string());
                format!("Running (PID {})", pid)
            } else {
                "Stopped".to_string()
            };

            // Get IP addresses for running containers
            let mut ip = String::new();
            if state == "running" {
                if let Ok(info_out) = Command::new("lxc-info")
                    .args(["-n", &vmid, "-iH"])
                    .output()
                {
                    let info_ip = String::from_utf8_lossy(&info_out.stdout)
                        .lines()
                        .filter(|l| !l.contains(':'))
                        .collect::<Vec<_>>()
                        .join(", ");
                    if !info_ip.is_empty() && info_ip != "-" {
                        ip = info_ip;
                    }
                }
            }

            // Read hostname, autostart, and rootfs from pct config (Proxmox format)
            let mut hostname = pct_name.clone();
            let mut autostart = false;
            let mut rootfs_storage = String::new();
            if let Ok(cfg_out) = Command::new("pct").args(["config", &vmid]).output() {
                let cfg_text = String::from_utf8_lossy(&cfg_out.stdout);
                for cline in cfg_text.lines() {
                    let cline = cline.trim();
                    if cline.starts_with("hostname:") {
                        hostname = cline.split(':').nth(1).unwrap_or("").trim().to_string();
                    } else if cline.starts_with("onboot:") {
                        autostart = cline.split(':').nth(1).unwrap_or("").trim() == "1";
                    } else if cline.starts_with("rootfs:") {
                        rootfs_storage = cline.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
                    }
                    // Also extract IPs from net* lines for stopped containers
                    if ip.is_empty() && cline.starts_with("net") && cline.contains("ip=") {
                        if let Some(ip_part) = cline.split(',').find(|p| p.trim().starts_with("ip=")) {
                            let configured_ip = ip_part.trim().trim_start_matches("ip=");
                            if !configured_ip.is_empty() && configured_ip != "dhcp" {
                                ip = configured_ip.to_string();
                            }
                        }
                    }
                }
            }

            // WolfNet IP
            let wolfnet_ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", vmid);
            let wolfnet_ip = std::fs::read_to_string(&wolfnet_ip_file)
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if !wolfnet_ip.is_empty() {
                if ip.is_empty() {
                    ip = format!("{} (wolfnet)", wolfnet_ip);
                } else if !ip.contains(&wolfnet_ip) {
                    ip = format!("{}, {} (wolfnet)", ip, wolfnet_ip);
                }
            }

            let rootfs_path = format!("/var/lib/lxc/{}/rootfs", vmid);
            let storage_path = if !rootfs_storage.is_empty() {
                Some(rootfs_storage.clone())
            } else if std::path::Path::new(&rootfs_path).exists() {
                Some(rootfs_path.clone())
            } else { None };

            // For Proxmox containers, get per-container disk usage instead of pool-level stats.
            // Running: use `pct exec {vmid} -- df -T --block-size=1 /` to get rootfs usage inside the CT.
            // Stopped: parse the allocated size from rootfs config (e.g. "size=32G").
            let (du, dt, ft) = if state == "running" {
                // Try to get actual disk usage from inside the container
                match Command::new("pct").args(["exec", &vmid, "--", "df", "-T", "--block-size=1", "/"]).output() {
                    Ok(out) if out.status.success() => {
                        let text = String::from_utf8_lossy(&out.stdout);
                        if let Some(line) = text.lines().nth(1) {
                            let p: Vec<&str> = line.split_whitespace().collect();
                            let fs = p.get(1).map(|s| s.to_string());
                            let total = p.get(2).and_then(|s| s.parse::<u64>().ok());
                            let used  = p.get(3).and_then(|s| s.parse::<u64>().ok());
                            (used, total, fs)
                        } else {
                            (None, None, None)
                        }
                    }
                    _ => (None, None, None),
                }
            } else {
                // Stopped container — parse allocated size from rootfs config
                let alloc_bytes = parse_pct_rootfs_size(&rootfs_storage);
                (Some(0), alloc_bytes, None)
            };

            let pve_rootfs_path = format!("/var/lib/lxc/{}/rootfs", vmid);
            let version = lxc_read_os_version(&pve_rootfs_path);

            Some(ContainerInfo {
                id: vmid.clone(),
                name: vmid,
                image: "lxc".to_string(),
                status,
                state,
                created: String::new(),
                ports: vec![],
                runtime: "lxc".to_string(),
                ip_address: ip,
                autostart,
                hostname,
                storage_path,
                disk_usage: du,
                disk_total: dt,
                fs_type: ft,
                version,
            })
        })
        .collect()
}

/// Read OS version from an LXC container's rootfs (e.g. "Ubuntu 22.04.3 LTS")
fn lxc_read_os_version(rootfs_path: &str) -> Option<String> {
    // Try /etc/os-release first (standard on modern distros)
    let os_release_path = format!("{}/etc/os-release", rootfs_path);
    if let Ok(content) = std::fs::read_to_string(&os_release_path) {
        // Look for PRETTY_NAME first, then NAME + VERSION
        let mut pretty_name = None;
        let mut name = None;
        let mut version = None;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("PRETTY_NAME=") {
                pretty_name = Some(line.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"').to_string());
            } else if line.starts_with("NAME=") {
                name = Some(line.trim_start_matches("NAME=")
                    .trim_matches('"').to_string());
            } else if line.starts_with("VERSION=") {
                version = Some(line.trim_start_matches("VERSION=")
                    .trim_matches('"').to_string());
            }
        }
        if let Some(pn) = pretty_name {
            if !pn.is_empty() { return Some(pn); }
        }
        if let (Some(n), Some(v)) = (name, version) {
            return Some(format!("{} {}", n, v));
        }
    }
    // Fallback: try /etc/lsb-release
    let lsb_path = format!("{}/etc/lsb-release", rootfs_path);
    if let Ok(content) = std::fs::read_to_string(&lsb_path) {
        for line in content.lines() {
            if line.starts_with("DISTRIB_DESCRIPTION=") {
                return Some(line.trim_start_matches("DISTRIB_DESCRIPTION=")
                    .trim_matches('"').to_string());
            }
        }
    }
    None
}

/// Get disk usage for a path using df (returns used_bytes, total_bytes)
fn get_path_disk_usage(path: &str) -> (Option<u64>, Option<u64>, Option<String>) {
    // df -T --block-size=1 outputs: Filesystem Type 1B-blocks Used Available Use% Mounted
    if let Ok(out) = Command::new("df").args(["-T", "--block-size=1", path]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = text.lines().nth(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let fs_type = parts.get(1).map(|s| s.to_string());
            let total = parts.get(2).and_then(|s| s.parse::<u64>().ok());
            let used  = parts.get(3).and_then(|s| s.parse::<u64>().ok());
            return (used, total, fs_type);
        }
    }
    (None, None, None)
}

/// Parse the allocated rootfs size from a Proxmox rootfs config string.
/// Example input: "local-lvm:vm-101-disk-0,size=32G" → Some(34359738368)
fn parse_pct_rootfs_size(rootfs_cfg: &str) -> Option<u64> {
    // Look for "size=NNN[GMTK]" in the rootfs config
    for part in rootfs_cfg.split(',') {
        let p = part.trim();
        if p.starts_with("size=") {
            let size_str = p.trim_start_matches("size=");
            // Parse number + optional suffix (G, M, T, K)
            let (num_part, multiplier) = if size_str.ends_with('T') {
                (&size_str[..size_str.len()-1], 1024u64 * 1024 * 1024 * 1024)
            } else if size_str.ends_with('G') {
                (&size_str[..size_str.len()-1], 1024u64 * 1024 * 1024)
            } else if size_str.ends_with('M') {
                (&size_str[..size_str.len()-1], 1024u64 * 1024)
            } else if size_str.ends_with('K') {
                (&size_str[..size_str.len()-1], 1024u64)
            } else {
                (size_str, 1024u64 * 1024 * 1024) // Default to GiB
            };
            if let Ok(n) = num_part.parse::<f64>() {
                return Some((n * multiplier as f64) as u64);
            }
        }
    }
    None
}

/// Get LXC container stats
pub fn lxc_stats() -> Vec<ContainerStats> {
    let containers = lxc_list_all();
    containers.iter()
        .filter(|c| c.state == "running")
        .map(|c| {
            let info = lxc_info(&c.name);
            ContainerStats {
                id: c.name.clone(),
                name: c.name.clone(),
                cpu_percent: info.cpu_percent,
                memory_usage: info.memory_usage,
                memory_limit: info.memory_limit,
                memory_percent: if info.memory_limit > 0 {
                    (info.memory_usage as f64 / info.memory_limit as f64) * 100.0
                } else {
                    0.0
                },
                net_input: info.net_input,
                net_output: info.net_output,
                block_read: 0,
                block_write: 0,
                pids: info.pids,
                runtime: "lxc".to_string(),
            }
        })
        .collect()
}

struct LxcDetailInfo {
    cpu_percent: f64,
    memory_usage: u64,
    memory_limit: u64,
    net_input: u64,
    net_output: u64,
    pids: u32,
}

fn lxc_info(name: &str) -> LxcDetailInfo {
    // Memory usage via lxc-cgroup (works on cgroup v1 and v2)
    let memory_usage = lxc_cgroup_read(name, "memory.current")
        .or_else(|| lxc_cgroup_read(name, "memory.usage_in_bytes"))
        .unwrap_or(0);

    let memory_limit = lxc_cgroup_read(name, "memory.max")
        .or_else(|| lxc_cgroup_read(name, "memory.limit_in_bytes"))
        .unwrap_or(0);

    // CPU — use lxc-attach to read /proc/stat quickly
    let cpu_percent = lxc_cpu_percent(name);

    // PID count
    let pids = Command::new("lxc-info")
        .args(["-n", name, "-pH"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);

    // Network
    let (net_in, net_out) = read_container_net(name);

    LxcDetailInfo {
        cpu_percent,
        memory_usage,
        memory_limit,
        net_input: net_in,
        net_output: net_out,
        pids,
    }
}

/// Get LXC container logs from journal
pub fn lxc_logs(container: &str, lines: u32) -> Vec<String> {
    // Try getting logs from lxc-attach dmesg or journal
    Command::new("lxc-attach")
        .args(["-n", container, "--", "journalctl", "--no-pager", "-n", &lines.to_string()])
        .output()
        .ok()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            if out.trim().is_empty() {
                // Fallback: read from syslog
                Command::new("lxc-attach")
                    .args(["-n", container, "--", "cat", "/var/log/syslog"])
                    .output()
                    .ok()
                    .map(|o2| {
                        String::from_utf8_lossy(&o2.stdout)
                            .lines()
                            .rev()
                            .take(lines as usize)
                            .map(|l| l.to_string())
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                out.lines().map(|l| l.to_string()).collect()
            }
        })
        .unwrap_or_default()
}

/// Set the root password on an LXC container
/// Writes password hash directly to rootfs /etc/shadow (no need to start container)
pub fn lxc_set_root_password(container: &str, password: &str) -> Result<String, String> {
    info!("Setting root password for LXC container {}", container);

    // Generate password hash using openssl
    let hash_output = Command::new("openssl")
        .args(["passwd", "-6", password])
        .output()
        .map_err(|e| format!("Failed to generate password hash: {}", e))?;

    if !hash_output.status.success() {
        return Err("Failed to generate password hash".to_string());
    }

    let hash = String::from_utf8_lossy(&hash_output.stdout).trim().to_string();

    // Find the rootfs — could be in default path or custom storage
    let shadow_path = format!("/var/lib/lxc/{}/rootfs/etc/shadow", container);
    
    if let Ok(shadow) = std::fs::read_to_string(&shadow_path) {
        let new_shadow: String = shadow.lines().map(|line| {
            if line.starts_with("root:") {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() >= 3 {
                    format!("root:{}:{}", hash, parts[2])
                } else {
                    format!("root:{}:19000:0:99999:7:::", hash)
                }
            } else {
                line.to_string()
            }
        }).collect::<Vec<_>>().join("\n");

        // Preserve trailing newline
        let new_shadow = if shadow.ends_with('\n') && !new_shadow.ends_with('\n') {
            format!("{}\n", new_shadow)
        } else {
            new_shadow
        };

        std::fs::write(&shadow_path, new_shadow)
            .map_err(|e| format!("Failed to write shadow file: {}", e))?;

        Ok("Root password set".to_string())
    } else {
        Err(format!("Shadow file not found at {}", shadow_path))
    }
}

/// Start an LXC container
pub fn lxc_start(container: &str) -> Result<String, String> {
    ensure_lxc_bridge();
    let result = if is_proxmox() {
        run_lxc_cmd(&["pct", "start", container])
    } else {
        run_lxc_cmd(&["lxc-start", "-n", container])
    };
    
    // Apply WolfNet IP if configured
    if result.is_ok() {
        lxc_apply_wolfnet(container);
        lxc_post_start_setup(container);
    }
    
    result
}

/// First-boot setup for LXC containers (runs once)
fn lxc_post_start_setup(container: &str) {
    let marker = format!("/var/lib/lxc/{}/.wolfstack_setup_done", container);
    if std::path::Path::new(&marker).exists() { return; }

    info!("Running first-boot setup for container {}", container);

    // Assign a unique bridge IP if not already configured by WolfNet
    let wolfnet_file = format!("/var/lib/lxc/{}/.wolfnet/ip", container);
    if !std::path::Path::new(&wolfnet_file).exists() {
        let bridge_ip = assign_container_bridge_ip(container);
        info!("Assigned bridge IP {} to container {}", bridge_ip, container);
        // Apply immediately
        let _ = Command::new("lxc-attach")
            .args(["-n", container, "--", "ip", "addr", "flush", "dev", "eth0"])
            .output();
        let _ = Command::new("lxc-attach")
            .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/24", bridge_ip), "dev", "eth0"])
            .output();
        let _ = Command::new("lxc-attach")
            .args(["-n", container, "--", "ip", "route", "replace", "default", "via", "10.0.3.1"])
            .output();
        // Restart networking (multi-distro)
        let _ = Command::new("lxc-attach")
            .args(["-n", container, "--", "sh", "-c",
                "systemctl restart systemd-networkd 2>/dev/null; \
                 netplan apply 2>/dev/null; \
                 /etc/init.d/networking restart 2>/dev/null; \
                 true"])
            .output();
    }

    // Wait for container networking to settle
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Install openssh-server
    let ssh_install = Command::new("lxc-attach")
        .args(["-n", container, "--", "sh", "-c",
            "apt-get update -qq && apt-get install -y -qq openssh-server 2>/dev/null || \
             yum install -y openssh-server 2>/dev/null || \
             apk add openssh 2>/dev/null"])
        .output();

    let ssh_ok = ssh_install.as_ref().map(|o| o.status.success()).unwrap_or(false);

    if ssh_ok {
        // Enable root SSH login and start sshd
        let _ = Command::new("lxc-attach")
            .args(["-n", container, "--", "sh", "-c",
                "sed -i 's/#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null; \
                 sed -i 's/#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null; \
                 mkdir -p /run/sshd; \
                 systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || /usr/sbin/sshd 2>/dev/null || true; \
                 systemctl enable sshd 2>/dev/null || update-rc.d ssh enable 2>/dev/null || true"])
            .output();
        info!("SSH installed and configured for container {}", container);
    } else {
        info!("SSH install failed for {} (no network?), will retry next boot", container);
    }

    // Create WolfStack MOTD — write directly to rootfs (avoids shell escaping issues)
    let motd_path = format!("/var/lib/lxc/{}/rootfs/etc/motd", container);
    let _ = std::fs::write(&motd_path, r#"
 __        __    _  __ ____  _             _
 \ \      / /__ | |/ _/ ___|| |_ __ _  ___| | __
  \ \ /\ / / _ \| | |_\___ \| __/ _` |/ __| |/ /
   \ V  V / (_) | |  _|___) | || (_| | (__|   <
    \_/\_/ \___/|_|_| |____/ \__\__,_|\___|_|\_\

  Managed by WolfStack — wolf.uk.com
  Container powered by Wolf Software Systems Ltd

"#);

    // Only mark done if SSH was installed successfully
    if ssh_ok {
        let _ = std::fs::write(&marker, "done");
        info!("First-boot setup complete for container {}", container);
    }
}

/// Stop an LXC container
pub fn lxc_stop(container: &str) -> Result<String, String> {
    if is_proxmox() {
        run_lxc_cmd(&["pct", "stop", container])
    } else {
        run_lxc_cmd(&["lxc-stop", "-n", container])
    }
}

/// Restart an LXC container
pub fn lxc_restart(container: &str) -> Result<String, String> {
    lxc_stop(container)?;
    lxc_start(container)
}

/// Freeze (pause) an LXC container
pub fn lxc_freeze(container: &str) -> Result<String, String> {
    if is_proxmox() {
        run_lxc_cmd(&["pct", "suspend", container])
    } else {
        run_lxc_cmd(&["lxc-freeze", "-n", container])
    }
}

/// Unfreeze an LXC container
pub fn lxc_unfreeze(container: &str) -> Result<String, String> {
    if is_proxmox() {
        run_lxc_cmd(&["pct", "resume", container])
    } else {
        run_lxc_cmd(&["lxc-unfreeze", "-n", container])
    }
}

/// Destroy an LXC container
pub fn lxc_destroy(container: &str) -> Result<String, String> {
    lxc_stop(container).ok(); // Stop first, ignore errors
    if is_proxmox() {
        run_lxc_cmd(&["pct", "destroy", container])
    } else {
        run_lxc_cmd(&["lxc-destroy", "-n", container])
    }
}

/// Read LXC container config
pub fn lxc_config(container: &str) -> Option<String> {
    let path = format!("/var/lib/lxc/{}/config", container);
    std::fs::read_to_string(&path).ok()
}

/// Save LXC container config (creates .bak backup first)
pub fn lxc_save_config(container: &str, content: &str) -> Result<String, String> {
    let path = format!("/var/lib/lxc/{}/config", container);
    if !std::path::Path::new(&path).exists() {
        return Err(format!("Container '{}' config not found", container));
    }
    let backup = format!("{}.bak", path);
    let _ = std::fs::copy(&path, &backup);
    std::fs::write(&path, content)
        .map(|_| format!("Config saved for '{}'", container))
        .map_err(|e| format!("Failed to save config: {}", e))
}

/// Structured representation of a single LXC network interface
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LxcNetInterface {
    pub index: u32,
    pub net_type: String,      // veth, etc.
    pub link: String,          // bridge name
    pub name: String,          // interface name inside container (eth0)
    pub hwaddr: String,        // MAC address
    pub ipv4: String,          // e.g. "192.168.1.100/24" or "" for DHCP
    pub ipv4_gw: String,       // gateway
    pub ipv6: String,
    pub ipv6_gw: String,
    pub firewall: bool,
    pub mtu: String,
    pub vlan: String,
    pub flags: String,         // e.g. "up"
}

/// Structured representation of an LXC config
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LxcParsedConfig {
    // General
    pub hostname: String,
    pub arch: String,
    pub autostart: bool,
    pub start_delay: u32,
    pub start_order: u32,
    pub unprivileged: bool,

    // Network — flat fields kept for backward compat (populated from net.0)
    pub net_type: String,
    pub net_link: String,
    pub net_name: String,
    pub net_hwaddr: String,
    pub net_ipv4: String,
    pub net_ipv4_gw: String,
    pub net_ipv6: String,
    pub net_ipv6_gw: String,
    pub net_firewall: bool,
    pub net_mtu: String,
    pub net_vlan: String,

    // All network interfaces
    pub network_interfaces: Vec<LxcNetInterface>,

    // Resources
    pub memory_limit: String,  // e.g. "1G", "512M"
    pub swap_limit: String,
    pub cpus: String,          // cpuset e.g. "0-3"
    pub cpu_shares: String,

    // Features
    pub tun_enabled: bool,
    pub fuse_enabled: bool,
    pub nesting_enabled: bool,
    pub nfs_enabled: bool,
    pub keyctl_enabled: bool,

    // Raw config for advanced editing
    pub raw_config: String,

    // WolfNet
    pub wolfnet_ip: String,
}
/// Parse a Proxmox-format config (/etc/pve/lxc/<vmid>.conf)
/// Format: `key: value` with network as `net0: name=eth0,bridge=vmbr0,hwaddr=...,ip=...,gw=...`
fn parse_proxmox_config(mut cfg: LxcParsedConfig, content: &str, container: &str) -> LxcParsedConfig {
    let mut net_map: std::collections::BTreeMap<u32, LxcNetInterface> = std::collections::BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }

        // Proxmox format: "key: value"
        let (key, val) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        // Network interfaces: net0, net1, etc.
        if key.starts_with("net") {
            if let Ok(idx) = key[3..].parse::<u32>() {
                let nic = net_map.entry(idx).or_insert_with(|| LxcNetInterface {
                    index: idx,
                    ..Default::default()
                });
                // Parse comma-separated key=value pairs
                for part in val.split(',') {
                    let part = part.trim();
                    if let Some((pk, pv)) = part.split_once('=') {
                        match pk.trim() {
                            "name" => nic.name = pv.to_string(),
                            "bridge" => nic.link = pv.to_string(),
                            "hwaddr" => nic.hwaddr = pv.to_string(),
                            "ip" => {
                                if pv != "dhcp" {
                                    nic.ipv4 = pv.to_string();
                                }
                            }
                            "gw" => nic.ipv4_gw = pv.to_string(),
                            "ip6" => {
                                if pv != "dhcp" && pv != "auto" {
                                    nic.ipv6 = pv.to_string();
                                }
                            }
                            "gw6" => nic.ipv6_gw = pv.to_string(),
                            "type" => nic.net_type = pv.to_string(),
                            "mtu" => nic.mtu = pv.to_string(),
                            "tag" => nic.vlan = pv.to_string(),
                            "firewall" => nic.firewall = pv == "1",
                            "rate" => {} // bandwidth limit, ignore
                            _ => {}
                        }
                    }
                }
                if nic.name.is_empty() {
                    nic.name = format!("eth{}", idx);
                }
                if nic.net_type.is_empty() {
                    nic.net_type = "veth".to_string();
                }
                nic.flags = "up".to_string();
                continue;
            }
        }

        match key {
            "hostname" => cfg.hostname = val.to_string(),
            "arch" => cfg.arch = val.to_string(),
            "onboot" => cfg.autostart = val == "1",
            "startup" => {
                // Parse startup order: "order=N" format
                if let Some(order_part) = val.split(',').find(|p| p.starts_with("order=")) {
                    cfg.start_order = order_part[6..].parse().unwrap_or(0);
                }
            }
            "cores" => cfg.cpus = val.to_string(),
            "memory" => {
                // Proxmox stores MB as plain number — pass through as-is
                cfg.memory_limit = val.to_string();
            }
            "swap" => {
                cfg.swap_limit = val.to_string();
            }
            "unprivileged" => cfg.unprivileged = val == "1",
            "features" => {
                // features: nesting=1,keyctl=1,fuse=1
                for feat in val.split(',') {
                    let feat = feat.trim();
                    match feat {
                        "nesting=1" => cfg.nesting_enabled = true,
                        "keyctl=1" => cfg.keyctl_enabled = true,
                        "fuse=1" => cfg.fuse_enabled = true,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Populate flat fields from NIC 0 for backward compat
    if let Some(nic0) = net_map.get(&0) {
        cfg.net_type = nic0.net_type.clone();
        cfg.net_link = nic0.link.clone();
        cfg.net_name = nic0.name.clone();
        cfg.net_hwaddr = nic0.hwaddr.clone();
        cfg.net_ipv4 = nic0.ipv4.clone();
        cfg.net_ipv4_gw = nic0.ipv4_gw.clone();
        cfg.net_ipv6 = nic0.ipv6.clone();
        cfg.net_ipv6_gw = nic0.ipv6_gw.clone();
        cfg.net_firewall = nic0.firewall;
        cfg.net_mtu = nic0.mtu.clone();
        cfg.net_vlan = nic0.vlan.clone();
    }

    cfg.network_interfaces = net_map.into_values().collect();

    // Read WolfNet IP
    let wolfnet_ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", container);
    if let Ok(ip) = std::fs::read_to_string(&wolfnet_ip_file) {
        cfg.wolfnet_ip = ip.trim().to_string();
    }

    cfg
}

/// Parse an LXC container config into structured form
pub fn lxc_parse_config(container: &str) -> Option<LxcParsedConfig> {
    // Try Proxmox config first (/etc/pve/lxc/<vmid>.conf), then native LXC
    let pve_path = format!("/etc/pve/lxc/{}.conf", container);
    let lxc_path = format!("/var/lib/lxc/{}/config", container);

    let (content, is_proxmox_fmt) = if let Ok(c) = std::fs::read_to_string(&pve_path) {
        (c, true)
    } else if let Ok(c) = std::fs::read_to_string(&lxc_path) {
        (c, false)
    } else {
        return None;
    };

    let mut cfg = LxcParsedConfig {
        raw_config: content.clone(),
        ..Default::default()
    };

    if is_proxmox_fmt {
        return Some(parse_proxmox_config(cfg, &content, container));
    }

    // Collect network interfaces by index
    let mut net_map: std::collections::BTreeMap<u32, LxcNetInterface> = std::collections::BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 { continue; }
        let key = parts[0].trim();
        let val = parts[1].trim();

        // Parse lxc.net.N.* keys for all network interfaces
        if key.starts_with("lxc.net.") {
            let remainder = &key["lxc.net.".len()..];
            if let Some(dot_pos) = remainder.find('.') {
                if let Ok(idx) = remainder[..dot_pos].parse::<u32>() {
                    let field = &remainder[dot_pos + 1..];
                    let nic = net_map.entry(idx).or_insert_with(|| LxcNetInterface {
                        index: idx,
                        ..Default::default()
                    });
                    match field {
                        "type" => nic.net_type = val.to_string(),
                        "link" => nic.link = val.to_string(),
                        "name" => nic.name = val.to_string(),
                        "hwaddr" => nic.hwaddr = val.to_string(),
                        "ipv4.address" => nic.ipv4 = val.to_string(),
                        "ipv4.gateway" => nic.ipv4_gw = val.to_string(),
                        "ipv6.address" => nic.ipv6 = val.to_string(),
                        "ipv6.gateway" => nic.ipv6_gw = val.to_string(),
                        "flags" => nic.flags = val.to_string(),
                        "mtu" => nic.mtu = val.to_string(),
                        "vlan.id" => nic.vlan = val.to_string(),
                        "firewall" => nic.firewall = val == "1",
                        _ => {}
                    }
                }
            }
            continue;
        }

        match key {
            "lxc.uts.name" => cfg.hostname = val.to_string(),
            "lxc.arch" => cfg.arch = val.to_string(),
            "lxc.start.auto" => cfg.autostart = val == "1",
            "lxc.start.delay" => cfg.start_delay = val.parse().unwrap_or(0),
            "lxc.start.order" => cfg.start_order = val.parse().unwrap_or(0),
            "lxc.idmap" => cfg.unprivileged = true,
            _ => {
                // Feature detection
                if key == "lxc.mount.entry" && val.contains("/dev/net/tun") {
                    cfg.tun_enabled = true;
                }
                if key == "lxc.mount.entry" && val.contains("/dev/fuse") {
                    cfg.fuse_enabled = true;
                }
                if key == "lxc.include" && val.contains("nesting.conf") {
                    cfg.nesting_enabled = true;
                }
                if key == "lxc.mount.auto" && val.contains("cgroup") {
                    cfg.nesting_enabled = true;
                }
                if key == "lxc.mount.entry" && val.contains("nfsd") {
                    cfg.nfs_enabled = true;
                }

                // Resource limits (cgroup v1 and v2)
                if key.contains("memory.limit") || key.contains("memory.max") {
                    cfg.memory_limit = val.to_string();
                }
                if key.contains("memory.memsw") || key.contains("swap") {
                    cfg.swap_limit = val.to_string();
                }
                if key.contains("cpuset.cpus") {
                    cfg.cpus = val.to_string();
                }
                if key.contains("cpu.shares") {
                    cfg.cpu_shares = val.to_string();
                }
            }
        }

        // keyctl detection
        if key == "lxc.mount.auto" && val.contains("proc:rw") {
            cfg.keyctl_enabled = true;
        }
    }

    // Set default interface name for NICs missing one
    for nic in net_map.values_mut() {
        if nic.name.is_empty() && !nic.net_type.is_empty() {
            nic.name = format!("eth{}", nic.index);
        }
    }

    // Populate flat fields from NIC 0 for backward compatibility
    if let Some(nic0) = net_map.get(&0) {
        cfg.net_type = nic0.net_type.clone();
        cfg.net_link = nic0.link.clone();
        cfg.net_name = nic0.name.clone();
        cfg.net_hwaddr = nic0.hwaddr.clone();
        cfg.net_ipv4 = nic0.ipv4.clone();
        cfg.net_ipv4_gw = nic0.ipv4_gw.clone();
        cfg.net_ipv6 = nic0.ipv6.clone();
        cfg.net_ipv6_gw = nic0.ipv6_gw.clone();
        cfg.net_firewall = nic0.firewall;
        cfg.net_mtu = nic0.mtu.clone();
        cfg.net_vlan = nic0.vlan.clone();
    }

    // Store all NICs
    cfg.network_interfaces = net_map.into_values().collect();

    // Read WolfNet IP from file
    let wolfnet_ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", container);
    if let Ok(ip) = std::fs::read_to_string(&wolfnet_ip_file) {
        cfg.wolfnet_ip = ip.trim().to_string();
    }

    Some(cfg)
}

/// Update settings for an LXC container with structured data
/// Preserves existing config lines that aren't being modified
#[derive(Debug, Deserialize)]
pub struct LxcSettingsUpdate {
    // General
    pub hostname: Option<String>,
    pub autostart: Option<bool>,
    pub start_delay: Option<u32>,
    pub start_order: Option<u32>,
    pub unprivileged: Option<bool>,

    // Network (flat fields for backward compat — net.0 only)
    pub net_link: Option<String>,
    pub net_name: Option<String>,
    pub net_hwaddr: Option<String>,
    pub net_ipv4: Option<String>,
    pub net_ipv4_gw: Option<String>,
    pub net_ipv6: Option<String>,
    pub net_ipv6_gw: Option<String>,
    pub net_mtu: Option<String>,
    pub net_vlan: Option<String>,

    // All network interfaces (overrides flat fields if present)
    pub network_interfaces: Option<Vec<LxcNetInterface>>,

    // Resources
    pub memory_limit: Option<String>,
    pub swap_limit: Option<String>,
    pub cpus: Option<String>,

    // Features
    pub tun_enabled: Option<bool>,
    pub fuse_enabled: Option<bool>,
    pub nesting_enabled: Option<bool>,
    pub nfs_enabled: Option<bool>,
    pub keyctl_enabled: Option<bool>,

    // WolfNet
    pub wolfnet_ip: Option<String>,
}
/// Update LXC container settings via Proxmox pct set
fn pct_update_settings(container: &str, settings: &LxcSettingsUpdate) -> Result<String, String> {
    let current = lxc_parse_config(container).unwrap_or_default();
    let mut args: Vec<String> = vec!["set".to_string(), container.to_string()];

    // Hostname
    if let Some(ref h) = settings.hostname {
        if !h.is_empty() {
            args.push("--hostname".to_string());
            args.push(h.clone());
        }
    }

    // Memory (Proxmox uses MB as integer)
    let mem = settings.memory_limit.as_deref().unwrap_or(&current.memory_limit);
    if !mem.is_empty() {
        let mb = parse_mem_to_mb(mem);
        if mb > 0 {
            args.push("--memory".to_string());
            args.push(mb.to_string());
        }
    }

    // Swap
    let swap = settings.swap_limit.as_deref().unwrap_or(&current.swap_limit);
    if !swap.is_empty() {
        let mb = parse_mem_to_mb(swap);
        if mb > 0 {
            args.push("--swap".to_string());
            args.push(mb.to_string());
        }
    }

    // Cores / CPUs
    let cpus = settings.cpus.as_deref().unwrap_or(&current.cpus);
    if !cpus.is_empty() {
        args.push("--cores".to_string());
        args.push(cpus.to_string());
    }

    // Autostart
    let autostart = settings.autostart.unwrap_or(current.autostart);
    args.push("--onboot".to_string());
    args.push(if autostart { "1" } else { "0" }.to_string());

    // Features
    let mut features: Vec<String> = Vec::new();
    if settings.nesting_enabled.unwrap_or(current.nesting_enabled) { features.push("nesting=1".to_string()); }
    if settings.keyctl_enabled.unwrap_or(current.keyctl_enabled) { features.push("keyctl=1".to_string()); }
    if settings.fuse_enabled.unwrap_or(current.fuse_enabled) { features.push("fuse=1".to_string()); }
    if !features.is_empty() {
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    // Network interfaces
    let nics: Vec<LxcNetInterface> = if let Some(ref ifaces) = settings.network_interfaces {
        ifaces.clone()
    } else {
        current.network_interfaces.clone()
    };

    for nic in &nics {
        let mut parts: Vec<String> = Vec::new();
        let name = if nic.name.is_empty() { format!("eth{}", nic.index) } else { nic.name.clone() };
        parts.push(format!("name={}", name));
        if !nic.link.is_empty() { parts.push(format!("bridge={}", nic.link)); }
        if !nic.hwaddr.is_empty() { parts.push(format!("hwaddr={}", nic.hwaddr)); }
        if !nic.ipv4.is_empty() {
            parts.push(format!("ip={}", nic.ipv4));
        }
        if !nic.ipv4_gw.is_empty() { parts.push(format!("gw={}", nic.ipv4_gw)); }
        if !nic.ipv6.is_empty() {
            parts.push(format!("ip6={}", nic.ipv6));
        }
        if !nic.ipv6_gw.is_empty() { parts.push(format!("gw6={}", nic.ipv6_gw)); }
        let net_type = if nic.net_type.is_empty() { "veth".to_string() } else { nic.net_type.clone() };
        parts.push(format!("type={}", net_type));
        if !nic.mtu.is_empty() { parts.push(format!("mtu={}", nic.mtu)); }
        if !nic.vlan.is_empty() { parts.push(format!("tag={}", nic.vlan)); }
        if nic.firewall { parts.push("firewall=1".to_string()); }

        args.push(format!("--net{}", nic.index));
        args.push(parts.join(","));
    }

    // Execute pct set
    let output = Command::new("pct")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run pct set: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pct set failed: {}", stderr));
    }

    // Handle WolfNet IP separately
    if let Some(ref wip) = settings.wolfnet_ip {
        let wolfnet_dir = format!("/var/lib/lxc/{}/.wolfnet", container);
        let wolfnet_ip_file = format!("{}/ip", wolfnet_dir);
        let ip_trimmed = wip.trim();
        if ip_trimmed.is_empty() {
            let _ = std::fs::remove_file(&wolfnet_ip_file);
            // Remove the wn0 NIC from pct config if it exists
            let current = lxc_parse_config(container).unwrap_or_default();
            if let Some(wn_nic) = current.network_interfaces.iter().find(|n| n.name == "wn0" || n.link == "lxcbr0") {
                let _ = Command::new("pct")
                    .args(["set", container, &format!("--delete"), &format!("net{}", wn_nic.index)])
                    .output();
                info!("Removed WolfNet NIC (net{}) from VMID {}", wn_nic.index, container);
            }
        } else {
            let _ = std::fs::create_dir_all(&wolfnet_dir);
            std::fs::write(&wolfnet_ip_file, ip_trimmed)
                .map_err(|e| format!("Failed to write WolfNet IP: {}", e))?;

            // Ensure lxcbr0 bridge exists
            ensure_lxc_bridge();

            // Find existing wn0 NIC index or use next free index
            let current = lxc_parse_config(container).unwrap_or_default();
            let wn_index = current.network_interfaces.iter()
                .find(|n| n.name == "wn0" || n.link == "lxcbr0")
                .map(|n| n.index)
                .unwrap_or_else(|| {
                    // Find next free net index
                    let max = current.network_interfaces.iter().map(|n| n.index).max().unwrap_or(0);
                    max + 1
                });

            // Add/update the wn0 NIC on lxcbr0 via pct set — NO ip/gw to avoid
            // creating a second default gateway that conflicts with eth0 on vmbr0.
            // lxc_apply_wolfnet will assign the bridge IP and WolfNet IP at runtime.
            let net_cfg = "name=wn0,bridge=lxcbr0";
            let set_out = Command::new("pct")
                .args(["set", container, &format!("--net{}", wn_index), net_cfg])
                .output();
            match set_out {
                Ok(ref o) if o.status.success() => {
                    info!("Updated WolfNet NIC (net{}) on lxcbr0 for VMID {} (IP applied at runtime)", wn_index, container);
                }
                Ok(ref o) => {
                    error!("Failed to set WolfNet NIC on VMID {}: {}", container, String::from_utf8_lossy(&o.stderr));
                }
                Err(e) => {
                    error!("Failed to run pct set for WolfNet NIC on VMID {}: {}", container, e);
                }
            }

            // Apply live if the container is running
            let running = Command::new("pct")
                .args(["status", container])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("running"))
                .unwrap_or(false);
            if running {
                info!("Container {} is running — applying WolfNet IP {} live", container, ip_trimmed);
                lxc_apply_wolfnet(container);
            }
        }
    }

    Ok(format!("Settings updated for '{}' via pct", container))
}

/// Parse memory string (e.g. "512M", "1G", "1024") to MB
fn parse_mem_to_mb(mem: &str) -> u64 {
    let mem = mem.trim();
    if mem.ends_with('G') || mem.ends_with('g') {
        mem[..mem.len()-1].parse::<u64>().unwrap_or(0) * 1024
    } else if mem.ends_with('M') || mem.ends_with('m') {
        mem[..mem.len()-1].parse::<u64>().unwrap_or(0)
    } else {
        // Assume bytes or MB depending on magnitude
        let val = mem.parse::<u64>().unwrap_or(0);
        if val > 10000 { val / (1024 * 1024) } else { val }
    }
}

pub fn lxc_update_settings(container: &str, settings: &LxcSettingsUpdate) -> Result<String, String> {
    // Check if this is a Proxmox container
    let pve_path = format!("/etc/pve/lxc/{}.conf", container);
    if std::path::Path::new(&pve_path).exists() {
        return pct_update_settings(container, settings);
    }

    let path = format!("/var/lib/lxc/{}/config", container);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Config not found: {}", e))?;

    // Backup
    let _ = std::fs::copy(&path, format!("{}.bak", path));

    // Keys we manage — we'll remove these and re-add them with new values
    let managed_keys = [
        "lxc.uts.name", "lxc.start.auto", "lxc.start.delay", "lxc.start.order",
    ];

    // Feature-related lines we'll manage
    let feature_markers = [
        "/dev/net/tun", "/dev/fuse", "nesting.conf",
        "nfsd", "proc:rw sys:rw cgroup:rw",
    ];

    // Cgroup resource keys
    let resource_patterns = [
        "memory.limit", "memory.max", "memory.memsw", "swap",
        "cpuset.cpus", "cpu.shares",
    ];

    let mut preserved: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            preserved.push(line.to_string());
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() != 2 {
            preserved.push(line.to_string());
            continue;
        }
        let key = parts[0].trim();
        let val = parts[1].trim();

        // Skip managed keys — we'll re-add them
        if managed_keys.contains(&key) { continue; }

        // Skip ALL lxc.net.N.* keys — we'll re-add them from network_interfaces
        if key.starts_with("lxc.net.") { continue; }

        // Skip feature mount entries we manage
        if key == "lxc.mount.entry" && feature_markers.iter().any(|m| val.contains(m)) { continue; }
        if key == "lxc.include" && (val.contains("nesting.conf") || val.contains("userns.conf")) { continue; }
        if key == "lxc.mount.auto" && val.contains("cgroup") { continue; }

        // Skip idmap lines (managed by privilege toggle)
        if key == "lxc.idmap" { continue; }

        // Skip cgroup2 device allows for TUN/FUSE that we manage
        if (key == "lxc.cgroup2.devices.allow" || key == "lxc.cgroup.devices.allow")
            && (val.contains("10:200") || val.contains("10:229")) { continue; }

        // Skip resource keys we manage
        if resource_patterns.iter().any(|p| key.contains(p)) { continue; }

        // Keep everything else
        preserved.push(line.to_string());
    }

    // Now re-add managed settings with new values
    // Read current config to get defaults for values not being changed
    let current = lxc_parse_config(container).unwrap_or_default();

    // General
    let hostname = settings.hostname.as_deref().unwrap_or(&current.hostname);
    if !hostname.is_empty() {
        preserved.push(format!("lxc.uts.name = {}", hostname));
    }

    let autostart = settings.autostart.unwrap_or(current.autostart);
    if autostart {
        preserved.push("lxc.start.auto = 1".to_string());
        let delay = settings.start_delay.unwrap_or(current.start_delay);
        if delay > 0 { preserved.push(format!("lxc.start.delay = {}", delay)); }
        let order = settings.start_order.unwrap_or(current.start_order);
        if order > 0 { preserved.push(format!("lxc.start.order = {}", order)); }
    }

    // Network — build list of interfaces to write
    let nics: Vec<LxcNetInterface> = if let Some(ref ifaces) = settings.network_interfaces {
        // Use full multi-NIC data from frontend
        ifaces.clone()
    } else {
        // Backward compat: build single NIC from flat fields + current config
        let mut nic0 = current.network_interfaces.first().cloned().unwrap_or_default();
        if let Some(ref v) = settings.net_link { nic0.link = v.clone(); }
        if let Some(ref v) = settings.net_name { nic0.name = v.clone(); }
        if let Some(ref v) = settings.net_hwaddr { nic0.hwaddr = v.clone(); }
        if let Some(ref v) = settings.net_ipv4 { nic0.ipv4 = v.clone(); }
        if let Some(ref v) = settings.net_ipv4_gw { nic0.ipv4_gw = v.clone(); }
        if let Some(ref v) = settings.net_ipv6 { nic0.ipv6 = v.clone(); }
        if let Some(ref v) = settings.net_ipv6_gw { nic0.ipv6_gw = v.clone(); }
        if let Some(ref v) = settings.net_mtu { nic0.mtu = v.clone(); }
        if let Some(ref v) = settings.net_vlan { nic0.vlan = v.clone(); }
        // Include other existing NICs beyond index 0
        let mut all = vec![nic0];
        for nic in current.network_interfaces.iter().skip(1) {
            all.push(nic.clone());
        }
        all
    };

    // Write all network interfaces
    for nic in &nics {
        let i = nic.index;
        let net_type = if nic.net_type.is_empty() { "veth" } else { &nic.net_type };
        preserved.push(format!("lxc.net.{}.type = {}", i, net_type));
        preserved.push(format!("lxc.net.{}.flags = up", i));
        if !nic.link.is_empty() {
            preserved.push(format!("lxc.net.{}.link = {}", i, nic.link));
        }
        let iface_name = if nic.name.is_empty() { format!("eth{}", i) } else { nic.name.clone() };
        preserved.push(format!("lxc.net.{}.name = {}", i, iface_name));
        if !nic.hwaddr.is_empty() {
            preserved.push(format!("lxc.net.{}.hwaddr = {}", i, nic.hwaddr));
        }
        if !nic.ipv4.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv4.address = {}", i, nic.ipv4));
        }
        if !nic.ipv4_gw.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv4.gateway = {}", i, nic.ipv4_gw));
        }
        if !nic.ipv6.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv6.address = {}", i, nic.ipv6));
        }
        if !nic.ipv6_gw.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv6.gateway = {}", i, nic.ipv6_gw));
        }
        if !nic.mtu.is_empty() {
            preserved.push(format!("lxc.net.{}.mtu = {}", i, nic.mtu));
        }
        if !nic.vlan.is_empty() {
            preserved.push(format!("lxc.net.{}.vlan.id = {}", i, nic.vlan));
        }
        if nic.firewall {
            preserved.push(format!("lxc.net.{}.firewall = 1", i));
        }
    }

    // Resources
    let mem = settings.memory_limit.as_deref().unwrap_or(&current.memory_limit);
    if !mem.is_empty() {
        preserved.push(format!("lxc.cgroup2.memory.max = {}", mem));
    }

    let swap = settings.swap_limit.as_deref().unwrap_or(&current.swap_limit);
    if !swap.is_empty() {
        preserved.push(format!("lxc.cgroup2.memory.swap.max = {}", swap));
    }

    let cpus = settings.cpus.as_deref().unwrap_or(&current.cpus);
    if !cpus.is_empty() {
        preserved.push(format!("lxc.cgroup2.cpuset.cpus = {}", cpus));
    }

    // Features
    let tun = settings.tun_enabled.unwrap_or(current.tun_enabled);
    if tun {
        preserved.push("lxc.mount.entry = /dev/net/tun dev/net/tun none bind,create=file 0 0".to_string());
        preserved.push("lxc.cgroup2.devices.allow = c 10:200 rwm".to_string());
    }

    let fuse = settings.fuse_enabled.unwrap_or(current.fuse_enabled);
    if fuse {
        preserved.push("lxc.mount.entry = /dev/fuse dev/fuse none bind,create=file 0 0".to_string());
        preserved.push("lxc.cgroup2.devices.allow = c 10:229 rwm".to_string());
    }

    let nesting = settings.nesting_enabled.unwrap_or(current.nesting_enabled);
    if nesting {
        preserved.push("lxc.include = /usr/share/lxc/config/nesting.conf".to_string());
        preserved.push("lxc.mount.auto = proc:rw sys:rw cgroup:rw".to_string());
    }

    let nfs = settings.nfs_enabled.unwrap_or(current.nfs_enabled);
    if nfs {
        preserved.push("lxc.mount.entry = nfsd nfsd nfsd defaults 0 0".to_string());
    }

    let keyctl = settings.keyctl_enabled.unwrap_or(current.keyctl_enabled);
    if keyctl && !nesting {
        // Only add if not already covered by nesting
        preserved.push("lxc.mount.auto = proc:rw sys:rw".to_string());
    }

    // Privilege mode (unprivileged = uses idmap for uid/gid remapping)
    let unprivileged = settings.unprivileged.unwrap_or(current.unprivileged);
    if unprivileged {
        preserved.push("lxc.idmap = u 0 100000 65536".to_string());
        preserved.push("lxc.idmap = g 0 100000 65536".to_string());
        preserved.push("lxc.include = /usr/share/lxc/config/userns.conf".to_string());
    }

    // Write final config
    let mut output = preserved.join("\n");
    if !output.ends_with('\n') {
        output.push('\n');
    }

    std::fs::write(&path, &output)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Handle WolfNet IP separately (stored in .wolfnet/ip file)
    if let Some(ref wip) = settings.wolfnet_ip {
        let wolfnet_dir = format!("/var/lib/lxc/{}/.wolfnet", container);
        let wolfnet_ip_file = format!("{}/ip", wolfnet_dir);
        let ip_trimmed = wip.trim();
        if ip_trimmed.is_empty() {
            // Remove WolfNet IP
            let _ = std::fs::remove_file(&wolfnet_ip_file);
        } else {
            let _ = std::fs::create_dir_all(&wolfnet_dir);
            std::fs::write(&wolfnet_ip_file, ip_trimmed)
                .map_err(|e| format!("Failed to write WolfNet IP: {}", e))?;

            // Apply live if the container is running
            let running = Command::new("lxc-info")
                .args(["-n", container, "-sH"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
                .unwrap_or(false);
            if running {
                info!("Container {} is running — applying WolfNet IP {} live", container, ip_trimmed);
                lxc_apply_wolfnet(container);
            }
        }
    }

    Ok(format!("Settings updated for '{}'", container))
}

/// Update LXC container autostart specifically
pub fn lxc_set_autostart(container: &str, enabled: bool) -> Result<String, String> {
    let path = format!("/var/lib/lxc/{}/config", container);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Config not found: {}", e))?;

    let mut new_lines: Vec<String> = content.lines()
        .filter(|l| !l.trim().starts_with("lxc.start.auto") && !l.trim().starts_with("lxc.start.delay"))
        .map(|l| l.to_string())
        .collect();

    if enabled {
        new_lines.push("lxc.start.auto = 1".to_string());
        new_lines.push("lxc.start.delay = 5".to_string());
    }

    std::fs::write(&path, new_lines.join("\n")).map_err(|e| e.to_string())?;
    Ok(format!("Autostart set to {}", enabled))
}

/// Update LXC container network link (bridge/vlan)
pub fn lxc_set_network_link(container: &str, link: &str) -> Result<String, String> {
    let path = format!("/var/lib/lxc/{}/config", container);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Config not found: {}", e))?;

    let mut new_lines: Vec<String> = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        if line.trim().starts_with("lxc.net.0.link") {
            new_lines.push(format!("lxc.net.0.link = {}", link));
            replaced = true;
        } else {
            new_lines.push(line.to_string());
        }
    }

    if !replaced {
        new_lines.push(format!("lxc.net.0.link = {}", link));
    }

    std::fs::write(&path, new_lines.join("\n")).map_err(|e| e.to_string())?;
    Ok(format!("Network link set to {}", link))
}

/// Find the next available WolfNet IP (10.10.10.x) not in use by any LXC container
pub fn next_available_wolfnet_ip() -> Option<String> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Scan WolfNet config for node's own IP and all peer IPs
    if let Ok(content) = std::fs::read_to_string("/etc/wolfnet/config.toml") {
        for line in content.lines() {
            let trimmed = line.trim();
            // Node's own address: address = "10.10.10.3"
            if trimmed.starts_with("address") && trimmed.contains('=') {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let ip = val.trim().trim_matches('"').trim().to_string();
                    if !ip.is_empty() { used.insert(ip); }
                }
            }
            // Peer allowed_ip: allowed_ip = "10.10.10.1"
            if trimmed.starts_with("allowed_ip") && trimmed.contains('=') {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let ip = val.trim().trim_matches('"').trim().to_string();
                    if !ip.is_empty() { used.insert(ip); }
                }
            }
        }
    }

    // Also reserve .1 (usually gateway) and .255 (broadcast)
    used.insert("10.10.10.1".to_string());
    used.insert("10.10.10.255".to_string());

    // Scan live IPs on wolfnet0 interface (catches VIPs, manual assignments)
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", "wolfnet0"])
        .output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            // Lines like: "inet 10.10.10.3/24 ..." or "inet 10.10.10.40/32 ..."
            if trimmed.starts_with("inet ") {
                if let Some(cidr) = trimmed.split_whitespace().nth(1) {
                    let ip = cidr.split('/').next().unwrap_or("").to_string();
                    if !ip.is_empty() {
                        used.insert(ip);
                    }
                }
            }
        }
    }

    // Scan all LXC containers for WolfNet IPs
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", name);
            if let Ok(ip) = std::fs::read_to_string(&ip_file) {
                let ip = ip.trim().to_string();
                if !ip.is_empty() {
                    used.insert(ip);
                }
            }
        }
    }

    // Scan VM configs for WolfNet IPs
    if let Ok(entries) = std::fs::read_dir("/etc/wolfstack/vms") {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(vm) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(ip) = vm.get("wolfnet_ip").and_then(|v| v.as_str()) {
                        if !ip.is_empty() {
                            used.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    // Also check Docker containers with WolfNet labels
    if let Ok(output) = std::process::Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Label \"wolfnet.ip\"}}"])
        .output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let ip = line.trim().to_string();
            if !ip.is_empty() && ip != "<no value>" {
                used.insert(ip);
            }
        }
    }

    // Scan WolfRun services for service VIPs and all instance WolfNet IPs
    // This prevents VIP or remote-node container IPs from being re-allocated
    if let Ok(content) = std::fs::read_to_string("/etc/wolfstack/wolfrun/services.json") {
        if let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            for svc in &services {
                // Service VIP
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str()) {
                    if !vip.is_empty() {
                        used.insert(vip.to_string());
                    }
                }
                // All instance WolfNet IPs (may be on remote nodes)
                if let Some(instances) = svc.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        if let Some(ip) = inst.get("wolfnet_ip").and_then(|v| v.as_str()) {
                            if !ip.is_empty() {
                                used.insert(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Scan IP mappings to avoid colliding with port-forward destinations
    if let Ok(content) = std::fs::read_to_string("/etc/wolfstack/ip-mappings.json") {
        if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(mappings) = wrapper.get("mappings").and_then(|v| v.as_array()) {
                for m in mappings {
                    if let Some(ip) = m.get("wolfnet_ip").and_then(|v| v.as_str()) {
                        if !ip.is_empty() {
                            used.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    // Cluster-wide: check in-memory route cache (populated by poll_remote_nodes)
    // This is more up-to-date than routes.json since it's updated on every poll cycle
    {
        let cache = WOLFNET_ROUTES.lock().unwrap();
        for ip in cache.keys() {
            used.insert(ip.clone());
        }
    }

    // Also check routes.json as fallback (in case cache was reset on restart)
    if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json") {
        if let Ok(routes) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
            for ip in routes.keys() {
                used.insert(ip.clone());
            }
        }
    }

    // Find next available in 10.10.10.2 - 10.10.10.254
    for i in 2..=254u8 {
        let candidate = format!("10.10.10.{}", i);
        if !used.contains(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Detect duplicate MAC addresses and IP addresses across all LXC containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConflict {
    pub conflict_type: String, // "mac" or "ip"
    pub severity: String,      // "error" or "warning"
    pub value: String,         // the duplicate MAC or IP
    pub containers: Vec<String>, // container names that share this value
}

pub fn detect_network_conflicts() -> Vec<NetworkConflict> {
    let mut mac_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut ip_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    // Scan all LXC containers
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let config_path = format!("/var/lib/lxc/{}/config", name);
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                for line in content.lines() {
                    let line = line.trim();
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() != 2 { continue; }
                    let key = parts[0].trim();
                    let val = parts[1].trim().to_lowercase();

                    if key == "lxc.net.0.hwaddr" && !val.is_empty() {
                        mac_map.entry(val.clone()).or_default().push(name.clone());
                    }
                    if key == "lxc.net.0.ipv4.address" && !val.is_empty() {
                        // Strip CIDR notation for comparison
                        let ip = val.split('/').next().unwrap_or("").to_string();
                        if !ip.is_empty() {
                            ip_map.entry(ip).or_default().push(name.clone());
                        }
                    }
                }
            }
        }
    }

    let mut conflicts = Vec::new();

    for (mac, containers) in &mac_map {
        if containers.len() > 1 {
            conflicts.push(NetworkConflict {
                conflict_type: "mac".to_string(),
                severity: "error".to_string(),
                value: mac.clone(),
                containers: containers.clone(),
            });
        }
    }

    for (ip, containers) in &ip_map {
        if containers.len() > 1 {
            conflicts.push(NetworkConflict {
                conflict_type: "ip".to_string(),
                severity: "warning".to_string(),
                value: ip.clone(),
                containers: containers.clone(),
            });
        }
    }

    conflicts
}

/// Autostart all enabled LXC containers, then re-apply WolfNet networking.
/// lxc-autostart doesn't call our lxc_apply_wolfnet(), so we do it afterwards.
pub fn lxc_autostart_all() {
    // Wait for autostart to complete so containers are running
    let _ = Command::new("lxc-autostart").output();

    // Give containers a moment to initialise their network interfaces
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Now re-apply WolfNet IPs and host routes for all running containers
    reapply_wolfnet_routes();
}

fn run_lxc_cmd(args: &[&str]) -> Result<String, String> {
    let cmd = args[0];
    let output = Command::new(cmd)
        .args(&args[1..])
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

// ─── Templates & Container Creation ───

/// LXC template entry from the download server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LxcTemplate {
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub variant: String,
}

/// List available LXC templates from the LXC image server (standalone) or pveam (Proxmox)
pub fn lxc_list_templates() -> Vec<LxcTemplate> {
    if is_proxmox() {
        return lxc_list_templates_proxmox();
    }

    // Standalone: fetch from lxc image server index
    let output = Command::new("wget")
        .args(["-qO-", "https://images.linuxcontainers.org/meta/1.0/index-system"])
        .output();

    // If wget isn't available, try curl
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => {
            match Command::new("curl")
                .args(["-sL", "https://images.linuxcontainers.org/meta/1.0/index-system"])
                .output()
            {
                Ok(o) if o.status.success() => o,
                _ => {
                    // Return a curated list of common templates as fallback
                    return vec![
                        LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "ubuntu".into(), release: "22.04".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "ubuntu".into(), release: "20.04".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "debian".into(), release: "bookworm".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "debian".into(), release: "bullseye".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "alpine".into(), release: "3.19".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "alpine".into(), release: "3.18".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "fedora".into(), release: "39".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "centos".into(), release: "9-Stream".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "archlinux".into(), release: "current".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "rockylinux".into(), release: "9".into(), architecture: "amd64".into(), variant: "default".into() },
                        LxcTemplate { distribution: "opensuse".into(), release: "15.5".into(), architecture: "amd64".into(), variant: "default".into() },
                    ];
                }
            }
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut templates = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        // Format: distribution;release;architecture;variant;...
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() >= 4 {
            let dist = parts[0].trim();
            let rel = parts[1].trim();
            let arch = parts[2].trim();
            let variant = parts[3].trim();

            // Skip cloud variants - they require cloud-init and won't work with standard LXC
            let variant_str = if variant.is_empty() { "default" } else { variant };
            if !dist.is_empty() && !rel.is_empty() && !arch.is_empty() {
                let key = format!("{}-{}-{}-{}", dist, rel, arch, variant_str);
                if seen.insert(key) {
                    templates.push(LxcTemplate {
                        distribution: dist.to_string(),
                        release: rel.to_string(),
                        architecture: arch.to_string(),
                        variant: variant_str.to_string(),
                    });
                }
            }
        }
    }

    // Sort by distribution, then release descending
    templates.sort_by(|a, b| {
        a.distribution.cmp(&b.distribution)
            .then(b.release.cmp(&a.release))
    });

    if templates.is_empty() {
        // If parsing failed, return fallback
        return vec![
            LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: "amd64".into(), variant: "default".into() },
            LxcTemplate { distribution: "debian".into(), release: "bookworm".into(), architecture: "amd64".into(), variant: "default".into() },
            LxcTemplate { distribution: "alpine".into(), release: "3.19".into(), architecture: "amd64".into(), variant: "default".into() },
        ];
    }

    templates
}

/// List available templates from Proxmox (pveam available --section system)
/// Parses template names like: debian-12-standard_12.2-1_amd64.tar.zst
fn lxc_list_templates_proxmox() -> Vec<LxcTemplate> {
    // Update template index first
    let _ = Command::new("pveam").arg("update").output();

    let output = Command::new("pveam")
        .args(["available", "--section", "system"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => {
            info!("Failed to run pveam available, falling back to curated Proxmox templates");
            return vec![
                LxcTemplate { distribution: "debian".into(), release: "12".into(), architecture: "amd64".into(), variant: "standard".into() },
                LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: "amd64".into(), variant: "standard".into() },
                LxcTemplate { distribution: "ubuntu".into(), release: "22.04".into(), architecture: "amd64".into(), variant: "standard".into() },
                LxcTemplate { distribution: "alpine".into(), release: "3.20".into(), architecture: "amd64".into(), variant: "default".into() },
                LxcTemplate { distribution: "centos".into(), release: "9".into(), architecture: "amd64".into(), variant: "default".into() },
                LxcTemplate { distribution: "fedora".into(), release: "40".into(), architecture: "amd64".into(), variant: "default".into() },
                LxcTemplate { distribution: "rockylinux".into(), release: "9".into(), architecture: "amd64".into(), variant: "default".into() },
            ];
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut templates = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        // Format: "system          debian-12-standard_12.2-1_amd64.tar.zst"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 { continue; }
        let tpl_name = parts[1]; // e.g. "debian-12-standard_12.2-1_amd64.tar.zst"

        // Strip file extension (.tar.zst, .tar.gz, .tar.xz)
        let base = tpl_name
            .trim_end_matches(".tar.zst")
            .trim_end_matches(".tar.gz")
            .trim_end_matches(".tar.xz");

        // Parse: {distro}-{release}-{variant}_{version}_{arch}
        // Examples:
        //   debian-12-standard_12.7-1_amd64
        //   ubuntu-24.04-standard_24.04-2_amd64
        //   alpine-3.20-default_20240908_amd64
        //   archlinux-base_20230608-1_amd64  (no release number in name)

        // Extract architecture (last segment after _)
        let arch = if let Some(pos) = base.rfind('_') {
            &base[pos+1..]
        } else {
            "amd64"
        };

        // Get the part before the architecture
        let pre_arch = if let Some(pos) = base.rfind('_') {
            &base[..pos]
        } else {
            base
        };

        // Split on the first underscore to separate distro-release-variant from version
        let (dist_rel_var, _version) = if let Some(pos) = pre_arch.find('_') {
            (&pre_arch[..pos], &pre_arch[pos+1..])
        } else {
            (pre_arch, "")
        };

        // Parse distro-release-variant: split by '-' 
        // Common patterns: "debian-12-standard", "ubuntu-24.04-standard", "alpine-3.20-default"
        // Edge cases: "archlinux-base" (no numeric release)
        let segments: Vec<&str> = dist_rel_var.splitn(3, '-').collect();
        let (distro, release, variant) = match segments.len() {
            3 => (segments[0], segments[1], segments[2]),
            2 => {
                // Could be "archlinux-base" or "distro-release"
                let s1 = segments[1];
                if s1.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    (segments[0], s1, "default")
                } else {
                    (segments[0], "latest", s1)
                }
            },
            1 => (segments[0], "latest", "default"),
            _ => continue,
        };

        let key = format!("{}-{}-{}", distro, release, arch);
        if seen.insert(key) {
            templates.push(LxcTemplate {
                distribution: distro.to_string(),
                release: release.to_string(),
                architecture: arch.to_string(),
                variant: variant.to_string(),
            });
        }
    }

    // Sort by distribution, then release descending
    templates.sort_by(|a, b| {
        a.distribution.cmp(&b.distribution)
            .then(b.release.cmp(&a.release))
    });

    if templates.is_empty() {
        return vec![
            LxcTemplate { distribution: "debian".into(), release: "12".into(), architecture: "amd64".into(), variant: "standard".into() },
            LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: "amd64".into(), variant: "standard".into() },
        ];
    }

    info!("Listed {} Proxmox templates via pveam", templates.len());
    templates
}

// ─── Proxmox VE Detection & Helpers ───

/// Detect if we're running on a Proxmox VE node (cached after first check)
pub fn is_proxmox() -> bool {
    static IS_PVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IS_PVE.get_or_init(|| {
        Command::new("which").arg("pct").output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// PVE storage entry from `pvesm status`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PveStorage {
    pub id: String,
    pub storage_type: String,
    pub status: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    /// Which content types are allowed (e.g. "images", "rootdir", "vztmpl", "iso")
    pub content: Vec<String>,
}

/// List available Proxmox storage via `pvesm status`
pub fn pvesm_list_storage() -> Vec<PveStorage> {
    let output = match Command::new("pvesm").args(["status", "--output-format", "json"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            // Fallback: try text format
            return pvesm_list_storage_text();
        }
    };

    // Try JSON parsing first
    if let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&output) {
        return items.iter().filter_map(|item| {
            let id = item.get("storage")?.as_str()?.to_string();
            let storage_type = item.get("type")?.as_str()?.to_string();
            let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("active").to_string();
            let total = item.get("total").and_then(|v| v.as_u64()).unwrap_or(0) * 1024; // KB to bytes
            let used = item.get("used").and_then(|v| v.as_u64()).unwrap_or(0) * 1024;
            let avail = item.get("avail").and_then(|v| v.as_u64()).unwrap_or(0) * 1024;
            let content = item.get("content").and_then(|v| v.as_str())
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Some(PveStorage { id, storage_type, status, total_bytes: total, used_bytes: used, available_bytes: avail, content })
        }).collect();
    }

    pvesm_list_storage_text()
}

/// Fallback: parse `pvesm status` text output
fn pvesm_list_storage_text() -> Vec<PveStorage> {
    let output = match Command::new("pvesm").arg("status").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };

    // Header: Name           Type     Status           Total            Used       Available        %
    output.lines().skip(1).filter_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 { return None; }
        let id = parts[0].to_string();
        let storage_type = parts[1].to_string();
        let status = parts[2].to_string();
        let total = parts[3].parse::<u64>().unwrap_or(0) * 1024;
        let used = parts[4].parse::<u64>().unwrap_or(0) * 1024;
        let avail = parts[5].parse::<u64>().unwrap_or(0) * 1024;

        // Get content types from `pvesm show <storage>`
        let content = pvesm_get_content(&id);
        Some(PveStorage { id, storage_type, status, total_bytes: total, used_bytes: used, available_bytes: avail, content })
    }).collect()
}

/// Get content types for a specific PVE storage
fn pvesm_get_content(storage_id: &str) -> Vec<String> {
    // Try reading from /etc/pve/storage.cfg directly for speed
    if let Ok(cfg) = std::fs::read_to_string("/etc/pve/storage.cfg") {
        let mut in_section = false;
        for line in cfg.lines() {
            let trimmed = line.trim();
            // Section headers look like: dir: local
            if !trimmed.starts_with('#') && trimmed.contains(':') && !trimmed.starts_with('\t') && !trimmed.starts_with(' ') {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                in_section = parts.get(1).map(|s| s.trim()) == Some(storage_id);
            } else if in_section && trimmed.starts_with("content") {
                return trimmed.split_whitespace().skip(1)
                    .flat_map(|s| s.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }
    vec![]
}

/// Get next available VMID from Proxmox
fn pct_next_vmid() -> Result<u32, String> {
    let output = Command::new("pvesh").args(["get", "/cluster/nextid"])
        .output()
        .map_err(|e| format!("Failed to get next VMID: {}", e))?;
    if !output.status.success() {
        return Err("pvesh get /cluster/nextid failed".to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // pvesh may return JSON string like "100" or just 100
    let cleaned = text.trim_matches('"');
    cleaned.parse::<u32>().map_err(|e| format!("Invalid VMID '{}': {}", cleaned, e))
}

/// Find a Proxmox VMID by container hostname/name
#[allow(dead_code)]
fn pct_find_vmid(name: &str) -> Option<u32> {
    let output = Command::new("pct").arg("list").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let vmid = parts[0];
            let hostname = parts[2..].join(" ");
            // Match by hostname or VMID
            if hostname == name || vmid == name {
                return vmid.parse().ok();
            }
        }
    }
    None
}

/// Download a template to Proxmox's template storage if not already cached
fn pct_ensure_template(storage: &str, distribution: &str, release: &str, architecture: &str) -> Result<String, String> {
    // Check if template already exists
    let list_output = Command::new("pveam").args(["list", storage]).output()
        .map_err(|e| format!("Failed to list templates: {}", e))?;
    let list_text = String::from_utf8_lossy(&list_output.stdout);

    // Look for matching template (e.g. "ubuntu-24.04-standard" or "debian-12-standard")
    let search_term = format!("{}-{}", distribution, release);
    for line in list_text.lines() {
        if line.contains(&search_term) && line.contains(architecture) {
            // Already have this template — extract the volid
            let volid = line.split_whitespace().next().unwrap_or("").to_string();
            if !volid.is_empty() {
                info!("Template already cached: {}", volid);
                return Ok(volid);
            }
        }
    }

    // Update available template list
    info!("Updating Proxmox template list...");
    let _ = Command::new("pveam").arg("update").output();

    // Search available templates
    let avail_output = Command::new("pveam").args(["available", "--section", "system"]).output()
        .map_err(|e| format!("Failed to search templates: {}", e))?;
    let avail_text = String::from_utf8_lossy(&avail_output.stdout);

    // Find best matching template
    let mut best_template = String::new();
    for line in avail_text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let template_name = parts[1];
            if template_name.contains(&search_term) {
                // Prefer "standard" variant and matching architecture
                if template_name.contains("standard") || best_template.is_empty() {
                    best_template = template_name.to_string();
                }
            }
        }
    }

    if best_template.is_empty() {
        return Err(format!("No Proxmox template found matching '{} {} {}'. Available templates may not include this distribution/release. Check 'pveam available --section system' on the node.", distribution, release, architecture));
    }

    // Download the template
    info!("Downloading template: {} to {}", best_template, storage);
    let dl_output = Command::new("pveam").args(["download", storage, &best_template]).output()
        .map_err(|e| format!("Failed to download template: {}", e))?;

    if !dl_output.status.success() {
        let stderr = String::from_utf8_lossy(&dl_output.stderr);
        let stdout = String::from_utf8_lossy(&dl_output.stdout);
        return Err(format!("Template download failed for '{}' on storage '{}': {} {}", best_template, storage, stderr.trim(), stdout.trim()));
    }

    info!("Template downloaded: {} to {}", best_template, storage);

    // Return the volid
    Ok(format!("{}:vztmpl/{}", storage, best_template))
}

/// Create an LXC container via Proxmox's pct command (public API entry point)
pub fn pct_create_api(name: &str, distribution: &str, release: &str, architecture: &str,
              storage_id: Option<&str>, root_password: Option<&str>,
              memory_mb: Option<u32>, cpu_cores: Option<u32>,
              wolfnet_ip: Option<&str>) -> Result<String, String> {
    let vmid = pct_next_vmid()?;
    let storage = storage_id.unwrap_or("local-lvm");

    // Determine which storage holds templates (use "local" for vztmpl by default)
    let template_storage = if storage == "local-lvm" || storage == "local-zfs" {
        "local"  // LVM/ZFS can't hold templates, use "local" (directory)
    } else {
        storage
    };

    // Ensure the template is downloaded
    let template_volid = pct_ensure_template(template_storage, distribution, release, architecture)?;

    info!("Creating Proxmox container {} (VMID {}) from {}", name, vmid, template_volid);

    let mut args = vec![
        "create".to_string(),
        vmid.to_string(),
        template_volid,
        "--hostname".to_string(), name.to_string(),
        "--storage".to_string(), storage.to_string(),
        "--rootfs".to_string(), format!("{}:8", storage), // 8GB default rootfs
        "--net0".to_string(), "name=eth0,bridge=vmbr0,ip=dhcp".to_string(),
        "--start".to_string(), "0".to_string(),
        "--unprivileged".to_string(), "1".to_string(),
    ];

    if let Some(pw) = root_password {
        if !pw.is_empty() {
            args.push("--password".to_string());
            args.push(pw.to_string());
        }
    }

    if let Some(mem) = memory_mb {
        if mem > 0 {
            args.push("--memory".to_string());
            args.push(mem.to_string());
        }
    }

    if let Some(cores) = cpu_cores {
        if cores > 0 {
            args.push("--cores".to_string());
            args.push(cores.to_string());
        }
    }

    info!("pct {}", args.join(" "));
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("pct")
        .args(&args_ref)
        .output()
        .map_err(|e| format!("Failed to run pct create: {}", e))?;

    if output.status.success() {
        info!("Proxmox container {} (VMID {}) created successfully", name, vmid);

        // Attach WolfNet: add wn0 on lxcbr0 with the WolfNet IP
        if let Some(ip) = wolfnet_ip {
            // Ensure lxcbr0 bridge exists before adding NIC
            ensure_lxc_bridge();

            // Add a second NIC on lxcbr0 for WolfNet traffic — NO ip/gw to avoid
            // conflicting with eth0's default gateway on vmbr0.
            // lxc_apply_wolfnet will assign bridge IP and WolfNet IP at runtime.
            let net1_cfg = "name=wn0,bridge=lxcbr0".to_string();
            let set_out = Command::new("pct")
                .args(["set", &vmid.to_string(), "--net1", &net1_cfg])
                .output();
            match set_out {
                Ok(ref o) if o.status.success() => {
                    info!("Added WolfNet NIC (wn0) on lxcbr0 with IP {} to VMID {}", ip, vmid);
                }
                Ok(ref o) => {
                    error!("Failed to add WolfNet NIC to VMID {}: {}", vmid, String::from_utf8_lossy(&o.stderr));
                }
                Err(e) => {
                    error!("Failed to run pct set for WolfNet NIC on VMID {}: {}", vmid, e);
                }
            }

            // Save the WolfNet marker for lxc_apply_wolfnet (host routing setup at start)
            if let Err(e) = lxc_attach_wolfnet(&vmid.to_string(), ip) {
                error!("WolfNet marker warning for VMID {}: {}", vmid, e);
            }
        }

        Ok(format!("Container '{}' created (VMID {}, {} {} {}, storage: {})", name, vmid, distribution, release, architecture, storage))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!("pct create failed for '{}' (VMID {}): {} {}", name, vmid, stderr.trim(), stdout.trim());
        Err(format!("Container creation failed (VMID {}): {} {}", vmid, stderr.trim(), stdout.trim()))
    }
}

// ─── Clone, Export, Import ───

/// Clone an LXC container on the same node
pub fn lxc_clone_local(source: &str, new_name: &str, storage: Option<&str>) -> Result<String, String> {
    info!("Cloning container {} → {}", source, new_name);

    if is_proxmox() {
        let new_vmid = pct_next_vmid()?;
        let mut args = vec![
            "clone".to_string(),
            source.to_string(),          // source VMID
            new_vmid.to_string(),        // target VMID
            "--hostname".to_string(), new_name.to_string(),
            "--full".to_string(), "1".to_string(),  // full clone, not linked
        ];
        if let Some(s) = storage {
            if !s.is_empty() {
                args.push("--storage".to_string());
                args.push(s.to_string());
            }
        }
        info!("pct {}", args.join(" "));
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("pct").args(&args_ref).output()
            .map_err(|e| format!("Failed to run pct clone: {}", e))?;

        if output.status.success() {
            info!("Cloned {} → {} (VMID {})", source, new_name, new_vmid);
            lxc_clone_fixup_ip(new_name);
            Ok(format!("Container '{}' cloned to '{}' (VMID {})", source, new_name, new_vmid))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!("Clone failed: {} {}", stderr.trim(), stdout.trim()))
        }
    } else {
        // Standalone: lxc-copy
        let mut args = vec!["-n", source, "-N", new_name];
        let path_str;
        if let Some(s) = storage {
            if !s.is_empty() && s != "/var/lib/lxc" {
                path_str = s.to_string();
                args.push("-P");
                args.push(&path_str);
            }
        }
        let output = Command::new("lxc-copy").args(&args).output()
            .map_err(|e| format!("Failed to run lxc-copy: {}", e))?;

        if output.status.success() {
            info!("Cloned {} → {} via lxc-copy", source, new_name);
            lxc_clone_fixup_ip(new_name);
            Ok(format!("Container '{}' cloned to '{}'", source, new_name))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Clone failed: {}", stderr.trim()))
        }
    }
}

/// Export container metadata for transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExportMeta {
    pub name: String,
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub memory_mb: Option<u32>,
    pub cpu_cores: Option<u32>,
    pub source_type: String, // "proxmox" or "standalone"
    pub archive_format: String, // "vzdump" or "tar.gz"
}

/// Export an LXC container to an archive file
/// Returns (archive_path, metadata)
pub fn lxc_export(container: &str) -> Result<(std::path::PathBuf, ContainerExportMeta), String> {
    let export_dir = std::path::Path::new("/tmp/wolfstack-exports");
    std::fs::create_dir_all(export_dir).map_err(|e| format!("Failed to create export dir: {}", e))?;

    if is_proxmox() {
        // Use vzdump for Proxmox containers
        info!("Exporting Proxmox container {} via vzdump", container);
        let output = Command::new("vzdump")
            .args([container, "--dumpdir", "/tmp/wolfstack-exports", "--mode", "stop", "--compress", "zstd"])
            .output()
            .map_err(|e| format!("vzdump failed to start: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("vzdump failed: {}", stderr.trim()));
        }

        // Find the generated vzdump file
        let stdout = String::from_utf8_lossy(&output.stdout);
        let archive_path = find_vzdump_archive(&stdout, export_dir, container)?;

        // Extract metadata from pct config
        let meta = extract_pve_container_meta(container)?;

        Ok((archive_path, meta))
    } else {
        // Standalone: tar the rootfs + config
        info!("Exporting standalone container {} via tar", container);
        let container_dir = format!("/var/lib/lxc/{}", container);
        if !std::path::Path::new(&container_dir).exists() {
            return Err(format!("Container directory not found: {}", container_dir));
        }

        let archive_name = format!("{}.tar.gz", container);
        let archive_path = export_dir.join(&archive_name);

        let output = Command::new("tar")
            .args(["czf", archive_path.to_str().unwrap(), "-C", &container_dir, "."])
            .output()
            .map_err(|e| format!("tar failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("tar failed: {}", stderr.trim()));
        }

        let meta = ContainerExportMeta {
            name: container.to_string(),
            distribution: "unknown".to_string(),
            release: "unknown".to_string(),
            architecture: "amd64".to_string(),
            memory_mb: None,
            cpu_cores: None,
            source_type: "standalone".to_string(),
            archive_format: "tar.gz".to_string(),
        };

        info!("Exported {} to {}", container, archive_path.display());
        Ok((archive_path, meta))
    }
}

/// Find the vzdump archive file from vzdump output
fn find_vzdump_archive(stdout: &str, export_dir: &std::path::Path, vmid: &str) -> Result<std::path::PathBuf, String> {
    // vzdump prints the archive path: "creating vzdump archive '/tmp/.../vzdump-lxc-100-...tar.zst'"
    for line in stdout.lines() {
        if line.contains("creating") && line.contains("vzdump") {
            if let Some(start) = line.find('\'') {
                if let Some(end) = line.rfind('\'') {
                    if start < end {
                        let path = &line[start+1..end];
                        let p = std::path::PathBuf::from(path);
                        if p.exists() {
                            return Ok(p);
                        }
                    }
                }
            }
        }
    }
    // Fallback: search the export dir for the newest vzdump file matching this vmid
    if let Ok(entries) = std::fs::read_dir(export_dir) {
        let mut best: Option<(std::path::PathBuf, std::time::SystemTime)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("vzdump-lxc-{}-", vmid)) {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if best.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                            best = Some((entry.path(), modified));
                        }
                    }
                }
            }
        }
        if let Some((path, _)) = best {
            return Ok(path);
        }
    }
    Err(format!("Could not find vzdump archive for VMID {}", vmid))
}

/// Extract container metadata from Proxmox config
fn extract_pve_container_meta(vmid: &str) -> Result<ContainerExportMeta, String> {
    let output = Command::new("pct").args(["config", vmid]).output()
        .map_err(|e| format!("pct config failed: {}", e))?;
    let config_text = String::from_utf8_lossy(&output.stdout);

    let mut memory_mb = None;
    let mut cpu_cores = None;
    let mut hostname = vmid.to_string();

    for line in config_text.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "hostname" => hostname = val.to_string(),
                "memory" => memory_mb = val.parse().ok(),
                "cores" => cpu_cores = val.parse().ok(),
                _ => {}
            }
        }
    }

    Ok(ContainerExportMeta {
        name: hostname,
        distribution: "unknown".to_string(),
        release: "unknown".to_string(),
        architecture: "amd64".to_string(),
        memory_mb,
        cpu_cores,
        source_type: "proxmox".to_string(),
        archive_format: "vzdump".to_string(),
    })
}

/// Import an LXC container from an archive file
pub fn lxc_import(archive_path: &str, new_name: &str, storage: Option<&str>) -> Result<String, String> {
    let path = std::path::Path::new(archive_path);
    if !path.exists() {
        return Err(format!("Archive not found: {}", archive_path));
    }

    info!("Importing container '{}' from {}", new_name, archive_path);

    if is_proxmox() {
        let new_vmid = pct_next_vmid()?;
        let storage_id = storage.unwrap_or("local-lvm");

        let mut args = vec![
            "restore".to_string(),
            new_vmid.to_string(),
            archive_path.to_string(),
            "--storage".to_string(), storage_id.to_string(),
            "--hostname".to_string(), new_name.to_string(),
        ];

        // For vzdump archives, pct restore handles them natively
        // For tar.gz archives from standalone nodes, we need --rootfs
        if archive_path.ends_with(".tar.gz") {
            args.push("--unprivileged".to_string());
            args.push("1".to_string());
        }

        info!("pct {}", args.join(" "));
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("pct").args(&args_ref).output()
            .map_err(|e| format!("pct restore failed: {}", e))?;

        if output.status.success() {
            info!("Imported '{}' as VMID {}", new_name, new_vmid);
            Ok(format!("Container '{}' imported (VMID {}, storage: {})", new_name, new_vmid, storage_id))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!("Import failed: {} {}", stderr.trim(), stdout.trim()))
        }
    } else {
        // Standalone: create empty container + extract archive
        let container_dir = format!("/var/lib/lxc/{}", new_name);
        if std::path::Path::new(&container_dir).exists() {
            return Err(format!("Container '{}' already exists", new_name));
        }

        std::fs::create_dir_all(&container_dir)
            .map_err(|e| format!("Failed to create container dir: {}", e))?;

        let output = Command::new("tar")
            .args(["xzf", archive_path, "-C", &container_dir])
            .output()
            .map_err(|e| format!("tar extract failed: {}", e))?;

        if output.status.success() {
            info!("Imported standalone container '{}'", new_name);
            Ok(format!("Container '{}' imported from archive", new_name))
        } else {
            // Cleanup on failure
            let _ = std::fs::remove_dir_all(&container_dir);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Import failed: {}", stderr.trim()))
        }
    }
}

/// Clean up export files after transfer
pub fn lxc_export_cleanup(archive_path: &str) {
    let _ = std::fs::remove_file(archive_path);
    // Also remove .meta.json if present
    let meta_path = format!("{}.meta.json", archive_path.trim_end_matches(".tar.gz").trim_end_matches(".tar.zst"));
    let _ = std::fs::remove_file(&meta_path);
    info!("Cleaned up export: {}", archive_path);
}

/// Create an LXC container from a download template
/// On Proxmox nodes, automatically uses `pct create` instead of `lxc-create`
pub fn lxc_create(name: &str, distribution: &str, release: &str, architecture: &str, storage_path: Option<&str>) -> Result<String, String> {
    info!("Creating LXC container {} ({} {} {})", name, distribution, release, architecture);

    // On Proxmox, delegate to pct create
    if is_proxmox() {
        info!("Proxmox detected — using pct create");
        return pct_create_api(name, distribution, release, architecture, storage_path, None, None, None, None);
    }

    // Standalone: use native lxc-create
    let mut args = vec![
        "-t", "download",
        "-n", name,
    ];

    // Custom storage path
    let path_str;
    if let Some(path) = storage_path {
        if !path.is_empty() && path != "/var/lib/lxc" {
            path_str = path.to_string();
            args.push("-P");
            args.push(&path_str);
        }
    }

    args.extend_from_slice(&["--", "-d", distribution, "-r", release, "-a", architecture]);

    let output = Command::new("lxc-create")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to create LXC container: {}", e))?;

    if output.status.success() {
        info!("LXC container {} created successfully", name);

        // Ensure LXC config has proper networking (the download template often
        // omits hwaddr, bridge, etc., leaving the container without networking)
        lxc_ensure_network_config(name);

        let storage_info = storage_path.filter(|p| !p.is_empty() && *p != "/var/lib/lxc")
            .map(|p| format!(" on {}", p))
            .unwrap_or_default();
        Ok(format!("Container '{}' created ({} {} {}){}", name, distribution, release, architecture, storage_info))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to create container: {}", stderr))
    }
}

/// Docker Hub search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSearchResult {
    pub name: String,
    pub description: String,
    pub stars: u32,
    pub official: bool,
}

/// Search Docker Hub for images
/// Tries the Docker CLI first; if docker is not installed or fails,
/// falls back to the Docker Hub REST API (works on Proxmox without Docker).
pub fn docker_search(query: &str) -> Vec<DockerSearchResult> {
    // Try CLI first
    let output = Command::new("docker")
        .args(["search", "--format", "{{.Name}}\t{{.Description}}\t{{.StarCount}}\t{{.IsOfficial}}", "--limit", "100", query])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let results: Vec<DockerSearchResult> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    DockerSearchResult {
                        name: parts.first().unwrap_or(&"").to_string(),
                        description: parts.get(1).unwrap_or(&"").to_string(),
                        stars: parts.get(2).unwrap_or(&"0").parse().unwrap_or(0),
                        official: parts.get(3).unwrap_or(&"") == &"[OK]",
                    }
                })
                .collect();
            if !results.is_empty() {
                return results;
            }
        }
        _ => {}
    }

    // Fallback: Docker Hub REST API (no Docker required)
    info!("docker search CLI failed or returned empty — trying Docker Hub REST API for '{}'", query);
    docker_search_hub_api(query)
}

/// Query Docker Hub REST API directly (no Docker daemon needed)
fn docker_search_hub_api(query: &str) -> Vec<DockerSearchResult> {
    // Use curl -G --data-urlencode to safely encode the query parameter
    let output = Command::new("curl")
        .args(["-s", "--max-time", "10", "-G",
               "--data-urlencode", &format!("query={}", query),
               "--data-urlencode", "page_size=50",
               "https://hub.docker.com/v2/search/repositories/"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
                    return results.iter().filter_map(|r| {
                        let name = r.get("repo_name")
                            .or_else(|| r.get("slug"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if name.is_empty() { return None; }
                        Some(DockerSearchResult {
                            name,
                            description: r.get("short_description")
                                .or_else(|| r.get("description"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            stars: r.get("star_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32,
                            official: r.get("is_official")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                        })
                    }).collect();
                }
            }
            vec![]
        }
        _ => {
            info!("Docker Hub API fallback also failed");
            vec![]
        }
    }
}

/// Pull a Docker image
pub fn docker_pull(image: &str) -> Result<String, String> {
    info!("Pulling Docker image: {}", image);

    let output = Command::new("docker")
        .args(["pull", image])
        .output()
        .map_err(|e| format!("Failed to pull image: {}", e))?;

    if output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        info!("Docker image {} pulled", image);
        Ok(format!("Image '{}' pulled successfully. {}", image, out.lines().last().unwrap_or("")))
    } else {
        Err(format!(
            "Pull failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Create a Docker container from an image
/// If wolfnet_ip is provided, the container will be connected to the WolfNet overlay network
/// volumes: list of volume mount specs, e.g. ["/host/path:/container/path", "myvolume:/data"]
pub fn docker_create(name: &str, image: &str, ports: &[String], env: &[String], wolfnet_ip: Option<&str>, 
                     memory: Option<&str>, cpus: Option<&str>, _storage: Option<&str>,
                     volumes: &[String]) -> Result<String, String> {
    info!("Creating Docker container {} from image {}", name, image);

    let mut args = vec![
        "create".to_string(),
        "--name".to_string(), name.to_string(),
        "-it".to_string(),                           // interactive + tty (keeps container running)
        "--restart".to_string(), "unless-stopped".to_string(), // auto-restart
    ];

    // Add resource limits
    if let Some(mem) = memory {
        if !mem.is_empty() {
            args.push("--memory".to_string());
            args.push(mem.to_string());
        }
    }
    if let Some(cpu) = cpus {
        if !cpu.is_empty() {
            args.push("--cpus".to_string());
            args.push(cpu.to_string());
        }
    }

    // Add volume mounts (-v host:container or -v named_volume:container)
    for vol in volumes {
        let vol = vol.trim();
        if !vol.is_empty() {
            args.push("-v".to_string());
            args.push(vol.to_string());
        }
    }

    // Label with WolfNet IP so it can be re-applied on start/restart
    if let Some(ip) = wolfnet_ip {
        let ip = ip.trim();
        if !ip.is_empty() {
            // Validate IP format
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                return Err(format!("Invalid WolfNet IP: '{}' — must be like 10.10.10.100", ip));
            }
            args.push("--label".to_string());
            args.push(format!("wolfnet.ip={}", ip));
        }
    }

    // Add port mappings
    for port in ports {
        if !port.is_empty() {
            args.push("-p".to_string());
            args.push(port.to_string());
        }
    }

    // Add environment variables
    for e in env {
        if !e.is_empty() {
            args.push("-e".to_string());
            args.push(e.to_string());
        }
    }

    args.push(image.to_string());

    info!("Docker create command: docker {}", args.join(" "));
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("docker")
        .args(&args_ref)
        .output()
        .map_err(|e| format!("Failed to run docker create: {}", e))?;

    if output.status.success() {
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info!("Docker container {} created ({})", name, &id[..12.min(id.len())]);

        // WolfNet is applied on docker_start (reads wolfnet.ip label) — not here,
        // because the container isn't running yet and docker exec would fail.

        let wolfnet_msg = wolfnet_ip
            .filter(|ip| !ip.is_empty())
            .map(|ip| format!(" [WolfNet: {} — applied on start]", ip))
            .unwrap_or_default();

        Ok(format!("Container '{}' created ({}){}", name, &id[..12.min(id.len())], wolfnet_msg))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        error!("Docker create failed: {}", stderr);
        Err(format!("Create failed: {}", stderr))
    }
}

/// Set resource limits for an LXC container
pub fn lxc_set_resource_limits(container: &str, memory: Option<&str>, cpus: Option<&str>) -> Result<Option<String>, String> {
    let mut messages = Vec::new();
    
    // Limits are applied via lxc-cgroup but only work if container is running.
    // However, we want them persistent. Persistent config is in /var/lib/lxc/NAME/config
    let config_path = format!("/var/lib/lxc/{}/config", container);
    if let Ok(mut config) = std::fs::read_to_string(&config_path) {
        let mut modified = false;
        
        if let Some(mem) = memory {
            if !mem.is_empty() {
                // Convert e.g. "1G" to bytes if needed, but lxc.cgroup.memory.limit_in_bytes often accepts suffixes
                let limit_line = format!("\nlxc.cgroup.memory.limit_in_bytes = {}\n", mem);
                if !config.contains("lxc.cgroup.memory.limit_in_bytes") {
                   config.push_str(&limit_line);
                   modified = true;
                   messages.push(format!("Memory limit set to {}", mem));
                }
            }
        }
        
        if let Some(cpu) = cpus {
            if !cpu.is_empty() {
                 // Convert core count to cpuset? Actually easier to use cpu.shares or quota for generic limits
                 // But typically users want "2 cores" -> cpuset.cpus = 0-1
                 // Implementing simple cpuset based on count is tricky without knowing topology.
                 // We'll use cgroup.cpu.max or similar if cgroup2, or shares.
                 // For now, let's just append the raw value if it's a cpuset, or use shares?
                 // Let's assume the user input (dropdown) maps to cpuset e.g. "0" or "0-1" in a smarter way?
                 // The frontend sends "2", "4" etc.
                 // A safe way is cpu.shares = 1024 * cores.
                 if let Ok(cores) = cpu.parse::<u32>() {
                     let shares = cores * 1024;
                     let limit_line = format!("\nlxc.cgroup.cpu.shares = {}\n", shares);
                     if !config.contains("lxc.cgroup.cpu.shares") {
                        config.push_str(&limit_line);
                        modified = true;
                         messages.push(format!("CPU shares set to {}", shares));
                     }
                 }
            }
        }

        if modified {
            if let Err(e) = std::fs::write(&config_path, config) {
                return Err(format!("Failed to write config: {}", e));
            }
        }
    }

    if messages.is_empty() {
        Ok(None)
    } else {
        Ok(Some(messages.join(", ")))
    }
}

/// Stop an LXC container

/// Clone a Docker container — commits it as an image, then creates a new container
pub fn docker_clone(container: &str, new_name: &str) -> Result<String, String> {
    info!("Cloning Docker container {} as {}", container, new_name);

    // Step 1: Commit the container to a new image
    let image_name = format!("wolfstack-clone/{}", new_name);
    let output = Command::new("docker")
        .args(["commit", container, &image_name])
        .output()
        .map_err(|e| format!("Failed to commit container: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to commit container: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 2: Create a new container from the committed image
    let output = Command::new("docker")
        .args(["create", "--name", new_name, &image_name])
        .output()
        .map_err(|e| format!("Failed to create cloned container: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to create cloned container: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let new_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    info!("Docker container cloned: {} -> {} ({})", container, new_name, &new_id[..12]);
    Ok(format!("Container cloned as '{}' ({})", new_name, &new_id[..12.min(new_id.len())]))
}

/// Migrate a Docker container to a remote WolfStack node
/// Exports the container, sends it to the target, imports and optionally starts it
pub fn docker_migrate(container: &str, target_url: &str, remove_source: bool) -> Result<String, String> {
    info!("Migrating Docker container {} to {}", container, target_url);

    // Step 1: Stop the container if running
    let _ = docker_stop(container);

    // Step 2: Commit the container to a temporary image
    let temp_image = format!("wolfstack-migrate/{}", container);
    let output = Command::new("docker")
        .args(["commit", container, &temp_image])
        .output()
        .map_err(|e| format!("Failed to commit container for migration: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Commit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 3: Export the image to a tar file
    let export_path = format!("/tmp/wolfstack-migrate-{}.tar", container);
    let output = Command::new("docker")
        .args(["save", "-o", &export_path, &temp_image])
        .output()
        .map_err(|e| format!("Failed to save image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Save failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 4: Send the tar to the remote WolfStack node
    let import_url = format!("{}/api/containers/docker/import?name={}", target_url.trim_end_matches('/'), container);
    info!("Sending container image to {}", import_url);
    let output = Command::new("curl")
        .args([
            "-s", "-f",          // --fail: return error on HTTP errors (4xx, 5xx)
            "--max-time", "300", // 5 minute timeout for large images
            "-X", "POST",
            "-H", "Content-Type: application/octet-stream",
            "--data-binary", &format!("@{}", export_path),
            &import_url,
        ])
        .output()
        .map_err(|e| format!("Failed to send to remote: {}", e))?;

    // Clean up temp files
    let _ = std::fs::remove_file(&export_path);
    let _ = Command::new("docker").args(["rmi", &temp_image]).output();

    let response = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        // curl --fail returns non-zero on HTTP errors — do NOT remove the source
        error!("Migration transfer failed for {}: {} {}", container, stderr, response);
        // Restart the source container since migration failed
        let _ = docker_start(container);
        return Err(format!(
            "Transfer to remote node failed (container preserved on source): {}",
            if stderr.is_empty() { &response } else { &stderr }
        ));
    }

    // Verify the remote actually confirmed success — check for "error" in response
    if response.contains("\"error\"") {
        error!("Remote import failed for {}: {}", container, response);
        let _ = docker_start(container);
        return Err(format!(
            "Remote import failed (container preserved on source): {}",
            response
        ));
    }

    info!("Container {} successfully transferred to {}", container, target_url);
    
    // Step 5: Optionally remove the source container (only after confirmed success)
    if remove_source {
        let _ = docker_remove(container);
        info!("Source container {} removed after successful migration", container);
    } else {
        // Restart the source container since we're keeping it
        let _ = docker_start(container);
        info!("Container {} copied to {} (source preserved)", container, target_url);
    }

    Ok(format!("Container migrated to {} successfully. {}", target_url, response))
}

/// Import a Docker container image from a tar file
pub fn docker_import_image(tar_path: &str, container_name: &str) -> Result<String, String> {
    info!("Importing Docker image from {} as {}", tar_path, container_name);

    // Load the image
    let output = Command::new("docker")
        .args(["load", "-i", tar_path])
        .output()
        .map_err(|e| format!("Failed to load image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Image load failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let load_output = String::from_utf8_lossy(&output.stdout).to_string();
    
    // Extract the loaded image name from output like "Loaded image: wolfstack-migrate/foo:latest"
    let image_name = load_output.lines()
        .find(|l| l.contains("Loaded image"))
        .and_then(|l| l.split(": ").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("wolfstack-migrate/{}", container_name));

    // Create a container from the loaded image
    let output = Command::new("docker")
        .args(["create", "--name", container_name, &image_name])
        .output()
        .map_err(|e| format!("Failed to create container: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Container creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Clean up temp tar
    let _ = std::fs::remove_file(tar_path);

    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(format!("Container '{}' imported ({})", container_name, &id[..12.min(id.len())]))
}
/// Clone an LXC container (Proxmox-aware)
#[allow(dead_code)]
pub fn lxc_clone(container: &str, new_name: &str) -> Result<String, String> {
    info!("Cloning LXC container {} as {}", container, new_name);

    if is_proxmox() {
        return lxc_clone_local(container, new_name, None);
    }

    let output = Command::new("lxc-copy")
        .args(["-n", container, "-N", new_name])
        .output()
        .map_err(|e| format!("Failed to clone LXC container: {}", e))?;

    if output.status.success() {
        lxc_clone_fixup_ip(new_name);
        Ok(format!("LXC container cloned as '{}'", new_name))
    } else {
        Err(format!(
            "LXC clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Clone an LXC container as a snapshot (faster, copy-on-write)
/// On Proxmox, uses linked clone (not full)
pub fn lxc_clone_snapshot(container: &str, new_name: &str) -> Result<String, String> {
    info!("Snapshot-cloning LXC container {} as {}", container, new_name);

    if is_proxmox() {
        // Proxmox linked clone (--full 0)
        let new_vmid = pct_next_vmid()?;
        let vmid_str = new_vmid.to_string();
        let args = vec![
            "clone", container, &vmid_str,
            "--hostname", new_name,
        ];
        info!("pct {}", args.join(" "));
        let output = Command::new("pct").args(&args).output()
            .map_err(|e| format!("pct clone failed: {}", e))?;

        if output.status.success() {
            lxc_clone_fixup_ip(new_name);
            return Ok(format!("Container '{}' linked-cloned to '{}' (VMID {})", container, new_name, new_vmid));
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Linked clone failed: {}", stderr.trim()));
        }
    }

    let output = Command::new("lxc-copy")
        .args(["-n", container, "-N", new_name, "-s"])
        .output()
        .map_err(|e| format!("Failed to snapshot-clone LXC container: {}", e))?;

    if output.status.success() {
        lxc_clone_fixup_ip(new_name);
        Ok(format!("LXC container snapshot-cloned as '{}'", new_name))
    } else {
        Err(format!(
            "LXC snapshot clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub fn lxc_clone_fixup_ip(new_name: &str) {
    let new_last = find_free_bridge_ip();
    let new_ip = format!("10.0.3.{}", new_last);
    info!("Assigning new bridge IP {} to cloned container {}", new_ip, new_name);

    // Write multi-distro network config inside rootfs
    write_container_network_config(new_name, &new_ip);

    // Remove WolfNet IP marker from clone (it shouldn't inherit the original's WolfNet IP)
    let wolfnet_dir = format!("/var/lib/lxc/{}/.wolfnet", new_name);
    let _ = std::fs::remove_dir_all(&wolfnet_dir);

    // Update the LXC config: rootfs path, hostname, hwaddr, ipv4.address, and ensure
    // all required networking fields are present
    let config_path = format!("/var/lib/lxc/{}/config", new_name);
    if let Ok(config) = std::fs::read_to_string(&config_path) {
        let new_mac = format!("00:16:3e:{:02x}:{:02x}:{:02x}",
            rand_byte(), rand_byte(), new_last);
        let correct_rootfs = format!("dir:/var/lib/lxc/{}/rootfs", new_name);
        let mut has_hwaddr = false;
        let mut has_type = false;
        let mut has_link = false;
        let mut has_name = false;
        let mut has_flags = false;
        let mut updated: Vec<String> = config.lines().map(|line| {
            let trimmed = line.trim();
            // Fix rootfs path to point to the new container name
            if trimmed.starts_with("lxc.rootfs.path") {
                return format!("lxc.rootfs.path = {}", correct_rootfs);
            }
            // Fix hostname to match the new container name
            if trimmed.starts_with("lxc.uts.name") {
                return format!("lxc.uts.name = {}", new_name);
            }
            // Track and update network config fields
            if trimmed.starts_with("lxc.net.0.hwaddr") {
                has_hwaddr = true;
                return format!("lxc.net.0.hwaddr = {}", new_mac);
            }
            if trimmed.starts_with("lxc.net.0.type") { has_type = true; }
            if trimmed.starts_with("lxc.net.0.link") { has_link = true; }
            if trimmed.starts_with("lxc.net.0.name") { has_name = true; }
            if trimmed.starts_with("lxc.net.0.flags") { has_flags = true; }
            if trimmed.starts_with("lxc.net.0.ipv4.address") {
                return format!("lxc.net.0.ipv4.address = {}/24", new_ip);
            }
            line.to_string()
        }).collect();

        // Add any missing networking fields
        let mut net_additions = Vec::new();
        if !has_type  { net_additions.push("lxc.net.0.type = veth".to_string()); }
        if !has_link  { net_additions.push("lxc.net.0.link = lxcbr0".to_string()); }
        if !has_flags { net_additions.push("lxc.net.0.flags = up".to_string()); }
        if !has_name  { net_additions.push("lxc.net.0.name = eth0".to_string()); }
        if !has_hwaddr { net_additions.push(format!("lxc.net.0.hwaddr = {}", new_mac)); }

        if !net_additions.is_empty() {
            // Insert after existing lxc.net.0 lines, or at end
            let insert_pos = updated.iter().rposition(|l| l.trim().starts_with("lxc.net.0."))
                .map(|p| p + 1)
                .unwrap_or(updated.len());
            for (i, line) in net_additions.iter().enumerate() {
                updated.insert(insert_pos + i, line.clone());
            }
            info!("Added missing network config to cloned container {}: {:?}", new_name, net_additions);
        }

        let _ = std::fs::write(&config_path, updated.join("\n"));
    }

    // Write the setup_done marker so lxc_post_start_setup doesn't
    // redundantly re-assign the bridge IP we just set
    let marker = format!("/var/lib/lxc/{}/.wolfstack_setup_done", new_name);
    let _ = std::fs::write(&marker, "cloned");
}

/// Ensure an LXC container has proper networking config after creation.
/// The `lxc-create -t download` template often omits hwaddr, bridge, etc.
pub fn lxc_ensure_network_config(name: &str) {
    let config_path = format!("/var/lib/lxc/{}/config", name);
    let config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut has_type = false;
    let mut has_link = false;
    let mut has_name = false;
    let mut has_flags = false;
    let mut has_hwaddr = false;

    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("lxc.net.0.type")  { has_type = true; }
        if trimmed.starts_with("lxc.net.0.link")  { has_link = true; }
        if trimmed.starts_with("lxc.net.0.name")  { has_name = true; }
        if trimmed.starts_with("lxc.net.0.flags") { has_flags = true; }
        if trimmed.starts_with("lxc.net.0.hwaddr") { has_hwaddr = true; }
    }

    let mut additions = Vec::new();
    if !has_type   { additions.push("lxc.net.0.type = veth".to_string()); }
    if !has_link   { additions.push("lxc.net.0.link = lxcbr0".to_string()); }
    if !has_flags  { additions.push("lxc.net.0.flags = up".to_string()); }
    if !has_name   { additions.push("lxc.net.0.name = eth0".to_string()); }
    if !has_hwaddr {
        let last = find_free_bridge_ip();
        let mac = format!("00:16:3e:{:02x}:{:02x}:{:02x}", rand_byte(), rand_byte(), last);
        additions.push(format!("lxc.net.0.hwaddr = {}", mac));
    }

    if additions.is_empty() { return; }

    let mut lines: Vec<String> = config.lines().map(|l| l.to_string()).collect();
    // Insert after existing lxc.net.0 lines, or at end
    let insert_pos = lines.iter().rposition(|l| l.trim().starts_with("lxc.net.0."))
        .map(|p| p + 1)
        .unwrap_or(lines.len());
    for (i, line) in additions.iter().enumerate() {
        lines.insert(insert_pos + i, line.clone());
    }
    let _ = std::fs::write(&config_path, lines.join("\n"));
    info!("Ensured network config for container {}: {:?}", name, additions);
}

fn rand_byte() -> u8 {
    let mut buf = [0u8; 1];
    if let Ok(f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut f = f;
        let _ = f.read_exact(&mut buf);
    }
    buf[0]
}

// ─── Installation ───

/// Install Docker
pub fn install_docker() -> Result<String, String> {
    info!("Installing Docker...");

    // Use Docker's official convenience script
    let output = Command::new("bash")
        .args(["-c", "curl -fsSL https://get.docker.com | bash"])
        .output()
        .map_err(|e| format!("Failed to run Docker installer: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker installation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Enable and start Docker
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "docker"])
        .output();

    info!("Docker installed successfully");
    Ok("Docker installed and started successfully".to_string())
}

/// Install LXC
pub fn install_lxc() -> Result<String, String> {
    info!("Installing LXC...");

    // Detect package manager
    let (pkg_mgr, install_flag) = if std::path::Path::new("/usr/bin/apt-get").exists() {
        ("apt-get", "install")
    } else if std::path::Path::new("/usr/bin/dnf").exists() {
        ("dnf", "install")
    } else if std::path::Path::new("/usr/bin/yum").exists() {
        ("yum", "install")
    } else {
        return Err("Unsupported package manager".to_string());
    };

    // Update package cache for apt
    if pkg_mgr == "apt-get" {
        let _ = Command::new("apt-get")
            .args(["update", "-qq"])
            .output();
    }

    let packages = if pkg_mgr == "apt-get" {
        vec!["lxc", "lxc-templates", "lxcfs"]
    } else {
        vec!["lxc", "lxc-templates"]
    };

    let output = Command::new(pkg_mgr)
        .args([install_flag, "-y"])
        .args(&packages)
        .output()
        .map_err(|e| format!("Failed to install LXC: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "LXC installation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Start lxcfs if available
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "lxcfs"])
        .output();

    info!("LXC installed successfully");
    Ok("LXC installed successfully".to_string())
}

// ─── Parsing helpers ───

fn parse_docker_mem(s: &str) -> (u64, u64) {
    // "150.3MiB / 31.27GiB" -> (usage_bytes, limit_bytes)
    let parts: Vec<&str> = s.split('/').collect();
    let usage = parts.first().map(|v| parse_size_str(v.trim())).unwrap_or(0);
    let limit = parts.get(1).map(|v| parse_size_str(v.trim())).unwrap_or(0);
    (usage, limit)
}

fn parse_docker_io(s: &str) -> (u64, u64) {
    // "1.23kB / 456B"
    let parts: Vec<&str> = s.split('/').collect();
    let input = parts.first().map(|v| parse_size_str(v.trim())).unwrap_or(0);
    let output = parts.get(1).map(|v| parse_size_str(v.trim())).unwrap_or(0);
    (input, output)
}

fn parse_size_str(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() { return 0; }

    let multipliers = [
        ("TiB", 1024u64 * 1024 * 1024 * 1024),
        ("GiB", 1024u64 * 1024 * 1024),
        ("MiB", 1024u64 * 1024),
        ("KiB", 1024u64),
        ("TB", 1000u64 * 1000 * 1000 * 1000),
        ("GB", 1000u64 * 1000 * 1000),
        ("MB", 1000u64 * 1000),
        ("kB", 1000u64),
        ("B", 1u64),
    ];

    for (suffix, mult) in &multipliers {
        if s.ends_with(suffix) {
            let num = s.trim_end_matches(suffix).trim();
            return (num.parse::<f64>().unwrap_or(0.0) * *mult as f64) as u64;
        }
    }

    s.parse().unwrap_or(0)
}


/// Read a cgroup value via lxc-cgroup command
fn lxc_cgroup_read(name: &str, key: &str) -> Option<u64> {
    Command::new("lxc-cgroup")
        .args(["-n", name, key])
        .output()
        .ok()
        .and_then(|o| {
            let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if val == "max" || val.is_empty() { return None; }
            val.parse::<u64>().ok()
        })
}

/// Get CPU usage percentage for an LXC container
fn lxc_cpu_percent(name: &str) -> f64 {
    // Read cpu.stat usage_usec (cgroup v2)
    let usage = Command::new("lxc-cgroup")
        .args(["-n", name, "cpu.stat"])
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            text.lines()
                .find(|l| l.starts_with("usage_usec"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        });

    if let Some(usec) = usage {
        // Convert to rough percentage using total system uptime
        if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs) = uptime.split_whitespace().next()
                .and_then(|s| s.parse::<f64>().ok()) {
                let total_usec = (secs * 1_000_000.0) as u64;
                if total_usec > 0 {
                    return ((usec as f64 / total_usec as f64) * 100.0 * 10.0).round() / 10.0;
                }
            }
        }
    }
    0.0
}

fn read_container_net(name: &str) -> (u64, u64) {
    // Read network stats via container's PID
    let pid = Command::new("lxc-info")
        .args(["-n", name, "-pH"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    if let Some(pid) = pid {
        let net_path = format!("/proc/{}/net/dev", pid);
        if let Ok(content) = std::fs::read_to_string(&net_path) {
            let mut rx_total: u64 = 0;
            let mut tx_total: u64 = 0;
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let iface = parts[0].trim_end_matches(':');
                    if iface != "lo" {
                        rx_total += parts[1].parse::<u64>().unwrap_or(0);
                        tx_total += parts[9].parse::<u64>().unwrap_or(0);
                    }
                }
            }
            return (rx_total, tx_total);
        }
    }
    (0, 0)
}

// ─── Install Wolf Components into Containers ───

/// Install a Wolf component into a Docker or LXC container
pub fn install_component_in_container(
    runtime: &str,
    container: &str,
    component: &str,
) -> Result<String, String> {
    info!("Installing component '{}' into {} container '{}'", component, runtime, container);

    // Validate the component name
    let install_script = match component {
        "wolfnet" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/wolfnet/setup.sh",
        "wolfproxy" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfProxy/main/setup.sh",
        "wolfserve" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfServe/main/setup.sh",
        "wolfdisk" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup.sh",
        "wolfscale" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup_lb.sh",
        other => return Err(format!("Unknown Wolf component: '{}'. Available: wolfnet, wolfproxy, wolfserve, wolfdisk, wolfscale", other)),
    };

    // Build the exec command based on runtime
    let exec_cmd = match runtime {
        "docker" => {
            // Verify container is running
            let check = Command::new("docker")
                .args(["inspect", "--format", "{{.State.Running}}", container])
                .output()
                .map_err(|e| format!("Failed to check container state: {}", e))?;
            let state = String::from_utf8_lossy(&check.stdout).trim().to_string();
            if state != "true" {
                return Err(format!("Container '{}' is not running. Start it first.", container));
            }

            // First ensure curl is available in the container
            let _ = Command::new("docker")
                .args(["exec", container, "sh", "-c",
                    "apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || yum install -y -q curl 2>/dev/null || apk add --quiet curl 2>/dev/null || true"])
                .output();

            // Download and run install script
            Command::new("docker")
                .args(["exec", container, "sh", "-c",
                    &format!("curl -fsSL '{}' | bash", install_script)])
                .output()
                .map_err(|e| format!("Failed to exec in container: {}", e))?
        }
        "lxc" => {
            // Verify container is running
            let check = Command::new("lxc-info")
                .args(["-n", container, "-sH"])
                .output()
                .map_err(|e| format!("Failed to check container state: {}", e))?;
            let state = String::from_utf8_lossy(&check.stdout).trim().to_string();
            if state != "RUNNING" {
                return Err(format!("Container '{}' is not running (state: {}). Start it first.", container, state));
            }

            // First ensure curl is available
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "sh", "-c",
                    "apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || yum install -y -q curl 2>/dev/null || apk add --quiet curl 2>/dev/null || true"])
                .output();

            // Download and run install script
            Command::new("lxc-attach")
                .args(["-n", container, "--", "sh", "-c",
                    &format!("curl -fsSL '{}' | bash", install_script)])
                .output()
                .map_err(|e| format!("Failed to attach to container: {}", e))?
        }
        _ => return Err(format!("Unsupported runtime: '{}'. Use 'docker' or 'lxc'.", runtime)),
    };

    if exec_cmd.status.success() {
        let stdout = String::from_utf8_lossy(&exec_cmd.stdout);
        info!("Successfully installed {} in {} container {}", component, runtime, container);
        Ok(format!("{} installed in {} container '{}'. {}", 
            component, runtime, container, 
            stdout.lines().last().unwrap_or("Done")))
    } else {
        let stderr = String::from_utf8_lossy(&exec_cmd.stderr).to_string();
        let stdout = String::from_utf8_lossy(&exec_cmd.stdout).to_string();
        error!("Failed to install {} in container {}: {}", component, container, stderr);
        Err(format!("Installation failed: {}{}", 
            if stderr.is_empty() { &stdout } else { &stderr },
            ""))
    }
}

/// List running containers (both Docker and LXC) for component installation UI
pub fn list_running_containers() -> Vec<(String, String, String)> {
    let mut result = Vec::new();

    // Docker containers
    if let Ok(output) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Image}}"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.is_empty() { continue; }
            let parts: Vec<&str> = line.split('\t').collect();
            let name = parts.first().unwrap_or(&"").to_string();
            let image = parts.get(1).unwrap_or(&"").to_string();
            result.push(("docker".to_string(), name, image));
        }
    }

    // LXC containers
    if let Ok(output) = Command::new("lxc-ls")
        .args(["--running"])
        .output()
    {
        for name in String::from_utf8_lossy(&output.stdout).split_whitespace() {
            result.push(("lxc".to_string(), name.to_string(), "LXC".to_string()));
        }
    }

    result
}

// ─── Volume / Mount Management ───

/// A mount point for display in the UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMount {
    pub host_path: String,
    pub container_path: String,
    pub mount_type: String,  // "bind", "volume", "tmpfs"
    pub read_only: bool,
}

/// Add a bind mount to an LXC container's config (container must be stopped)
pub fn lxc_add_mount(container: &str, host_path: &str, container_path: &str, read_only: bool) -> Result<String, String> {
    let config_path = format!("/var/lib/lxc/{}/config", container);
    let mut config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Container '{}' config not found: {}", container, e))?;

    // Ensure host path exists (create it if it doesn't)
    if !std::path::Path::new(host_path).exists() {
        std::fs::create_dir_all(host_path)
            .map_err(|e| format!("Failed to create host path '{}': {}", host_path, e))?;
    }

    // Build the mount entry
    let ro_flag = if read_only { ",ro" } else { "" };
    // Container path must not have a leading / for lxc.mount.entry
    let clean_container_path = container_path.trim_start_matches('/');
    let entry = format!("\nlxc.mount.entry = {} {} none bind,create=dir{} 0 0\n",
        host_path, clean_container_path, ro_flag);

    // Check for duplicate
    if config.contains(&format!("{} {} none bind", host_path, clean_container_path)) {
        return Err(format!("Mount {} -> {} already exists", host_path, container_path));
    }

    config.push_str(&entry);
    std::fs::write(&config_path, config)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    info!("Added mount {} -> {} to LXC container {}", host_path, container_path, container);
    Ok(format!("Mount added: {} → {}", host_path, container_path))
}

/// Remove a bind mount from an LXC container's config
pub fn lxc_remove_mount(container: &str, host_path: &str) -> Result<String, String> {
    let config_path = format!("/var/lib/lxc/{}/config", container);
    let config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Container '{}' config not found: {}", container, e))?;

    let filtered: Vec<&str> = config.lines()
        .filter(|line| {
            if line.trim().starts_with("lxc.mount.entry") && line.contains(host_path) {
                false
            } else {
                true
            }
        })
        .collect();

    let new_config = filtered.join("\n");
    std::fs::write(&config_path, &new_config)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    info!("Removed mount for {} from LXC container {}", host_path, container);
    Ok(format!("Mount removed: {}", host_path))
}

/// List current bind mounts for an LXC container
pub fn lxc_list_mounts(container: &str) -> Vec<ContainerMount> {
    let config_path = format!("/var/lib/lxc/{}/config", container);
    let config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    config.lines()
        .filter(|line| line.trim().starts_with("lxc.mount.entry"))
        .filter_map(|line| {
            // Format: lxc.mount.entry = /host/path container/path none bind,create=dir 0 0
            let entry = line.split('=').nth(1)?.trim();
            let parts: Vec<&str> = entry.split_whitespace().collect();
            if parts.len() >= 4 && parts[3].contains("bind") {
                Some(ContainerMount {
                    host_path: parts[0].to_string(),
                    container_path: format!("/{}", parts[1]),
                    mount_type: "bind".to_string(),
                    read_only: parts[3].contains("ro"),
                })
            } else {
                None
            }
        })
        .collect()
}

/// List volume mounts for a Docker container (uses docker inspect)
pub fn docker_list_volumes(container: &str) -> Vec<ContainerMount> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{range .Mounts}}{{.Type}}\t{{.Source}}\t{{.Destination}}\t{{.RW}}{{println}}{{end}}", container])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 4 {
                        Some(ContainerMount {
                            host_path: parts[1].to_string(),
                            container_path: parts[2].to_string(),
                            mount_type: parts[0].to_string(),
                            read_only: parts[3] != "true",
                        })
                    } else {
                        None
                    }
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Export a Docker container as a tar image for migration.
/// Uses `docker commit` to snapshot the container state, then `docker save` to tar.
#[allow(dead_code)]
pub fn docker_export(container_name: &str) -> Result<String, String> {
    let image_tag = format!("wolfrun-migrate:{}", container_name);
    let tar_path = format!("/tmp/wolfrun-migrate-{}.tar", container_name);
    info!("Exporting Docker container '{}' to {}", container_name, tar_path);

    // Commit the container to an image
    let output = Command::new("docker")
        .args(["commit", container_name, &image_tag])
        .output()
        .map_err(|e| format!("docker commit failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("docker commit failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Save the image to a tar file
    let output = Command::new("docker")
        .args(["save", "-o", &tar_path, &image_tag])
        .output()
        .map_err(|e| format!("docker save failed: {}", e))?;

    // Clean up the temporary image
    let _ = Command::new("docker").args(["rmi", &image_tag]).output();

    if output.status.success() {
        info!("Exported Docker '{}' to {} ({})", container_name, tar_path,
            std::fs::metadata(&tar_path).map(|m| format!("{} MB", m.len() / 1_048_576)).unwrap_or_default());
        Ok(tar_path)
    } else {
        Err(format!("docker save failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

/// Import a Docker image from a tar file, then create and start a container.
#[allow(dead_code)]
pub fn docker_import(
    container_name: &str,
    tar_path: &str,
    ports: &[String],
    env: &[String],
    volumes: &[String],
) -> Result<String, String> {
    info!("Importing Docker container '{}' from {}", container_name, tar_path);

    // Load the image
    let output = Command::new("docker")
        .args(["load", "-i", tar_path])
        .output()
        .map_err(|e| format!("docker load failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("docker load failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Parse the loaded image name from stdout (e.g., "Loaded image: wolfrun-migrate:name")
    let stdout = String::from_utf8_lossy(&output.stdout);
    let image_name = stdout.lines()
        .find(|l| l.contains("Loaded image"))
        .and_then(|l| l.split(": ").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("wolfrun-migrate:{}", container_name));

    // Create container from the loaded image
    let wolfnet_ip = next_available_wolfnet_ip();
    docker_create(
        container_name, &image_name, ports, env,
        wolfnet_ip.as_deref(), None, None, None, volumes,
    )?;

    // Start it
    docker_start(container_name)?;

    // Clean up the migration image
    let _ = Command::new("docker").args(["rmi", &image_name]).output();

    info!("Imported Docker '{}' and started", container_name);
    Ok(format!("Container '{}' imported and running", container_name))
}

