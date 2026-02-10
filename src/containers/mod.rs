//! Container management — Docker and LXC support for WolfStack
//!
//! Docker: communicates via /var/run/docker.sock REST API
//! LXC: communicates via lxc-* CLI commands
//! WolfNet: Optional overlay network integration for container networking

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, error};

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

    // Check Docker containers connected to wolfnet
    if let Ok(output) = Command::new("docker")
        .args(["network", "inspect", "wolfnet", "--format",
               "{{range .Containers}}{{.IPv4Address}} {{end}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for addr in text.split_whitespace() {
            if let Some(ip) = addr.split('/').next() {
                let ip_parts: Vec<&str> = ip.split('.').collect();
                if ip_parts.len() == 4 {
                    if let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
                }
            }
        }
    }

    // Check LXC containers too
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
        if let Some(ip) = text.lines()
            .find(|l| l.contains("inet "))
            .and_then(|l| l.trim().split_whitespace().nth(1))
            .and_then(|s| s.split('/').next())
        {
            ips.push(ip.to_string());
        }
    }

    // Docker containers on wolfnet
    if let Ok(output) = Command::new("docker")
        .args(["network", "inspect", "wolfnet", "--format",
               "{{range .Containers}}{{.IPv4Address}} {{end}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for addr in text.split_whitespace() {
            if let Some(ip) = addr.split('/').next() {
                if !ip.is_empty() {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    // LXC containers (from ARP table)
    if let Ok(output) = Command::new("ip")
        .args(["neigh", "show", "dev", "wolfnet0"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(ip) = line.split_whitespace().next() {
                if ip.contains('.') {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    ips
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

    // 2. Configure Container Side
    // Add IP alias /32
    let exec_ip = Command::new("docker")
        .args(["exec", container, "ip", "addr", "add", &format!("{}/32", ip), "dev", "eth0"])
        .output();
    
    // Add route to WolfNet subnet via gateway
    // Assuming WolfNet is 10.10.10.0/24 — really should get this from config but defaulting for now
    let subnet = "10.10.10.0/24";
    let _ = Command::new("docker")
        .args(["exec", container, "ip", "route", "add", subnet, "via", &gateway])
        .output();

    if let Err(e) = exec_ip {
        return Err(format!("Failed to configure container: {}", e));
    }

    // 3. Configure Host Side
    // Enable forwarding for WolfNet <-> Docker
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", "wolfnet0", "-o", "docker0", "-j", "ACCEPT"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", "docker0", "-o", "wolfnet0", "-j", "ACCEPT"]).output();

    // Route traffic for this container IP to docker0
    let _ = Command::new("ip")
        .args(["route", "add", &format!("{}/32", ip), "dev", "docker0"])
        .output();

    Ok(format!("Container '{}' routed to WolfNet at {}", container, ip))
}

/// Ensure lxcbr0 bridge exists for default LXC container networking (with DHCP/NAT)
pub fn ensure_lxc_bridge() {
    // 1. Try standard systemd service first
    let _ = Command::new("systemctl").args(["enable", "--now", "lxc-net"]).output();
    
    // Wait briefly for service to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if lxcbr0 exists and has an IP
    if let Ok(output) = Command::new("ip").args(["addr", "show", "lxcbr0"]).output() {
        if output.status.success() { 
            // Check if dnsmasq is running on it (port 53/67)
            // ps aux | grep dnsmasq | grep lxcbr0
            let ps = Command::new("pgrep").args(["-f", "dnsmasq.*lxcbr0"]).output();
            if let Ok(p) = ps {
                if p.status.success() { return; }
            }
        }
    }

    info!("Manually configuring lxcbr0 bridge and DHCP");

    // Create bridge (idempotent)
    let _ = Command::new("ip").args(["link", "add", "lxcbr0", "type", "bridge"]).output();
    let _ = Command::new("ip").args(["addr", "add", "10.0.3.1/24", "dev", "lxcbr0"]).output();
    let _ = Command::new("ip").args(["link", "set", "lxcbr0", "up"]).output();

    // Enable NAT
    let _ = Command::new("sh").args(["-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]).output();
    let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.0.3.0/24", "!", "-d", "10.0.3.0/24", "-j", "MASQUERADE"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", "lxcbr0", "-j", "ACCEPT"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-o", "lxcbr0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();

    // Start dnsmasq for DHCP
    // dnsmasq --strict-order --bind-interfaces --pid-file=/run/lxc/dnsmasq.pid --listen-address 10.0.3.1 --dhcp-range 10.0.3.2,10.0.3.254 --dhcp-lease-max=253 --dhcp-no-override --except-interface=lo --interface=lxcbr0
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

    Ok(format!("LXC container '{}' will use WolfNet IP {} on start", container, ip))
}

/// Apply WolfNet IP inside a running container (called after lxc-start)
fn lxc_apply_wolfnet(container: &str) {
    let ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", container);
    if let Ok(ip) = std::fs::read_to_string(&ip_file) {
        let ip = ip.trim();
        if ip.is_empty() { return; }
        info!("Applying WolfNet IP {} to container {}", ip, container);

        // Wait for container networking to be ready
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Step 1: Ensure container has a bridge IPv4 (10.0.3.x) on eth0
        //         This is REQUIRED — without it, ARP fails on lxcbr0
        let mut bridge_ip = get_container_ipv4(container);
        if bridge_ip.is_empty() {
            info!("No IPv4 on eth0, trying dhclient...");
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "dhclient", "-4", "eth0"])
                .output();
            std::thread::sleep(std::time::Duration::from_secs(3));
            bridge_ip = get_container_ipv4(container);
        }
        if bridge_ip.is_empty() {
            // Static fallback: derive 10.0.3.x from last octet of WolfNet IP
            let last: u8 = ip.split('.').last()
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(50)
                .wrapping_add(100);
            bridge_ip = format!("10.0.3.{}", last);
            info!("dhclient failed, assigning static bridge IP: {}", bridge_ip);
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/24", bridge_ip), "dev", "eth0"])
                .output();
            let _ = Command::new("lxc-attach")
                .args(["-n", container, "--", "ip", "route", "add", "default", "via", "10.0.3.1"])
                .output();
        }
        info!("Container {} bridge IP: {}", container, bridge_ip);

        // Step 2: Add WolfNet IP as secondary /32 on eth0
        let _ = Command::new("lxc-attach")
            .args(["-n", container, "--", "ip", "addr", "add", &format!("{}/32", ip), "dev", "eth0"])
            .output();

        // Step 3: Host route — via bridge IP so ARP resolves on lxcbr0
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

        // Step 4: Forwarding + iptables
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.forwarding=1"]).output();
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.proxy_arp=1"]).output();
        let check = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
        if check.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
            let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", "lxcbr0", "-o", "wolfnet0", "-j", "ACCEPT"]).output();
        }

        info!("WolfNet ready: {} -> wolfnet={}, bridge={}", container, ip, bridge_ip);
    }
}

/// Get IPv4 address from a running LXC container's eth0
fn get_container_ipv4(container: &str) -> String {
    Command::new("lxc-attach")
        .args(["-n", container, "--", "sh", "-c",
            "ip -4 addr show eth0 | grep -oP 'inet \\K[0-9.]+' | head -1"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
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
                    // Get IP from docker inspect for this container
                    let ip = Command::new("docker")
                        .args(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", &name])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();
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
    run_docker_cmd(&["start", container])
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
                    }
                })
                .collect()
        })
        .unwrap_or_default()
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
    let result = run_lxc_cmd(&["lxc-start", "-n", container]);
    
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

    // Wait for container init to finish
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Install openssh-server
    let _ = Command::new("lxc-attach")
        .args(["-n", container, "--", "sh", "-c",
            "apt-get update -qq && apt-get install -y -qq openssh-server 2>/dev/null || yum install -y openssh-server 2>/dev/null || apk add openssh 2>/dev/null || true"])
        .output();

    // Enable root SSH login
    let _ = Command::new("lxc-attach")
        .args(["-n", container, "--", "sh", "-c",
            "sed -i 's/#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null; \
             sed -i 's/#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null; \
             mkdir -p /run/sshd; \
             service ssh restart 2>/dev/null || systemctl restart sshd 2>/dev/null || /usr/sbin/sshd 2>/dev/null || true"])
        .output();

    // Create WolfStack MOTD
    let motd = r#"
 __        __    _  __ ____  _             _    
 \ \      / /__ | |/ _/ ___|| |_ __ _  ___| | __
  \ \ /\ / / _ \| | |_\___ \| __/ _` |/ __| |/ /
   \ V  V / (_) | |  _|___) | || (_| | (__|   < 
    \_/\_/ \___/|_|_| |____/ \__\__,_|\___|_|\_\

  Managed by WolfStack — wolf.uk.com
  Container powered by Wolf Software Systems Ltd

"#;
    let _ = Command::new("lxc-attach")
        .args(["-n", container, "--", "sh", "-c", &format!("cat > /etc/motd << 'MOTD'\n{}\nMOTD", motd)])
        .output();

    // Mark setup as done
    let _ = std::fs::write(&marker, "done");
    info!("First-boot setup complete for container {}", container);
}

/// Stop an LXC container
pub fn lxc_stop(container: &str) -> Result<String, String> {
    run_lxc_cmd(&["lxc-stop", "-n", container])
}

/// Restart an LXC container
pub fn lxc_restart(container: &str) -> Result<String, String> {
    lxc_stop(container)?;
    lxc_start(container)
}

/// Freeze (pause) an LXC container
pub fn lxc_freeze(container: &str) -> Result<String, String> {
    run_lxc_cmd(&["lxc-freeze", "-n", container])
}

/// Unfreeze an LXC container
pub fn lxc_unfreeze(container: &str) -> Result<String, String> {
    run_lxc_cmd(&["lxc-unfreeze", "-n", container])
}

/// Destroy an LXC container
pub fn lxc_destroy(container: &str) -> Result<String, String> {
    lxc_stop(container).ok(); // Stop first, ignore errors
    run_lxc_cmd(&["lxc-destroy", "-n", container])
}

/// Read LXC container config
pub fn lxc_config(container: &str) -> Option<String> {
    let path = format!("/var/lib/lxc/{}/config", container);
    std::fs::read_to_string(&path).ok()
}

/// Save LXC container config
pub fn lxc_save_config(container: &str, content: &str) -> Result<String, String> {
    let path = format!("/var/lib/lxc/{}/config", container);
    std::fs::write(&path, content)
        .map(|_| "Config saved".to_string())
        .map_err(|e| format!("Failed to save config: {}", e))
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

/// List available LXC templates from the LXC image server
pub fn lxc_list_templates() -> Vec<LxcTemplate> {
    // Try fetching from lxc image server index
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
            if variant_str == "cloud" { continue; }
            if arch == "amd64" && !dist.is_empty() && !rel.is_empty() {
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

/// Create an LXC container from a download template
pub fn lxc_create(name: &str, distribution: &str, release: &str, architecture: &str, storage_path: Option<&str>) -> Result<String, String> {
    info!("Creating LXC container {} ({} {} {})", name, distribution, release, architecture);

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
pub fn docker_search(query: &str) -> Vec<DockerSearchResult> {
    let output = Command::new("docker")
        .args(["search", "--format", "{{.Name}}\\t{{.Description}}\\t{{.StarCount}}\\t{{.IsOfficial}}", "--limit", "25", query])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
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
                .collect()
        }
        _ => vec![],
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
pub fn docker_create(name: &str, image: &str, ports: &[String], env: &[String], wolfnet_ip: Option<&str>, 
                     memory: Option<&str>, cpus: Option<&str>, storage: Option<&str>) -> Result<String, String> {
    info!("Creating Docker container {} from image {}", name, image);

    let mut args = vec!["create".to_string(), "--name".to_string(), name.to_string()];

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
    if let Some(store) = storage {
        if !store.is_empty() {
            args.push("--storage-opt".to_string());
            args.push(format!("size={}", store));
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

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("docker")
        .args(&args_ref)
        .output()
        .map_err(|e| format!("Failed to create container: {}", e))?;

    if output.status.success() {
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info!("Docker container {} created ({})", name, &id[..12.min(id.len())]);

        // Connect to WolfNet if requested
        if let Some(ip) = wolfnet_ip {
            if !ip.is_empty() {
                match docker_connect_wolfnet(name, ip) {
                    Ok(msg) => info!("{}", msg),
                    Err(e) => info!("WolfNet connect warning: {} (container still created)", e),
                }
            }
        }

        let wolfnet_msg = wolfnet_ip
            .filter(|ip| !ip.is_empty())
            .map(|ip| format!(" [WolfNet: {}]", ip))
            .unwrap_or_default();

        Ok(format!("Container '{}' created ({}){}", name, &id[..12.min(id.len())], wolfnet_msg))
    } else {
        Err(format!(
            "Create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
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
    let output = Command::new("curl")
        .args([
            "-s", "-X", "POST",
            "-H", "Content-Type: application/octet-stream",
            "--data-binary", &format!("@{}", export_path),
            &import_url,
        ])
        .output()
        .map_err(|e| format!("Failed to send to remote: {}", e))?;

    // Clean up temp files
    let _ = std::fs::remove_file(&export_path);
    let _ = Command::new("docker").args(["rmi", &temp_image]).output();

    if !output.status.success() {
        return Err(format!(
            "Transfer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let response = String::from_utf8_lossy(&output.stdout).to_string();
    
    // Step 5: Optionally remove the source container
    if remove_source {
        let _ = docker_remove(container);
        info!("Container {} migrated to {} and removed from source", container, target_url);
    } else {
        info!("Container {} copied to {}", container, target_url);
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

/// Clone an LXC container using lxc-copy
pub fn lxc_clone(container: &str, new_name: &str) -> Result<String, String> {
    info!("Cloning LXC container {} as {}", container, new_name);

    let output = Command::new("lxc-copy")
        .args(["-n", container, "-N", new_name])
        .output()
        .map_err(|e| format!("Failed to clone LXC container: {}", e))?;

    if output.status.success() {
        Ok(format!("LXC container cloned as '{}'", new_name))
    } else {
        Err(format!(
            "LXC clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Clone an LXC container as a snapshot (faster, copy-on-write)
pub fn lxc_clone_snapshot(container: &str, new_name: &str) -> Result<String, String> {
    info!("Snapshot-cloning LXC container {} as {}", container, new_name);

    let output = Command::new("lxc-copy")
        .args(["-n", container, "-N", new_name, "-s"])
        .output()
        .map_err(|e| format!("Failed to snapshot-clone LXC container: {}", e))?;

    if output.status.success() {
        Ok(format!("LXC container snapshot-cloned as '{}'", new_name))
    } else {
        Err(format!(
            "LXC snapshot clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
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
