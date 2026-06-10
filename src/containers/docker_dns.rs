// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Docker DNS and outbound connectivity — ensures Docker containers can
//! resolve DNS and reach the outside world on hosts running
//! systemd-resolved.
//!
//! Problem: systemd-resolved puts `127.0.0.53` in /etc/resolv.conf.
//! Docker copies that into containers where it's unreachable (the
//! container's own loopback, nothing listening). Docker's built-in
//! fallback to 8.8.8.8 doesn't always fire and ignores the host's
//! real upstream DNS / search domains.
//!
//! Fix: detect the host's real upstream nameservers (via
//! `networking::get_dns()` which already filters 127.0.0.53) and
//! write them to `/etc/docker/daemon.json` so every container gets
//! working DNS by default. Also provides `get_docker_dns_servers()`
//! for per-container `--dns` flags.
//!
//! Additionally ensures Docker's own NAT and FORWARD iptables rules
//! are intact — on some hosts these get clobbered by firewalld
//! reloads, nftables flushes, or WolfStack's own wolfnet0 rule
//! management.

use std::process::Command;
use tracing::{info, warn};

const DAEMON_JSON: &str = "/etc/docker/daemon.json";

/// Get the host's real DNS servers for use with Docker `--dns` flags.
/// Returns the actual upstream nameservers (never 127.0.0.53), with
/// a safe fallback to 8.8.8.8 + 1.1.1.1 if detection fails.
pub fn get_docker_dns_servers() -> Vec<String> {
    let dns = crate::networking::get_dns();
    let mut servers = dns.nameservers;
    // Belt-and-suspenders: filter stub even though get_dns() should
    // already do this for systemd-resolved/netplan methods.
    servers.retain(|s| s != "127.0.0.53" && s != "127.0.0.1");
    if servers.is_empty() {
        servers = vec!["8.8.8.8".into(), "1.1.1.1".into()];
    }
    // Cap at 3 — Docker only uses the first 3 DNS servers.
    servers.truncate(3);
    servers
}

/// Ensure `/etc/docker/daemon.json` contains real upstream DNS servers.
/// Merges the `"dns"` key into the existing file, preserving all other
/// settings (storage-driver, log config, etc). Returns true if the
/// file was changed and Docker should be reloaded.
pub fn ensure_docker_dns() -> bool {
    // Only act if Docker is installed.
    if !docker_installed() {
        return false;
    }

    let servers = get_docker_dns_servers();
    let dns_json: Vec<serde_json::Value> = servers.iter()
        .map(|s| serde_json::Value::String(s.clone()))
        .collect();

    // Read existing daemon.json (or start with empty object).
    let mut config: serde_json::Map<String, serde_json::Value> = match std::fs::read_to_string(DAEMON_JSON) {
        Ok(content) => {
            let content = content.trim();
            if content.is_empty() {
                serde_json::Map::new()
            } else {
                match serde_json::from_str(content) {
                    Ok(serde_json::Value::Object(map)) => map,
                    _ => {
                        warn!("docker_dns: {} is not valid JSON — will overwrite", DAEMON_JSON);
                        serde_json::Map::new()
                    }
                }
            }
        }
        Err(_) => serde_json::Map::new(),
    };

    // Check if the current dns key already matches.
    let new_dns = serde_json::Value::Array(dns_json);
    if config.get("dns") == Some(&new_dns) {
        return false; // Already correct — no change needed.
    }

    // Merge our dns key.
    config.insert("dns".to_string(), new_dns);

    // Write atomically: tmp file + rename.
    let _ = std::fs::create_dir_all("/etc/docker");
    let tmp_path = format!("{}.wolfstack-tmp", DAEMON_JSON);
    let json_str = match serde_json::to_string_pretty(&serde_json::Value::Object(config)) {
        Ok(s) => s,
        Err(e) => {
            warn!("docker_dns: failed to serialize daemon.json: {}", e);
            return false;
        }
    };

    if let Err(e) = std::fs::write(&tmp_path, format!("{}\n", json_str)) {
        warn!("docker_dns: failed to write {}: {}", tmp_path, e);
        return false;
    }
    if let Err(e) = std::fs::rename(&tmp_path, DAEMON_JSON) {
        warn!("docker_dns: failed to rename {} to {}: {}", tmp_path, DAEMON_JSON, e);
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }

    info!("docker_dns: updated {} with DNS servers {:?}", DAEMON_JSON, servers);
    true
}

/// Remove WolfStack-managed DNS keys from daemon.json. Used by
/// uninstall so we don't leave stale config behind. Preserves all
/// other user-set keys.
#[allow(dead_code)]
pub fn remove_docker_dns() {
    let content = match std::fs::read_to_string(DAEMON_JSON) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut config: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(content.trim()) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => return,
    };

    let had_dns = config.remove("dns").is_some();
    if !had_dns {
        return;
    }

    if config.is_empty() {
        // Nothing left — remove the file entirely.
        let _ = std::fs::remove_file(DAEMON_JSON);
        info!("docker_dns: removed {} (was empty after cleanup)", DAEMON_JSON);
    } else {
        if let Ok(json_str) = serde_json::to_string_pretty(&serde_json::Value::Object(config)) {
            let _ = std::fs::write(DAEMON_JSON, format!("{}\n", json_str));
            info!("docker_dns: removed dns key from {}", DAEMON_JSON);
        }
    }
}

/// Reload Docker daemon to pick up daemon.json changes. Tries
/// `systemctl reload` first (Docker 25+, no container disruption),
/// falls back to `systemctl restart` on older versions.
pub fn reload_docker_if_needed() {
    // `reload` sends SIGHUP — supported on modern Docker.
    let reload = Command::new("systemctl")
        .args(["reload", "docker"])
        .output();
    match reload {
        Ok(o) if o.status.success() => {
            info!("docker_dns: reloaded Docker daemon (SIGHUP)");
        }
        _ => {
            // Fallback: full restart. This briefly interrupts running
            // containers but ensures daemon.json is picked up.
            info!("docker_dns: reload not supported — restarting Docker daemon");
            let _ = Command::new("systemctl")
                .args(["restart", "docker"])
                .output();
        }
    }
}

/// Ensure Docker's outbound connectivity is working: ip_forward on,
/// MASQUERADE rules for Docker bridge subnets, FORWARD rules allowing
/// traffic from Docker bridges. Called periodically alongside
/// `ensure_docker_wolfnet_network()`.
///
/// Docker normally manages its own iptables rules, but they can be
/// clobbered by: firewalld reloads, nftables flushes, manual
/// iptables-restore, or certain system update scripts. This function
/// detects the gap and re-adds the minimum rules needed.
pub fn ensure_docker_outbound() {
    if !docker_installed() {
        return;
    }

    // 1. ip_forward must be on (Docker normally sets this, but
    //    firewalld reloads can reset it on some distros).
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output();

    // 2. Discover Docker bridge networks and their subnets.
    //    `docker network ls` + `docker network inspect` give us the
    //    subnet and bridge interface for each network.
    let networks = discover_docker_bridge_networks();

    for net in &networks {
        // 3. MASQUERADE — NAT for outbound traffic from this subnet.
        //    Docker's own rule: -s <subnet> ! -o <bridge> -j MASQUERADE
        let nat_present = Command::new("iptables")
            .args([
                "-t", "nat", "-C", "POSTROUTING",
                "-s", &net.subnet, "!", "-o", &net.bridge,
                "-j", "MASQUERADE",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !nat_present {
            let o = Command::new("iptables")
                .args([
                    "-t", "nat", "-A", "POSTROUTING",
                    "-s", &net.subnet, "!", "-o", &net.bridge,
                    "-j", "MASQUERADE",
                ])
                .output();
            if let Ok(o) = o {
                if o.status.success() {
                    info!("docker_dns: re-added MASQUERADE for {} via {}", net.subnet, net.bridge);
                } else {
                    warn!("docker_dns: MASQUERADE insert for {} failed: {}",
                        net.subnet, String::from_utf8_lossy(&o.stderr).trim());
                }
            }
        }

        // 4. FORWARD — allow outbound from this bridge.
        let fwd_out = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", &net.bridge, "!", "-o", &net.bridge, "-j", "ACCEPT"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !fwd_out {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", "-i", &net.bridge, "!", "-o", &net.bridge, "-j", "ACCEPT"])
                .output();
            info!("docker_dns: re-added FORWARD -i {} ACCEPT", net.bridge);
        }

        // 5. FORWARD — allow return traffic to this bridge.
        let fwd_in = Command::new("iptables")
            .args([
                "-C", "FORWARD", "-o", &net.bridge,
                "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                "-j", "ACCEPT",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !fwd_in {
            let _ = Command::new("iptables")
                .args([
                    "-I", "FORWARD", "-o", &net.bridge,
                    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                    "-j", "ACCEPT",
                ])
                .output();
        }

        // 6. Per-interface forwarding sysctl.
        let _ = Command::new("sysctl")
            .args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", net.bridge)])
            .output();
    }
}

/// A Docker bridge network with its subnet and host-side interface.
struct DockerBridgeNet {
    #[allow(dead_code)]
    name: String,
    subnet: String,
    bridge: String,
}

/// Discover all Docker bridge networks, their subnets, and their
/// host-side bridge interface names.
fn discover_docker_bridge_networks() -> Vec<DockerBridgeNet> {
    let mut nets = Vec::new();

    // `docker network ls --filter driver=bridge --format '{{.Name}}'`
    let output = match Command::new("docker")
        .args(["network", "ls", "--filter", "driver=bridge", "--format", "{{.Name}}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return nets,
    };

    let names = String::from_utf8_lossy(&output.stdout);
    for name in names.lines() {
        let name = name.trim();
        if name.is_empty() { continue; }

        // Inspect each network for subnet + bridge interface.
        let inspect_fmt = "{{range .IPAM.Config}}{{.Subnet}}{{end}}|{{.Options}}|{{.Id}}";
        let inspect = match Command::new("docker")
            .args(["network", "inspect", name, "--format", inspect_fmt])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => continue,
        };

        let parts: Vec<&str> = inspect.split('|').collect();
        let subnet = if !parts.is_empty() { parts[0].trim() } else { "" };
        if subnet.is_empty() { continue; }

        // Determine the bridge interface name.
        let bridge = docker_network_bridge_name(name);
        if bridge.is_empty() { continue; }

        nets.push(DockerBridgeNet {
            name: name.to_string(),
            subnet: subnet.to_string(),
            bridge,
        });
    }

    nets
}

/// Get the host-side bridge interface name for a Docker network.
fn docker_network_bridge_name(network: &str) -> String {
    if network == "bridge" {
        return "docker0".to_string();
    }

    // Check for explicit bridge name option.
    let explicit = Command::new("docker")
        .args(["network", "inspect", network, "--format",
               "{{index .Options \"com.docker.network.bridge.name\"}}"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !explicit.is_empty() && explicit != "<no value>" {
        return explicit;
    }

    // Default: br-<first 12 chars of network ID>.
    let net_id = Command::new("docker")
        .args(["network", "inspect", network, "--format", "{{.Id}}"])
        .output()
        .map(|o| {
            let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if id.len() >= 12 { id[..12].to_string() } else { id }
        })
        .unwrap_or_default();
    if !net_id.is_empty() {
        return format!("br-{}", net_id);
    }

    String::new()
}

/// Quick check: is Docker installed on this host?
fn docker_installed() -> bool {
    Command::new("docker").arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
