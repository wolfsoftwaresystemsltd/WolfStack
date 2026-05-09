// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Per-LAN runtime health for WolfRouter.
//!
//! Detects the failure modes that produce the classic "DHCP works but
//! clients can't resolve DNS" trap (PapaSchlumpf, April 2026):
//!
//!   • dnsmasq isn't running for this LAN
//!   • dnsmasq is running but `:53` isn't bound to `router_ip`
//!     (mode=External, listen_port=5353, or systemd-resolved/lxc-net
//!     squatting on the bridge IP first)
//!   • The LAN's interface vanished, went down, or lost router_ip
//!   • A live UDP DNS probe to router_ip times out (last-mile reality
//!     check — covers the case where ss says "bound" but a host
//!     firewall layer drops queries)
//!
//! Read-only. Safe to call from a poll. Each check returns a
//! [`HealthCheck`] with a severity + optional `fix` string, in the
//! same shape as the existing preflight at GET /api/router/preflight.
//!
//! Also hosts the dnsmasq watchdog state — a per-LAN circuit breaker
//! that tracks recent restart failures so the background task in
//! main.rs doesn't loop forever on a permanently broken LAN.

use serde::Serialize;
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use super::{DnsMode, LanSegment};

/// One row in the LAN health report. Mirrors the PreflightCheck shape so
/// the UI can render both with the same component.
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    pub id: &'static str,
    pub name: &'static str,
    pub ok: bool,
    pub severity: &'static str, // "error" | "warning" | "info"
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// Optional one-click action ID the UI can wire to a button. Each ID
    /// maps to a route on the API side. Off-limits for any action that
    /// could lock the operator out (we never auto-evict the host's DNS
    /// daemon, for instance — those are explicit clicks only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'static str>,
}

/// Aggregate health for one LAN.
#[derive(Debug, Clone, Serialize)]
pub struct LanHealth {
    pub lan_id: String,
    pub lan_name: String,
    pub node_id: String,
    /// Overall status — derived from the worst check severity.
    pub status: &'static str, // "ok" | "warning" | "error" | "remote"
    pub checks: Vec<HealthCheck>,
    /// What `dhcp::resolve_apply_interface` would do right now if the
    /// watchdog re-applied. None when not owned by this node.
    pub apply_resolution: Option<super::dhcp::ApplyResolution>,
    /// Watchdog circuit-breaker state for this LAN, when present.
    pub breaker: Option<BreakerStatus>,
}

/// What the watchdog has been doing for one LAN. Surfaced so the UI can
/// show "we tried 3 times in 5 minutes, here's the last error."
#[derive(Debug, Clone, Serialize)]
pub struct BreakerStatus {
    pub open: bool,
    pub recent_failure_count: u32,
    pub last_error: Option<String>,
    pub last_attempt_secs_ago: Option<u64>,
    pub last_success_secs_ago: Option<u64>,
}

/// Build a full health report for the LAN. When the LAN is owned by a
/// different node, returns a single "remote" row pointing at the proxy
/// path the UI can use to ask the owner directly.
pub fn lan_health(lan: &LanSegment, self_node_id: &str) -> LanHealth {
    if lan.node_id != self_node_id {
        // Remote LAN — health has to be answered by the owning node.
        // Caller is expected to proxy via /api/nodes/{owner}/proxy/...
        return LanHealth {
            lan_id: lan.id.clone(),
            lan_name: lan.name.clone(),
            node_id: lan.node_id.clone(),
            status: "remote",
            checks: vec![HealthCheck {
                id: "remote",
                name: "Owned by another node",
                ok: true,
                severity: "info",
                message: format!(
                    "LAN '{}' is owned by node '{}'. Open the WolfRouter page \
                     for that node (or the cluster view) to see live health.",
                    lan.name, lan.node_id
                ),
                fix: None,
                action: None,
            }],
            apply_resolution: None,
            breaker: None,
        };
    }

    let mut checks: Vec<HealthCheck> = Vec::new();

    // 1. Resolve which interface dnsmasq SHOULD bind to. The resolution
    //    function performs safe live fixes (`ip addr add`, `ip link set
    //    up`) — we run it read-mostly here too because the live state
    //    matters more than the saved config for "is this LAN actually
    //    serving clients?". Watchdog ticks call this same function.
    let apply_resolution = match super::dhcp::resolve_apply_interface(lan) {
        Ok(r) => Some(r),
        Err(e) => {
            checks.push(HealthCheck {
                id: "iface_resolve",
                name: "LAN interface resolution",
                ok: false,
                severity: "error",
                message: e,
                fix: Some(
                    "Edit the LAN in WolfRouter → LAN segments and either point \
                     `interface` at an interface that exists, or change `router_ip` \
                     to one carried by an existing interface.".into()
                ),
                action: None,
            });
            None
        }
    };

    // Surface self-heal outcomes as warnings (they're not errors —
    // dnsmasq IS bound — but the operator should know we patched
    // around their config).
    if let Some(res) = &apply_resolution {
        match res {
            super::dhcp::ApplyResolution::Healthy { iface } => {
                checks.push(HealthCheck {
                    id: "iface_resolve",
                    name: "LAN interface",
                    ok: true,
                    severity: "info",
                    message: format!(
                        "Interface '{}' is up and carries router_ip {}.",
                        iface, lan.router_ip
                    ),
                    fix: None,
                    action: None,
                });
            }
            super::dhcp::ApplyResolution::BoundToActualInterface { configured, actual } => {
                checks.push(HealthCheck {
                    id: "iface_mismatch",
                    name: "Interface mismatch (auto-bound)",
                    ok: false,
                    severity: "warning",
                    message: format!(
                        "LAN is configured for interface '{}', but router_ip {} is on '{}'. \
                         WolfRouter bound dnsmasq to '{}' so DHCP/DNS still work — but the \
                         saved config is out of sync with the host.",
                        configured, lan.router_ip, actual, actual
                    ),
                    fix: Some(format!(
                        "Either click 'Use {actual}' to update the LAN's saved interface, \
                         or move {ip} off '{actual}' and onto '{configured}' if you \
                         really meant {configured}.",
                        actual = actual, configured = configured, ip = lan.router_ip,
                    )),
                    action: Some("set_lan_interface"),
                });
            }
            super::dhcp::ApplyResolution::AssignedRouterIp { iface } => {
                checks.push(HealthCheck {
                    id: "router_ip_live_assigned",
                    name: "router_ip auto-assigned (not persisted)",
                    ok: false,
                    severity: "warning",
                    message: format!(
                        "router_ip {} wasn't on any interface, so WolfRouter ran \
                         `ip addr add {}/<prefix> dev {}` live. This isn't persisted \
                         to /etc/network/interfaces or netplan — on reboot, the watchdog \
                         re-applies it, but you should pin it in the host's network \
                         config to be safe.",
                        lan.router_ip, lan.router_ip, iface
                    ),
                    fix: Some(format!(
                        "On Debian/Ubuntu (`/etc/network/interfaces`):\n  \
                         iface {iface} inet static\n      address {ip}/{prefix}\n\n\
                         On netplan (`/etc/netplan/*.yaml`):\n  network:\n    ethernets:\n      \
                         {iface}:\n        addresses: [{ip}/{prefix}]",
                        iface = iface, ip = lan.router_ip,
                        prefix = lan.subnet_cidr.split('/').nth(1).unwrap_or("24"),
                    )),
                    action: None,
                });
            }
            super::dhcp::ApplyResolution::BoundToBridgeMaster { slave, master } => {
                checks.push(HealthCheck {
                    id: "iface_bridge_slave",
                    name: "LAN interface enslaved to bridge",
                    ok: false,
                    severity: "warning",
                    message: format!(
                        "LAN is configured for '{}', but '{}' is enslaved to bridge '{}' \
                         (typical when a VM uses bridge-mode passthrough on this NIC). Bridge \
                         slaves can't deliver DHCP or other broadcast frames up the host stack, \
                         so dnsmasq is bound to '{}' instead. Clients still get IPs, but the \
                         saved LAN config is out of sync with the host.",
                        slave, slave, master, master
                    ),
                    fix: Some(format!(
                        "Either click 'Use {master}' to update the LAN's saved interface to the \
                         bridge, or detach '{slave}' from '{master}' if the passthrough was \
                         unintended (`ip link set {slave} nomaster`) and remove the bridge.",
                        master = master, slave = slave,
                    )),
                    action: Some("set_lan_interface"),
                });
            }
        }
    }

    // The interface dnsmasq is currently using (after self-heal). If
    // resolution failed, fall back to the saved one — every later check
    // still benefits from a best-effort answer.
    let bind_iface = apply_resolution.as_ref()
        .map(|r| r.iface().to_string())
        .unwrap_or_else(|| lan.interface.clone());

    // 2. dnsmasq process for this LAN — pid file + /proc check.
    let dnsmasq_pid = read_lan_pid(&lan.id);
    let dnsmasq_alive = dnsmasq_pid
        .map(|p| std::path::Path::new(&format!("/proc/{}", p)).exists())
        .unwrap_or(false);
    if dnsmasq_alive {
        checks.push(HealthCheck {
            id: "dnsmasq_alive",
            name: "dnsmasq process",
            ok: true,
            severity: "info",
            message: format!(
                "Running (pid {}).",
                dnsmasq_pid.unwrap_or(0)
            ),
            fix: None,
            action: None,
        });
    } else {
        checks.push(HealthCheck {
            id: "dnsmasq_alive",
            name: "dnsmasq process",
            ok: false,
            severity: "error",
            message: "No dnsmasq process is alive for this LAN. DHCP and DNS are both down.".into(),
            fix: Some(
                "Click 'Restart dnsmasq' to relaunch via the same path the watchdog uses. \
                 If it keeps dying, check `journalctl -t dnsmasq` and the rendered config \
                 at /etc/wolfstack/router/dnsmasq.d/lan-<id>.conf.".into()
            ),
            action: Some("restart_dnsmasq"),
        });
    }

    // 3. DNS listener — is `:listen_port` actually bound to router_ip?
    //    Only meaningful when the LAN is in WolfRouter mode. External
    //    mode renders `port=0` so we skip the bound-port check entirely
    //    and just confirm DHCP option 6 has somewhere to point clients.
    match lan.dns.mode {
        DnsMode::WolfRouter => {
            let target_addr = format!("{}:{}", lan.router_ip, lan.dns.listen_port);
            let bindings = ss_udp_bindings_on_port(lan.dns.listen_port);
            let bound_to_router_ip = bindings.iter()
                .any(|b| b.local_addr_matches(&lan.router_ip, lan.dns.listen_port));

            if bound_to_router_ip {
                checks.push(HealthCheck {
                    id: "dns_listener",
                    name: "DNS listener",
                    ok: true,
                    severity: "info",
                    message: format!("UDP/{} bound to {}.", lan.dns.listen_port, target_addr),
                    fix: None,
                    action: None,
                });
            } else if !bindings.is_empty() {
                // Something's on :port, just not on router_ip. Most
                // common cause: lxc-net's dnsmasq on 10.0.3.1:53, or a
                // resolver bound to 127.0.0.x:53.
                let owners: Vec<String> = bindings.iter()
                    .map(|b| format!("{} on {}", b.owner, b.local_addr))
                    .collect();
                checks.push(HealthCheck {
                    id: "dns_listener_squatter",
                    name: "DNS listener (squatter)",
                    ok: false,
                    severity: "error",
                    message: format!(
                        "Nothing is bound to {}, but UDP/{} IS in use elsewhere on this host: {}. \
                         Most likely the WolfRouter dnsmasq couldn't claim the LAN bridge IP \
                         because the configured interface doesn't actually carry router_ip, \
                         or dnsmasq isn't running.",
                        target_addr, lan.dns.listen_port, owners.join(", ")
                    ),
                    fix: Some(
                        "Click 'Restart dnsmasq' to retry. If the squatter is systemd-resolved \
                         on 0.0.0.0, use the Host DNS panel's 'Disable stub listener' action.".into()
                    ),
                    action: Some("restart_dnsmasq"),
                });
            } else {
                checks.push(HealthCheck {
                    id: "dns_listener",
                    name: "DNS listener",
                    ok: false,
                    severity: "error",
                    message: format!(
                        "Nothing is bound to UDP/{} on this host, including {}. \
                         dnsmasq either failed to start or is running with port=0.",
                        lan.dns.listen_port, target_addr
                    ),
                    fix: Some(
                        "Click 'Restart dnsmasq' below. If the rendered config has `port=0` \
                         then the LAN's DNS mode is set to External — check the LAN's DNS \
                         settings and switch to WolfRouter if you want it answering DNS.".into()
                    ),
                    action: Some("restart_dnsmasq"),
                });
            }

            // 4. Live UDP DNS probe — last-mile reality check. ss says
            //    "bound", but does a query actually round-trip? Catches
            //    the host-firewall and apparmor cases where the socket
            //    is open but packets get dropped.
            if bound_to_router_ip {
                if let Some((ok, msg)) = probe_udp_dns(&lan.router_ip, lan.dns.listen_port) {
                    if ok {
                        checks.push(HealthCheck {
                            id: "dns_probe",
                            name: "Live DNS probe",
                            ok: true,
                            severity: "info",
                            message: msg,
                            fix: None,
                            action: None,
                        });
                    } else {
                        checks.push(HealthCheck {
                            id: "dns_probe",
                            name: "Live DNS probe",
                            ok: false,
                            severity: "error",
                            message: msg,
                            fix: Some(
                                "dnsmasq is bound but doesn't answer queries from this host. \
                                 Check host iptables for a rule dropping UDP/53 on the LAN \
                                 interface, AppArmor/SELinux denials in dmesg, or whether \
                                 dnsmasq is in a restart loop (look at `journalctl -t dnsmasq`).".into()
                            ),
                            action: None,
                        });
                    }
                }
            }
        }
        DnsMode::External => {
            let ext = lan.dns.external_server.as_deref().unwrap_or("").trim();
            if ext.is_empty() {
                checks.push(HealthCheck {
                    id: "dns_external_unset",
                    name: "External DNS server",
                    ok: false,
                    severity: "error",
                    message: "DNS mode is External but no external_server is set. \
                              DHCP option 6 will fall back to advertising router_ip, \
                              which dnsmasq isn't listening on (port=0). Clients will \
                              time out resolving anything.".into(),
                    fix: Some(
                        "Edit the LAN → DNS settings and either set external_server \
                         (e.g. AdGuard Home container IP), or switch DNS mode back \
                         to WolfRouter.".into()
                    ),
                    action: None,
                });
            } else {
                checks.push(HealthCheck {
                    id: "dns_external_ok",
                    name: "External DNS server",
                    ok: true,
                    severity: "info",
                    message: format!("DHCP option 6 advertises {} (DNS off on dnsmasq).", ext),
                    fix: None,
                    action: None,
                });
            }
        }
    }

    // 5. DHCP-side liveness: when was the most recent lease written?
    let lease_path = format!("/var/lib/wolfstack-router/lan-{}.leases", lan.id);
    match std::fs::metadata(&lease_path) {
        Ok(m) => {
            let mtime = m.modified().ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            if let Some(t) = mtime {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok().map(|d| d.as_secs()).unwrap_or(0);
                let ago = now.saturating_sub(t);
                checks.push(HealthCheck {
                    id: "dhcp_leasefile",
                    name: "DHCP lease file",
                    ok: true,
                    severity: "info",
                    message: format!("Last touched {}.", human_secs(ago)),
                    fix: None,
                    action: None,
                });
            }
        }
        Err(_) => {
            // Lease file may not exist yet on a fresh LAN — informational.
            checks.push(HealthCheck {
                id: "dhcp_leasefile",
                name: "DHCP lease file",
                ok: true,
                severity: "info",
                message: "No lease file yet — dnsmasq creates it on first lease.".into(),
                fix: None,
                action: None,
            });
        }
    }

    // 6. iptables INPUT-chain check — is anything DROPing UDP/53 from
    //    the LAN subnet to router_ip? This is conservative: we only
    //    flag the unambiguous case (DROP/REJECT on udp dport 53/<port>
    //    with no matching ACCEPT before it).
    if let Some(reason) = inputs_dropping_dns(&lan.subnet_cidr, lan.dns.listen_port) {
        checks.push(HealthCheck {
            id: "iptables_drop_53",
            name: "iptables drops UDP/53",
            ok: false,
            severity: "error",
            message: reason,
            fix: Some(
                "WolfRouter doesn't install a UDP/53 DROP itself — most likely the host \
                 has its own iptables-persistent or ufw policy. Inspect with \
                 `sudo iptables -nvL INPUT --line-numbers` and remove the drop, or \
                 add an explicit ACCEPT for the LAN subnet to UDP/53 before it.".into()
            ),
            action: None,
        });
    }

    let _ = bind_iface; // Suppress unused — surfaced via apply_resolution.

    // Compute overall status from worst severity.
    let worst = if checks.iter().any(|c| !c.ok && c.severity == "error") {
        "error"
    } else if checks.iter().any(|c| !c.ok && c.severity == "warning") {
        "warning"
    } else {
        "ok"
    };

    let breaker = breaker_status(&lan.id);

    LanHealth {
        lan_id: lan.id.clone(),
        lan_name: lan.name.clone(),
        node_id: lan.node_id.clone(),
        status: worst,
        checks,
        apply_resolution,
        breaker,
    }
}

/// Cheap "is this LAN's dnsmasq actually serving traffic right now?"
/// probe used by the watchdog. Two checks combined:
///   1. The pid file points at a live process (cheap stat in /proc).
///   2. For WolfRouter-mode LANs, UDP/<listen_port> is bound to router_ip.
///      External-mode LANs render `port=0`, so we don't expect a DNS
///      socket — only the pid check applies there.
///
/// Returns true only when the LAN looks fully healthy. The watchdog
/// uses this to decide whether to re-apply.
pub fn dnsmasq_is_serving(lan: &LanSegment) -> bool {
    // Process alive?
    let Some(pid) = read_lan_pid(&lan.id) else { return false; };
    if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
        return false;
    }
    // External mode: port=0 in dnsmasq config, so no DNS socket. The
    // process being alive is enough — DHCP is what dnsmasq does there.
    if matches!(lan.dns.mode, DnsMode::External) {
        return true;
    }
    // WolfRouter mode: must be bound to router_ip on listen_port.
    let bindings = ss_udp_bindings_on_port(lan.dns.listen_port);
    bindings.iter()
        .any(|b| b.local_addr_matches(&lan.router_ip, lan.dns.listen_port))
}

// ─── ss -ulnp parsing ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct UdpBinding {
    owner: String,
    local_addr: String, // e.g. "10.10.10.1:53", "0.0.0.0:53", "[::]:53"
}

impl UdpBinding {
    fn local_addr_matches(&self, target_ip: &str, target_port: u16) -> bool {
        // Match the literal `<ip>:<port>`, plus the wildcard cases —
        // dnsmasq with bind-interfaces always reports the specific IP,
        // but a wildcard listener (0.0.0.0:53 / [::]:53) ALSO covers
        // router_ip from the kernel's POV.
        let port_suffix = format!(":{}", target_port);
        if !self.local_addr.ends_with(&port_suffix) { return false; }
        let addr_part = &self.local_addr[..self.local_addr.len() - port_suffix.len()];
        addr_part == target_ip
            || addr_part == "0.0.0.0"
            || addr_part == "[::]"
            || addr_part == "*"
    }
}

/// Parse `ss -ulnp` for every UDP socket bound to the given port. We
/// don't filter by owner here — the caller decides whether each binding
/// is "ours" or a squatter.
fn ss_udp_bindings_on_port(port: u16) -> Vec<UdpBinding> {
    let Ok(out) = Command::new("ss").args(["-ulnp"]).output() else { return vec![]; };
    if !out.status.success() { return vec![]; }
    let text = String::from_utf8_lossy(&out.stdout);
    let port_suffix = format!(":{}", port);
    let mut bindings: Vec<UdpBinding> = Vec::new();
    for line in text.lines() {
        // Skip header.
        if line.starts_with("Netid") || line.starts_with("State") { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // ss -ulnp format: Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port [Process]
        // (No Netid column when -t/-u alone, but -ulnp prints it.)
        // Find the local-addr column by scanning for one ending with our port.
        let local = parts.iter()
            .find(|p| p.ends_with(&port_suffix))
            .copied();
        let Some(local) = local else { continue; };
        let process_col = parts.last().copied().unwrap_or("");
        let owner = extract_process_name(process_col)
            .unwrap_or_else(|| "unknown".into());
        let already = bindings.iter()
            .any(|b| b.owner == owner && b.local_addr == local);
        if !already {
            bindings.push(UdpBinding {
                owner,
                local_addr: local.to_string(),
            });
        }
    }
    bindings
}

/// Extract the process name from the `users:(("dnsmasq",pid=…,fd=…))`
/// trailing column ss prints with `-p`. Returns None on parse failure.
fn extract_process_name(col: &str) -> Option<String> {
    let open = col.find("((\"")?;
    let start = open + 3;
    let rest = col.get(start..)?;
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}

// ─── pid file ───────────────────────────────────────────────────────────

fn read_lan_pid(lan_id: &str) -> Option<u32> {
    let path = format!("/run/wolfstack-router/lan-{}.pid", lan_id);
    let s = std::fs::read_to_string(&path).ok()?;
    s.trim().parse::<u32>().ok()
}

// ─── live UDP DNS probe ─────────────────────────────────────────────────

/// Send a tiny DNS query to `<target_ip>:<port>` from this host and wait
/// up to 1.5s for any response. Returns:
///   • Some((true, msg))  — got a response; DNS path works
///   • Some((false, msg)) — bound but no answer; firewall/policy issue
///   • None               — couldn't even create a socket / bad input
///
/// The query is for `wolfstack-health-probe.invalid.` so we don't pollute
/// real upstream caches and so we don't depend on any real domain
/// existing. dnsmasq will return SERVFAIL or NXDOMAIN; either is a valid
/// "yes, you're there" signal.
fn probe_udp_dns(target_ip: &str, port: u16) -> Option<(bool, String)> {
    let target: IpAddr = target_ip.parse().ok()?;
    let dest = SocketAddr::new(target, port);
    // Bind ephemeral on whatever interface the kernel picks. router_ip
    // is local to this host, so the kernel routes via the loopback fast
    // path and hits the dnsmasq socket bound to the LAN iface IP.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    sock.connect(dest).ok()?;

    let query = build_dns_a_query("wolfstack-health-probe.invalid", 0xBEEF);
    if sock.send(&query).is_err() {
        return Some((false, format!(
            "Couldn't send a UDP DNS query to {} (kernel rejected the send — \
             likely the address isn't routable from this host).",
            dest
        )));
    }
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Ok(n) if n >= 12 => Some((true, format!(
            "Sent a probe query to {} and got {} bytes back — DNS path works.",
            dest, n
        ))),
        Ok(_) => Some((false, format!(
            "Got a runt response from {} (<12 bytes — not a valid DNS reply).",
            dest
        ))),
        Err(_) => Some((false, format!(
            "Sent a UDP DNS query to {} and got no response within 1.5s. \
             ss reports the socket bound, but packets don't make it through.",
            dest
        ))),
    }
}

/// Build a DNS A-query packet for `name`. Tiny encoder — RFC1035 §4.1.
/// Header (12 B): id, flags=0x0100 RD, qdcount=1.
/// Question: <labels> 0x00 type=A(1) class=IN(1).
fn build_dns_a_query(name: &str, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    out.extend_from_slice(&1u16.to_be_bytes());      // qdcount
    out.extend_from_slice(&0u16.to_be_bytes());      // ancount
    out.extend_from_slice(&0u16.to_be_bytes());      // nscount
    out.extend_from_slice(&0u16.to_be_bytes());      // arcount
    for label in name.split('.') {
        // Defensive: oversized labels just get truncated to 63 bytes;
        // the probe target is fixed so this branch only matters if the
        // function gets reused later.
        let bytes = label.as_bytes();
        let len = bytes.len().min(63) as u8;
        out.push(len);
        out.extend_from_slice(&bytes[..len as usize]);
    }
    out.push(0);                                     // root label
    out.extend_from_slice(&1u16.to_be_bytes());      // qtype A
    out.extend_from_slice(&1u16.to_be_bytes());      // qclass IN
    out
}

// ─── iptables INPUT-chain DNS-drop heuristic ────────────────────────────

/// Look for an unambiguous `-A INPUT … -p udp --dport <port> -j DROP/REJECT`
/// with no preceding ACCEPT for the LAN subnet. Returns Some(reason) when
/// the operator's host firewall is blocking DNS, None when nothing
/// suspicious is seen.
///
/// Uses iptables-save format so we can scan all rules in one shot. We
/// purposefully don't consult ufw rule files — those compile down to
/// iptables, which we already see here.
fn inputs_dropping_dns(lan_subnet: &str, port: u16) -> Option<String> {
    let out = Command::new("iptables-save").arg("-t").arg("filter").output().ok()?;
    if !out.status.success() { return None; }
    let dump = String::from_utf8_lossy(&out.stdout);

    // Walk INPUT-chain rules in order. The first match wins per iptables
    // semantics, so we don't flag a DROP that has a preceding ACCEPT
    // for the same subnet+port.
    let mut prior_accept_for_subnet = false;
    for line in dump.lines() {
        let line = line.trim();
        if !line.starts_with("-A INPUT ") { continue; }
        // Cheap field-presence parse — iptables-save tokens are space-
        // separated and don't contain spaces in their values.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let has_proto_udp = window_contains(&tokens, &["-p", "udp"]);
        let has_dport = window_contains(&tokens, &["--dport", &port.to_string()])
            || window_contains(&tokens, &["--dports", &port.to_string()]);
        let src_match = tokens.iter().enumerate().find(|(_, t)| **t == "-s")
            .and_then(|(i, _)| tokens.get(i + 1))
            .map(|s| (*s).to_string());
        let target = tokens.iter().enumerate().find(|(_, t)| **t == "-j")
            .and_then(|(i, _)| tokens.get(i + 1))
            .map(|s| s.to_string())
            .unwrap_or_default();

        if !has_proto_udp || !has_dport { continue; }

        // Source filter: rule applies if it has no -s (matches everyone),
        // or its -s overlaps the LAN subnet (we treat exact-match as
        // overlap; partial CIDR overlap would need more work but the
        // common cases are exact-subnet rules).
        let src_applies = match &src_match {
            None => true,
            Some(s) if s == lan_subnet => true,
            Some(_) => false, // narrower or unrelated source — ignore
        };
        if !src_applies { continue; }

        if target == "ACCEPT" {
            prior_accept_for_subnet = true;
            continue;
        }
        if target == "DROP" || target == "REJECT" {
            if prior_accept_for_subnet { return None; }
            return Some(format!(
                "INPUT chain has `{} ` matching UDP/{} from {} — clients can't \
                 reach the router's DNS port even though dnsmasq is bound.",
                line, port,
                src_match.as_deref().unwrap_or("any source")
            ));
        }
    }
    None
}

fn window_contains(tokens: &[&str], window: &[&str]) -> bool {
    if tokens.len() < window.len() { return false; }
    tokens.windows(window.len()).any(|w| w == window)
}

// ─── Watchdog circuit-breaker state ─────────────────────────────────────

/// Per-LAN breaker tracking. Watchdog increments on failed restart;
/// resets on success. After 3 fails inside 5min the breaker opens and
/// the watchdog stops trying until the operator clicks "Restart" or 5
/// minutes have passed without any activity.
#[derive(Debug, Default)]
struct Breaker {
    failures: Vec<Instant>,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    last_error: Option<String>,
    open: bool,
}

const BREAKER_WINDOW: Duration = Duration::from_secs(300); // 5 min
const BREAKER_MAX_FAILURES: usize = 3;

static BREAKERS: LazyLock<Mutex<HashMap<String, Breaker>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Watchdog reports a successful (re)start.
pub fn breaker_record_success(lan_id: &str) {
    let mut map = BREAKERS.lock().unwrap();
    let b = map.entry(lan_id.to_string()).or_default();
    b.failures.clear();
    b.last_attempt = Some(Instant::now());
    b.last_success = Some(Instant::now());
    b.last_error = None;
    b.open = false;
}

/// Watchdog reports a failed (re)start.
pub fn breaker_record_failure(lan_id: &str, err: &str) {
    let mut map = BREAKERS.lock().unwrap();
    let b = map.entry(lan_id.to_string()).or_default();
    let now = Instant::now();
    b.last_attempt = Some(now);
    b.last_error = Some(err.to_string());
    b.failures.retain(|t| now.duration_since(*t) < BREAKER_WINDOW);
    b.failures.push(now);
    if b.failures.len() >= BREAKER_MAX_FAILURES {
        b.open = true;
    }
}

/// Watchdog asks "should I try a restart right now?". Returns false when
/// the breaker is open AND the last attempt was inside the cooldown
/// window — keeps us from re-trying every tick on a permanently broken LAN.
pub fn breaker_allow_attempt(lan_id: &str) -> bool {
    let map = BREAKERS.lock().unwrap();
    let Some(b) = map.get(lan_id) else { return true; };
    if !b.open { return true; }
    // Open: only allow a probe attempt if the cooldown's expired.
    match b.last_attempt {
        Some(t) => Instant::now().duration_since(t) >= BREAKER_WINDOW,
        None => true,
    }
}

/// Manual reset — UI's "Restart dnsmasq" action calls this so the
/// watchdog gets a fresh chance after the operator's intervention.
pub fn breaker_reset(lan_id: &str) {
    let mut map = BREAKERS.lock().unwrap();
    if let Some(b) = map.get_mut(lan_id) {
        b.failures.clear();
        b.open = false;
    }
}

fn breaker_status(lan_id: &str) -> Option<BreakerStatus> {
    let map = BREAKERS.lock().unwrap();
    let b = map.get(lan_id)?;
    let now = Instant::now();
    Some(BreakerStatus {
        open: b.open,
        recent_failure_count: b.failures.iter()
            .filter(|t| now.duration_since(**t) < BREAKER_WINDOW)
            .count() as u32,
        last_error: b.last_error.clone(),
        last_attempt_secs_ago: b.last_attempt.map(|t| now.duration_since(t).as_secs()),
        last_success_secs_ago: b.last_success.map(|t| now.duration_since(t).as_secs()),
    })
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn human_secs(s: u64) -> String {
    if s < 60 { return format!("{}s ago", s); }
    if s < 3600 { return format!("{}m ago", s / 60); }
    if s < 86400 { return format!("{}h ago", s / 3600); }
    format!("{}d ago", s / 86400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_a_query_is_well_formed() {
        let q = build_dns_a_query("example.com", 0x1234);
        // Header = 12 bytes; question = labels(7+5+1) + 2 (qtype) + 2 (qclass)
        assert_eq!(q.len(), 12 + 7 + 5 + 1 + 4);
        assert_eq!(&q[0..2], &[0x12, 0x34]);     // id
        assert_eq!(&q[2..4], &[0x01, 0x00]);     // flags=RD
        assert_eq!(&q[4..6], &[0x00, 0x01]);     // qdcount=1
        // First label "example" — len 7
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        // qtype=A, qclass=IN
        assert_eq!(&q[25..27], &[0, 1]);
        assert_eq!(&q[27..29], &[0, 1]);
    }

    #[test]
    fn binding_matches_router_ip() {
        let b = UdpBinding {
            owner: "dnsmasq".into(),
            local_addr: "10.10.10.1:53".into(),
        };
        assert!(b.local_addr_matches("10.10.10.1", 53));
        assert!(!b.local_addr_matches("10.10.10.2", 53));
        assert!(!b.local_addr_matches("10.10.10.1", 5353));
    }

    #[test]
    fn binding_wildcard_matches() {
        let b = UdpBinding {
            owner: "named".into(),
            local_addr: "0.0.0.0:53".into(),
        };
        assert!(b.local_addr_matches("10.10.10.1", 53));
        assert!(b.local_addr_matches("192.168.99.1", 53));
        assert!(!b.local_addr_matches("10.10.10.1", 5353));
    }

    #[test]
    fn breaker_opens_after_three_failures() {
        let id = "test-breaker-open";
        // Reset state from any prior test run.
        breaker_record_success(id);
        assert!(breaker_allow_attempt(id));
        breaker_record_failure(id, "x");
        breaker_record_failure(id, "x");
        assert!(breaker_allow_attempt(id));
        breaker_record_failure(id, "x");
        // Open: cooldown blocks. last_attempt was just set, so window
        // hasn't elapsed.
        assert!(!breaker_allow_attempt(id));
        // Manual reset re-enables attempts.
        breaker_reset(id);
        assert!(breaker_allow_attempt(id));
    }

    #[test]
    fn human_secs_formats() {
        assert_eq!(human_secs(0), "0s ago");
        assert_eq!(human_secs(45), "45s ago");
        assert_eq!(human_secs(60), "1m ago");
        assert_eq!(human_secs(3600), "1h ago");
        assert_eq!(human_secs(86400), "1d ago");
    }

    #[test]
    fn iptables_drop_heuristic_no_match_when_not_seen() {
        // Empty INPUT — no DROP exists, function returns None when
        // iptables-save isn't on PATH or there's no matching rule.
        // We can't fake iptables-save here, so just assert the helper
        // tokenisation works.
        let toks = vec!["-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "DROP"];
        assert!(window_contains(&toks, &["-p", "udp"]));
        assert!(window_contains(&toks, &["--dport", "53"]));
        assert!(!window_contains(&toks, &["--dport", "5353"]));
    }
}
