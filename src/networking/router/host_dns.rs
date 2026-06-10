// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Host DNS resolver integration — detect what owns port 53 on this
//! node and, when requested, free it up so containerised DNS servers
//! (AdGuard Home, Pi-hole) can bind it directly.
//!
//! Scope: systemd-resolved (the 90 % case on modern Linux) has full
//! release/restore support. Other resolvers (dnsmasq, unbound, named)
//! are detected read-only — the UI surfaces that they're present and
//! tells the operator what to do manually. Writing four different
//! config grammars is a separate feature.

use serde::Serialize;
use std::path::Path;
use std::process::Command;

use super::{DnsMode, LanSegment};

/// One process currently bound to something:53 on this host. We collect
/// every binding rather than the first so the panel can show the real
/// state (stub + per-LAN dnsmasq typically coexist on different addrs).
#[derive(Debug, Clone, Serialize)]
pub struct Port53Binding {
    /// Process name as reported by `ss -tulnp` (e.g. "dnsmasq",
    /// "systemd-resolve").
    pub owner: String,
    /// Local address:port the process is bound to (e.g.
    /// "127.0.0.53:53", "192.168.10.1:53", "0.0.0.0:53").
    pub local_addr: String,
}

/// One WolfRouter LAN served by THIS node, surfaced to the panel so the
/// UI can offer a per-LAN "move dnsmasq off :53" action without having
/// to fetch `/api/router/segments` separately. Only local LANs are
/// included — the Host DNS panel is node-scoped.
#[derive(Debug, Clone, Serialize)]
pub struct WolfRouterLanDns {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub router_ip: String,
    /// "wolf_router" or "external" — matches DnsMode's serde rename.
    pub mode: String,
    pub listen_port: u16,
}

/// Detection result surfaced to the UI. `resolver` names the daemon
/// currently bound to port 53 on this host (or `"none"`); the other
/// fields carry enough context for the panel to explain itself.
#[derive(Debug, Clone, Serialize)]
pub struct HostDnsStatus {
    pub resolver: String,
    /// Kept for backward compatibility with older UIs: the first
    /// non-stub owner seen, or the stub owner when it's alone. New
    /// code should iterate `port_53_bindings` instead.
    pub port_53_owner: Option<String>,
    /// Every process currently holding a `:53` socket on this host.
    /// Stub + per-LAN dnsmasq routinely coexist on different local
    /// addrs; the panel needs the full list to avoid race-sensitive
    /// "first one wins" misrepresentation (bug seen in v18.7.25).
    pub port_53_bindings: Vec<Port53Binding>,
    /// True when systemd-resolved's stub listener is on — i.e. it's
    /// actively holding 127.0.0.53:53.
    pub stub_listener: bool,
    /// True when we've already dropped in our release-port-53 override.
    pub release_applied: bool,
    /// True when WolfRouter's own dnsmasq serves a LAN on this node
    /// *on port 53*. When true the UI shows per-LAN "move off :53"
    /// actions so the operator can free :53 for a containerised
    /// resolver (AdGuard Home, Pi-hole) without breaking their LAN
    /// DNS — the old "Release" button couldn't help because stopping
    /// systemd-resolved's stub alone doesn't vacate :53 on the LAN
    /// bridge.
    pub wolfrouter_owns_53: bool,
    /// WolfRouter LANs owned by this node, with their DNS mode and
    /// port. Empty when this node serves no LANs. The UI renders one
    /// row per LAN and offers "move DNS off :53" on any row whose
    /// mode is WolfRouter and listen_port is 53.
    pub wolfrouter_lans: Vec<WolfRouterLanDns>,
    /// Nameservers seen in /etc/resolv.conf at the moment of detection.
    pub resolv_conf_servers: Vec<String>,
    /// Detected distro family — helps the UI and the enforcer pick
    /// the right strategy per distro (e.g. Ubuntu ships NM-controlled
    /// resolv.conf by default; Proxmox often doesn't run resolved at
    /// all). `"debian" | "ubuntu" | "fedora" | "arch" | "proxmox" |
    /// "alpine" | "unknown"`.
    pub distro: String,
    /// NetworkManager is present on this host. When true and we write
    /// to /etc/resolv.conf, NM may clobber us back — we warn and tell
    /// the operator to disable NM's resolv.conf management.
    pub network_manager_active: bool,
    /// /etc/resolv.conf has the immutable attribute (`chattr +i`). We
    /// can't write to it without clearing the flag first.
    pub resolv_conf_immutable: bool,
    /// Whether the tools the release logic actually needs (`systemctl`
    /// and `ss`) were found on PATH. `resolvectl` is nice-to-have (it
    /// gives us the definitive stub-listener readout) but not
    /// required — we fall back to `systemctl is-active` + defaults.
    pub tools_ok: bool,
    /// Human-readable summary for the panel.
    pub message: String,
}

const RELEASE_DROPIN: &str = "/etc/systemd/resolved.conf.d/99-wolfstack-release-53.conf";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_BACKUP: &str = "/etc/resolv.conf.wolfstack-backup";
/// NetworkManager drop-in that stops NM rewriting /etc/resolv.conf.
/// Present on release, removed on restore. Only written when NM is
/// detected as active — most non-desktop distros don't ship NM at all.
const NM_DROPIN: &str = "/etc/NetworkManager/conf.d/99-wolfstack-release-53.conf";

/// Detect host DNS state. Read-only — safe to call from a status poll.
///
/// `lans` is the full WolfRouter LAN list (from RouterConfig). Only
/// LANs whose `node_id` matches `self_node_id` are reported — the
/// panel is node-scoped so remote LANs aren't relevant here.
pub fn detect(lans: &[LanSegment], self_node_id: &str) -> HostDnsStatus {
    let release_applied = Path::new(RELEASE_DROPIN).exists();
    let stub_listener = detect_stub_listener();
    let port_53_bindings = detect_port_53_bindings();
    // Backward-compat: pick a representative owner. Prefer a non-stub
    // binding so the old UI doesn't hide dnsmasq behind systemd-resolve
    // (or vice versa). `None` stays `None` when nothing is bound.
    let port_53_owner = pick_representative_owner(&port_53_bindings);
    let resolver = classify_resolver(&port_53_bindings, stub_listener);
    let resolv_conf_servers = read_resolv_conf_servers();
    // wolfrouter_owns_53 now requires a LAN whose dnsmasq actually
    // binds :53 — a LAN on mode=External or listen_port=5353 isn't in
    // the way of a containerised resolver.
    let wolfrouter_lans: Vec<WolfRouterLanDns> = lans.iter()
        .filter(|l| l.node_id == self_node_id)
        .map(|l| WolfRouterLanDns {
            id: l.id.clone(),
            name: l.name.clone(),
            interface: l.interface.clone(),
            router_ip: l.router_ip.clone(),
            mode: match l.dns.mode {
                DnsMode::WolfRouter => "wolf_router".into(),
                DnsMode::External => "external".into(),
            },
            listen_port: l.dns.listen_port,
        })
        .collect();
    let wolfrouter_owns_53 = wolfrouter_lans.iter().any(|l|
        l.mode == "wolf_router" && l.listen_port == 53
    ) && wolfrouter_dnsmasq_running();
    let distro = detect_distro();
    let network_manager_active = network_manager_active();
    let resolv_conf_immutable = resolv_conf_is_immutable();
    let tools_ok = tool_exists("systemctl") && tool_exists("ss");
    let message = build_message(
        &resolver, stub_listener, release_applied, wolfrouter_owns_53,
        network_manager_active, resolv_conf_immutable, &distro,
    );
    HostDnsStatus {
        resolver,
        port_53_owner,
        port_53_bindings,
        stub_listener,
        release_applied,
        wolfrouter_owns_53,
        wolfrouter_lans,
        resolv_conf_servers,
        distro,
        network_manager_active,
        resolv_conf_immutable,
        tools_ok,
        message,
    }
}

/// Choose a single owner name for the legacy `port_53_owner` field.
/// Prefer anything that isn't the stub — otherwise users who also run
/// dnsmasq next to systemd-resolved can't tell from the top-level
/// owner alone that dnsmasq is there too. Falls back to the stub's
/// owner when that's all there is.
fn pick_representative_owner(bindings: &[Port53Binding]) -> Option<String> {
    let non_stub = bindings.iter().find(|b|
        b.owner != "systemd-resolve" && b.owner != "systemd-resolved"
    );
    if let Some(b) = non_stub { return Some(b.owner.clone()); }
    bindings.first().map(|b| b.owner.clone())
}

/// Best-effort distro classification from /etc/os-release. Used
/// primarily to colour the UI messaging — the release/restore logic
/// is distro-agnostic since it leans on systemd standards.
fn detect_distro() -> String {
    let Ok(text) = std::fs::read_to_string("/etc/os-release") else { return "unknown".into(); };
    let mut id = String::new();
    let mut id_like = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ID=") { id = v.trim_matches('"').to_lowercase(); }
        if let Some(v) = line.strip_prefix("ID_LIKE=") { id_like = v.trim_matches('"').to_lowercase(); }
    }
    // Proxmox is Debian-based but we classify it separately so the UI
    // can tell the operator PVE rarely runs systemd-resolved and the
    // feature may be a no-op there.
    if id.contains("pve") || id.contains("proxmox") { return "proxmox".into(); }
    match id.as_str() {
        "ubuntu" => "ubuntu".into(),
        "debian" => "debian".into(),
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => "fedora".into(),
        "arch" | "cachyos" | "manjaro" | "endeavouros" => "arch".into(),
        "alpine" => "alpine".into(),
        _ if id_like.contains("debian") => "debian".into(),
        _ if id_like.contains("rhel") || id_like.contains("fedora") => "fedora".into(),
        _ if id_like.contains("arch") => "arch".into(),
        _ => "unknown".into(),
    }
}

/// NetworkManager rewrites /etc/resolv.conf by default on many
/// distros. If it's active, our rewrite will be clobbered the next
/// time a NIC bounces. We warn rather than fail so the operator can
/// decide whether to disable NM's management (`dns=none` in
/// NetworkManager.conf) or accept the clobber risk.
fn network_manager_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "NetworkManager"])
        .status().map(|s| s.success()).unwrap_or(false)
}

/// chattr +i can be set on /etc/resolv.conf (older resolvconf tricks,
/// or distros shipping it locked). Without this check our write errors
/// out with EPERM; with it we can tell the operator exactly why.
fn resolv_conf_is_immutable() -> bool {
    let Ok(out) = Command::new("lsattr").arg(RESOLV_CONF).output() else { return false; };
    if !out.status.success() { return false; }
    let s = String::from_utf8_lossy(&out.stdout);
    // lsattr emits `----i---------e----- /etc/resolv.conf` when the
    // immutable flag is set — we only care about the `i` in the attrs.
    s.split_whitespace().next()
        .map(|attrs| attrs.contains('i'))
        .unwrap_or(false)
}

fn tool_exists(bin: &str) -> bool {
    Command::new("which").arg(bin).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

/// Drop in the systemd-resolved override that disables the stub
/// listener, rewrite /etc/resolv.conf so the host still resolves via
/// a real upstream, restart systemd-resolved.
/// `upstream` is optional — defaults to 1.1.1.1 if None. Caller can
/// pass the WolfRouter's LAN IP so the host DNS keeps going through
/// the operator's own resolver chain.
pub fn release_port_53(upstream: Option<&str>) -> Result<String, String> {
    if !systemd_resolved_active() {
        return Err("systemd-resolved is not active on this host — manual configuration needed for your resolver (dnsmasq: drop-in under /etc/dnsmasq.d/ with `port=5353`; unbound: include in /etc/unbound/unbound.conf.d/ with `interface: 127.0.0.1@5353`)".into());
    }
    // If /etc/resolv.conf is locked immutable we can't write it; tell
    // the operator to unlock it first so they don't get a confusing
    // EPERM from the filesystem.
    if resolv_conf_is_immutable() {
        return Err(format!("/etc/resolv.conf has the immutable flag set. Run `sudo chattr -i {}` and try again.", RESOLV_CONF));
    }
    // Ensure parent directory exists (some minimal installs don't ship it).
    let dir = Path::new(RELEASE_DROPIN).parent().ok_or("bad drop-in path")?;
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("create {}: {}", dir.display(), e))?;

    // The drop-in is the only thing we write; keeping it tiny means
    // easy rollback by deleting the file. Marked with a WolfStack
    // header so a sysadmin spelunking /etc/systemd knows what did it.
    let contents = "# Managed by WolfStack — do not edit by hand.\n\
                    # Created by WolfRouter Host DNS panel to free port 53\n\
                    # on this host so a containerised resolver (AdGuard Home,\n\
                    # Pi-hole, etc.) can bind directly. Delete this file and\n\
                    # restart systemd-resolved to undo.\n\
                    [Resolve]\n\
                    DNSStubListener=no\n";
    std::fs::write(RELEASE_DROPIN, contents)
        .map_err(|e| format!("write {}: {}", RELEASE_DROPIN, e))?;

    // Back up /etc/resolv.conf once, then rewrite to point somewhere
    // that still works. Without this step disabling the stub breaks
    // host DNS entirely because /etc/resolv.conf was pointing at
    // 127.0.0.53 which is no longer listening.
    //
    // Validate the upstream: trim whitespace, default to 1.1.1.1 when
    // None or empty, and reject obviously broken strings (whitespace
    // or newlines in the middle would produce malformed resolv.conf).
    let upstream_val = match upstream.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':') => s,
        Some(bad) => {
            return Err(format!(
                "upstream '{}' isn't a valid IPv4/IPv6 literal — only digits, dots, colons, and hex allowed",
                bad
            ));
        }
        None => "1.1.1.1",
    };
    if !Path::new(RESOLV_BACKUP).exists() {
        if let Ok(existing) = std::fs::read_to_string(RESOLV_CONF) {
            let _ = std::fs::write(RESOLV_BACKUP, existing);
        }
    }
    let new_resolv = format!(
        "# Managed by WolfStack — host DNS routed to {upstream}\n\
         # Original saved to {backup}. Delete {dropin} and restart\n\
         # systemd-resolved to restore.\n\
         nameserver {upstream}\n\
         options edns0\n",
        upstream = upstream_val, backup = RESOLV_BACKUP, dropin = RELEASE_DROPIN,
    );
    // /etc/resolv.conf is sometimes a symlink to the stub's file.
    // Remove it first so we write a plain file rather than clobbering
    // through the symlink into the wrong place.
    let _ = std::fs::remove_file(RESOLV_CONF);
    std::fs::write(RESOLV_CONF, new_resolv)
        .map_err(|e| format!("write {}: {}", RESOLV_CONF, e))?;

    // If NetworkManager is active and managing DNS, drop a config
    // that tells it to stop touching /etc/resolv.conf. Without this
    // NM will clobber our rewrite the next time a NIC bounces —
    // silently breaking host DNS again. Reload NM to apply.
    if network_manager_active() {
        let nm_dir = Path::new(NM_DROPIN).parent().ok_or("bad NM drop-in path")?;
        let _ = std::fs::create_dir_all(nm_dir);
        let nm_contents = "# Managed by WolfStack — do not edit by hand.\n\
                           # Stops NetworkManager from rewriting /etc/resolv.conf\n\
                           # while the Host DNS release is active. Delete this file\n\
                           # and restart NetworkManager to restore NM's DNS management.\n\
                           [main]\n\
                           dns=none\n\
                           rc-manager=unmanaged\n";
        if let Err(e) = std::fs::write(NM_DROPIN, nm_contents) {
            return Err(format!("write NetworkManager drop-in {}: {}", NM_DROPIN, e));
        }
        let _ = Command::new("systemctl")
            .args(["reload", "NetworkManager"])
            .output();
    }

    let out = Command::new("systemctl").args(["restart", "systemd-resolved"]).output()
        .map_err(|e| format!("systemctl: {}", e))?;
    if !out.status.success() {
        return Err(format!("systemctl restart failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }

    // Update Docker's daemon.json with the new upstream DNS and ensure
    // outbound NAT/FORWARD rules are intact — the resolv.conf rewrite
    // above may have changed the upstream that Docker containers see.
    if crate::containers::docker_dns::ensure_docker_dns() {
        crate::containers::docker_dns::reload_docker_if_needed();
    }
    crate::containers::docker_dns::ensure_docker_outbound();

    Ok(format!("Port 53 released. Host DNS routed to {}. Undo with Restore.", upstream_val))
}

/// Remove the drop-in and restore the original /etc/resolv.conf from
/// the backup. Safe to call when no release has been applied — returns
/// "nothing to restore" in that case.
pub fn restore() -> Result<String, String> {
    let dropin_existed = Path::new(RELEASE_DROPIN).exists();
    let backup_existed = Path::new(RESOLV_BACKUP).exists();
    if !dropin_existed && !backup_existed {
        return Ok("No WolfStack release override found — nothing to restore.".into());
    }
    if dropin_existed {
        std::fs::remove_file(RELEASE_DROPIN)
            .map_err(|e| format!("remove {}: {}", RELEASE_DROPIN, e))?;
    }
    if backup_existed {
        if let Ok(orig) = std::fs::read_to_string(RESOLV_BACKUP) {
            let _ = std::fs::remove_file(RESOLV_CONF);
            std::fs::write(RESOLV_CONF, orig)
                .map_err(|e| format!("restore resolv.conf: {}", e))?;
            let _ = std::fs::remove_file(RESOLV_BACKUP);
        }
    }
    // Clean up the NetworkManager drop-in if we laid one down, and
    // ask NM to reload so its normal DNS management resumes.
    if Path::new(NM_DROPIN).exists() {
        let _ = std::fs::remove_file(NM_DROPIN);
        let _ = Command::new("systemctl")
            .args(["reload", "NetworkManager"])
            .output();
    }
    if systemd_resolved_active() {
        let _ = Command::new("systemctl").args(["restart", "systemd-resolved"]).output();
    }

    // Update Docker's daemon.json — the real upstream may have changed
    // back now that the stub listener is restored.
    if crate::containers::docker_dns::ensure_docker_dns() {
        crate::containers::docker_dns::reload_docker_if_needed();
    }
    crate::containers::docker_dns::ensure_docker_outbound();

    Ok("Host DNS restored. Stub listener back on 127.0.0.53.".into())
}

/// Return true when systemd-resolved.service is currently active.
fn systemd_resolved_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Peek systemd-resolved's live config for the stub-listener state.
/// `resolvectl status` prints "DNS Stub Listener: yes|no"; older
/// versions put the same info in `systemctl show systemd-resolved`.
fn detect_stub_listener() -> bool {
    if !systemd_resolved_active() { return false; }
    if let Ok(out) = Command::new("resolvectl").args(["status"]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let l = line.trim();
                if l.to_lowercase().starts_with("dns stub listener") {
                    return l.to_lowercase().contains("yes");
                }
            }
        }
    }
    // Fallback: if systemd-resolved is active and we can't prove
    // otherwise, assume the stub is on (the default).
    true
}

/// Every process currently bound to something:53 on this host. Both
/// UDP and TCP sockets are reported separately (dnsmasq always binds
/// both, as does systemd-resolved) — the UI dedupes by (owner,addr)
/// for display if it wants.
///
/// We collect ALL bindings rather than just the first because stub +
/// dnsmasq routinely coexist on different addrs (127.0.0.53 for the
/// stub, the LAN bridge IP for dnsmasq). The old "first line wins"
/// code was race-sensitive to `ss`'s output ordering — see
/// HostDnsStatus::port_53_bindings for the bug this replaces.
fn detect_port_53_bindings() -> Vec<Port53Binding> {
    // `ss -tulnp` is the standard modern probe; -p requires CAP_NET_ADMIN
    // or root, which WolfStack has. Parse every line whose local address
    // ends with :53.
    let Ok(out) = Command::new("ss").args(["-tulnp"]).output() else { return Vec::new(); };
    if !out.status.success() { return Vec::new(); }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut bindings: Vec<Port53Binding> = Vec::new();
    for line in text.lines() {
        // Skip header.
        if line.starts_with("Netid") { continue; }
        // Columns: Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let local = parts[4];
        // Match any IPv4/IPv6/interface-scoped :53. The port tail is
        // checked against `:53` with the port separator so we don't
        // match e.g. "...:5353" — ends_with(":53") rejects that
        // correctly because 5353 doesn't end with a colon before 53.
        if !local.ends_with(":53") { continue; }
        // Prefer the process field (last column) when it exists — it
        // looks like `users:(("systemd-resolve",pid=1234,fd=17))`.
        let process_col = parts.last().copied().unwrap_or("");
        if let Some(owner) = extract_process_name(process_col) {
            // Dedupe — dnsmasq and systemd-resolved each bind both
            // TCP and UDP on the same local addr, which would
            // otherwise produce two identical rows in the panel.
            let already = bindings.iter().any(|b| b.owner == owner && b.local_addr == local);
            if !already {
                bindings.push(Port53Binding { owner, local_addr: local.to_string() });
            }
        }
    }
    bindings
}

/// Parse `users:(("systemd-resolve",pid=1234,fd=17))` down to
/// `systemd-resolve`. Returns None on anything unexpected so the
/// caller falls through to "unknown owner".
fn extract_process_name(col: &str) -> Option<String> {
    let open = col.find("((\"")?;
    let start = open + 3;
    let rest = col.get(start..)?;
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}

/// Friendly resolver label from the full bindings list + stub state.
/// When multiple owners are present we prefer the non-stub one so the
/// panel's headline matches what the operator actually needs to
/// reason about (the stub is handled separately via its own row).
/// Falls back to "systemd-resolved" when only the stub is bound, or
/// "none" when nothing holds :53.
fn classify_resolver(bindings: &[Port53Binding], stub: bool) -> String {
    // Prefer non-stub owner for the headline label.
    let non_stub = bindings.iter().find(|b|
        b.owner != "systemd-resolve" && b.owner != "systemd-resolved"
    );
    if let Some(b) = non_stub {
        return match b.owner.as_str() {
            "dnsmasq" => "dnsmasq".into(),
            "unbound" => "unbound".into(),
            "named" => "bind/named".into(),
            other => other.to_string(),
        };
    }
    if bindings.iter().any(|b|
        b.owner == "systemd-resolve" || b.owner == "systemd-resolved"
    ) {
        return "systemd-resolved".into();
    }
    if stub { return "systemd-resolved".into(); }
    "none".into()
}

/// Does WolfRouter itself serve a LAN on this node via dnsmasq? If
/// yes, releasing port 53 would break our own DNS — the UI warns.
///
/// WolfRouter spawns dnsmasq as a plain process (see dhcp::start)
/// with a per-LAN pid file under /run/wolfstack-router/. The
/// presence of any live pid-file (with a matching running process)
/// tells us WolfRouter is the one holding port 53 — more reliable
/// than searching systemd units, which WolfRouter doesn't install.
fn wolfrouter_dnsmasq_running() -> bool {
    let dir = std::path::Path::new("/run/wolfstack-router");
    let Ok(entries) = std::fs::read_dir(dir) else { return false; };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(s) = name.to_str() else { continue; };
        if !(s.starts_with("lan-") && s.ends_with(".pid")) { continue; }
        let Ok(pid_str) = std::fs::read_to_string(e.path()) else { continue; };
        let Ok(pid) = pid_str.trim().parse::<i32>() else { continue; };
        // /proc/<pid> existing is the cheapest "process alive?" probe.
        if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            return true;
        }
    }
    false
}

fn read_resolv_conf_servers() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(RESOLV_CONF) else { return Vec::new(); };
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("nameserver") {
            out.push(rest.trim().to_string());
        }
    }
    out
}

fn build_message(
    resolver: &str, stub: bool, release_applied: bool, wolfrouter_owns: bool,
    nm_active: bool, immutable: bool, distro: &str,
) -> String {
    // wolfrouter_owns and stub state are orthogonal — both can be true
    // simultaneously (stub on 127.0.0.53 + dnsmasq on the LAN bridge).
    // Previous versions short-circuited here and hid the stub release
    // button when wolfrouter_owns was true, which left operators with
    // no way forward. Now we always speak to stub/release state first
    // and let the per-LAN rows surface the dnsmasq-on-:53 action.
    if immutable {
        return format!("/etc/resolv.conf is marked immutable (chattr +i). Release would fail. \
                        Clear the flag with `sudo chattr -i /etc/resolv.conf` before using this.");
    }
    if release_applied {
        let mut msg = String::from("WolfStack has released systemd-resolved's stub listener. Click Restore stub to undo.");
        if wolfrouter_owns {
            msg.push_str(" WolfRouter's own dnsmasq is still binding :53 on one or more LAN bridges — use the per-LAN rows below to move those off :53 as well if a container needs :53 on a LAN interface.");
        } else {
            msg.push_str(" A container on this node can now bind :53 on any interface where nothing else is listening.");
        }
        if nm_active {
            msg.push_str(" (NetworkManager is managed via drop-in while the release is active.)");
        }
        return msg;
    }
    // Distro-specific nudges for the common cases.
    let distro_note = match distro {
        "proxmox" => " Proxmox typically doesn't run systemd-resolved — this feature may be a no-op on PVE nodes.",
        "alpine" => " Alpine uses openrc, not systemd — this feature requires systemd-resolved which isn't available.",
        _ => "",
    };
    let nm_note = if nm_active {
        " NetworkManager is active on this host — release will auto-drop in a config telling NM to stop managing /etc/resolv.conf, restoring its management on Restore."
    } else { "" };
    match resolver {
        "systemd-resolved" => {
            if stub {
                format!("systemd-resolved's stub listener is holding port 53 on 127.0.0.53. Click \
                         Release to disable the stub so a containerised DNS server (AdGuard Home, \
                         Pi-hole) can bind directly. Undo any time with Restore.{}{}", nm_note, distro_note)
            } else {
                format!("systemd-resolved is running but the stub listener is already off. Port 53 \
                         should be available for a containerised resolver.{}", distro_note)
            }
        }
        "dnsmasq" if wolfrouter_owns => format!("WolfRouter's own dnsmasq is binding port 53 \
                              on this node for one or more LANs. To free :53 for a \
                              containerised resolver (AdGuard Home, Pi-hole), use the \
                              per-LAN rows below to move each affected LAN's DNS off :53. \
                              That also updates DHCP option 6 to point clients at your \
                              container.{}", distro_note),
        "dnsmasq" => format!("A system-level dnsmasq is binding port 53 on this host. Releasing it \
                              automatically isn't supported yet — stop or reconfigure the host \
                              dnsmasq manually (move to port 5353 via a drop-in in \
                              /etc/dnsmasq.d/).{}", distro_note),
        "unbound" => format!("unbound is binding port 53 on this host. Releasing it automatically \
                              isn't supported yet — move its listening port manually via an \
                              include in /etc/unbound/unbound.conf.d/.{}", distro_note),
        "bind/named" => format!("BIND/named is binding port 53 on this host. Move its listen-on \
                                 directive manually to free the port.{}", distro_note),
        "none" => format!("Nothing is holding port 53 on this host. A containerised resolver can \
                           bind it directly — no change needed.{}", distro_note),
        other => format!("Port 53 is held by '{}' — not a resolver WolfStack knows how to \
                          release automatically. Reconfigure it manually.{}", other, distro_note),
    }
}
