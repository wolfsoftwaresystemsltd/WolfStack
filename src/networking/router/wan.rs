// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! WAN connection management.
//!
//! Three modes:
//!   • **DHCP** — interface gets its IP from upstream (the default for
//!     plug-in-and-go modems / ONTs in bridge mode).
//!   • **Static** — operator hard-codes IP/netmask/gateway. Same as
//!     editing /etc/network/interfaces by hand, just driven from
//!     WolfRouter.
//!   • **PPPoE** — common for ADSL/VDSL/fibre lines (especially in
//!     Germany and other European markets where the ISP requires a
//!     PPPoE login over Ethernet). WolfRouter writes
//!     `/etc/ppp/peers/wolfrouter-{id}` plus the PAP/CHAP secrets,
//!     then runs `pppd call` to bring the link up.
//!
//! Service lifecycle: a WanConnection's `enabled` flag controls
//! whether the OS-level service is started. Disabling drops the link.
//! State is computed live from `ip link` (PPP devices appear as
//! `ppp0`, `ppp1`, ...).

use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use tracing::{info, warn};

const PEERS_DIR: &str = "/etc/ppp/peers";
const CHAP_SECRETS: &str = "/etc/ppp/chap-secrets";
const PAP_SECRETS: &str = "/etc/ppp/pap-secrets";
const IP_PRE_UP_DIR: &str = "/etc/ppp/ip-pre-up.d";
const IP_UP_DIR: &str = "/etc/ppp/ip-up.d";
const IP_DOWN_DIR: &str = "/etc/ppp/ip-down.d";
const STATE_DIR: &str = "/var/run/wolfrouter";

/// Idempotent add of `POSTROUTING -o <iface> -j MASQUERADE` in the nat
/// table. Without this, LAN clients routed through a WolfRouter WAN
/// leave with private source IPs and the ISP drops them — which is
/// exactly the "clients can't go online" symptom users hit when
/// WolfRouter looked otherwise healthy. The `-C` pre-check keeps
/// apply() safe to call repeatedly.
fn nat_ensure(iface: &str) -> Result<(), String> {
    if iface.is_empty() { return Ok(()); }
    let check = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
        .status();
    let masq_needs_add = !matches!(check, Ok(s) if s.success());
    if masq_needs_add {
        let out = Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
            .output()
            .map_err(|e| format!("iptables -A POSTROUTING: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "WAN MASQUERADE add on {} failed: {}",
                iface, String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        info!("WolfRouter: MASQUERADE installed on WAN interface {}", iface);
    }
    // MSS clamp is non-optional — without it, PPPoE and any tunnelled
    // WAN stalls on large TCP flows (apt, docker pulls, Windows Update,
    // TLS payloads) because LAN clients negotiate 1460-byte segments
    // that won't fit in a 1492-byte pipe, and PMTU ICMPs frequently
    // get eaten somewhere between us and the target. Install it right
    // next to MASQUERADE so the two always travel together.
    mss_clamp_ensure(iface)
}

/// Drop every MASQUERADE rule whose output interface matches. Loop on
/// `-D` so duplicate rules (from earlier bugs or manual edits) all go.
fn nat_remove(iface: &str) {
    if iface.is_empty() { return; }
    for _ in 0..16 {
        let out = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
            .output();
        match out {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }
    // Companion — strip the MSS clamp too. Same idempotent loop so
    // duplicates from earlier bugs don't accumulate.
    for _ in 0..16 {
        let out = Command::new("iptables")
            .args(["-t", "mangle", "-D", "FORWARD",
                   "-o", iface, "-p", "tcp",
                   "--tcp-flags", "SYN,RST", "SYN",
                   "-j", "TCPMSS", "--clamp-mss-to-pmtu"])
            .output();
        match out {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }
}

/// Install an MSS clamp on TCP SYN packets leaving through `iface`.
/// Rewrites the MSS option in every outgoing SYN to the path MTU so
/// LAN clients never negotiate a segment size bigger than the WAN can
/// actually carry — the classic fix for "small things work, big
/// downloads stall" on PPPoE links (MTU 1492 instead of 1500) and on
/// any link where Path MTU Discovery ICMPs get eaten upstream.
///
/// `--clamp-mss-to-pmtu` auto-picks from the interface MTU, so the
/// same rule works for PPPoE (1492 → MSS 1452), DHCP (1500 → 1460),
/// and anything tunnelled (WireGuard, GRE, etc).
///
/// Idempotent: `-C` pre-check means apply() is safe to call
/// repeatedly. Without this, every WAN-enable would stack another
/// duplicate rule.
fn mss_clamp_ensure(iface: &str) -> Result<(), String> {
    if iface.is_empty() { return Ok(()); }
    // Two explicit arg arrays (check vs add) — cheaper readability win
    // over mutating a shared array by index. Only the op flag differs
    // between them; everything else must stay identical for the `-C`
    // lookup to find the rule a later `-A` installed.
    let check_args = [
        "-t", "mangle", "-C", "FORWARD",
        "-o", iface, "-p", "tcp",
        "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ];
    let add_args = [
        "-t", "mangle", "-A", "FORWARD",
        "-o", iface, "-p", "tcp",
        "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ];
    if matches!(Command::new("iptables").args(check_args).status(), Ok(s) if s.success()) {
        return Ok(());
    }
    let out = Command::new("iptables")
        .args(add_args)
        .output()
        .map_err(|e| format!("iptables -A mangle FORWARD: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "WAN MSS clamp add on {} failed: {}",
            iface, String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    info!("WolfRouter: MSS clamp-to-pmtu installed on WAN interface {}", iface);
    Ok(())
}

/// One WAN uplink configuration. Keyed by `id` (auto-generated) and
/// owned by `node_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanConnection {
    pub id: String,
    pub name: String,
    /// Node that hosts the physical interface.
    pub node_id: String,
    /// Physical / VLAN interface that carries the uplink. For PPPoE
    /// this is the Ethernet port the ONT/modem is plugged into; the
    /// resulting ppp0/ppp1 is created automatically.
    pub interface: String,
    pub mode: WanMode,
    /// If false, WolfRouter doesn't try to start the connection. Lets
    /// users stage a config without bringing up an unwanted dialer.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

fn default_enabled() -> bool { true }

/// Mode-specific config. Tagged enum so the JSON shape is obvious to
/// the frontend — `{ "mode": "pppoe", "config": { ... } }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "config", rename_all = "snake_case")]
pub enum WanMode {
    Dhcp,
    Static(StaticConfig),
    Pppoe(PppoeConfig),
}

impl Default for WanMode {
    fn default() -> Self { WanMode::Dhcp }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StaticConfig {
    /// CIDR address, e.g. "192.168.1.10/24".
    pub address_cidr: String,
    pub gateway: String,
    /// Optional DNS servers (one per line in dispatcher).
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PppoeConfig {
    pub username: String,
    /// Plaintext password — stored encrypted at rest in
    /// /etc/ppp/chap-secrets (mode 0600). Not roundtripped to the UI
    /// after save: the GET endpoint masks this to "***".
    pub password: String,
    /// Optional PPPoE service name (most ISPs leave this blank).
    #[serde(default)]
    pub service_name: String,
    /// MTU. Defaults to 1492 (PPPoE overhead).
    #[serde(default = "default_pppoe_mtu")]
    pub mtu: u32,
    /// MRU. Defaults to 1492.
    #[serde(default = "default_pppoe_mtu")]
    pub mru: u32,
    /// Reconnect persistently on link drops. Default true.
    #[serde(default = "default_true_local")]
    pub persist: bool,
    /// LCP echo interval (seconds). 0 disables. Default 30s.
    #[serde(default = "default_lcp_echo_interval")]
    pub lcp_echo_interval: u32,
    /// LCP echo failures before pppd considers the link dead. Default 4.
    #[serde(default = "default_lcp_echo_failure")]
    pub lcp_echo_failure: u32,
    /// If true, pppd installs this link as the system's default route
    /// and kicks any existing default. **Default OFF** — turning it on
    /// accidentally on a server that already has working internet via
    /// a different interface will wipe that connectivity the moment
    /// PPPoE succeeds. Only enable when this PPP link is genuinely
    /// meant to be the server's WAN.
    #[serde(default)]
    pub use_default_route: bool,
    /// If true, pppd overwrites /etc/resolv.conf with the DNS servers
    /// the ISP hands out. **Default OFF** for the same reason — on a
    /// server with a working DNS config, this clobbers it the moment
    /// PPPoE succeeds.
    #[serde(default)]
    pub use_peer_dns: bool,
}

fn default_pppoe_mtu() -> u32 { 1492 }
fn default_true_local() -> bool { true }
fn default_lcp_echo_interval() -> u32 { 30 }
fn default_lcp_echo_failure() -> u32 { 4 }

/// Validate user-supplied fields that get written into config files —
/// reject anything that could break out of the file format (newlines,
/// quotes that aren't escaped). Returns Err with a human reason.
pub fn validate(conn: &WanConnection) -> Result<(), String> {
    let no_newlines = |field: &str, v: &str| -> Result<(), String> {
        if v.contains('\n') || v.contains('\r') {
            return Err(format!("{} contains newline characters", field));
        }
        Ok(())
    };
    no_newlines("name", &conn.name)?;
    no_newlines("interface", &conn.interface)?;
    no_newlines("description", &conn.description)?;
    if !conn.interface.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        return Err("interface name has illegal characters".into());
    }
    match &conn.mode {
        WanMode::Dhcp => {}
        WanMode::Static(s) => {
            no_newlines("address_cidr", &s.address_cidr)?;
            no_newlines("gateway", &s.gateway)?;
            for d in &s.dns { no_newlines("dns", d)?; }
        }
        WanMode::Pppoe(p) => {
            no_newlines("username", &p.username)?;
            no_newlines("password", &p.password)?;
            no_newlines("service_name", &p.service_name)?;
            // username must be free of double quotes (we wrap in quotes
            // when writing the peers file).
            if p.username.contains('"') {
                return Err("username contains double quotes".into());
            }
            if p.password.contains('"') {
                return Err("password contains double quotes".into());
            }
            if p.username.is_empty() {
                return Err("PPPoE username is required".into());
            }
        }
    }
    Ok(())
}

// ─── PPPoE service lifecycle ───

/// Install the ip-pre-up and ip-down hook scripts that snapshot the
/// system's current default route + /etc/resolv.conf before PPPoE
/// messes with them, and restore them when the link goes down.
///
/// This is the belt-and-braces we need because pppd's own
/// `replacedefaultroute` only works reliably when pppd exits cleanly
/// via poff — and even then, some distros' pppd versions don't
/// restore on unexpected link drops. Running our own save/restore
/// in the pppd hook directories guarantees the system comes back to
/// its pre-PPPoE state regardless of how pppd died.
fn install_ppp_hooks(peer_name: &str) -> Result<(), String> {
    fs::create_dir_all(IP_PRE_UP_DIR)
        .map_err(|e| format!("mkdir {}: {}", IP_PRE_UP_DIR, e))?;
    fs::create_dir_all(IP_UP_DIR)
        .map_err(|e| format!("mkdir {}: {}", IP_UP_DIR, e))?;
    fs::create_dir_all(IP_DOWN_DIR)
        .map_err(|e| format!("mkdir {}: {}", IP_DOWN_DIR, e))?;
    fs::create_dir_all(STATE_DIR)
        .map_err(|e| format!("mkdir {}: {}", STATE_DIR, e))?;

    let state_prefix = format!("{}/{}-", STATE_DIR, peer_name);

    // ip-pre-up: runs before pppd touches routing. Save default route
    // and resolv.conf so ip-down can restore them.
    let pre_up = format!(
        "#!/bin/sh\n\
         # WolfRouter pre-up hook for {peer} — saves pre-PPPoE state.\n\
         # $6 is the pppd peer name; only act on ours.\n\
         [ \"$6\" = \"{peer}\" ] || exit 0\n\
         ip route show default > \"{prefix}default-route\" 2>/dev/null || true\n\
         cp /etc/resolv.conf \"{prefix}resolv.conf\" 2>/dev/null || true\n\
         exit 0\n",
        peer = peer_name, prefix = state_prefix,
    );
    let pre_up_path = format!("{}/wolfrouter-{}", IP_PRE_UP_DIR, peer_name);
    fs::write(&pre_up_path, pre_up)
        .map_err(|e| format!("write {}: {}", pre_up_path, e))?;
    make_executable(&pre_up_path);

    // ip-up: runs after pppd has negotiated the link and the ppp*
    // interface is ready. Install MASQUERADE on $1 (the ppp iface) so
    // LAN clients routed over this WAN actually reach the internet,
    // AND the TCPMSS clamp so LAN TCP sessions don't negotiate a
    // segment size bigger than the 1492-byte PPPoE pipe — without it,
    // apt/docker/TLS bulk transfers stall intermittently while tiny
    // flows (ping, DNS, TLS handshakes) look fine.
    // Record the iface name in state so ip-down can clean up even if
    // the dynamic number differs between runs.
    let up = format!(
        "#!/bin/sh\n\
         # WolfRouter ip-up hook for {peer} — installs WAN MASQUERADE + MSS clamp.\n\
         [ \"$6\" = \"{peer}\" ] || exit 0\n\
         IFACE=\"$1\"\n\
         [ -n \"$IFACE\" ] || exit 0\n\
         echo \"$IFACE\" > \"{prefix}iface\" 2>/dev/null || true\n\
         iptables -t nat -C POSTROUTING -o \"$IFACE\" -j MASQUERADE 2>/dev/null \\\n\
             || iptables -t nat -A POSTROUTING -o \"$IFACE\" -j MASQUERADE 2>/dev/null || true\n\
         iptables -t mangle -C FORWARD -o \"$IFACE\" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \\\n\
             || iptables -t mangle -A FORWARD -o \"$IFACE\" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n\
         exit 0\n",
        peer = peer_name, prefix = state_prefix,
    );
    let up_path = format!("{}/wolfrouter-{}", IP_UP_DIR, peer_name);
    fs::write(&up_path, up)
        .map_err(|e| format!("write {}: {}", up_path, e))?;
    make_executable(&up_path);

    // ip-down: runs when link drops (expected or not). Restore state.
    // Add the saved default route back — harmless if it's already
    // there. Restore /etc/resolv.conf from our snapshot.
    let down = format!(
        "#!/bin/sh\n\
         # WolfRouter ip-down hook for {peer} — restores pre-PPPoE state.\n\
         [ \"$6\" = \"{peer}\" ] || exit 0\n\
         # Remove any MASQUERADE + MSS-clamp rule(s) we installed for\n\
         # this link. Try both $1 (pppd passes the iface) and the iface\n\
         # we recorded in state during ip-up, in case they differ on a rebind.\n\
         for IF in \"$1\" \"$(cat \"{prefix}iface\" 2>/dev/null)\"; do\n\
             [ -z \"$IF\" ] && continue\n\
             while iptables -t nat -D POSTROUTING -o \"$IF\" -j MASQUERADE 2>/dev/null; do :; done\n\
             while iptables -t mangle -D FORWARD -o \"$IF\" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done\n\
         done\n\
         rm -f \"{prefix}iface\" 2>/dev/null || true\n\
         SAVED_ROUTE=$(cat \"{prefix}default-route\" 2>/dev/null)\n\
         if [ -n \"$SAVED_ROUTE\" ]; then\n\
             # Strip any trailing ppp0 cruft and re-add. ip route add\n\
             # will fail if the route already exists; that's fine.\n\
             echo \"$SAVED_ROUTE\" | while read -r route; do\n\
                 [ -z \"$route\" ] && continue\n\
                 ip route replace $route 2>/dev/null || true\n\
             done\n\
         fi\n\
         if [ -f \"{prefix}resolv.conf\" ]; then\n\
             cp \"{prefix}resolv.conf\" /etc/resolv.conf 2>/dev/null || true\n\
         fi\n\
         exit 0\n",
        peer = peer_name, prefix = state_prefix,
    );
    let down_path = format!("{}/wolfrouter-{}", IP_DOWN_DIR, peer_name);
    fs::write(&down_path, down)
        .map_err(|e| format!("write {}: {}", down_path, e))?;
    make_executable(&down_path);

    Ok(())
}

fn make_executable(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(path, perms);
    }
}

fn remove_ppp_hooks(peer_name: &str) {
    let _ = fs::remove_file(format!("{}/wolfrouter-{}", IP_PRE_UP_DIR, peer_name));
    let _ = fs::remove_file(format!("{}/wolfrouter-{}", IP_UP_DIR, peer_name));
    let _ = fs::remove_file(format!("{}/wolfrouter-{}", IP_DOWN_DIR, peer_name));
    let state_prefix = format!("{}/{}-", STATE_DIR, peer_name);
    let _ = fs::remove_file(format!("{}default-route", state_prefix));
    let _ = fs::remove_file(format!("{}resolv.conf", state_prefix));
    let _ = fs::remove_file(format!("{}iface", state_prefix));
}

/// Build a CPU bitmask with the low `n_cpus` bits set, in the kernel's
/// `rps_cpus` sysfs format: 32-bit hex words, most-significant first,
/// comma-separated (e.g. 4 CPUs → "f"; 40 CPUs → "ff,ffffffff"). Pure so
/// it's unit-testable without sysfs.
fn rps_mask(n_cpus: usize) -> String {
    let n = n_cpus.min(4096); // sanity cap; real routers have a handful
    let words = n.div_ceil(32).max(1);
    let mut groups = Vec::with_capacity(words);
    for w in 0..words {
        let mut word: u32 = 0;
        for bit in 0..32 {
            if w * 32 + bit < n {
                word |= 1 << bit;
            }
        }
        groups.push(word);
    }
    // Most-significant 32-bit word first.
    groups.iter().rev().map(|g| format!("{:x}", g)).collect::<Vec<_>>().join(",")
}

/// Spread receive-side softirq processing for `iface` across all CPUs via
/// RPS (Receive Packet Steering). PPPoE has no NIC hardware offload, so its
/// whole RX chain — frame receive, PPPoE decapsulation, netfilter, and the
/// forwarding decision — otherwise runs in softirq on the **single** core
/// that takes the NIC's interrupt. On a weak multi-core CPU that one core
/// saturates under sustained download and caps throughput well below line
/// rate (PapaSchlumpf: recurring ~210→120 Mbps that only a reboot clears).
/// Writing the all-CPU mask to each RX queue's `rps_cpus` lets the kernel
/// hash incoming packets across every core, multiplying the ceiling.
///
/// Applied to the **physical** WAN NIC (`conn.interface`) — that's where the
/// PPPoE RX softirq actually runs; the virtual `ppp0` only sees already-
/// decapsulated traffic. No-op on a single-core host (nothing to steer to)
/// and entirely best-effort: a missing sysfs path or a NIC that doesn't
/// expose `rps_cpus` logs and returns, never failing the WAN bring-up.
fn apply_rps(iface: &str) {
    let n_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if n_cpus <= 1 {
        return; // RPS has nowhere to spread to on a uniprocessor.
    }
    let mask = rps_mask(n_cpus);
    let queues_dir = format!("/sys/class/net/{}/queues", iface);
    let entries = match fs::read_dir(&queues_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("WolfRouter RPS: cannot read {} ({}) — RX softirq stays single-core for {}",
                  queues_dir, e, iface);
            return;
        }
    };
    let mut applied = 0u32;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("rx-") {
            continue;
        }
        let path = entry.path().join("rps_cpus");
        match fs::write(&path, format!("{}\n", mask)) {
            Ok(()) => applied += 1,
            Err(e) => warn!("WolfRouter RPS: write {} failed: {}", path.display(), e),
        }
    }
    if applied > 0 {
        info!("WolfRouter RPS: spread RX softirq for {} across {} CPUs (mask {}, {} queue(s)) \
               — PPPoE has no NIC offload, so this lifts the single-core download ceiling",
              iface, n_cpus, mask, applied);
    }
}

/// Write the pppd peers file + chap/pap secrets for a PPPoE connection
/// and start the link. Idempotent: stops the link first if it's
/// already running so config updates take effect cleanly.
pub fn pppoe_apply(conn: &WanConnection, cfg: &PppoeConfig) -> Result<(), String> {
    fs::create_dir_all(PEERS_DIR)
        .map_err(|e| format!("mkdir {}: {}", PEERS_DIR, e))?;

    let peer_name = peer_name_for(&conn.id);
    let peer_path = format!("{}/{}", PEERS_DIR, peer_name);

    // Install the pre-up/down hooks that save and restore the pre-
    // PPPoE default route + resolv.conf. Belt-and-braces on top of
    // pppd's own replacedefaultroute behaviour.
    install_ppp_hooks(&peer_name)?;

    // Peer file — references the PPPoE plugin and the underlying iface.
    let mut peer = String::new();
    peer.push_str(&format!("# WolfRouter PPPoE peer for connection {} ({})\n", conn.id, conn.name));
    peer.push_str("# Managed by WolfStack — do not edit by hand.\n");
    peer.push_str(&format!("plugin pppoe.so {}\n", conn.interface));
    peer.push_str(&format!("name \"{}\"\n", cfg.username));
    if !cfg.service_name.is_empty() {
        peer.push_str(&format!("rp_pppoe_service \"{}\"\n", cfg.service_name));
    }
    peer.push_str("noauth\n");
    peer.push_str("hide-password\n");
    peer.push_str("noipdefault\n");
    // defaultroute and usepeerdns are DESTRUCTIVE on a server with
    // existing internet via a different NIC — pppd wipes the live
    // default route / resolv.conf the moment the link comes up. Both
    // are opt-in now. Users who want PPPoE as their actual WAN must
    // explicitly tick the boxes in the WAN editor.
    if cfg.use_default_route {
        peer.push_str("defaultroute\n");
        // replacedefaultroute makes pppd REPLACE any pre-existing
        // default (instead of refusing to add one). We only want this
        // if the user explicitly asked — otherwise pppd will warn but
        // leave the existing default alone.
        peer.push_str("replacedefaultroute\n");
    } else {
        peer.push_str("nodefaultroute\n");
    }
    if cfg.use_peer_dns {
        peer.push_str("usepeerdns\n");
    }
    peer.push_str("noaccomp\n");
    peer.push_str("default-asyncmap\n");
    peer.push_str(&format!("mtu {}\n", cfg.mtu));
    peer.push_str(&format!("mru {}\n", cfg.mru));
    if cfg.persist { peer.push_str("persist\n"); peer.push_str("maxfail 0\n"); }
    if cfg.lcp_echo_interval > 0 {
        peer.push_str(&format!("lcp-echo-interval {}\n", cfg.lcp_echo_interval));
        peer.push_str(&format!("lcp-echo-failure {}\n", cfg.lcp_echo_failure));
    }
    fs::write(&peer_path, peer)
        .map_err(|e| format!("write {}: {}", peer_path, e))?;

    // Secrets — both PAP and CHAP since we don't know which the ISP
    // will negotiate. Mode 0600 (root-only) so the password isn't
    // world-readable.
    write_secret(CHAP_SECRETS, &cfg.username, &cfg.password)?;
    write_secret(PAP_SECRETS, &cfg.username, &cfg.password)?;

    // Bring down any existing instance of this peer first.
    let _ = pppoe_stop(conn);

    // pppd call <peer_name> — daemonises by default.
    let out = Command::new("pppd")
        .args(["call", &peer_name])
        .output()
        .map_err(|e| format!("spawn pppd: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("pppd exited {}: {}",
            out.status.code().unwrap_or(-1),
            stderr.trim()));
    }
    info!("WolfRouter: PPPoE link '{}' (peer {}) started on {}", conn.name, peer_name, conn.interface);

    // Spread the PPPoE RX softirq across all cores. The physical NIC stays up
    // across PPPoE reconnects, and `apply()` re-runs on every WolfRouter
    // startup, so this re-asserts after a reboot (rps_cpus is reset by the
    // kernel on boot / NIC down). Best-effort — never fails the bring-up.
    apply_rps(&conn.interface);

    Ok(())
}

/// Tear down the PPP link for this connection. Safe to call when no
/// link exists.
///
/// Stop sequence is deliberately GENTLE — pppd needs to run its own
/// ip-down.d hooks (including ours, which restore the pre-PPPoE
/// default route + resolv.conf) before it exits. Jumping straight to
/// pkill -9 skips those hooks and is exactly how v17.2.1 users ended
/// up with a broken default route requiring a reboot.
///
///   1. `poff <peer>` — the clean way, lets pppd run all hooks.
///   2. Wait up to 8s for the pid file to disappear.
///   3. Only if still alive, SIGTERM (pppd still runs hooks on TERM).
///   4. Wait another 4s.
///   5. Last resort: SIGKILL. If we had to come this far, the hooks
///      didn't run, and the caller (apply) should fall back to a
///      manual route restore.
pub fn pppoe_stop(conn: &WanConnection) -> Result<(), String> {
    let peer_name = peer_name_for(&conn.id);
    // Liveness is the running pppd process, NOT a pidfile. `pppd call <peer>`
    // writes /var/run/ppp<N>.pid (keyed on the iface unit), never
    // /var/run/<peer>.pid — so the old pidfile sentinel never existed, the
    // SIGTERM/SIGKILL ladder below never fired, and a stuck pppd (e.g. persist
    // + maxfail 0) had no fallback past poff. pppd_running_for() probes the
    // actual process, so the escalation now works.
    let alive = || pppd_running_for(&peer_name);

    // 1. Clean shutdown via poff (matches `call <peer>`, SIGTERMs pppd so its
    //    ip-down hooks run).
    let _ = Command::new("poff").arg(&peer_name).status();

    // 2. Wait up to 8s for pppd to actually exit.
    for _ in 0..32 {
        if !alive() { break; }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // 3. Still alive? SIGTERM — pppd still runs ip-down hooks on TERM. Anchor
    //    the pattern ($) so we never kill another link whose peer name shares
    //    this one's prefix (wolfrouter-wan vs wolfrouter-wan2).
    if alive() {
        let _ = Command::new("pkill")
            .args(["-TERM", "-f", &format!("pppd call {}$", peer_name)])
            .status();
        for _ in 0..16 {
            if !alive() { break; }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    // 4. Truly stuck? SIGKILL — we lose hook execution, so the
    // caller falls back to manual state restore.
    let hooks_skipped = if alive() {
        let _ = Command::new("pkill")
            .args(["-KILL", "-f", &format!("pppd call {}$", peer_name)])
            .status();
        for _ in 0..8 {
            if !alive() { break; }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        true
    } else { false };

    // If we had to SIGKILL, the ip-down hook didn't run — manually
    // replay the "restore pre-PPPoE state" the hook would have done.
    if hooks_skipped {
        manual_state_restore(&peer_name);
    }
    Ok(())
}

/// Last-resort restore when the pppd ip-down hook didn't run (we had
/// to SIGKILL). Reads the saved state files the ip-pre-up hook wrote
/// and restores the default route + /etc/resolv.conf directly. Also
/// strips the WAN MASQUERADE the ip-up hook installed — otherwise a
/// killed pppd leaves a stale rule bound to a ppp iface that no
/// longer exists, which piles up over restarts.
fn manual_state_restore(peer_name: &str) {
    let prefix = format!("{}/{}-", STATE_DIR, peer_name);
    if let Ok(iface) = fs::read_to_string(format!("{}iface", prefix)) {
        let iface = iface.trim();
        nat_remove(iface);
    }
    let _ = fs::remove_file(format!("{}iface", prefix));
    if let Ok(route) = fs::read_to_string(format!("{}default-route", prefix)) {
        for line in route.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let args: Vec<&str> = line.split_whitespace().collect();
            let mut cmd = Command::new("ip");
            cmd.arg("route").arg("replace");
            cmd.args(&args);
            let _ = cmd.status();
        }
    }
    let snap = format!("{}resolv.conf", prefix);
    if std::path::Path::new(&snap).exists() {
        let _ = Command::new("cp").args([&snap, "/etc/resolv.conf"]).status();
    }
}

pub fn pppoe_purge(conn: &WanConnection) -> Result<(), String> {
    let peer_name = peer_name_for(&conn.id);
    let _ = pppoe_stop(conn);
    let peer_path = format!("{}/{}", PEERS_DIR, peer_name);
    let _ = fs::remove_file(&peer_path);
    remove_ppp_hooks(&peer_name);
    Ok(())
}

/// Write a CHAP/PAP secret line for the given user. Replaces an
/// existing line if one matches; otherwise appends. File mode 0600.
fn write_secret(path: &str, user: &str, password: &str) -> Result<(), String> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut out = String::new();
    let user_q = format!("\"{}\"", user);
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line); out.push('\n'); continue;
        }
        let first = trimmed.split_whitespace().next().unwrap_or("");
        if first == user_q || first.trim_matches('"') == user {
            // Replace with our line below.
            replaced = true;
            continue;
        }
        out.push_str(line); out.push('\n');
    }
    // The replace-pass above skipped any existing line for this user
    // via `continue`, so the new line is always needed — either as
    // the replacement for the skipped old line (replaced=true) or as
    // the very first entry for this user (replaced=false). Either
    // way, one push. Pre-v18.7.30 this was also unconditional but
    // the loop did NOT `continue` on a match, so duplicate lines
    // accumulated; that's now fixed by the continue at line 613.
    out.push_str(&format!("{} * \"{}\" *\n", user_q, password));
    let _ = replaced;  // kept for log/debug hooks; no behaviour branch

    // write_secure sets 0600 atomically at open — no TOCTOU window
    // where the ISP password was world-readable before the explicit
    // chmod. Replaces the fs::write + metadata+set_permissions dance.
    crate::paths::write_secure(path, out)
        .map_err(|e| format!("write {}: {}", path, e))?;
    Ok(())
}

fn peer_name_for(id: &str) -> String {
    // pppd uses the file name as the "call" target — keep it short
    // and free of path separators.
    let safe: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    format!("wolfrouter-{}", safe)
}

/// Live PPP interface state — returns (iface_name, ip_addr) when this
/// connection's PPPoE link is up, None otherwise.
///
/// We deliberately do NOT gate on a pidfile. `pppd call <peer>` writes
/// `/var/run/ppp<N>.pid` (named after the interface unit), never
/// `/var/run/<peer>.pid` — so the old gate could never pass and the WAN's
/// live IP stayed invisible in the UI until an operator restarted WolfStack
/// and something re-walked the topology. That is exactly the "Addresses: —"
/// PapaSchlumpf saw while `ip a show ppp0` clearly held 100.65.x. Instead we
/// confirm pppd is actually running for THIS peer (same `pppd call <peer>`
/// cmdline pppoe_stop kills) and then read the live ppp* address — which also
/// correctly picks up a pppd that survived an in-place binary upgrade.
pub fn pppoe_status(conn: &WanConnection) -> Option<(String, String)> {
    let peer = peer_name_for(&conn.id);
    if !pppd_running_for(&peer) {
        return None;
    }
    // Walk ppp interfaces and return the first carrying an IPv4. Single-PPPoE
    // is the supported case; strict per-peer mapping for multi-PPPoE is future
    // work (a ppp iface doesn't record which peer file dialled it). Skip
    // IP-less ppp ifaces rather than bailing — a down ppp0 must not hide an
    // up ppp1.
    let out = Command::new("ip").args(["-j", "-4", "addr", "show"]).output().ok()?;
    if !out.status.success() { return None; }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    for entry in json.as_array()? {
        let Some(name) = entry.get("ifname").and_then(|v| v.as_str()) else { continue };
        if !name.starts_with("ppp") { continue; }
        let ip = entry.get("addr_info").and_then(|a| a.as_array())
            .and_then(|arr| arr.iter().find_map(|a| a.get("local").and_then(|v| v.as_str())));
        if let Some(ip) = ip {
            return Some((name.to_string(), ip.to_string()));
        }
    }
    None
}

/// True when a pppd process is running for this peer. pppd's argv is
/// `pppd call <peer>` (pppoe_stop relies on the same shape in its pkill), so
/// `pgrep -f` on that exact string is an accurate per-peer liveness probe that
/// doesn't depend on a pidfile pppd may never have written under this name.
fn pppd_running_for(peer: &str) -> bool {
    // `$`-anchor the pattern: the peer is pppd's last argv, so anchoring stops
    // `wolfrouter-wan` from also matching a running `wolfrouter-wan2`. Worst
    // case (a pgrep build that leaves a trailing space) is a conservative
    // non-match, never a false positive that would mis-kill another link.
    Command::new("pgrep")
        .args(["-f", &format!("pppd call {}$", peer)])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

/// Apply or stop a single connection based on its enabled flag.
pub fn apply(conn: &WanConnection) -> Result<(), String> {
    if !conn.enabled {
        // On disable, strip MASQUERADE for the physical iface too
        // (PPPoE also covers the dynamic ppp iface via its ip-down
        // hook / manual_state_restore; this catches DHCP/Static).
        nat_remove(&conn.interface);
        if let WanMode::Pppoe(_) = &conn.mode {
            return pppoe_stop(conn);
        }
        return Ok(());
    }
    // Bring the underlying WAN NIC administratively UP before applying any mode.
    // After a reboot the ISP NIC can come back admin-DOWN when no host network
    // manager owns it: PPPoE discovery (PADI) then never finds the link, and
    // DHCP/Static traffic black-holes — exactly why PapaSchlumpf had to run
    // `ip link set <iface> up` by hand (2026-06-17). `ip link set up` is
    // idempotent, so this is a no-op on hosts that already bring the NIC up.
    // For PPPoE, `conn.interface` is the ETHERNET device the pppoe plugin rides
    // on (not the ppp unit), which is precisely the one that must be up.
    if let Err(e) = crate::networking::set_interface_state(&conn.interface, true) {
        warn!("WolfRouter: could not bring WAN interface {} up ({}) — continuing", conn.interface, e);
    }
    match &conn.mode {
        WanMode::Pppoe(p) => pppoe_apply(conn, p),
        WanMode::Dhcp => {
            // WolfRouter defers DHCP to the host's client when one owns the NIC
            // — the safe default that never fights NetworkManager/networkd. But
            // on a headless router box where nothing manages the WAN NIC, the
            // link comes up (above) with no lease and all WAN traffic
            // black-holes. So if the interface has no IPv4 lease, request one
            // ourselves with the same one-shot dhclient the operator "fix" runs.
            // It only fires while there's genuinely no address, so it can't
            // stomp a working host-managed link.
            if interface_has_ipv4(&conn.interface) {
                info!("WolfRouter: WAN {} already has a DHCP lease — leaving the host's client in charge", conn.interface);
            } else {
                match request_dhcp_lease(&conn.interface) {
                    Ok(()) => info!("WolfRouter: requested a DHCP lease on WAN {} (no existing lease)", conn.interface),
                    Err(e) => warn!("WolfRouter: DHCP lease request on WAN {} failed ({}) — falling back to the host's DHCP client", conn.interface, e),
                }
            }
            // NAT must be installed by WolfRouter even for passthrough
            // modes — without MASQUERADE on this interface, LAN clients
            // routed through it leave with private source IPs and the
            // upstream drops them. ip_forward is enabled globally
            // elsewhere (networking::mod.rs); this is the companion
            // piece that actually makes routing reach the internet. The rule
            // is interface-based, so a DHCP lease IP change never invalidates it.
            nat_ensure(&conn.interface)?;
            Ok(())
        }
        WanMode::Static(_s) => {
            warn!("WAN static IP for {} is a passthrough — manage via host network config", conn.name);
            nat_ensure(&conn.interface)?;
            Ok(())
        }
    }
}

/// Does the WAN interface currently hold an IPv4 lease/address? Used to decide
/// whether WolfRouter should request one itself (headless box) or defer to the
/// host's DHCP client (which already gave it an address).
fn interface_has_ipv4(iface: &str) -> bool {
    // Require a GLOBAL-scope address — an APIPA/link-local (169.254.x.x, `scope
    // link`), which avahi-autoipd or a prior failed DHCP attempt can leave
    // behind, is NOT a real lease and must not suppress our DHCP request.
    Command::new("ip")
        .args(["-4", "addr", "show", "dev", iface])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|l| l.contains("inet ") && l.contains("scope global")))
        .unwrap_or(false)
}

/// Request a DHCP lease on `iface` with a one-shot, non-blocking dhclient —
/// the same client the operator "fix/dhclient" runs, kept consistent with the
/// rest of the codebase's DHCP handling. `-1` gives up rather than retrying
/// forever if the upstream isn't leasing; `-nw` backgrounds acquisition so this
/// call returns promptly. dhclient's own per-iface pidfile makes a redundant
/// invocation (e.g. two quick applies) harmless.
fn request_dhcp_lease(iface: &str) -> Result<(), String> {
    // Guard the iface name before it reaches dhclient's argv — a leading '-'
    // would be parsed as a flag. Matches the operator fix endpoint's validation.
    if iface.is_empty()
        || iface.starts_with('-')
        || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("refusing to run dhclient on suspicious interface name '{}'", iface));
    }
    // `-v` matches the operator fix so failure stderr is diagnostic.
    let out = Command::new("dhclient")
        .args(["-v", "-1", "-nw", iface])
        .output()
        .map_err(|e| format!("spawn dhclient: {} (is dhclient installed?)", e))?;
    if !out.status.success() {
        return Err(format!("dhclient: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::rps_mask;

    #[test]
    fn rps_mask_common_core_counts() {
        // Single 32-bit word: low n bits set, no leading zeros.
        assert_eq!(rps_mask(1), "1");
        assert_eq!(rps_mask(2), "3");
        assert_eq!(rps_mask(4), "f");      // the N3150 quad-core case
        assert_eq!(rps_mask(8), "ff");
        assert_eq!(rps_mask(16), "ffff");
        assert_eq!(rps_mask(32), "ffffffff");
    }

    #[test]
    fn rps_mask_spans_multiple_words() {
        // >32 CPUs → comma-separated 32-bit words, most-significant first.
        assert_eq!(rps_mask(33), "1,ffffffff");
        assert_eq!(rps_mask(40), "ff,ffffffff");
        assert_eq!(rps_mask(64), "ffffffff,ffffffff");
    }

    #[test]
    fn rps_mask_never_empty() {
        // Even a degenerate 0 yields a parseable single word, never "".
        assert_eq!(rps_mask(0), "0");
    }
}
