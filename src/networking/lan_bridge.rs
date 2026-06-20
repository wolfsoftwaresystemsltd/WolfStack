// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! LAN bridge creation — build a real layer-2 bridge that enslaves a
//! host physical NIC (e.g. `br0` carrying `eth0`) so that LXC/VM guests
//! attached in "Bridged LAN" mode are reachable from the physical LAN.
//!
//! ## Why this exists
//!
//! On a native (non-Proxmox) host the only bridges that exist by
//! default are `lxcbr0` / `virbr0` — both NAT bridges behind their own
//! private subnet. A guest attached there is never reachable from the
//! LAN. There was previously no way in the UI to create a true LAN
//! bridge. This module fills that gap.
//!
//! ## Safety
//!
//! Enslaving the management NIC (the one carrying the default route /
//! the operator's SSH+web session) is the dangerous case: there is a
//! brief window where the host's IP moves from the NIC to the bridge,
//! and any mistake in the persistence config can mean the host comes
//! up with no network after a reboot. wabil bricked a box once by
//! hand-editing `/etc/network/interfaces`; we never touch the
//! operator's primary config file. Instead:
//!
//! - We migrate the IP to the bridge **before** removing it from the
//!   NIC, minimising the dead window.
//! - For the management NIC we require explicit `accept_risk` and arm a
//!   **commit-confirm** timer: if the operator doesn't confirm within
//!   90 seconds (because they got locked out), we automatically revert
//!   the runtime change *and* the persistence files. This is the same
//!   pattern Cisco/MikroTik call "safe mode" / "commit confirmed".
//!
//! Persistence is implemented for all three auto-persist managers
//! (NetworkManager, systemd-networkd, ifupdown). Unknown managers get a
//! runtime-only change and an honest message that it won't survive a
//! reboot.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tracing::{info, warn};

use crate::networking::detect_primary_interface;
use crate::networking::vlan::{detect_net_manager, NetManager};

/// How long (seconds) the operator has to confirm a management-NIC
/// bridge before it auto-reverts. Mirrors the Mikrotik "safe mode"
/// timeout style — long enough to log back in, short enough that a
/// lockout self-heals quickly.
const ROLLBACK_SECONDS: u32 = 90;

// ────────────────────────────────────────────────────────────────────
// Public data types
// ────────────────────────────────────────────────────────────────────

/// What a bridge is for, as far as guest LAN-reachability goes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BridgeKind {
    /// Has a physical NIC enslaved — guests are reachable from the LAN.
    Lan,
    /// NAT bridge (lxcbr0 / virbr0 / virbr* / wnbr-*) — guests sit
    /// behind a private subnet and are NOT reachable from the LAN.
    Nat,
    /// No members — an L2-only / unused bridge.
    Empty,
}

/// A bridge interface on this host plus its LAN/NAT classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInfo {
    pub name: String,
    pub kind: BridgeKind,
    /// Enslaved members (contents of `/sys/class/net/<br>/brif/`).
    pub members: Vec<String>,
    /// True if this bridge holds the host's default route (i.e. the
    /// management path runs over it). Removing/altering it risks lockout.
    pub carries_management: bool,
}

/// A physical NIC that could be enslaved into a new LAN bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicCandidate {
    pub name: String,
    pub mac: String,
    /// IPv4 CIDRs currently bound to the NIC (e.g. `192.168.1.10/24`).
    pub addresses: Vec<String>,
    /// True if this is the default-route NIC (the management path).
    pub is_management: bool,
    /// True if the NIC is already a member of some bridge.
    pub already_enslaved: bool,
}

/// Request to build a new LAN bridge.
pub struct CreateLanBridgeParams {
    pub bridge_name: String,
    pub nic: String,
    /// The operator explicitly acknowledged the lockout risk. Required
    /// when `nic` is the management NIC.
    pub accept_risk: bool,
}

/// Result of a create attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOutcome {
    pub message: String,
    /// Present only when a commit-confirm timer is armed (management
    /// NIC). The caller must POST this token back within
    /// `rollback_seconds` to keep the change, else it auto-reverts.
    pub pending_confirm: Option<String>,
    pub rollback_seconds: u32,
}

// ────────────────────────────────────────────────────────────────────
// Enumeration / classification
// ────────────────────────────────────────────────────────────────────

/// True if `<name>` is a bridge (kernel exposes `/sys/class/net/<name>/bridge`).
fn is_bridge(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}/bridge", name)).exists()
}

/// True if `<name>` is a physical NIC — i.e. it has a backing device
/// (`/sys/class/net/<name>/device`). veth/tap/tun/wg/wn/bridge do not.
fn is_physical_nic(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}/device", name)).exists()
}

/// Read the enslaved members of a bridge from its `brif` directory.
fn bridge_members(name: &str) -> Vec<String> {
    let mut members = Vec::new();
    if let Ok(read) = std::fs::read_dir(format!("/sys/class/net/{}/brif", name)) {
        for entry in read.flatten() {
            if let Ok(m) = entry.file_name().into_string() {
                members.push(m);
            }
        }
    }
    members.sort();
    members
}

/// A bridge name that is, by convention, a NAT bridge rather than a LAN
/// bridge: the libvirt default `virbr0` / any `virbr*`, LXC's `lxcbr0`,
/// and WolfStack's per-VM/libvirt NAT bridges `wnbr-*`.
fn is_nat_bridge_name(name: &str) -> bool {
    name == "lxcbr0"
        || name == "virbr0"
        || name.starts_with("virbr")
        || name.starts_with("wnbr-")
}

/// Enumerate every bridge interface on the host and classify it.
pub fn classify_bridges() -> Vec<BridgeInfo> {
    let mgmt = detect_primary_interface();
    let mut out = Vec::new();

    let read = match std::fs::read_dir("/sys/class/net") {
        Ok(r) => r,
        Err(e) => {
            warn!("classify_bridges: cannot read /sys/class/net: {}", e);
            return out;
        }
    };

    for entry in read.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !is_bridge(&name) {
            continue;
        }

        let members = bridge_members(&name);

        let kind = if is_nat_bridge_name(&name) {
            BridgeKind::Nat
        } else if members.iter().any(|m| is_physical_nic(m)) {
            BridgeKind::Lan
        } else {
            BridgeKind::Empty
        };

        // Management bridge = this bridge IS the default-route dev.
        let carries_management = name == mgmt;

        out.push(BridgeInfo {
            name,
            kind,
            members,
            carries_management,
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Set of NIC names that are currently a member of some bridge.
fn enslaved_nics() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(read) = std::fs::read_dir("/sys/class/net") {
        for entry in read.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if is_bridge(&name) {
                out.extend(bridge_members(&name));
            }
        }
    }
    out
}

/// Candidate physical NICs that could be enslaved into a LAN bridge.
/// Excludes bridges, VLAN sub-interfaces, virtual interfaces, and
/// WireGuard / WolfNet overlay devices.
pub fn candidate_nics() -> Vec<NicCandidate> {
    let mgmt = detect_primary_interface();
    let enslaved = enslaved_nics();
    let mut out = Vec::new();

    for iface in crate::networking::list_interfaces() {
        let name = &iface.name;
        // Only true physical NICs.
        if !is_physical_nic(name) {
            continue;
        }
        // No VLAN sub-interfaces (eth0.100) — enslaving the tagged
        // device, not the bare NIC, is a different operation.
        if iface.is_vlan || name.contains('.') {
            continue;
        }
        // No bridges (a physical NIC is never a bridge, but be safe).
        if is_bridge(name) {
            continue;
        }
        // No overlay / VPN devices.
        if name.starts_with("wg")
            || name.starts_with("wn")
            || name.starts_with("wolfnet")
            || name.starts_with("tun")
            || name.starts_with("tap")
        {
            continue;
        }

        let addresses: Vec<String> = iface
            .addresses
            .iter()
            .filter(|a| a.family == "inet")
            .map(|a| format!("{}/{}", a.address, a.prefix))
            .collect();

        out.push(NicCandidate {
            name: name.clone(),
            mac: iface.mac.clone(),
            addresses,
            is_management: *name == mgmt,
            already_enslaved: enslaved.contains(name),
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ────────────────────────────────────────────────────────────────────
// Live-state capture helpers
// ────────────────────────────────────────────────────────────────────

/// Read the IPv4 CIDRs currently bound to a NIC via `ip -j addr show`.
/// Mirrors the JSON-parsing style of `list_interfaces`.
fn nic_ipv4_cidrs(nic: &str) -> Vec<String> {
    let out = match Command::new("ip")
        .args(["-j", "addr", "show", "dev", nic])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut cidrs = Vec::new();
    if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
        for entry in entries {
            if let Some(addr_info) = entry["addr_info"].as_array() {
                for addr in addr_info {
                    if addr["family"].as_str() == Some("inet") {
                        // Skip link-local / host scopes — only global
                        // addresses migrate to the bridge.
                        let scope = addr["scope"].as_str().unwrap_or("");
                        if scope == "host" || scope == "link" {
                            continue;
                        }
                        let local = addr["local"].as_str().unwrap_or("");
                        let prefix = addr["prefixlen"].as_u64().unwrap_or(0);
                        if !local.is_empty() {
                            cidrs.push(format!("{}/{}", local, prefix));
                        }
                    }
                }
            }
        }
    }
    cidrs
}

/// Read the default-route gateway IP if (and only if) the default route
/// currently leaves via `nic`. Returns `None` when there is no default
/// route on this NIC (so we don't wrongly install one on the bridge).
fn default_gateway_via(nic: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let dev = parts
            .iter()
            .position(|&p| p == "dev")
            .and_then(|i| parts.get(i + 1));
        if dev != Some(&nic) {
            continue;
        }
        if let Some(gw) = parts
            .iter()
            .position(|&p| p == "via")
            .and_then(|i| parts.get(i + 1))
        {
            return Some(gw.to_string());
        }
    }
    None
}

/// Convert a CIDR prefix length (0..=32) to a dotted IPv4 netmask.
/// Local replica of the same helper in `vlan.rs` (which is private).
fn cidr_to_netmask_v4(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let octets = mask.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// Split a CIDR into (address, prefix).
fn split_cidr(cidr: &str) -> Option<(String, u8)> {
    let (addr, p) = cidr.split_once('/')?;
    let prefix: u8 = p.parse().ok()?;
    Some((addr.to_string(), prefix))
}

// ────────────────────────────────────────────────────────────────────
// Commit-confirm rollback registry
// ────────────────────────────────────────────────────────────────────

/// Everything required to revert a management-NIC bridge if the
/// operator never confirms.
#[derive(Debug, Clone)]
struct PendingRollback {
    bridge: String,
    nic: String,
    /// CIDRs that were migrated off the NIC onto the bridge.
    cidrs: Vec<String>,
    /// Default gateway that was running via the NIC (if any).
    gateway: Option<String>,
    /// Persistence files written for this bridge (removed on revert).
    persist_files: Vec<String>,
    /// nmcli connection names created for this bridge (deleted on revert).
    nmcli_cons: Vec<String>,
    /// (original, backup) file pairs to restore on revert.
    backups: Vec<(String, String)>,
    /// nmcli connections to reactivate on revert (the NIC's displaced one).
    nmcli_restore: Vec<String>,
    /// Once true, the operator confirmed and the timer must NOT revert.
    confirmed: bool,
}

fn pending_registry() -> &'static Mutex<HashMap<String, PendingRollback>> {
    static PENDING: OnceLock<Mutex<HashMap<String, PendingRollback>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Generate an opaque confirmation token. A monotonic counter guarantees
/// uniqueness; mixing in the wall-clock nanoseconds makes the token
/// unpredictable across process restarts so one operator can't compute
/// another's pending token from their own. FNV-1a hashes it all into a
/// non-sequential string.
fn next_token(nic: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in n
        .to_le_bytes()
        .iter()
        .chain(nanos.to_le_bytes().iter())
        .chain(nic.as_bytes())
    {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Include both hash and nanos so two calls in the same nanosecond
    // (different counter) still differ, without exposing the counter.
    format!("lanbr-{:x}{:x}", hash, nanos & 0xffff)
}

// ────────────────────────────────────────────────────────────────────
// Runtime apply / revert (the `ip` commands)
// ────────────────────────────────────────────────────────────────────

/// Run an `ip` command, returning Err on non-zero exit. `tolerate`
/// strings (matched in stderr) downgrade the failure to Ok — used for
/// idempotent "File exists" cases.
fn ip(args: &[&str], tolerate: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("spawn `ip {}`: {}", args.join(" "), e))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    for t in tolerate {
        if stderr.contains(t) {
            return Ok(());
        }
    }
    Err(format!("`ip {}` failed: {}", args.join(" "), stderr.trim()))
}

/// Bring up the bridge, enslave the NIC, and migrate IP + default route.
///
/// Note on the dead window: the kernel **strips all IP addresses from an
/// interface the instant it becomes a bridge slave**. There is therefore
/// an unavoidable sub-second window — one `ip(8)` fork — between
/// enslaving the NIC and re-adding its address to the bridge, during
/// which the management path has no address. This cannot be eliminated;
/// it is the reason the management-NIC path is gated behind the
/// commit-confirm watchdog. We minimise the window by enslaving and
/// re-addressing back-to-back with nothing in between.
fn runtime_apply(
    bridge: &str,
    nic: &str,
    cidrs: &[String],
    gateway: &Option<String>,
) -> Result<(), String> {
    // Create bridge (idempotent), disable STP, bring up.
    ip(&["link", "add", bridge, "type", "bridge"], &["File exists"])?;
    ip(&["link", "set", bridge, "type", "bridge", "stp_state", "0"], &[])?;
    ip(&["link", "set", bridge, "up"], &[])?;

    // Enslave the NIC and ensure it is up. The kernel drops the NIC's
    // addresses here.
    ip(&["link", "set", nic, "master", bridge], &[])?;
    ip(&["link", "set", nic, "up"], &[])?;

    // Re-add the captured addresses on the bridge (they were stripped
    // from the NIC by enslavement). Belt-and-braces delete clears any
    // address that somehow lingered on the (now-slave) NIC.
    for cidr in cidrs {
        ip(&["addr", "add", cidr, "dev", bridge], &["File exists"])?;
        let _ = ip(&["addr", "del", cidr, "dev", nic], &["Cannot assign requested address"]);
    }

    // Re-establish the default route on the bridge if one ran via the NIC.
    if let Some(gw) = gateway {
        ip(&["route", "replace", "default", "via", gw, "dev", bridge], &[])?;
    }

    Ok(())
}

/// Undo a runtime apply: move addresses back to the NIC, restore the
/// default route, unslave, delete the bridge. Best-effort — keeps going
/// past individual failures so a partial state still gets cleaned up.
fn runtime_revert(
    bridge: &str,
    nic: &str,
    cidrs: &[String],
    gateway: &Option<String>,
) {
    // ORDER IS CRITICAL. The kernel refuses `ip addr add` on a bridge
    // slave, so we MUST unslave the NIC before we can put its address
    // back. Doing it the other way round (the original bug) leaves the
    // host with no IP and no route — a worse lockout than not reverting.
    //
    // 1. Free the NIC from the bridge.
    let _ = ip(&["link", "set", nic, "nomaster"], &[]);
    // 2. Bring it up.
    let _ = ip(&["link", "set", nic, "up"], &[]);
    // 3. Move the addresses back onto the (now-standalone) NIC and drop
    //    them from the bridge.
    for cidr in cidrs {
        let _ = ip(&["addr", "add", cidr, "dev", nic], &["File exists"]);
        let _ = ip(&["addr", "del", cidr, "dev", bridge], &["Cannot assign requested address"]);
    }
    // 4. Restore the default route via the NIC (now that it has an addr).
    if let Some(gw) = gateway {
        let _ = ip(&["route", "replace", "default", "via", gw, "dev", nic], &[]);
    }
    // 5. Delete the bridge.
    let _ = ip(&["link", "del", bridge], &["Cannot find device"]);
}

// ────────────────────────────────────────────────────────────────────
// Persistence — one implementation per supported NetManager
// ────────────────────────────────────────────────────────────────────

/// systemd-networkd config directory.
const NETWORKD_DIR: &str = "/etc/systemd/network";

/// Where the ifupdown drop-in for a given bridge lives. We NEVER touch
/// `/etc/network/interfaces` itself — only this dedicated drop-in under
/// the `interfaces.d` directory that Debian-derived systems source.
fn ifupdown_snippet_path(bridge: &str) -> String {
    format!("/etc/network/interfaces.d/wolfstack-lanbridge-{}.conf", bridge)
}

/// Result of writing persistence: the files we created (for revert), the
/// nmcli connection names we created (for revert), any pre-existing files
/// we moved aside (so revert can put them back), plus a human-readable
/// warning to surface to the operator.
struct PersistResult {
    /// Files WolfStack newly created (deleted on revert).
    files: Vec<String>,
    /// nmcli connection names WolfStack created (deleted on revert).
    nmcli_cons: Vec<String>,
    /// (original_path, backup_path) pairs for files that already existed
    /// and were moved aside. On revert the backup is restored.
    backups: Vec<(String, String)>,
    /// NetworkManager connection names we deactivated (not deleted) and
    /// must reactivate on revert — typically the NIC's original
    /// auto-connection that we displaced with the bridge.
    nmcli_restore: Vec<String>,
    warning: Option<String>,
    /// Plain-English description of what was persisted (or not).
    note: String,
}

/// Find the active NetworkManager connection name bound to a device, if
/// any. Used so we can deactivate (and later restore) the NIC's existing
/// connection rather than fight it. Returns None if NM isn't tracking it.
fn nm_active_connection_for_device(dev: &str) -> Option<String> {
    let out = Command::new("nmcli")
        .args(["-t", "-f", "DEVICE,CONNECTION", "device", "status"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // Format: DEVICE:CONNECTION  (colon-separated, -t terse mode)
        let mut parts = line.splitn(2, ':');
        let d = parts.next().unwrap_or("");
        let con = parts.next().unwrap_or("");
        if d == dev && !con.is_empty() && con != "--" {
            return Some(con.to_string());
        }
    }
    None
}

/// NetworkManager persistence via `nmcli`. Creates a bridge connection
/// (static or DHCP based on the migrated CIDRs) and an ethernet slave
/// connection binding the NIC to the bridge.
fn persist_networkmanager(
    bridge: &str,
    nic: &str,
    cidrs: &[String],
    gateway: &Option<String>,
) -> Result<PersistResult, String> {
    let br_con = bridge.to_string();
    let slave_con = format!("{}-{}", bridge, nic);

    let nmcli = |args: &[&str]| -> Result<(), String> {
        let out = Command::new("nmcli")
            .args(args)
            .output()
            .map_err(|e| format!("spawn `nmcli {}`: {}", args.join(" "), e))?;
        if out.status.success() {
            return Ok(());
        }
        Err(format!(
            "`nmcli {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    };

    // Capture (and deactivate, NOT delete) the NIC's existing NM
    // connection so it doesn't fight the bridge. We keep it on disk so
    // revert can simply reactivate it, preserving its original settings.
    let nic_restore = nm_active_connection_for_device(nic)
        .filter(|c| *c != br_con && *c != slave_con);
    if let Some(c) = &nic_restore {
        let _ = nmcli(&["con", "down", c]);
    }

    // Bridge master connection. STP off to match the runtime config.
    nmcli(&[
        "con", "add", "type", "bridge", "ifname", bridge, "con-name", &br_con, "stp", "no",
    ])?;

    // IPv4 method: static if the NIC had a global address, else DHCP.
    if let Some(first) = cidrs.first() {
        nmcli(&[
            "con", "mod", &br_con, "ipv4.addresses", first, "ipv4.method", "manual",
        ])?;
        // Additional addresses (rare) appended via +ipv4.addresses.
        for extra in cidrs.iter().skip(1) {
            nmcli(&["con", "mod", &br_con, "+ipv4.addresses", extra])?;
        }
        if let Some(gw) = gateway {
            nmcli(&["con", "mod", &br_con, "ipv4.gateway", gw])?;
        }
    } else {
        nmcli(&["con", "mod", &br_con, "ipv4.method", "auto"])?;
    }

    // Slave ethernet connection binding the NIC to the bridge.
    nmcli(&[
        "con", "add", "type", "ethernet", "ifname", nic, "master", bridge, "con-name", &slave_con,
    ])?;

    // Activate the bridge connection (slave follows).
    nmcli(&["con", "up", &br_con])?;

    Ok(PersistResult {
        files: Vec::new(),
        nmcli_cons: vec![br_con.clone(), slave_con.clone()],
        backups: Vec::new(),
        nmcli_restore: nic_restore.into_iter().collect(),
        warning: None,
        note: format!(
            "Persisted via NetworkManager (connections '{}' + '{}').",
            br_con, slave_con
        ),
    })
}

/// systemd-networkd persistence: write `<br>.netdev`, `<br>.network`,
/// and `<nic>.network`, then `networkctl reload` (best-effort).
fn persist_systemd_networkd(
    bridge: &str,
    nic: &str,
    cidrs: &[String],
    gateway: &Option<String>,
) -> Result<PersistResult, String> {
    let netdev_path = format!("{}/{}.netdev", NETWORKD_DIR, bridge);
    let br_net_path = format!("{}/{}.network", NETWORKD_DIR, bridge);
    let nic_net_path = format!("{}/{}.network", NETWORKD_DIR, nic);

    std::fs::create_dir_all(NETWORKD_DIR)
        .map_err(|e| format!("create {}: {}", NETWORKD_DIR, e))?;

    // Track which files we newly created (delete on revert) vs. files
    // that already existed and were moved aside (restore on revert).
    let mut created: Vec<String> = Vec::new();
    let mut backups: Vec<(String, String)> = Vec::new();

    // If a config path already exists, rename it to a `.wolfstack-bak`
    // sidecar so we never destroy a distro-shipped config. Records the
    // (original, backup) pair for restore on revert.
    let mut back_up = |path: &str| -> Result<(), String> {
        if std::path::Path::new(path).exists() {
            let bak = format!("{}.wolfstack-bak", path);
            std::fs::rename(path, &bak)
                .map_err(|e| format!("back up {}: {}", path, e))?;
            backups.push((path.to_string(), bak));
        }
        Ok(())
    };
    back_up(&netdev_path)?;
    back_up(&br_net_path)?;
    back_up(&nic_net_path)?;

    // <br>.netdev — declares the bridge device.
    let netdev = format!(
        "# Auto-generated by WolfStack — LAN bridge. Do not edit by hand.\n\
         [NetDev]\nName={}\nKind=bridge\n",
        bridge
    );
    std::fs::write(&netdev_path, netdev)
        .map_err(|e| format!("write {}: {}", netdev_path, e))?;
    created.push(netdev_path);

    // <br>.network — the host address lives on the bridge now.
    let mut br_net = String::from(
        "# Auto-generated by WolfStack — LAN bridge. Do not edit by hand.\n\
         [Match]\n",
    );
    br_net.push_str(&format!("Name={}\n\n[Network]\n", bridge));
    if cidrs.is_empty() {
        br_net.push_str("DHCP=yes\n");
    } else {
        for cidr in cidrs {
            br_net.push_str(&format!("Address={}\n", cidr));
        }
        if let Some(gw) = gateway {
            br_net.push_str(&format!("Gateway={}\n", gw));
        }
    }
    std::fs::write(&br_net_path, br_net)
        .map_err(|e| format!("write {}: {}", br_net_path, e))?;
    created.push(br_net_path);

    // <nic>.network — binds the physical NIC into the bridge, no IP.
    let nic_net = format!(
        "# Auto-generated by WolfStack — LAN bridge slave. Do not edit by hand.\n\
         [Match]\nName={}\n\n[Network]\nBridge={}\n",
        nic, bridge
    );
    std::fs::write(&nic_net_path, nic_net)
        .map_err(|e| format!("write {}: {}", nic_net_path, e))?;
    created.push(nic_net_path);

    // Best-effort live reload — runtime is already applied, so a reload
    // failure isn't fatal.
    let reloaded = Command::new("networkctl")
        .arg("reload")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let note = if reloaded {
        "Persisted via systemd-networkd (reloaded).".to_string()
    } else {
        "Persisted via systemd-networkd (reload not run — applies on next boot).".to_string()
    };

    Ok(PersistResult {
        files: created,
        nmcli_cons: Vec::new(),
        backups,
        nmcli_restore: Vec::new(),
        warning: None,
        note,
    })
}

/// ifupdown persistence: write a dedicated drop-in under
/// `/etc/network/interfaces.d/`. The operator's primary
/// `/etc/network/interfaces` is never edited. If that primary file
/// still configures the NIC, the bridge won't come up cleanly on
/// reboot — we detect that and warn loudly.
fn persist_ifupdown(
    bridge: &str,
    nic: &str,
    cidrs: &[String],
    gateway: &Option<String>,
) -> Result<PersistResult, String> {
    let path = ifupdown_snippet_path(bridge);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }

    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — LAN bridge. Do not edit by hand.\n");
    out.push_str(&format!("# Bridge {} enslaving {}\n\n", bridge, nic));
    // The slave NIC itself is brought up manual (no IP); the bridge
    // owns it via bridge_ports.
    out.push_str(&format!("auto {}\n", bridge));
    if cidrs.is_empty() {
        out.push_str(&format!("iface {} inet dhcp\n", bridge));
    } else {
        // ifupdown's static stanza takes one address/netmask pair; use
        // the first migrated CIDR (the primary). Extra addresses are
        // added via post-up.
        let (addr, prefix) = split_cidr(&cidrs[0])
            .ok_or_else(|| format!("malformed CIDR '{}'", cidrs[0]))?;
        let netmask = cidr_to_netmask_v4(prefix);
        out.push_str(&format!("iface {} inet static\n", bridge));
        out.push_str(&format!("    address {}\n", addr));
        out.push_str(&format!("    netmask {}\n", netmask));
        if let Some(gw) = gateway {
            out.push_str(&format!("    gateway {}\n", gw));
        }
        for extra in cidrs.iter().skip(1) {
            out.push_str(&format!("    post-up ip addr add {} dev {} || true\n", extra, bridge));
        }
    }
    out.push_str(&format!("    bridge_ports {}\n", nic));
    out.push_str("    bridge_stp off\n");
    out.push_str("    bridge_fd 0\n\n");
    // Declare the slave NIC as `manual` so ifup doesn't try to configure
    // it independently and fight the bridge for it on boot. This lives in
    // our own drop-in only — /etc/network/interfaces is never touched.
    out.push_str(&format!("iface {} inet manual\n", nic));

    std::fs::write(&path, &out).map_err(|e| format!("write {}: {}", path, e))?;

    // Detect whether the operator's primary interfaces file still
    // configures this NIC — if so the bridge fight for the NIC on boot.
    let warning = if primary_interfaces_configures_nic(nic) {
        Some(format!(
            "Your /etc/network/interfaces still configures '{}'. \
             Remove its 'iface {}' / 'auto {}' stanza (we do NOT edit that \
             file ourselves) or the bridge will not come up on reboot.",
            nic, nic, nic
        ))
    } else {
        None
    };

    Ok(PersistResult {
        files: vec![path.clone()],
        nmcli_cons: Vec::new(),
        backups: Vec::new(),
        nmcli_restore: Vec::new(),
        warning,
        note: format!("Persisted via ifupdown ({}).", path),
    })
}

/// Scan `/etc/network/interfaces` for an `iface`/`auto`/`allow-hotplug`
/// stanza naming `<nic>`. Follows `source` and `source-directory`
/// directives (the modern Debian layout splits config across files) so a
/// NIC configured in a sourced file is still detected. Skips our own
/// drop-in. Read-only; never edits. Excludes our own
/// `wolfstack-lanbridge-*` file (which legitimately mentions the NIC).
fn primary_interfaces_configures_nic(nic: &str) -> bool {
    primary_interfaces_scan("/etc/network/interfaces", nic, 0)
}

/// Recursive helper for `primary_interfaces_configures_nic`. `depth`
/// guards against pathological `source` loops.
fn primary_interfaces_scan(path: &str, nic: &str, depth: u8) -> bool {
    if depth > 8 {
        return false;
    }
    // Never count our own drop-in — it intentionally names the NIC.
    if path.contains("wolfstack-lanbridge-") {
        return false;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let base_dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        let mut tok = l.split_whitespace();
        match tok.next() {
            Some("iface") | Some("auto") | Some("allow-hotplug") => {
                if tok.next() == Some(nic) {
                    return true;
                }
            }
            Some("source") => {
                // `source <pattern>` — resolve relative to the including
                // dir. Handle the common `dir/*` / `dir/*.cfg` wildcard
                // forms without pulling in a glob crate.
                if let Some(pat) = tok.next() {
                    let full = if pat.starts_with('/') {
                        pat.to_string()
                    } else {
                        base_dir.join(pat).to_string_lossy().to_string()
                    };
                    for resolved in expand_source_pattern(&full) {
                        if primary_interfaces_scan(&resolved, nic, depth + 1) {
                            return true;
                        }
                    }
                }
            }
            Some("source-directory") => {
                if let Some(dir) = tok.next() {
                    let full = if dir.starts_with('/') {
                        std::path::PathBuf::from(dir)
                    } else {
                        base_dir.join(dir)
                    };
                    if let Ok(read) = std::fs::read_dir(&full) {
                        for e in read.flatten() {
                            if primary_interfaces_scan(&e.path().to_string_lossy(), nic, depth + 1) {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Expand an ifupdown `source` pattern into concrete file paths. Handles
/// a literal path, a `dir/*` (all files in dir), and a `dir/*.ext`
/// (suffix-filtered) — the only forms ifupdown's `source` glob uses in
/// practice. No external glob dependency.
fn expand_source_pattern(pattern: &str) -> Vec<String> {
    if !pattern.contains('*') {
        return vec![pattern.to_string()];
    }
    let p = std::path::Path::new(pattern);
    let parent = match p.parent() {
        Some(d) => d,
        None => return Vec::new(),
    };
    let file_pat = p.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
    // Suffix after the '*', e.g. "*.cfg" -> ".cfg"; "*" -> "".
    let suffix = file_pat.strip_prefix('*').unwrap_or("").to_string();
    let mut out = Vec::new();
    if let Ok(read) = std::fs::read_dir(parent) {
        for e in read.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if suffix.is_empty() || name.ends_with(&suffix) {
                out.push(e.path().to_string_lossy().to_string());
            }
        }
    }
    out
}

/// Undo the persistence we wrote. Best-effort:
/// - delete the files we created,
/// - restore any pre-existing files we moved aside (the backup wins over
///   any file we may have left — so distro config returns intact),
/// - delete the nmcli connections we created and reactivate the NIC's
///   original connection that we displaced.
fn revert_persistence(
    files: &[String],
    nmcli_cons: &[String],
    backups: &[(String, String)],
    nmcli_restore: &[String],
) {
    for f in files {
        // Best-effort: a missing file is fine (already gone).
        match std::fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("LAN bridge revert: could not remove {}: {}", f, e),
        }
    }
    // Restore moved-aside originals (rename the .wolfstack-bak back).
    for (orig, bak) in backups {
        if let Err(e) = std::fs::rename(bak, orig) {
            warn!("LAN bridge revert: could not restore {} from {}: {}", orig, bak, e);
        }
    }
    for con in nmcli_cons {
        let _ = Command::new("nmcli").args(["con", "delete", con]).status();
    }
    for con in nmcli_restore {
        let _ = Command::new("nmcli").args(["con", "up", con]).status();
    }
    // Best-effort reload so the removed/restored networkd files take effect.
    let _ = Command::new("networkctl").arg("reload").status();
}

/// Dispatch persistence to the detected manager. Returns the persist
/// artifacts plus a human-readable note. Unknown/Wicked/Netplan get a
/// runtime-only result with an honest "won't survive reboot" note.
fn persist(
    manager: NetManager,
    bridge: &str,
    nic: &str,
    cidrs: &[String],
    gateway: &Option<String>,
) -> Result<PersistResult, String> {
    match manager {
        NetManager::NetworkManager => persist_networkmanager(bridge, nic, cidrs, gateway),
        NetManager::SystemdNetworkd => persist_systemd_networkd(bridge, nic, cidrs, gateway),
        NetManager::Ifupdown => persist_ifupdown(bridge, nic, cidrs, gateway),
        // Netplan/Wicked/Unknown: we don't write their formats here.
        // Runtime change stands; tell the operator it isn't permanent.
        other => Ok(PersistResult {
            files: Vec::new(),
            nmcli_cons: Vec::new(),
            backups: Vec::new(),
            nmcli_restore: Vec::new(),
            warning: Some(format!(
                "Network manager '{}' is not auto-persisted by WolfStack. \
                 The bridge is live now but will NOT survive a reboot — make \
                 it permanent in your network config manually.",
                other.label()
            )),
            note: format!("Runtime only — '{}' not auto-persisted.", other.label()),
        }),
    }
}

// ────────────────────────────────────────────────────────────────────
// Public entry points
// ────────────────────────────────────────────────────────────────────

/// Validate a bridge name: 1..=15 chars, ASCII alphanumeric or '-'.
fn valid_bridge_name(name: &str) -> bool {
    let len = name.len();
    (1..=15).contains(&len)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// True if `<name>` is an existing interface that is NOT a bridge — we
/// must not clobber a real NIC / VLAN / overlay with our bridge name.
fn exists_as_non_bridge(name: &str) -> bool {
    let path = format!("/sys/class/net/{}", name);
    std::path::Path::new(&path).exists() && !is_bridge(name)
}

/// Build a new LAN bridge. See module docs for the full safety story.
pub fn create_lan_bridge(p: &CreateLanBridgeParams) -> Result<CreateOutcome, String> {
    // ── 1. Validate ──────────────────────────────────────────────
    if !valid_bridge_name(&p.bridge_name) {
        return Err(format!(
            "Invalid bridge name '{}': must be 1-15 characters, letters/digits/'-' only.",
            p.bridge_name
        ));
    }
    if exists_as_non_bridge(&p.bridge_name) {
        return Err(format!(
            "'{}' already exists as a non-bridge interface — choose a different bridge name.",
            p.bridge_name
        ));
    }
    if !std::path::Path::new(&format!("/sys/class/net/{}", p.nic)).exists() {
        return Err(format!("NIC '{}' does not exist.", p.nic));
    }
    if !is_physical_nic(&p.nic) {
        return Err(format!(
            "'{}' is not a physical NIC — only a real interface with a backing device can be enslaved.",
            p.nic
        ));
    }
    if is_bridge(&p.nic) {
        return Err(format!("'{}' is itself a bridge, not a NIC.", p.nic));
    }

    // ── 2. Management detection ──────────────────────────────────
    let mgmt = detect_primary_interface();
    let gateway = default_gateway_via(&p.nic);
    let is_management = p.nic == mgmt || gateway.is_some();

    // ── 3. Risk gate ─────────────────────────────────────────────
    if is_management && !p.accept_risk {
        return Err(format!(
            "'{}' is the management NIC (it carries the default route / your \
             remote session). Enslaving it can briefly cut off access. Re-submit \
             with the risk acknowledgement — WolfStack will arm a {}-second \
             auto-revert so the host self-heals if you get locked out.",
            p.nic, ROLLBACK_SECONDS
        ));
    }

    // ── 4. Capture current state BEFORE changing anything ────────
    let cidrs = nic_ipv4_cidrs(&p.nic);

    // ── 5. Runtime apply ─────────────────────────────────────────
    runtime_apply(&p.bridge_name, &p.nic, &cidrs, &gateway).map_err(|e| {
        // Roll back any partial runtime state on failure so we don't
        // leave a half-built bridge with the operator's IP in limbo.
        runtime_revert(&p.bridge_name, &p.nic, &cidrs, &gateway);
        format!("Runtime apply failed (rolled back): {}", e)
    })?;
    info!(
        "LAN bridge {} created enslaving {} (mgmt={}, addrs={:?})",
        p.bridge_name, p.nic, is_management, cidrs
    );

    // ── 6. Persist across reboot ─────────────────────────────────
    let manager = detect_net_manager();
    let persist_result = match persist(manager, &p.bridge_name, &p.nic, &cidrs, &gateway) {
        Ok(r) => r,
        Err(e) => {
            // Persistence failed — undo the runtime change too so we
            // never leave a live-but-unpersisted management bridge that
            // vanishes on reboot without the operator knowing.
            runtime_revert(&p.bridge_name, &p.nic, &cidrs, &gateway);
            return Err(format!("Persistence failed (runtime change reverted): {}", e));
        }
    };

    let mut message = format!(
        "LAN bridge '{}' is up and enslaves '{}'. {}",
        p.bridge_name, p.nic, persist_result.note
    );
    if let Some(w) = &persist_result.warning {
        message.push_str("  WARNING: ");
        message.push_str(w);
    }

    // ── 7. Commit-confirm (management NIC only) ──────────────────
    if is_management {
        let token = next_token(&p.nic);
        let pending = PendingRollback {
            bridge: p.bridge_name.clone(),
            nic: p.nic.clone(),
            cidrs: cidrs.clone(),
            gateway: gateway.clone(),
            persist_files: persist_result.files.clone(),
            nmcli_cons: persist_result.nmcli_cons.clone(),
            backups: persist_result.backups.clone(),
            nmcli_restore: persist_result.nmcli_restore.clone(),
            confirmed: false,
        };

        // Register the rollback record FIRST, then spawn the watchdog that
        // consults it. Inserting before spawning closes two races: (1) a
        // confirm that lands in the tiny window before insertion would
        // otherwise return "unknown token" while the bridge is live, and the
        // later watchdog would then revert a change the operator tried to
        // keep; (2) the watchdog waking before the insert would find no entry
        // and skip the revert, leaving an un-watchdogged bridge. The watchdog
        // sleeps the full grace period, so the record is always present when
        // it wakes. If the spawn fails we remove the record and fully revert.
        pending_registry()
            .lock()
            .unwrap()
            .insert(token.clone(), pending);

        let token_for_thread = token.clone();
        let spawn_res = std::thread::Builder::new()
            .name("lanbridge-confirm".to_string())
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(ROLLBACK_SECONDS as u64));
                let entry = {
                    let mut reg = pending_registry().lock().unwrap();
                    reg.remove(&token_for_thread)
                };
                match entry {
                    Some(e) if !e.confirmed => {
                        warn!(
                            "LAN bridge {} on {} NOT confirmed within {}s — auto-reverting",
                            e.bridge, e.nic, ROLLBACK_SECONDS
                        );
                        runtime_revert(&e.bridge, &e.nic, &e.cidrs, &e.gateway);
                        revert_persistence(
                            &e.persist_files,
                            &e.nmcli_cons,
                            &e.backups,
                            &e.nmcli_restore,
                        );
                        info!("LAN bridge {} reverted", e.bridge);
                    }
                    Some(e) => {
                        info!("LAN bridge {} confirmed — keeping", e.bridge);
                    }
                    None => {
                        // Already removed (confirmed path cleaned it up).
                    }
                }
            });

        if spawn_res.is_err() {
            // Cannot arm the safety watchdog — drop the record we just
            // inserted and undo everything so the management NIC is never
            // left in a fragile state with no auto-revert.
            pending_registry().lock().unwrap().remove(&token);
            runtime_revert(&p.bridge_name, &p.nic, &cidrs, &gateway);
            revert_persistence(
                &persist_result.files,
                &persist_result.nmcli_cons,
                &persist_result.backups,
                &persist_result.nmcli_restore,
            );
            return Err(
                "Could not arm the auto-revert safety watchdog — the bridge change \
                 was fully reverted to protect your management connection. Try again."
                    .to_string(),
            );
        }

        message.push_str(&format!(
            "  This is the management NIC — confirm within {}s to keep it, or it auto-reverts.",
            ROLLBACK_SECONDS
        ));

        return Ok(CreateOutcome {
            message,
            pending_confirm: Some(token),
            rollback_seconds: ROLLBACK_SECONDS,
        });
    }

    // Non-management NIC — permanent immediately, no timer.
    Ok(CreateOutcome {
        message,
        pending_confirm: None,
        rollback_seconds: 0,
    })
}

/// Confirm a pending management-NIC bridge so its auto-revert timer
/// won't fire. Returns Ok with a confirmation message, Err if the token
/// is unknown / already expired.
pub fn confirm_lan_bridge(token: &str) -> Result<String, String> {
    let mut reg = pending_registry().lock().unwrap();
    match reg.get_mut(token) {
        Some(p) => {
            p.confirmed = true;
            let msg = format!(
                "LAN bridge '{}' confirmed — it will be kept and persists across reboot.",
                p.bridge
            );
            info!("{}", msg);
            Ok(msg)
        }
        None => Err(
            "Unknown or expired confirmation token — the change may have already \
             auto-reverted, or was never a management-NIC change."
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_conversion() {
        assert_eq!(cidr_to_netmask_v4(24), "255.255.255.0");
        assert_eq!(cidr_to_netmask_v4(16), "255.255.0.0");
        assert_eq!(cidr_to_netmask_v4(8), "255.0.0.0");
        assert_eq!(cidr_to_netmask_v4(32), "255.255.255.255");
        assert_eq!(cidr_to_netmask_v4(0), "0.0.0.0");
        assert_eq!(cidr_to_netmask_v4(25), "255.255.255.128");
    }

    #[test]
    fn bridge_name_validation() {
        assert!(valid_bridge_name("br0"));
        assert!(valid_bridge_name("lan-bridge0"));
        assert!(valid_bridge_name("a"));
        assert!(valid_bridge_name("123456789012345")); // exactly 15
        assert!(!valid_bridge_name("")); // empty
        assert!(!valid_bridge_name("1234567890123456")); // 16 chars
        assert!(!valid_bridge_name("br 0")); // space
        assert!(!valid_bridge_name("br.0")); // dot (VLAN-like)
        assert!(!valid_bridge_name("br_0")); // underscore
    }

    #[test]
    fn nat_bridge_classification() {
        assert!(is_nat_bridge_name("lxcbr0"));
        assert!(is_nat_bridge_name("virbr0"));
        assert!(is_nat_bridge_name("virbr1"));
        assert!(is_nat_bridge_name("wnbr-vm42"));
        assert!(!is_nat_bridge_name("br0"));
        assert!(!is_nat_bridge_name("lan0"));
    }

    #[test]
    fn split_cidr_works() {
        assert_eq!(split_cidr("192.168.1.10/24"), Some(("192.168.1.10".to_string(), 24)));
        assert_eq!(split_cidr("10.0.0.1/8"), Some(("10.0.0.1".to_string(), 8)));
        assert_eq!(split_cidr("nonsense"), None);
        assert_eq!(split_cidr("1.2.3.4/notanumber"), None);
    }

    #[test]
    fn token_is_unique_and_deterministic_per_call() {
        let t1 = next_token("eth0");
        let t2 = next_token("eth0");
        assert_ne!(t1, t2); // counter advances
        assert!(t1.starts_with("lanbr-"));
    }
}
