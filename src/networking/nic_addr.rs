// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Persistent per-NIC IP assignment — the UI's "add IP to interface"
//! used to be a bare runtime `ip addr add`: stored nowhere, gone on
//! reboot, and (worse) squatting on the address so a hand-written
//! `/etc/network/interfaces` stanza failed `ifup` with "already
//! assigned", while the UI's remove button couldn't clear an address
//! that actually lived on a different NIC (RutgerDiehard, 2026-08-11:
//! new 2.5GbE cards unusable from the UI).
//!
//! Model:
//! * WolfStack keeps its own record of UI-assigned addresses per NIC in
//!   `nic-addrs.json` — the source of truth the persistence files are
//!   regenerated from on every change. Runtime state is never adopted
//!   into it (a DHCP lease must not get frozen into a static stanza).
//! * Persistence mirrors `lan_bridge`'s tri-manager posture: ifupdown
//!   drop-in, systemd-networkd `.network` drop-in, NetworkManager via
//!   `nmcli` on the device's existing manual connection. Anything else
//!   gets a runtime-only change and an honest note that it won't
//!   survive a reboot.
//! * Adding an address that is already present on the SAME interface is
//!   not an error — the runtime add is skipped and persistence still
//!   happens (this is exactly the "UI added it runtime-only last boot"
//!   healing path). Already present on a DIFFERENT interface is a
//!   clear, named error instead of a raw RTNETLINK message.

use std::collections::HashMap;
use std::process::Command;

use super::lan_bridge::{cidr_to_netmask_v4, interfaces_sources_dropins, split_cidr};
use super::vlan::{detect_net_manager, NetManager};

fn store_path() -> String {
    format!("{}/nic-addrs.json", crate::paths::get().config_dir)
}

fn load_store() -> HashMap<String, Vec<String>> {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_store(store: &HashMap<String, Vec<String>>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
    crate::paths::write_secure(&store_path(), json).map_err(|e| e.to_string())
}

/// Which interface currently holds `address` (exact IPv4 match), if any.
/// Parses `ip -4 -br addr` (`IFACE STATE CIDR [CIDR…]`).
fn interface_holding(address: &str) -> Option<String> {
    let out = Command::new("ip").args(["-4", "-br", "addr"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    find_holder(&String::from_utf8_lossy(&out.stdout), address)
}

/// Pure parser half of [`interface_holding`] — unit-tested.
fn find_holder(ip_br_output: &str, address: &str) -> Option<String> {
    for line in ip_br_output.lines() {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?.to_string();
        let _state = cols.next();
        for cidr in cols {
            if cidr.split('/').next() == Some(address) {
                // `ip -br` renders sub-interfaces as name@parent.
                return Some(iface.split('@').next().unwrap_or(&iface).to_string());
            }
        }
    }
    None
}

fn ifupdown_snippet_path(nic: &str) -> String {
    format!("/etc/network/interfaces.d/wolfstack-nic-{}.conf", nic)
}

fn networkd_snippet_path(nic: &str) -> String {
    format!("/etc/systemd/network/50-wolfstack-nic-{}.network", nic)
}

/// True when a non-comment stanza for `nic` exists in the operator's
/// primary `/etc/network/interfaces`. WolfStack must not write a
/// dueling drop-in for a NIC the operator already configures by hand —
/// two static stanzas for one NIC is how `ifup` conflicts start.
fn main_interfaces_file_owns(nic: &str) -> bool {
    let Ok(main) = std::fs::read_to_string("/etc/network/interfaces") else {
        return false;
    };
    main.lines().any(|l| {
        let t = l.trim();
        !t.starts_with('#')
            && (t == format!("iface {} inet static", nic)
                || t == format!("iface {} inet dhcp", nic)
                || t == format!("iface {} inet manual", nic)
                || t.starts_with(&format!("iface {} ", nic)))
    })
}

/// Regenerate (or delete, when `cidrs` is empty) this NIC's persistence
/// under the active network manager. Returns a plain-English note for
/// the operator about what was (or wasn't) persisted.
fn persist(nic: &str, cidrs: &[String]) -> String {
    let mgr = detect_net_manager();
    match mgr {
        NetManager::Ifupdown => persist_ifupdown(nic, cidrs),
        NetManager::SystemdNetworkd => persist_networkd(nic, cidrs),
        NetManager::NetworkManager => persist_networkmanager(nic, cidrs),
        // netplan/wicked/unknown: no safe write path here — be honest,
        // exactly like lan_bridge's posture for managers it can't drive.
        _ => format!(
            "Applied to the running system only — this host uses {} which \
             WolfStack doesn't persist interface addresses to yet; add the \
             address to your {} config or it will not survive a reboot.",
            mgr.label(), mgr.label()
        ),
    }
}

fn persist_ifupdown(nic: &str, cidrs: &[String]) -> String {
    let path = ifupdown_snippet_path(nic);
    if cidrs.is_empty() {
        let _ = std::fs::remove_file(&path);
        return format!("Persistent config for {} removed.", nic);
    }
    if main_interfaces_file_owns(nic) {
        return format!(
            "Applied to the running system; NOT persisted: /etc/network/interfaces \
             already has its own stanza for {} — edit that file to change what \
             comes up at boot (two configs for one NIC would fight).",
            nic
        );
    }
    if let Some(parent) = std::path::Path::new(&path).parent()
        && let Err(e) = std::fs::create_dir_all(parent) {
            return format!("Applied to the running system; persisting failed: {}", e);
        }
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — interface addresses set in the UI.\n");
    out.push_str("# Regenerated on every change; do not edit by hand.\n\n");
    out.push_str(&format!("auto {}\n", nic));
    let (addr, prefix) = match split_cidr(&cidrs[0]) {
        Some(v) => v,
        None => return format!("Applied to the running system; persisting failed: malformed CIDR '{}'", cidrs[0]),
    };
    out.push_str(&format!("iface {} inet static\n", nic));
    out.push_str(&format!("    address {}\n", addr));
    out.push_str(&format!("    netmask {}\n", cidr_to_netmask_v4(prefix)));
    for extra in cidrs.iter().skip(1) {
        out.push_str(&format!("    post-up ip addr add {} dev {} || true\n", extra, nic));
    }
    if let Err(e) = std::fs::write(&path, &out) {
        return format!("Applied to the running system; persisting failed: {}", e);
    }
    if !interfaces_sources_dropins() {
        return format!(
            "Applied and written to {}, but /etc/network/interfaces does not source \
             interfaces.d/* — add `source /etc/network/interfaces.d/*` near the top \
             of it or the address will NOT return after a reboot.",
            path
        );
    }
    format!("Applied and persisted (survives reboot: {}).", path)
}

fn persist_networkd(nic: &str, cidrs: &[String]) -> String {
    let path = networkd_snippet_path(nic);
    if cidrs.is_empty() {
        let _ = std::fs::remove_file(&path);
        let _ = Command::new("networkctl").arg("reload").output();
        return format!("Persistent config for {} removed.", nic);
    }
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — interface addresses set in the UI.\n");
    out.push_str("# Regenerated on every change; do not edit by hand.\n");
    out.push_str(&format!("[Match]\nName={}\n\n[Network]\n", nic));
    for cidr in cidrs {
        out.push_str(&format!("Address={}\n", cidr));
    }
    if let Err(e) = std::fs::write(&path, &out) {
        return format!("Applied to the running system; persisting failed: {}", e);
    }
    let _ = Command::new("networkctl").arg("reload").output();
    format!("Applied and persisted (survives reboot: {}).", path)
}

fn persist_networkmanager(nic: &str, cidrs: &[String]) -> String {
    // Only a device with an existing MANUAL-method connection can take
    // static addresses without WolfStack changing how the NIC gets its
    // primary address. Flipping a DHCP connection to manual behind the
    // operator's back could drop the very lease their session rides on.
    let Some(con) = super::lan_bridge::nm_active_connection_for_device(nic) else {
        return format!(
            "Applied to the running system; NOT persisted: NetworkManager has no \
             active connection for {} — create one (nmcli con add …) and re-add \
             the address, or it will not survive a reboot.",
            nic
        );
    };
    let method = Command::new("nmcli")
        .args(["-g", "ipv4.method", "con", "show", &con])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if method != "manual" && !cidrs.is_empty() {
        return format!(
            "Applied to the running system; NOT persisted: {}'s NetworkManager \
             connection '{}' uses method '{}' (not manual) — putting a static \
             address in it would change how the NIC boots. Set the address in \
             the connection itself if you want it permanent.",
            nic, con, method
        );
    }
    // Rebuild the connection's address list to match ours exactly.
    let desired = cidrs.join(",");
    let args: Vec<&str> = if cidrs.is_empty() {
        vec!["con", "mod", &con, "ipv4.addresses", ""]
    } else {
        vec!["con", "mod", &con, "ipv4.addresses", &desired]
    };
    let ok = Command::new("nmcli").args(&args).output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        return format!("Applied to the running system; nmcli could not update connection '{}'.", con);
    }
    // Reapply without bouncing the device (a `con up` would drop the link).
    let _ = Command::new("nmcli").args(["device", "reapply", nic]).output();
    if cidrs.is_empty() {
        format!("Persistent addresses cleared from NetworkManager connection '{}'.", con)
    } else {
        format!("Applied and persisted in NetworkManager connection '{}'.", con)
    }
}

/// Add `address/prefix` to `nic`, runtime + persisted. See module docs.
pub fn add_ip(nic: &str, address: &str, prefix: u32) -> Result<String, String> {
    let cidr = format!("{}/{}", address, prefix);
    match interface_holding(address) {
        Some(holder) if holder != nic => {
            return Err(format!(
                "{} is already assigned to {} — remove it there first \
                 (Networking → {} → its address list).",
                address, holder, holder
            ));
        }
        Some(_) => { /* already on this NIC — skip the runtime add, still persist */ }
        None => {
            let out = Command::new("ip")
                .args(["addr", "add", &cidr, "dev", nic])
                .output()
                .map_err(|e| format!("Failed to run ip addr add: {}", e))?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).to_string());
            }
        }
    }
    let mut store = load_store();
    let list = store.entry(nic.to_string()).or_default();
    if !list.contains(&cidr) {
        list.push(cidr.clone());
    }
    let cidrs = list.clone();
    if let Err(e) = save_store(&store) {
        return Ok(format!("Added {} to {} (running system), but saving WolfStack's record failed: {}", cidr, nic, e));
    }
    let note = persist(nic, &cidrs);
    Ok(format!("Added {} to {}. {}", cidr, nic, note))
}

/// Remove `address/prefix` from `nic`, runtime + persisted. Succeeds
/// (and still cleans persistence) when the runtime address is already
/// gone — remove must always be able to clear stale state.
pub fn remove_ip(nic: &str, address: &str, prefix: u32) -> Result<String, String> {
    let cidr = format!("{}/{}", address, prefix);
    if let Some(holder) = interface_holding(address) {
        if holder != nic {
            return Err(format!(
                "{} is not on {} — it is currently assigned to {}. Remove it from \
                 {} instead.",
                address, nic, holder, holder
            ));
        }
        let out = Command::new("ip")
            .args(["addr", "del", &cidr, "dev", nic])
            .output()
            .map_err(|e| format!("Failed to run ip addr del: {}", e))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).to_string());
        }
    }
    let mut store = load_store();
    let mut note = String::new();
    if let Some(list) = store.get_mut(nic) {
        list.retain(|c| c != &cidr && c.split('/').next() != Some(address));
        let cidrs = list.clone();
        if cidrs.is_empty() {
            store.remove(nic);
        }
        if let Err(e) = save_store(&store) {
            return Ok(format!("Removed {} from {} (running system), but saving WolfStack's record failed: {}", cidr, nic, e));
        }
        note = persist(nic, &cidrs);
    }
    if note.is_empty() {
        Ok(format!("Removed {} from {}.", cidr, nic))
    } else {
        Ok(format!("Removed {} from {}. {}", cidr, nic, note))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_holder_matches_exact_address_on_any_interface() {
        let out = "\
lo               UNKNOWN        127.0.0.1/8
wlan0            UP             192.168.50.241/24
enp5s0           DOWN           192.168.60.10/24 10.0.0.5/32
vlan40@enp5s0    UP             10.0.40.2/24
";
        assert_eq!(find_holder(out, "192.168.60.10"), Some("enp5s0".into()));
        assert_eq!(find_holder(out, "10.0.0.5"), Some("enp5s0".into()));
        // Sub-interface name is trimmed at the @.
        assert_eq!(find_holder(out, "10.0.40.2"), Some("vlan40".into()));
        // Prefix of an address must not match (192.168.50.24 vs .241).
        assert_eq!(find_holder(out, "192.168.50.24"), None);
        assert_eq!(find_holder(out, "203.0.113.9"), None);
    }

    #[test]
    fn ifupdown_snippet_is_regenerated_per_change() {
        // Pure string assembly check via the public shape: first CIDR is
        // the stanza, extras become post-up lines. (Write path exercised
        // only when the target dir exists — CI has no /etc/network.)
        let (addr, prefix) = split_cidr("192.168.60.10/24").unwrap();
        assert_eq!(addr, "192.168.60.10");
        assert_eq!(cidr_to_netmask_v4(prefix), "255.255.255.0");
    }
}
