// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Boot persistence for "bring this interface UP" done in the UI.
//!
//! `ip link set <nic> up` is runtime-only. A NIC that no network manager
//! owns (typical for a USB NIC added after install: no
//! /etc/network/interfaces stanza, no .network file, no NM connection)
//! is DOWN again after every reboot — RutgerDiehard, Discord 2026-08-18:
//! "Bringing up in the UI resolved this but it doesn't survive a reboot."
//!
//! Rather than writing per-network-manager config for a bare link-up
//! (nic_addr.rs already does that dance for ADDRESSES, where it's
//! unavoidable), WolfStack records the intent in its own store and
//! re-applies it at boot. That works identically on ifupdown, networkd,
//! NetworkManager, netplan and none-of-the-above, never fights another
//! manager (link-up is idempotent), and — because the boot task retries
//! for a few minutes — covers USB NICs that enumerate after the daemon
//! starts.
//!
//! Scope: UP intent only. Bringing a NIC DOWN in the UI removes the
//! record (back to system default) — it does NOT enforce down-at-boot,
//! which would fight whatever config legitimately ups the NIC.

use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{info, warn};

fn store_path() -> String {
    format!("{}/nic-links.json", crate::paths::get().config_dir)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LinkStore {
    /// Interfaces to bring UP at boot, in the order they were recorded.
    #[serde(default)]
    up: Vec<String>,
}

fn load_store() -> LinkStore {
    match fs::read_to_string(store_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => LinkStore::default(),
    }
}

fn save_store(store: &LinkStore) -> Result<(), String> {
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Failed to serialize link store: {}", e))?;
    fs::write(store_path(), json)
        .map_err(|e| format!("Failed to write {}: {}", store_path(), e))
}

/// Remember that `nic` should be UP after boot. Returns a human note for
/// the UI message. Idempotent.
pub fn record_up(nic: &str) -> String {
    let mut store = load_store();
    if !store.up.iter().any(|n| n == nic) {
        store.up.push(nic.to_string());
        if let Err(e) = save_store(&store) {
            warn!("Failed to persist link-up intent for {}: {}", nic, e);
            return format!(
                " (WARNING: could not persist — {} may be down again after a reboot: {})",
                nic, e
            );
        }
    }
    " — WolfStack will bring it up again after a reboot".to_string()
}

/// Forget the up-at-boot intent for `nic` (operator brought it down —
/// back to whatever the system's own config does). Idempotent.
pub fn clear(nic: &str) {
    let mut store = load_store();
    let before = store.up.len();
    store.up.retain(|n| n != nic);
    if store.up.len() != before
        && let Err(e) = save_store(&store)
    {
        warn!("Failed to remove link-up intent for {}: {}", nic, e);
    }
}

fn interface_exists(nic: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}", nic)).exists()
}

fn interface_is_up(nic: &str) -> bool {
    // /sys flags bit 0 = IFF_UP (admin state — exactly what `ip link set
    // up` toggles; operstate would also depend on carrier, which a NIC
    // with no cable can never satisfy).
    fs::read_to_string(format!("/sys/class/net/{}/flags", nic))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .map(|f| f & 1 == 1)
        .unwrap_or(false)
}

/// One boot-apply attempt: bring up every recorded NIC that exists and
/// is down. Returns the NICs still outstanding (absent — USB not yet
/// enumerated — or the up command failed), so the caller can retry.
pub fn apply_once() -> Vec<String> {
    let store = load_store();
    let mut outstanding = Vec::new();
    for nic in &store.up {
        if !interface_exists(nic) {
            outstanding.push(nic.clone());
            continue;
        }
        if interface_is_up(nic) {
            continue;
        }
        match super::set_interface_state(nic, true) {
            Ok(_) => info!("boot link-up: {} brought up (WolfStack persisted intent)", nic),
            Err(e) => {
                warn!("boot link-up: {} failed: {}", nic, e);
                outstanding.push(nic.clone());
            }
        }
    }
    outstanding
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE test fn (paths::set_for_test is process-global; see
    /// wolfrun's note). Covers record/clear round-trip + idempotence.
    #[test]
    fn record_and_clear_round_trip() {
        let tmp = std::env::temp_dir().join(format!("ws-niclinks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let mut locs = crate::paths::get();
        locs.config_dir = tmp.to_string_lossy().into_owned();
        crate::paths::set_for_test(locs);

        assert!(record_up("usb0").contains("after a reboot"));
        record_up("usb0"); // idempotent — no duplicate
        record_up("eth9");
        assert_eq!(load_store().up, vec!["usb0".to_string(), "eth9".to_string()]);

        clear("usb0");
        assert_eq!(load_store().up, vec!["eth9".to_string()]);
        clear("usb0"); // clearing a non-entry is fine
        clear("eth9");
        assert!(load_store().up.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }
}
