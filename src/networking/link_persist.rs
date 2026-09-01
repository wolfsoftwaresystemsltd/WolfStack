// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
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
//! The intent is keyed on HARDWARE IDENTITY, not just the interface
//! name. `enx*` names are derived from the adapter's MAC address, and
//! USB adapters without a burned-in MAC present a random one on every
//! boot — renaming the interface each reboot, so a name-only record
//! would never match again (Rutger's retest of v25.15.0: up survived
//! the session, next boot the NIC was down under a new name). Each
//! intent therefore also stores the sysfs device path (stable per
//! physical port) and the permanent MAC (`ethtool -P`, when the
//! adapter has one); at boot a missing name is re-matched by either,
//! and the stored name is updated so a later UI "down" on the new name
//! clears the right record.
//!
//! Scope: UP intent only. Bringing a NIC DOWN in the UI removes the
//! record (back to system default) — it does NOT enforce down-at-boot,
//! which would fight whatever config legitimately ups the NIC.

use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use tracing::{info, warn};

fn store_path() -> String {
    format!("{}/nic-links.json", crate::paths::get().config_dir)
}

/// One "keep this NIC up at boot" record. `name` is what the operator
/// saw when they clicked; the identity fields survive a rename.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct LinkIntent {
    name: String,
    /// Canonical /sys device path (e.g. .../usb1/1-2/1-2:1.0) — stable
    /// for the same physical port. Absent for virtual interfaces and
    /// when capture failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dev_path: Option<String>,
    /// Permanent hardware address from `ethtool -P`. Absent when
    /// ethtool is missing or the adapter reports none/zeros.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    perm_mac: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LinkStore {
    /// Interface names to bring UP at boot. Kept as a mirror of
    /// `intents` so a pre-identity build (v25.15.0) reading this file
    /// still applies by name, and so pre-identity files still parse.
    #[serde(default)]
    up: Vec<String>,
    /// The identity-carrying records. Empty in files written by
    /// v25.15.0 — load_store() migrates `up` names into here.
    #[serde(default)]
    intents: Vec<LinkIntent>,
}

fn load_store() -> LinkStore {
    let mut store: LinkStore = match fs::read_to_string(store_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => LinkStore::default(),
    };
    // Migrate a v25.15.0 name-only file: every `up` name becomes an
    // intent with no identity (it gains identity the next time the
    // operator clicks Bring up, or stays name-matched forever).
    for name in &store.up {
        if !store.intents.iter().any(|i| &i.name == name) {
            store.intents.push(LinkIntent { name: name.clone(), ..Default::default() });
        }
    }
    store
}

fn save_store(store: &mut LinkStore) -> Result<(), String> {
    // `up` is always rewritten from `intents` — they never diverge in
    // files this build writes (a renamed intent renames its mirror too).
    store.up = store.intents.iter().map(|i| i.name.clone()).collect();
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Failed to serialize link store: {}", e))?;
    fs::write(store_path(), json)
        .map_err(|e| format!("Failed to write {}: {}", store_path(), e))
}

/// Canonical sysfs device path for `nic`. Virtual interfaces have no
/// `device` entry, so canonicalize fails and they get None — which the
/// matcher treats as "never matches" (None == None is NOT a match).
fn device_path(nic: &str) -> Option<String> {
    fs::canonicalize(format!("/sys/class/net/{}/device", nic))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Permanent (burned-in) MAC via `ethtool -P`. None when ethtool is
/// absent, errors, or the adapter reports no permanent address —
/// exactly the adapters whose runtime MAC randomizes per boot.
fn permanent_mac(nic: &str) -> Option<String> {
    let out = Command::new("ethtool").args(["-P", nic]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mac = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Permanent address:"))?
        .trim()
        .to_lowercase();
    // "00:00:00:00:00:00" and "not set" both mean "no burned-in MAC".
    if mac.is_empty() || mac == "not set" || mac.chars().all(|c| c == '0' || c == ':') {
        return None;
    }
    Some(mac)
}

/// Capture the current identity of `nic` into `intent` (name included).
fn capture_identity(nic: &str, intent: &mut LinkIntent) {
    intent.name = nic.to_string();
    intent.dev_path = device_path(nic);
    intent.perm_mac = permanent_mac(nic);
}

/// True when `intent` and a candidate `(dev_path, perm_mac)` share a
/// concrete identity. Pure so the rename-match logic is unit-testable;
/// None on either side never matches — otherwise every virtual NIC
/// would "match" every ethtool-less record.
fn identity_matches(
    intent: &LinkIntent, cand_dev: &Option<String>, cand_mac: &Option<String>,
) -> bool {
    if let (Some(a), Some(b)) = (&intent.dev_path, cand_dev)
        && a == b
    {
        return true;
    }
    if let (Some(a), Some(b)) = (&intent.perm_mac, cand_mac)
        && a == b
    {
        return true;
    }
    false
}

/// Remember that `nic` should be UP after boot. Returns a human note for
/// the UI message. Idempotent — and if the same physical adapter was
/// recorded under an old name (MAC-derived name changed across a
/// reboot), that record is renamed rather than duplicated.
pub fn record_up(nic: &str) -> String {
    let mut store = load_store();
    let dev = device_path(nic);
    let mac = permanent_mac(nic);
    let existing = store.intents.iter_mut().find(|i| {
        i.name == nic || identity_matches(i, &dev, &mac)
    });
    match existing {
        Some(intent) => capture_identity(nic, intent),
        None => {
            let mut intent = LinkIntent::default();
            capture_identity(nic, &mut intent);
            store.intents.push(intent);
        }
    }
    if let Err(e) = save_store(&mut store) {
        warn!("Failed to persist link-up intent for {}: {}", nic, e);
        return format!(
            " (WARNING: could not persist — {} may be down again after a reboot: {})",
            nic, e
        );
    }
    " — WolfStack will bring it up again after a reboot".to_string()
}

/// Forget the up-at-boot intent for `nic` (operator brought it down —
/// back to whatever the system's own config does). Matches by name OR
/// by the live adapter's identity, so a stale-named record for this
/// same physical device can't survive as a zombie. Idempotent.
pub fn clear(nic: &str) {
    let mut store = load_store();
    let dev = device_path(nic);
    let mac = permanent_mac(nic);
    let before = store.intents.len();
    store.intents.retain(|i| i.name != nic && !identity_matches(i, &dev, &mac));
    if store.intents.len() != before
        && let Err(e) = save_store(&mut store)
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

/// All interface names currently in /sys/class/net (minus loopback).
fn live_interfaces() -> Vec<String> {
    fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != "lo")
                .collect()
        })
        .unwrap_or_default()
}

/// One boot-apply attempt: bring up every recorded NIC. A record whose
/// name no longer exists is re-matched against the live interfaces by
/// device path / permanent MAC (USB adapters with a random per-boot MAC
/// get a new enx* name every reboot); a match renames the stored record.
/// Returns the intents still outstanding (device absent — USB not yet
/// enumerated — or the up command failed), so the caller can retry.
pub fn apply_once() -> Vec<String> {
    let mut store = load_store();
    let mut outstanding = Vec::new();
    let mut renamed = false;
    for intent in store.intents.iter_mut() {
        if !interface_exists(&intent.name) {
            // Name gone — is the same physical adapter here under a new
            // name? Only identity-bearing records can re-match, so skip
            // the scan (and its per-candidate ethtool exec) for the
            // name-only records migrated from v25.15.0 files.
            let found = if intent.dev_path.is_some() || intent.perm_mac.is_some() {
                live_interfaces().into_iter().find(|cand| {
                    identity_matches(intent, &device_path(cand), &permanent_mac(cand))
                })
            } else {
                None
            };
            match found {
                Some(new_name) => {
                    info!(
                        "boot link-up: {} re-matched by hardware identity as {} \
                         (MAC-derived interface name changed across the reboot)",
                        intent.name, new_name
                    );
                    intent.name = new_name;
                    renamed = true;
                }
                None => {
                    outstanding.push(intent.name.clone());
                    continue;
                }
            }
        }
        if interface_is_up(&intent.name) {
            continue;
        }
        match super::set_interface_state(&intent.name, true) {
            Ok(_) => info!(
                "boot link-up: {} brought up (WolfStack persisted intent)",
                intent.name
            ),
            Err(e) => {
                warn!("boot link-up: {} failed: {}", intent.name, e);
                outstanding.push(intent.name.clone());
            }
        }
    }
    if renamed && let Err(e) = save_store(&mut store) {
        // Non-fatal: the NIC is up; only the stored name is stale until
        // the next successful save.
        warn!("boot link-up: could not persist renamed intent(s): {}", e);
    }
    outstanding
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE test fn (paths::set_for_test is process-global; see
    /// wolfrun's note). Covers record/clear round-trip + idempotence,
    /// v25.15.0 name-only file migration, and identity matching.
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
        assert!(load_store().intents.is_empty());

        // A v25.15.0 file carries only names — loading must migrate
        // them into intents (no identity) without losing any.
        fs::write(store_path(), r#"{"up":["enxaabbccddeeff"]}"#).unwrap();
        let migrated = load_store();
        assert_eq!(migrated.intents.len(), 1);
        assert_eq!(migrated.intents[0].name, "enxaabbccddeeff");
        assert_eq!(migrated.intents[0].dev_path, None);

        // Identity matching: concrete equal values match; None never
        // matches None (else every virtual NIC would match every
        // identity-less record).
        let intent = LinkIntent {
            name: "enxOLD".into(),
            dev_path: Some("/sys/devices/usb1/1-2".into()),
            perm_mac: None,
        };
        assert!(identity_matches(&intent, &Some("/sys/devices/usb1/1-2".into()), &None));
        assert!(!identity_matches(&intent, &Some("/sys/devices/usb1/1-3".into()), &None));
        assert!(!identity_matches(&intent, &None, &None));
        let no_id = LinkIntent { name: "enxOLD".into(), ..Default::default() };
        assert!(!identity_matches(&no_id, &None, &None));
        assert!(!identity_matches(&no_id, &Some("/sys/devices/usb1/1-2".into()), &None));
        // Permanent-MAC path.
        let by_mac = LinkIntent {
            name: "enxOLD".into(),
            dev_path: None,
            perm_mac: Some("aa:bb:cc:dd:ee:ff".into()),
        };
        assert!(identity_matches(&by_mac, &None, &Some("aa:bb:cc:dd:ee:ff".into())));
        assert!(!identity_matches(&by_mac, &None, &Some("11:22:33:44:55:66".into())));

        let _ = fs::remove_dir_all(&tmp);
    }
}
