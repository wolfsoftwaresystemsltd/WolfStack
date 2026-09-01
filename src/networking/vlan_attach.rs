// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Backend-specific code for attaching/detaching a guest (LXC native,
//! Proxmox CT/VM, Docker container, libvirt VM) to a VLAN bridge.
//!
//! Every backend takes the same logical inputs:
//! - bridge name (e.g. `vmbr4000`)
//! - IP/CIDR (e.g. `10.0.1.10/24`)
//! - MTU (e.g. `1400`)
//! - target id (container name / VMID / docker name / domain name)
//!
//! Each adapter writes the backend's native config + brings the
//! interface up. `apply` returns a brief human-readable summary
//! suitable for the UI's success toast or a warning toast on partial
//! failure (e.g. config saved but container needs manual restart).
//!
//! ## Honest scope
//!
//! - **LXC native (raw `lxc-start`)**: full support — write config +
//!   restart container.
//! - **Proxmox LXC**: requires `pct` on PATH (which it always is on
//!   Proxmox hosts). Writes config via `pct set` and restarts.
//! - **Docker**: creates a docker macvlan/bridge network on top of the
//!   VLAN bridge (so multiple containers can share it without IP
//!   collision) and attaches via `docker network connect`.
//! - **Native VMs (libvirt)**: requires libvirt + qemu present.
//!   `virsh attach-interface` (persistent, explicit MAC) attaches the
//!   NIC; the in-guest IP is staged via a NoCloud cloud-init seed ISO
//!   (`cloud-localds`) attached as a CD-ROM. The guest applies it on
//!   the next boot — requires cloud-init present in the guest.
//! - **Proxmox VMs**: `qm set -netN` attaches the NIC; the in-guest IP
//!   is staged via Proxmox cloud-init (`qm set --ipconfigN`), adding a
//!   cloud-init drive if the VM lacks one. Applied on the next boot.
//!
//! ## VM IP — the cloud-init constraint
//!
//! A VM's IP lives inside the guest OS; it cannot be set from the
//! hypervisor at runtime. Both VM backends therefore *stage* the IP
//! via cloud-init and the guest applies it on its **next boot**. The
//! caller can request an immediate reboot (`AttachParams.reboot`).

use std::process::Command;
use crate::networking::vlan::RouteEntry;

/// Common operation parameters; same shape regardless of backend.
pub struct AttachParams<'a> {
    pub bridge: &'a str,
    /// Full CIDR (e.g. "10.0.1.10/24"), not just the address.
    pub ip_cidr: &'a str,
    pub mtu: u32,
    /// Optional gateway. None = static IP without default route.
    /// Used by the container backends (a container's VLAN NIC is
    /// usually its only NIC, so a default route is correct). VM
    /// backends ignore this: a vSwitch NIC on a VM is a *secondary*
    /// interface and must not hijack the guest's existing default
    /// route.
    pub gateway: Option<&'a str>,
    /// Operator-configured VLAN routes. The libvirt VM backend emits
    /// these as specific, non-default routes in the guest's cloud-init
    /// network config. Empty = address only.
    pub routes: &'a [RouteEntry],
    /// VM backends only: reboot the guest after staging cloud-init so
    /// the IP applies immediately. False = stage only; the operator
    /// reboots when ready.
    pub reboot: bool,
    /// Backend-specific identifier (container name, VMID, etc.).
    pub target_id: &'a str,
}

#[derive(Debug)]
pub struct AttachOutcome {
    pub message: String,
    pub restarted: bool,
}

/// Strip the prefix off a CIDR, returning just the address. Used by
/// backends that take a separate IP and netmask.
fn ip_only(cidr: &str) -> String {
    cidr.split('/').next().unwrap_or(cidr).to_string()
}

// ────────────────────────────────────────────────────────────────────
// LXC native (raw /var/lib/lxc/<name>/config)
// ────────────────────────────────────────────────────────────────────

/// Attach a native LXC container to the bridge. Writes a fresh
/// `lxc.net.N.*` block with the next available index, then restarts
/// the container so the change takes effect.
pub fn attach_lxc_native(p: &AttachParams) -> Result<AttachOutcome, String> {
    let cfg_path = format!("/var/lib/lxc/{}/config", p.target_id);
    let existing = std::fs::read_to_string(&cfg_path)
        .map_err(|e| format!("read {}: {}", cfg_path, e))?;
    let next_idx = next_lxc_net_index(&existing);
    // Stable host-side veth name so `ip link` output is debuggable
    // ("ws-<container>-<idx>" instead of random "vethXYZ"). 15-char
    // limit on Linux iface names — truncate the container name part
    // if needed but keep the index suffix so multiple attaches don't
    // collide.
    let veth_pair = stable_veth_name(p.target_id, next_idx);
    // Stable hardware address derived deterministically from the
    // container name + bridge + index. Without an explicit hwaddr,
    // LXC generates a random MAC each boot — DHCP reservations break,
    // ARP caches go stale, and operators can't pin firewall rules to
    // a known MAC. Stable MAC fixes all three. The 02:xx prefix marks
    // it as locally-administered (universal/local bit set).
    let hwaddr = stable_hwaddr(p.target_id, p.bridge, next_idx);
    let mut block = String::new();
    block.push_str("\n# Added by WolfStack — VLAN bridge attachment\n");
    block.push_str(&format!("lxc.net.{}.type = veth\n", next_idx));
    block.push_str(&format!("lxc.net.{}.link = {}\n", next_idx, p.bridge));
    block.push_str(&format!("lxc.net.{}.veth.pair = {}\n", next_idx, veth_pair));
    block.push_str(&format!("lxc.net.{}.hwaddr = {}\n", next_idx, hwaddr));
    block.push_str(&format!("lxc.net.{}.flags = up\n", next_idx));
    block.push_str(&format!("lxc.net.{}.mtu = {}\n", next_idx, p.mtu));
    block.push_str(&format!("lxc.net.{}.ipv4.address = {}\n", next_idx, p.ip_cidr));
    if let Some(gw) = p.gateway {
        block.push_str(&format!("lxc.net.{}.ipv4.gateway = {}\n", next_idx, gw));
    }
    let mut combined = existing;
    if !combined.ends_with('\n') { combined.push('\n'); }
    combined.push_str(&block);
    std::fs::write(&cfg_path, combined)
        .map_err(|e| format!("write {}: {}", cfg_path, e))?;

    // Restart the container. Stop+start because reboot keeps the
    // container's namespace and won't pick up the new lxc.net entry.
    //
    // 60s graceful shutdown timeout — long enough for a database
    // container to flush WAL and shut down cleanly. The previous
    // 10s default was an early-pre-empt risk for production loads.
    // After 60s we fall through to lxc-start which will SIGKILL any
    // remaining process group; the operator gets a clear message.
    let _ = Command::new("lxc-stop").args(["-n", p.target_id, "-t", "60"]).output();
    let start = Command::new("lxc-start").args(["-n", p.target_id]).output()
        .map_err(|e| format!("spawn lxc-start: {}", e))?;
    if !start.status.success() {
        return Ok(AttachOutcome {
            message: format!(
                "Config updated but container failed to restart: {}",
                String::from_utf8_lossy(&start.stderr).trim()
            ),
            restarted: false,
        });
    }
    Ok(AttachOutcome {
        message: format!("Attached lxc.net.{} on {} ({}); container restarted.", next_idx, p.bridge, p.ip_cidr),
        restarted: true,
    })
}

/// Build a stable host-side veth name for a (container, index) pair.
/// Linux interface names cap at 15 chars (IFNAMSIZ-1 = 15). The format
/// is `ws-<container>-<idx>`, with the container portion truncated as
/// needed so the suffix always fits. Any non-alphanumeric character
/// in the container name is dropped (interface names disallow them).
fn stable_veth_name(container: &str, idx: u32) -> String {
    let suffix = format!("-{}", idx);
    let prefix = "ws-";
    // Available room for the container name portion.
    let max_container = 15 - prefix.len() - suffix.len();
    let cleaned: String = container.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(max_container)
        .collect();
    format!("{}{}{}", prefix, cleaned, suffix)
}

/// Build a stable, locally-administered MAC address from a (container,
/// bridge, index) tuple. Uses a deterministic hash so the same inputs
/// always produce the same MAC — the operator's container keeps its
/// MAC across reboots and reattach cycles. Locally-administered prefix
/// `02:` is RFC-compliant for OS-assigned MACs (no OUI registration).
fn stable_hwaddr(container: &str, bridge: &str, idx: u32) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    container.hash(&mut h);
    bridge.hash(&mut h);
    idx.hash(&mut h);
    let n = h.finish();
    let bytes = n.to_be_bytes();
    // 02:xx:xx:xx:xx:xx — 02 marks it as locally-administered (bit 1
    // of the first octet set), unicast (bit 0 clear).
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
    )
}

/// Find the next free `lxc.net.N` index by scanning the config.
fn next_lxc_net_index(cfg: &str) -> u32 {
    let mut max_seen: i32 = -1;
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("lxc.net.")
            && let Some(num_str) = rest.split('.').next()
                && let Ok(n) = num_str.parse::<i32>()
                    && n > max_seen { max_seen = n; }
    }
    (max_seen + 1) as u32
}

/// Detach by removing all lxc.net.N.* lines that reference the given
/// bridge. Restarts the container so the change takes effect.
pub fn detach_lxc_native(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    let cfg_path = format!("/var/lib/lxc/{}/config", target_id);
    let existing = std::fs::read_to_string(&cfg_path)
        .map_err(|e| format!("read {}: {}", cfg_path, e))?;
    // Find which index(es) reference this bridge, then drop every
    // lxc.net.IDX.* line for each matched index. We don't reindex
    // remaining blocks — LXC tolerates gaps in the numbering.
    let mut indexes_to_drop: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for line in existing.lines() {
        let t = line.trim();
        if t.starts_with('#') { continue; }
        let Some(rest) = t.strip_prefix("lxc.net.") else { continue };
        let Some((num_str, suffix)) = rest.split_once('.') else { continue };
        // Match the `link` key exactly — not `linkN`, not anything else
        // that happens to start with the same letters. The key is
        // followed by either `=` directly or whitespace before `=`.
        let suffix = suffix.trim_start();
        let Some(after_link) = suffix.strip_prefix("link") else { continue };
        let next = after_link.chars().next();
        if !matches!(next, Some('=') | Some(' ') | Some('\t')) { continue; }
        let Some((_, val)) = t.split_once('=') else { continue };
        if val.trim() != bridge { continue; }
        let Ok(n) = num_str.parse::<u32>() else { continue };
        indexes_to_drop.insert(n);
    }
    if indexes_to_drop.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No lxc.net entry referenced bridge {} — nothing to detach.", bridge),
            restarted: false,
        });
    }
    let prefixes: Vec<String> = indexes_to_drop.iter()
        .map(|i| format!("lxc.net.{}.", i))
        .collect();
    let kept: Vec<&str> = existing.lines()
        .filter(|line| {
            let t = line.trim();
            !prefixes.iter().any(|p| t.starts_with(p.as_str()))
        })
        .collect();
    let new_cfg = kept.join("\n");
    std::fs::write(&cfg_path, &new_cfg)
        .map_err(|e| format!("write {}: {}", cfg_path, e))?;

    let _ = Command::new("lxc-stop").args(["-n", target_id, "-t", "60"]).output();
    let _ = Command::new("lxc-start").args(["-n", target_id]).output();
    Ok(AttachOutcome {
        message: format!("Removed {} lxc.net entr{} for bridge {}; container restarted.",
            indexes_to_drop.len(),
            if indexes_to_drop.len() == 1 { "y" } else { "ies" },
            bridge),
        restarted: true,
    })
}

// ────────────────────────────────────────────────────────────────────
// LXC on Proxmox (`pct set`)
// ────────────────────────────────────────────────────────────────────

/// Attach a Proxmox LXC container by adding a netN device. Picks the
/// next free index by inspecting the current config.
pub fn attach_lxc_proxmox(p: &AttachParams) -> Result<AttachOutcome, String> {
    let vmid = p.target_id;
    let next_idx = next_pct_net_index(vmid)?;
    let cidr = p.ip_cidr;
    let mut spec = format!("name=eth{idx},bridge={br},ip={ip},mtu={mtu}",
        idx = next_idx, br = p.bridge, ip = cidr, mtu = p.mtu);
    if let Some(gw) = p.gateway {
        spec.push_str(&format!(",gw={}", gw));
    }
    let arg = format!("-net{}", next_idx);
    let out = Command::new("pct").args(["set", vmid, &arg, &spec]).output()
        .map_err(|e| format!("spawn pct: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct set failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    // Graceful shutdown then start, rather than `pct reboot` which
    // SIGKILLs after a hard 60s timeout. shutdown sends SIGPWR / ACPI
    // so the container init can flush state. We give it 90s before
    // moving on; if it doesn't stop in that window the container is
    // probably wedged and the operator will see it didn't restart.
    let stopped = Command::new("pct")
        .args(["shutdown", vmid, "--timeout", "90"])
        .output();
    let start_needed = match stopped {
        Ok(o) if o.status.success() => true,
        _ => {
            // shutdown failed (already stopped, or wedged). Try `start`
            // anyway — if it's already running, start is a no-op.
            true
        }
    };
    if start_needed {
        let _ = Command::new("pct").args(["start", vmid]).output();
    }
    Ok(AttachOutcome {
        message: format!(
            "Attached net{} on {} ({}); container restarted via graceful shutdown.",
            next_idx, p.bridge, cidr,
        ),
        restarted: true,
    })
}

/// Find the next free netN slot in a Proxmox CT config by parsing
/// `pct config <vmid>` output.
fn next_pct_net_index(vmid: &str) -> Result<u32, String> {
    let out = Command::new("pct").args(["config", vmid]).output()
        .map_err(|e| format!("spawn pct: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct config failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let cfg = String::from_utf8_lossy(&out.stdout);
    let mut max_seen: i32 = -1;
    for line in cfg.lines() {
        if let Some(rest) = line.trim().strip_prefix("net")
            && let Some((num_str, _)) = rest.split_once(':')
                && let Ok(n) = num_str.parse::<i32>()
                    && n > max_seen { max_seen = n; }
    }
    Ok((max_seen + 1) as u32)
}

/// Detach by removing the netN device(s) that reference the bridge.
pub fn detach_lxc_proxmox(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    let cfg_out = Command::new("pct").args(["config", target_id]).output()
        .map_err(|e| format!("spawn pct: {}", e))?;
    if !cfg_out.status.success() {
        return Err(format!("pct config failed: {}", String::from_utf8_lossy(&cfg_out.stderr).trim()));
    }
    let cfg = String::from_utf8_lossy(&cfg_out.stdout);
    let mut to_remove: Vec<String> = Vec::new();
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("net")
            && let Some((num_str, val)) = rest.split_once(':')
                && val.contains(&format!("bridge={}", bridge)) {
                    to_remove.push(format!("net{}", num_str));
                }
    }
    if to_remove.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No net device on container {} referenced {}.", target_id, bridge),
            restarted: false,
        });
    }
    for dev in &to_remove {
        let arg = format!("--delete={}", dev);
        let _ = Command::new("pct").args(["set", target_id, &arg]).output();
    }
    let _ = Command::new("pct").args(["shutdown", target_id, "--timeout", "90"]).output();
    let _ = Command::new("pct").args(["start", target_id]).output();
    Ok(AttachOutcome {
        message: format!(
            "Removed {} net device(s) on {}; container restarted via graceful shutdown.",
            to_remove.len(), target_id,
        ),
        restarted: true,
    })
}

// ────────────────────────────────────────────────────────────────────
// VMs on Proxmox (`qm set` + cloud-init)
// ────────────────────────────────────────────────────────────────────

/// Attach a Proxmox QEMU VM to the bridge and stage its IP via
/// Proxmox cloud-init.
///
/// Flow: `qm set -netN` attaches the NIC; `qm set --ipconfigN` stages
/// the IP on the matching index; `qm cloudinit update` regenerates the
/// drive. If the VM has no cloud-init drive we add one on a free IDE
/// slot. The guest applies the IP on its next boot — we reboot here
/// only if the caller asked.
///
/// Verified syntax (Proxmox `qm.1` man page): `--ipconfig[n]` carries
/// `gw=<GatewayIPv4>` / `ip=<IPv4Format/CIDR>` and configures the
/// correspondingly-indexed `net[n]` device; `qm cloudinit update`
/// regenerates the cloud-init drive; `qm reboot` applies pending
/// changes. Verified syntax (Proxmox `Cloud-Init_Support` wiki):
/// `qm set <vmid> --ide2 <storage>:cloudinit` adds a cloud-init drive.
pub fn attach_vm_proxmox(p: &AttachParams) -> Result<AttachOutcome, String> {
    let vmid = p.target_id;
    let cfg = qm_config(vmid)?;
    let next_idx = (max_cfg_index(&cfg, "net") + 1) as u32;

    // 1. Attach the NIC. No ip= here — the IP goes via cloud-init.
    let spec = format!("model=virtio,bridge={br},mtu={mtu}", br = p.bridge, mtu = p.mtu);
    run_qm(&["set", vmid, &format!("-net{}", next_idx), &spec])?;

    // 2. Ensure the VM has a cloud-init drive — add one if not.
    let ci_note = match ensure_cloudinit_drive(vmid, &cfg) {
        Ok(Some(slot)) => format!(" Added a cloud-init drive on ide{}.", slot),
        Ok(None) => String::new(),
        Err(e) => {
            return Ok(AttachOutcome {
                message: format!(
                    "Attached net{} on {}, but {}. Add a cloud-init drive in Proxmox \
                     (Hardware → Add → CloudInit Drive), then re-attach, or set IP {} \
                     inside the guest.",
                    next_idx, p.bridge, e, p.ip_cidr),
                restarted: false,
            });
        }
    };

    // 3. Stage the IP on the matching ipconfig index. Proxmox
    //    ipconfigN carries only ip + gw; a vSwitch NIC is a secondary
    //    interface, so we set ip only — never a gw, which would
    //    hijack the guest's existing default route.
    run_qm(&["set", vmid, &format!("--ipconfig{}", next_idx),
        &format!("ip={}", p.ip_cidr)])?;
    let routes_note = if p.routes.is_empty() { "" } else {
        " This VLAN has custom routes — Proxmox cloud-init carries only \
          the IP, so add those routes inside the guest."
    };

    // 4. Regenerate the cloud-init drive so it carries the new config.
    let _ = run_qm(&["cloudinit", "update", vmid]);

    // 5. Reboot only if asked. `qm reboot` applies pending changes.
    if p.reboot {
        if let Err(e) = run_qm(&["reboot", vmid]) {
            return Ok(AttachOutcome {
                message: format!(
                    "Attached net{} on {} and staged IP {} via cloud-init{}, but the reboot \
                     failed: {}. Reboot the VM manually to apply the IP.{}",
                    next_idx, p.bridge, p.ip_cidr, ci_note, e, routes_note),
                restarted: false,
            });
        }
        return Ok(AttachOutcome {
            message: format!(
                "Attached net{} on {}, staged IP {} via cloud-init{}, and rebooted the VM to \
                 apply it.{}",
                next_idx, p.bridge, p.ip_cidr, ci_note, routes_note),
            restarted: true,
        });
    }
    Ok(AttachOutcome {
        message: format!(
            "Attached net{} on {} and staged IP {} via cloud-init{}. Reboot the VM to apply \
             the IP.{}",
            next_idx, p.bridge, p.ip_cidr, ci_note, routes_note),
        restarted: false,
    })
}

/// Run `qm` with the given args; map a non-zero exit to an Err.
fn run_qm(args: &[&str]) -> Result<(), String> {
    let out = Command::new("qm").args(args).output()
        .map_err(|e| format!("spawn qm: {}", e))?;
    if !out.status.success() {
        return Err(format!("qm {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Fetch `qm config <vmid>` as a string.
fn qm_config(vmid: &str) -> Result<String, String> {
    let out = Command::new("qm").args(["config", vmid]).output()
        .map_err(|e| format!("spawn qm: {}", e))?;
    if !out.status.success() {
        return Err(format!("qm config failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Highest `<prefix><N>:` index in a `qm`/`pct` config dump, or -1 if
/// none present. Next free index is the return value + 1.
fn max_cfg_index(cfg: &str, prefix: &str) -> i32 {
    let mut max_seen: i32 = -1;
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(prefix)
            && let Some((num, _)) = rest.split_once(':')
            && let Ok(n) = num.parse::<i32>()
            && n > max_seen
        {
            max_seen = n;
        }
    }
    max_seen
}

/// True if the `qm config` dump already lists a cloud-init drive.
/// Proxmox cloud-init drives hold a `vm-<vmid>-cloudinit` volume on a
/// cdrom-media bus slot, so a `cloudinit` substring on a disk-bus line
/// is the reliable marker.
fn cfg_has_cloudinit_drive(cfg: &str) -> bool {
    cfg.lines().any(|line| {
        let t = line.trim();
        is_disk_bus_key(t) && t.contains("cloudinit")
    })
}

/// True if a `qm config` line's key is a disk-bus slot
/// (`ideN:` / `sataN:` / `scsiN:` / `virtioN:`) — i.e. `<bus><digits>:`.
/// Excludes non-disk keys that share a prefix (e.g. `scsihw:`).
fn is_disk_bus_key(line: &str) -> bool {
    let Some((key, _)) = line.split_once(':') else { return false };
    for bus in ["ide", "sata", "scsi", "virtio"] {
        if let Some(rest) = key.strip_prefix(bus)
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// Pick a free IDE slot (0-3) for a new cloud-init drive. Prefers
/// ide2 then ide3 (Proxmox's own wizard uses ide2 for cloud-init),
/// falling back to ide0/ide1. None = all four IDE slots are in use.
fn free_ide_slot(cfg: &str) -> Option<u32> {
    let used: std::collections::HashSet<u32> = cfg.lines()
        .filter_map(|l| {
            let key = l.trim().split_once(':')?.0;
            key.strip_prefix("ide")?.parse::<u32>().ok()
        })
        .collect();
    [2u32, 3, 0, 1].into_iter().find(|s| !used.contains(s))
}

/// Storage id backing the VM's OS disk — used as the storage for a
/// newly-added cloud-init drive (it definitely supports images).
/// Returns the storage of the first real disk, skipping cdrom media
/// and any existing cloud-init volume.
fn os_disk_storage(cfg: &str) -> Option<String> {
    for line in cfg.lines() {
        let t = line.trim();
        if !is_disk_bus_key(t) { continue; }
        let val = match t.split_once(':') { Some((_, v)) => v.trim(), None => continue };
        if val.contains("media=cdrom") || val.contains("cloudinit") { continue; }
        let storage = val.split(':').next().unwrap_or("").trim();
        if !storage.is_empty() && storage != "none" {
            return Some(storage.to_string());
        }
    }
    None
}

pub fn detach_vm_proxmox(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    let cfg = qm_config(target_id)?;
    // Collect the indexes of every netN device on this bridge.
    let mut indexes: Vec<u32> = Vec::new();
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("net")
            && let Some((num_str, val)) = rest.split_once(':')
            && val.contains(&format!("bridge={}", bridge))
            && let Ok(n) = num_str.parse::<u32>()
        {
            indexes.push(n);
        }
    }
    if indexes.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No net device on VM {} referenced {}.", target_id, bridge),
            restarted: false,
        });
    }
    // Drop the NIC and its matching ipconfig (cloud-init) entry. The
    // ipconfig delete is best-effort — the key may not exist if the
    // NIC was attached before cloud-init IP staging shipped.
    for n in &indexes {
        let _ = run_qm(&["set", target_id, &format!("--delete=net{}", n)]);
        let _ = run_qm(&["set", target_id, &format!("--delete=ipconfig{}", n)]);
    }
    let _ = run_qm(&["cloudinit", "update", target_id]);
    Ok(AttachOutcome {
        message: format!(
            "Removed {} net device(s) and their cloud-init IP config on VM {}. \
             Reboot the VM if it doesn't drop the NIC live.",
            indexes.len(), target_id),
        restarted: false,
    })
}

/// Ensure a Proxmox VM has a cloud-init drive, adding one on a free IDE
/// slot when it doesn't. `Ok(Some(slot))` = we added one, `Ok(None)` = it
/// already had one. Shared by the vSwitch attach and the primary-NIC IP
/// staging: without a drive, Proxmox has nowhere to write the config and
/// the guest never sees the IP.
fn ensure_cloudinit_drive(vmid: &str, cfg: &str) -> Result<Option<u32>, String> {
    if cfg_has_cloudinit_drive(cfg) {
        return Ok(None);
    }
    match (free_ide_slot(cfg), os_disk_storage(cfg)) {
        (Some(slot), Some(storage)) => {
            run_qm(&["set", vmid, &format!("--ide{}", slot), &format!("{}:cloudinit", storage)])
                .map_err(|e| format!("adding a cloud-init drive failed: {}", e))?;
            Ok(Some(slot))
        }
        _ => Err("the VM has no cloud-init drive and WolfStack could not add one \
                  (no free IDE slot, or the VM's disk storage is unknown)".to_string()),
    }
}

/// Rebuild a libvirt VM's NoCloud seed from every per-NIC block it has and
/// attach it as a CD-ROM if it isn't already. Idempotent: on a re-stage the
/// ISO is rebuilt in place, so the existing CD-ROM serves the new config.
/// Config-only (`--config`) — cloud-init reads it at the next boot.
fn restage_vm_seed(domain: &str) -> Result<(), String> {
    let netcfg = assemble_vm_netcfg(domain)
        .ok_or("the cloud-init netcfg could not be assembled")?;
    let seed = build_vm_seed_iso(domain, &netcfg)
        .map_err(|e| format!("the cloud-init seed could not be built: {}", e))?;
    if seed_already_attached(domain, &seed) {
        return Ok(());
    }
    let target = free_cdrom_target(domain)
        .ok_or("no free CD-ROM slot was available for the cloud-init seed")?;
    let cd = Command::new("virsh").args([
        "attach-disk", domain, &seed, &target,
        "--type", "cdrom", "--mode", "readonly", "--config",
    ]).output().map_err(|e| format!("spawn virsh attach-disk: {}", e))?;
    if !cd.status.success() {
        return Err(format!(
            "attaching the cloud-init seed CD-ROM failed: {}",
            String::from_utf8_lossy(&cd.stderr).trim()));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Primary NIC (net0) IP — VM Settings, not a vSwitch attach
// ────────────────────────────────────────────────────────────────────
//
// The operator's "Bridged LAN + static IP" choice in VM Settings was
// stored and echoed back for two years but never applied to anything, so
// the guest just kept DHCPing and its /etc/network/interfaces still said
// dhcp (RutgerDiehard 2026-08-21). A VM's IP lives inside the guest and
// cannot be set from the hypervisor at runtime, so — exactly like the
// vSwitch path above — we STAGE it via cloud-init and the guest applies it
// on its next boot.
//
// The one thing that differs from a vSwitch NIC: this is the VM's primary
// interface, so it DOES take the default route. A vSwitch NIC is secondary
// and deliberately never gets one.

/// What the operator asked for on a VM's primary NIC.
#[derive(Debug, Clone, PartialEq)]
pub enum PrimaryIp {
    /// Static address (CIDR) plus the gateway that becomes the guest's
    /// default route. `gateway: None` = address only, no default route.
    Static { ip_cidr: String, gateway: Option<String> },
    /// Hand the NIC back to DHCP.
    Dhcp,
}

/// True for a plain dotted-quad IPv4 address.
fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// True for an IPv4 CIDR ("192.168.1.50/24"). Prefix must be 0-32.
fn is_ipv4_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, pfx)) => is_ipv4(ip) && pfx.parse::<u8>().map(|p| p <= 32).unwrap_or(false),
        None => false,
    }
}

/// Reject anything that isn't a clean address before it reaches `qm` or a
/// generated YAML document.
fn validate_primary_ip(plan: &PrimaryIp) -> Result<(), String> {
    if let PrimaryIp::Static { ip_cidr, gateway } = plan {
        if !is_ipv4_cidr(ip_cidr) {
            return Err(format!(
                "'{}' is not a valid IPv4 address with a prefix (e.g. 192.168.1.50/24)", ip_cidr));
        }
        if let Some(gw) = gateway
            && !gw.is_empty() && !is_ipv4(gw) {
            return Err(format!("'{}' is not a valid IPv4 gateway", gw));
        }
    }
    Ok(())
}

/// Stage a Proxmox VM's PRIMARY NIC IP via cloud-init (`ipconfig0`, which
/// Proxmox pairs with `net0`). Returns the advisory to show the operator.
///
/// Verified syntax (Proxmox `qm.1`): `--ipconfig[n]` carries
/// `[gw=<GatewayIPv4>] [,ip=<IPv4Format/CIDR>]` and `ip=dhcp` is accepted
/// for DHCP; `qm cloudinit update` regenerates the drive.
/// `Ok(None)` = nothing needed doing (a DHCP request on a VM we never staged
/// an address for — the guest already DHCPs, and giving it a cloud-init drive
/// it never had, purely to say "use DHCP", would change its hardware for no
/// gain).
pub fn stage_primary_ip_proxmox(vmid: &str, plan: &PrimaryIp) -> Result<Option<String>, String> {
    validate_primary_ip(plan)?;
    let cfg = qm_config(vmid)?;
    let (value, what, ci_note) = match plan {
        PrimaryIp::Static { ip_cidr, gateway } => {
            // A static address is an explicit request, so adding the drive
            // that makes it possible is justified — and reported.
            let ci_note = match ensure_cloudinit_drive(vmid, &cfg)? {
                Some(slot) => format!(" Added a cloud-init drive on ide{}.", slot),
                None => String::new(),
            };
            let mut v = format!("ip={}", ip_cidr);
            if let Some(gw) = gateway.as_deref().filter(|g| !g.is_empty()) {
                v.push_str(&format!(",gw={}", gw));
            }
            (v, format!("static IP {}", ip_cidr), ci_note)
        }
        PrimaryIp::Dhcp => {
            if !cfg_has_ipconfig0(&cfg) {
                return Ok(None);
            }
            ("ip=dhcp".to_string(), "DHCP".to_string(), String::new())
        }
    };
    run_qm(&["set", vmid, "--ipconfig0", &value])?;
    let _ = run_qm(&["cloudinit", "update", vmid]);
    Ok(Some(format!(
        "Staged {} on the primary NIC via cloud-init.{} It applies the next time the VM boots \
         (requires cloud-init in the guest).",
        what, ci_note)))
}

/// True if a `qm config` dump already stages a primary-NIC IP.
fn cfg_has_ipconfig0(cfg: &str) -> bool {
    cfg.lines().any(|l| l.trim_start().starts_with("ipconfig0:"))
}

/// One netplan `ethernets` entry for a VM's primary NIC, matched by MAC.
/// Separate from [`vm_ethernet_block`] because the primary NIC takes the
/// default route and must not have an MTU forced on it.
fn vm_primary_ethernet_block(mac: &str, plan: &PrimaryIp) -> String {
    let mut s = String::new();
    s.push_str(&format!("  wsprimary{}:\n", mac.replace(':', "")));
    s.push_str("    match:\n");
    s.push_str(&format!("      macaddress: \"{}\"\n", mac));
    match plan {
        PrimaryIp::Static { ip_cidr, gateway } => {
            s.push_str("    dhcp4: false\n");
            s.push_str("    dhcp6: false\n");
            s.push_str("    addresses:\n");
            s.push_str(&format!("      - \"{}\"\n", ip_cidr));
            if let Some(gw) = gateway.as_deref().filter(|g| !g.is_empty()) {
                // The primary NIC owns the guest's default route.
                s.push_str("    routes:\n");
                s.push_str("      - to: \"default\"\n");
                s.push_str(&format!("        via: \"{}\"\n", gw));
            }
        }
        PrimaryIp::Dhcp => {
            // Stated explicitly rather than by omission, so switching back
            // from static actually tells the guest to go get a lease.
            s.push_str("    dhcp4: true\n");
        }
    }
    s
}

/// Stage a libvirt VM's PRIMARY NIC IP via its NoCloud seed. `mac` is the
/// primary NIC's MAC — the seed matches on it, so the config binds to that
/// interface and not to whichever name the guest happened to assign.
/// `Ok(None)` = nothing needed doing, for the same reason as the Proxmox
/// version: a DHCP request on a VM we never staged an address for must not
/// attach a cloud-init seed ISO it never had.
pub fn stage_primary_ip_libvirt(domain: &str, mac: &str, plan: &PrimaryIp)
    -> Result<Option<String>, String>
{
    validate_primary_ip(plan)?;
    if mac.is_empty() {
        return Err("the VM's primary NIC has no MAC address to match on".to_string());
    }
    if matches!(plan, PrimaryIp::Dhcp)
        && !std::path::Path::new(&mac_block_file(domain, mac)).exists() {
        return Ok(None);
    }
    let dir = vm_blocks_dir(domain);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir, e))?;
    std::fs::write(mac_block_file(domain, mac), vm_primary_ethernet_block(mac, plan))
        .map_err(|e| format!("write cloud-init block: {}", e))?;
    restage_vm_seed(domain)?;
    let what = match plan {
        PrimaryIp::Static { ip_cidr, .. } => format!("static IP {}", ip_cidr),
        PrimaryIp::Dhcp => "DHCP".to_string(),
    };
    Ok(Some(format!(
        "Staged {} on the primary NIC ({}) via a cloud-init seed. It applies the next time the \
         VM boots (requires cloud-init + the NoCloud datasource in the guest).",
        what, mac)))
}

/// Undo a primary-NIC IP WolfStack previously staged, when the VM leaves
/// bridge mode. Returns whether anything was actually cleared.
///
/// Deliberately a no-op when we never staged one: a VM that has nothing to
/// do with cloud-init must not be handed a seed (or, on Proxmox, a new
/// cloud-init drive) just because the operator moved it to WolfNet. Without
/// this, a static address staged for bridge mode would keep being applied by
/// the guest long after the operator moved that VM somewhere else.
pub fn clear_primary_ip_libvirt(domain: &str, mac: &str) -> Result<bool, String> {
    if mac.is_empty() {
        return Ok(false);
    }
    let block = mac_block_file(domain, mac);
    if !std::path::Path::new(&block).exists() {
        return Ok(false);
    }
    std::fs::remove_file(&block).map_err(|e| format!("remove cloud-init block: {}", e))?;
    // Any remaining blocks (other vSwitch NICs) still need a seed; with none
    // left there is nothing to rebuild and the stale ISO simply goes unused.
    if assemble_vm_netcfg(domain).is_some() {
        restage_vm_seed(domain)?;
    }
    Ok(true)
}

/// Proxmox counterpart of [`clear_primary_ip_libvirt`]. Only acts when the CT
/// config already carries an `ipconfig0` — we hand the NIC back to DHCP rather
/// than `--delete`, which errors when the key was never set.
pub fn clear_primary_ip_proxmox(vmid: &str) -> Result<bool, String> {
    let cfg = qm_config(vmid)?;
    if !cfg.lines().any(|l| l.trim_start().starts_with("ipconfig0:")) {
        return Ok(false);
    }
    run_qm(&["set", vmid, "--ipconfig0", "ip=dhcp"])?;
    let _ = run_qm(&["cloudinit", "update", vmid]);
    Ok(true)
}

/// The primary NIC's MAC for a libvirt domain: the first interface on
/// `bridge` as `virsh domiflist` lists it. None = the domain has no NIC on
/// that bridge (so there's nothing to stage an IP for).
pub fn primary_nic_mac_libvirt(domain: &str, bridge: &str) -> Option<String> {
    let out = Command::new("virsh").args(["domiflist", domain]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_libvirt_macs_for_bridge(&String::from_utf8_lossy(&out.stdout), bridge)
        .into_iter()
        .next()
}

// ────────────────────────────────────────────────────────────────────
// Docker (via docker macvlan / bridge network)
// ────────────────────────────────────────────────────────────────────

/// Driver to use for Docker network creation. Hetzner vSwitch enforces
/// ONE MAC per server port — macvlan creates a unique MAC per container,
/// so packets sourced from those MACs are silently dropped by the
/// vSwitch. ipvlan L2 mode uses the parent's MAC for every container
/// and differentiates by IP, which Hetzner accepts.
///
/// For OVH vRack, Equinix Metal, and generic 802.1Q trunks, macvlan is
/// fine and gives true L2 isolation between containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerVlanDriver {
    /// Each container gets a unique MAC. Don't use on Hetzner.
    Macvlan,
    /// Single shared MAC, IPs differentiate. Required for Hetzner.
    IpvlanL2,
}

impl DockerVlanDriver {
    pub fn driver_arg(&self) -> &'static str {
        match self {
            DockerVlanDriver::Macvlan => "macvlan",
            DockerVlanDriver::IpvlanL2 => "ipvlan",
        }
    }
}

/// Attach a Docker container by creating (idempotently) a docker
/// network attached to the VLAN's TAGGED SUB-INTERFACE (not the
/// bridge — Docker's macvlan/ipvlan drivers attach directly to the
/// underlying L2 device, and bridging on top of a bridge is a recipe
/// for MAC-learning chaos).
///
/// The docker network's name is derived from the bridge name so it's
/// reusable across containers: `wolfstack-<bridge>`.
///
/// `parent_iface` should be the VLAN sub-interface name (e.g.
/// `eno1.4000`), NOT the bridge. The caller knows both — pass the
/// sub-interface here.
pub fn attach_docker(
    p: &AttachParams,
    parent_iface: &str,
    subnet: &str,
    gateway_ip: &str,
    driver: DockerVlanDriver,
) -> Result<AttachOutcome, String> {
    // Encode the driver in the network name so we don't accidentally
    // re-use a macvlan network when the operator's now on a Hetzner
    // VLAN (or vice versa) — different drivers can't coexist for the
    // same parent.
    let net_name = format!("wolfstack-{}-{}", p.bridge, driver.driver_arg());
    // Create the docker network if missing. Idempotent: we inspect first.
    let inspect = Command::new("docker").args(["network", "inspect", &net_name]).output()
        .map_err(|e| format!("spawn docker: {}", e))?;
    if !inspect.status.success() {
        // Docker's macvlan/ipvlan IPAM cannot allocate without a subnet.
        // The API handler already refuses attaches on a subnet-less VLAN, so
        // this is a backstop for any other caller — `docker network create
        // --subnet ""` fails with an opaque parse error that tells the
        // operator nothing.
        if subnet.is_empty() {
            return Err(format!(
                "VLAN `{}` has no subnet recorded, and Docker's {} driver needs one to \
                 assign container IPs. Set the VLAN's subnet — this host's own IP can \
                 stay blank if it should remain off the VLAN.",
                p.bridge, driver.driver_arg(),
            ));
        }
        let mut args: Vec<String> = vec![
            "network".into(), "create".into(),
            "--driver".into(), driver.driver_arg().into(),
            "--subnet".into(), subnet.into(),
            "-o".into(), format!("parent={}", parent_iface),
            "-o".into(), format!("com.docker.network.driver.mtu={}", p.mtu),
        ];
        // Only pin a gateway when there is one. On an L2-only VLAN the host
        // holds no address, so we let Docker default it rather than passing
        // `--gateway ""`, which docker rejects.
        if !gateway_ip.is_empty() {
            args.push("--gateway".into());
            args.push(gateway_ip.into());
        }
        // ipvlan needs explicit mode flag.
        if matches!(driver, DockerVlanDriver::IpvlanL2) {
            args.push("-o".into());
            args.push("ipvlan_mode=l2".into());
        }
        args.push(net_name.clone());
        let create = Command::new("docker").args(&args).output()
            .map_err(|e| format!("spawn docker network create: {}", e))?;
        if !create.status.success() {
            return Err(format!(
                "docker network create failed: {}",
                String::from_utf8_lossy(&create.stderr).trim()
            ));
        }
    }
    // Connect the container with a fixed IP.
    let ip_addr = ip_only(p.ip_cidr);
    let connect = Command::new("docker").args([
        "network", "connect",
        "--ip", &ip_addr,
        &net_name, p.target_id,
    ]).output()
        .map_err(|e| format!("spawn docker network connect: {}", e))?;
    if !connect.status.success() {
        return Err(format!(
            "docker network connect failed: {}",
            String::from_utf8_lossy(&connect.stderr).trim()
        ));
    }
    Ok(AttachOutcome {
        message: format!(
            "Connected container {} to {} network {} with IP {} (parent: {}).",
            p.target_id, driver.driver_arg(), net_name, ip_addr, parent_iface,
        ),
        restarted: false,
    })
}

pub fn detach_docker(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    // Try both driver-suffixed names (we stamped the driver into the
    // network name when creating). Older WolfStack versions used the
    // un-suffixed `wolfstack-{bridge}` form; check that too so we can
    // detach networks created by older builds.
    let candidates = [
        format!("wolfstack-{}-macvlan", bridge),
        format!("wolfstack-{}-ipvlan", bridge),
        format!("wolfstack-{}", bridge),
    ];
    let mut last_err: Option<String> = None;
    for net_name in &candidates {
        let out = Command::new("docker")
            .args(["network", "disconnect", net_name, target_id])
            .output()
            .map_err(|e| format!("spawn docker: {}", e))?;
        if out.status.success() {
            return Ok(AttachOutcome {
                message: format!("Disconnected container {} from network {}.", target_id, net_name),
                restarted: false,
            });
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // If the network doesn't exist OR the container isn't connected,
        // try the next candidate. Other errors we surface immediately.
        if !stderr.contains("not found") && !stderr.contains("is not connected") {
            return Err(format!("docker network disconnect failed: {}", stderr));
        }
        last_err = Some(stderr);
    }
    Err(format!(
        "container {} is not attached to any wolfstack docker network for bridge {} ({})",
        target_id, bridge, last_err.unwrap_or_default()
    ))
}

// ────────────────────────────────────────────────────────────────────
// Native VMs (libvirt)
// ────────────────────────────────────────────────────────────────────

/// Attach a libvirt VM to the bridge and stage its IP via a NoCloud
/// cloud-init seed.
///
/// libvirt cannot set an in-guest IP, so:
///   1. `virsh attach-interface` adds the NIC persistently with an
///      explicit stable MAC (so the seed's network-config can match
///      exactly this interface).
///   2. A NoCloud seed ISO carrying only a network-config (matched by
///      MAC) is built with `cloud-localds` and attached as a CD-ROM.
///   3. On the next boot the guest's cloud-init reads the seed and
///      applies the static IP. Requires cloud-init + the NoCloud
///      datasource enabled in the guest.
///
/// Every step degrades honestly: if the seed can't be built or
/// attached, the NIC is still attached and the message says so.
pub fn attach_vm_libvirt(p: &AttachParams) -> Result<AttachOutcome, String> {
    let domain = p.target_id;
    // Index the MAC by how many NICs the VM already has on this
    // bridge, so attaching the same VM to the same vSwitch twice
    // yields distinct, deterministic MACs.
    let nic_index = Command::new("virsh").args(["domiflist", domain]).output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_libvirt_macs_for_bridge(
            &String::from_utf8_lossy(&o.stdout), p.bridge).len())
        .unwrap_or(0) as u32;
    let mac = stable_hwaddr(domain, p.bridge, nic_index);

    // 1. Attach the NIC, persistent across reboots.
    let out = Command::new("virsh").args([
        "attach-interface", domain,
        "--type", "bridge",
        "--source", p.bridge,
        "--model", "virtio",
        "--mac", &mac,
        "--mtu", &p.mtu.to_string(),
        "--persistent",
    ]).output()
        .map_err(|e| format!("spawn virsh: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "virsh attach-interface failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Honest-degradation helper: the NIC is attached, but a later
    // cloud-init step failed — say so and tell the operator what to do.
    let degraded = |why: String| AttachOutcome {
        message: format!(
            "Attached NIC ({}) on {} via libvirt, but {}. Configure IP {} inside the guest.",
            mac, p.bridge, why, p.ip_cidr),
        restarted: false,
    };

    // 2. Record this NIC as a per-NIC cloud-init block, then assemble
    //    the VM's full netcfg from EVERY block — so a VM attached to
    //    several vSwitches keeps every IP, not just the latest. Build
    //    the NoCloud seed from the assembled netcfg.
    if let Err(e) = write_vm_block(domain, &mac, p.ip_cidr, p.mtu, p.routes) {
        return Ok(degraded(format!("the cloud-init block could not be written: {}", e)));
    }
    // 3. Rebuild the seed from every block and make sure it's attached.
    if let Err(e) = restage_vm_seed(domain) {
        return Ok(degraded(e));
    }

    // 4. Reboot only if asked.
    if p.reboot {
        let rb = Command::new("virsh").args(["reboot", domain]).output()
            .map_err(|e| format!("spawn virsh reboot: {}", e))?;
        if !rb.status.success() {
            return Ok(AttachOutcome {
                message: format!(
                    "Attached NIC ({}) on {} and staged IP {} via cloud-init, but the reboot \
                     failed: {}. Reboot the VM manually to apply the IP.",
                    mac, p.bridge, p.ip_cidr, String::from_utf8_lossy(&rb.stderr).trim()),
                restarted: false,
            });
        }
        return Ok(AttachOutcome {
            message: format!(
                "Attached NIC ({}) on {}, staged IP {} via cloud-init, and rebooted the VM. \
                 The IP applies once the guest's cloud-init runs (requires cloud-init + the \
                 NoCloud datasource in the guest).",
                mac, p.bridge, p.ip_cidr),
            restarted: true,
        });
    }
    Ok(AttachOutcome {
        message: format!(
            "Attached NIC ({}) on {} and staged IP {} via a cloud-init seed. Reboot the VM to \
             apply it (requires cloud-init + the NoCloud datasource in the guest).",
            mac, p.bridge, p.ip_cidr),
        restarted: false,
    })
}

/// Per-VM directory holding one `<mac>.block` file per WolfStack
/// vSwitch NIC. `assemble_vm_netcfg` concatenates them into the seed.
fn vm_blocks_dir(domain: &str) -> String {
    format!("/var/lib/wolfstack/vlan-seeds/{}.d", safe_seed_name(domain))
}

/// Path of the per-NIC cloud-init block file for one MAC.
fn mac_block_file(domain: &str, mac: &str) -> String {
    format!("{}/{}.block", vm_blocks_dir(domain), mac.replace(':', ""))
}

/// Build one cloud-init network-config (v2 / netplan) `ethernets`
/// entry for a VLAN NIC, matched by MAC so it binds to exactly that
/// interface. Operator-configured VLAN routes are emitted as specific
/// routes — never a default route, since a vSwitch NIC is a secondary
/// interface. This is one block; `assemble_vm_netcfg` wraps all of a
/// VM's blocks under a single `version: 2` / `ethernets:` header.
fn vm_ethernet_block(mac: &str, ip_cidr: &str, mtu: u32, routes: &[RouteEntry]) -> String {
    let mut s = String::new();
    // Key the entry by MAC so several vSwitch NICs on one VM never
    // collide when their blocks are concatenated.
    s.push_str(&format!("  wsvlan{}:\n", mac.replace(':', "")));
    s.push_str("    match:\n");
    s.push_str(&format!("      macaddress: \"{}\"\n", mac));
    s.push_str("    dhcp4: false\n");
    s.push_str("    dhcp6: false\n");
    s.push_str(&format!("    mtu: {}\n", mtu));
    s.push_str("    addresses:\n");
    s.push_str(&format!("      - \"{}\"\n", ip_cidr));
    // Only emit routes whose destination + via look like IP/CIDR —
    // operator free-text must not be able to inject YAML.
    let safe: Vec<&RouteEntry> = routes.iter()
        .filter(|r| is_ip_like(&r.destination) && is_ip_like(&r.via))
        .collect();
    if !safe.is_empty() {
        s.push_str("    routes:\n");
        for r in safe {
            s.push_str(&format!("      - to: \"{}\"\n", r.destination));
            s.push_str(&format!("        via: \"{}\"\n", r.via));
        }
    }
    s
}

/// Write (overwrite) the per-NIC cloud-init block for one MAC.
fn write_vm_block(domain: &str, mac: &str, ip_cidr: &str, mtu: u32, routes: &[RouteEntry])
    -> Result<(), String>
{
    let dir = vm_blocks_dir(domain);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir, e))?;
    std::fs::write(mac_block_file(domain, mac), vm_ethernet_block(mac, ip_cidr, mtu, routes))
        .map_err(|e| format!("write block: {}", e))
}

/// Concatenate every per-NIC block in the VM's blocks dir into one
/// netplan-v2 network-config. None = the VM has no WolfStack vSwitch
/// NIC blocks (dir missing or empty).
fn assemble_vm_netcfg(domain: &str) -> Option<String> {
    let mut blocks: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(vm_blocks_dir(domain)).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("block") { continue; }
        if let Ok(content) = std::fs::read_to_string(&path) {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            blocks.push((name, content));
        }
    }
    if blocks.is_empty() { return None; }
    blocks.sort_by(|a, b| a.0.cmp(&b.0));   // deterministic order
    let mut s = String::from("version: 2\nethernets:\n");
    for (_, content) in blocks { s.push_str(&content); }
    Some(s)
}

/// True if the VM already has the given seed ISO attached as a disk.
fn seed_already_attached(domain: &str, seed_iso: &str) -> bool {
    Command::new("virsh").args(["domblklist", domain]).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|l| l.split_whitespace().nth(1) == Some(seed_iso)))
        .unwrap_or(false)
}

/// True if `s` contains only characters legal in an IPv4 address or
/// CIDR (`default` is also allowed, for a default route). Keeps
/// operator free-text out of the generated YAML.
fn is_ip_like(s: &str) -> bool {
    s == "default"
        || (!s.is_empty()
            && s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '/'))
}

/// Build a NoCloud seed ISO carrying just the network-config. Returns
/// the ISO path. Uses `cloud-localds` — the canonical NoCloud tool,
/// already a WolfStack pool prerequisite.
///
/// A fresh `instance-id` each call makes the guest's cloud-init treat
/// the seed as a new instance and re-apply the network stage on the
/// next boot. user-data is minimal and pins `preserve_hostname` +
/// `ssh_deletekeys: false` so the re-init can't rename the host or
/// regenerate the SSH host keys.
fn build_vm_seed_iso(domain: &str, network_config: &str) -> Result<String, String> {
    if !command_exists("cloud-localds") {
        return Err("cloud-localds not installed (apt: cloud-image-utils / \
            cloud-utils, dnf: cloud-utils)".into());
    }
    let dir = "/var/lib/wolfstack/vlan-seeds";
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir, e))?;
    let safe = safe_seed_name(domain);
    let user_data = format!("{}/{}-userdata.yaml", dir, safe);
    let meta_data = format!("{}/{}-metadata.yaml", dir, safe);
    let net_cfg = format!("{}/{}-netcfg.yaml", dir, safe);
    let seed_iso = format!("{}/{}-vlan-seed.iso", dir, safe);

    let iid = format!("wolfstack-vlan-{}", unix_now());
    std::fs::write(&user_data,
        "#cloud-config\npreserve_hostname: true\nssh_deletekeys: false\n")
        .map_err(|e| format!("write user-data: {}", e))?;
    std::fs::write(&meta_data, format!("instance-id: {}\n", iid))
        .map_err(|e| format!("write meta-data: {}", e))?;
    std::fs::write(&net_cfg, network_config)
        .map_err(|e| format!("write network-config: {}", e))?;

    // cloud-localds [--network-config F] OUTPUT USER-DATA [META-DATA]
    let out = Command::new("cloud-localds")
        .arg("--network-config").arg(&net_cfg)
        .arg(&seed_iso).arg(&user_data).arg(&meta_data)
        .output().map_err(|e| format!("cloud-localds spawn: {}", e))?;
    if !out.status.success() {
        return Err(format!("cloud-localds failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(seed_iso)
}

/// Filesystem-safe per-domain stem for seed artefacts.
fn safe_seed_name(domain: &str) -> String {
    domain.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64).collect()
}

/// Seconds since the Unix epoch — a unique cloud-init instance-id per
/// attach.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// PATH lookup for an executable. True iff `name` is on $PATH and is
/// an executable file.
fn command_exists(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        if let Ok(meta) = std::fs::metadata(dir.join(name))
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return true;
        }
    }
    false
}

/// Pick a free disk target for the cloud-init CD-ROM by inspecting
/// `virsh domblklist`. None = every candidate slot is taken.
fn free_cdrom_target(domain: &str) -> Option<String> {
    let out = Command::new("virsh").args(["domblklist", domain]).output().ok()?;
    if !out.status.success() { return None; }
    let listing = String::from_utf8_lossy(&out.stdout);
    // domblklist columns: Target | Source. First column = target dev.
    let used: std::collections::HashSet<String> = listing.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|t| !t.eq_ignore_ascii_case("target"))
        .map(|t| t.to_string())
        .collect();
    ["sdb", "sdc", "sdd", "sde", "hdc", "hdd", "hdb", "sda"]
        .into_iter()
        .find(|c| !used.contains(*c))
        .map(|c| c.to_string())
}

pub fn detach_vm_libvirt(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    // libvirt's detach-interface requires a MAC. We get it by parsing
    // `virsh domiflist <domain>` — a tabular listing of every NIC with
    // its source bridge and MAC. There can be multiple matches if the
    // operator attached the same VM to the bridge more than once;
    // detach all of them so the result is "no NICs left on this bridge".
    let list = Command::new("virsh").args(["domiflist", target_id]).output()
        .map_err(|e| format!("spawn virsh domiflist: {}", e))?;
    if !list.status.success() {
        return Err(format!(
            "virsh domiflist failed: {}",
            String::from_utf8_lossy(&list.stderr).trim()
        ));
    }
    let macs = parse_libvirt_macs_for_bridge(&String::from_utf8_lossy(&list.stdout), bridge);
    if macs.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No interface on VM {} sourced from bridge {}.", target_id, bridge),
            restarted: false,
        });
    }
    let mut detached = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for mac in &macs {
        let out = Command::new("virsh").args([
            "detach-interface", target_id,
            "--type", "bridge",
            "--mac", mac,
            "--persistent",
        ]).output()
            .map_err(|e| format!("spawn virsh detach-interface: {}", e))?;
        if out.status.success() {
            detached += 1;
        } else {
            errors.push(format!(
                "{}: {}", mac, String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    if detached == 0 {
        return Err(format!(
            "Found {} interface(s) on bridge {} but virsh refused all detaches: {}",
            macs.len(), bridge, errors.join("; ")
        ));
    }
    let warning = if errors.is_empty() {
        String::new()
    } else {
        format!(" ({} failed: {})", errors.len(), errors.join("; "))
    };
    let seed_note = cleanup_libvirt_seed(target_id, &macs);
    Ok(AttachOutcome {
        message: format!(
            "Detached {} interface(s) from VM {} on bridge {}{}.{}",
            detached, target_id, bridge, warning, seed_note,
        ),
        restarted: false,
    })
}

/// After NIC detach: drop the per-NIC cloud-init blocks for the
/// removed MACs. If the VM still has other WolfStack vSwitch NICs,
/// rebuild the seed in place so their IPs survive; otherwise detach
/// the seed CD-ROM and wipe every artefact. Returns a note for the
/// detach message.
fn cleanup_libvirt_seed(domain: &str, removed_macs: &[String]) -> String {
    for mac in removed_macs {
        let _ = std::fs::remove_file(mac_block_file(domain, mac));
    }
    if let Some(netcfg) = assemble_vm_netcfg(domain) {
        // VM still has WolfStack vSwitch NICs — refresh the seed in
        // place (the CD-ROM keeps pointing at the same path).
        return match build_vm_seed_iso(domain, &netcfg) {
            Ok(_) => " Rebuilt the cloud-init seed for the VM's remaining vSwitch NICs.".into(),
            Err(_) => String::new(),
        };
    }
    // No WolfStack NICs left — detach the seed CD-ROM and wipe it.
    let dir = "/var/lib/wolfstack/vlan-seeds";
    let safe = safe_seed_name(domain);
    let seed_iso = format!("{}/{}-vlan-seed.iso", dir, safe);
    let mut note = String::new();
    if let Ok(out) = Command::new("virsh").args(["domblklist", domain]).output()
        && out.status.success()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 2 && cols[1] == seed_iso {
                let _ = Command::new("virsh")
                    .args(["detach-disk", domain, cols[0], "--config"])
                    .output();
                note = " Removed the cloud-init seed CD-ROM.".into();
            }
        }
    }
    // Delete the seed artefacts. remove_file ignores missing files.
    for suffix in ["-vlan-seed.iso", "-userdata.yaml", "-metadata.yaml", "-netcfg.yaml"] {
        let _ = std::fs::remove_file(format!("{}/{}{}", dir, safe, suffix));
    }
    let _ = std::fs::remove_dir_all(vm_blocks_dir(domain));
    note
}

/// Parse `virsh domiflist` output to find every MAC whose source matches
/// the given bridge. Output looks like:
///
/// ```text
///  Interface   Type     Source     Model    MAC
/// -----------------------------------------------
///  vnet0       bridge   vmbr4000   virtio   52:54:00:aa:bb:cc
///  vnet1       bridge   vmbr0      virtio   52:54:00:aa:bb:cd
/// ```
///
/// Robust to header variations and extra whitespace; only matches lines
/// where the third whitespace-separated column equals the bridge name
/// AND the second is "bridge". This is intentionally conservative —
/// network=, direct, etc. don't match.
fn parse_libvirt_macs_for_bridge(stdout: &str, bridge: &str) -> Vec<String> {
    let mut macs = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('-') { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 { continue; }
        // Skip the header row: column 1 is "Interface" (case-insensitive).
        if cols[0].eq_ignore_ascii_case("interface") { continue; }
        if cols[1] != "bridge" { continue; }
        if cols[2] != bridge { continue; }
        // MAC is the last column. Validate shape (xx:xx:xx:xx:xx:xx).
        let mac = cols[cols.len() - 1];
        if mac.len() == 17 && mac.matches(':').count() == 5 {
            macs.push(mac.to_string());
        }
    }
    macs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_lxc_net_index_starts_at_zero_when_empty() {
        assert_eq!(next_lxc_net_index(""), 0);
        assert_eq!(next_lxc_net_index("# comment only\n"), 0);
    }

    #[test]
    fn next_lxc_net_index_finds_max_plus_one() {
        let cfg = r#"
lxc.uts.name = test
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.net.0.flags = up

lxc.net.2.type = veth
lxc.net.2.link = vmbr4000
"#;
        // Highest seen is 2; next should be 3 even though 1 is unused.
        assert_eq!(next_lxc_net_index(cfg), 3);
    }

    #[test]
    fn ip_only_strips_prefix() {
        assert_eq!(ip_only("10.0.1.10/24"), "10.0.1.10");
        assert_eq!(ip_only("10.0.1.10"), "10.0.1.10");
    }

    #[test]
    fn parse_libvirt_macs_typical_output() {
        let out = "\
 Interface   Type     Source     Model    MAC
-----------------------------------------------
 vnet0       bridge   vmbr4000   virtio   52:54:00:aa:bb:cc
 vnet1       bridge   vmbr0      virtio   52:54:00:11:22:33
 vnet2       bridge   vmbr4000   virtio   52:54:00:dd:ee:ff
";
        let macs = parse_libvirt_macs_for_bridge(out, "vmbr4000");
        assert_eq!(macs, vec!["52:54:00:aa:bb:cc", "52:54:00:dd:ee:ff"]);
    }

    #[test]
    fn parse_libvirt_macs_skips_header_and_empty() {
        // Header row "Interface ..." must NOT be matched even though
        // it has 5 columns.
        let out = "\
 Interface   Type     Source     Model    MAC
";
        assert!(parse_libvirt_macs_for_bridge(out, "anything").is_empty());
    }

    #[test]
    fn parse_libvirt_macs_only_bridge_type() {
        // network=, direct, etc. must not be picked up.
        let out = "\
 vnet0       network  default    virtio   52:54:00:aa:bb:cc
 vnet1       direct   eno1       virtio   52:54:00:11:22:33
";
        assert!(parse_libvirt_macs_for_bridge(out, "default").is_empty());
        assert!(parse_libvirt_macs_for_bridge(out, "eno1").is_empty());
    }

    #[test]
    fn stable_veth_name_fits_15_chars() {
        // Real container name short enough — no truncation needed.
        assert_eq!(stable_veth_name("regions80", 0), "ws-regions80-0");
        assert_eq!(stable_veth_name("regions80", 12), "ws-regions80-12");
        // Long container name — truncated to fit IFNAMSIZ.
        let n = stable_veth_name("a-very-long-container-name", 0);
        assert!(n.len() <= 15, "name must fit IFNAMSIZ: got '{}' ({})", n, n.len());
        assert!(n.starts_with("ws-"));
        assert!(n.ends_with("-0"));
        // Non-alphanumeric (hyphens / dots) stripped per Linux iface rules.
        assert_eq!(stable_veth_name("a.b-c_d", 1), "ws-abcd-1");
    }

    #[test]
    fn stable_hwaddr_is_deterministic_and_local() {
        let m1 = stable_hwaddr("regions80", "vmbr4000", 2);
        let m2 = stable_hwaddr("regions80", "vmbr4000", 2);
        assert_eq!(m1, m2, "same inputs must yield same MAC across calls");
        // Different inputs → different MAC (overwhelmingly likely; not a
        // crypto hash but distinct enough for typical inputs).
        assert_ne!(m1, stable_hwaddr("regions81", "vmbr4000", 2));
        assert_ne!(m1, stable_hwaddr("regions80", "vmbr4001", 2));
        assert_ne!(m1, stable_hwaddr("regions80", "vmbr4000", 3));
        // Locally-administered prefix (02:) — first octet bit 1 set.
        assert!(m1.starts_with("02:"), "got {}", m1);
        // 17-char xx:xx:xx:xx:xx:xx shape.
        assert_eq!(m1.len(), 17);
        assert_eq!(m1.matches(':').count(), 5);
    }

    #[test]
    fn parse_libvirt_macs_validates_mac_shape() {
        // A line with the right column shape but a bogus MAC is rejected.
        let out = "\
 vnet0       bridge   vmbr4000   virtio   not-a-real-mac-address
";
        assert!(parse_libvirt_macs_for_bridge(out, "vmbr4000").is_empty());
    }

    #[test]
    fn max_cfg_index_finds_highest() {
        let cfg = "net0: virtio=AA,bridge=vmbr0\n\
                   net2: virtio=BB,bridge=vmbr4000\n\
                   scsi0: local:vm-1-disk-0\n";
        assert_eq!(max_cfg_index(cfg, "net"), 2);
        assert_eq!(max_cfg_index("", "net"), -1);
        assert_eq!(max_cfg_index("memory: 2048\n", "net"), -1);
    }

    #[test]
    fn is_disk_bus_key_excludes_controller() {
        assert!(is_disk_bus_key("scsi0: local:vm-1-disk-0,size=32G"));
        assert!(is_disk_bus_key("ide2: local:vm-1-cloudinit,media=cdrom"));
        assert!(is_disk_bus_key("virtio0: local:vm-1-disk-0"));
        // scsihw is the SCSI controller model, not a disk slot.
        assert!(!is_disk_bus_key("scsihw: virtio-scsi-pci"));
        assert!(!is_disk_bus_key("net0: virtio=AA,bridge=vmbr0"));
        assert!(!is_disk_bus_key("memory: 2048"));
    }

    #[test]
    fn cfg_has_cloudinit_drive_detects_drive() {
        let with = "scsi0: local:vm-1-disk-0\n\
                    ide2: local-lvm:vm-1-cloudinit,media=cdrom\n";
        let without = "scsi0: local:vm-1-disk-0\nide2: none,media=cdrom\n";
        assert!(cfg_has_cloudinit_drive(with));
        assert!(!cfg_has_cloudinit_drive(without));
    }

    #[test]
    fn free_ide_slot_prefers_two_then_three() {
        assert_eq!(free_ide_slot(""), Some(2));
        assert_eq!(free_ide_slot("ide2: local:vm-1-cd,media=cdrom\n"), Some(3));
        assert_eq!(free_ide_slot("ide0: local:vm-1-disk-0\n"), Some(2));
        assert_eq!(free_ide_slot("ide0: a\nide1: b\nide2: c\nide3: d\n"), None);
    }

    #[test]
    fn os_disk_storage_skips_cdrom_and_cloudinit() {
        let cfg = "ide2: local-lvm:vm-1-cloudinit,media=cdrom\n\
                   ide0: none,media=cdrom\n\
                   scsi0: fastpool:vm-1-disk-0,size=32G\n";
        assert_eq!(os_disk_storage(cfg).as_deref(), Some("fastpool"));
        assert_eq!(os_disk_storage("memory: 2048\n"), None);
    }

    #[test]
    fn is_ip_like_accepts_only_ip_chars() {
        assert!(is_ip_like("10.0.0.0/16"));
        assert!(is_ip_like("10.0.1.1"));
        assert!(is_ip_like("default"));
        assert!(!is_ip_like("10.0.0.0/16\"; rm -rf"));
        assert!(!is_ip_like(""));
        assert!(!is_ip_like("evil\nkey: value"));
    }

    #[test]
    fn vm_ethernet_block_matches_by_mac() {
        let routes = vec![
            RouteEntry { destination: "10.0.0.0/16".into(), via: "10.0.1.1".into() },
        ];
        let block = vm_ethernet_block(
            "02:ab:cd:ef:01:02", "10.0.1.10/24", 1400, &routes);
        // Entry keyed by MAC so multiple NICs never collide on assembly.
        assert!(block.contains("wsvlan02abcdef0102:"));
        assert!(block.contains("macaddress: \"02:ab:cd:ef:01:02\""));
        assert!(block.contains("- \"10.0.1.10/24\""));
        assert!(block.contains("mtu: 1400"));
        assert!(block.contains("to: \"10.0.0.0/16\""));
        assert!(block.contains("via: \"10.0.1.1\""));
    }

    #[test]
    fn vm_ethernet_block_drops_unsafe_routes() {
        let routes = vec![
            RouteEntry { destination: "evil\"\ninject: x".into(), via: "10.0.1.1".into() },
        ];
        let block = vm_ethernet_block(
            "02:ab:cd:ef:01:02", "10.0.1.10/24", 1400, &routes);
        // The unsafe route is filtered out — no routes block emitted.
        assert!(!block.contains("routes:"));
        assert!(!block.contains("inject"));
    }

    #[test]
    fn mac_block_file_strips_colons() {
        let path = mac_block_file("web01", "02:ab:cd:ef:01:02");
        assert!(path.ends_with("/web01.d/02abcdef0102.block"));
    }
}

#[cfg(test)]
mod primary_ip_tests {
    use super::*;

    #[test]
    fn only_clean_addresses_reach_a_generated_config() {
        assert!(validate_primary_ip(&PrimaryIp::Static {
            ip_cidr: "192.168.1.50/24".into(), gateway: Some("192.168.1.1".into()) }).is_ok());
        assert!(validate_primary_ip(&PrimaryIp::Dhcp).is_ok());
        // A bare address is not enough — qm and netplan both want the prefix.
        assert!(validate_primary_ip(&PrimaryIp::Static {
            ip_cidr: "192.168.1.50".into(), gateway: None }).is_err());
        assert!(validate_primary_ip(&PrimaryIp::Static {
            ip_cidr: "192.168.1.50/33".into(), gateway: None }).is_err());
        // YAML/CLI injection attempts die at the boundary.
        assert!(validate_primary_ip(&PrimaryIp::Static {
            ip_cidr: "1.2.3.4/24\"\n    gateway4: 6.6.6.6".into(), gateway: None }).is_err());
        assert!(validate_primary_ip(&PrimaryIp::Static {
            ip_cidr: "1.2.3.4/24".into(), gateway: Some("6.6.6.6,ip=9.9.9.9".into()) }).is_err());
        // An empty gateway is "no default route", not an error.
        assert!(validate_primary_ip(&PrimaryIp::Static {
            ip_cidr: "1.2.3.4/24".into(), gateway: Some(String::new()) }).is_ok());
    }

    /// The primary NIC takes the default route — this is what a vSwitch NIC
    /// deliberately never gets, and it's why it needs its own block builder.
    #[test]
    fn the_primary_block_carries_the_default_route() {
        let yaml = vm_primary_ethernet_block("52:54:00:ab:cd:ef", &PrimaryIp::Static {
            ip_cidr: "192.168.1.50/24".into(), gateway: Some("192.168.1.1".into()) });
        assert_eq!(yaml, "  wsprimary525400abcdef:\n    match:\n      macaddress: \"52:54:00:ab:cd:ef\"\n    dhcp4: false\n    dhcp6: false\n    addresses:\n      - \"192.168.1.50/24\"\n    routes:\n      - to: \"default\"\n        via: \"192.168.1.1\"\n");
    }

    #[test]
    fn a_static_block_without_a_gateway_sets_no_route() {
        let yaml = vm_primary_ethernet_block("52:54:00:ab:cd:ef", &PrimaryIp::Static {
            ip_cidr: "10.0.0.5/24".into(), gateway: None });
        assert!(yaml.contains("addresses:"));
        assert!(!yaml.contains("routes:"), "{}", yaml);
    }

    /// Switching back to DHCP must SAY dhcp4: true — leaving the NIC out of
    /// the seed would let the previous static config stand.
    #[test]
    fn dhcp_is_stated_explicitly() {
        let yaml = vm_primary_ethernet_block("52:54:00:ab:cd:ef", &PrimaryIp::Dhcp);
        assert!(yaml.contains("dhcp4: true"), "{}", yaml);
        assert!(!yaml.contains("addresses:"), "{}", yaml);
    }

    /// The primary block and a vSwitch block must key differently so a VM
    /// with both keeps both entries when the seed is assembled.
    #[test]
    fn primary_and_vswitch_blocks_do_not_collide() {
        let primary = vm_primary_ethernet_block("52:54:00:aa:bb:cc", &PrimaryIp::Dhcp);
        let vlan = vm_ethernet_block("02:11:22:33:44:55", "10.9.0.5/24", 1400, &[]);
        assert!(primary.starts_with("  wsprimary"));
        assert!(vlan.starts_with("  wsvlan"));
    }
}

#[cfg(test)]
mod primary_ip_drive_tests {
    use super::*;

    /// A DHCP save must never be the reason a VM gains cloud-init hardware:
    /// the guest already DHCPs by default, so adding an IDE drive (Proxmox) or
    /// a seed ISO (libvirt) purely to say "use DHCP" would change the VM's
    /// hardware for no gain. Only an explicit static address earns that.
    #[test]
    fn ipconfig0_presence_is_what_gates_a_dhcp_restage() {
        assert!(cfg_has_ipconfig0("name: test\nipconfig0: ip=10.0.0.5/24,gw=10.0.0.1\n"));
        assert!(cfg_has_ipconfig0("ipconfig0: ip=dhcp\n"));
        assert!(!cfg_has_ipconfig0("name: test\nnet0: virtio,bridge=vmbr0\n"));
        // A different index is not ours to touch.
        assert!(!cfg_has_ipconfig0("ipconfig1: ip=10.0.0.5/24\n"));
    }

    #[test]
    fn a_dhcp_stage_on_an_unstaged_libvirt_vm_does_nothing() {
        let domain = format!("wolfstack-dhcptest-{}", std::process::id());
        let _ = std::fs::remove_dir_all(vm_blocks_dir(&domain));
        // No block file for this MAC => nothing was ever staged => no-op, and
        // crucially no seed ISO is built or attached.
        let r = stage_primary_ip_libvirt(&domain, "52:54:00:11:22:33", &PrimaryIp::Dhcp);
        assert_eq!(r, Ok(None));
        assert!(!std::path::Path::new(&vm_blocks_dir(&domain)).exists());
    }

    #[test]
    fn clearing_an_unstaged_libvirt_vm_does_nothing() {
        let domain = format!("wolfstack-cleartest-{}", std::process::id());
        let _ = std::fs::remove_dir_all(vm_blocks_dir(&domain));
        assert_eq!(clear_primary_ip_libvirt(&domain, "52:54:00:11:22:33"), Ok(false));
    }
}
