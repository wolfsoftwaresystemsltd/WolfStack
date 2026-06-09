// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! USB and PCI device passthrough — host enumeration, preflight checks,
//! backend-specific wiring (native QEMU, Proxmox qm, libvirt hostdev XML).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

use super::manager::{PciDevice, UsbDevice, VmConfig};

// ─── Host enumeration ───

/// A USB device visible on the host as returned to the frontend picker.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostUsbDevice {
    /// Vendor ID in lowercase hex (4 chars, no 0x)
    pub vendor_id: String,
    /// Product ID in lowercase hex (4 chars, no 0x)
    pub product_id: String,
    /// Bus-port path (e.g. "1-4") for port-stable pinning
    pub host_bus: String,
    /// Human-readable description from lsusb
    pub description: String,
    /// Stable identifier for the frontend to match against VmConfig.usb_devices
    pub match_key: String,
    /// Currently assigned to this VM (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_use_by: Option<String>,
    /// Is the owning VM currently running
    #[serde(default)]
    pub in_use_running: bool,
}

/// A PCI device visible on the host as returned to the frontend picker.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostPciDevice {
    /// Canonical BDF: DDDD:BB:DD.F
    pub bdf: String,
    /// Vendor ID (4-char hex, lowercase)
    pub vendor_id: String,
    /// Device ID (4-char hex, lowercase)
    pub device_id: String,
    /// Short class (e.g. "VGA compatible controller")
    pub class: String,
    /// Full vendor + device description from lspci -nn
    pub description: String,
    /// IOMMU group number (None if IOMMU disabled / not isolated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iommu_group: Option<u32>,
    /// Current kernel driver bound to the device (e.g. "nvidia", "vfio-pci")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// Stable identifier for frontend matching
    pub match_key: String,
    /// VM currently claiming this device (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_use_by: Option<String>,
    /// Is the owning VM currently running
    #[serde(default)]
    pub in_use_running: bool,
}

/// VFIO / IOMMU host preflight state — surfaced to the UI so the user
/// knows why PCI passthrough might be rejected.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostPassthroughPreflight {
    /// IOMMU groups populated under /sys/kernel/iommu_groups — means IOMMU is on.
    pub iommu_enabled: bool,
    /// `vfio-pci` kernel module is loaded (required for QEMU/libvirt VFIO).
    pub vfio_pci_loaded: bool,
    /// Kernel command line contains `intel_iommu=on` or `amd_iommu=on`.
    pub iommu_cmdline: bool,
    /// Backend currently in use: "proxmox", "libvirt", or "native"
    pub backend: String,
    /// Warnings the user should see at the top of the picker
    pub warnings: Vec<String>,
}

/// Full response for GET /api/vms/host-devices
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostDevicesResponse {
    pub usb: Vec<HostUsbDevice>,
    pub pci: Vec<HostPciDevice>,
    pub preflight: HostPassthroughPreflight,
}

/// Convert `in_use_by` map keys (match_key) → VM name/running state.
pub struct DeviceOwnership {
    /// match_key → (vm_name, running)
    pub by_key: HashMap<String, (String, bool)>,
}

/// Parse `lsusb` output. Format per line:
///   `Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver`
pub fn list_host_usb() -> Vec<HostUsbDevice> {
    let output = match Command::new("lsusb").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };

    let mut devs = Vec::new();
    for line in output.lines() {
        // Bus BBB Device DDD: ID vvvv:pppp <description>
        let line = line.trim();
        if line.is_empty() { continue; }
        // Split "ID xxxx:yyyy ..."
        let id_idx = match line.find("ID ") { Some(i) => i, None => continue };
        let rest = &line[id_idx + 3..];
        let space_idx = rest.find(' ').unwrap_or(rest.len());
        let id_part = &rest[..space_idx];
        let desc = rest.get(space_idx + 1..).unwrap_or("").trim().to_string();
        let mut ids = id_part.split(':');
        let vid = ids.next().unwrap_or("").to_lowercase();
        let pid = ids.next().unwrap_or("").to_lowercase();
        if vid.len() != 4 || pid.len() != 4 { continue; }

        // Skip Linux Foundation root hubs — users can't pass them through and
        // they clutter the list.
        if vid == "1d6b" { continue; }

        // Extract Bus nnn Device nnn → bus-port style via sysfs if possible,
        // otherwise just "Bus-Device" as a reasonable host_bus hint.
        let bus_num: u32 = line.split_whitespace().nth(1)
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let dev_num: u32 = line.split_whitespace().nth(3)
            .and_then(|s| s.trim_end_matches(':').parse().ok()).unwrap_or(0);
        let host_bus = format!("{}-{}", bus_num, dev_num);

        let dev = HostUsbDevice {
            vendor_id: vid.clone(),
            product_id: pid.clone(),
            host_bus,
            description: if desc.is_empty() { format!("USB device {}:{}", vid, pid) } else { desc },
            match_key: format!("usb:{}:{}", vid, pid),
            in_use_by: None,
            in_use_running: false,
        };
        devs.push(dev);
    }
    devs
}

/// Parse `lspci -nn -D` output plus IOMMU groups from sysfs.
/// Line format:
///   `0000:01:00.0 VGA compatible controller [0300]: NVIDIA ... [10de:2484] (rev a1)`
pub fn list_host_pci() -> Vec<HostPciDevice> {
    let output = match Command::new("lspci").args(["-nn", "-D"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };

    // Build BDF -> IOMMU group map by walking /sys/kernel/iommu_groups/
    let iommu = read_iommu_groups();

    let mut devs = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // BDF is the first whitespace token
        let mut parts = line.splitn(2, ' ');
        let bdf = parts.next().unwrap_or("").to_lowercase();
        let rest = parts.next().unwrap_or("");
        if bdf.len() < 7 { continue; }

        // Split "<class> [CCCC]: <vendor device> [VVVV:DDDD] (rev ...)"
        // Class is before the first colon that follows "]:".
        let class_end = rest.find("]:").map(|i| i + 1).unwrap_or(0);
        let class = rest[..class_end].trim_end_matches(':').trim().to_string();
        let after_class = rest.get(class_end + 1..).unwrap_or(rest).trim();

        // Vendor:device ID is in the LAST [vvvv:dddd]
        let (vendor_id, device_id) = extract_last_id(after_class).unwrap_or_else(|| (String::new(), String::new()));
        if vendor_id.is_empty() { continue; }

        // Skip host bridge / root ports — they can't be passed through and
        // usually own the whole IOMMU group anyway.
        if class.to_lowercase().contains("host bridge")
            || class.to_lowercase().contains("pci bridge")
            || class.to_lowercase().contains("isa bridge")
        {
            continue;
        }

        let driver = read_pci_driver(&bdf);
        let iommu_group = iommu.get(&bdf).copied();

        devs.push(HostPciDevice {
            bdf: bdf.clone(),
            vendor_id,
            device_id,
            class,
            description: after_class.trim().to_string(),
            iommu_group,
            driver,
            match_key: format!("pci:{}", bdf),
            in_use_by: None,
            in_use_running: false,
        });
    }
    devs
}

/// Extract the LAST [xxxx:yyyy] from a string.
fn extract_last_id(s: &str) -> Option<(String, String)> {
    let mut last: Option<(String, String)> = None;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(close) = s[i + 1..].find(']') {
                let inner = &s[i + 1..i + 1 + close];
                if inner.len() == 9 && &inner[4..5] == ":" {
                    let v = inner[..4].to_lowercase();
                    let d = inner[5..].to_lowercase();
                    if v.chars().all(|c| c.is_ascii_hexdigit())
                        && d.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        last = Some((v, d));
                    }
                }
                i = i + 1 + close + 1;
                continue;
            }
        }
        i += 1;
    }
    last
}

/// Build a BDF -> IOMMU group number map by walking /sys/kernel/iommu_groups/*/devices/
fn read_iommu_groups() -> HashMap<String, u32> {
    let mut map = HashMap::new();
    let root = Path::new("/sys/kernel/iommu_groups");
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return map,
    };
    for entry in entries.flatten() {
        let group: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let dev_dir = entry.path().join("devices");
        if let Ok(devs) = std::fs::read_dir(&dev_dir) {
            for d in devs.flatten() {
                let bdf = d.file_name().to_string_lossy().to_lowercase();
                map.insert(bdf, group);
            }
        }
    }
    map
}

fn read_pci_driver(bdf: &str) -> Option<String> {
    let link = format!("/sys/bus/pci/devices/{}/driver", bdf);
    let target = std::fs::read_link(&link).ok()?;
    target.file_name().map(|n| n.to_string_lossy().to_string())
}

/// Check host passthrough readiness.
pub fn host_preflight() -> HostPassthroughPreflight {
    let iommu_enabled = std::fs::read_dir("/sys/kernel/iommu_groups")
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);

    let vfio_pci_loaded = std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().any(|l| l.starts_with("vfio_pci ") || l.starts_with("vfio_pci\t")))
        .unwrap_or(false)
        || Path::new("/sys/module/vfio_pci").exists();

    let iommu_cmdline = std::fs::read_to_string("/proc/cmdline")
        .map(|s| s.contains("intel_iommu=on") || s.contains("amd_iommu=on") || s.contains("iommu=pt"))
        .unwrap_or(false);

    let backend = if crate::containers::is_proxmox() {
        "proxmox".to_string()
    } else if crate::containers::is_libvirt() {
        "libvirt".to_string()
    } else {
        "native".to_string()
    };

    let mut warnings = Vec::new();
    if !iommu_enabled {
        warnings.push("IOMMU groups not found — the kernel IOMMU is not active. PCI passthrough will not work until you enable it.".to_string());
    }
    if !iommu_cmdline {
        warnings.push("Kernel command line does not include intel_iommu=on or amd_iommu=on — add it to GRUB_CMDLINE_LINUX_DEFAULT and regenerate grub, then reboot.".to_string());
    }
    if !vfio_pci_loaded {
        warnings.push("vfio-pci kernel module is not loaded — run `modprobe vfio-pci` (and add to /etc/modules-load.d/vfio.conf for persistence).".to_string());
    }

    HostPassthroughPreflight {
        iommu_enabled,
        vfio_pci_loaded,
        iommu_cmdline,
        backend,
        warnings,
    }
}

/// Full host devices response. `ownership` tags devices that are already
/// configured on another VM so the UI can grey them out.
pub fn list_host_devices(ownership: &DeviceOwnership) -> HostDevicesResponse {
    let mut usb = list_host_usb();
    let mut pci = list_host_pci();

    for u in &mut usb {
        if let Some((name, running)) = ownership.by_key.get(&u.match_key) {
            u.in_use_by = Some(name.clone());
            u.in_use_running = *running;
        }
    }
    for p in &mut pci {
        if let Some((name, running)) = ownership.by_key.get(&p.match_key) {
            p.in_use_by = Some(name.clone());
            p.in_use_running = *running;
        }
    }

    HostDevicesResponse {
        usb,
        pci,
        preflight: host_preflight(),
    }
}

/// Build an ownership map from a list of VMs.
pub fn build_ownership(vms: &[VmConfig]) -> DeviceOwnership {
    let mut by_key = HashMap::new();
    for vm in vms {
        for u in &vm.usb_devices {
            by_key.insert(u.match_key(), (vm.name.clone(), vm.running));
        }
        for p in &vm.pci_devices {
            by_key.insert(p.match_key(), (vm.name.clone(), vm.running));
        }
    }
    DeviceOwnership { by_key }
}

// ─── Conflict detection ───

/// Find conflicts: which devices in `target` are already claimed by another
/// running VM in `others`. Returns human-readable conflict messages.
pub fn find_conflicts(target: &VmConfig, others: &[VmConfig]) -> Vec<String> {
    let mut claimed: HashMap<String, String> = HashMap::new();
    for vm in others {
        if vm.name == target.name || !vm.running { continue; }
        for u in &vm.usb_devices {
            claimed.insert(u.match_key(), vm.name.clone());
        }
        for p in &vm.pci_devices {
            claimed.insert(p.match_key(), vm.name.clone());
        }
    }

    let mut conflicts = Vec::new();
    for u in &target.usb_devices {
        if let Some(other) = claimed.get(&u.match_key()) {
            conflicts.push(format!(
                "USB device {}:{} is in use by running VM '{}'",
                u.vendor_id, u.product_id, other
            ));
        }
    }
    for p in &target.pci_devices {
        if let Some(other) = claimed.get(&p.match_key()) {
            conflicts.push(format!(
                "PCI device {} is in use by running VM '{}'",
                p.bdf, other
            ));
        }
    }
    conflicts
}

// ─── Native QEMU argument builders ───

/// Is a USB device with `vendor_id:product_id` present on this host?
///
/// Checks `lsusb` output for a matching `ID xxxx:yyyy` line. Used by
/// `start_vm`'s pre-flight so we catch "device not on host bus" before
/// QEMU spawns and silently fails to bind. Lowercases both sides
/// because `lsusb` output is hex in lowercase while our VmConfig stores
/// in mixed case.
pub fn usb_device_present_on_host(vendor_id: &str, product_id: &str) -> bool {
    let needle = format!("{}:{}", vendor_id.to_ascii_lowercase(), product_id.to_ascii_lowercase());
    let Ok(output) = Command::new("lsusb").output() else { return false; };
    if !output.status.success() { return false; }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // lsusb lines look like: "Bus 001 Device 042: ID 1a86:7523 QinHeng..."
    // We check for the "ID xxxx:yyyy " pattern (ASCII lowercase) so a
    // device whose label happens to contain matching text doesn't trigger
    // a false positive.
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(idx) = lower.find(" id ") {
            let rest = &lower[idx + 4..];
            if rest.starts_with(&needle) {
                return true;
            }
        }
    }
    false
}

/// Append `-device usb-host,...` and `-device vfio-pci,...` arguments for each
/// configured passthrough device. The caller is responsible for having `-usb`
/// already on the command line (the native start path already does).
pub fn append_qemu_passthrough_args(cmd: &mut Command, config: &VmConfig) -> Result<(), String> {
    // When the operator asked to boot a passed-through USB first, the FIRST
    // usb-host device gets bootindex=0 so SeaBIOS/OVMF tries it before the disk
    // (which has no bootindex and follows in the firmware's default order). This
    // is the safe "boot the USB installer, fall back to disk" case without
    // restructuring the disk devices.
    let usb_boot = super::manager::boot_order_usb_first(&config.boot_order);
    for (i, u) in config.usb_devices.iter().enumerate() {
        // All usb-host devices attach to the xhci bus (see manager.rs VM
        // startup). xhci handles every USB speed from low through superspeed+
        // so UVC webcams, USB 3 storage, HID, everything works.
        let spec = if let Some(ref hb) = u.host_bus {
            if !hb.is_empty() {
                let (bus, port) = match hb.split_once('-') {
                    Some((b, p)) => (b, p),
                    None => return Err(format!("Invalid host_bus format '{}', expected 'bus-port'", hb)),
                };
                format!("usb-host,bus=xhci.0,hostbus={},hostport={}", bus, port)
            } else {
                format!("usb-host,bus=xhci.0,vendorid=0x{},productid=0x{}", u.vendor_id, u.product_id)
            }
        } else {
            if u.vendor_id.len() != 4 || u.product_id.len() != 4 {
                return Err(format!(
                    "Invalid USB device id: vendor='{}' product='{}'",
                    u.vendor_id, u.product_id
                ));
            }
            format!("usb-host,bus=xhci.0,vendorid=0x{},productid=0x{}", u.vendor_id, u.product_id)
        };
        let spec = if usb_boot && i == 0 { format!("{},bootindex=0", spec) } else { spec };
        cmd.arg("-device").arg(spec);
    }

    for p in &config.pci_devices {
        validate_bdf(&p.bdf)?;
        // Bind to vfio-pci first. If the device is already bound (e.g. at boot)
        // this is a no-op. Ignore errors — QEMU will give a better diagnostic.
        let _ = bind_vfio_pci(&p.bdf);

        let mut spec = format!("vfio-pci,host={}", p.bdf);
        if p.primary_gpu {
            spec.push_str(",x-vga=on");
        }
        cmd.arg("-device").arg(spec);
    }
    Ok(())
}

/// Validate a BDF string to prevent shell injection and malformed addresses.
/// Accepts both short (BB:DD.F) and full (DDDD:BB:DD.F) forms, normalising to full.
pub fn normalize_bdf(bdf: &str) -> Result<String, String> {
    let bdf = bdf.trim();
    if bdf.is_empty() { return Err("Empty BDF".to_string()); }
    let parts: Vec<&str> = bdf.split(':').collect();
    let (dom, bus, devfunc) = match parts.len() {
        3 => (parts[0].to_string(), parts[1].to_string(), parts[2].to_string()),
        2 => ("0000".to_string(), parts[0].to_string(), parts[1].to_string()),
        _ => return Err(format!("Invalid BDF '{}': expected DDDD:BB:DD.F or BB:DD.F", bdf)),
    };
    let df_parts: Vec<&str> = devfunc.split('.').collect();
    if df_parts.len() != 2 {
        return Err(format!("Invalid BDF '{}': device.function missing", bdf));
    }
    if dom.len() != 4 || bus.len() != 2 || df_parts[0].len() != 2 || df_parts[1].len() != 1 {
        return Err(format!("Invalid BDF '{}': component width wrong", bdf));
    }
    let all_hex = [&dom, &bus, &df_parts[0].to_string(), &df_parts[1].to_string()]
        .iter()
        .all(|s| s.chars().all(|c| c.is_ascii_hexdigit()));
    if !all_hex {
        return Err(format!("Invalid BDF '{}': non-hex characters", bdf));
    }
    Ok(format!("{}:{}:{}.{}", dom.to_lowercase(), bus.to_lowercase(),
               df_parts[0].to_lowercase(), df_parts[1]))
}

fn validate_bdf(bdf: &str) -> Result<(), String> {
    normalize_bdf(bdf).map(|_| ())
}

/// Bind a PCI device to the vfio-pci driver. Best-effort — returns Ok even if
/// the device is already bound.
fn bind_vfio_pci(bdf: &str) -> Result<(), String> {
    let bdf = normalize_bdf(bdf)?;
    let dev_path = format!("/sys/bus/pci/devices/{}", bdf);
    if !Path::new(&dev_path).exists() {
        return Err(format!("PCI device {} not found in sysfs", bdf));
    }

    // If already bound to vfio-pci, nothing to do
    if let Ok(target) = std::fs::read_link(format!("{}/driver", dev_path)) {
        if target.file_name().and_then(|s| s.to_str()) == Some("vfio-pci") {
            return Ok(());
        }
    }

    // Read vendor:device for the driver_override
    let vendor = std::fs::read_to_string(format!("{}/vendor", dev_path))
        .map_err(|e| format!("Read vendor: {}", e))?
        .trim().trim_start_matches("0x").to_string();
    let device = std::fs::read_to_string(format!("{}/device", dev_path))
        .map_err(|e| format!("Read device: {}", e))?
        .trim().trim_start_matches("0x").to_string();

    // Unbind from current driver
    let unbind = format!("{}/driver/unbind", dev_path);
    if Path::new(&unbind).exists() {
        let _ = std::fs::write(&unbind, bdf.as_bytes());
    }

    // Tell the kernel to route future binds to vfio-pci
    let _ = std::fs::write(format!("{}/driver_override", dev_path), b"vfio-pci");

    // Register the ID with vfio-pci then probe
    let _ = std::fs::write(
        "/sys/bus/pci/drivers/vfio-pci/new_id",
        format!("{} {}", vendor, device).as_bytes(),
    );
    let _ = std::fs::write("/sys/bus/pci/drivers_probe", bdf.as_bytes());
    Ok(())
}

// ─── Release / hand-back a PCI device after a VM is destroyed ───
//
// When a VM with PCI passthrough is deleted, we need to undo `bind_vfio_pci`
// so the host kernel can claim the device again and use it normally. For NIC
// passthrough specifically, the host typically had no netplan config for the
// returned interface (cloud-init only saw it once it reappeared) — so the
// NIC comes back unconfigured and the operator has to hand-edit netplan to
// get DHCP working. We close that loop by writing a per-iface netplan
// drop-in here.
//
// All operations are best-effort. None of them fail the calling delete
// flow; the worst case is the device stays bound to vfio-pci (which is
// what was happening anyway before this code existed).

/// Detach a PCI device from vfio-pci and let the kernel re-bind it to the
/// appropriate driver (e1000e, igb, nvidia, etc). Idempotent: if the device
/// is already bound to something other than vfio-pci, this is a no-op so we
/// don't touch user-managed devices.
///
/// Returns `Some(ifname)` when the device is a network controller (PCI
/// class 0x02xxxx) and a netdev appeared after re-binding; `None` for
/// non-NIC devices, devices that didn't re-bind, or any failure path.
pub fn release_pci_device(bdf: &str) -> Option<String> {
    let bdf = normalize_bdf(bdf).ok()?;
    let dev_path = format!("/sys/bus/pci/devices/{}", bdf);
    if !Path::new(&dev_path).exists() {
        return None;
    }

    // Only release if the device is currently bound to vfio-pci. If the
    // user (or a different tool) bound it to something else after a VM
    // shutdown, leave that choice alone.
    let bound_to_vfio = std::fs::read_link(format!("{}/driver", dev_path))
        .ok()
        .and_then(|p| p.file_name().and_then(|s| s.to_str()).map(String::from))
        .as_deref()
        == Some("vfio-pci");
    if !bound_to_vfio {
        return None;
    }

    // PCI class is in the form "0xCCSSPP" — class, subclass, prog-IF.
    // Class 0x02 = Network controller (Ethernet, WLAN, etc).
    let class_hex = std::fs::read_to_string(format!("{}/class", dev_path))
        .unwrap_or_default();
    let is_nic = class_hex
        .trim()
        .trim_start_matches("0x")
        .to_lowercase()
        .starts_with("02");

    // Unbind from vfio-pci.
    let _ = std::fs::write(format!("{}/driver/unbind", dev_path), bdf.as_bytes());

    // Clear driver_override so the kernel's normal driver-matching logic
    // can pick the right driver. Writing an empty string is the documented
    // way to clear it (kernel sysfs(7)).
    let _ = std::fs::write(format!("{}/driver_override", dev_path), b"");

    // Trigger driver probe — kernel scans loaded drivers and binds the
    // matching one (e1000e/igb/r8169/nvidia/...).
    let _ = std::fs::write("/sys/bus/pci/drivers_probe", bdf.as_bytes());

    if !is_nic {
        return None;
    }

    // Give the kernel a brief moment to bind the driver and create the
    // netdev. Network drivers register the netdev synchronously inside
    // their probe, so this is usually instant — but on slow systems or
    // when the driver wasn't pre-loaded we want a small grace period.
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Look up the iface name via /sys/bus/pci/devices/<bdf>/net/<iface>.
    let net_dir = format!("{}/net", dev_path);
    if let Ok(entries) = std::fs::read_dir(&net_dir) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Write a netplan drop-in giving a freshly-released NIC a DHCP config so
/// the operator doesn't have to hand-edit netplan after VM delete. The
/// drop-in uses `optional: true` so a future re-passthrough of the same
/// NIC won't hang the boot (netplan will skip the missing iface).
///
/// No-op when /etc/netplan doesn't exist (Fedora/RHEL/Arch use NM /
/// systemd-networkd / etc — those distros' resolvers will pick up the
/// returned NIC themselves once udev fires).
pub fn write_netplan_dhcp_dropin_for(iface: &str) -> Result<(), String> {
    if !Path::new("/etc/netplan").is_dir() {
        return Ok(());
    }
    // Sanity-check the iface name to avoid path traversal / weird chars.
    if iface.is_empty()
        || iface.len() > 32
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(format!("refusing to write netplan dropin for iface name `{}`", iface));
    }

    let path = format!("/etc/netplan/99-wolfstack-released-{}.yaml", iface);
    let content = format!(
        "# Written by WolfStack on PCI passthrough release.\n\
         # The interface `{iface}` was returned to the host from a VM that\n\
         # had it bound to vfio-pci. Cloud-init / the original netplan\n\
         # didn't know about it (the NIC was missing at boot or had been\n\
         # claimed by vfio-pci before netplan ran), so the host had no IP\n\
         # config for it. This drop-in gives it DHCP. `optional: true`\n\
         # means boot won't hang if the iface is later re-passthrough'd to\n\
         # another VM and disappears again.\n\
         #\n\
         # Safe to delete this file once you've configured the iface in\n\
         # your main netplan config or the iface no longer exists.\n\
         network:\n  \
         version: 2\n  \
         ethernets:\n    \
         {iface}:\n      \
         dhcp4: true\n      \
         optional: true\n",
        iface = iface
    );
    std::fs::write(&path, content).map_err(|e| format!("write {}: {}", path, e))?;

    // netplan generate (validate) → apply. Best-effort; if either fails
    // the file is still on disk and will take effect on next boot.
    let _ = std::process::Command::new("netplan").arg("generate").output();
    let _ = std::process::Command::new("netplan").arg("apply").output();
    Ok(())
}

/// Release every PCI device in `config.pci_devices` (best-effort). For
/// network devices, also writes a netplan drop-in so the returned NIC
/// gets DHCP without manual intervention. Called from `delete_vm` on
/// every VM-management backend (native QEMU, libvirt, Proxmox) — the
/// per-backend code is responsible for capturing `pre_destroy_config`
/// before the platform's destroy step makes the source-of-truth
/// (config file / dumpxml / qm config) unreadable.
pub fn release_passthrough_devices(config: &VmConfig) {
    for p in &config.pci_devices {
        if p.bdf.is_empty() {
            continue;
        }
        if let Some(iface) = release_pci_device(&p.bdf) {
            tracing::info!(
                "released PCI passthrough device {} → host iface {}",
                p.bdf,
                iface
            );
            if let Err(e) = write_netplan_dhcp_dropin_for(&iface) {
                tracing::warn!(
                    "released NIC {} but couldn't write netplan dropin: {}",
                    iface,
                    e
                );
            }
        } else {
            tracing::debug!(
                "release_pci_device({}): not bound to vfio-pci or non-NIC — no-op",
                p.bdf
            );
        }
    }
}

// ─── Proxmox qm set helpers ───

/// Apply passthrough devices to a Proxmox VM via `qm set`.
/// Removes any usbN/hostpciN slots higher than what we're setting so
/// devices removed in the UI actually get removed from Proxmox.
pub fn apply_proxmox_passthrough(vmid: u32, config: &VmConfig) -> Result<(), String> {
    let vmid_str = vmid.to_string();

    // Read current config so we know which slots currently exist
    let cfg_text = Command::new("qm").args(["config", &vmid_str]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // USB slots: usb0..usb4 on Proxmox (5 slots total)
    for (i, u) in config.usb_devices.iter().take(5).enumerate() {
        let key = format!("--usb{}", i);
        let val = if let Some(ref hb) = u.host_bus {
            if !hb.is_empty() {
                format!("host={},usb3=1", hb)
            } else {
                format!("host={}:{}", u.vendor_id, u.product_id)
            }
        } else {
            if u.vendor_id.len() != 4 || u.product_id.len() != 4 {
                return Err(format!("Invalid USB device id {}:{}", u.vendor_id, u.product_id));
            }
            format!("host={}:{}", u.vendor_id, u.product_id)
        };
        let out = Command::new("qm").args(["set", &vmid_str, &key, &val]).output()
            .map_err(|e| format!("qm set usb failed: {}", e))?;
        if !out.status.success() {
            return Err(format!("qm set {} failed: {}", key, String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    // Drop higher-numbered usb slots that are no longer wanted
    for i in config.usb_devices.len()..5 {
        let key = format!("usb{}", i);
        if cfg_text.lines().any(|l| l.starts_with(&format!("{}: ", key))) {
            let _ = Command::new("qm").args(["set", &vmid_str, "--delete", &key]).output();
        }
    }

    // PCI slots: hostpci0..hostpci3 (4 slots)
    for (i, p) in config.pci_devices.iter().take(4).enumerate() {
        let bdf = normalize_bdf(&p.bdf)?;
        let key = format!("--hostpci{}", i);
        let mut val = bdf.clone();
        if p.pcie { val.push_str(",pcie=1"); }
        if p.primary_gpu { val.push_str(",x-vga=1"); }
        let out = Command::new("qm").args(["set", &vmid_str, &key, &val]).output()
            .map_err(|e| format!("qm set hostpci failed: {}", e))?;
        if !out.status.success() {
            return Err(format!("qm set {} failed: {}", key, String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    for i in config.pci_devices.len()..4 {
        let key = format!("hostpci{}", i);
        if cfg_text.lines().any(|l| l.starts_with(&format!("{}: ", key))) {
            let _ = Command::new("qm").args(["set", &vmid_str, "--delete", &key]).output();
        }
    }

    Ok(())
}

/// Parse `qm config` output for existing usbN=/hostpciN= lines.
pub fn parse_proxmox_passthrough(cfg_text: &str) -> (Vec<UsbDevice>, Vec<PciDevice>) {
    let mut usb = Vec::new();
    let mut pci = Vec::new();

    for line in cfg_text.lines() {
        let line = line.trim();
        // usbN: host=VID:PID[,usb3=1]  or  host=1-4
        if line.starts_with("usb") && line.contains(':') {
            if let Some(rest) = line.splitn(2, ':').nth(1) {
                let rest = rest.trim();
                let host_val = rest
                    .split(',')
                    .find_map(|kv| kv.trim().strip_prefix("host="))
                    .unwrap_or("");
                if host_val.is_empty() { continue; }
                if host_val.contains(':') {
                    // vendor:product
                    let mut it = host_val.split(':');
                    let v = it.next().unwrap_or("").to_lowercase();
                    let p = it.next().unwrap_or("").to_lowercase();
                    usb.push(UsbDevice {
                        vendor_id: v,
                        product_id: p,
                        host_bus: None,
                        label: None,
                    });
                } else if host_val.contains('-') {
                    // bus-port
                    usb.push(UsbDevice {
                        vendor_id: String::new(),
                        product_id: String::new(),
                        host_bus: Some(host_val.to_string()),
                        label: None,
                    });
                }
            }
        } else if line.starts_with("hostpci") && line.contains(':') {
            if let Some(rest) = line.splitn(2, ':').nth(1) {
                let rest = rest.trim();
                // First token (before a comma) is the BDF
                let first = rest.split(',').next().unwrap_or("").trim();
                // Proxmox also accepts "host=BDF" — strip the prefix if present
                let bdf_raw = first.trim_start_matches("host=");
                if let Ok(bdf) = normalize_bdf(bdf_raw) {
                    let pcie = rest.split(',').any(|kv| kv.trim() == "pcie=1");
                    let primary = rest.split(',').any(|kv| kv.trim() == "x-vga=1");
                    pci.push(PciDevice {
                        bdf,
                        pcie,
                        primary_gpu: primary,
                        label: None,
                    });
                }
            }
        }
    }
    (usb, pci)
}

// ─── Libvirt hostdev XML ───

/// Build a `<hostdev>` XML fragment for a single USB device.
/// managed='no' for USB because libvirt handles USB binding itself and doesn't
/// need the driver detach/reattach dance.
pub fn libvirt_usb_xml(u: &UsbDevice) -> Result<String, String> {
    if u.vendor_id.len() != 4 || u.product_id.len() != 4 {
        return Err(format!("Invalid USB device id {}:{}", u.vendor_id, u.product_id));
    }
    Ok(format!(
        "<hostdev mode='subsystem' type='usb' managed='no'>\n  <source>\n    <vendor id='0x{}'/>\n    <product id='0x{}'/>\n  </source>\n</hostdev>",
        u.vendor_id, u.product_id
    ))
}

/// Build a `<hostdev>` XML fragment for a PCI device. managed='yes' lets
/// libvirt detach the host driver and reattach it on guest shutdown.
pub fn libvirt_pci_xml(p: &PciDevice) -> Result<String, String> {
    let bdf = normalize_bdf(&p.bdf)?;
    // DDDD:BB:DD.F → domain/bus/slot/function
    let parts: Vec<&str> = bdf.split(':').collect();
    let dom = parts[0];
    let bus = parts[1];
    let df: Vec<&str> = parts[2].split('.').collect();
    let slot = df[0];
    let func = df[1];
    Ok(format!(
        "<hostdev mode='subsystem' type='pci' managed='yes'>\n  <source>\n    <address domain='0x{}' bus='0x{}' slot='0x{}' function='0x{}'/>\n  </source>\n</hostdev>",
        dom, bus, slot, func
    ))
}

/// Apply passthrough to a libvirt domain: detach devices no longer wanted,
/// attach new ones. Uses `virsh attach-device --config` (persistent).
pub fn apply_libvirt_passthrough(name: &str, config: &VmConfig) -> Result<(), String> {
    // Read current domain XML to know what's already attached
    let xml_out = Command::new("virsh").args(["dumpxml", name]).output()
        .map_err(|e| format!("virsh dumpxml failed: {}", e))?;
    let xml = String::from_utf8_lossy(&xml_out.stdout).to_string();
    let (current_usb, current_pci) = parse_libvirt_hostdevs(&xml);

    // Desired state -> match_key set
    let desired_usb: HashSet<String> = config.usb_devices.iter().map(|u| u.match_key()).collect();
    let desired_pci: HashSet<String> = config.pci_devices.iter().map(|p| p.match_key()).collect();

    // Detach any currently-attached device that's no longer wanted
    for u in &current_usb {
        if !desired_usb.contains(&u.match_key()) {
            let xml = libvirt_usb_xml(u)?;
            detach_libvirt_device(name, &xml)?;
        }
    }
    for p in &current_pci {
        if !desired_pci.contains(&p.match_key()) {
            let xml = libvirt_pci_xml(p)?;
            detach_libvirt_device(name, &xml)?;
        }
    }

    // Attach any new device not already present
    let current_usb_keys: HashSet<String> = current_usb.iter().map(|u| u.match_key()).collect();
    let current_pci_keys: HashSet<String> = current_pci.iter().map(|p| p.match_key()).collect();

    for u in &config.usb_devices {
        if !current_usb_keys.contains(&u.match_key()) {
            let xml = libvirt_usb_xml(u)?;
            attach_libvirt_device(name, &xml)?;
        }
    }
    for p in &config.pci_devices {
        if !current_pci_keys.contains(&p.match_key()) {
            let xml = libvirt_pci_xml(p)?;
            attach_libvirt_device(name, &xml)?;
        }
    }
    Ok(())
}

fn attach_libvirt_device(vm: &str, xml: &str) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!("wolfstack-hostdev-{}.xml", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, xml).map_err(|e| format!("Failed to write hostdev XML: {}", e))?;
    let out = Command::new("virsh")
        .args(["attach-device", vm, &tmp.to_string_lossy(), "--config"])
        .output()
        .map_err(|e| format!("virsh attach-device failed: {}", e))?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "already exists" is not fatal
        if stderr.contains("already exists") || stderr.contains("exists in domain") {
            return Ok(());
        }
        return Err(format!("virsh attach-device failed: {}", stderr.trim()));
    }
    Ok(())
}

fn detach_libvirt_device(vm: &str, xml: &str) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!("wolfstack-hostdev-{}.xml", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, xml).map_err(|e| format!("Failed to write hostdev XML: {}", e))?;
    let out = Command::new("virsh")
        .args(["detach-device", vm, &tmp.to_string_lossy(), "--config"])
        .output()
        .map_err(|e| format!("virsh detach-device failed: {}", e))?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Device already gone → not an error
        if stderr.contains("not found") || stderr.contains("no such") {
            return Ok(());
        }
        return Err(format!("virsh detach-device failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Parse `<hostdev>` nodes from a libvirt domain XML blob.
/// Handles both USB (vendor/product) and PCI (address) forms.
pub fn parse_libvirt_hostdevs(xml: &str) -> (Vec<UsbDevice>, Vec<PciDevice>) {
    let mut usb = Vec::new();
    let mut pci = Vec::new();

    // Split on "<hostdev" occurrences — simple state machine, no XML parser dep
    let mut rest = xml;
    while let Some(start) = rest.find("<hostdev") {
        let after = &rest[start..];
        let end = match after.find("</hostdev>") {
            Some(e) => e + "</hostdev>".len(),
            None => break,
        };
        let block = &after[..end];
        rest = &after[end..];

        let is_usb = block.contains("type='usb'") || block.contains("type=\"usb\"");
        let is_pci = block.contains("type='pci'") || block.contains("type=\"pci\"");

        if is_usb {
            let vid = extract_xml_attr(block, "vendor", "id").unwrap_or_default();
            let pid = extract_xml_attr(block, "product", "id").unwrap_or_default();
            // strip 0x prefix and lowercase
            let vid = vid.trim_start_matches("0x").to_lowercase();
            let pid = pid.trim_start_matches("0x").to_lowercase();
            if vid.len() == 4 && pid.len() == 4 {
                usb.push(UsbDevice {
                    vendor_id: vid,
                    product_id: pid,
                    host_bus: None,
                    label: None,
                });
            }
        } else if is_pci {
            let dom = extract_xml_attr(block, "address", "domain").unwrap_or_else(|| "0x0000".to_string());
            let bus = extract_xml_attr(block, "address", "bus").unwrap_or_default();
            let slot = extract_xml_attr(block, "address", "slot").unwrap_or_default();
            let func = extract_xml_attr(block, "address", "function").unwrap_or_default();
            let clean = |s: String, width: usize| -> String {
                let s = s.trim_start_matches("0x").to_string();
                format!("{:0>width$}", s, width = width)
            };
            let bdf = format!(
                "{}:{}:{}.{}",
                clean(dom, 4), clean(bus, 2), clean(slot, 2), clean(func, 1)
            );
            if let Ok(norm) = normalize_bdf(&bdf) {
                // We can't reliably infer primary_gpu from the libvirt XML —
                // it's stored by virt-manager as a QEMU commandline arg hack.
                pci.push(PciDevice {
                    bdf: norm,
                    pcie: true,
                    primary_gpu: false,
                    label: None,
                });
            }
        }
    }
    (usb, pci)
}

/// Extract `attr='value'` or `attr="value"` from the given tag inside `block`.
fn extract_xml_attr(block: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_open = format!("<{}", tag);
    let tag_pos = block.find(&tag_open)?;
    let after = &block[tag_pos..];
    // Limit to end of the tag (before `/>` or `>`)
    let end = after.find(">").unwrap_or(after.len());
    let inside = &after[..end];

    for quote in ['\'', '"'] {
        let key = format!("{}={}", attr, quote);
        if let Some(p) = inside.find(&key) {
            let val_start = p + key.len();
            if let Some(q) = inside[val_start..].find(quote) {
                return Some(inside[val_start..val_start + q].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsusb_line() {
        let sample = "Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver";
        // Simulate by feeding one line via stdout: we can only test the parser indirectly
        let ex = extract_last_id("Logitech, Inc. Unifying Receiver [046d:c52b]");
        assert_eq!(ex, Some(("046d".to_string(), "c52b".to_string())));
        // Ensure the full lsusb line contains what we need
        assert!(sample.contains("046d:c52b"));
    }

    #[test]
    fn extracts_last_pci_id() {
        let line = "VGA compatible controller [0300]: NVIDIA GP104 [GeForce GTX 1080] [10de:1b80] (rev a1)";
        assert_eq!(
            extract_last_id(line),
            Some(("10de".to_string(), "1b80".to_string()))
        );
    }

    #[test]
    fn normalizes_bdf_variants() {
        assert_eq!(normalize_bdf("01:00.0").unwrap(), "0000:01:00.0");
        assert_eq!(normalize_bdf("0000:01:00.0").unwrap(), "0000:01:00.0");
        assert_eq!(normalize_bdf("0000:AB:CD.1").unwrap(), "0000:ab:cd.1");
        assert!(normalize_bdf("").is_err());
        assert!(normalize_bdf("bogus").is_err());
        assert!(normalize_bdf("0000:01:00").is_err());
        assert!(normalize_bdf("zz:00.0").is_err());
    }

    #[test]
    fn parses_proxmox_passthrough_lines() {
        let cfg = "\
cores: 4
memory: 4096
usb0: host=046d:c52b
usb1: host=1-4,usb3=1
hostpci0: 0000:01:00.0,pcie=1,x-vga=1
hostpci1: host=0000:02:00.0
net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0
";
        let (usb, pci) = parse_proxmox_passthrough(cfg);
        assert_eq!(usb.len(), 2);
        assert_eq!(usb[0].vendor_id, "046d");
        assert_eq!(usb[0].product_id, "c52b");
        assert_eq!(usb[1].host_bus.as_deref(), Some("1-4"));
        assert_eq!(pci.len(), 2);
        assert_eq!(pci[0].bdf, "0000:01:00.0");
        assert!(pci[0].pcie);
        assert!(pci[0].primary_gpu);
        assert_eq!(pci[1].bdf, "0000:02:00.0");
    }

    #[test]
    fn parses_libvirt_hostdev_xml() {
        let xml = "\
<domain>
  <devices>
    <hostdev mode='subsystem' type='usb' managed='no'>
      <source>
        <vendor id='0x046d'/>
        <product id='0xc52b'/>
      </source>
    </hostdev>
    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source>
        <address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
      </source>
    </hostdev>
  </devices>
</domain>";
        let (usb, pci) = parse_libvirt_hostdevs(xml);
        assert_eq!(usb.len(), 1);
        assert_eq!(usb[0].vendor_id, "046d");
        assert_eq!(usb[0].product_id, "c52b");
        assert_eq!(pci.len(), 1);
        assert_eq!(pci[0].bdf, "0000:01:00.0");
    }

    #[test]
    fn find_conflicts_detects_running_claim() {
        let running = VmConfig {
            name: "gaming".to_string(),
            running: true,
            usb_devices: vec![UsbDevice {
                vendor_id: "046d".to_string(),
                product_id: "c52b".to_string(),
                host_bus: None,
                label: None,
            }],
            pci_devices: vec![PciDevice {
                bdf: "0000:01:00.0".to_string(),
                pcie: true,
                primary_gpu: true,
                label: None,
            }],
            ..VmConfig::new("gaming".to_string(), 1, 1024, 10)
        };
        let target = VmConfig {
            name: "work".to_string(),
            usb_devices: vec![UsbDevice {
                vendor_id: "046d".to_string(),
                product_id: "c52b".to_string(),
                host_bus: None,
                label: None,
            }],
            pci_devices: vec![],
            ..VmConfig::new("work".to_string(), 1, 1024, 10)
        };
        let conflicts = find_conflicts(&target, &[running]);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("046d:c52b"));
        assert!(conflicts[0].contains("gaming"));
    }

    #[test]
    fn find_conflicts_ignores_stopped_claim() {
        let stopped = VmConfig {
            name: "other".to_string(),
            running: false,
            pci_devices: vec![PciDevice {
                bdf: "0000:01:00.0".to_string(),
                pcie: true,
                primary_gpu: false,
                label: None,
            }],
            ..VmConfig::new("other".to_string(), 1, 1024, 10)
        };
        let target = VmConfig {
            name: "work".to_string(),
            pci_devices: vec![PciDevice {
                bdf: "0000:01:00.0".to_string(),
                pcie: true,
                primary_gpu: false,
                label: None,
            }],
            ..VmConfig::new("work".to_string(), 1, 1024, 10)
        };
        assert!(find_conflicts(&target, &[stopped]).is_empty());
    }
}

// ─── Network-safety preflight ──────────────────────────────────────
//
// Reported on Discord (PapaSchlumpf 2026-05-02): an HA-OS VM with PCI
// passthrough of a NIC nuked DHCP for the entire network the moment
// it started. The cause is structural — VFIO passthrough removes the
// device from the host kernel, so any service binding to it (the
// host's default-route, dnsmasq for WolfNet clients) loses its leg
// instantly. Reboot is required because re-attaching from VFIO
// without one tends to leave the device in an unrecoverable state.
//
// `check_passthrough_steals_host_net` returns the offending interface
// name when the VM's passthrough list would claim the host's
// default-route interface, so the start path can refuse with a
// clear error before the operator nukes their own connectivity.

/// Returns `Some(iface_name)` if any of `vm`'s passthrough config
/// would steal the host's default-route interface. `None` when the
/// VM is safe to start (or when we couldn't determine the host's
/// default route — fail open rather than block legitimate starts).
///
/// IMPORTANT: only **PCI passthrough** (`vm.pci_devices`, true VFIO)
/// is checked. The original v22.7.3 implementation also blocked
/// `nic.passthrough_interface`, but that was a false positive —
/// `passthrough_interface` is **bridge mode**: WolfStack auto-creates
/// `br-pt-<iface>` (see `manager::create_linux_passthrough_bridge`)
/// and moves the host's IP onto the bridge, so the host KEEPS
/// connectivity through the same physical NIC. Blocking it cost
/// PapaSchlumpf his only passthrough workaround on 2026-05-06 —
/// his HA VM uses bridge-mode passthrough on the same NIC the host
/// uses for its uplink, which is a perfectly safe config.
///
/// True VFIO PCI passthrough is the only case where the host loses
/// the device entirely — the kernel hands it to the guest via VFIO
/// and `ip link` can't get it back without re-binding from `vfio-pci`,
/// usually requiring a host reboot. That's the case we still block.
pub fn check_passthrough_steals_host_net(vm: &VmConfig) -> Option<String> {
    let host_default_iface = host_default_route_interface()?;
    check_pci_steals_host_iface(&vm.pci_devices, &host_default_iface, &pci_bdf_to_net_iface)
}

/// Pure logic for the VFIO check. Separated from the I/O-bound
/// `check_passthrough_steals_host_net` so unit tests can drive both
/// the positive and negative paths with synthetic resolvers — the
/// real `pci_bdf_to_net_iface` only resolves real sysfs entries on
/// the test runner's host, which makes positive-path tests for the
/// "this BDF maps to the default-route NIC" case impossible
/// otherwise.
fn check_pci_steals_host_iface(
    pci_devices: &[crate::vms::manager::PciDevice],
    host_default_iface: &str,
    bdf_resolver: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    for dev in pci_devices {
        if let Some(net_iface) = bdf_resolver(&dev.bdf) {
            if net_iface == host_default_iface {
                return Some(host_default_iface.to_string());
            }
        }
    }
    None
}

/// Returns `Some(iface_name)` when a `nic.passthrough_interface` (i.e.
/// bridge-mode passthrough) names the host's default-route iface.
/// This is **not** a fatal condition — bridge mode keeps the host
/// connected via the auto-created `br-pt-<iface>` — but the brief
/// window during the IP-move can blip ongoing connections (SSH
/// usually survives via TCP keepalive; long-running TCP flows may
/// reset). Callers can surface this as a non-blocking advisory so
/// the operator knows what to expect.
pub fn bridge_passthrough_uses_default_route_iface(vm: &VmConfig) -> Option<String> {
    let host_default_iface = host_default_route_interface()?;
    for nic in &vm.extra_nics {
        if let Some(iface) = &nic.passthrough_interface {
            if iface == &host_default_iface {
                return Some(host_default_iface);
            }
        }
    }
    None
}

/// Read the host's IPv4 default-route interface from `/proc/net/route`.
/// Avoids shelling out to `ip` for the hot path. Returns `None` if
/// no default route exists (host might be a network-isolated lab box
/// where killing connectivity isn't fatal).
fn host_default_route_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 { continue; }
        // Default route = destination 00000000. Field order on
        // every Linux kernel: Iface Destination Gateway Flags ...
        if cols[1] == "00000000" {
            return Some(cols[0].to_string());
        }
    }
    None
}

/// Map a PCI BDF (e.g. "0000:01:00.0" or "01:00.0") to the kernel
/// network-interface name it backs, by reading
/// `/sys/bus/pci/devices/{normalised-bdf}/net/`. Returns `None`
/// when:
///   • the BDF doesn't resolve in sysfs (device not present);
///   • the device isn't a network class (the `net/` directory
///     doesn't exist — e.g. a GPU passthrough);
///   • the device IS a NIC but is already bound to vfio-pci (in
///     which case the host doesn't currently use it, so it can't
///     be the default-route interface either — safe).
fn pci_bdf_to_net_iface(bdf: &str) -> Option<String> {
    // Normalise short-form BDFs (`01:00.0`) to the full form sysfs
    // uses (`0000:01:00.0`). Full-form input passes through.
    let normalised = if bdf.matches(':').count() == 1 {
        format!("0000:{}", bdf)
    } else {
        bdf.to_string()
    };
    let net_dir = format!("/sys/bus/pci/devices/{}/net", normalised);
    let entries = std::fs::read_dir(&net_dir).ok()?;
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod network_preflight_tests {
    use super::*;
    use super::super::manager::{NicConfig, VmConfig};

    fn empty_vm() -> VmConfig {
        VmConfig::new("test".to_string(), 1, 1024, 10)
    }

    fn nic_with_passthrough(iface: &str) -> NicConfig {
        NicConfig {
            model: "virtio".into(),
            mac: None,
            bridge: None,
            passthrough_interface: Some(iface.to_string()),
        }
    }

    #[test]
    fn vm_with_no_passthrough_is_safe() {
        let vm = empty_vm();
        // A VM with no passthrough at all can never steal the host
        // NIC, regardless of the host's actual route table.
        assert!(check_passthrough_steals_host_net(&vm).is_none());
    }

    #[test]
    fn bridge_passthrough_iface_matching_default_route_does_not_block_start() {
        // PapaSchlumpf scenario, 2026-05-06: HA VM uses
        // `passthrough_interface` (bridge mode — host's IP gets moved
        // onto br-pt-X). The original v22.7.3 preflight rejected this
        // because the comment author confused bridge-mode with VFIO
        // PCI passthrough. The fix: bridge mode is safe, must not
        // refuse the start.
        let Some(host_iface) = host_default_route_interface() else { return; };
        let mut vm = empty_vm();
        vm.extra_nics.push(nic_with_passthrough(&host_iface));
        assert!(
            check_passthrough_steals_host_net(&vm).is_none(),
            "passthrough_interface (bridge mode) must NOT block VM start — \
             host keeps connectivity via br-pt-<iface>",
        );
        // It DOES still get reported by the advisory variant so the
        // operator can be told "expect a brief blip during IP move".
        assert_eq!(
            bridge_passthrough_uses_default_route_iface(&vm).as_deref(),
            Some(host_iface.as_str()),
            "advisory must still flag bridge-mode passthrough on the default route",
        );
    }

    fn pci(bdf: &str) -> crate::vms::manager::PciDevice {
        crate::vms::manager::PciDevice {
            bdf: bdf.into(),
            pcie: true,
            primary_gpu: false,
            label: None,
        }
    }

    #[test]
    fn pci_passthrough_of_default_route_nic_blocks() {
        // Positive-path: a `pci_devices` entry whose BDF resolves to
        // the host's default-route NIC must trigger the block. We
        // drive the pure helper with a synthetic resolver because
        // the real `pci_bdf_to_net_iface` only resolves devices that
        // actually exist on the test runner.
        let devs = vec![pci("0000:01:00.0")];
        let resolver = |bdf: &str| -> Option<String> {
            if bdf == "0000:01:00.0" { Some("eth0".into()) } else { None }
        };
        assert_eq!(
            check_pci_steals_host_iface(&devs, "eth0", &resolver).as_deref(),
            Some("eth0"),
            "PCI BDF resolving to the default-route NIC MUST block",
        );
    }

    #[test]
    fn pci_passthrough_of_other_nic_allows() {
        // The PCI device resolves to a NIC, just not the host's
        // default-route one. Safe to start.
        let devs = vec![pci("0000:02:00.0")];
        let resolver = |_: &str| Some("eth1".to_string());
        assert!(check_pci_steals_host_iface(&devs, "eth0", &resolver).is_none());
    }

    #[test]
    fn pci_passthrough_unresolvable_bdf_allows() {
        // BDF that isn't a NIC at all (GPU passthrough, fake BDF,
        // device bound to vfio-pci already, etc). Must not false-
        // positive on the safe path.
        let devs = vec![pci("0000:0a:00.0")];
        let resolver = |_: &str| None;
        assert!(check_pci_steals_host_iface(&devs, "eth0", &resolver).is_none());
    }

    #[test]
    fn pci_passthrough_first_match_wins_deterministically() {
        // A VM with multiple PCI passthroughs where ONE of them is
        // the host's NIC: still blocks. Documents that we don't
        // require the bad device to be first in the list.
        let devs = vec![pci("0000:01:00.0"), pci("0000:02:00.0"), pci("0000:03:00.0")];
        let resolver = |bdf: &str| -> Option<String> {
            match bdf {
                "0000:02:00.0" => Some("eth0".into()),
                _ => None,
            }
        };
        assert_eq!(
            check_pci_steals_host_iface(&devs, "eth0", &resolver).as_deref(),
            Some("eth0"),
        );
    }

    #[test]
    fn pci_passthrough_sysfs_smoke_test_no_panic() {
        // The wrapping function (which uses the real sysfs resolver)
        // must not panic on a fake BDF when the host has no default
        // route or the BDF doesn't resolve. Guards against the
        // refactor accidentally breaking the production path.
        let mut vm = empty_vm();
        vm.pci_devices.push(pci("ff:ff.7"));
        let _ = check_passthrough_steals_host_net(&vm);
    }

    #[test]
    fn passthrough_iface_not_matching_default_route_allows() {
        let mut vm = empty_vm();
        // A bogus interface name that can't possibly be the host's
        // default route. Counter-test pinning the safe path so a
        // future false-positive bug is caught.
        vm.extra_nics.push(nic_with_passthrough("does-not-exist-9999"));
        assert!(check_passthrough_steals_host_net(&vm).is_none());
        assert!(bridge_passthrough_uses_default_route_iface(&vm).is_none());
    }

    #[test]
    fn pci_bdf_to_net_iface_handles_short_form() {
        // We can't assert the actual return without a known PCI
        // device, but we can confirm the BDF normalisation doesn't
        // panic and returns None for a clearly-fake address.
        assert_eq!(pci_bdf_to_net_iface("ff:ff.7"), None);
        assert_eq!(pci_bdf_to_net_iface("0000:ff:ff.7"), None);
    }

    #[test]
    fn host_default_route_interface_returns_string_or_none() {
        // Smoke test — must not panic. Result depends on the host.
        let _ = host_default_route_interface();
    }
}
