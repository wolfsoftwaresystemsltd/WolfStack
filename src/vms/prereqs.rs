// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! VM host prerequisites — the preflight that tells an operator, up
//! front, which system components a VM needs and which are missing, so
//! they can install them with one click instead of discovering each
//! gap as a failed VM start (masterpier, 2026-07-15: on minimal Ubuntu
//! a Windows 11 VM needs swtpm + OVMF that aren't shipped, and the old
//! flow surfaced them one error at a time).
//!
//! Native (raw-QEMU) hosts are where this matters. Proxmox nodes ship
//! qemu/swtpm/OVMF as part of PVE, so we report them ready and skip the
//! install machinery entirely.

use serde::Serialize;

/// One required/optional component and its live status on this host.
#[derive(Debug, Clone, Serialize)]
pub struct Prereq {
    /// Logical package name for `/api/system/install-package`, or a
    /// sentinel like "kvm" for capabilities that can't be installed.
    pub key: String,
    /// Human label shown in the preflight panel.
    pub label: String,
    /// Why the VM needs it — one line, operator-facing.
    pub purpose: String,
    pub installed: bool,
    /// Required for the CURRENT VM config (e.g. swtpm only when TPM is
    /// enabled). A missing required item blocks a clean start.
    pub required: bool,
    /// Can WolfStack install it on this host (mapped for this distro)?
    /// False for `/dev/kvm` (hardware/kernel) and unmapped distros.
    pub installable: bool,
    /// Fallback hint when not installable (manual step / BIOS setting).
    pub hint: String,
}

/// Full preflight result for the VM host.
#[derive(Debug, Clone, Serialize)]
pub struct PrereqReport {
    /// True when nothing REQUIRED is missing — the VM can start cleanly.
    pub ready: bool,
    /// Proxmox node: everything is managed by PVE, `items` is empty and
    /// the UI shows a "managed by Proxmox" note instead of install
    /// buttons.
    pub proxmox: bool,
    pub items: Vec<Prereq>,
}

/// Build the preflight for a native VM host. `needs_uefi` / `needs_tpm`
/// come from the VM form's Firmware / TPM toggles so a component is
/// only marked REQUIRED when the current config actually uses it — but
/// every component's install state is reported regardless, so the panel
/// can offer proactive installs.
pub fn check(needs_uefi: bool, needs_tpm: bool) -> PrereqReport {
    if crate::containers::is_proxmox() {
        // PVE ships the whole stack; nothing for us to install.
        return PrereqReport { ready: true, proxmox: true, items: Vec::new() };
    }

    let pkg = |key: &str, label: &str, purpose: &str, required: bool, hint: &str| -> Prereq {
        let installed = crate::installer::packages::is_present(key).unwrap_or(false);
        Prereq {
            key: key.to_string(),
            label: label.to_string(),
            purpose: purpose.to_string(),
            installed,
            required,
            installable: crate::installer::packages::is_installable(key),
            hint: hint.to_string(),
        }
    };

    let mut items = vec![
        pkg("qemu", "QEMU emulator", "Runs the virtual machine.", true,
            "Install the qemu-system-x86 package for your distro."),
        pkg("qemu-img", "QEMU disk tools", "Creates and converts VM disks.", true,
            "Install qemu-utils (Debian/Ubuntu) or qemu-img."),
        // OVMF / swtpm: install-state always reported; only REQUIRED when
        // the current VM config uses UEFI / TPM.
        pkg("ovmf", "OVMF UEFI firmware", "UEFI boot & Secure Boot (Windows 11).", needs_uefi,
            "Install ovmf (Debian/Ubuntu) or edk2-ovmf (Arch/RHEL)."),
        pkg("swtpm", "swtpm (TPM 2.0)", "Emulated TPM for Windows 11.", needs_tpm,
            "Install the swtpm package for your distro."),
    ];

    // Hardware virtualization: a capability, not a package. Without it
    // VMs fall back to slow TCG emulation, so it's RECOMMENDED (warn),
    // never a hard requirement, and never "installable" — it's a kernel
    // module + BIOS/UEFI virtualization setting.
    let kvm = std::path::Path::new("/dev/kvm").exists();
    items.push(Prereq {
        key: "kvm".to_string(),
        label: "KVM acceleration".to_string(),
        purpose: "Hardware virtualization — without it VMs are very slow.".to_string(),
        installed: kvm,
        required: false,
        installable: false,
        hint: "Enable virtualization (VT-x/AMD-V) in BIOS/UEFI and load the kvm module.".to_string(),
    });

    let ready = items.iter().all(|i| !i.required || i.installed);
    PrereqReport { ready, proxmox: false, items }
}
