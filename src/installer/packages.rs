// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! System package installer — generic, distro-aware, allowlisted.
//!
//! Background: WolfStack assumes a handful of system tools exist on the
//! host (crontab, qemu-system, virsh, dnsmasq, etc.). Debian-based
//! installs ship most of them; Arch ships almost none of them by
//! default and our endpoints fail with a confusing "command not found"
//! when the user first hits a feature. This module gives both the
//! System Check UI and any feature that wants to lazy-install a
//! prereq one place to call.
//!
//! Allowlist + per-distro mapping rather than free-form `apt install
//! $whatever` because the install endpoint is reachable by any
//! authenticated session — we don't want it doubling as an
//! arbitrary-package execution surface.

use std::process::Command;
use super::{detect_distro, DistroFamily};

/// One row in the install table — maps a logical package name (what
/// callers ask for) to the per-distro package name + an optional
/// systemd unit to enable+start after install.
struct PackageMapping {
    /// Stable identifier used by callers — `cron`, `qemu`, etc. Maps
    /// 1:1 to a row in this table.
    logical: &'static str,
    /// What the caller cares about (`crontab`, `qemu-system-x86_64`).
    /// Used for the post-install `command -v` verification.
    binary: &'static str,
    /// Per-distro package name. None means the package isn't available
    /// on that distro and we should refuse the install.
    debian: Option<&'static str>,
    rhel: Option<&'static str>,
    arch: Option<&'static str>,
    suse: Option<&'static str>,
    /// Alpine Linux apk package name. None means we haven't verified
    /// it's available — caller surfaces "not available on this distro"
    /// rather than guessing wrong. Most apk packages share their name
    /// with Debian or Arch, so we set the common cases here.
    alpine: Option<&'static str>,
    /// systemd unit to enable+start once the install succeeds. `None`
    /// for tools that don't have a daemon (e.g. tcpdump). cronie's
    /// daemon won't actually start running cron jobs without this.
    service_unit: Option<&'static str>,
}

/// Allowlist. Add new entries here when WolfStack grows a feature
/// that needs a new system package. Keep this list small — every
/// entry is one more thing the install endpoint will happily run as
/// root.
const PACKAGES: &[PackageMapping] = &[
    PackageMapping {
        logical: "cron",
        binary: "crontab",
        debian: Some("cron"),
        rhel: Some("cronie"),
        arch: Some("cronie"),
        suse: Some("cron"),
        // Alpine: dcron is the default cron implementation; provides
        // /usr/bin/crontab. busybox-suid also provides crontab but
        // dcron is the standard package operators install.
        alpine: Some("dcron"),
        service_unit: Some("cronie.service"),
    },
    PackageMapping {
        logical: "tcpdump",
        binary: "tcpdump",
        debian: Some("tcpdump"),
        rhel: Some("tcpdump"),
        arch: Some("tcpdump"),
        suse: Some("tcpdump"),
        alpine: Some("tcpdump"),
        service_unit: None,
    },
    PackageMapping {
        // Used by the Visual TraceRoute tab in WolfRouter and the
        // /api/traceroute endpoint. Ubuntu minimal / cloud images ship
        // without it by default — Adam Cogswell 2026-04-30 reported
        // the tab failing with no in-app install path.
        logical: "traceroute",
        binary: "traceroute",
        debian: Some("traceroute"),
        rhel: Some("traceroute"),
        arch: Some("traceroute"),
        suse: Some("traceroute"),
        alpine: Some("traceroute"),
        service_unit: None,
    },
    PackageMapping {
        logical: "conntrack",
        binary: "conntrack",
        debian: Some("conntrack"),
        rhel: Some("conntrack-tools"),
        arch: Some("conntrack-tools"),
        suse: Some("conntrack-tools"),
        alpine: Some("conntrack-tools"),
        service_unit: None,
    },
    PackageMapping {
        logical: "iptables",
        binary: "iptables",
        debian: Some("iptables"),
        rhel: Some("iptables"),
        arch: Some("iptables"),
        suse: Some("iptables"),
        alpine: Some("iptables"),
        service_unit: None,
    },
    PackageMapping {
        logical: "dnsmasq",
        binary: "dnsmasq",
        debian: Some("dnsmasq"),
        rhel: Some("dnsmasq"),
        arch: Some("dnsmasq"),
        suse: Some("dnsmasq"),
        alpine: Some("dnsmasq"),
        service_unit: None,
    },
    PackageMapping {
        logical: "qemu",
        binary: "qemu-system-x86_64",
        debian: Some("qemu-system-x86"),
        rhel: Some("qemu-kvm"),
        arch: Some("qemu-full"),
        suse: Some("qemu-x86"),
        // Alpine ships qemu-system-x86_64 as its own package; the
        // qemu meta-package doesn't exist.
        alpine: Some("qemu-system-x86_64"),
        service_unit: None,
    },
    PackageMapping {
        logical: "libvirt",
        binary: "virsh",
        debian: Some("libvirt-clients"),
        rhel: Some("libvirt-client"),
        arch: Some("libvirt"),
        suse: Some("libvirt-client"),
        alpine: Some("libvirt-client"),
        service_unit: Some("libvirtd.service"),
    },
    PackageMapping {
        logical: "openssh-server",
        binary: "sshd",
        debian: Some("openssh-server"),
        rhel: Some("openssh-server"),
        arch: Some("openssh"),
        suse: Some("openssh"),
        alpine: Some("openssh-server"),
        service_unit: Some("sshd.service"),
    },
    PackageMapping {
        logical: "wireguard-tools",
        binary: "wg",
        debian: Some("wireguard-tools"),
        rhel: Some("wireguard-tools"),
        arch: Some("wireguard-tools"),
        suse: Some("wireguard-tools"),
        alpine: Some("wireguard-tools"),
        service_unit: None,
    },
    PackageMapping {
        logical: "nftables",
        binary: "nft",
        debian: Some("nftables"),
        rhel: Some("nftables"),
        arch: Some("nftables"),
        suse: Some("nftables"),
        alpine: Some("nftables"),
        service_unit: None,
    },
    PackageMapping {
        logical: "bind-utils",
        binary: "dig",
        debian: Some("dnsutils"),
        rhel: Some("bind-utils"),
        arch: Some("bind"),
        suse: Some("bind-utils"),
        // Alpine names it bind-tools (NOT bind-utils).
        alpine: Some("bind-tools"),
        service_unit: None,
    },
    PackageMapping {
        // Required for Threat Intel: kernel-side IP set used by the
        // -m set --match-set rule we install in WOLFSTACK_THREAT_INTEL.
        // No daemon — just a CLI that talks to the xt_set kernel module.
        logical: "ipset",
        binary: "ipset",
        debian: Some("ipset"),
        rhel: Some("ipset"),
        arch: Some("ipset"),
        suse: Some("ipset"),
        alpine: Some("ipset"),
        service_unit: None,
    },
    PackageMapping {
        // GlusterFS distributed storage. The package ships both the `gluster`
        // CLI and the `glusterd` management daemon (service_unit below), so a
        // single install gives WolfStack everything it needs to manage a pool.
        // RHEL/CentOS need the centos-release-gluster repo for current builds,
        // but the base `glusterfs-server` name resolves on EL with that repo
        // (or EPEL) present; we surface a clear error if the package is absent.
        logical: "glusterfs",
        binary: "gluster",
        debian: Some("glusterfs-server"),
        rhel: Some("glusterfs-server"),
        arch: Some("glusterfs"),
        suse: Some("glusterfs"),
        alpine: Some("glusterfs"),
        service_unit: Some("glusterd"),
    },
];

/// Outcome of an install attempt. Returned to the API caller (and
/// shown in the System Check UI). `output` is the package manager's
/// stdout/stderr trimmed and capped — useful when "success" actually
/// means "already installed" or when the manager surfaces a useful
/// hint.
pub struct InstallReport {
    pub package: String,
    pub binary: String,
    pub success: bool,
    pub message: String,
    pub service_started: Option<bool>,
}

/// List the logical package names this endpoint accepts. Used by the
/// API handler for diagnostics and by tests to assert no typos crept
/// into the allowlist.
pub fn known_packages() -> Vec<&'static str> {
    PACKAGES.iter().map(|p| p.logical).collect()
}

/// Look up a package by its logical name, returning a borrow of the
/// allowlist row. Used internally + by the API handler when the
/// caller asks "is this name valid?".
fn lookup(logical: &str) -> Option<&'static PackageMapping> {
    PACKAGES.iter().find(|p| p.logical == logical)
}

/// Resolve the distro-specific package name for `logical`. Returns
/// `None` if the package isn't available on this distro — the caller
/// surfaces that as a refusal rather than blindly trying.
fn resolve(pkg: &PackageMapping, distro: DistroFamily) -> Option<&'static str> {
    match distro {
        DistroFamily::Debian => pkg.debian,
        DistroFamily::RedHat => pkg.rhel,
        DistroFamily::Arch => pkg.arch,
        DistroFamily::Suse => pkg.suse,
        DistroFamily::Alpine => pkg.alpine,
        DistroFamily::Unknown => pkg.debian, // best effort fall-through
    }
}

/// Cheap binary-on-PATH check. Used both before install (so an
/// already-installed binary short-circuits) and after install (so we
/// can tell the caller whether the package manager actually delivered
/// the binary they asked for).
fn binary_present(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {}", name)])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Install a logical package by its WolfStack-internal name (e.g.
/// `cron`, `qemu`). Detects the distro, resolves the right package
/// name, runs the package manager, then verifies the binary appears
/// on PATH. If a `service_unit` is set, also enables + starts it so
/// e.g. cronie actually runs jobs after install.
///
/// Returns `Ok(InstallReport)` on success OR no-op (already
/// installed). Returns `Err(String)` only on hard failures the caller
/// should surface as an error — unknown package, package manager
/// missing, package manager exited non-zero.
pub fn install(logical: &str) -> Result<InstallReport, String> {
    let mapping = lookup(logical)
        .ok_or_else(|| format!("unknown package '{}' — allowed: {}",
            logical, known_packages().join(", ")))?;

    // Already installed? Avoid the package-manager round-trip and the
    // confusing "X is up to date" output that comes back as success.
    if binary_present(mapping.binary) {
        return Ok(InstallReport {
            package: logical.to_string(),
            binary: mapping.binary.to_string(),
            success: true,
            message: format!("{} is already installed", mapping.binary),
            service_started: mapping.service_unit.map(svc_active),
        });
    }

    let distro = detect_distro();
    let resolved = resolve(mapping, distro)
        .ok_or_else(|| format!("'{}' is not available on this distro", logical))?;

    let (cmd, args): (&str, Vec<&str>) = match distro {
        DistroFamily::Debian => ("apt-get", vec!["install", "-y", resolved]),
        DistroFamily::RedHat => ("dnf", vec!["install", "-y", resolved]),
        DistroFamily::Arch => ("pacman", vec!["-Sy", "--noconfirm", resolved]),
        DistroFamily::Suse => ("zypper", vec!["install", "-y", resolved]),
        DistroFamily::Alpine => ("apk", vec!["add", "--no-cache", resolved]),
        DistroFamily::Unknown => ("apt-get", vec!["install", "-y", resolved]),
    };

    let out = Command::new(cmd)
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| format!("failed to run {}: {} (is it installed and in PATH?)", cmd, e))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let combined = format!("{}{}", stdout, stderr);
    // Cap at 4 KB — package managers can be chatty and we don't want
    // to push an 80 KB blob through the API.
    let trimmed = combined.chars().take(4096).collect::<String>();

    if !out.status.success() {
        return Err(format!("{} failed (exit {:?}): {}",
            cmd, out.status.code(), trimmed.trim()));
    }

    // Verify the binary actually appeared. Some package managers report
    // success even when the binary lives elsewhere (different name).
    if !binary_present(mapping.binary) {
        return Err(format!(
            "{} reported success but '{}' is still not on PATH — installed package: {}",
            cmd, mapping.binary, resolved));
    }

    // Enable + start the daemon if there is one. Failures here are
    // soft — the binary IS installed and the user can start it
    // manually if needed.
    let service_started = mapping.service_unit.map(|unit| {
        let _ = Command::new("systemctl").args(["enable", unit]).status();
        let started = Command::new("systemctl").args(["start", unit]).status()
            .map(|s| s.success()).unwrap_or(false);
        started
    });

    Ok(InstallReport {
        package: logical.to_string(),
        binary: mapping.binary.to_string(),
        success: true,
        message: format!("Installed '{}' ({}) via {}", logical, resolved, cmd),
        service_started,
    })
}

fn svc_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Visual TraceRoute one-click installer in WolfRouter and the
    /// System Check page both look up the logical name "traceroute"
    /// and assume every supported distro can resolve it. If somebody
    /// later refactors PACKAGES and drops a row, that breakage would
    /// be invisible until a real user hit it. Pin it down here.
    #[test]
    fn traceroute_mapping_resolves_for_all_distros() {
        let pkg = PACKAGES.iter().find(|p| p.logical == "traceroute")
            .expect("traceroute logical name must be in PACKAGES");
        for d in [
            DistroFamily::Debian,
            DistroFamily::RedHat,
            DistroFamily::Arch,
            DistroFamily::Suse,
        ] {
            assert_eq!(
                resolve(pkg, d), Some("traceroute"),
                "traceroute mapping missing for distro {:?}", d
            );
        }
        assert_eq!(pkg.binary, "traceroute");
    }

    /// Every logical name advertised through the System Check UI's
    /// "Install" button must be in this table — otherwise the button
    /// 400s with "unknown package". Keep the list of expected logical
    /// names checked here; failing this test means a callsite was
    /// added without a corresponding row.
    #[test]
    fn known_logical_names_are_present() {
        for logical in &["traceroute", "tcpdump", "conntrack", "bind-utils"] {
            assert!(
                PACKAGES.iter().any(|p| p.logical == *logical),
                "expected logical name {:?} in PACKAGES", logical
            );
        }
    }

    /// bind-utils is unusual: the package name differs across all four
    /// distros (dnsutils / bind-utils / bind / bind-utils). The
    /// System Check page surfaces dig-missing via the "bind-utils"
    /// logical name; if the per-distro names ever drift this test
    /// catches it.
    #[test]
    fn bind_utils_resolves_per_distro_names() {
        let pkg = PACKAGES.iter().find(|p| p.logical == "bind-utils")
            .expect("bind-utils logical name must be in PACKAGES");
        assert_eq!(resolve(pkg, DistroFamily::Debian), Some("dnsutils"));
        assert_eq!(resolve(pkg, DistroFamily::RedHat), Some("bind-utils"));
        assert_eq!(resolve(pkg, DistroFamily::Arch),   Some("bind"));
        assert_eq!(resolve(pkg, DistroFamily::Suse),   Some("bind-utils"));
        assert_eq!(pkg.binary, "dig");
    }
}
