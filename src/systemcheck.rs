// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Runtime dependency audit — iterates every tool / service / kernel
//! feature WolfStack touches and reports whether it's installed, whether
//! it's healthy, and what to do if it isn't.
//!
//! Drives the "System Check" button in Settings. The audit is intentionally
//! server-local — each cluster node runs it on demand and the UI displays
//! the result. Pairs with the AI agent to turn warnings into
//! actionable remediation.

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::Path;

use crate::installer::{detect_distro, DistroFamily};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepStatus {
    /// Green — installed, running, healthy.
    Ok,
    /// Amber — installed but something looks off (service stopped, wrong
    /// permissions, etc.). AI is most useful on these.
    Warning,
    /// Red — not installed, WolfStack functionality will be degraded.
    Missing,
    /// Grey — the host OS/architecture doesn't ship this, nothing to fix.
    Unsupported,
    /// Blue — not installed, but WolfStack installs this automatically the
    /// first time the feature that needs it is used (e.g. pppd gets pulled
    /// in when PPPoE WAN is configured, tcpdump when packet capture runs).
    /// Not a problem — just an informational note.
    AutoInstall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheck {
    pub name: String,
    pub category: String,
    pub status: DepStatus,
    pub version: Option<String>,
    /// Short human-readable explanation of what we found.
    pub detail: String,
    /// What the admin should do — populated on Warning/Missing.
    pub install_hint: Option<String>,
    /// Fires true when AI is genuinely useful here (i.e. it's not a
    /// plain "apt install X" fix but something where context matters).
    pub ai_helpful: bool,
    /// Logical package name the System Check UI's "Install" button
    /// passes to `POST /api/system/install-package`. Set this when the
    /// fix is straightforward (apt/pacman/dnf install X) and the
    /// package is in `installer::packages::PACKAGES`. `None` means no
    /// auto-install button — the user has to follow `install_hint`
    /// manually (e.g. for kernel modules, manual config, etc.).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub install_package: Option<String>,
}

/// Is a binary on PATH? Returns (found, version-string).
fn bin_check(cmd: &str, version_arg: &[&str]) -> (bool, Option<String>) {
    let which = Command::new("sh")
        .args(["-c", &format!("command -v {}", cmd)])
        .output();
    let found = matches!(which, Ok(o) if o.status.success() && !o.stdout.is_empty());
    if !found { return (false, None); }
    let ver = Command::new(cmd).args(version_arg).output().ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            let t = String::from_utf8_lossy(&o.stderr).to_string();
            let combined = if s.trim().is_empty() { t } else { s };
            combined.lines().next().map(|l| l.trim().to_string())
        });
    (true, ver)
}

/// Is a systemd unit active?
fn svc_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Distro-specific install hint string. Shown verbatim in the UI.
fn hint(name_deb: &str, name_rhel: &str, name_arch: &str, name_suse: &str) -> String {
    match detect_distro() {
        DistroFamily::Debian => format!("apt install {}", name_deb),
        DistroFamily::RedHat => format!("dnf install {}", name_rhel),
        DistroFamily::Arch   => format!("pacman -S {}", name_arch),
        DistroFamily::Suse   => format!("zypper install {}", name_suse),
        // Alpine package names usually match Debian's for our basic
        // toolchain (tcpdump, traceroute, conntrack-tools, etc.) —
        // good-enough hint string. Real install goes through the
        // package allowlist in installer::packages which has Alpine
        // names per-entry.
        DistroFamily::Alpine => format!("apk add {}", name_deb),
        DistroFamily::Unknown => format!("Install the '{}' package for your distro", name_deb),
    }
}

/// Run every check and produce the report. Cheap enough to call on
/// demand — nothing here is slow (all syscalls + local subprocess).
pub fn run_checks() -> Vec<DependencyCheck> {
    let mut out = Vec::new();
    let distro = detect_distro();
    let arch = std::env::consts::ARCH;
    let is_alpine = Path::new("/etc/alpine-release").exists();

    // ─── Core system ─────────────────────────────────────────────
    out.push(check_kernel());
    out.push(simple("systemctl", "Core", &["--version"],
        "service manager — WolfStack registers units via it",
        hint("systemd", "systemd", "systemd", "systemd"), false));
    out.push(simple("curl", "Core", &["--version"],
        "HTTP client — used for setup downloads + AI API",
        hint("curl", "curl", "curl", "curl"), false));
    out.push(simple("git", "Core", &["--version"],
        "source checkout for WolfNet/WolfStack builds",
        hint("git", "git", "git", "git"), false));
    out.push(simple("modprobe", "Core", &["--version"],
        "kernel module loader — needed for usbip/tun",
        hint("kmod", "kmod", "kmod", "kmod"), false));
    out.push(simple("pgrep", "Core", &["--version"],
        "process lookup — used to check dnsmasq/pppd state",
        hint("procps", "procps-ng", "procps-ng", "procps"), false));

    // ─── Container runtime ───────────────────────────────────────
    out.push(check_docker());
    out.push(check_containerd());
    out.push(simple("lxc-ls", "Containers", &["--version"],
        "system container management",
        hint("lxc", "lxc", "lxc", "lxc"), true));

    // ─── Virtualisation ──────────────────────────────────────────
    out.push(check_qemu());
    // Proxmox isn't required — it's an integration — so report OK when
    // absent rather than Missing, and Ok when present.
    if Path::new("/usr/bin/pveversion").exists() {
        let ver = Command::new("pveversion").output().ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(|s| s.to_string()));
        out.push(DependencyCheck {
            name: "Proxmox VE".into(), category: "Virtualisation".into(),
            status: DepStatus::Ok, version: ver,
            detail: "Proxmox hypervisor detected — PVE integration active".into(),
            install_hint: None, ai_helpful: false,
            install_package: None,
        });
    }

    // ─── Networking ──────────────────────────────────────────────
    out.push(simple("iptables", "Networking", &["--version"],
        "firewall rule compiler (WolfRouter, container NAT)",
        hint("iptables", "iptables", "iptables", "iptables"), false));
    out.push(simple("ip", "Networking", &["-V"],
        "iproute2 — WolfStack configures bridges/VLANs via this",
        hint("iproute2", "iproute", "iproute2", "iproute2"), false));
    out.push(check_brctl());
    out.push(simple("dnsmasq", "Networking", &["--version"],
        "per-LAN DHCP/DNS; without it LAN segments can't serve leases",
        hint("dnsmasq-base", "dnsmasq", "dnsmasq", "dnsmasq"), true));
    out.push(simple("socat", "Networking", &["-V"],
        "TCP/UNIX socket bridge — VM serial consoles",
        hint("socat", "socat", "socat", "socat"), false));
    out.push(simple_auto("ethtool", "Networking", &["--version"],
        "VLAN passthrough NIC offload tuning",
        hint("ethtool", "ethtool", "ethtool", "ethtool")));
    out.push(simple_auto("tcpdump", "Networking", &["--version"],
        "packet capture (Packets tab in WolfRouter)",
        hint("tcpdump", "tcpdump", "tcpdump", "tcpdump")));
    out.push(check_traceroute());
    out.push(check_dig());
    out.push(simple_auto("pppd", "Networking", &["--version"],
        "PPPoE dial-up (WolfRouter WAN)",
        hint("ppp", "ppp", "ppp", "ppp")));
    out.push(simple_auto("pppoe", "Networking", &["-V"],
        "PPPoE plugin (WolfRouter WAN)",
        hint("pppoe", "rp-pppoe", "rp-pppoe", "rp-pppoe")));
    out.push(check_tun());

    // ─── Storage ─────────────────────────────────────────────────
    out.push(check_fuse3());
    out.push(simple_auto("s3fs", "Storage", &["--version"],
        "S3 bucket mounts (Storage → S3)",
        hint("s3fs", "s3fs-fuse", "s3fs-fuse", "s3fs")));
    out.push(simple_auto("mount.nfs", "Storage", &[],
        "NFS mounts (Storage → NFS)",
        hint("nfs-common", "nfs-utils", "nfs-utils", "nfs-client")));

    // ─── USB passthrough ────────────────────────────────────────
    out.push(check_kernel_module("vhci_hcd", "USB",
        "USB virtualisation (client) — attach remote USB via WolfUSB"));
    out.push(check_kernel_module("usbip_host", "USB",
        "USB sharing (server) — export local USB to the cluster"));

    // ─── Scheduling / cron ──────────────────────────────────────
    // Arch ships zero cron daemon by default; Settings → Cron and any
    // crontab-based feature silently fail with "command not found"
    // until cronie is installed. Surface as a Missing finding with the
    // one-click installer hooked up to /api/system/install-package.
    out.push(check_cron());

    // ─── Architecture-specific guards ───────────────────────────
    if arch == "powerpc64" || arch == "powerpc64le" {
        out.push(DependencyCheck {
            name: "ppc64le QEMU".into(), category: "Virtualisation".into(),
            status: DepStatus::Warning, version: None,
            detail: "IBM Power architecture — some VM backends (amd64 ISOs) won't boot here".into(),
            install_hint: Some("Use ppc64le ISOs for VM installs".into()),
            ai_helpful: true,
            install_package: None,
        });
    }
    if is_alpine {
        // Silence the noise: things known to be unavailable on Alpine
        // get flipped from Missing to Unsupported so the UI doesn't
        // waste the user's attention.
        for c in out.iter_mut() {
            let unsupported = matches!(c.name.as_str(),
                "docker" | "s3fs" | "dnsmasq" | "mount.nfs")
                && matches!(c.status, DepStatus::Missing);
            if unsupported {
                c.status = DepStatus::Unsupported;
                c.detail = format!("{} — not available on Alpine", c.detail);
                c.install_hint = None;
            }
        }
    }
    let _ = distro;  // reserved for future distro-specific tweaks

    out
}

/// Minimal check: `bin present?` with install hint. Used for the
/// "just need it on PATH" checks.
fn simple(
    cmd: &str,
    category: &str,
    version_args: &[&str],
    why: &str,
    install: String,
    ai_helpful: bool,
) -> DependencyCheck {
    simple_inner(cmd, category, version_args, why, install, ai_helpful, false)
}

/// Same as `simple`, but flags the binary as one WolfStack auto-installs
/// the first time the feature that needs it is used. When missing we
/// report AutoInstall (blue, informational) instead of Missing (red).
fn simple_auto(
    cmd: &str,
    category: &str,
    version_args: &[&str],
    why: &str,
    install: String,
) -> DependencyCheck {
    simple_inner(cmd, category, version_args, why, install, false, true)
}

fn simple_inner(
    cmd: &str,
    category: &str,
    version_args: &[&str],
    why: &str,
    install: String,
    ai_helpful: bool,
    auto_install: bool,
) -> DependencyCheck {
    let (found, ver) = bin_check(cmd, version_args);
    let status = if found { DepStatus::Ok }
                 else if auto_install { DepStatus::AutoInstall }
                 else { DepStatus::Missing };
    let detail = if found {
        format!("Installed — {}", why)
    } else if auto_install {
        format!("Not installed — WolfStack installs this automatically when {} is used", why)
    } else {
        format!("Not installed — {}", why)
    };
    DependencyCheck {
        name: cmd.to_string(),
        category: category.to_string(),
        status,
        version: ver,
        detail,
        install_hint: if found { None } else { Some(install) },
        ai_helpful,
        install_package: None,
    }
}

fn check_docker() -> DependencyCheck {
    let (found, ver) = bin_check("docker", &["--version"]);
    if !found {
        return DependencyCheck {
            name: "docker".into(), category: "Containers".into(),
            status: DepStatus::Missing, version: None,
            detail: "Docker not installed — app store Docker installs will fail".into(),
            install_hint: Some(hint("docker.io", "docker-ce", "docker", "docker")),
            ai_helpful: true,
            install_package: None,
        };
    }
    // Can we actually talk to the daemon? `docker info` exits non-zero
    // if the socket is not reachable / the service is stopped / the
    // user lacks permission. This catches the "installed but broken"
    // case the user specifically mentioned.
    let info = Command::new("docker").arg("info").output();
    let daemon_ok = matches!(info.as_ref(), Ok(o) if o.status.success());
    if daemon_ok {
        return DependencyCheck {
            name: "docker".into(), category: "Containers".into(),
            status: DepStatus::Ok, version: ver,
            detail: "Docker installed, daemon reachable".into(),
            install_hint: None, ai_helpful: false,
            install_package: None,
        };
    }
    // It's there but something's off. Build a detailed reason from the
    // stderr of `docker info` so the AI has something useful to chew on.
    let stderr = info.as_ref().ok()
        .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
        .unwrap_or_default();
    let svc_up = svc_active("docker");
    let reason = if !svc_up {
        "systemd `docker` service is not active".to_string()
    } else if stderr.to_lowercase().contains("permission denied") {
        "cannot access /var/run/docker.sock — user missing `docker` group?".into()
    } else if stderr.trim().is_empty() {
        "`docker info` failed without a clear error".into()
    } else {
        format!("`docker info` error: {}", stderr.lines().next().unwrap_or("").trim())
    };
    DependencyCheck {
        name: "docker".into(), category: "Containers".into(),
        status: DepStatus::Warning, version: ver,
        detail: format!("Installed but not healthy — {}", reason),
        install_hint: Some(if !svc_up {
            "systemctl enable --now docker".into()
        } else {
            "usermod -aG docker $USER && newgrp docker".into()
        }),
        ai_helpful: true,
        install_package: None,
    }
}

fn check_containerd() -> DependencyCheck {
    let (found, ver) = bin_check("containerd", &["--version"]);
    let running = svc_active("containerd");
    if !found {
        return DependencyCheck {
            name: "containerd".into(), category: "Containers".into(),
            status: DepStatus::Missing, version: None,
            detail: "containerd not installed — Docker will not start without it".into(),
            install_hint: Some(hint("containerd", "containerd.io", "containerd", "containerd")),
            ai_helpful: false,
            install_package: None,
        };
    }
    DependencyCheck {
        name: "containerd".into(), category: "Containers".into(),
        status: if running { DepStatus::Ok } else { DepStatus::Warning },
        version: ver,
        detail: if running { "containerd service active".into() }
                else       { "containerd installed but service is not running".into() },
        install_hint: if running { None } else { Some("systemctl enable --now containerd".into()) },
        ai_helpful: !running,
        install_package: None,
    }
}

fn check_qemu() -> DependencyCheck {
    // Try the arch-specific binary first, then fall back to generic
    // `qemu-system-x86_64` if we're on amd64.
    let arch = std::env::consts::ARCH;
    let cmd = match arch {
        "aarch64" => "qemu-system-aarch64",
        "powerpc64" | "powerpc64le" => "qemu-system-ppc64",
        _ => "qemu-system-x86_64",
    };
    let (found, ver) = bin_check(cmd, &["--version"]);
    DependencyCheck {
        name: format!("QEMU ({})", cmd),
        category: "Virtualisation".into(),
        status: if found { DepStatus::Ok } else { DepStatus::Missing },
        version: ver,
        detail: if found { "KVM VM backend available".into() }
                else     { "No QEMU binary for this architecture — VM installs will fail".into() },
        install_hint: if found { None } else {
            Some(hint(
                "qemu-system-x86", "qemu-kvm", "qemu-full", "qemu-kvm",
            ))
        },
        ai_helpful: !found,
        install_package: if found { None } else { Some("qemu".into()) },
    }
}

fn check_brctl() -> DependencyCheck {
    // `brctl` is deprecated in favour of `ip link`; consider present
    // if EITHER exists so we don't chase a false positive on Arch.
    let brctl_ok = bin_check("brctl", &["--version"]).0;
    let ip_ok = bin_check("ip", &["-V"]).0;
    if brctl_ok || ip_ok {
        return DependencyCheck {
            name: "bridge-utils".into(), category: "Networking".into(),
            status: DepStatus::Ok, version: None,
            detail: if brctl_ok { "brctl present".into() }
                    else        { "ip link (iproute2) present — brctl not required".into() },
            install_hint: None, ai_helpful: false,
            install_package: None,
        };
    }
    DependencyCheck {
        name: "bridge-utils".into(), category: "Networking".into(),
        status: DepStatus::Missing, version: None,
        detail: "Neither brctl nor iproute2 found — bridges can't be created".into(),
        install_hint: Some(hint("bridge-utils", "bridge-utils", "bridge-utils", "bridge-utils")),
        ai_helpful: false,
        install_package: None,
    }
}

fn check_tun() -> DependencyCheck {
    let exists = Path::new("/dev/net/tun").exists();
    DependencyCheck {
        name: "/dev/net/tun".into(), category: "Networking".into(),
        status: if exists { DepStatus::Ok } else { DepStatus::Warning },
        version: None,
        detail: if exists { "TUN/TAP device available — WolfNet overlay works".into() }
                else {
                    "TUN device missing — unprivileged LXC containers need a cgroup device allowlist to create it".into()
                },
        install_hint: if exists { None } else {
            Some("modprobe tun && mkdir -p /dev/net && mknod /dev/net/tun c 10 200".into())
        },
        ai_helpful: !exists,
        install_package: None,
    }
}

fn check_fuse3() -> DependencyCheck {
    // Look for libfuse3.so.* in the standard lib dirs. This is cheaper
    // and more reliable than shelling out to pkg-config.
    let found = ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu"]
        .iter()
        .any(|dir| std::fs::read_dir(dir).ok().is_some_and(|entries|
            entries.flatten().any(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("libfuse3.so")
            })
        ));
    DependencyCheck {
        name: "fuse3".into(), category: "Storage".into(),
        status: if found { DepStatus::Ok } else { DepStatus::Missing },
        version: None,
        detail: if found { "libfuse3 available — s3fs/sshfs mounts work".into() }
                else     { "libfuse3 not found — user-space mounts (S3, SSHFS, WolfDisk) will fail".into() },
        install_hint: if found { None } else { Some(hint("libfuse3-3", "fuse3", "fuse3", "fuse3")) },
        ai_helpful: !found,
        install_package: None,
    }
}

fn check_kernel_module(modname: &str, category: &str, why: &str) -> DependencyCheck {
    // Considered "Ok" if the module is loaded OR if the module file
    // exists on disk (just not loaded yet). Otherwise, missing.
    let loaded = Command::new("lsmod").output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout)
            .lines().any(|l| l.split_whitespace().next() == Some(modname)))
        .unwrap_or(false);
    if loaded {
        return DependencyCheck {
            name: format!("{} (kernel module)", modname), category: category.into(),
            status: DepStatus::Ok, version: None,
            detail: format!("{} loaded", modname),
            install_hint: None, ai_helpful: false,
            install_package: None,
        };
    }
    // Does modprobe know about it without actually loading?
    let known = Command::new("modprobe").args(["-n", modname])
        .output().map(|o| o.status.success()).unwrap_or(false);
    DependencyCheck {
        name: format!("{} (kernel module)", modname), category: category.into(),
        status: if known { DepStatus::Warning } else { DepStatus::Missing },
        version: None,
        detail: if known { format!("{} present but not loaded — {}", modname, why) }
                else     { format!("{} not available — {}", modname, why) },
        install_hint: if known {
            Some(format!("modprobe {}", modname))
        } else {
            Some(hint(
                "linux-modules-extra-$(uname -r)",
                "kernel-modules-extra",
                "linux",
                "kernel-default-extra",
            ))
        },
        ai_helpful: !known,
        install_package: None,
    }
}

/// Visual TraceRoute (and the /api/traceroute endpoint) shells out to
/// `traceroute`. It's not in the core diag-tool bundle and Ubuntu's
/// minimal / cloud images don't ship it. Surface it on the System
/// Check page with a one-click install button so an operator who
/// opens the WolfRouter Trace tab knows up front whether they need
/// to install something. Adam Cogswell 2026-04-30: "if traceroute is
/// missing offer the user the chance to install it from a button".
fn check_traceroute() -> DependencyCheck {
    let (found, ver) = bin_check("traceroute", &["--version"]);
    let status = if found { DepStatus::Ok } else { DepStatus::Missing };
    let detail = if found {
        "Installed — Visual TraceRoute tab in WolfRouter renders the path map.".into()
    } else {
        "Not installed — the WolfRouter Visual TraceRoute tab will fail. Common on Ubuntu minimal / cloud images that omit it from the default package set.".into()
    };
    DependencyCheck {
        name: "traceroute".into(),
        category: "Networking".into(),
        status,
        version: ver,
        detail,
        install_hint: if found { None } else {
            Some(hint("traceroute", "traceroute", "traceroute", "traceroute"))
        },
        ai_helpful: false,
        // One-click install hooked to /api/system/install-package via
        // the "traceroute" mapping added in installer/packages.rs.
        install_package: if found { None } else { Some("traceroute".into()) },
    }
}

/// `dig` (from bind-utils / dnsutils / bind) is used by WolfRouter's
/// topology view for reverse-DNS router labels and by the forwarder
/// probe in `networking::router::dns`. Missing dig fails silently —
/// the user just sees IPs instead of hostnames in the rack view —
/// which is degraded UX with no in-app explanation. Surface it on the
/// System Check page with a one-click install so the operator knows
/// why their topology labels look bare. The package name varies per
/// distro (dnsutils on Debian, bind on Arch, bind-utils on RHEL/SUSE),
/// so use the "bind-utils" logical name from installer/packages.rs.
fn check_dig() -> DependencyCheck {
    let (found, ver) = bin_check("dig", &["-v"]);
    let status = if found { DepStatus::Ok } else { DepStatus::Missing };
    let detail = if found {
        "Installed — WolfRouter topology view can resolve reverse-DNS labels for routers and clients.".into()
    } else {
        "Not installed — WolfRouter topology view will show IP addresses instead of hostnames, and DNS forwarder probes report unreachable. Common on Arch and minimal-container images.".into()
    };
    DependencyCheck {
        name: "dig".into(),
        category: "Networking".into(),
        status,
        version: ver,
        detail,
        install_hint: if found { None } else {
            Some(hint("dnsutils", "bind-utils", "bind", "bind-utils"))
        },
        ai_helpful: false,
        // Logical name "bind-utils" maps to the right package per distro
        // in installer/packages.rs (dnsutils on Debian, bind on Arch).
        install_package: if found { None } else { Some("bind-utils".into()) },
    }
}

fn check_cron() -> DependencyCheck {
    let (found, ver) = bin_check("crontab", &["-V"]);
    // The binary alone isn't enough — without a running daemon, jobs
    // never fire. Probe the most common unit names across distros.
    let svc_up = svc_active("cronie") || svc_active("cron")
        || svc_active("crond") || svc_active("vixie-cron");
    let status = if !found { DepStatus::Missing }
                 else if !svc_up { DepStatus::Warning }
                 else { DepStatus::Ok };
    let detail = if !found {
        "No `crontab` on PATH — Settings → Cron and any scheduled task feature will fail. Common on Arch (no cron ships by default) and minimal containers.".into()
    } else if !svc_up {
        "crontab installed but no cron daemon (cronie/cron/crond) is active — jobs won't run until you enable+start the service.".into()
    } else {
        "crontab + active cron daemon — scheduled jobs will run.".into()
    };
    let install_hint = if !found {
        Some(hint("cron", "cronie", "cronie", "cron"))
    } else if !svc_up {
        Some("systemctl enable --now cronie  (or `cron` on Debian/Ubuntu)".into())
    } else { None };
    DependencyCheck {
        name: "cron".into(),
        category: "Scheduling".into(),
        status,
        version: ver,
        detail,
        install_hint,
        ai_helpful: false,
        // Wire the one-click installer for the Missing case. When the
        // daemon's just stopped we don't auto-install (already there)
        // — the user just needs to start it; the hint above tells them.
        install_package: if !found { Some("cron".into()) } else { None },
    }
}

fn check_kernel() -> DependencyCheck {
    let ver = Command::new("uname").arg("-r").output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().to_string().into());
    let ver_str = ver.clone().unwrap_or_default();
    let (major, minor) = parse_kernel_version(&ver_str);
    let too_old = major < 5 || (major == 5 && minor < 4);
    DependencyCheck {
        name: "Linux kernel".into(), category: "Core".into(),
        status: if too_old { DepStatus::Warning } else { DepStatus::Ok },
        version: ver,
        detail: if too_old {
            format!("Kernel {} is older than 5.4 — some features (WolfNet, cgroup v2) may not work", ver_str)
        } else {
            format!("Kernel {} is fine", ver_str)
        },
        install_hint: if too_old {
            Some("Upgrade your kernel package — WolfStack needs 5.4+ for WolfNet/cgroup2".into())
        } else { None },
        ai_helpful: too_old,
        install_package: None,
    }
}

fn parse_kernel_version(s: &str) -> (u32, u32) {
    let mut parts = s.split(|c: char| !c.is_ascii_digit());
    let maj = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let min = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    (maj, min)
}
