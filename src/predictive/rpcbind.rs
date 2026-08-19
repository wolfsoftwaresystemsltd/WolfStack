// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Switching an unused portmapper off — the action behind the
//! `rpcbind-portmap` finding in [`super::security_posture`].
//!
//! WHY THIS EXISTS: `setup.sh` installs `nfs-common` (WolfStack mounts NFS
//! shares), and on Debian/Ubuntu that pulls in `rpcbind` as an automatic
//! dependency whose socket unit listens on `0.0.0.0:111` — tcp and udp. So a
//! WolfStack host on a public IP with no host firewall answers portmapper
//! queries from the whole internet, which is a 7-28x UDP amplification vector
//! (CERT TA14-017A). CERT-Bund scans for it and reports it to the hosting
//! provider's abuse desk, which is how ours surfaced: a BSI notice forwarded by
//! Hetzner for asset-mirror-1 on 2026-08-19, four days after that host was
//! built. The analyzer had already flagged it; nothing acted on the finding.
//!
//! Two callers:
//!   * `wolfstack --secure-rpcbind`, run by the installer right after the
//!     package step, so a fresh install never opens 111 in the first place.
//!   * `POST /api/proposals/{id}/apply`, so an existing install can act on the
//!     finding from the inbox instead of copy-pasting four commands.
//!
//! Both go through [`lock_down`], and both refuse when the host actually uses
//! RPC — masking rpcbind under a live NFS server would break every export, and
//! silently breaking a working service to close a port is not a fix. The
//! decision is made from [`inspect`]: what is registered with the local
//! portmapper, what is mounted, what is exported, and whether an NFS server
//! unit is running.
//!
//! [`restore`] is the other half of the contract. WolfStack can turn a host
//! INTO an NFS server (`gateway::nfs` writes `/etc/exports.d` and runs
//! `exportfs`), and a masked rpcbind would make that fail — so every path that
//! enables NFS serving unmasks it again first.

use std::process::Command;

/// Both units matter. `rpcbind.socket` is what actually holds port 111 under
/// systemd socket activation, so stopping only `rpcbind.service` leaves the
/// listener in place — the mistake that makes "I disabled rpcbind" reports
/// disagree with what the port scan says.
const UNITS: [&str; 2] = ["rpcbind.socket", "rpcbind.service"];

/// What, if anything, on this host is using RPC.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RpcbindUsage {
    /// Programs registered with the local portmapper, excluding `portmapper`
    /// itself (which is always registered and proves nothing).
    pub registrations: Vec<String>,
    /// Mounted NFS filesystems (`nfs` or `nfs4`).
    pub nfs_mounts: Vec<String>,
    /// Non-comment export lines from `/etc/exports` and `/etc/exports.d/*`.
    pub exports: Vec<String>,
    /// `nfs-server` / `nfs-kernel-server` active.
    pub nfs_server_active: bool,
    /// True when rpcbind isn't installed at all — nothing to do, and NOT the
    /// same as "installed but idle".
    pub absent: bool,
}

impl RpcbindUsage {
    /// Whether rpcbind is carrying real work. Anything in any of the four
    /// buckets counts: an NFSv3 client mount needs the local `rpc.statd`
    /// registration for locking, and an export needs remote clients to be able
    /// to query the portmapper.
    pub fn load_bearing(&self) -> bool {
        !self.registrations.is_empty()
            || !self.nfs_mounts.is_empty()
            || !self.exports.is_empty()
            || self.nfs_server_active
    }

    /// One line an operator can act on, listing what was found.
    pub fn summary(&self) -> String {
        if self.absent {
            return "rpcbind is not installed on this host".to_string();
        }
        if !self.load_bearing() {
            return "nothing on this host uses RPC: only `portmapper` is \
                    registered, no NFS mounts, no exports, no NFS server"
                .to_string();
        }
        let mut parts = Vec::new();
        if !self.registrations.is_empty() {
            parts.push(format!("RPC programs registered: {}", self.registrations.join(", ")));
        }
        if !self.nfs_mounts.is_empty() {
            parts.push(format!("NFS mounts: {}", self.nfs_mounts.join(", ")));
        }
        if !self.exports.is_empty() {
            parts.push(format!("{} export(s) configured", self.exports.len()));
        }
        if self.nfs_server_active {
            parts.push("NFS server is running".to_string());
        }
        parts.join("; ")
    }
}

/// Programs other than `portmapper` in `rpcinfo -p` output.
///
/// Parsed rather than pattern-matched on the whole blob so a service whose name
/// merely CONTAINS "portmapper" can't hide behind the filter. Lines look like
/// `    100003    3   tcp   2049  nfs`, with a `program vers proto port service`
/// header first.
fn parse_rpcinfo(stdout: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 4 fields = a registration with no service name resolved; 5 = named.
        if fields.len() < 4 { continue; }
        if fields[0] == "program" { continue; }             // header
        if fields[0].parse::<u32>().is_err() { continue; }  // not a data row
        let service = fields.get(4).copied().unwrap_or(fields[0]);
        if service == "portmapper" || service == "rpcbind" { continue; }
        if !out.iter().any(|s| s == service) {
            out.push(service.to_string());
        }
    }
    out
}

/// Export definitions in an `/etc/exports`-style file: every line that isn't
/// blank and isn't a comment.
fn parse_exports(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// True when a unit is present on the system (any state except "not-found").
fn unit_exists(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["cat", unit])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn unit_is_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

/// Sample what the host is using RPC for. Blocking (runs `rpcinfo`, `findmnt`
/// and `systemctl`) — call it from `web::block` on the async side.
pub fn inspect() -> RpcbindUsage {
    if !unit_exists("rpcbind.socket") && !unit_exists("rpcbind.service") {
        return RpcbindUsage { absent: true, ..Default::default() };
    }

    // Ask the LOCAL portmapper only. A remote query would tell us about
    // someone else's host, and on a masked rpcbind this simply fails, which
    // correctly reads as "nothing registered".
    let registrations = Command::new("rpcinfo")
        .args(["-p", "127.0.0.1"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_rpcinfo(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();

    let nfs_mounts = Command::new("findmnt")
        .args(["-n", "-t", "nfs,nfs4", "-o", "TARGET"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // /etc/exports plus the drop-in dir WolfStack's own NFS gateway writes to
    // (`gateway::nfs` never edits /etc/exports itself), so a share published
    // through the UI counts as load-bearing.
    let mut exports = std::fs::read_to_string("/etc/exports")
        .map(|c| parse_exports(&c))
        .unwrap_or_default();
    if let Ok(dir) = std::fs::read_dir("/etc/exports.d") {
        for entry in dir.flatten() {
            if let Ok(c) = std::fs::read_to_string(entry.path()) {
                exports.extend(parse_exports(&c));
            }
        }
    }

    // Debian/Ubuntu call it nfs-kernel-server, Red Hat/SUSE/Arch nfs-server.
    let nfs_server_active = ["nfs-server", "nfs-kernel-server"]
        .iter()
        .any(|u| unit_is_active(u));

    RpcbindUsage { registrations, nfs_mounts, exports, nfs_server_active, absent: false }
}

/// Anything still listening on port 111, as `ss` sees it. Used to VERIFY the
/// lockdown rather than trusting the exit status of `systemctl mask` — the
/// whole class of bug here is a unit that reports success while the socket
/// stays bound.
fn listeners_on_111() -> Vec<String> {
    Command::new("ss")
        .args(["-lntup"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| port_111_in_ss_line(l))
                .map(|l| l.split_whitespace().take(5).collect::<Vec<_>>().join(" "))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether an `ss -lntup` line is a listener on port 111.
///
/// Matches the LOCAL address column exactly (`…:111`), so `10.0.0.111:22` and a
/// peer address of `1.2.3.4:1111` don't read as a portmapper.
fn port_111_in_ss_line(line: &str) -> bool {
    line.split_whitespace()
        .nth(4)
        .and_then(|local| local.rsplit(':').next())
        .map(|port| port == "111")
        .unwrap_or(false)
}

/// Stop and mask both rpcbind units, then verify port 111 is unbound.
///
/// Refuses (without touching anything) when [`inspect`] says the host is using
/// RPC — the caller shows that summary to the operator, who can firewall 111 to
/// their storage network instead. Masking, not just disabling: a disabled unit
/// can still be pulled back up by a dependency or a package update, and this
/// port must stay shut once closed.
pub fn lock_down() -> Result<String, String> {
    let usage = inspect();
    if usage.absent {
        return Ok("rpcbind is not installed — nothing to do".to_string());
    }
    if usage.load_bearing() {
        return Err(format!(
            "rpcbind is in use on this host, so switching it off would break \
             NFS: {}. Firewall port 111 to your storage network instead.",
            usage.summary(),
        ));
    }

    // `disable --now` first so the units are stopped and un-wanted, then mask.
    // Masking a running unit leaves it running until the next boot, so the
    // order matters: a mask-then-stop would report success with 111 still open.
    let disable = Command::new("systemctl")
        .arg("disable")
        .arg("--now")
        .args(UNITS)
        .output()
        .map_err(|e| format!("could not run systemctl disable: {}", e))?;
    if !disable.status.success() {
        return Err(format!(
            "systemctl disable --now {} failed: {}",
            UNITS.join(" "),
            String::from_utf8_lossy(&disable.stderr).trim(),
        ));
    }
    let mask = Command::new("systemctl")
        .arg("mask")
        .args(UNITS)
        .output()
        .map_err(|e| format!("could not run systemctl mask: {}", e))?;
    if !mask.status.success() {
        return Err(format!(
            "systemctl mask {} failed: {}",
            UNITS.join(" "),
            String::from_utf8_lossy(&mask.stderr).trim(),
        ));
    }

    // Verify, don't assume.
    let still = listeners_on_111();
    if !still.is_empty() {
        return Err(format!(
            "rpcbind units were masked but port 111 is still bound: {}. \
             Check for a second RPC implementation or a container publishing \
             111, and firewall the port.",
            still.join(" | "),
        ));
    }

    tracing::info!("rpcbind: units masked, port 111 no longer bound");
    Ok("rpcbind stopped and masked — port 111 is no longer listening. \
        Publishing an NFS share through WolfStack re-enables it automatically; \
        by hand it is `systemctl unmask rpcbind.socket rpcbind.service`."
        .to_string())
}

/// Bring rpcbind back — the counterpart to [`lock_down`], called before this
/// host starts serving NFS. Idempotent: on a host where rpcbind was never
/// masked this just re-asserts enabled+started.
///
/// Without this, closing port 111 at install time would silently break
/// WolfStack's own NFS share publishing: `rpc.mountd` can't register and
/// `nfs-server.service` wants `rpcbind.socket`, which a masked unit refuses.
pub fn restore() -> Result<String, String> {
    if !unit_exists("rpcbind.socket") && !unit_exists("rpcbind.service") {
        // Masked units still "exist" (systemctl cat succeeds on the /dev/null
        // symlink), so reaching here means the package genuinely isn't there.
        return Err("rpcbind is not installed — install nfs-common (Debian/Ubuntu) \
                    or nfs-utils (RHEL/SUSE/Arch) before serving NFS"
            .to_string());
    }
    let unmask = Command::new("systemctl")
        .arg("unmask")
        .args(UNITS)
        .output()
        .map_err(|e| format!("could not run systemctl unmask: {}", e))?;
    if !unmask.status.success() {
        return Err(format!(
            "systemctl unmask {} failed: {}",
            UNITS.join(" "),
            String::from_utf8_lossy(&unmask.stderr).trim(),
        ));
    }
    let enable = Command::new("systemctl")
        .arg("enable")
        .arg("--now")
        .args(UNITS)
        .output()
        .map_err(|e| format!("could not run systemctl enable: {}", e))?;
    if !enable.status.success() {
        return Err(format!(
            "systemctl enable --now {} failed: {}",
            UNITS.join(" "),
            String::from_utf8_lossy(&enable.stderr).trim(),
        ));
    }
    tracing::info!("rpcbind: units unmasked and started for NFS serving");
    Ok("rpcbind unmasked and running".to_string())
}

/// Whether a proposal is the `rpcbind-portmap` exposure finding, and so may be
/// applied by [`lock_down`].
///
/// Gates on the analyzer's own identifiers — finding type plus a port-111
/// resource id (`0.0.0.0:111/udp`) — so no other exposure finding, and nothing
/// an API caller invents, can reach the action.
pub fn is_rpcbind_exposure(p: &crate::predictive::Proposal) -> bool {
    if p.finding_type != super::security_posture::FINDING_SERVICE_PUBLIC {
        return false;
    }
    p.scope
        .resource_id
        .as_deref()
        .map(resource_id_is_port_111)
        .unwrap_or(false)
}

/// `0.0.0.0:111/udp` / `1.2.3.4:111/tcp` / `[::]:111` → true.
///
/// Splits the protocol suffix off and compares the port exactly, so
/// `10.0.0.111:2049` (an address ENDING in 111) is not mistaken for a
/// portmapper.
fn resource_id_is_port_111(resource_id: &str) -> bool {
    let without_proto = resource_id
        .rsplit_once('/')
        .map(|(head, _)| head)
        .unwrap_or(resource_id);
    without_proto
        .rsplit_once(':')
        .map(|(_, port)| port == "111")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpcinfo_with_only_the_portmapper_registers_nothing() {
        let out = "   program vers proto   port  service\n\
                   \x20   100000    4   tcp    111  portmapper\n\
                   \x20   100000    3   udp    111  portmapper\n";
        assert!(parse_rpcinfo(out).is_empty());
    }

    #[test]
    fn rpcinfo_reports_real_registrations() {
        let out = "   program vers proto   port  service\n\
                   \x20   100000    4   tcp    111  portmapper\n\
                   \x20   100003    3   tcp   2049  nfs\n\
                   \x20   100005    3   udp  20048  mountd\n\
                   \x20   100024    1   udp  57000  status\n";
        let regs = parse_rpcinfo(out);
        assert_eq!(regs, vec!["nfs", "mountd", "status"]);
    }

    #[test]
    fn rpcinfo_rows_without_a_service_name_still_count() {
        // `rpcinfo -p` prints the program number with no name when
        // /etc/rpc has no entry for it. That is still a registration.
        let out = "   program vers proto   port  service\n\
                   \x20   100000    4   tcp    111  portmapper\n\
                   \x20   391002    2   tcp    698\n";
        assert_eq!(parse_rpcinfo(out), vec!["391002"]);
    }

    #[test]
    fn exports_ignore_comments_and_blanks() {
        let contents = "# /etc/exports\n\n\
                        /srv/media 10.0.0.0/24(rw,sync)\n\
                        \x20  # indented comment\n\
                        /srv/backup 10.0.0.5(ro)\n";
        assert_eq!(
            parse_exports(contents),
            vec![
                "/srv/media 10.0.0.0/24(rw,sync)".to_string(),
                "/srv/backup 10.0.0.5(ro)".to_string(),
            ],
        );
    }

    #[test]
    fn an_idle_host_is_not_load_bearing_but_any_single_use_is() {
        let idle = RpcbindUsage::default();
        assert!(!idle.load_bearing());
        assert!(idle.summary().contains("nothing on this host uses RPC"));

        for usage in [
            RpcbindUsage { registrations: vec!["nfs".into()], ..Default::default() },
            RpcbindUsage { nfs_mounts: vec!["/mnt/nas".into()], ..Default::default() },
            RpcbindUsage { exports: vec!["/srv 10.0.0.0/24(rw)".into()], ..Default::default() },
            RpcbindUsage { nfs_server_active: true, ..Default::default() },
        ] {
            assert!(usage.load_bearing(), "should be load-bearing: {:?}", usage);
            assert!(!usage.summary().contains("nothing on this host uses RPC"));
        }
    }

    #[test]
    fn an_absent_rpcbind_reports_absent_not_idle() {
        let usage = RpcbindUsage { absent: true, ..Default::default() };
        assert!(!usage.load_bearing());
        assert_eq!(usage.summary(), "rpcbind is not installed on this host");
    }

    #[test]
    fn ss_lines_match_only_a_real_port_111_listener() {
        let listener = "udp   UNCONN 0      0      0.0.0.0:111        0.0.0.0:*    users:((\"rpcbind\",pid=1,fd=5))";
        let v6 = "tcp   LISTEN 0      4096      [::]:111           [::]:*";
        assert!(port_111_in_ss_line(listener));
        assert!(port_111_in_ss_line(v6));
        // An address that merely ends in 111, and a four-digit port.
        assert!(!port_111_in_ss_line("tcp LISTEN 0 128 10.0.0.111:22 0.0.0.0:*"));
        assert!(!port_111_in_ss_line("tcp LISTEN 0 128 0.0.0.0:1111 0.0.0.0:*"));
        assert!(!port_111_in_ss_line("Netid State  Recv-Q Send-Q Local"));
    }

    #[test]
    fn only_port_111_resource_ids_are_applicable() {
        assert!(resource_id_is_port_111("0.0.0.0:111/udp"));
        assert!(resource_id_is_port_111("0.0.0.0:111/tcp"));
        assert!(resource_id_is_port_111("[::]:111"));
        assert!(resource_id_is_port_111("192.168.1.5:111/udp"));
        // Other exposure findings must never reach the rpcbind action.
        assert!(!resource_id_is_port_111("0.0.0.0:3306"));
        assert!(!resource_id_is_port_111("10.0.0.111:2049/tcp"));
        assert!(!resource_id_is_port_111("scan_detector"));
        assert!(!resource_id_is_port_111("0.0.0.0:1111/udp"));
    }
}
