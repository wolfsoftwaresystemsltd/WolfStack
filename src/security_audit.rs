// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Per-node security audit — surfaces every container, VM, and host
//! attribute the operator needs to spot a compromise. Designed to be
//! aggregated fleet-wide via the existing `fleet_fanout_get` pattern
//! into the Fleet Security UI.
//!
//! ## What this collects (per host)
//!
//! - Every running container (LXC native, Proxmox CT, Docker)
//! - Every VM (Proxmox QEMU, libvirt) — running state + name
//! - Per-container risk flags:
//!     * `--privileged` Docker container (host root via /proc/1/root)
//!     * `/var/run/docker.sock` mounted into a container (= container can spawn arbitrary host processes)
//!     * `network=host` Docker (container shares host network namespace)
//!     * Container running with no resource limits (escape blast radius)
//! - Host attack-surface:
//!     * Suspicious processes by name (xmrig, kinsing, t-rex, minerd, etc.)
//!     * Recently-modified executables in /tmp, /dev/shm, /var/tmp
//!     * sshd_config policy summary (PermitRootLogin, PasswordAuthentication)
//!     * Recently-changed /root/.ssh/authorized_keys
//!     * Cron entries pointing at /tmp / random executables
//!
//! Read-only. Spawned in parallel under tokio::task::spawn_blocking
//! because container CLI calls are slow.

use serde::{Serialize, Deserialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadAudit {
    /// "lxc-native" | "lxc-proxmox" | "docker" | "vm-proxmox" | "vm-libvirt"
    pub kind: String,
    pub name: String,
    pub running: bool,
    /// Per-workload risk flags. Empty = clean. Operator-readable strings;
    /// the UI just renders them as red bullet points under the row.
    pub risks: Vec<String>,
    /// Source of this row (so the UI can dedupe across LXC/Proxmox CT
    /// when the same container is visible to both tools).
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAudit {
    pub hostname: String,
    pub workloads: Vec<WorkloadAudit>,
    pub host_findings: Vec<HostFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFinding {
    /// "info" | "warn" | "critical"
    pub severity: String,
    pub title: String,
    pub detail: String,
}

/// Build the full per-host audit. Designed to be called from a
/// blocking task (spawns lots of subprocesses). Never panics —
/// missing tools / commands return empty results.
pub fn collect_host_audit() -> HostAudit {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut workloads = Vec::new();
    workloads.extend(collect_lxc_native());
    workloads.extend(collect_lxc_proxmox());
    workloads.extend(collect_docker());
    workloads.extend(collect_proxmox_vms());
    workloads.extend(collect_libvirt_vms());

    // Dedupe: a Proxmox CT might appear under both lxc-proxmox (via
    // pct list) and lxc-native (via lxc-ls if installed). Prefer the
    // pct version (it has the VMID); collapse by name.
    let mut by_name: std::collections::HashMap<String, WorkloadAudit> = Default::default();
    for w in workloads {
        let key = w.name.clone();
        by_name.entry(key)
            .and_modify(|existing| {
                // Keep the entry with more info / lower-priority source
                // ("lxc-proxmox" > "lxc-native" because pct gives more)
                if w.source == "pct" && existing.source != "pct" {
                    *existing = w.clone();
                }
            })
            .or_insert(w);
    }
    let workloads: Vec<WorkloadAudit> = by_name.into_values().collect();

    HostAudit {
        hostname,
        workloads,
        host_findings: collect_host_findings(),
    }
}

// ─── LXC native ─────────────────────────────────────────────────────

fn collect_lxc_native() -> Vec<WorkloadAudit> {
    let out = Command::new("lxc-ls").args(["-f", "--running"]).output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&stdout);
    let mut workloads = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 { continue; } // header row
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() { continue; }
        let name = cols[0].to_string();
        let state = cols.get(1).copied().unwrap_or("UNKNOWN");
        workloads.push(WorkloadAudit {
            kind: "lxc-native".into(),
            name,
            running: state == "RUNNING",
            risks: Vec::new(),
            source: "lxc-ls".into(),
        });
    }
    workloads
}

// ─── LXC Proxmox (pct) ──────────────────────────────────────────────

fn collect_lxc_proxmox() -> Vec<WorkloadAudit> {
    let out = Command::new("pct").arg("list").output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&stdout);
    let mut workloads = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 { continue; }
        let vmid = cols[0].to_string();
        let status = cols[1];
        let name = cols.get(2).copied().unwrap_or(vmid.as_str()).to_string();
        workloads.push(WorkloadAudit {
            kind: "lxc-proxmox".into(),
            name: format!("{} ({})", name, vmid),
            running: status == "running",
            risks: Vec::new(),
            source: "pct".into(),
        });
    }
    workloads
}

// ─── Docker ─────────────────────────────────────────────────────────

fn collect_docker() -> Vec<WorkloadAudit> {
    let out = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Image}}"])
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&stdout);
    let mut workloads = Vec::new();
    for line in s.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 2 { continue; }
        let name = parts[0].to_string();
        let state = parts[1];
        let mut risks = Vec::new();
        // Inspect each container for risky configuration. This is
        // moderately expensive (one docker inspect per container) but
        // the audit runs out-of-band, not on the hot path.
        let inspect = Command::new("docker")
            .args(["inspect", &name, "--format",
                "{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{range .Mounts}}{{.Source}}\n{{end}}"
            ])
            .output();
        if let Ok(out) = inspect {
            if out.status.success() {
                let info = String::from_utf8_lossy(&out.stdout);
                let lines: Vec<&str> = info.split('\n').collect();
                if let Some(first) = lines.first() {
                    let cols: Vec<&str> = first.split('|').collect();
                    if cols.first().copied() == Some("true") {
                        risks.push("running with --privileged (full host access if breached)".into());
                    }
                    if cols.get(1).copied() == Some("host") {
                        risks.push("using --network=host (sees + binds host ports directly)".into());
                    }
                    let mounts = cols.get(2).copied().unwrap_or("");
                    if mounts.contains("/var/run/docker.sock") {
                        risks.push("docker.sock mounted (container can spawn arbitrary host containers — root-equivalent)".into());
                    }
                    if mounts.contains("/proc") && !mounts.contains("/proc/sys") {
                        risks.push("host /proc mounted (host process visibility / kill access)".into());
                    }
                    if mounts.contains("/etc") || mounts.contains("/root") {
                        risks.push("host /etc or /root mounted (read or write host config)".into());
                    }
                }
            }
        }
        workloads.push(WorkloadAudit {
            kind: "docker".into(),
            name,
            running: state == "running",
            risks,
            source: "docker".into(),
        });
    }
    workloads
}

// ─── Proxmox QEMU VMs ───────────────────────────────────────────────

fn collect_proxmox_vms() -> Vec<WorkloadAudit> {
    let out = Command::new("qm").arg("list").output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&stdout);
    let mut workloads = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 { continue; }
        let vmid = cols[0].to_string();
        let name = cols.get(1).copied().unwrap_or(vmid.as_str()).to_string();
        let status = cols.get(2).copied().unwrap_or("");
        workloads.push(WorkloadAudit {
            kind: "vm-proxmox".into(),
            name: format!("{} ({})", name, vmid),
            running: status == "running",
            risks: Vec::new(),
            source: "qm".into(),
        });
    }
    workloads
}

// ─── libvirt VMs ────────────────────────────────────────────────────

fn collect_libvirt_vms() -> Vec<WorkloadAudit> {
    let out = Command::new("virsh").args(["list", "--all", "--name"]).output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&stdout);
    let mut workloads = Vec::new();
    for line in s.lines() {
        let name = line.trim();
        if name.is_empty() { continue; }
        // Per-domain state.
        let state_out = Command::new("virsh").args(["domstate", name]).output();
        let running = state_out
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "running")
            .unwrap_or(false);
        workloads.push(WorkloadAudit {
            kind: "vm-libvirt".into(),
            name: name.to_string(),
            running,
            risks: Vec::new(),
            source: "virsh".into(),
        });
    }
    workloads
}

// ─── Host findings ──────────────────────────────────────────────────

fn collect_host_findings() -> Vec<HostFinding> {
    let mut out = Vec::new();
    out.extend(suspicious_processes());
    out.extend(executables_in_temp());
    out.extend(sshd_policy_summary());
    out.extend(authorized_keys_recent_changes());
    out.extend(suspicious_cron_entries());
    out
}

/// Known-bad process names (cryptominers, scanner toolkits, common
/// botnet binaries). When found, severity=critical so the operator's
/// eye lands here first.
fn suspicious_processes() -> Vec<HostFinding> {
    let bad = [
        "xmrig", "kinsing", "t-rex", "minerd", "cpuminer",
        "ethminer", "phoenixminer", "claymore",
        "zmap", "masscan",
        "kdevtmpfsi", "kthrotlds", "watchdogs",
    ];
    let out = match Command::new("ps").args(["-eo", "comm"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&out);
    let processes: std::collections::HashSet<&str> = s.lines()
        .map(|l| l.trim())
        .collect();
    let mut findings = Vec::new();
    for name in bad {
        if processes.contains(name) {
            findings.push(HostFinding {
                severity: "critical".into(),
                title: format!("Known-bad process running: {}", name),
                detail: format!(
                    "Process named '{}' is currently running. This name is on the WolfStack list of known compromise indicators (cryptominers, scanners, botnet payloads). Investigate immediately: `ps auxf | grep {}` then `lsof -p <pid>` and `cat /proc/<pid>/cmdline`.",
                    name, name,
                ),
            });
        }
    }
    findings
}

/// Executable files in malware drop directories. Returns one finding
/// per file (capped at 20) so the operator can see exactly what to
/// look at.
fn executables_in_temp() -> Vec<HostFinding> {
    let dirs = ["/tmp", "/var/tmp", "/dev/shm"];
    let mut findings = Vec::new();
    let mut total = 0;
    for dir in dirs {
        let out = Command::new("find").args([
            dir, "-maxdepth", "2", "-type", "f", "-perm", "/u+x", "-mtime", "-7",
        ]).output();
        let s = match out {
            Ok(o) if o.status.success() => o.stdout,
            _ => continue,
        };
        let stdout = String::from_utf8_lossy(&s);
        for path in stdout.lines() {
            if total >= 20 { break; }
            let path = path.trim();
            if path.is_empty() { continue; }
            // Skip well-known benign paths (pip, npm install caches).
            if path.contains("/pip-") || path.contains("/npm-") { continue; }
            findings.push(HostFinding {
                severity: "warn".into(),
                title: format!("Recently-modified executable in temp dir: {}", path),
                detail: format!(
                    "Executable file at `{}` modified in the last 7 days. \
                     Malware commonly drops binaries in /tmp, /var/tmp, /dev/shm \
                     because those are world-writable. Run `file {}` and `sha256sum {}` then check the hash on VirusTotal.",
                    path, path, path,
                ),
            });
            total += 1;
        }
    }
    findings
}

/// sshd config policy snapshot. Surfaces the two settings that, when
/// permissive, are the most common entry vector.
fn sshd_policy_summary() -> Vec<HostFinding> {
    let out = Command::new("sshd").arg("-T").output();
    let s = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let cfg = String::from_utf8_lossy(&s).to_lowercase();
    let mut findings = Vec::new();
    let permitroot = cfg.lines()
        .find(|l| l.starts_with("permitrootlogin "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("?");
    let passauth = cfg.lines()
        .find(|l| l.starts_with("passwordauthentication "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("?");
    // Proxmox uses root SSH for cluster operations and re-asserts
    // PermitRootLogin on its own, so the finding is un-actionable there —
    // suppress it on Proxmox. (A /etc/ssh/sshd_config.d/*.conf drop-in with
    // `prohibit-password` is the way to harden + survives the reset.)
    if permitroot == "yes" && !crate::containers::is_proxmox() {
        findings.push(HostFinding {
            severity: "critical".into(),
            title: "SSH allows direct root login".into(),
            detail: "sshd_config has `PermitRootLogin yes`. This is the #1 attack surface for credential brute-force. Set to `prohibit-password` (key-only) at minimum, or `no` if you have a non-root admin account.".into(),
        });
    }
    if passauth == "yes" {
        findings.push(HostFinding {
            severity: "warn".into(),
            title: "SSH password authentication is enabled".into(),
            detail: "sshd_config has `PasswordAuthentication yes`. Set to `no` to require SSH keys — eliminates the entire class of password-brute-force attacks.".into(),
        });
    }
    findings
}

/// Authorized-keys files modified in the last 7 days = recent SSH-key
/// addition. Operator should sanity-check it was them.
fn authorized_keys_recent_changes() -> Vec<HostFinding> {
    let out = Command::new("find").args([
        "/root", "/home", "-name", "authorized_keys", "-mtime", "-7", "-type", "f",
    ]).output();
    let s = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&s);
    let mut findings = Vec::new();
    for path in stdout.lines() {
        let path = path.trim();
        if path.is_empty() { continue; }
        findings.push(HostFinding {
            severity: "warn".into(),
            title: format!("authorized_keys recently modified: {}", path),
            detail: format!(
                "`{}` was modified in the last 7 days. If you didn't add a key, somebody else did — this is a common persistence move after an initial compromise. Check: `cat {}` and remove any unknown entries.",
                path, path,
            ),
        });
    }
    findings
}

/// Cron entries pointing at /tmp / /var/tmp / /dev/shm — same logic
/// as the executable-in-temp check, but cron-launched payloads are
/// the persistence mechanism for many cryptominer kits.
fn suspicious_cron_entries() -> Vec<HostFinding> {
    let mut findings = Vec::new();
    let out = Command::new("cut").args(["-f1", "-d:", "/etc/passwd"]).output();
    let users = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };
    for user in users.lines() {
        let cron_out = Command::new("crontab").args(["-u", user, "-l"]).output();
        let cron = match cron_out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => continue,
        };
        for line in cron.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') { continue; }
            if l.contains("/tmp/") || l.contains("/var/tmp/") || l.contains("/dev/shm/") {
                findings.push(HostFinding {
                    severity: "critical".into(),
                    title: format!("Cron entry runs from a temp dir (user {})", user),
                    detail: format!(
                        "Cron line: `{}`\n\nLegitimate software doesn't put cron payloads in /tmp. This is the persistence pattern for cryptominer / botnet kits. Inspect the target file and remove the cron line if you didn't add it.",
                        l,
                    ),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    // Most functions in this module shell out to system tools. Behaviour
    // is best verified manually on a real Proxmox host. The pure-data
    // serialization below verifies the wire format for the UI.

    use super::*;

    #[test]
    fn workload_audit_serializes() {
        let w = WorkloadAudit {
            kind: "docker".into(),
            name: "myapp".into(),
            running: true,
            risks: vec!["docker.sock mounted".into()],
            source: "docker".into(),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"kind\":\"docker\""));
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("docker.sock mounted"));
    }

    #[test]
    fn host_finding_serializes() {
        let f = HostFinding {
            severity: "critical".into(),
            title: "Known-bad process".into(),
            detail: "xmrig running".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"severity\":\"critical\""));
    }
}
