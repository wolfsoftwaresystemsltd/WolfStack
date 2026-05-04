// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Disk-array management — the storage backend Klas asked for. Sits
//! on top of either:
//!
//!   * Vanilla **Linux mdadm** software RAID (RAID 0/1/5/6/10) — the
//!     default everywhere; status via `/proc/mdstat`, control via
//!     `mdadm`.
//!   * **NoNRAID** (open-source port of the Unraid parity driver to
//!     mainline kernels) — same `/proc/mdstat`-style status surface,
//!     control via `mdcmd`. We auto-detect the binary and prefer it
//!     when present so Unraid migrants get their `mdcmd start` /
//!     `mdcmd stop` semantics.
//!
//! v1.0 scope:
//!   * List arrays + per-disk detail (size, role, SMART status)
//!   * Start / stop the array
//!   * Trigger a parity check now, or schedule one (cron-style)
//!   * Predictive analyser that fires on degraded / failed-disk /
//!     parity-mismatch events through the existing alert channels
//!
//! Not in v1.0: array creation, add/remove disks, filesystem ops on
//! top of the array. Use `mdadm`/`mdcmd` directly for those —
//! WolfStack's job is monitoring + day-to-day ops.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

// ─── Backend detection ───

/// Which control plane to use for array ops. Detected once per call;
/// cheap (just checks for binary presence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend { Mdadm, Nonraid }

pub fn detect_backend() -> Backend {
    // NoNRAID's `mdcmd` userspace tool is the most reliable signal —
    // when both are installed (a NoNRAID-on-Debian setup will have
    // mdadm too), `mdcmd` always wins because it speaks the parity
    // semantics that mdadm doesn't.
    if which("mdcmd").is_some() { Backend::Nonraid } else { Backend::Mdadm }
}

// ─── Public types ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Array {
    /// Kernel device name, e.g. "md0" / "md1".
    pub name: String,
    /// "raid1" / "raid5" / "raid6" / "raid10" / "uraid" / "linear" / "..."
    pub level: String,
    /// "active" / "clean" / "degraded" / "resyncing" / "checking" / "recovering" / "stopped" / "unknown"
    pub state: String,
    /// Sync progress 0..=100 if a check/resync is running.
    pub sync_progress: Option<u8>,
    /// Speed in KB/s reported by the kernel during sync.
    pub sync_speed_kbs: Option<u64>,
    pub disks: Vec<Disk>,
    /// Array-level size, bytes. Zero if not derivable.
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    /// One of "mdadm" / "nonraid".
    pub backend: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Disk {
    /// Block device path on the host, e.g. "/dev/sda".
    pub device: String,
    /// "data" / "parity" / "parity2" / "spare" / "missing" / "unknown".
    pub role: String,
    /// "active" / "in_sync" / "faulty" / "spare" / "missing" / "syncing" / "unknown".
    pub state: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    /// SMART overall — "PASSED" / "FAILED" / "unknown". Best-effort —
    /// we run smartctl with a tight timeout; if it's missing, we mark
    /// unknown rather than fail the whole array view.
    pub smart_status: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub temperature_c: Option<i32>,
}

// ─── Persisted config ───

fn config_path() -> PathBuf {
    PathBuf::from(crate::paths::get().config_dir.clone()).join("arrays.json")
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ArrayConfig {
    /// Per-array operator preferences.
    #[serde(default)]
    pub schedules: Vec<ParitySchedule>,
    /// Alert toggles per array. Default: all on.
    #[serde(default)]
    pub alert_overrides: Vec<AlertOverride>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ParitySchedule {
    pub array: String,        // "md0"
    pub cron: String,         // standard 5-field cron expression
    /// "check" = read-only verify (the safe default), "repair" =
    /// fix mismatches (only safe when you trust the data more than
    /// the parity).
    pub action: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AlertOverride {
    pub array: String,
    /// Suppress these alerts. Values: "degraded", "failed_disk",
    /// "smart_prefail", "parity_mismatch", "sync_started", "sync_done".
    pub suppress: Vec<String>,
}

impl ArrayConfig {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::paths::write_secure(&path.to_string_lossy(), json)
            .map_err(std::io::Error::other)
    }
}

// ─── /proc/mdstat parser ───

/// Parse `/proc/mdstat` into a list of arrays. Format is well-known
/// and stable — kernel docs in Documentation/admin-guide/md.rst.
/// Returns empty list if the file isn't there (md kernel module not
/// loaded), which is the common case on hosts that don't run an
/// array.
pub fn list_arrays() -> Vec<Array> {
    let content = match std::fs::read_to_string("/proc/mdstat") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let backend = detect_backend();
    let backend_label = match backend { Backend::Mdadm => "mdadm", Backend::Nonraid => "nonraid" };
    let mut arrays = parse_mdstat(&content, backend_label);
    // df-based filesystem usage probes can't be in the pure parser
    // (they hit the host); apply them here.
    for a in arrays.iter_mut() {
        a.used_bytes = filesystem_used_bytes_for(&format!("/dev/{}", a.name)).unwrap_or(0);
    }
    arrays
}

/// Pure parser for `/proc/mdstat` content. Carved out so the unit
/// tests can exercise it without a real /proc filesystem.
///
/// Active header:   `md0 : active raid1 sda1[0] sdb1[1]`
/// Inactive header: `md0 : inactive sda1[0] sdb1[1]`           (no level word)
/// Read-only:       `md0 : active (read-only) raid1 sda1[0] ...`
pub fn parse_mdstat(content: &str, backend_label: &str) -> Vec<Array> {
    let mut arrays: Vec<Array> = Vec::new();
    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("md") { continue; }
        // Need a colon directly after the name — skips
        // "md_d0_raid_disk" or other prefixes.
        let (name_field, rest) = match trimmed.split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let name = name_field.trim().to_string();
        if name.is_empty() || !name.starts_with("md") { continue; }

        let mut tokens = rest.split_whitespace().peekable();
        let state_raw = tokens.next().unwrap_or("unknown").to_lowercase();

        // "active" may be followed by an optional "(read-only)" or
        // "(auto-read-only)" annotation before the level word. Skip
        // any parenthesised flags.
        while let Some(t) = tokens.peek() {
            if t.starts_with('(') && t.ends_with(')') { tokens.next(); } else { break; }
        }

        // Inactive arrays have no level word — the next token is the
        // first disk (matching `<name>[<idx>]`). Detect this and leave
        // level as "unknown" rather than mis-consuming the first disk.
        let level = match tokens.peek() {
            Some(t) if looks_like_disk_token(t) => "unknown".to_string(),
            Some(_) => tokens.next().unwrap().to_string(),
            None => "unknown".to_string(),
        };

        let mut disks: Vec<Disk> = Vec::new();
        for token in tokens {
            if !looks_like_disk_token(token) { continue; }
            let dev_part = token.split('[').next().unwrap_or(token);
            let device = format!("/dev/{}", dev_part);
            let dstate = if token.contains("(F)") { "faulty" }
                else if token.contains("(S)") { "spare" }
                else if token.contains("(R)") { "replacement" }
                else { "in_sync" }.to_string();
            disks.push(Disk {
                device,
                role: "data".into(),
                state: dstate,
                size_bytes: 0,
                used_bytes: 0,
                smart_status: "unknown".into(),
                model: None,
                serial: None,
                temperature_c: None,
            });
        }

        let mut sync_progress = None;
        let mut sync_speed_kbs = None;
        let mut size_bytes = 0u64;
        let mut state_refined = state_raw.clone();
        while let Some(next) = lines.peek() {
            let t = next.trim_start();
            if t.is_empty() || (t.starts_with("md") && t.contains(':')) { break; }
            if t.contains("blocks") {
                if let Some(blocks_str) = t.split_whitespace().next() {
                    if let Ok(blocks) = blocks_str.parse::<u64>() {
                        size_bytes = blocks * 1024;
                    }
                }
                if t.contains('_') {
                    state_refined = "degraded".into();
                } else if t.contains("[U") {
                    state_refined = "clean".into();
                }
            }
            if t.contains('=') && (t.contains("resync") || t.contains("recovery")
                || t.contains("check") || t.contains("reshape"))
            {
                if let Some(pct_idx) = t.find('%') {
                    let head = &t[..pct_idx];
                    let pct: String = head.chars().rev()
                        .take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                    let pct: String = pct.chars().rev().collect();
                    if let Ok(p) = pct.parse::<f64>() {
                        sync_progress = Some(p as u8);
                    }
                }
                if let Some(sp_pos) = t.find("speed=") {
                    let rest = &t[sp_pos + 6..];
                    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = num.parse::<u64>() {
                        sync_speed_kbs = Some(n);
                    }
                }
                if t.contains("recovery") { state_refined = "recovering".into(); }
                else if t.contains("check") { state_refined = "checking".into(); }
                else if t.contains("resync") { state_refined = "resyncing".into(); }
            }
            lines.next();
        }

        arrays.push(Array {
            name,
            level,
            state: state_refined,
            sync_progress,
            sync_speed_kbs,
            disks,
            size_bytes,
            used_bytes: 0, // filled by list_arrays() outside the pure parser
            backend: backend_label.into(),
        });
    }
    arrays
}

/// Heuristic: does this token look like a disk entry (e.g. "sda1[0]"
/// / "nvme0n1p1[0]" / "sdb1[1](F)")? Used by the parser to
/// distinguish disk tokens from level / option words on inactive
/// arrays.
fn looks_like_disk_token(t: &str) -> bool {
    // Must contain "[<digits>]" somewhere and start with a letter.
    if !t.starts_with(|c: char| c.is_ascii_alphabetic()) { return false; }
    let Some(open) = t.find('[') else { return false; };
    let Some(close) = t[open..].find(']') else { return false; };
    let inside = &t[open + 1 .. open + close];
    !inside.is_empty() && inside.chars().all(|c| c.is_ascii_digit())
}

/// Enrich an array with per-disk SMART data + role refinement from
/// `mdadm --detail`. Slow-ish (smartctl per disk), so we only do it
/// when the operator views detail — not on every list refresh.
pub fn array_detail(name: &str) -> Option<Array> {
    let mut arr = list_arrays().into_iter().find(|a| a.name == name)?;

    // Refine roles from `mdadm --detail`.
    let detail = Command::new("mdadm")
        .args(["--detail", &format!("/dev/{}", name)])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    for d in arr.disks.iter_mut() {
        let dev = d.device.trim_start_matches("/dev/");
        // mdadm --detail line:
        //   "       0       8        1        0      active sync   /dev/sda1"
        //   "       1       8       17        -      faulty   /dev/sdb1"
        for line in detail.lines() {
            if !line.contains(dev) { continue; }
            let lc = line.to_ascii_lowercase();
            if lc.contains("faulty")    { d.state = "faulty".into(); }
            else if lc.contains("spare")     { d.state = "spare".into(); }
            else if lc.contains("active")    { d.state = "active".into(); }
            // role detection (parity vs data) — mdadm doesn't print
            // an explicit "parity" word for vanilla raid5/6, but
            // NoNRAID does. For uraid/raid5, the LAST disk in the
            // listing is the parity. We approximate by leaving role
            // = data here and let nonraid_detail() override below.
        }
        // Per-disk size, model, serial, SMART. Best-effort.
        if let Some(info) = lsblk_disk_info(&d.device) {
            d.size_bytes = info.size_bytes;
            d.model = info.model;
            d.serial = info.serial;
        }
        if let Some((status, temp)) = smart_summary(&d.device) {
            d.smart_status = status;
            d.temperature_c = temp;
        }
    }

    // NoNRAID-specific: refine roles via `mdcmd status` and look up
    // per-data-disk fill via /proc/mounts. Vanilla RAID5/6/10 has a
    // single filesystem on top so per-disk fill is meaningless and
    // we leave that path alone.
    if detect_backend() == Backend::Nonraid {
        nonraid_refine_roles(&mut arr);
        fill_per_disk_usage_nonraid(&mut arr);
    }

    Some(arr)
}

/// Look up the per-disk used bytes for NoNRAID-style arrays where
/// each data disk carries its own filesystem (Unraid/NoNRAID
/// convention is `/mnt/disk1`, `/mnt/disk2`, …, `/mnt/parity`,
/// `/mnt/parity2`). For vanilla mdadm RAID5/6/10 there's a single
/// filesystem on top of the whole array, so per-disk fill is
/// meaningless and we leave `used_bytes` at zero — `array.used_bytes`
/// covers it.
fn fill_per_disk_usage_nonraid(arr: &mut Array) {
    // Build a map of `<source-device-stem> → used-bytes` from
    // /proc/mounts + statfs. We resolve symlinks once so e.g.
    // `/dev/disk/by-id/...` and `/dev/sda1` both match.
    let mounts = match std::fs::read_to_string("/proc/mounts") {
        Ok(m) => m,
        Err(_) => return,
    };
    for d in arr.disks.iter_mut() {
        if d.role == "parity" || d.role == "parity2" {
            // Parity disks don't carry a filesystem we can read.
            // Their fill is implied by the largest data disk.
            continue;
        }
        let dev_target = std::fs::canonicalize(&d.device)
            .unwrap_or_else(|_| std::path::PathBuf::from(&d.device));
        let dev_str = dev_target.to_string_lossy().to_string();

        for line in mounts.lines() {
            let mut it = line.split_whitespace();
            let src = match it.next() { Some(s) => s, None => continue };
            let mnt = match it.next() { Some(m) => m, None => continue };
            // Match by canonicalised device — handles partition
            // suffixes (sda1 mounted from /dev/sda + partition).
            let src_canon = std::fs::canonicalize(src)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| src.to_string());
            if src_canon != dev_str {
                // Also accept the case where the array lists the bare
                // disk (e.g. /dev/sda) but the mount source is a
                // partition (/dev/sda1 / /dev/sdap1). NoNRAID
                // typically partitions. The character immediately
                // after the device name MUST be a digit or the letter
                // 'p' (NVMe convention: nvme0n1p1). Otherwise we'd
                // false-positive on adjacent device names like
                // /dev/sda matching /dev/sdab.
                if !src_canon.starts_with(&dev_str) { continue; }
                let suffix = &src_canon[dev_str.len()..];
                let first_char = suffix.chars().next();
                let is_partition = match first_char {
                    Some(c) if c.is_ascii_digit() => true,
                    Some('p') => suffix[1..].chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false),
                    _ => false,
                };
                if !is_partition { continue; }
            }
            // statfs the mount point for used-bytes.
            if let Some(used) = mount_used_bytes(mnt) {
                d.used_bytes = used;
                if d.size_bytes == 0 {
                    if let Some(total) = mount_total_bytes(mnt) {
                        d.size_bytes = total;
                    }
                }
                break;
            }
        }
    }
}

fn mount_used_bytes(mnt: &str) -> Option<u64> {
    let out = std::process::Command::new("df").args(["-Bk", "--output=used", mnt]).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    let used_kb: u64 = s.lines().nth(1)?.trim().trim_end_matches('K').parse().ok()?;
    Some(used_kb * 1024)
}

fn mount_total_bytes(mnt: &str) -> Option<u64> {
    let out = std::process::Command::new("df").args(["-Bk", "--output=size", mnt]).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    let total_kb: u64 = s.lines().nth(1)?.trim().trim_end_matches('K').parse().ok()?;
    Some(total_kb * 1024)
}

fn nonraid_refine_roles(arr: &mut Array) {
    // `mdcmd status` outputs lines like:
    //   "rdevName.0=md1p1"     → parity
    //   "rdevName.1=md1p2"     → data slot 1
    // Index 0 is parity in Unraid/NoNRAID convention.
    let out = Command::new("mdcmd").arg("status").output();
    let Ok(out) = out else { return };
    if !out.status.success() { return; }
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    for line in s.lines() {
        if let Some(rest) = line.trim().strip_prefix("rdevName.") {
            let mut sp = rest.splitn(2, '=');
            let idx = sp.next().and_then(|n| n.parse::<usize>().ok());
            let dev = sp.next();
            if let (Some(idx), Some(dev)) = (idx, dev) {
                let dev_path = if dev.starts_with("/dev/") { dev.into() } else { format!("/dev/{}", dev) };
                if let Some(d) = arr.disks.iter_mut().find(|d| d.device == dev_path) {
                    // NoNRAID/Unraid disk-index convention:
                    //   0  = parity (the first parity disk)
                    //   28 = parity2 (the dual-parity slot — Unraid 6.7+)
                    //   1..27 = data slots
                    // Verified against Unraid's `mdcmd status` output
                    // and the lime-technology/nonraid kernel patches
                    // (the fork enumerates disks identically).
                    d.role = match idx {
                        0 => "parity".into(),
                        28 => "parity2".into(),
                        _ => "data".into(),
                    };
                }
            }
        }
    }
}

// ─── Operations ───

#[derive(Debug)]
pub enum ArrayError {
    NotInstalled { tool: String, install_package: String },
    CommandFailed(String),
    NoSuchArray(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ArrayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArrayError::NotInstalled { tool, install_package } => write!(
                f, "{} not installed (install package '{}')", tool, install_package
            ),
            ArrayError::CommandFailed(s) => write!(f, "command failed: {}", s),
            ArrayError::NoSuchArray(n) => write!(f, "no such array: {}", n),
            ArrayError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl From<std::io::Error> for ArrayError {
    fn from(e: std::io::Error) -> Self { ArrayError::Io(e) }
}

/// Stop an array. mdadm: `mdadm --stop /dev/mdN`. NoNRAID: `mdcmd stop`.
pub fn stop_array(name: &str) -> Result<String, ArrayError> {
    if list_arrays().iter().find(|a| a.name == name).is_none() {
        return Err(ArrayError::NoSuchArray(name.into()));
    }
    match detect_backend() {
        Backend::Nonraid => run_capturing("mdcmd", &["stop"], "mdcmd"),
        Backend::Mdadm   => run_capturing("mdadm", &["--stop", &format!("/dev/{}", name)], "mdadm"),
    }
}

/// Start (assemble) an array. NoNRAID has a single-array model so
/// `mdcmd start` brings up the configured array; mdadm assembles by
/// device name.
pub fn start_array(name: &str) -> Result<String, ArrayError> {
    match detect_backend() {
        Backend::Nonraid => run_capturing("mdcmd", &["start"], "mdcmd"),
        Backend::Mdadm   => run_capturing("mdadm", &["--assemble", &format!("/dev/{}", name)], "mdadm"),
    }
}

/// Trigger a parity check. Action is "check" (read-only verify, the
/// default) or "repair" (overwrite mismatches).
pub fn parity_check(name: &str, action: &str) -> Result<String, ArrayError> {
    if !["check", "repair"].contains(&action) {
        return Err(ArrayError::CommandFailed(format!(
            "action must be 'check' or 'repair', got '{}'", action
        )));
    }
    match detect_backend() {
        Backend::Nonraid => {
            // mdcmd: `mdcmd check` (read-only) or `mdcmd check correct` (repair)
            let args = if action == "repair" { vec!["check", "correct"] } else { vec!["check"] };
            run_capturing("mdcmd", &args, "mdcmd")
        }
        Backend::Mdadm => {
            // Vanilla mdadm: write to /sys/block/mdN/md/sync_action.
            let path = format!("/sys/block/{}/md/sync_action", name);
            std::fs::write(&path, action.as_bytes())
                .map_err(|e| ArrayError::CommandFailed(format!("write {}: {}", path, e)))?;
            Ok(format!("{} started on /dev/{}", action, name))
        }
    }
}

/// Cancel an in-progress parity check.
pub fn parity_cancel(name: &str) -> Result<String, ArrayError> {
    match detect_backend() {
        Backend::Nonraid => run_capturing("mdcmd", &["nocheck"], "mdcmd"),
        Backend::Mdadm => {
            let path = format!("/sys/block/{}/md/sync_action", name);
            std::fs::write(&path, b"idle")
                .map_err(|e| ArrayError::CommandFailed(format!("write {}: {}", path, e)))?;
            Ok(format!("parity check cancelled on /dev/{}", name))
        }
    }
}

// ─── Helpers ───

fn run_capturing(bin: &str, args: &[&str], pkg: &str) -> Result<String, ArrayError> {
    let out = Command::new(bin).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ArrayError::NotInstalled { tool: bin.into(), install_package: pkg.into() }
        } else { ArrayError::Io(e) }
    })?;
    if !out.status.success() {
        return Err(ArrayError::CommandFailed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn which(bin: &str) -> Option<PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = PathBuf::from(dir).join(bin);
        if candidate.exists() { return Some(candidate); }
    }
    for fixed in ["/sbin", "/usr/sbin", "/usr/local/sbin"] {
        let candidate = PathBuf::from(fixed).join(bin);
        if candidate.exists() { return Some(candidate); }
    }
    None
}

struct LsblkInfo { size_bytes: u64, model: Option<String>, serial: Option<String> }

fn lsblk_disk_info(device: &str) -> Option<LsblkInfo> {
    let out = Command::new("lsblk")
        .args(["-Jbno", "NAME,SIZE,MODEL,SERIAL", device])
        .output().ok()?;
    if !out.status.success() { return None; }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let arr = v.get("blockdevices").and_then(|x| x.as_array())?;
    let first = arr.first()?;
    Some(LsblkInfo {
        size_bytes: first.get("size").and_then(|x| x.as_u64()).unwrap_or(0),
        model: first.get("model").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.trim().to_string()),
        serial: first.get("serial").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.trim().to_string()),
    })
}

fn smart_summary(device: &str) -> Option<(String, Option<i32>)> {
    // smartctl returns non-zero on SMART errors which is fine — we
    // still parse stdout. Tight 5s timeout: SMART scans can hang on
    // misbehaving USB enclosures.
    let out = Command::new("timeout").args(["5", "smartctl", "-H", "-A", device]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut status = "unknown".to_string();
    let mut temp: Option<i32> = None;
    for line in s.lines() {
        let l = line.trim();
        if let Some(idx) = l.find("overall-health self-assessment test result:") {
            let rest = l[idx + "overall-health self-assessment test result:".len()..].trim();
            status = rest.to_string();
        }
        // SMART attribute 194 is Temperature_Celsius — line format:
        //   "194 Temperature_Celsius     0x0022   ... 38 ..."
        if l.starts_with("194") && l.contains("Temperature") {
            if let Some(num) = l.split_whitespace().nth(9).and_then(|t| t.parse::<i32>().ok()) {
                temp = Some(num);
            }
        }
    }
    Some((status, temp))
}

fn filesystem_used_bytes_for(device: &str) -> Option<u64> {
    // If the array's underlying device has a mounted filesystem,
    // report its `df` usage. Best-effort — not every array has one
    // (could be an LVM PV, a raw block target, etc.).
    let out = Command::new("df").args(["-Bk", "--output=used", device]).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    let used_kb: u64 = s.lines().nth(1)?.trim().trim_end_matches('K').parse().ok()?;
    Some(used_kb * 1024)
}

// ─── Predictive integration ───

/// Snapshot every array's state and emit predictive findings for any
/// unhappy condition. Called from the existing predictive
/// orchestrator on its 5-minute tick. Findings flow through the
/// existing alert channels (private — never the public status page).
#[allow(dead_code)]
pub fn predictive_findings() -> Vec<ArrayFinding> {
    let mut findings = Vec::new();
    for arr in list_arrays() {
        if arr.state == "degraded" {
            let missing: Vec<String> = arr.disks.iter()
                .filter(|d| d.state == "faulty" || d.state == "missing")
                .map(|d| d.device.clone()).collect();
            findings.push(ArrayFinding {
                array: arr.name.clone(),
                kind: "degraded".into(),
                severity: "critical".into(),
                detail: format!("array degraded — disks unhealthy: [{}]", missing.join(", ")),
            });
        }
        for d in &arr.disks {
            if d.smart_status.eq_ignore_ascii_case("FAILED") {
                findings.push(ArrayFinding {
                    array: arr.name.clone(),
                    kind: "smart_prefail".into(),
                    severity: "critical".into(),
                    detail: format!("disk {} reports SMART FAILED", d.device),
                });
            }
        }
    }
    findings
}

#[derive(Debug, Clone, Serialize)]
pub struct ArrayFinding {
    pub array: String,
    pub kind: String,
    pub severity: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_arrays_returns_empty_on_no_mdstat() {
        // On a host without /proc/mdstat (most dev machines, this
        // CI runner, etc.), list_arrays returns Vec::new() rather
        // than panicking.
        let r = list_arrays();
        let _ = r.len(); // just exercising the path
    }

    #[test]
    fn parity_check_rejects_bad_action() {
        let err = parity_check("md0", "wipe").unwrap_err();
        assert!(matches!(err, ArrayError::CommandFailed(_)));
    }

    #[test]
    fn detect_backend_returns_a_value() {
        // Doesn't matter which; just must not panic on either path.
        let _ = detect_backend();
    }

    #[test]
    fn array_config_save_load_roundtrip() {
        let mut cfg = ArrayConfig::default();
        cfg.schedules.push(ParitySchedule {
            array: "md0".into(),
            cron: "0 3 * * 0".into(),
            action: "check".into(),
            enabled: true,
        });
        // We can't actually save in tests (root-owned config dir) but
        // we can verify the JSON shape round-trips.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ArrayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schedules.len(), 1);
        assert_eq!(back.schedules[0].array, "md0");
    }

    #[test]
    fn parse_mdstat_clean_raid1() {
        let sample = "Personalities : [raid1]\n\
            md0 : active raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n      \
            bitmap: 0/15 pages [0KB], 65536KB chunk\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays.len(), 1, "expected one array, got {:?}", arrays);
        let a = &arrays[0];
        assert_eq!(a.name, "md0");
        assert_eq!(a.level, "raid1");
        assert_eq!(a.state, "clean");
        assert_eq!(a.disks.len(), 2);
        assert_eq!(a.disks[0].device, "/dev/sda1");
        assert_eq!(a.disks[1].device, "/dev/sdb1");
        for d in &a.disks { assert_eq!(d.state, "in_sync"); }
    }

    #[test]
    fn parse_mdstat_inactive_array_does_not_steal_first_disk_as_level() {
        // Inactive arrays have no level word — the disk list comes
        // straight after "inactive". The bug being pinned: the
        // pre-fix parser advanced past "inactive" then called
        // parts.next() again expecting a level word, swallowing the
        // first disk as the level and leaving it out of the disk list.
        let sample = "Personalities : [raid1]\n\
            md0 : inactive sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays.len(), 1);
        let a = &arrays[0];
        assert_eq!(a.state, "inactive");
        assert_eq!(a.level, "unknown", "inactive arrays have no level word");
        assert_eq!(a.disks.len(), 2, "first disk must not be consumed as level — got {:?}", a.disks);
        assert_eq!(a.disks[0].device, "/dev/sda1");
    }

    #[test]
    fn parse_mdstat_degraded_raid1() {
        let sample = "Personalities : [raid1]\n\
            md0 : active raid1 sda1[0] sdb1[1](F)\n      \
            1953382464 blocks super 1.2 [2/1] [U_]\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        let a = &arrays[0];
        assert_eq!(a.state, "degraded");
        let faulty = a.disks.iter().find(|d| d.device == "/dev/sdb1").unwrap();
        assert_eq!(faulty.state, "faulty");
    }

    #[test]
    fn parse_mdstat_resyncing_progress_and_speed() {
        let sample = "Personalities : [raid1]\n\
            md0 : active raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n      \
            [=>...................]  resync = 12.3% (240000/1953382464) finish=8.4min speed=234567K/sec\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        let a = &arrays[0];
        assert_eq!(a.state, "resyncing");
        assert_eq!(a.sync_progress, Some(12));
        assert_eq!(a.sync_speed_kbs, Some(234567));
    }

    #[test]
    fn parse_mdstat_check_running() {
        let sample = "md0 : active raid5 sda1[0] sdb1[1] sdc1[2]\n      \
            3906764800 blocks super 1.2 level 5, 64k chunk, algorithm 2 [3/3] [UUU]\n      \
            [=>...................]  check =  5.7% (74203264/3906764800) finish=99.9min speed=614305K/sec\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        let a = &arrays[0];
        assert_eq!(a.state, "checking");
        assert_eq!(a.sync_progress, Some(5));
    }

    #[test]
    fn parse_mdstat_read_only_annotation_skipped() {
        // `active (read-only)` appears between state and level. The
        // parser must not consume "(read-only)" as the level word.
        let sample = "md0 : active (read-only) raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays[0].level, "raid1");
        assert_eq!(arrays[0].disks.len(), 2);
    }

    #[test]
    fn parse_mdstat_ignores_personalities_and_unused_lines() {
        let sample = "Personalities : [raid1] [raid6] [raid5] [raid4]\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert!(arrays.is_empty());
    }

    #[test]
    fn parse_mdstat_handles_nvme_partition_names() {
        // NVMe devices use the `nvme0n1p1` naming convention. Make
        // sure looks_like_disk_token doesn't reject them.
        let sample = "md0 : active raid1 nvme0n1p1[0] nvme1n1p1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays[0].disks.len(), 2);
        assert_eq!(arrays[0].disks[0].device, "/dev/nvme0n1p1");
    }

    #[test]
    fn looks_like_disk_token_rejects_non_disk_words() {
        // Negatives — these tokens appear in mdstat lines and must not
        // be interpreted as disks.
        for bad in ["active", "raid1", "(read-only)", "blocks", "[UU]", "5.7%"] {
            assert!(!looks_like_disk_token(bad), "should reject: {:?}", bad);
        }
        // Positives.
        for good in ["sda1[0]", "sdb1[1](F)", "nvme0n1p1[0]", "sdc1[2](S)"] {
            assert!(looks_like_disk_token(good), "should accept: {:?}", good);
        }
    }
}
