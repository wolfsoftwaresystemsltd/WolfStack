// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Outbound scan detection — would have caught the zmap incident at
//! minute 1 instead of waiting for Hetzner's abuse mail.
//!
//! ## How it works
//!
//! Every 30s we sample `/proc/net/tcp` and `/proc/net/tcp6` for
//! sockets in SYN_SENT state. Each row gives us a (local_pid via
//! `inode→pid` mapping, remote_addr) pair. We count distinct remote
//! addresses per local-process across a rolling 60s window. Above
//! `threshold_destinations` distinct destinations in the window =
//! suspect scanner, alert + auto-action.
//!
//! ## Why /proc/net/tcp not eBPF
//!
//! eBPF would be more accurate but requires kernel headers, BCC, and
//! root privileges WolfStack already has but operators on minimal
//! Hetzner installs may have other dependencies missing. /proc/net/
//! is universal — exists on every Linux kernel since 2.0.
//!
//! ## What we do on detection
//!
//! 1. Log a CRITICAL audit entry with the offending PID + comm
//! 2. SIGTERM (then SIGKILL after 5s) the process
//! 3. Add an iptables OUTPUT rule for that PID's UID (kernel-level
//!    block of all further outbound from the same user)
//! 4. Push an alert into the WolfStack alert log
//! 5. Surface in the Fleet Security UI
//!
//! ## False-positive mitigation
//!
//! Many legitimate processes make many outbound connections (apt
//! during a big upgrade, docker pulling layers, ceph-osd peering,
//! WolfStack itself polling 14 peers). Allowlist by comm name:
//! apt, dpkg, docker*, ceph-*, wolfstack, sshd, etc.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanDetectorConfig {
    /// Enable the detector. Default true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// How many distinct destinations within the window flag a process.
    #[serde(default = "default_threshold")]
    pub threshold_destinations: usize,
    /// Window in seconds for counting destinations.
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    /// Sample interval. Smaller = faster detection, more CPU.
    #[serde(default = "default_sample")]
    pub sample_interval_seconds: u64,
    /// Comm names that bypass detection. Pre-populated with known
    /// legitimate fan-out processes.
    #[serde(default = "default_allowlist")]
    pub allowlist_comms: Vec<String>,
    /// Numeric UIDs that bypass detection entirely. Use this for
    /// dedicated service accounts running legitimate high-fanout
    /// software (data-analysis pipelines, multi-API integrations).
    /// Safer than comm-name allowlisting when the process runs under
    /// a generic interpreter like `python` or `node` — operator can
    /// allowlist just the analytics user without exempting EVERY
    /// python process on the box.
    ///
    /// Find a user's UID: `id -u <username>` or
    /// `getent passwd <username> | cut -d: -f3`.
    #[serde(default)]
    pub allowlist_uids: Vec<u32>,
    /// What to do on detection. "alert_only" | "kill_and_block" (default).
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_enabled() -> bool { true }
fn default_threshold() -> usize { 50 }
fn default_window() -> u64 { 60 }
fn default_sample() -> u64 { 15 }
fn default_action() -> String { "kill_and_block".into() }
fn default_allowlist() -> Vec<String> {
    vec![
        "apt".into(), "apt-get".into(), "dpkg".into(), "unattended-upgr".into(),
        "dockerd".into(), "containerd".into(), "docker".into(),
        "ceph-osd".into(), "ceph-mon".into(), "ceph-mgr".into(), "ceph-mds".into(),
        "wolfstack".into(), "wolfagent".into(), "wolfram".into(), "wolfusb".into(),
        "sshd".into(), "sshd-session".into(),
        "pveproxy".into(), "pvedaemon".into(), "pvestatd".into(), "pveupload".into(),
        "rsyncd".into(), "rsync".into(),
        "chronyd".into(), "systemd-resolve".into(), "systemd-network".into(),
        "tailscaled".into(), "tailscale".into(), "wg-quick".into(),
        "node_exporter".into(), "prometheus".into(),
    ]
}

impl Default for ScanDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            threshold_destinations: default_threshold(),
            window_seconds: default_window(),
            sample_interval_seconds: default_sample(),
            allowlist_comms: default_allowlist(),
            allowlist_uids: Vec::new(),
            action: default_action(),
        }
    }
}

impl ScanDetectorConfig {
    fn config_path() -> String {
        format!("{}/scan-detector.json", crate::paths::get().config_dir)
    }
    pub fn load() -> Self {
        std::fs::read_to_string(Self::config_path()).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("save scan detector config: {}", e))
    }
}

/// One detection event, kept in a bounded ring for the UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectionEvent {
    pub timestamp: u64,
    pub pid: i32,
    pub comm: String,
    pub uid: u32,
    pub distinct_destinations: usize,
    pub window_seconds: u64,
    pub sample_destinations: Vec<String>,
    pub action_taken: String,
}

const EVENTS_MAX: usize = 200;

#[derive(Default)]
struct Inner {
    /// Per-PID: rolling list of (timestamp, dest_ip).
    samples: HashMap<i32, Vec<(Instant, String)>>,
    /// PIDs we've already actioned (don't repeat-action).
    actioned: HashMap<i32, Instant>,
    events: std::collections::VecDeque<DetectionEvent>,
}

/// (title, body) callback fired when a scanner is detected. main.rs
/// wires this to alerting::send_node_alert so the operator gets a
/// Discord / Slack / Telegram / email with the cluster + hostname
/// included.
pub type ScanAlertHook = Arc<dyn Fn(String, String) + Send + Sync>;

pub struct ScanDetector {
    inner: Mutex<Inner>,
    config: std::sync::RwLock<ScanDetectorConfig>,
    alert_hook: std::sync::RwLock<Option<ScanAlertHook>>,
}

impl ScanDetector {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            config: std::sync::RwLock::new(ScanDetectorConfig::load()),
            alert_hook: std::sync::RwLock::new(None),
        }
    }

    pub fn install_alert_hook(&self, hook: ScanAlertHook) {
        *self.alert_hook.write().unwrap() = Some(hook);
    }

    pub fn config(&self) -> ScanDetectorConfig {
        self.config.read().unwrap().clone()
    }

    pub fn set_config(&self, new: ScanDetectorConfig) -> Result<ScanDetectorConfig, String> {
        new.save()?;
        *self.config.write().unwrap() = new.clone();
        Ok(new)
    }

    pub fn events(&self) -> Vec<DetectionEvent> {
        let inner = self.inner.lock().unwrap();
        inner.events.iter().rev().cloned().collect()
    }

    /// Start the periodic sampler thread. Idempotent — calling twice
    /// just spawns two samplers (which is harmless but wasteful), so
    /// the caller (main.rs) calls once at startup.
    pub fn start(self: Arc<Self>) {
        std::thread::Builder::new()
            .name("wolfstack-scandetect".into())
            .spawn(move || self.run_loop())
            .ok();
    }

    fn run_loop(self: Arc<Self>) {
        loop {
            let cfg = self.config.read().unwrap().clone();
            if cfg.enabled {
                self.tick(&cfg);
            }
            std::thread::sleep(Duration::from_secs(cfg.sample_interval_seconds));
        }
    }

    fn tick(&self, cfg: &ScanDetectorConfig) {
        // Build inode→PID map ONCE per tick (it's the expensive part).
        let inode_to_pid = build_inode_pid_map();
        // Sample SYN_SENT sockets across v4 + v6.
        let mut samples: Vec<(i32, String)> = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            samples.extend(parse_syn_sent(path, &inode_to_pid));
        }
        // Insert into rolling window.
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_seconds);
        let mut inner = self.inner.lock().unwrap();
        for (pid, dest) in samples {
            let entry = inner.samples.entry(pid).or_default();
            entry.push((now, dest));
        }
        // Prune old samples + check thresholds. Snapshot `actioned`
        // ahead of the iter_mut so we don't hold conflicting borrows
        // on `inner` simultaneously.
        let allowlist: HashSet<&str> = cfg.allowlist_comms.iter().map(|s| s.as_str()).collect();
        let recently_actioned: HashMap<i32, Instant> = inner.actioned.clone();
        let mut to_action: Vec<(i32, String, u32, HashSet<String>)> = Vec::new();
        for (pid, entries) in inner.samples.iter_mut() {
            entries.retain(|(t, _)| now.duration_since(*t) < window);
            let distinct: HashSet<String> = entries.iter().map(|(_, d)| d.clone()).collect();
            if distinct.len() < cfg.threshold_destinations { continue; }
            // Already actioned recently? Skip.
            if let Some(when) = recently_actioned.get(pid) {
                if now.duration_since(*when) < Duration::from_secs(300) { continue; }
            }
            let comm = read_comm(*pid).unwrap_or_else(|| "?".into());
            if allowlist.contains(comm.as_str()) { continue; }
            let uid = read_uid(*pid).unwrap_or(0);
            // UID allowlist — dedicated service accounts for legit
            // high-fanout software bypass detection entirely.
            if cfg.allowlist_uids.contains(&uid) { continue; }
            to_action.push((*pid, comm, uid, distinct.clone()));
        }
        for (pid, comm, uid, dests) in to_action {
            let action_taken = self.take_action(pid, &comm, uid, cfg);
            let sample_dests: Vec<String> = dests.iter().take(20).cloned().collect();
            let event = DetectionEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                pid,
                comm: comm.clone(),
                uid,
                distinct_destinations: dests.len(),
                window_seconds: cfg.window_seconds,
                sample_destinations: sample_dests,
                action_taken: action_taken.clone(),
            };
            inner.actioned.insert(pid, now);
            if inner.events.len() >= EVENTS_MAX { inner.events.pop_front(); }
            inner.events.push_back(event.clone());
            tracing::error!(
                "scan-detect: PID {} ({}, uid {}) made {} distinct outbound connections in {}s — action: {}",
                pid, comm, uid, dests.len(), cfg.window_seconds, action_taken
            );
            // Operator alert out-of-band. Cluster + hostname stamped
            // by the alert hook. Sample destinations included so the
            // operator can immediately see if it's a scanner pattern
            // (random IPs across many /8s) vs a noisy app (lots of
            // connections all to one CDN).
            let hook = self.alert_hook.read().unwrap().clone();
            if let Some(h) = hook {
                let title = format!("🚨 Outbound scan detected: PID {} ({})", pid, comm);
                let dests_preview = event.sample_destinations.iter()
                    .take(15)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let body = format!(
                    "A process on this host hit the outbound-scan threshold:\n\n\
                     PID:      {}\n\
                     comm:     {}\n\
                     UID:      {}\n\
                     Distinct destinations: {} in {} seconds\n\
                     Action taken: {}\n\n\
                     Sample destinations: {}\n\n\
                     This is the same fingerprint that triggered the recent Hetzner abuse mail. \
                     If the process was legitimate (a bulk apt upgrade, etc.) add its comm name \
                     to the scan-detector allowlist on the Fleet Security page.",
                    pid, comm, uid,
                    event.distinct_destinations, event.window_seconds,
                    action_taken,
                    if dests_preview.is_empty() { "(none captured)".into() } else { dests_preview },
                );
                h(title, body);
            }
        }
        // Garbage-collect actioned entries older than 1h.
        inner.actioned.retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
        inner.samples.retain(|_, entries| !entries.is_empty());
    }

    /// Apply the configured action. Returns a human-readable description.
    fn take_action(&self, pid: i32, comm: &str, uid: u32, cfg: &ScanDetectorConfig) -> String {
        // Hard safety guard: NEVER kill PID 1 (init) or our own
        // process, no matter what the operator did to the allowlist.
        // Killing PID 1 = reboot loop. Killing ourselves = silent
        // brick of WolfStack. Both are unrecoverable without console.
        let our_pid = std::process::id() as i32;
        if pid == 1 || pid == our_pid {
            tracing::error!(
                "scan-detect: REFUSING to kill PID {} ({}) — protected (init or WolfStack itself)",
                pid, comm
            );
            return format!("REFUSED to kill PID {} (protected — init or WolfStack)", pid);
        }
        match cfg.action.as_str() {
            "alert_only" => {
                "alert only (no kill / no block)".into()
            }
            _ => {
                // SIGTERM, then SIGKILL after 2s if still alive.
                let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).output();
                std::thread::sleep(Duration::from_secs(2));
                let _ = Command::new("kill").args(["-KILL", &pid.to_string()]).output();
                // Block all further outbound from that UID. This catches
                // re-spawns from cron or systemd that would otherwise
                // immediately resume scanning.
                if uid != 0 {
                    // Don't iptables-block UID 0 — would break too much.
                    let _ = Command::new("iptables").args([
                        "-I", "OUTPUT", "1",
                        "-m", "owner", "--uid-owner", &uid.to_string(),
                        "-p", "tcp", "--syn",
                        "-j", "REJECT",
                    ]).output();
                    format!("killed PID {} ({}); blocked outbound TCP SYN for UID {}", pid, comm, uid)
                } else {
                    format!("killed PID {} ({}); UID 0 not auto-blocked (would break too much) — investigate manually", pid, comm)
                }
            }
        }
    }
}

/// Walk /proc to build inode→pid map. Used to translate /proc/net/tcp
/// inode column back to a PID. Reasonably fast on a typical host
/// (under 100ms for ~2000 processes).
fn build_inode_pid_map() -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    let proc = match std::fs::read_dir("/proc") { Ok(r) => r, Err(_) => return map };
    for entry in proc.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: i32 = match name_str.parse() { Ok(p) => p, Err(_) => continue };
        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match std::fs::read_dir(&fd_dir) { Ok(r) => r, Err(_) => continue };
        for fd in fds.flatten() {
            let target = match std::fs::read_link(fd.path()) { Ok(t) => t, Err(_) => continue };
            let s = target.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(end) = rest.find(']') {
                    if let Ok(inode) = rest[..end].parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }
    map
}

/// Parse /proc/net/tcp[6] for SYN_SENT (state=02) sockets. Returns
/// (pid, remote_ip) pairs, joined via the inode→pid map.
fn parse_syn_sent(path: &str, inode_to_pid: &HashMap<u64, i32>) -> Vec<(i32, String)> {
    let content = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return Vec::new() };
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 { continue; } // header
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        // cols[3] = "ST" (state, hex). 02 = SYN_SENT.
        if cols[3] != "02" { continue; }
        // cols[2] = remote address "HEX:PORT"
        let rem = cols[2];
        let ip = match rem.rsplit_once(':') {
            Some((hex_ip, _)) => hex_to_ip(hex_ip),
            None => continue,
        };
        // cols[9] = inode
        let inode: u64 = match cols[9].parse() { Ok(i) => i, Err(_) => continue };
        if let Some(&pid) = inode_to_pid.get(&inode) {
            out.push((pid, ip));
        }
    }
    out
}

/// Convert /proc/net/tcp's hex-encoded IP to a printable string.
/// Format is little-endian per-byte: e.g. "0100007F" → "127.0.0.1",
/// or for v6 a 32-char string of 4 little-endian dwords.
fn hex_to_ip(hex: &str) -> String {
    if hex.len() == 8 {
        // v4
        let mut bytes = [0u8; 4];
        for i in 0..4 {
            bytes[3 - i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else if hex.len() == 32 {
        // v6 — 4 dwords, each little-endian
        let mut groups: Vec<String> = Vec::new();
        for dw in 0..4 {
            for word in 0..2 {
                let i = dw * 8 + (1 - word) * 4;
                let chunk = &hex[i..i + 4];
                // Each "word" needs byte-swap within the 16-bit chunk.
                let hi = u8::from_str_radix(&chunk[0..2], 16).unwrap_or(0);
                let lo = u8::from_str_radix(&chunk[2..4], 16).unwrap_or(0);
                let val = ((lo as u16) << 8) | (hi as u16);
                groups.push(format!("{:x}", val));
            }
        }
        groups.join(":")
    } else {
        hex.to_string()
    }
}

fn read_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_ipv4_localhost() {
        // 127.0.0.1 little-endian = 0100007F
        assert_eq!(hex_to_ip("0100007F"), "127.0.0.1");
    }

    #[test]
    fn hex_to_ipv4_external() {
        // 8.8.8.8 little-endian = 08080808
        assert_eq!(hex_to_ip("08080808"), "8.8.8.8");
    }

    #[test]
    fn config_default_includes_known_safe_processes() {
        let cfg = ScanDetectorConfig::default();
        assert!(cfg.allowlist_comms.contains(&"apt".to_string()));
        assert!(cfg.allowlist_comms.contains(&"docker".to_string()));
        assert!(cfg.allowlist_comms.contains(&"wolfstack".to_string()));
        assert!(cfg.allowlist_comms.contains(&"ceph-osd".to_string()));
        assert!(cfg.threshold_destinations >= 10, "default threshold should be permissive enough not to false-positive");
    }

    #[test]
    fn take_action_refuses_to_kill_pid_1() {
        let det = ScanDetector::new();
        let cfg = ScanDetectorConfig {
            action: "kill_and_block".into(),
            ..Default::default()
        };
        let result = det.take_action(1, "systemd", 0, &cfg);
        assert!(result.contains("REFUSED"), "must refuse PID 1, got: {}", result);
    }

    #[test]
    fn take_action_refuses_to_kill_self() {
        let det = ScanDetector::new();
        let cfg = ScanDetectorConfig {
            action: "kill_and_block".into(),
            ..Default::default()
        };
        let our_pid = std::process::id() as i32;
        let result = det.take_action(our_pid, "wolfstack", 0, &cfg);
        assert!(result.contains("REFUSED"), "must refuse own PID, got: {}", result);
    }

    #[test]
    fn config_round_trip() {
        let mut cfg = ScanDetectorConfig::default();
        cfg.threshold_destinations = 75;
        cfg.action = "alert_only".into();
        cfg.allowlist_uids = vec![1000, 1001];
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ScanDetectorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.threshold_destinations, 75);
        assert_eq!(back.action, "alert_only");
        assert_eq!(back.allowlist_uids, vec![1000, 1001]);
    }

    #[test]
    fn uid_allowlist_default_is_empty() {
        let cfg = ScanDetectorConfig::default();
        assert!(cfg.allowlist_uids.is_empty(),
            "default config must NOT auto-allowlist any UIDs — operator opts in explicitly");
    }

    #[test]
    fn deserialise_without_allowlist_uids_field_defaults_to_empty() {
        // Backwards-compat: existing config files written by v23.10.0
        // (no allowlist_uids field) must still load without error.
        let old_json = r#"{
            "enabled": true,
            "threshold_destinations": 50,
            "window_seconds": 60,
            "sample_interval_seconds": 15,
            "allowlist_comms": ["apt"],
            "action": "kill_and_block"
        }"#;
        let cfg: ScanDetectorConfig = serde_json::from_str(old_json).unwrap();
        assert!(cfg.allowlist_uids.is_empty(),
            "missing allowlist_uids field must default to empty Vec");
        assert_eq!(cfg.threshold_destinations, 50);
    }
}
