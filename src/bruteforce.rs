// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Brute-force protection — one switch that extends WolfStack's existing auth
//! lockout beyond the host SSH/Proxmox surface (already covered by
//! `auth::log_monitor`) to **web servers** (apache/nginx) and **every managed
//! LXC container**, inside the container as well as on the host.
//!
//! Every detection funnels into the same [`LoginRateLimiter`] the login page
//! and SSH monitor use, so a hit anywhere produces a kernel-block in the
//! `wolfstack_block4/6` ipset **and fleet-wide propagation** — there is no
//! parallel ban system. Because `record_failure_with()` fires the propagation
//! hook installed at startup, a brute-force attempt against a WordPress login
//! inside `web-servers` on node A blocks that IP on every node in the cluster.
//!
//! ## Sources discovered per node
//! - **container-ssh** — each running LXC container's own sshd, tailed via
//!   `lxc-attach … journalctl` (the host monitor only sees the host's sshd).
//! - **container-web** — apache `*error.log` + nginx `error.log` HTTP-auth
//!   failures inside each container that serves web. We match only unambiguous
//!   basic-auth failures, never bare 404s, so legitimate users are never banned.
//!
//! The host's own sshd/pveproxy/pvedaemon remain covered by
//! [`crate::auth::log_monitor`]; this module deliberately does not duplicate it.
//!
//! ## Lifecycle
//! One tailer thread per (container, source). Threads self-restart if their
//! child dies (journal/log rotation). [`BruteforceState::apply`] stops every
//! worker and respawns the desired set from the current config; it is called at
//! startup and after any config change (local or peer-propagated). Config lives
//! in `/etc/wolfstack/bruteforce.json` and fans out to cluster peers via the
//! standard `X-WolfStack-Secret` path.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::auth::LoginRateLimiter;

fn config_path() -> String {
    format!("{}/bruteforce.json", crate::paths::get().config_dir)
}
fn default_true() -> bool {
    true
}

/// Persisted config — `/etc/wolfstack/bruteforce.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BruteforceConfig {
    /// Master switch for the extended (web + container) monitoring. The host's
    /// own SSH/Proxmox lockout is independent of this and always on.
    #[serde(default)]
    pub enabled: bool,
    /// Watch apache/nginx auth-failure logs inside containers that serve web.
    #[serde(default = "default_true")]
    pub watch_web: bool,
    /// Tail each managed LXC container's own sshd, not just the host's.
    #[serde(default = "default_true")]
    pub watch_container_ssh: bool,
}

impl Default for BruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_web: true,
            watch_container_ssh: true,
        }
    }
}

impl BruteforceConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(config_path()) {
            Ok(d) => serde_json::from_str(&d).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, &json).map_err(|e| format!("write bruteforce.json: {}", e))
    }
}

/// One log source we are (or could be) tailing — surfaced to the UI so the
/// operator sees exactly what a "scan" attached to.
#[derive(Debug, Clone, Serialize)]
pub struct WatchSource {
    /// "container-ssh" | "container-web"
    pub kind: String,
    /// e.g. "lxc:web-servers"
    pub location: String,
    /// The command/log being followed (human-readable).
    pub detail: String,
    /// "watching" | "unavailable"
    pub status: String,
}

impl WatchSource {
    fn key(&self) -> String {
        format!("{}|{}", self.kind, self.location)
    }
}

/// A running tailer. `apply` stops the whole set and respawns, so no per-worker
/// key is tracked — the flag + child PID are all it needs to be torn down.
struct Worker {
    alive: Arc<AtomicBool>,
    /// PID of the current child, so `apply` can break a blocking read.
    child_pid: Arc<Mutex<Option<u32>>>,
}

/// Runtime state — held in `AppState.bruteforce`.
pub struct BruteforceState {
    pub config: RwLock<BruteforceConfig>,
    /// Snapshot of currently-attached sources (for the status/scan UI).
    pub sources: RwLock<Vec<WatchSource>>,
    /// Per-source hit counters since process start (for the dashboard).
    pub hits: RwLock<HashMap<String, u64>>,
    workers: Mutex<Vec<Worker>>,
    limiter: Arc<LoginRateLimiter>,
}

impl BruteforceState {
    pub fn new(limiter: Arc<LoginRateLimiter>) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(BruteforceConfig::load()),
            sources: RwLock::new(Vec::new()),
            hits: RwLock::new(HashMap::new()),
            workers: Mutex::new(Vec::new()),
            limiter,
        })
    }

    /// Enumerate the log sources that *should* be watched on this node given
    /// the config. Pure discovery — spawns nothing. Also used by the "scan"
    /// endpoint so the UI can show what was found before/while attaching.
    pub fn discover(&self) -> Vec<WatchSource> {
        let cfg = self.config.read().unwrap().clone();
        let mut out = Vec::new();
        if !cfg.enabled {
            return out;
        }
        for ct in list_running_lxc() {
            if cfg.watch_container_ssh {
                out.push(WatchSource {
                    kind: "container-ssh".into(),
                    location: format!("lxc:{}", ct),
                    detail: format!("lxc-attach {} journalctl -f _COMM=sshd", ct),
                    status: "watching".into(),
                });
            }
            if cfg.watch_web {
                if let Some(logs) = container_web_logs(&ct) {
                    out.push(WatchSource {
                        kind: "container-web".into(),
                        location: format!("lxc:{}", ct),
                        detail: format!("tail -F {}", logs.join(" ")),
                        status: "watching".into(),
                    });
                }
            }
        }
        out
    }

    /// Stop all workers and (re)spawn the desired set from the current config.
    /// Idempotent; safe to call repeatedly. Called at startup and after any
    /// config change.
    pub fn apply(self: &Arc<Self>) {
        // Stop existing workers: flag dead + kill their child to unblock reads.
        {
            let mut workers = self.workers.lock().unwrap();
            for w in workers.drain(..) {
                w.alive.store(false, Ordering::SeqCst);
                if let Some(pid) = *w.child_pid.lock().unwrap() {
                    kill_pid(pid);
                }
            }
        }

        let desired = self.discover();
        *self.sources.write().unwrap() = desired.clone();

        let mut workers = self.workers.lock().unwrap();
        for src in desired {
            let alive = Arc::new(AtomicBool::new(true));
            let child_pid = Arc::new(Mutex::new(None));
            let w_alive = alive.clone();
            let w_pid = child_pid.clone();
            let state = self.clone();
            std::thread::Builder::new()
                .name("wolfstack-bruteforce".into())
                .spawn(move || worker_loop(src, state, w_alive, w_pid))
                .ok();
            workers.push(Worker { alive, child_pid });
        }
    }

    /// Persist a new config, swap it in, and (re)apply the monitor set. Used by
    /// the config API on both the local node and each peer that receives the
    /// propagated change.
    pub fn set_config_and_apply(
        self: &Arc<Self>,
        cfg: BruteforceConfig,
    ) -> Result<BruteforceConfig, String> {
        cfg.save()?;
        *self.config.write().unwrap() = cfg.clone();
        self.apply();
        Ok(cfg)
    }

    /// Re-run discovery and (re)attach the monitor set, returning the sources
    /// now watched. Used by the "scan" API for live per-node feedback.
    pub fn rescan(self: &Arc<Self>) -> Vec<WatchSource> {
        self.apply();
        self.sources.read().unwrap().clone()
    }

    /// Live snapshot for the status/scan API: watched sources + active bans +
    /// per-source hit counts. Bans come straight from the shared limiter, so
    /// they are identical to what the SSH monitor and login page report.
    pub fn status_json(&self) -> serde_json::Value {
        let cfg = self.config.read().unwrap().clone();
        let sources = self.sources.read().unwrap().clone();
        let hits = self.hits.read().unwrap().clone();
        let lockouts: Vec<serde_json::Value> = self
            .limiter
            .current_lockouts()
            .into_iter()
            .map(|(ip, remaining, user)| {
                serde_json::json!({ "ip": ip, "remaining_seconds": remaining, "last_username": user })
            })
            .collect();
        let hit_rows: Vec<serde_json::Value> = hits
            .iter()
            .map(|(k, n)| serde_json::json!({ "source": k, "hits": n }))
            .collect();
        serde_json::json!({
            "config": {
                "enabled": cfg.enabled,
                "watch_web": cfg.watch_web,
                "watch_container_ssh": cfg.watch_container_ssh,
            },
            "watched_sources": sources,
            "active_bans": lockouts,
            "hits_by_source": hit_rows,
        })
    }
}

/// The tail loop for one source. Self-restarts the child (journal/log rotation)
/// while `alive`; exits promptly once `apply` clears the flag and kills the
/// child.
fn worker_loop(
    src: WatchSource,
    state: Arc<BruteforceState>,
    alive: Arc<AtomicBool>,
    child_pid: Arc<Mutex<Option<u32>>>,
) {
    let key = src.key();
    while alive.load(Ordering::Relaxed) {
        let mut cmd = build_command(&src);
        let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
            Ok(c) => c,
            Err(_) => {
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
        };
        *child_pid.lock().unwrap() = Some(child.id());
        if let Some(out) = child.stdout.take() {
            let reader = BufReader::new(out);
            for line in reader.lines() {
                if !alive.load(Ordering::Relaxed) {
                    break;
                }
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if let Some((ip, user, kind)) = parse_line(&src, &line) {
                    // Same call the login page + SSH monitor use: threshold →
                    // kernel-block → fleet propagation → persist → alert.
                    let tagged = format!("{}:{}", kind, user);
                    let locked = state.limiter.record_failure_with(&ip, &tagged);
                    {
                        let mut h = state.hits.write().unwrap();
                        *h.entry(key.clone()).or_insert(0) += 1;
                    }
                    if locked {
                        tracing::warn!(
                            "bruteforce: {} threshold reached for {} ({}) — kernel-blocked + propagated",
                            src.location, ip, kind
                        );
                    }
                }
            }
        }
        let _ = child.wait();
        *child_pid.lock().unwrap() = None;
        if alive.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

/// Build the follow command for a source.
fn build_command(src: &WatchSource) -> Command {
    let ct = src.location.strip_prefix("lxc:").unwrap_or(&src.location);
    match src.kind.as_str() {
        "container-ssh" => {
            // Tail the container's own journal for sshd auth failures.
            let mut c = Command::new("lxc-attach");
            c.args([
                "-n", ct, "--", "journalctl", "--follow", "--no-pager",
                "--output=short", "--since=now", "_COMM=sshd", "_COMM=sshd-session",
            ]);
            c
        }
        _ => {
            // container-web: follow apache/nginx error logs for basic-auth
            // failures. `-F` survives rotation; `-n0` skips history.
            let mut c = Command::new("lxc-attach");
            c.args([
                "-n", ct, "--", "sh", "-c",
                "tail -F -n0 /var/log/apache2/*error.log /var/log/nginx/*error.log 2>/dev/null",
            ]);
            c
        }
    }
}

/// Dispatch a line to the right parser for its source kind.
fn parse_line(src: &WatchSource, line: &str) -> Option<(String, String, &'static str)> {
    match src.kind.as_str() {
        "container-ssh" => parse_ssh_failure(line),
        _ => parse_web_failure(line),
    }
}

/// sshd failure lines — same shapes as `auth::log_monitor::parse_failure`, kept
/// local so this module stands alone.
fn parse_ssh_failure(line: &str) -> Option<(String, String, &'static str)> {
    if let Some(rest) = line.find("Failed password for ").map(|i| &line[i + 20..]) {
        let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
        if let Some((user_part, after)) = rest.split_once(" from ") {
            let user = user_part.trim().to_string();
            let ip = after.split_whitespace().next()?.to_string();
            return Some((ip, user, "ssh"));
        }
    }
    if let Some(rest) = line.find("Invalid user ").map(|i| &line[i + 13..]) {
        if let Some((user_part, after)) = rest.split_once(" from ") {
            let user = user_part.trim().to_string();
            let ip = after.split_whitespace().next()?.to_string();
            return Some((ip, user, "ssh"));
        }
    }
    None
}

/// Web basic-auth failures only — apache `AH01617/AH01618/AH01797` and nginx
/// "password mismatch" / "was not found" / "no user/password was provided".
/// We deliberately ignore 404s and normal 401 landing pages so a legitimate
/// user who mistypes once (and there is no repeated-failure pattern) is never
/// walked toward a ban by anything but genuine credential guessing.
fn parse_web_failure(line: &str) -> Option<(String, String, &'static str)> {
    let is_apache_auth = line.contains("AH01617")
        || line.contains("AH01618")
        || line.contains("AH01797")
        || (line.contains("auth_basic") && line.contains("authentication failure"));
    let is_nginx_auth = line.contains("password mismatch")
        || line.contains("was not found in")
        || line.contains("no user/password was provided for basic authentication");
    if !is_apache_auth && !is_nginx_auth {
        return None;
    }
    let ip = extract_client_ip(line)?;
    let user = extract_web_user(line);
    Some((ip, user, "web-auth"))
}

/// Pull the client IP from an apache `[client 1.2.3.4:5678]` or nginx
/// `client: 1.2.3.4,` fragment.
fn extract_client_ip(line: &str) -> Option<String> {
    if let Some(i) = line.find("[client ") {
        let rest = &line[i + 8..];
        let end = rest.find(']').unwrap_or(rest.len());
        let token = &rest[..end];
        // strip :port
        let ip = token.rsplit_once(':').map(|(h, _)| h).unwrap_or(token);
        if !ip.is_empty() {
            return Some(ip.trim().to_string());
        }
    }
    if let Some(i) = line.find("client: ") {
        let rest = &line[i + 8..];
        let ip = rest
            .split(|c| c == ',' || c == ' ')
            .next()
            .unwrap_or("")
            .trim();
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }
    None
}

/// Best-effort username from a web auth-failure line (apache `user X:` / nginx
/// `user "X":`). Empty string when absent — the ban does not depend on it.
fn extract_web_user(line: &str) -> String {
    if let Some(i) = line.find("user \"") {
        let rest = &line[i + 6..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    if let Some(i) = line.find("user ") {
        let rest = &line[i + 5..];
        let tok = rest.split(|c| c == ':' || c == ' ').next().unwrap_or("");
        if !tok.is_empty() {
            return tok.trim_matches('"').to_string();
        }
    }
    String::new()
}

/// Running LXC container names, via `lxc-ls -1 --running` (falls back to the
/// non-flag form on older lxc).
fn list_running_lxc() -> Vec<String> {
    let out = Command::new("lxc-ls").args(["-1", "--running"]).output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => match Command::new("lxc-ls").arg("-1").output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        },
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Return the container's web error-log paths if it serves web (apache/nginx
/// error logs present), else None.
fn container_web_logs(ct: &str) -> Option<Vec<String>> {
    let out = Command::new("lxc-attach")
        .args([
            "-n", ct, "--", "sh", "-c",
            "ls /var/log/apache2/*error.log /var/log/nginx/*error.log 2>/dev/null",
        ])
        .output()
        .ok()?;
    let logs: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if logs.is_empty() {
        None
    } else {
        Some(logs)
    }
}

/// SIGKILL a child by PID (used to break a tailer's blocking read on config
/// change). Best-effort; a dead PID is a no-op.
fn kill_pid(pid: u32) {
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_failed_password() {
        let (ip, user, k) =
            parse_ssh_failure("sshd-session[1]: Failed password for root from 5.6.7.8 port 22 ssh2")
                .unwrap();
        assert_eq!((ip.as_str(), user.as_str(), k), ("5.6.7.8", "root", "ssh"));
    }

    #[test]
    fn apache_basic_auth_failure() {
        let line = "[Wed Jul 23 12:00:00 2026] [auth_basic:error] [pid 1] [client 9.9.9.9:44012] AH01617: user admin: authentication failure for \"/private\"";
        let (ip, user, k) = parse_web_failure(line).unwrap();
        assert_eq!((ip.as_str(), user.as_str(), k), ("9.9.9.9", "admin", "web-auth"));
    }

    #[test]
    fn nginx_basic_auth_failure() {
        let line = "2026/07/23 12:00:00 [error] 12#12: *5 user \"bob\": password mismatch, client: 3.3.3.3, server: x, request: \"GET / HTTP/1.1\"";
        let (ip, user, k) = parse_web_failure(line).unwrap();
        assert_eq!((ip.as_str(), user.as_str(), k), ("3.3.3.3", "bob", "web-auth"));
    }

    #[test]
    fn web_non_auth_ignored() {
        assert!(parse_web_failure("[client 1.2.3.4:1] AH00128: File does not exist: /x").is_none());
        assert!(parse_web_failure("some 404 access line").is_none());
    }
}
