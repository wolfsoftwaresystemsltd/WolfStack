// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Fleet Logs ("loghub") — native, dependency-free log aggregation and
//! retention for a WolfStack cluster.
//!
//! ## Roles
//!
//! Every enabled node runs a **shipper** ([`shipper`]) that tails its journald
//! (and, optionally, Docker/LXC container logs), redacts secrets, and forwards
//! batches to the cluster's designated **hub** node. The hub stores everything
//! as compressed, date-segmented JSONL under `paths::loghub_dir`, enforces
//! retention, and answers searches ([`query`], [`store`]).
//!
//! The whole subsystem is **opt-in and off by default** (`LogHubConfig.enabled`
//! starts false). A node that upgrades and never enables Fleet Logs does no new
//! work, ships nothing, and stores nothing — the Golden Rule of never breaking
//! an existing install.
//!
//! The shipper's journald collection is a direct generalisation of
//! [`crate::auth::log_monitor`], which already proves the "tail journald in a
//! blocking thread" pattern for the brute-force defence.
//!
//! Internal flavour: the two worker threads are the *watchers* (a shipper
//! that carries word to the hub, and a janitor that keeps the archive of
//! Minas Tirith from overflowing its vaults).

pub mod store;
pub mod query;
pub mod shipper;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::agent::ClusterState;

/// Where a single log line originated.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Journald,
    Docker,
    Lxc,
    File,
    Other,
}

impl LogSource {
    /// Stable filename stem for this source's segment files.
    pub fn stem(self) -> &'static str {
        match self {
            LogSource::Journald => "journald",
            LogSource::Docker => "docker",
            LogSource::Lxc => "lxc",
            LogSource::File => "file",
            LogSource::Other => "other",
        }
    }
}

/// Syslog-style severity. `Unknown` is allowed and common — many log lines
/// carry no parseable level, and we never guess one.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    // Ordered most-severe → least so `>=`/`<=` comparisons read naturally,
    // with Unknown last so a "min level" filter never hides unlabelled lines
    // unless the operator explicitly asks for a floor above Unknown.
    Emerg,
    Alert,
    Crit,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
    Unknown,
}

impl LogLevel {
    /// Map a syslog numeric priority ("0".."7", as journald emits in
    /// `PRIORITY`) to a level. Anything unparseable is `Unknown`.
    pub fn from_priority(p: &str) -> LogLevel {
        match p.trim() {
            "0" => LogLevel::Emerg,
            "1" => LogLevel::Alert,
            "2" => LogLevel::Crit,
            "3" => LogLevel::Error,
            "4" => LogLevel::Warning,
            "5" => LogLevel::Notice,
            "6" => LogLevel::Info,
            "7" => LogLevel::Debug,
            _ => LogLevel::Unknown,
        }
    }

    /// Best-effort severity sniff for sources with no structured priority
    /// (Docker/LXC plain text). Conservative — defaults to `Unknown` rather
    /// than mislabelling.
    pub fn sniff(line: &str) -> LogLevel {
        let l = line.to_ascii_lowercase();
        // Look only near the start of the line to avoid matching the word
        // "error" inside a normal message body.
        let head: String = l.chars().take(64).collect();
        if head.contains("emerg") || head.contains("fatal") || head.contains("panic") {
            LogLevel::Crit
        } else if head.contains("error") || head.contains(" err ") || head.contains("[error]") {
            LogLevel::Error
        } else if head.contains("warn") {
            LogLevel::Warning
        } else if head.contains("notice") {
            LogLevel::Notice
        } else if head.contains("debug") || head.contains("trace") {
            LogLevel::Debug
        } else if head.contains("info") {
            LogLevel::Info
        } else {
            LogLevel::Unknown
        }
    }
}

/// One normalised log line. Serialised one-per-line as JSONL in the store.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogEvent {
    /// Unix milliseconds (hub-normalised, UTC).
    pub ts: i64,
    /// Originating node id (`ClusterState` id).
    pub node: String,
    pub source: LogSource,
    /// systemd unit / container name / file path.
    pub unit: String,
    pub level: LogLevel,
    /// The (post-redaction) message text.
    pub msg: String,
    /// Optional structured extras. Skipped when empty to keep segments small.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}
fn default_retention_days() -> u32 {
    14
}
fn default_max_bytes() -> u64 {
    10 * 1024 * 1024 * 1024 // 10 GiB
}
fn default_min_free_pct() -> f64 {
    10.0
}

/// Persisted Fleet Logs configuration (`paths::loghub_config`,
/// `/etc/wolfstack/loghub.json`). Holds no credentials.
///
/// Every field carries a serde default so a config written by an older build
/// (or a `{}` fresh file) keeps deserialising across upgrades.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct LogHubConfig {
    /// Master switch. Off by default — nothing ships or stores until an
    /// operator turns it on and designates a hub.
    #[serde(default)]
    pub enabled: bool,
    /// The node id that stores logs for this cluster. `None` until set.
    #[serde(default)]
    pub hub_node_id: Option<String>,
    /// Delete segments older than this many days.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// Hard cap on the total on-disk store size (bytes). Oldest segments are
    /// shed first when exceeded.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Minimum free-space percentage on the store filesystem. Below this the
    /// hub stops ingesting and raises an alert rather than filling the disk.
    #[serde(default = "default_min_free_pct")]
    pub min_free_pct: f64,
    #[serde(default = "default_true")]
    pub ship_journald: bool,
    #[serde(default)]
    pub ship_docker: bool,
    #[serde(default)]
    pub ship_lxc: bool,
    /// Apply the built-in secret-redaction patterns before transmit/store.
    #[serde(default = "default_true")]
    pub redaction_builtin: bool,
    /// Extra operator-supplied redaction regexes (whole match replaced).
    #[serde(default)]
    pub redaction_patterns: Vec<String>,
    /// systemd units / container names to never collect.
    #[serde(default)]
    pub unit_denylist: Vec<String>,
}

impl Default for LogHubConfig {
    fn default() -> Self {
        // Lean on the serde defaults so this and on-disk `{}` agree exactly.
        serde_json::from_str("{}").expect("LogHubConfig defaults must deserialise")
    }
}

impl LogHubConfig {
    pub fn load() -> LogHubConfig {
        let path = crate::paths::get().loghub_config;
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => LogHubConfig::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = crate::paths::get().loghub_config;
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialise loghub config: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("write loghub config: {e}"))
    }
}

/// Runtime statistics surfaced on `/api/logs/stats`.
#[derive(Serialize, Clone, Default)]
pub struct LogHubStats {
    pub store_bytes: u64,
    pub segment_count: u64,
    pub node_count: u64,
    pub oldest_ts: Option<i64>,
    pub newest_ts: Option<i64>,
    pub free_pct: Option<f64>,
    pub ingest_blocked: bool,
}

/// Shared Fleet Logs state, held on `AppState`.
pub struct LogHubState {
    pub config: RwLock<LogHubConfig>,
    pub node_id: String,
    /// Total events written to disk by this hub since boot.
    pub ingested: AtomicU64,
    /// Events dropped from a shipper spool because the hub was unreachable
    /// and the spool hit its cap. Surfaced so the operator sees data loss.
    pub dropped: AtomicU64,
    /// True when the janitor has paused ingest due to low disk. Ingest
    /// returns 507 in this state; shippers keep spooling.
    pub ingest_blocked: AtomicBool,
    /// Ensures the worker threads are spawned exactly once.
    started: AtomicBool,
}

impl LogHubState {
    pub fn new(node_id: String) -> LogHubState {
        LogHubState {
            config: RwLock::new(LogHubConfig::load()),
            node_id,
            ingested: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            ingest_blocked: AtomicBool::new(false),
            started: AtomicBool::new(false),
        }
    }

    /// True when this node is the cluster's designated storage hub.
    pub fn is_hub(&self) -> bool {
        let cfg = self.config.read().unwrap();
        cfg.enabled && cfg.hub_node_id.as_deref() == Some(self.node_id.as_str())
    }

    pub fn store_root(&self) -> String {
        crate::paths::get().loghub_dir
    }
}

/// Current unix time in milliseconds.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// UTC `YYYY-MM-DD` segment-date string for a millisecond timestamp.
pub fn date_str(ts_millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts_millis)
        .unwrap_or_else(chrono::Utc::now)
        .format("%Y-%m-%d")
        .to_string()
}

/// Compiled secret-redaction engine. Built once per shipper round from the
/// active config; cheap to construct (a handful of regexes).
pub struct Redactor {
    res: Vec<regex::Regex>,
    kv: Option<regex::Regex>,
}

impl Redactor {
    pub fn new(cfg: &LogHubConfig) -> Redactor {
        let mut res = Vec::new();
        let mut kv = None;
        if cfg.redaction_builtin {
            // key=value / key: value secrets — keep the key, mask the value.
            // No lookbehind in `regex`, so we capture the key ($1) and rebuild.
            kv = regex::Regex::new(
                r#"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth|bearer|client[_-]?secret|private[_-]?key|session[_-]?id)\b(\s*[=:]\s*)(?:"[^"]*"|'[^']*'|\S+)"#,
            )
            .ok();
            // Whole-match maskers for well-known credential shapes.
            for p in [
                // Authorization header — consume the WHOLE value to end of line,
                // not just the first token (otherwise "Bearer <token>" leaked
                // the token after "Bearer").
                r"(?i)authorization:\s*.+",
                // Bare "Bearer <token>" without an Authorization: prefix.
                r"(?i)bearer\s+[A-Za-z0-9._~+/=\-]{6,}",
                r"AKIA[0-9A-Z]{16}",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
                r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", // JWT
            ] {
                if let Ok(re) = regex::Regex::new(p) {
                    res.push(re);
                }
            }
        }
        for p in &cfg.redaction_patterns {
            if let Ok(re) = regex::Regex::new(p) {
                res.push(re);
            }
        }
        Redactor { res, kv }
    }

    pub fn apply(&self, line: &str) -> String {
        let mut out = std::borrow::Cow::Borrowed(line);
        if let Some(kv) = &self.kv {
            out = std::borrow::Cow::Owned(kv.replace_all(&out, "$1$2***REDACTED***").into_owned());
        }
        for re in &self.res {
            if re.is_match(&out) {
                out = std::borrow::Cow::Owned(re.replace_all(&out, "***REDACTED***").into_owned());
            }
        }
        out.into_owned()
    }
}

/// Spawn the Fleet Logs worker threads. Idempotent — safe to call once at
/// boot; the worker loops re-read config every tick, so toggling `enabled`
/// (or changing the hub/retention) at runtime takes effect with no restart.
///
/// Both threads are no-op sleepers while `enabled` is false, so calling this
/// unconditionally at startup costs nothing on installs that never opt in.
pub fn start(loghub: Arc<LogHubState>, cluster: Arc<ClusterState>, cluster_secret: String) {
    if loghub.started.swap(true, Ordering::SeqCst) {
        return; // already running
    }

    // Shipper — collects this node's logs and forwards them to the hub.
    {
        let loghub = loghub.clone();
        let cluster = cluster.clone();
        let secret = cluster_secret.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("wolfstack-logship".into())
            .spawn(move || shipper::ship_loop(loghub, cluster, secret))
        {
            tracing::error!("loghub: failed to spawn shipper thread: {e}");
        }
    }

    // Janitor — retention + disk safety. Only does work when this node is the
    // hub; otherwise it idles.
    {
        let loghub = loghub.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("wolfstack-logjanitor".into())
            .spawn(move || store::janitor_loop(loghub))
        {
            tracing::error!("loghub: failed to spawn janitor thread: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_safe() {
        let c = LogHubConfig::default();
        assert!(!c.enabled, "must be opt-in / off by default");
        assert_eq!(c.retention_days, 14);
        assert_eq!(c.max_bytes, 10 * 1024 * 1024 * 1024);
        assert!(c.redaction_builtin);
        assert!(c.ship_journald);
        assert!(!c.ship_docker);
    }

    #[test]
    fn level_from_priority() {
        assert_eq!(LogLevel::from_priority("3"), LogLevel::Error);
        assert_eq!(LogLevel::from_priority("6"), LogLevel::Info);
        assert_eq!(LogLevel::from_priority("x"), LogLevel::Unknown);
    }

    #[test]
    fn redactor_masks_secrets_keeps_key() {
        let cfg = LogHubConfig::default();
        let r = Redactor::new(&cfg);
        let out = r.apply("user=bob password=hunter2 ok");
        assert!(out.contains("user=bob"), "non-secret kept: {out}");
        assert!(out.contains("password"), "key kept: {out}");
        assert!(!out.contains("hunter2"), "secret masked: {out}");
        assert!(out.contains("***REDACTED***"));
    }

    #[test]
    fn redactor_masks_bearer_and_jwt() {
        let cfg = LogHubConfig::default();
        let r = Redactor::new(&cfg);
        let jwt = "token eyJabcdefghij.eyJklmnopqrst.signature123456";
        let out = r.apply(jwt);
        assert!(!out.contains("eyJabcdefghij.eyJklmnopqrst.signature123456"), "{out}");
        let auth = r.apply("Authorization: Bearer sk-secret-value-here");
        assert!(!auth.contains("sk-secret-value-here"), "{auth}");
    }

    #[test]
    fn date_str_is_utc_ymd() {
        // 2021-01-01T00:00:00Z = 1609459200000 ms
        assert_eq!(date_str(1_609_459_200_000), "2021-01-01");
    }
}
