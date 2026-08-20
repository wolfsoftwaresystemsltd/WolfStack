// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! S3 bucket-sync jobs: "keep bucket A on remote X in sync with bucket B
//! on remote Y", executed by rclone. Local↔cloud, cloud↔cloud and
//! local↔local pairs are all just two saved-remote ids — the engine does
//! not care where either side lives.
//!
//! Design decisions (all from live operation of the wtgrid asset mirror,
//! 2026-08-14→17 — see plans/s3-storage-and-sync.md):
//! - `copy` is the default mode: for append-only stores it is backup and
//!   failover feed at once, and deletions/corruption can never propagate.
//!   `sync` DELETES destination objects and is gated behind an explicit
//!   confirmation field at save time.
//! - Credentials are NEVER stored in the job and never written to disk
//!   for rclone: jobs hold remote IDs, resolved from the S3Remote store
//!   at run time and handed to rclone via RCLONE_CONFIG_* environment
//!   variables on the child process (grammar verified empirically against
//!   rclone v1.74.4). Key rotation in the remotes store fixes every job.
//! - A pass that only wants "new objects" still LISTs the entire source
//!   (--no-traverse only skips the destination), so `--max-age` must be
//!   MUCH larger than one pass. Window::Auto = max(24h, 4× last pass);
//!   the first pass (and every `sync`-mode pass) runs Full.
//! - Stats flags are mandatory: at plain NOTICE rclone writes literally
//!   nothing to its log, so a run would leave a 0-byte file and no record.
//! - One in-flight run per job, enforced in-process; log rotation happens
//!   BETWEEN runs (we start rclone per pass, so no copytruncate dance).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use tracing::{info, warn};

const RUN_HISTORY_KEPT: usize = 20;
/// Hard ceiling on one rclone pass. Generous — the 18.7M-object wtgrid
/// seed took 51h45m; a routine incremental is minutes-to-hours. `timeout`
/// SIGTERMs at the cap and SIGKILLs 60s later.
const RUN_TIMEOUT_SECS: u64 = 60 * 60 * 60;
/// Rotate a job's log when it crosses this size (between runs).
const LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;

fn log_dir() -> String { crate::paths::get().s3_sync_log_dir }

fn config_file() -> String {
    let storage = super::config_path();
    let dir = std::path::Path::new(&storage)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/etc/wolfstack".to_string());
    format!("{}/s3-sync.json", dir)
}

// ─── Model ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEndpoint {
    /// Id in the S3Remote store (`wolfstack:name`, `rclone:name`, …).
    pub remote_id: String,
    pub bucket: String,
    /// Optional key prefix ("directory") within the bucket.
    #[serde(default)]
    pub prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// rclone copy — additive only; never deletes at the destination.
    Copy,
    /// rclone sync — makes destination IDENTICAL to source, deletions
    /// included. Gated at save time by `confirm_sync`.
    Sync,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncSchedule {
    /// Next pass starts `gap_minutes` after the previous one FINISHES.
    /// The honest default: a fixed calendar against a pass that takes
    /// hours silently skips slots (the wtgrid OnCalendar=hourly lesson).
    BackToBack { gap_minutes: u32 },
    /// Classic cron (same matcher WolfFlow uses). For genuinely short
    /// jobs where a calendar makes sense.
    Cron { expr: String },
    /// Run-now button only.
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncWindow {
    /// max(24h, 4 × last pass duration) — self-tunes as passes grow.
    Auto,
    /// Operator-fixed --max-age, in hours.
    MaxAgeHours { hours: u32 },
    /// No --max-age: consider every object, every pass.
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncTuning {
    #[serde(default = "default_transfers")]
    pub transfers: u32,
    #[serde(default = "default_checkers")]
    pub checkers: u32,
    /// rclone --bwlimit value ("10M", "1M:100k", "" = unlimited).
    #[serde(default)]
    pub bwlimit: String,
}

fn default_transfers() -> u32 { 32 }
fn default_checkers() -> u32 { 16 }

impl Default for SyncTuning {
    fn default() -> Self {
        // 32/16 ran the 1.3TB wtgrid seed and its incrementals without
        // drama on a 64GB box — sane middle ground.
        Self { transfers: 32, checkers: 16, bwlimit: String::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncRunRecord {
    pub started_epoch: u64,
    pub ended_epoch: u64,
    pub ok: bool,
    pub exit_code: i32,
    /// Objects transferred this pass (rclone's countable Transferred line).
    pub objects: u64,
    /// Human bytes figure from rclone's stats ("1.292 TiB / 1.292 TiB").
    pub bytes_human: String,
    pub errors: u64,
    /// "OK", or the tail of what went wrong.
    pub message: String,
    /// Which --max-age this pass ran with ("full" when none).
    pub window: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncJob {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub src: SyncEndpoint,
    pub dst: SyncEndpoint,
    pub mode: SyncMode,
    pub schedule: SyncSchedule,
    pub window: SyncWindow,
    #[serde(default)]
    pub tuning: SyncTuning,
    #[serde(default)]
    pub last_runs: Vec<SyncRunRecord>,
    /// Epoch of the last SUCCESSFUL pass end — the lag clock.
    #[serde(default)]
    pub last_success_epoch: u64,
    /// Duration of the last completed pass, feeds Window::Auto.
    #[serde(default)]
    pub last_pass_secs: u64,
    /// Lag alert latched (cleared on the next success) — one alert per
    /// stall, mirroring s3_health's outage/recovery edges.
    #[serde(default)]
    pub lag_alerted: bool,
    /// Epoch minute of the last cron trigger, so one cron match fires
    /// exactly once.
    #[serde(default)]
    pub last_cron_fire_minute: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub jobs: Vec<SyncJob>,
}

pub fn load() -> SyncConfig {
    match fs::read_to_string(config_file()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            warn!("Failed to parse {}: {} — starting empty", config_file(), e);
            SyncConfig::default()
        }),
        Err(_) => SyncConfig::default(),
    }
}

fn save(config: &SyncConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize sync config: {}", e))?;
    // Plain write is fine — the file holds remote IDs and stats, never
    // credentials (that is the whole point of the remote-id indirection).
    fs::write(config_file(), json)
        .map_err(|e| format!("Failed to write {}: {}", config_file(), e))
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Validation / persistence API ───

/// True while a job's rclone pass is in flight on this node.
static RUNNING: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn is_running(job_id: &str) -> bool {
    RUNNING.lock().map(|r| r.contains(job_id)).unwrap_or(false)
}

/// Guard that releases the running-set slot even if the run panics.
struct RunSlot(String);
impl Drop for RunSlot {
    fn drop(&mut self) {
        if let Ok(mut r) = RUNNING.lock() {
            r.remove(&self.0);
        }
    }
}

/// Create or update a job. `confirm_sync` must be true to save a job in
/// Sync (deleting) mode — the API layer passes the UI's typed
/// confirmation through, so a bare API call can't slip a deleting job in
/// quietly either.
pub fn save_job(mut job: SyncJob, confirm_sync: bool) -> Result<SyncJob, String> {
    job.name = job.name.trim().to_string();
    if job.name.is_empty() {
        return Err("Job name is required".to_string());
    }
    if job.mode == SyncMode::Sync && !confirm_sync {
        return Err(
            "This job uses sync mode, which DELETES destination objects that vanish from the source. \
             Confirm that explicitly to save it."
                .to_string(),
        );
    }
    for (label, ep) in [("Source", &job.src), ("Destination", &job.dst)] {
        if super::find_s3_remote(&ep.remote_id).is_none() {
            return Err(format!("{} remote '{}' does not exist", label, ep.remote_id));
        }
        super::validate_bucket_name(&ep.bucket)
            .map_err(|e| format!("{} bucket: {}", label, e))?;
    }
    if job.src.remote_id == job.dst.remote_id
        && job.src.bucket == job.dst.bucket
        && job.src.prefix.trim_matches('/') == job.dst.prefix.trim_matches('/')
    {
        return Err("Source and destination are the same bucket and prefix".to_string());
    }
    if let SyncSchedule::Cron { expr } = &job.schedule {
        // Validate the shape now, not at 3am: cron_matches on a bad expr
        // just never matches, which would read as "scheduler broken".
        if expr.split_whitespace().count() != 5 {
            return Err("Cron expression must have 5 fields (min hour dom month dow)".to_string());
        }
    }
    if let SyncSchedule::BackToBack { gap_minutes } = &job.schedule
        && *gap_minutes == 0
    {
        return Err("Gap between passes must be at least 1 minute".to_string());
    }
    if job.tuning.transfers == 0 || job.tuning.checkers == 0 {
        return Err("Transfers and checkers must be at least 1".to_string());
    }

    let mut config = load();
    if job.id.is_empty() {
        job.id = uuid::Uuid::new_v4().to_string();
        job.created_at = utc_now_string();
        config.jobs.push(job.clone());
    } else {
        match config.jobs.iter_mut().find(|j| j.id == job.id) {
            Some(existing) => {
                // Preserve run history/stats across edits.
                job.last_runs = existing.last_runs.clone();
                job.last_success_epoch = existing.last_success_epoch;
                job.last_pass_secs = existing.last_pass_secs;
                job.lag_alerted = existing.lag_alerted;
                job.last_cron_fire_minute = existing.last_cron_fire_minute;
                job.created_at = existing.created_at.clone();
                *existing = job.clone();
            }
            None => return Err(format!("Sync job '{}' not found", job.id)),
        }
    }
    save(&config)?;
    Ok(job)
}

fn utc_now_string() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn delete_job(id: &str) -> Result<(), String> {
    if is_running(id) {
        return Err("This job is currently running — wait for the pass to finish first".to_string());
    }
    let mut config = load();
    let before = config.jobs.len();
    config.jobs.retain(|j| j.id != id);
    if config.jobs.len() == before {
        return Err(format!("Sync job '{}' not found", id));
    }
    save(&config)
}

pub fn set_enabled(id: &str, enabled: bool) -> Result<(), String> {
    let mut config = load();
    let job = config.jobs.iter_mut().find(|j| j.id == id)
        .ok_or_else(|| format!("Sync job '{}' not found", id))?;
    job.enabled = enabled;
    save(&config)
}

/// Enabled sync jobs referencing a remote id — the delete-remote
/// dependency check ("what would break?").
pub fn jobs_using_remote(remote_id: &str) -> Vec<String> {
    load()
        .jobs
        .iter()
        .filter(|j| j.enabled && (j.src.remote_id == remote_id || j.dst.remote_id == remote_id))
        .map(|j| j.name.clone())
        .collect()
}

// ─── rclone invocation ───

/// Our provider strings → rclone's s3 provider names (rclone v1.74.4
/// `help backend s3`, captured 2026-08-18). Garage and Backblaze's
/// S3-compatible endpoint have no dedicated rclone provider — "Other"
/// is correct for both (verified against a live garage v2.3.0).
fn rclone_provider(provider: &str) -> &'static str {
    match provider {
        "AWS" => "AWS",
        "Cloudflare" => "Cloudflare",
        "DigitalOcean" => "DigitalOcean",
        "Wasabi" => "Wasabi",
        "IDrive" => "IDrive",
        "Minio" => "Minio",
        "Hetzner" => "Hetzner",
        "Scaleway" => "Scaleway",
        _ => "Other",
    }
}

/// RCLONE_CONFIG_<NAME>_* variables for one side. Nothing is written to
/// disk and nothing appears in argv (`ps` shows only remote names).
fn remote_env(name: &str, remote: &super::S3Remote) -> Vec<(String, String)> {
    let mut env = vec![
        (format!("RCLONE_CONFIG_{}_TYPE", name), "s3".to_string()),
        (format!("RCLONE_CONFIG_{}_PROVIDER", name), rclone_provider(&remote.provider).to_string()),
        (format!("RCLONE_CONFIG_{}_ACCESS_KEY_ID", name), remote.access_key_id.clone()),
        (format!("RCLONE_CONFIG_{}_SECRET_ACCESS_KEY", name), remote.secret_access_key.clone()),
    ];
    let endpoint = remote.endpoint.trim();
    if !endpoint.is_empty() {
        env.push((format!("RCLONE_CONFIG_{}_ENDPOINT", name), super::endpoint_url(endpoint)));
    }
    let region = remote.region.trim();
    if !region.is_empty() {
        env.push((format!("RCLONE_CONFIG_{}_REGION", name), region.to_string()));
    }
    env
}

/// "SRC:bucket/prefix" — prefix slashes normalised.
fn rclone_path(name: &str, ep: &SyncEndpoint) -> String {
    let prefix = ep.prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        format!("{}:{}", name, ep.bucket)
    } else {
        format!("{}:{}/{}", name, ep.bucket, prefix)
    }
}

/// The --max-age for this pass, or None for a full pass. First pass and
/// every Sync-mode pass are Full: a windowed first pass would silently
/// skip the backlog, and sync-with-a-window can neither see nor apply
/// deletions correctly.
fn effective_window_hours(job: &SyncJob) -> Option<u64> {
    if job.mode == SyncMode::Sync || job.last_success_epoch == 0 {
        return None;
    }
    match &job.window {
        SyncWindow::Full => None,
        SyncWindow::MaxAgeHours { hours } => Some(*hours as u64),
        SyncWindow::Auto => {
            // 4× the last pass, floor 24h, rounded UP to whole hours.
            let four_passes_hours = (job.last_pass_secs * 4).div_ceil(3600);
            Some(four_passes_hours.max(24))
        }
    }
}

fn job_log_path(job_id: &str) -> String {
    format!("{}/{}.log", log_dir(), job_id)
}

/// Rotate between runs when big — we start rclone per pass, so unlike a
/// long-lived daemon there is no open-fd problem and no copytruncate.
fn rotate_log_if_big(path: &str) {
    if let Ok(meta) = fs::metadata(path)
        && meta.len() > LOG_ROTATE_BYTES
    {
        let _ = fs::rename(path, format!("{}.1", path));
    }
}

/// Execute one pass of a job synchronously (call via spawn_blocking /
/// web::block). Updates the stored job record whatever the outcome.
pub fn run_job(job_id: &str) -> Result<SyncRunRecord, String> {
    // Single flight — insert-or-bail, slot released by RunSlot's Drop.
    {
        let mut running = RUNNING.lock().map_err(|_| "running-set lock poisoned".to_string())?;
        if !running.insert(job_id.to_string()) {
            return Err("A pass for this job is already running".to_string());
        }
    }
    let _slot = RunSlot(job_id.to_string());

    let config = load();
    let job = config.jobs.iter().find(|j| j.id == job_id)
        .ok_or_else(|| format!("Sync job '{}' not found", job_id))?
        .clone();

    let src_remote = super::find_s3_remote(&job.src.remote_id)
        .ok_or_else(|| format!("Source remote '{}' no longer exists", job.src.remote_id))?;
    let dst_remote = super::find_s3_remote(&job.dst.remote_id)
        .ok_or_else(|| format!("Destination remote '{}' no longer exists", job.dst.remote_id))?;

    let log_base = log_dir();
    fs::create_dir_all(&log_base).map_err(|e| format!("Failed to create {}: {}", log_base, e))?;
    let log_path = job_log_path(&job.id);
    rotate_log_if_big(&log_path);
    let log_offset = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let window_hours = effective_window_hours(&job);
    let window_label = window_hours.map(|h| format!("{}h", h)).unwrap_or_else(|| "full".to_string());

    let verb = match job.mode { SyncMode::Copy => "copy", SyncMode::Sync => "sync" };
    let mut args: Vec<String> = vec![
        "--kill-after=60".into(),
        RUN_TIMEOUT_SECS.to_string(),
        "rclone".into(),
        verb.into(),
        rclone_path("WSSRC", &job.src),
        rclone_path("WSDST", &job.dst),
        "--transfers".into(), job.tuning.transfers.to_string(),
        "--checkers".into(), job.tuning.checkers.to_string(),
        // The stats flags are NOT optional: bare NOTICE logs nothing at
        // all, so without these a pass leaves a 0-byte log and no record
        // of what it did (observed live on asset-mirror-1). Deliberately
        // NOT --stats-one-line: the one-line form is a bare "17 B / 17 B,
        // 100%, …" with no Transferred:/Errors: labels and NO object
        // count (verified live against rclone v1.74.4), which would make
        // the run record unparseable. The full block is what the record
        // parser reads.
        "--stats".into(), "30m".into(),
        "--stats-log-level".into(), "NOTICE".into(),
        "--log-level".into(), "NOTICE".into(),
        "--log-file".into(), log_path.clone(),
    ];
    if let Some(hours) = window_hours {
        // A windowed pass still LISTs the whole source; --no-traverse
        // skips the (pointless) full destination listing.
        args.push("--max-age".into());
        args.push(format!("{}h", hours));
        args.push("--no-traverse".into());
    }
    if !job.tuning.bwlimit.trim().is_empty() {
        args.push("--bwlimit".into());
        args.push(job.tuning.bwlimit.trim().to_string());
    }

    let mut cmd = Command::new("timeout");
    cmd.args(&args);
    for (k, v) in remote_env("WSSRC", &src_remote).into_iter().chain(remote_env("WSDST", &dst_remote)) {
        cmd.env(k, v);
    }

    let started = now_epoch();
    info!("s3-sync '{}': starting {} pass (window {})", job.name, verb, window_label);
    let output = cmd.output().map_err(|e| format!("Failed to launch rclone: {}", e))?;
    let ended = now_epoch();
    let exit_code = output.status.code().unwrap_or(-1);

    // rclone's own log went to --log-file; stderr only carries launcher-
    // level failures (binary missing, timeout kill).
    let segment = read_log_segment(&log_path, log_offset);
    let stats = parse_rclone_stats(&segment);

    let ok = exit_code == 0;
    let message = if ok {
        "OK".to_string()
    } else if exit_code == 124 {
        format!("Pass exceeded the {}h ceiling and was stopped", RUN_TIMEOUT_SECS / 3600)
    } else {
        // Last ERROR-ish line of the log segment, else stderr tail.
        last_error_line(&segment)
            .or_else(|| {
                let e = String::from_utf8_lossy(&output.stderr);
                let t = e.trim();
                if t.is_empty() { None } else { Some(t.chars().rev().take(300).collect::<String>().chars().rev().collect()) }
            })
            .unwrap_or_else(|| format!("rclone exited with code {}", exit_code))
    };

    let record = SyncRunRecord {
        started_epoch: started,
        ended_epoch: ended,
        ok,
        exit_code,
        objects: stats.objects,
        bytes_human: stats.bytes_human,
        errors: stats.errors,
        message,
        window: window_label,
    };

    // Persist the outcome — reload the config so a concurrent edit to a
    // DIFFERENT job made during a long pass isn't clobbered.
    let mut config = load();
    if let Some(stored) = config.jobs.iter_mut().find(|j| j.id == job_id) {
        stored.last_runs.insert(0, record.clone());
        stored.last_runs.truncate(RUN_HISTORY_KEPT);
        stored.last_pass_secs = ended.saturating_sub(started);
        if ok {
            stored.last_success_epoch = ended;
            stored.lag_alerted = false;
        }
        if let Err(e) = save(&config) {
            warn!("s3-sync '{}': pass finished but saving the record failed: {}", job.name, e);
        }
    }
    info!(
        "s3-sync '{}': pass finished ok={} objects={} errors={} in {}s",
        job.name, record.ok, record.objects, record.errors, ended.saturating_sub(started)
    );
    Ok(record)
}

struct ParsedStats {
    objects: u64,
    bytes_human: String,
    errors: u64,
}

fn read_log_segment(path: &str, from: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = fs::File::open(path) else { return String::new() };
    if f.seek(SeekFrom::Start(from)).is_err() {
        return String::new();
    }
    let mut s = String::new();
    let _ = f.take(2 * 1024 * 1024).read_to_string(&mut s);
    s
}

/// Pull the FINAL stats block out of a pass's log segment. Shape
/// (verified against real rclone logs from asset-mirror-1, v1.6x-1.7x):
///   Transferred:        1.292 TiB / 1.292 TiB, 100%, 8.630 MiB/s, ETA 0s
///   Errors:                 3 (retrying may help)          ← absent when 0
///   Transferred:     18677740 / 18677740, 100%
///   Elapsed time:  51h45m16.8s
/// The bytes line carries a unit; the objects line is bare numbers.
fn parse_rclone_stats(segment: &str) -> ParsedStats {
    let mut objects = 0u64;
    let mut bytes_human = String::new();
    let mut errors = 0u64;
    for line in segment.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Transferred:") {
            let value = rest.trim();
            // "18677740 / 18677740, 100%"  vs  "1.292 TiB / 1.292 TiB, …"
            let first_token = value.split_whitespace().next().unwrap_or("");
            let second_token = value.split_whitespace().nth(1).unwrap_or("");
            if (second_token.starts_with('/') || second_token == "/")
                && let Ok(n) = first_token.trim_end_matches(',').parse::<u64>()
            {
                objects = n;
                continue;
            }
            bytes_human = value.split(',').next().unwrap_or(value).trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("Errors:")
            && let Some(n) = rest.split_whitespace().next()
        {
            errors = n.parse::<u64>().unwrap_or(0);
        }
    }
    ParsedStats { objects, bytes_human, errors }
}

fn last_error_line(segment: &str) -> Option<String> {
    segment
        .lines()
        .rev()
        .find(|l| l.contains("ERROR") || l.contains("CRITICAL") || l.contains("Failed to"))
        .map(|l| {
            let t = l.trim();
            if t.chars().count() > 300 {
                let cut: String = t.chars().take(300).collect();
                format!("{}…", cut)
            } else {
                t.to_string()
            }
        })
}

/// Tail of a job's log for the UI viewer.
pub fn read_job_log(job_id: &str, max_bytes: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let path = job_log_path(job_id);
    let Ok(mut f) = fs::File::open(&path) else {
        return String::from("(no log yet — the job has not run on this node)");
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(max_bytes);
    let _ = f.seek(SeekFrom::Start(start));
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    if start > 0 {
        format!("… (showing last {} bytes)\n{}", max_bytes, s)
    } else {
        s
    }
}

// ─── Scheduler (driven from main.rs every 60s) ───

/// A lag alert edge for the caller to dispatch (same pattern as
/// s3_health::HealthAlert — this module is sync, alerting is async).
pub struct SyncAlert {
    pub title: String,
    pub body: String,
}

/// Jobs whose schedule says "start a pass now". Returns their ids; the
/// caller spawns run_job for each. Also computes lag alerts.
pub fn due_jobs_and_alerts() -> (Vec<String>, Vec<SyncAlert>) {
    let mut config = load();
    let now = now_epoch();
    let mut due = Vec::new();
    let mut alerts = Vec::new();
    let mut dirty = false;

    for job in config.jobs.iter_mut() {
        if !job.enabled || is_running(&job.id) {
            continue;
        }
        let last_finished = job.last_runs.first().map(|r| r.ended_epoch).unwrap_or(0);
        match &job.schedule {
            SyncSchedule::BackToBack { gap_minutes } => {
                if now >= last_finished + (*gap_minutes as u64) * 60 {
                    due.push(job.id.clone());
                }
            }
            SyncSchedule::Cron { expr } => {
                let minute = now / 60;
                if minute != job.last_cron_fire_minute {
                    let local = chrono::Local::now().naive_local();
                    if crate::wolfflow::cron_matches(expr, &local) {
                        job.last_cron_fire_minute = minute;
                        dirty = true;
                        due.push(job.id.clone());
                    }
                }
            }
            SyncSchedule::Manual => {}
        }

        // Lag: catches "passes succeed but the scheduler died" and "pass
        // duration crept past the cadence". Threshold = 3 × (typical pass
        // + gap), floor 2h so a brand-new fast job doesn't false-alarm.
        if job.last_success_epoch > 0 && !job.lag_alerted {
            let gap_secs = match &job.schedule {
                SyncSchedule::BackToBack { gap_minutes } => (*gap_minutes as u64) * 60,
                SyncSchedule::Cron { .. } => 3600,
                SyncSchedule::Manual => continue,
            };
            let threshold = (3 * (job.last_pass_secs + gap_secs)).max(2 * 3600);
            let lag = now.saturating_sub(job.last_success_epoch);
            if lag > threshold {
                job.lag_alerted = true;
                dirty = true;
                alerts.push(SyncAlert {
                    title: format!("S3 sync job falling behind: {}", job.name),
                    body: format!(
                        "“{}” last completed successfully {} hours ago (threshold {} hours).\n\n\
                         Source:      {} / {}\n\
                         Destination: {} / {}\n\
                         Last result: {}\n\n\
                         Check the job's log under Storage → Bucket Sync.",
                        job.name,
                        lag / 3600,
                        threshold / 3600,
                        job.src.remote_id, job.src.bucket,
                        job.dst.remote_id, job.dst.bucket,
                        job.last_runs.first().map(|r| r.message.clone()).unwrap_or_else(|| "never ran".into()),
                    ),
                });
            }
        }
    }

    if dirty && let Err(e) = save(&config) {
        warn!("s3-sync scheduler: failed to persist cron/lag state: {}", e);
    }
    (due, alerts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job_with(mode: SyncMode, window: SyncWindow, last_success: u64, last_pass: u64) -> SyncJob {
        SyncJob {
            id: "t".into(),
            name: "t".into(),
            enabled: true,
            src: SyncEndpoint { remote_id: "a".into(), bucket: "b1".into(), prefix: String::new() },
            dst: SyncEndpoint { remote_id: "c".into(), bucket: "b2".into(), prefix: String::new() },
            mode,
            schedule: SyncSchedule::Manual,
            window,
            tuning: SyncTuning::default(),
            last_runs: Vec::new(),
            last_success_epoch: last_success,
            last_pass_secs: last_pass,
            lag_alerted: false,
            last_cron_fire_minute: 0,
            created_at: String::new(),
        }
    }

    /// The window rules that came out of the wtgrid incident: first pass
    /// full, sync-mode always full, Auto = max(24h, 4× last pass).
    #[test]
    fn window_rules_from_the_wtgrid_lessons() {
        // First pass (no success yet): full, whatever the window says.
        assert_eq!(effective_window_hours(&job_with(SyncMode::Copy, SyncWindow::Auto, 0, 0)), None);
        // Sync mode: always full.
        assert_eq!(effective_window_hours(&job_with(SyncMode::Sync, SyncWindow::Auto, 1, 100)), None);
        assert_eq!(
            effective_window_hours(&job_with(SyncMode::Sync, SyncWindow::MaxAgeHours { hours: 6 }, 1, 100)),
            None
        );
        // Auto floors at 24h for quick passes…
        assert_eq!(effective_window_hours(&job_with(SyncMode::Copy, SyncWindow::Auto, 1, 600)), Some(24));
        // …and grows to 4× a long pass: 7h11m pass (the real wtgrid
        // number) → ceil(4 × 25860 / 3600) = 29h — a 6h window against
        // that pass was the hole.
        assert_eq!(effective_window_hours(&job_with(SyncMode::Copy, SyncWindow::Auto, 1, 25860)), Some(29));
        // Fixed hours pass through; Full stays full.
        assert_eq!(
            effective_window_hours(&job_with(SyncMode::Copy, SyncWindow::MaxAgeHours { hours: 48 }, 1, 0)),
            Some(48)
        );
        assert_eq!(effective_window_hours(&job_with(SyncMode::Copy, SyncWindow::Full, 1, 0)), None);
    }

    /// Stats parsing against the VERBATIM final block of the real
    /// asset-mirror-1 seed log (rclone, 2026-08-17).
    #[test]
    fn parses_real_rclone_stats() {
        let segment = "\
2026/08/17 01:09:08 NOTICE: \n\
Transferred:   \t    1.292 TiB / 1.292 TiB, 100%, 8.630 MiB/s, ETA 0s\n\
Transferred:     18677740 / 18677740, 100%\n\
Elapsed time:  51h45m16.8s\n";
        let stats = parse_rclone_stats(segment);
        assert_eq!(stats.objects, 18677740);
        assert_eq!(stats.bytes_human, "1.292 TiB / 1.292 TiB");
        assert_eq!(stats.errors, 0);

        // With an Errors line (shape from rclone docs/observed runs).
        let with_errors = "\
Transferred:   \t  904.8 GiB / 904.8 GiB, 100%, 8 MiB/s, ETA 0s\n\
Errors:                 3 (retrying may help)\n\
Transferred:     12952476 / 12952476, 100%\n";
        let stats = parse_rclone_stats(with_errors);
        assert_eq!(stats.objects, 12952476);
        assert_eq!(stats.errors, 3);
    }

    #[test]
    fn rclone_paths_normalise_prefixes() {
        let ep = |b: &str, p: &str| SyncEndpoint {
            remote_id: "r".into(), bucket: b.into(), prefix: p.into(),
        };
        assert_eq!(rclone_path("WSSRC", &ep("bkt", "")), "WSSRC:bkt");
        assert_eq!(rclone_path("WSSRC", &ep("bkt", "/deep/path/")), "WSSRC:bkt/deep/path");
        assert_eq!(rclone_path("WSDST", &ep("bkt", "x")), "WSDST:bkt/x");
    }

    /// Full end-to-end engine test against a live S3 server + real rclone.
    /// Needs: a scratch garage/minio (see storage::config_guard_tests::
    /// connection_test_live docs), rclone on PATH, and env vars:
    ///   WS_S3_TEST_ENDPOINT / WS_S3_TEST_REGION / WS_S3_TEST_KEY /
    ///   WS_S3_TEST_SECRET
    /// Run: cargo test sync_engine_live -- --ignored --nocapture
    #[test]
    #[ignore = "needs a scratch S3 server + rclone + WS_S3_TEST_* env vars"]
    fn sync_engine_live() {
        use crate::storage::{create_bucket_on, save_s3_remote, S3Remote};

        let endpoint = std::env::var("WS_S3_TEST_ENDPOINT").expect("WS_S3_TEST_ENDPOINT");
        let region = std::env::var("WS_S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".into());
        let key = std::env::var("WS_S3_TEST_KEY").expect("WS_S3_TEST_KEY");
        let secret = std::env::var("WS_S3_TEST_SECRET").expect("WS_S3_TEST_SECRET");

        // All state in a temp dir: remotes store, sync config, logs.
        let tmp = std::env::temp_dir().join(format!("ws-s3sync-live-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let mut locs = crate::paths::get();
        locs.storage_config = tmp.join("storage.json").to_string_lossy().into_owned();
        locs.s3_sync_log_dir = tmp.join("logs").to_string_lossy().into_owned();
        crate::paths::set_for_test(locs);

        let mk_remote = |name: &str, k: &str, s: &str| S3Remote {
            id: String::new(),
            name: name.into(),
            provider: "Garage".into(),
            endpoint: endpoint.clone(),
            region: region.clone(),
            access_key_id: k.into(),
            secret_access_key: s.into(),
            origin: String::new(),
        };
        let src_remote = save_s3_remote(mk_remote("live-src", &key, &secret)).expect("save src remote");
        let dst_remote = save_s3_remote(mk_remote("live-dst", &key, &secret)).expect("save dst remote");

        // Buckets + seed objects (2 top-level, 1 under sub/).
        let stamp = std::process::id();
        let src_bucket = format!("ws-sync-src-{}", stamp);
        let dst_bucket = format!("ws-sync-dst-{}", stamp);
        let pfx_bucket = format!("ws-sync-pfx-{}", stamp);
        create_bucket_on(&src_remote, &src_bucket).expect("create src");
        create_bucket_on(&dst_remote, &dst_bucket).expect("create dst");
        create_bucket_on(&dst_remote, &pfx_bucket).expect("create pfx dst");

        let s3_bucket = |bucket: &str| {
            let cfg = src_remote.to_s3_config(bucket);
            let creds = s3::creds::Credentials::new(
                Some(&cfg.access_key_id), Some(&cfg.secret_access_key), None, None, None,
            ).unwrap();
            s3::bucket::Bucket::new(bucket, crate::storage::build_s3_region(&cfg).unwrap(), creds)
                .unwrap()
                .with_path_style()
        };
        let rt = || tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt().block_on(async {
            let b = s3_bucket(&src_bucket);
            b.put_object("a.txt", b"alpha").await.expect("put a");
            b.put_object("b.txt", b"bravo").await.expect("put b");
            b.put_object("sub/c.txt", b"charlie").await.expect("put c");
        });

        let base_job = |name: &str, src_pfx: &str, dst_bkt: &str| SyncJob {
            id: String::new(),
            name: name.into(),
            enabled: false, // manual: the scheduler must not touch these
            src: SyncEndpoint { remote_id: src_remote.id.clone(), bucket: src_bucket.clone(), prefix: src_pfx.into() },
            dst: SyncEndpoint { remote_id: dst_remote.id.clone(), bucket: dst_bkt.into(), prefix: String::new() },
            mode: SyncMode::Copy,
            schedule: SyncSchedule::Manual,
            window: SyncWindow::Auto,
            tuning: SyncTuning { transfers: 4, checkers: 4, bwlimit: String::new() },
            last_runs: Vec::new(),
            last_success_epoch: 0,
            last_pass_secs: 0,
            lag_alerted: false,
            last_cron_fire_minute: 0,
            created_at: String::new(),
        };

        // 1. Whole-bucket copy: 3 objects, first pass = full window.
        let job = save_job(base_job("copy-all", "", &dst_bucket), false).expect("save job");
        let rec = run_job(&job.id).expect("run copy-all");
        assert!(rec.ok, "copy-all failed: {}", rec.message);
        assert_eq!(rec.objects, 3, "expected 3 objects: {:?}", rec.bytes_human);
        assert_eq!(rec.window, "full", "first pass must be full");
        let dst_keys = rt().block_on(async {
            s3_bucket(&dst_bucket).list(String::new(), None).await.unwrap()
                .into_iter().flat_map(|p| p.contents).map(|o| o.key).collect::<Vec<_>>()
        });
        assert_eq!(dst_keys.len(), 3, "dst listing: {:?}", dst_keys);
        assert!(dst_keys.iter().any(|k| k == "sub/c.txt"));

        // Second pass: windowed now (Auto → 24h floor), nothing new to move.
        let rec2 = run_job(&job.id).expect("second pass");
        assert!(rec2.ok);
        assert_eq!(rec2.window, "24h", "auto window after a success: {}", rec2.window);
        assert_eq!(rec2.objects, 0, "nothing new to transfer");

        // 2. Prefix copy: only sub/ lands in the prefix destination.
        let pjob = save_job(base_job("copy-prefix", "sub", &pfx_bucket), false).expect("save pfx job");
        let prec = run_job(&pjob.id).expect("run copy-prefix");
        assert!(prec.ok, "{}", prec.message);
        assert_eq!(prec.objects, 1);
        let pfx_keys = rt().block_on(async {
            s3_bucket(&pfx_bucket).list(String::new(), None).await.unwrap()
                .into_iter().flat_map(|p| p.contents).map(|o| o.key).collect::<Vec<_>>()
        });
        assert_eq!(pfx_keys, vec!["c.txt".to_string()], "prefix is stripped at the destination");

        // 3. Sync-mode gating + deletion propagation.
        assert!(
            save_job({ let mut j = base_job("sync-all", "", &dst_bucket); j.mode = SyncMode::Sync; j }, false).is_err(),
            "sync mode without confirmation must be refused"
        );
        let sjob = save_job({ let mut j = base_job("sync-all", "", &dst_bucket); j.mode = SyncMode::Sync; j }, true)
            .expect("confirmed sync job");
        rt().block_on(async { s3_bucket(&src_bucket).delete_object("b.txt").await.expect("delete b") });
        let srec = run_job(&sjob.id).expect("run sync");
        assert!(srec.ok, "{}", srec.message);
        let after = rt().block_on(async {
            s3_bucket(&dst_bucket).list(String::new(), None).await.unwrap()
                .into_iter().flat_map(|p| p.contents).map(|o| o.key).collect::<Vec<_>>()
        });
        assert!(!after.iter().any(|k| k == "b.txt"), "sync must propagate the deletion: {:?}", after);
        assert_eq!(after.len(), 2);

        // 4. Bad credentials: the pass fails loudly with a real message.
        let bad_remote = save_s3_remote(mk_remote("live-bad", &key, "wrong-secret")).expect("save bad");
        let mut bjob = base_job("bad-creds", "", &dst_bucket);
        bjob.src.remote_id = bad_remote.id.clone();
        let bjob = save_job(bjob, false).expect("save bad job");
        let brec = run_job(&bjob.id).expect("run bad");
        assert!(!brec.ok, "bad creds must fail");
        assert!(!brec.message.is_empty() && brec.message != "OK", "message: {}", brec.message);

        // 5. Run history persisted with the outcome.
        let stored = load().jobs.into_iter().find(|j| j.id == job.id).unwrap();
        assert_eq!(stored.last_runs.len(), 2);
        assert!(stored.last_success_epoch > 0);

        // Cleanup: scratch buckets emptied + deleted, temp dir removed.
        rt().block_on(async {
            for (bkt, keys) in [(&dst_bucket, vec!["a.txt", "sub/c.txt"]), (&pfx_bucket, vec!["c.txt"]), (&src_bucket, vec!["a.txt", "sub/c.txt"])] {
                let b = s3_bucket(bkt);
                for k in keys { let _ = b.delete_object(k).await; }
            }
        });
        for bkt in [&src_bucket, &dst_bucket, &pfx_bucket] {
            crate::storage::delete_bucket_on(&src_remote, bkt).expect("cleanup bucket");
        }
        let _ = fs::remove_dir_all(&tmp);
        println!("sync engine live test: all phases verified");
    }

    /// Provider mapping: every value the UI can produce maps to a name
    /// rclone v1.74.4 actually accepts (captured list, 2026-08-18).
    #[test]
    fn provider_mapping_stays_within_rclones_list() {
        for (ours, theirs) in [
            ("AWS", "AWS"), ("Cloudflare", "Cloudflare"), ("DigitalOcean", "DigitalOcean"),
            ("Wasabi", "Wasabi"), ("IDrive", "IDrive"), ("Minio", "Minio"),
            ("Hetzner", "Hetzner"), ("Scaleway", "Scaleway"),
            ("Garage", "Other"), ("Backblaze", "Other"), ("Other", "Other"), ("", "Other"),
        ] {
            assert_eq!(rclone_provider(ours), theirs, "{}", ours);
        }
    }
}
