// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! S3 remote endpoint health monitoring.
//!
//! Every saved S3 remote (WolfStack's own store, rclone.conf imports, and
//! the synthetic per-mount entries) gets a slow background probe — the
//! cheapest authenticated metadata call `storage::test_s3_connection`
//! makes — so a dead endpoint surfaces as a WolfStack alert instead of a
//! mystery downstream failure. Motivating incident: the 2026-08-14 IDrive
//! FRA2 outage, where the object store vanished and nothing in WolfStack
//! said so.
//!
//! Design points:
//! - Probes run on the node that holds the remote (per-node reachability
//!   is routing information — a remote can be fine from one node and
//!   unreachable from another).
//! - Default cadence 5 minutes, spread by a per-remote jitter so a fleet
//!   of remotes doesn't stampede one provider on the same second.
//! - Alert (AlertCategory::Threshold) after N consecutive failures,
//!   clear-on-recovery with a follow-up alert; the `alerted` flag makes
//!   both edges fire exactly once per outage.
//! - Per-remote opt-out for metered/egress-billed endpoints — the probe
//!   is a metadata call, not a data transfer, but the operator decides.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tracing::warn;

use super::{list_s3_remotes, load_config, test_s3_connection, MountType};

/// Seconds between probes of one remote.
const PROBE_INTERVAL_SECS: u64 = 300;
/// Consecutive failures before the outage alert fires. 3 × 5min ≈ a real
/// outage, not a blip.
const PROBE_FAILURES_TO_ALERT: u32 = 3;

fn health_path() -> String {
    let storage = super::config_path();
    let dir = std::path::Path::new(&storage)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/etc/wolfstack".to_string());
    format!("{}/s3-health.json", dir)
}

/// Persistent per-remote probe state. Serialized to s3-health.json — no
/// secrets in here, only ids/timestamps/error text.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct S3RemoteHealth {
    /// Operator opt-out: no probes, no alerts, state shows "disabled".
    #[serde(default)]
    pub disabled: bool,
    /// Unix epoch of the last probe attempt (0 = never probed).
    #[serde(default)]
    pub last_checked_epoch: u64,
    /// Unix epoch of the last SUCCESSFUL probe (0 = never succeeded).
    #[serde(default)]
    pub last_ok_epoch: u64,
    /// Latency of the last probe, whatever its outcome.
    #[serde(default)]
    pub latency_ms: u64,
    #[serde(default)]
    pub consecutive_failures: u32,
    /// "ok" | "auth" | "unreachable" | "error" | "" (never probed).
    #[serde(default)]
    pub verdict: String,
    /// Human message from the last failed probe; cleared on success.
    #[serde(default)]
    pub last_error: String,
    /// True while an outage alert has been sent and not yet cleared —
    /// makes the down/recovered edges fire exactly once each.
    #[serde(default)]
    pub alerted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HealthStore {
    #[serde(default)]
    remotes: HashMap<String, S3RemoteHealth>,
}

fn load_store() -> HealthStore {
    match fs::read_to_string(health_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            warn!("Failed to parse {}: {} — starting fresh", health_path(), e);
            HealthStore::default()
        }),
        Err(_) => HealthStore::default(),
    }
}

fn save_store(store: &HealthStore) {
    match serde_json::to_string_pretty(store) {
        Ok(json) => {
            if let Err(e) = fs::write(health_path(), json) {
                warn!("Failed to write {}: {}", health_path(), e);
            }
        }
        Err(e) => warn!("Failed to serialize S3 health state: {}", e),
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Deterministic 0-59s per-remote offset so probes spread across the
/// minute ticks instead of stampeding the provider together.
fn jitter_secs(id: &str) -> u64 {
    let mut h: u64 = 1469598103934665603; // FNV-1a offset basis
    for b in id.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h % 60
}

/// One alert-worthy edge from a probe round, for the async caller to
/// hand to `alerting::send_local_alert` (this module is sync — it runs
/// under spawn_blocking because the probe builds its own runtime).
pub struct HealthAlert {
    /// false = outage alert, true = recovery alert.
    pub recovered: bool,
    pub title: String,
    pub body: String,
}

/// Snapshot for the API: remote id → state.
pub fn health_snapshot() -> HashMap<String, S3RemoteHealth> {
    load_store().remotes
}

/// Flip probing on/off for one remote id. The id doesn't need to exist
/// yet (a fresh remote gets its state row on the first probe round).
pub fn set_probe_disabled(id: &str, disabled: bool) {
    let mut store = load_store();
    let entry = store.remotes.entry(id.to_string()).or_default();
    entry.disabled = disabled;
    if disabled {
        // A disabled remote must not carry stale outage state that would
        // fire a bogus "recovered" alert when re-enabled.
        entry.consecutive_failures = 0;
        entry.alerted = false;
    }
    save_store(&store);
}

/// Probe every remote whose interval (+jitter) has elapsed. Returns the
/// alert edges this round produced. Synchronous and self-contained —
/// call via spawn_blocking from the scheduler loop.
pub fn run_due_probes() -> Vec<HealthAlert> {
    let remotes = list_s3_remotes();
    let mut store = load_store();
    let now = now_epoch();
    let mut alerts = Vec::new();

    // The bucket a synthetic mount:* remote serves — lets the probe fall
    // back to a bucket-scoped check on accounts that deny ListBuckets.
    let mount_buckets: HashMap<String, String> = load_config()
        .mounts
        .iter()
        .filter(|m| m.mount_type == MountType::S3)
        .filter_map(|m| {
            m.s3_config
                .as_ref()
                .map(|s3| (format!("mount:{}", m.id), s3.bucket.clone()))
        })
        .collect();

    for remote in &remotes {
        let entry = store.remotes.entry(remote.id.clone()).or_default();
        if entry.disabled {
            continue;
        }
        let due_at = entry.last_checked_epoch + PROBE_INTERVAL_SECS + jitter_secs(&remote.id);
        if entry.last_checked_epoch != 0 && now < due_at {
            continue;
        }

        let bucket = mount_buckets.get(&remote.id).cloned().unwrap_or_default();
        let result = test_s3_connection(remote, &bucket);
        if let Some(alert) = apply_probe_result(
            entry,
            &remote.name,
            &display_endpoint(&remote.endpoint, &remote.region),
            &result,
        ) {
            alerts.push(alert);
        }
    }

    // Drop state rows whose remote no longer exists so a deleted remote
    // can't linger in the health API forever. (Disabled rows for absent
    // remotes go too — the flag is re-settable if the remote returns.)
    let live_ids: std::collections::HashSet<&str> =
        remotes.iter().map(|r| r.id.as_str()).collect();
    store.remotes.retain(|id, _| live_ids.contains(id.as_str()));

    save_store(&store);
    alerts
}

/// Fold one probe result into a remote's state row and return the alert
/// edge it produced, if any. Pure state machine — extracted from
/// run_due_probes so the down-after-N / recover-once contract is directly
/// testable without network or global paths:
///   failures 1..N-1  → no alert
///   failure  N       → ONE outage alert (alerted = true)
///   failures > N     → silent (already alerted)
///   next success     → ONE recovery alert, counters reset
fn apply_probe_result(
    entry: &mut S3RemoteHealth,
    name: &str,
    endpoint_label: &str,
    result: &super::S3TestResult,
) -> Option<HealthAlert> {
    entry.last_checked_epoch = now_epoch();
    entry.latency_ms = result.latency_ms;
    entry.verdict = result.verdict.clone();

    if result.ok {
        entry.last_ok_epoch = entry.last_checked_epoch;
        entry.consecutive_failures = 0;
        entry.last_error = String::new();
        if entry.alerted {
            entry.alerted = false;
            return Some(HealthAlert {
                recovered: true,
                title: format!("S3 remote recovered: {}", name),
                body: format!(
                    "The S3 endpoint for “{}” is answering again.\n\n\
                     Endpoint: {}\nLatency:  {} ms",
                    name, endpoint_label, result.latency_ms,
                ),
            });
        }
        return None;
    }

    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    entry.last_error = result.message.clone();
    if entry.consecutive_failures >= PROBE_FAILURES_TO_ALERT && !entry.alerted {
        entry.alerted = true;
        return Some(HealthAlert {
            recovered: false,
            title: format!("S3 remote unreachable: {}", name),
            body: format!(
                "The S3 endpoint for “{}” has failed {} consecutive checks (~{} minutes).\n\n\
                 Endpoint: {}\nVerdict:  {}\nError:    {}\n\n\
                 Mounts and sync jobs using these credentials will be failing. \
                 Probes continue every {} minutes; a recovery alert follows when it answers again.",
                name,
                entry.consecutive_failures,
                (entry.consecutive_failures as u64 * PROBE_INTERVAL_SECS) / 60,
                endpoint_label,
                result.verdict,
                result.message,
                PROBE_INTERVAL_SECS / 60,
            ),
        });
    }
    None
}

/// "endpoint (region)" for alert bodies — AWS remotes have no endpoint,
/// so fall back to the region alone rather than printing an empty field.
fn display_endpoint(endpoint: &str, region: &str) -> String {
    if endpoint.trim().is_empty() {
        format!("AWS (region {})", if region.is_empty() { "us-east-1" } else { region })
    } else if region.trim().is_empty() {
        endpoint.trim().to_string()
    } else {
        format!("{} (region {})", endpoint.trim(), region.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_is_deterministic_and_bounded() {
        for id in ["wolfstack:a", "rclone:b", "mount:c", ""] {
            let j = jitter_secs(id);
            assert_eq!(j, jitter_secs(id));
            assert!(j < 60);
        }
        // Two different ids should usually differ — spot-check the pair
        // actually used in the field doesn't collide.
        assert_ne!(jitter_secs("wolfstack:idrive-e2"), jitter_secs("wolfstack:backblaze"));
    }

    #[test]
    fn display_endpoint_covers_all_shapes() {
        assert_eq!(display_endpoint("", ""), "AWS (region us-east-1)");
        assert_eq!(display_endpoint("", "eu-west-2"), "AWS (region eu-west-2)");
        assert_eq!(display_endpoint("https://x.test", ""), "https://x.test");
        assert_eq!(
            display_endpoint("https://x.test", "auto"),
            "https://x.test (region auto)"
        );
    }

    fn result(ok: bool) -> crate::storage::S3TestResult {
        crate::storage::S3TestResult {
            ok,
            verdict: if ok { "ok".into() } else { "unreachable".into() },
            message: if ok { "Connected".into() } else { "connection refused".into() },
            latency_ms: 7,
            bucket_count: None,
            bucket: None,
        }
    }

    /// The whole alert contract in one pass: silent until failure N, ONE
    /// outage alert at N, silence past N, ONE recovery alert on success,
    /// and a clean second cycle after recovery.
    #[test]
    fn alert_edges_fire_exactly_once_per_outage() {
        let mut entry = S3RemoteHealth::default();

        // Failures below the threshold stay silent.
        for i in 1..PROBE_FAILURES_TO_ALERT {
            let alert = apply_probe_result(&mut entry, "r", "ep", &result(false));
            assert!(alert.is_none(), "failure {} must not alert", i);
            assert_eq!(entry.consecutive_failures, i);
            assert!(!entry.alerted);
        }

        // Failure N: exactly one outage alert.
        let alert = apply_probe_result(&mut entry, "r", "ep", &result(false))
            .expect("failure N must alert");
        assert!(!alert.recovered);
        assert!(alert.title.contains("unreachable"));
        assert!(entry.alerted);

        // Beyond N: still down, no repeat.
        assert!(apply_probe_result(&mut entry, "r", "ep", &result(false)).is_none());
        assert_eq!(entry.consecutive_failures, PROBE_FAILURES_TO_ALERT + 1);

        // Recovery: exactly one recovery alert, counters reset.
        let rec = apply_probe_result(&mut entry, "r", "ep", &result(true))
            .expect("recovery must alert");
        assert!(rec.recovered);
        assert!(rec.title.contains("recovered"));
        assert!(!entry.alerted);
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.last_error.is_empty());
        assert!(entry.last_ok_epoch > 0);

        // A success with no outstanding outage stays silent.
        assert!(apply_probe_result(&mut entry, "r", "ep", &result(true)).is_none());

        // Second outage cycle behaves like the first — the flag reset.
        for _ in 1..PROBE_FAILURES_TO_ALERT {
            assert!(apply_probe_result(&mut entry, "r", "ep", &result(false)).is_none());
        }
        assert!(apply_probe_result(&mut entry, "r", "ep", &result(false)).is_some());
    }
}
