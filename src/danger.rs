// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Deadman-switch framework for operations that can brick the node's
//! management interface.
//!
//! Design mirrors Cisco's `commit confirmed` / Mikrotik safe-mode:
//!   1. Operator triggers a dangerous op (host-DNS release, firewall
//!      apply, …) through the normal API endpoint.
//!   2. The op applies immediately AND registers a rollback closure +
//!      a TTL with this module.
//!   3. A background task ticks every second; when a pending op's TTL
//!      elapses without the operator calling `confirm`, the rollback
//!      closure runs and restores the pre-op state.
//!   4. The frontend polls `/api/danger/pending` and shows a persistent
//!      countdown banner with "Keep" (confirm) and "Rollback now"
//!      buttons. If the change bricks the browser's connection to
//!      the node, no call reaches `confirm` → auto-rollback fires
//!      and the node comes back on its own.
//!
//! In-flight rollback closures are stored in-memory only (can't be
//! serialized), so a wolfstack restart during the TTL window commits
//! the change implicitly. That's acceptable because a restart means
//! the operator had local access to stop/start the service — the
//! worst-case "operator locked out of a remote node" scenario is the
//! one this module exists to protect against, and a wolfstack restart
//! is a non-event in that scenario (they'd be SSHing in to fix it).

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// A closure that undoes a dangerous op. Returns Ok(msg) on successful
/// rollback, Err(msg) when rollback fails — in which case we log the
/// error and keep the PendingOp in the registry as "rollback_failed"
/// so the operator sees something is wrong.
pub type RollbackFn = Box<dyn Fn() -> Result<String, String> + Send + Sync>;

/// Serializable metadata for the API. The rollback closure itself
/// stays in a parallel map since Box<dyn Fn> can't derive Serialize.
#[derive(Debug, Clone, Serialize)]
pub struct PendingOp {
    pub id: String,
    /// Short machine-readable identifier: "host_dns_release",
    /// "firewall_apply", etc. UI uses this to pick an icon/colour.
    pub op_type: String,
    /// Human-readable description of what was done. Shown in the
    /// countdown banner.
    pub description: String,
    /// Seconds from applied_at until automatic rollback. The banner
    /// uses this + applied_at_unix to render a live countdown.
    pub ttl_secs: u64,
    /// Unix epoch seconds when the op was applied. Clock-based so
    /// the frontend can compute remaining time regardless of poll
    /// cadence.
    pub applied_at_unix: u64,
    /// "pending" while the timer's live; "confirmed" after confirm();
    /// "rolled_back" after auto-rollback; "rollback_failed" if the
    /// rollback closure itself errored.
    pub status: String,
    /// Populated on rollback — shows what the undo actually did
    /// ("restored /etc/resolv.conf from backup; systemd-resolved
    /// restarted"). Empty while pending.
    pub rollback_message: String,
}

/// Parallel storage: the closure for each pending op. Separate from
/// PendingOp because Box<dyn Fn> can't derive Serialize.
struct OpEntry {
    meta: PendingOp,
    applied_at: Instant,
    rollback: Option<RollbackFn>,
}

static REGISTRY: LazyLock<Mutex<HashMap<String, OpEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register a dangerous operation. Call AFTER the change has been
/// applied — we assume success at this point. Returns the op id the
/// operator needs to pass to `confirm()`.
///
/// - `op_type`: short machine-readable key ("host_dns_release").
/// - `description`: one-line human-readable summary.
/// - `ttl_secs`: how long until auto-rollback if unconfirmed.
/// - `rollback`: closure that undoes the change. Must be idempotent
///   enough that calling it twice (e.g. via manual rollback + auto
///   fallback) doesn't corrupt state.
pub fn schedule(
    op_type: &str,
    description: &str,
    ttl_secs: u64,
    rollback: RollbackFn,
) -> String {
    let id = format!("danger-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let applied_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let meta = PendingOp {
        id: id.clone(),
        op_type: op_type.to_string(),
        description: description.to_string(),
        ttl_secs,
        applied_at_unix,
        status: "pending".to_string(),
        rollback_message: String::new(),
    };
    let mut reg = REGISTRY.lock().unwrap();
    reg.insert(id.clone(), OpEntry {
        meta,
        applied_at: Instant::now(),
        rollback: Some(rollback),
    });
    info!("danger: scheduled op {} ({}) — auto-rollback in {}s", id, op_type, ttl_secs);
    id
}

/// Confirm (commit) a pending op. Returns the final state message
/// the API should echo back to the frontend. After confirm the op
/// stays in the registry with status="confirmed" for 5 minutes so
/// the UI can show "recently committed" before it vanishes.
pub fn confirm(id: &str) -> Result<String, String> {
    let mut reg = REGISTRY.lock().unwrap();
    let entry = reg.get_mut(id).ok_or_else(|| format!("op {} not found", id))?;
    if entry.meta.status == "confirmed" {
        return Ok(format!("op {} already confirmed", id));
    }
    if entry.meta.status != "pending" {
        return Err(format!(
            "op {} can't be confirmed — status is {}",
            id, entry.meta.status
        ));
    }
    entry.meta.status = "confirmed".to_string();
    entry.rollback = None;  // drop the closure — we're keeping the change
    info!("danger: confirmed op {} ({})", id, entry.meta.op_type);
    Ok("Change committed — auto-rollback cancelled.".to_string())
}

/// Manually roll back a pending op right now. Same effect as letting
/// the TTL expire, but faster. Returns the rollback closure's result.
pub fn rollback_now(id: &str) -> Result<String, String> {
    // Flip status to "rolling_back" BEFORE releasing the lock so a
    // racing confirm()/tick() sees a non-pending status and won't
    // double-run the closure or stamp "confirmed" over a live rollback.
    // Without this transition, the window between `.take()` and the
    // post-execution re-lock lets confirm(id) mark the op confirmed
    // even though the undo is already executing — the UI would claim
    // the change stuck when it actually rolled back.
    let rollback = {
        let mut reg = REGISTRY.lock().unwrap();
        let entry = reg.get_mut(id).ok_or_else(|| format!("op {} not found", id))?;
        if entry.meta.status != "pending" {
            return Err(format!(
                "op {} can't be rolled back — status is {}",
                id, entry.meta.status
            ));
        }
        entry.meta.status = "rolling_back".to_string();
        entry.rollback.take()
    };
    let result = rollback
        .ok_or_else(|| "rollback closure missing".to_string())
        .and_then(|f| f());
    let mut reg = REGISTRY.lock().unwrap();
    if let Some(entry) = reg.get_mut(id) {
        match &result {
            Ok(msg) => {
                entry.meta.status = "rolled_back".to_string();
                entry.meta.rollback_message = msg.clone();
                info!("danger: manually rolled back op {} ({})", id, entry.meta.op_type);
            }
            Err(e) => {
                entry.meta.status = "rollback_failed".to_string();
                entry.meta.rollback_message = e.clone();
                // error! not warn! — this is a genuine alert path.
                // Operators routinely grep journalctl for ERROR; a
                // failed rollback means something they explicitly
                // expected to be undoable is now stuck in a bad state.
                error!("danger: rollback FAILED for op {} ({}): {}", id, entry.meta.op_type, e);
            }
        }
    }
    result
}

/// List every op in the registry (pending, confirmed, rolled-back,
/// failed). The frontend filters to show what it needs.
pub fn list() -> Vec<PendingOp> {
    let reg = REGISTRY.lock().unwrap();
    reg.values().map(|e| e.meta.clone()).collect()
}

/// Background tick: called once per second from main.rs. Checks every
/// pending op's TTL; fires rollbacks that have expired. Also sweeps
/// confirmed/rolled-back ops older than 5 minutes so the registry
/// doesn't grow without bound.
pub fn tick() {
    // Collect ops whose TTL has expired. Drop the lock before running
    // the rollback closures — they may be slow (systemctl restart etc)
    // and we don't want to block confirm() or list() while they run.
    let expired_ids: Vec<String> = {
        let reg = REGISTRY.lock().unwrap();
        reg.iter()
            .filter(|(_, e)| {
                e.meta.status == "pending"
                    && e.applied_at.elapsed().as_secs() >= e.meta.ttl_secs
            })
            .map(|(id, _)| id.clone())
            .collect()
    };
    for id in expired_ids {
        warn!("danger: TTL expired for op {} — rolling back", id);
        let _ = rollback_now(&id);
    }
    // Sweep old completed entries. Keep pending AND rolling_back ops
    // (a slow rollback must not be evicted mid-execution — that would
    // let a second tick() re-pick the same id and call rollback_now
    // with a None closure, leaking a "rollback closure missing" error).
    let mut reg = REGISTRY.lock().unwrap();
    reg.retain(|_, e| {
        if e.meta.status == "pending" || e.meta.status == "rolling_back" { return true; }
        e.applied_at.elapsed().as_secs() < 300
    });
}
