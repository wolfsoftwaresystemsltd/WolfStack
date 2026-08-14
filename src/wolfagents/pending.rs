// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Pending-action queue — destructive or confirm-gated tool calls land
//! here instead of running. Operators see them in the agent's Pending
//! tab, click ✓ or ✗, and the result feeds back to the agent on its
//! next turn.
//!
//! File shape: `/etc/wolfstack/agents/<id>/pending.jsonl`. Append-only
//! — approve/deny appends a new entry with status: "approved"/"denied"
//! rather than mutating the original, so the audit trail of operator
//! decisions is complete.
//!
//! Each entry:
//! ```
//! {
//!   "seq": 42,
//!   "ts_queued": 1776515000,
//!   "tool": "exec_in_container",
//!   "arguments": { "name": "regions-1", "command": "rm -rf /home/..." },
//!   "reason": "destructive tool requires operator approval",
//!   "status": "pending" | "approved" | "denied" | "expired",
//!   "decided_by": "paul",           // only on non-pending
//!   "decided_at": 1776515123,
//!   "decision_note": "looks safe"   // optional operator comment
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::tools::ToolId;

/// Default age after which a pending entry auto-expires.
/// An expired entry is effectively a denial — the agent sees "no
/// operator response" on its next turn.
pub const PENDING_TTL_SECS: u64 = 24 * 3600;

/// On-disk shape for one pending-action line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEntry {
    pub seq: u64,
    pub ts_queued: u64,
    pub tool: String,
    pub arguments: serde_json::Value,
    pub reason: String,
    /// "pending" | "approved" | "denied" | "expired"
    pub status: String,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decided_at: Option<u64>,
    #[serde(default)]
    pub decision_note: Option<String>,
    /// If approved and executed, the ToolResult payload is stored so
    /// the agent can reference it on its next turn.
    #[serde(default)]
    pub execution_result: Option<serde_json::Value>,
}

/// Lock guards both read and write of pending.jsonl per agent.
/// Cheap — pending actions aren't a hot path.
static PENDING_LOCK: Mutex<()> = Mutex::new(());

fn path_for(agent_id: &str) -> PathBuf {
    PathBuf::from("/etc/wolfstack/agents").join(agent_id).join("pending.jsonl")
}

fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Append one entry to an agent's pending log. Creates the parent
/// directory with 0o700 on first use + file 0o600.
fn append(agent_id: &str, entry: &PendingEntry) -> Result<(), String> {
    let path = path_for(agent_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(parent) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(parent, perms);
            }
        }
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true).append(true).open(&path)
        .map_err(|e| format!("open: {}", e))?;
    let line = serde_json::to_string(entry).map_err(|e| format!("serialize: {}", e))?;
    writeln!(f, "{}", line).map_err(|e| format!("write: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }
    Ok(())
}

/// Load every entry ever written to the agent's pending log.
/// Walks the file linearly and returns the logical latest state per
/// `seq` (since approve/deny append a new line rather than mutating).
pub fn load_all(agent_id: &str) -> Vec<PendingEntry> {
    let _g = PENDING_LOCK.lock().unwrap();
    let path = path_for(agent_id);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    // Linear scan: later entries with the same seq supersede earlier
    // ones (approve/deny). Keep an index by seq and overwrite.
    let mut map: std::collections::BTreeMap<u64, PendingEntry> = Default::default();
    for line in text.lines() {
        if line.trim().is_empty() { continue; }
        if let Ok(e) = serde_json::from_str::<PendingEntry>(line) {
            map.insert(e.seq, e);
        }
    }
    let now = unix_seconds();
    let mut out: Vec<PendingEntry> = map.into_values().collect();
    // Auto-mark expired entries so the UI shows them greyed out.
    for e in out.iter_mut() {
        if e.status == "pending" && now.saturating_sub(e.ts_queued) > PENDING_TTL_SECS {
            e.status = "expired".into();
        }
    }
    out
}

/// Entries still awaiting a decision (status == "pending" and not
/// expired). Used by the API to drive the per-agent pending tab —
/// the current `agents_pending_list` endpoint returns everything for
/// history display, but this helper is kept for notification paths
/// (Discord push, badge counter) that only care about open items.
#[allow(dead_code)]
pub fn list_open(agent_id: &str) -> Vec<PendingEntry> {
    load_all(agent_id).into_iter().filter(|e| e.status == "pending").collect()
}

/// Allocate the next sequence number for an agent — one more than
/// the highest seq in its log. Simple; race-safe under the mutex.
fn next_seq(agent_id: &str) -> u64 {
    load_all(agent_id).iter().map(|e| e.seq).max().unwrap_or(0) + 1
}

/// Queue a tool call for operator approval. Returns the assigned
/// sequence number so the dispatcher can include it in the result
/// the agent sees ("Queued as pending #42").
pub fn enqueue(
    agent_id: &str,
    tool: ToolId,
    arguments: &serde_json::Value,
    reason: &str,
) -> Result<u64, String> {
    let _g = PENDING_LOCK.lock().unwrap();
    let seq = next_seq(agent_id);
    let entry = PendingEntry {
        seq,
        ts_queued: unix_seconds(),
        tool: tool.as_str().to_string(),
        arguments: arguments.clone(),
        reason: reason.to_string(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        decision_note: None,
        execution_result: None,
    };
    append(agent_id, &entry)?;
    Ok(seq)
}

/// Approve one pending entry. Appends an "approved" row so the
/// history is intact; the caller (API handler) is then responsible
/// for running the tool and calling `record_execution` with the
/// outcome so the agent sees the result on its next turn.
pub fn approve(
    agent_id: &str,
    seq: u64,
    decided_by: &str,
    note: Option<String>,
) -> Result<PendingEntry, String> {
    let _g = PENDING_LOCK.lock().unwrap();
    let orig = load_one_locked(agent_id, seq)?;
    if orig.status != "pending" {
        return Err(format!("entry #{} is already {}", seq, orig.status));
    }
    let updated = PendingEntry {
        status: "approved".to_string(),
        decided_by: Some(decided_by.to_string()),
        decided_at: Some(unix_seconds()),
        decision_note: note,
        ..orig
    };
    append(agent_id, &updated)?;
    Ok(updated)
}

/// Deny one pending entry. Symmetric with approve.
pub fn deny(
    agent_id: &str,
    seq: u64,
    decided_by: &str,
    note: Option<String>,
) -> Result<PendingEntry, String> {
    let _g = PENDING_LOCK.lock().unwrap();
    let orig = load_one_locked(agent_id, seq)?;
    if orig.status != "pending" {
        return Err(format!("entry #{} is already {}", seq, orig.status));
    }
    let updated = PendingEntry {
        status: "denied".to_string(),
        decided_by: Some(decided_by.to_string()),
        decided_at: Some(unix_seconds()),
        decision_note: note,
        ..orig
    };
    append(agent_id, &updated)?;
    Ok(updated)
}

/// Attach the ToolResult produced by running an approved tool call,
/// so the agent can pick up the outcome on its next turn.
pub fn record_execution(
    agent_id: &str,
    seq: u64,
    result: serde_json::Value,
) -> Result<(), String> {
    let _g = PENDING_LOCK.lock().unwrap();
    let orig = load_one_locked(agent_id, seq)?;
    let updated = PendingEntry {
        execution_result: Some(result),
        ..orig
    };
    append(agent_id, &updated)?;
    Ok(())
}

/// Read one entry's latest state. Expects the outer lock to be held.
fn load_one_locked(agent_id: &str, seq: u64) -> Result<PendingEntry, String> {
    let path = path_for(agent_id);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read: {}", e))?;
    let mut latest: Option<PendingEntry> = None;
    for line in text.lines() {
        if line.trim().is_empty() { continue; }
        if let Ok(e) = serde_json::from_str::<PendingEntry>(line)
            && e.seq == seq { latest = Some(e); }
    }
    latest.ok_or_else(|| format!("no pending entry with seq {}", seq))
}
