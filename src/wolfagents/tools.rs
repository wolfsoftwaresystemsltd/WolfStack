// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Agent tool registry — the set of WolfStack operations an agent is
//! allowed to invoke during a chat turn.
//!
//! Two layers of safety:
//!
//! 1. **Fixed catalogue**. Each tool is a named variant in `ToolId`.
//!    An agent's `allowed_tools` stores these names as strings; an
//!    unknown name is rejected before we even look at arguments. This
//!    means the tool surface is finite and auditable — no free-form
//!    shell escape hatch.
//!
//! 2. **Per-agent allowlist**. `validate_for_agent(agent, tool_id)`
//!    returns Ok only when the tool name is present in the agent's
//!    allowed list. The UI drives this — operators tick the specific
//!    tools an agent can use. Default on new agents is empty, so a
//!    freshly-created agent can chat but can't act until tools are
//!    deliberately granted.
//!
//! Every successful invocation appends a JSONL entry to
//! `/etc/wolfstack/agents/<id>/audit.jsonl` so operators can scroll
//! back and see exactly what the agent did and when.

// The tool registry is public infrastructure that the API surface +
// future LLM tool-use loops call into. Some items read as unused
// during the current build because the agent loop doesn't yet emit
// tool calls — the validator and audit helpers are wired in but not
// exercised until Phase 6+ adds Claude tool_use integration. Keep the
// machinery intact so Phase 6 can drop in without revisiting this
// file.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Agent, AccessLevel};

/// How risky a tool is. Combined with the agent's AccessLevel to
/// decide whether a call runs freely, needs operator approval, or is
/// refused outright. See `authorise` below for the full policy matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Danger {
    /// Read-only cluster observation. Always allowed when the tool is
    /// on the agent's allowlist, regardless of access level.
    Safe,
    /// Changes cluster state but the change is recoverable (restart a
    /// container, create a workflow, write a file under an allowed
    /// path). Needs at least ReadWrite.
    Mutating,
    /// Irrecoverable or high-blast-radius: arbitrary shell exec,
    /// file deletion, rm -rf. Needs explicit approval under ConfirmAll
    /// or ReadWrite; only runs freely under Trusted.
    Destructive,
}

/// Canonical tool identifiers. String form is what agents pass when
/// they emit a tool-use request, and what operators see as checkboxes
/// in the Edit Agent modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolId {
    // ── Safe / read-only ───────────────────────────────────────
    ListNodes,
    ListContainers,
    GetMetrics,
    ListAlerts,
    ReadLog,
    CheckDiskUsage,
    ReadFile,
    ListApiEndpoints,
    DescribeCluster,
    ListWorkflows,
    WebFetch,
    WebRender,
    SemanticSearch,

    // ── Mutating ───────────────────────────────────────────────
    RestartContainer,
    RunWorkflow,
    ScheduleWorkflow,
    WriteFile,
    SendEmail,

    // ── Destructive ────────────────────────────────────────────
    ExecInContainer,
    ExecOnNode,
    DeleteFile,

    // ── Universal WolfStack API (danger varies by method) ──────
    WolfstackApi,

    // ── SQL (gated by Agent::sql_* booleans + connection allowlist) ──
    // Three tools so the agent surface matches the three permission
    // tiers — granting `sql_read` doesn't imply Update or Delete.
    // Per-statement enforcement happens in sql_connections::classify
    // regardless of which tool the agent picked.
    SqlRead,
    SqlUpdate,
    SqlDelete,
}

impl ToolId {
    /// Lowercase stable string — what's persisted in
    /// `Agent.allowed_tools` and what the LLM emits.
    pub fn as_str(self) -> &'static str {
        match self {
            ToolId::ListNodes => "list_nodes",
            ToolId::ListContainers => "list_containers",
            ToolId::GetMetrics => "get_metrics",
            ToolId::ListAlerts => "list_alerts",
            ToolId::ReadLog => "read_log",
            ToolId::CheckDiskUsage => "check_disk_usage",
            ToolId::ReadFile => "read_file",
            ToolId::ListApiEndpoints => "list_api_endpoints",
            ToolId::DescribeCluster => "describe_cluster",
            ToolId::ListWorkflows => "list_workflows",
            ToolId::WebFetch => "web_fetch",
            ToolId::WebRender => "web_render",
            ToolId::SemanticSearch => "semantic_search",
            ToolId::RestartContainer => "restart_container",
            ToolId::RunWorkflow => "run_workflow",
            ToolId::ScheduleWorkflow => "schedule_workflow",
            ToolId::WriteFile => "write_file",
            ToolId::SendEmail => "send_email",
            ToolId::ExecInContainer => "exec_in_container",
            ToolId::ExecOnNode => "exec_on_node",
            ToolId::DeleteFile => "delete_file",
            ToolId::WolfstackApi => "wolfstack_api",
            ToolId::SqlRead => "sql_read",
            ToolId::SqlUpdate => "sql_update",
            ToolId::SqlDelete => "sql_delete",
        }
    }

    /// Human label for the UI checklist.
    pub fn label(self) -> &'static str {
        match self {
            ToolId::ListNodes => "List nodes",
            ToolId::ListContainers => "List containers & VMs",
            ToolId::GetMetrics => "Read metrics (CPU/mem/disk)",
            ToolId::ListAlerts => "List recent alerts",
            ToolId::ReadLog => "Read container/VM logs",
            ToolId::CheckDiskUsage => "Check disk usage in containers",
            ToolId::ReadFile => "Read a file from any cluster node (pass `node` = hostname/id; omit for this node)",
            ToolId::ListApiEndpoints => "List available WolfStack API endpoints",
            ToolId::DescribeCluster => "Describe a cluster in detail",
            ToolId::ListWorkflows => "List WolfFlow workflows",
            ToolId::WebFetch => "Fetch a public web URL (HTTP/HTTPS, no JS)",
            ToolId::WebRender => "Fetch a web URL via headless Chromium (JS-heavy sites; requires chromium on the host)",
            ToolId::SemanticSearch => "BM25 search across past agent memory / alerts / audit logs on any cluster node (pass `node` = hostname, '*' for cluster-wide merge, or omit for self)",
            ToolId::RestartContainer => "Restart container (Docker/LXC)",
            ToolId::RunWorkflow => "Run a WolfFlow workflow",
            ToolId::ScheduleWorkflow => "Schedule a WolfFlow workflow",
            ToolId::WriteFile => "Write a file on any cluster node (pass `node`; omit for self). Honours allowed_paths scope.",
            ToolId::SendEmail => "Send an email via the configured SMTP relay (subject, body, optional HTML)",
            ToolId::ExecInContainer => "Execute a shell command inside a container",
            ToolId::ExecOnNode => "Execute a shell command on a cluster node (self: full shell; remote: read-only allowlist — df, ps, cat, systemctl status, etc.)",
            ToolId::DeleteFile => "Delete a file on any cluster node (pass `node`; omit for self). Honours allowed_paths scope.",
            ToolId::WolfstackApi => "Call any WolfStack REST API endpoint",
            ToolId::SqlRead => "Run a read-only SQL query (SELECT / SHOW / EXPLAIN) against a configured connection. Requires the agent's `sql_read` permission.",
            ToolId::SqlUpdate => "Run an INSERT or UPDATE against a configured SQL connection. Requires the agent's `sql_update` permission.",
            ToolId::SqlDelete => "Run a DELETE or TRUNCATE against a configured SQL connection. Requires the agent's `sql_delete` permission.",
        }
    }

    /// Short sentence describing what granting this tool implies. The
    /// UI shows this under each checkbox so operators know what they
    /// just enabled.
    pub fn risk_note(self) -> &'static str {
        match self.danger() {
            Danger::Safe => "Read-only — observation, no state change.",
            Danger::Mutating =>
                "Changes cluster state. Needs access_level ≥ read_write.",
            Danger::Destructive =>
                "Irrecoverable or high blast-radius. Needs access_level = trusted to run \
                 without confirmation; otherwise queued for operator approval.",
        }
    }

    /// Classify the tool by how risky it is. The universal
    /// `wolfstack_api` tool is classified as Mutating; the
    /// per-request method check (GET vs POST/DELETE) further narrows
    /// this at call time inside the dispatcher.
    pub fn danger(self) -> Danger {
        match self {
            ToolId::ListNodes | ToolId::ListContainers | ToolId::GetMetrics
            | ToolId::ListAlerts | ToolId::ReadLog | ToolId::CheckDiskUsage
            | ToolId::ReadFile | ToolId::ListApiEndpoints
            | ToolId::DescribeCluster | ToolId::ListWorkflows
            | ToolId::WebFetch | ToolId::WebRender
            | ToolId::SemanticSearch => Danger::Safe,

            ToolId::RestartContainer | ToolId::RunWorkflow
            | ToolId::ScheduleWorkflow | ToolId::WriteFile
            | ToolId::SendEmail | ToolId::WolfstackApi
            | ToolId::SqlRead   // Safe within the SQL sense (SELECT-only)
                                //   but classed as Mutating to require
                                //   ReadWrite — the operator explicitly
                                //   opted in by setting `sql_read=true`
                                //   AND picking connections, so this is
                                //   their deliberate trust decision,
                                //   but we don't want a ReadOnly agent
                                //   to randomly SELECT-count a prod DB.
            | ToolId::SqlUpdate
                => Danger::Mutating,

            ToolId::ExecInContainer | ToolId::ExecOnNode
            | ToolId::DeleteFile
            | ToolId::SqlDelete
                => Danger::Destructive,
        }
    }

    pub fn from_str(s: &str) -> Option<ToolId> {
        match s {
            "list_nodes" => Some(ToolId::ListNodes),
            "list_containers" => Some(ToolId::ListContainers),
            "get_metrics" => Some(ToolId::GetMetrics),
            "list_alerts" => Some(ToolId::ListAlerts),
            "read_log" => Some(ToolId::ReadLog),
            "check_disk_usage" => Some(ToolId::CheckDiskUsage),
            "read_file" => Some(ToolId::ReadFile),
            "list_api_endpoints" => Some(ToolId::ListApiEndpoints),
            "describe_cluster" => Some(ToolId::DescribeCluster),
            "list_workflows" => Some(ToolId::ListWorkflows),
            "web_fetch" => Some(ToolId::WebFetch),
            "web_render" => Some(ToolId::WebRender),
            "semantic_search" => Some(ToolId::SemanticSearch),
            "restart_container" => Some(ToolId::RestartContainer),
            "run_workflow" => Some(ToolId::RunWorkflow),
            "schedule_workflow" => Some(ToolId::ScheduleWorkflow),
            "write_file" => Some(ToolId::WriteFile),
            "send_email" => Some(ToolId::SendEmail),
            "exec_in_container" => Some(ToolId::ExecInContainer),
            "exec_on_node" => Some(ToolId::ExecOnNode),
            "delete_file" => Some(ToolId::DeleteFile),
            "wolfstack_api" => Some(ToolId::WolfstackApi),
            "sql_read" => Some(ToolId::SqlRead),
            "sql_update" => Some(ToolId::SqlUpdate),
            "sql_delete" => Some(ToolId::SqlDelete),
            _ => None,
        }
    }

    /// Every tool known to the runtime. Driven by `ALL` so the UI,
    /// validator, and invoker stay in lockstep — add one variant here
    /// and it shows up everywhere.
    pub const ALL: &'static [ToolId] = &[
        ToolId::ListNodes,
        ToolId::ListContainers,
        ToolId::GetMetrics,
        ToolId::ListAlerts,
        ToolId::ReadLog,
        ToolId::CheckDiskUsage,
        ToolId::ReadFile,
        ToolId::ListApiEndpoints,
        ToolId::DescribeCluster,
        ToolId::ListWorkflows,
        ToolId::WebFetch,
        ToolId::WebRender,
        ToolId::SemanticSearch,
        ToolId::RestartContainer,
        ToolId::RunWorkflow,
        ToolId::ScheduleWorkflow,
        ToolId::WriteFile,
        ToolId::SendEmail,
        ToolId::ExecInContainer,
        ToolId::ExecOnNode,
        ToolId::DeleteFile,
        ToolId::WolfstackApi,
        ToolId::SqlRead,
        ToolId::SqlUpdate,
        ToolId::SqlDelete,
    ];
}

/// Decision from the authorisation step — tells the dispatcher
/// whether to run the tool, queue it for approval, or reject outright.
#[derive(Debug, Clone)]
pub enum AuthDecision {
    /// Tool runs immediately — allowlist + scope + policy all pass.
    Allow,
    /// Tool is allowed in principle but needs a human ✓ first.
    /// Dispatcher queues the call on pending.jsonl and returns a
    /// placeholder "awaiting approval" result to the agent.
    NeedsConfirmation { reason: String },
    /// Tool is refused. `reason` is safe to surface to the operator
    /// + audit log.
    Deny { reason: String },
}

/// Decide whether a specific tool call is authorised for an agent.
/// Runs the checks in strict order:
///   1. Allowlist — is the tool listed in agent.allowed_tools?
///   2. Danger vs AccessLevel policy — does the agent have enough
///      authority to run this class of tool?
///   3. Returns Allow, NeedsConfirmation, or Deny.
///
/// The hardcoded safety denylist (src/wolfagents/safety.rs) is NOT
/// checked here — it's checked inside each dispatcher, against the
/// specific command/path/API the tool is about to act on. Keeping it
/// there means safety applies to EVERY entry point (curated tools,
/// wolfstack_api, future plugin tools) without relying on the
/// authoriser remembering to call it.
pub fn authorise(agent: &Agent, tool: ToolId) -> AuthDecision {
    let tool_name = tool.as_str();
    if !agent.allowed_tools.iter().any(|t| t == tool_name) {
        return AuthDecision::Deny {
            reason: format!("tool '{}' is not in the agent's allowed_tools list", tool_name),
        };
    }
    match (tool.danger(), agent.access_level) {
        (Danger::Safe, _) => AuthDecision::Allow,

        (Danger::Mutating, AccessLevel::ReadOnly) => AuthDecision::Deny {
            reason: format!(
                "tool '{}' is mutating but the agent's access_level is read_only",
                tool_name
            ),
        },
        (Danger::Mutating, AccessLevel::ConfirmAll) => AuthDecision::NeedsConfirmation {
            reason: format!("mutating tool '{}' requires operator approval under confirm_all", tool_name),
        },
        (Danger::Mutating, AccessLevel::ReadWrite)
        | (Danger::Mutating, AccessLevel::Trusted) => AuthDecision::Allow,

        (Danger::Destructive, AccessLevel::ReadOnly) => AuthDecision::Deny {
            reason: format!(
                "tool '{}' is destructive but the agent's access_level is read_only",
                tool_name
            ),
        },
        (Danger::Destructive, AccessLevel::ReadWrite)
        | (Danger::Destructive, AccessLevel::ConfirmAll) => AuthDecision::NeedsConfirmation {
            reason: format!(
                "destructive tool '{}' requires operator approval",
                tool_name
            ),
        },
        (Danger::Destructive, AccessLevel::Trusted) => AuthDecision::Allow,
    }
}

/// Serialised view of one tool, used by the API to feed the frontend's
/// "allowed tools" checklist.
#[derive(Debug, Serialize)]
pub struct ToolDescriptor {
    pub id: &'static str,
    pub label: &'static str,
    pub risk_note: &'static str,
}

/// List every tool in the registry — used by `GET /api/agents/tools`
/// so the UI can render the Edit Agent checklist without hardcoding.
pub fn catalogue() -> Vec<ToolDescriptor> {
    ToolId::ALL.iter().map(|t| ToolDescriptor {
        id: t.as_str(),
        label: t.label(),
        risk_note: t.risk_note(),
    }).collect()
}

/// Single audit-log entry — persisted JSONL at
/// `/etc/wolfstack/agents/<id>/audit.jsonl`. Append-only, never
/// rotated by us (let the operator decide via log rotation tooling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: u64,
    pub agent_id: String,
    pub tool: String,
    pub arguments: serde_json::Value,
    pub outcome: String,            // "allowed" | "denied"
    #[serde(default)]
    pub reason: Option<String>,     // filled on "denied"
}

/// Authorise an agent to invoke a specific tool. Returns Ok on yes,
/// Err with a human-readable reason on no. Audit entry written in
/// BOTH cases so operators can see denied attempts — an agent
/// repeatedly asking for a tool it doesn't have is a useful signal.
pub fn validate_for_agent(
    agent: &Agent,
    tool: ToolId,
    arguments: &serde_json::Value,
) -> Result<(), String> {
    let tool_name = tool.as_str();
    if !agent.allowed_tools.iter().any(|t| t == tool_name) {
        let reason = format!(
            "tool '{}' is not in the agent's allowed_tools list",
            tool_name);
        append_audit(&agent.id, &AuditEntry {
            ts: unix_seconds(),
            agent_id: agent.id.clone(),
            tool: tool_name.to_string(),
            arguments: arguments.clone(),
            outcome: "denied".to_string(),
            reason: Some(reason.clone()),
        });
        return Err(reason);
    }
    Ok(())
}

/// Record that a tool call was run (or not). Call this AFTER
/// `validate_for_agent` passes and the tool has been dispatched, with
/// the outcome string summarising what happened. Separate from the
/// validator so the audit log captures the full before/after picture.
pub fn record_invocation(
    agent_id: &str,
    tool: ToolId,
    arguments: &serde_json::Value,
    outcome: &str,
) {
    append_audit(agent_id, &AuditEntry {
        ts: unix_seconds(),
        agent_id: agent_id.to_string(),
        tool: tool.as_str().to_string(),
        arguments: arguments.clone(),
        outcome: outcome.to_string(),
        reason: None,
    });
}

fn audit_path(agent_id: &str) -> PathBuf {
    PathBuf::from("/etc/wolfstack/agents").join(agent_id).join("audit.jsonl")
}

fn append_audit(agent_id: &str, entry: &AuditEntry) {
    let path = audit_path(agent_id);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        // 0o700 the agent dir — audit log can reveal operational
        // detail (what actions the agent took, when, which arguments)
        // that shouldn't leak to other local users.
        tighten_dir_perms_unix(parent, 0o700);
    }
    use std::io::Write;
    let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else {
        tracing::warn!("wolfagents: cannot open audit log at {}", path.display());
        return;
    };
    match serde_json::to_string(entry) {
        Ok(line) => { let _ = writeln!(f, "{}", line); }
        Err(e) => tracing::warn!("wolfagents: failed to serialize audit entry: {}", e),
    }
    // 0o600 the log file — idempotent so rotation tools can't leave
    // it world-readable between rotations.
    tighten_file_perms_unix(&path, 0o600);
}

#[cfg(unix)]
fn tighten_dir_perms_unix(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn tighten_dir_perms_unix(_path: &std::path::Path, _mode: u32) {}

#[cfg(unix)]
fn tighten_file_perms_unix(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn tighten_file_perms_unix(_path: &std::path::Path, _mode: u32) {}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the last N audit entries for an agent (newest last). Used by
/// the UI's "audit" tab in the Edit Agent modal so operators can see
/// what the agent has been up to.
pub fn tail_audit(agent_id: &str, limit: usize) -> Vec<AuditEntry> {
    let path = audit_path(agent_id);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(limit);
    lines[start..].iter()
        .filter_map(|l| serde_json::from_str::<AuditEntry>(l).ok())
        .collect()
}
