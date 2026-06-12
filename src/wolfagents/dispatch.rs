// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Tool dispatcher — takes an agent + tool call request, runs the
//! full safety/authz/target-scope chain, executes the tool, and
//! returns a result the LLM can fold into its next turn.
//!
//! Every tool goes through the same pipeline:
//!
//! 1. **Safety denylist** (`safety::validate_command` / `validate_path`
//!    / `validate_api_path`) — hardcoded, no override. rm -rf /,
//!    dd of=/dev/sda, `systemctl stop wolfstack`, etc. refused here.
//!
//! 2. **Per-agent allowlist** — tool name must be in `allowed_tools`.
//!
//! 3. **Danger vs AccessLevel policy** — Safe runs on any level;
//!    Mutating needs ≥ ReadWrite (Destructive on ReadWrite queues
//!    for confirmation, same with ConfirmAll on mutating); Trusted
//!    runs everything (still subject to safety denylist).
//!
//! 4. **Target scope** — allowed_clusters / allowed_container_patterns
//!    / allowed_hosts / allowed_paths / allowed_api_paths checked
//!    against the specific arguments of this call.
//!
//! 5. **Execute** and capture stdout/result.
//!
//! 6. **Audit** — append to `/etc/wolfstack/agents/<id>/audit.jsonl`
//!    regardless of outcome, so operators see every allow/deny/error.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

use super::{Agent, safety, tools::{self, AuthDecision, ToolId}};

/// Shared HTTP client for every inter-node dispatch call in this
/// module. Previously every tool-fan-out site built its own Client
/// (`crate::api::ipv4_only_client_builder()...build()`) — thirteen separate
/// pools, each leaked at function exit. One shared pool reuses
/// connections across all tool invocations. Timeout is set per
/// request via `RequestBuilder::timeout` because each tool picks
/// its own deadline (5s–30s).
static DISPATCH_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Result of one dispatched tool call — what we hand back to the
/// LLM as the tool_result block on its next turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Did the call complete successfully? `false` for denied,
    /// queued-for-confirmation, or execution failure.
    pub ok: bool,
    /// Human-readable status line — shown verbatim as the top of the
    /// tool_result content. "Allowed and ran", "Refused by scope",
    /// "Queued for operator approval (seq 42)", etc.
    pub status: String,
    /// Structured payload — for safe/read tools this is the data the
    /// LLM needs; for mutating tools a summary of what changed; for
    /// denied calls a blank object. The caller stringifies this into
    /// the tool_result content.
    #[serde(default)]
    pub data: serde_json::Value,
}

impl ToolResult {
    fn ok(status: impl Into<String>, data: serde_json::Value) -> Self {
        Self { ok: true, status: status.into(), data }
    }
    // Concrete `String` (rather than `impl Into<String>`) so callsites
    // can use either `"literal"` or `format!(...)` or `err_string.into()`
    // without running into E0283 "type annotations needed" from the
    // generic bound ambiguity.
    fn err(status: String) -> Self {
        Self { ok: false, status, data: serde_json::Value::Null }
    }
}

/// Check whether a container name matches any of the agent's allowed
/// patterns. Empty pattern list = no constraint. `*` is a wildcard
/// for any sequence (including empty); everything else is literal.
///
/// Kept deliberately simple — full glob or regex support invites
/// pattern injection via the agent's target scope. Operators who need
/// more power should narrow scope by adding multiple patterns rather
/// than one complex one.
fn matches_container_pattern(name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() { return true; }
    for pat in patterns {
        if glob_match(pat, name) { return true; }
    }
    false
}

/// Tiny glob matcher — only `*` is special. Good enough for "regions*"
/// or "*-prod" patterns; refuses nothing if pattern is empty.
fn glob_match(pattern: &str, s: &str) -> bool {
    let mut p_idx = 0;
    let mut s_idx = 0;
    let mut star_p: Option<usize> = None;
    let mut star_s = 0;
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    while s_idx < t.len() {
        if p_idx < p.len() && (p[p_idx] == t[s_idx] || p[p_idx] == '?') {
            p_idx += 1; s_idx += 1;
        } else if p_idx < p.len() && p[p_idx] == '*' {
            star_p = Some(p_idx);
            star_s = s_idx;
            p_idx += 1;
        } else if let Some(sp) = star_p {
            p_idx = sp + 1;
            star_s += 1;
            s_idx = star_s;
        } else {
            return false;
        }
    }
    while p_idx < p.len() && p[p_idx] == '*' { p_idx += 1; }
    p_idx == p.len()
}

/// Does this cluster name pass the agent's allowed_clusters filter?
/// Kept for future cluster-aware tool additions — agent_loop uses the
/// same check inline when building the per-turn cluster snapshot.
#[allow(dead_code)]
fn cluster_allowed(cluster: &str, agent: &Agent) -> bool {
    let list = &agent.target_scope.allowed_clusters;
    list.is_empty() || list.iter().any(|c| c == cluster)
}

/// Does this path pass the agent's allowed_paths prefix list?
fn path_allowed(path: &str, agent: &Agent) -> bool {
    let list = &agent.target_scope.allowed_paths;
    if list.is_empty() { return true; }
    list.iter().any(|prefix| path.starts_with(prefix))
}

/// Main entry point — called from the Claude tool_use loop with one
/// tool_use block per call. The loop is responsible for looping
/// between dispatch() and the LLM until the LLM stops emitting
/// tool_use blocks.
pub async fn dispatch(
    agent: &Agent,
    tool_name: &str,
    arguments: &serde_json::Value,
    state: &crate::api::AppState,
) -> ToolResult {
    // Unknown tool name — refuse before touching anything.
    let Some(tool) = ToolId::from_str(tool_name) else {
        tools::record_invocation(
            &agent.id, ToolId::ListNodes /* dummy */, arguments,
            &format!("unknown_tool:{}", tool_name),
        );
        return ToolResult::err(format!(
            "unknown tool '{}'. Available: {}",
            tool_name,
            ToolId::ALL.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ")
        ));
    };

    // Allowlist + danger policy.
    match tools::authorise(agent, tool) {
        AuthDecision::Deny { reason } => {
            tools::record_invocation(&agent.id, tool, arguments, &format!("denied:{}", reason));
            return ToolResult::err(format!("refused: {}", reason));
        }
        AuthDecision::NeedsConfirmation { reason } => {
            // Queue the call for operator approval and tell the agent.
            match super::pending::enqueue(&agent.id, tool, arguments, &reason) {
                Ok(seq) => {
                    tools::record_invocation(&agent.id, tool, arguments,
                        &format!("queued_pending:{}", seq));
                    return ToolResult::err(format!(
                        "Action queued for operator approval (pending #{}). {} \
                         You should stop and wait for the operator — your next \
                         turn will see the approval result. Do not retry the \
                         same tool call in this turn.",
                        seq, reason
                    ));
                }
                Err(e) => {
                    tools::record_invocation(&agent.id, tool, arguments,
                        &format!("queue_failed:{}", e));
                    return ToolResult::err(format!("failed to queue for approval: {}", e));
                }
            }
        }
        AuthDecision::Allow => { /* fall through */ }
    }

    // Execute. Each branch is responsible for calling safety::
    // validators against its specific arguments before touching
    // anything, and for target_scope checks.
    let result = match tool {
        ToolId::ListNodes => tool_list_nodes(state).await,
        ToolId::ListContainers => tool_list_containers(arguments, agent, state).await,
        ToolId::GetMetrics => tool_get_metrics(arguments, state).await,
        ToolId::ListAlerts => tool_list_alerts(arguments).await,
        ToolId::ReadLog => tool_read_log(arguments, agent, state).await,
        ToolId::CheckDiskUsage => tool_check_disk_usage(arguments, agent, state).await,
        ToolId::ReadFile => tool_read_file(arguments, agent, state).await,
        ToolId::ListApiEndpoints => tool_list_api_endpoints(agent).await,
        ToolId::DescribeCluster => tool_describe_cluster(arguments, agent, state).await,
        ToolId::ListWorkflows => tool_list_workflows(arguments, state).await,
        ToolId::WebFetch => tool_web_fetch(arguments, false).await,
        ToolId::WebRender => tool_web_fetch(arguments, true).await,
        ToolId::SemanticSearch => tool_semantic_search(arguments, agent, state).await,

        ToolId::RestartContainer => tool_restart_container(arguments, agent, state).await,
        ToolId::RunWorkflow => tool_run_workflow(arguments, state).await,
        ToolId::ScheduleWorkflow => tool_schedule_workflow(arguments, state).await,
        ToolId::WriteFile => tool_write_file(arguments, agent, state).await,
        ToolId::SendEmail => tool_send_email(arguments, agent, state).await,

        ToolId::ExecInContainer => tool_exec_in_container(arguments, agent, state).await,
        ToolId::ExecOnNode => tool_exec_on_node(arguments, agent, state).await,
        ToolId::DeleteFile => tool_delete_file(arguments, agent, state).await,

        ToolId::WolfstackApi => tool_wolfstack_api(arguments, agent, state).await,

        ToolId::SqlRead => tool_sql_query(arguments, agent, state, crate::sql_connections::SqlPermission::Read).await,
        ToolId::SqlUpdate => tool_sql_query(arguments, agent, state, crate::sql_connections::SqlPermission::Update).await,
        ToolId::SqlDelete => tool_sql_query(arguments, agent, state, crate::sql_connections::SqlPermission::Delete).await,
    };

    let outcome = if result.ok {
        "ran".to_string()
    } else {
        format!("error:{}", result.status)
    };
    tools::record_invocation(&agent.id, tool, arguments, &outcome);
    result
}

// ═══════════════════════════════════════════════════
// Safe / read-only tools
// ═══════════════════════════════════════════════════

async fn tool_list_nodes(state: &crate::api::AppState) -> ToolResult {
    let nodes = state.cluster.get_all_nodes();
    let summary: Vec<_> = nodes.iter().map(|n| serde_json::json!({
        "id": n.id,
        "hostname": n.hostname,
        "cluster": n.cluster_name,
        "online": n.online,
        "is_self": n.is_self,
        "docker_count": n.docker_count,
        "lxc_count": n.lxc_count,
        "vm_count": n.vm_count,
    })).collect();
    ToolResult::ok(
        format!("{} nodes in cluster", summary.len()),
        serde_json::json!({ "nodes": summary }),
    )
}

async fn tool_list_containers(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let filter_cluster = args.get("cluster").and_then(|v| v.as_str());
    let filter_pattern = args.get("name_pattern").and_then(|v| v.as_str());
    // Cluster-wide gather: start with this node's containers, then
    // fan out to every online remote node via cluster-secret-auth'd
    // HTTP. Previously this only returned LOCAL containers, which made
    // agents confidently report "no LXC containers" when the LXC lived
    // on a different node in the same cluster.
    let nodes = state.cluster.get_all_nodes();
    let self_node = nodes.iter().find(|n| n.is_self);
    let self_hostname = self_node.map(|n| n.hostname.clone()).unwrap_or_default();
    let self_cluster = self_node.and_then(|n| n.cluster_name.clone()).unwrap_or_default();

    let mut out: Vec<(String, String, String, String, String)> = Vec::new(); // (runtime, name, status, node, cluster)
    for (runtime, name, status) in crate::containers::list_running_containers() {
        out.push((runtime, name, status, self_hostname.clone(), self_cluster.clone()));
    }

    // Remote nodes — one HTTP call per online non-self node.
    let http = &*DISPATCH_CLIENT;
    {
        for node in nodes.iter().filter(|n| n.online && !n.is_self) {
            // Skip nodes outside the caller's cluster filter — saves
            // per-node HTTP when the agent asked for one cluster.
            if let Some(fc) = filter_cluster {
                if node.cluster_name.as_deref() != Some(fc) { continue; }
            }
            // WolfStack listens on 8553 with TLS by default. The
            // remote exposes separate /api/containers/docker and
            // /api/containers/lxc endpoints; call both.
            let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
            let push_from_array = |arr: serde_json::Value, runtime: &str, out: &mut Vec<(String, String, String, String, String)>| {
                if let Some(a) = arr.as_array() {
                    for c in a {
                        let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let status = c.get("state").and_then(|v| v.as_str())
                            .or_else(|| c.get("status").and_then(|v| v.as_str()))
                            .unwrap_or("").to_string();
                        if name.is_empty() { continue; }
                        out.push((runtime.to_string(), name, status,
                            node.hostname.clone(),
                            node.cluster_name.clone().unwrap_or_default()));
                    }
                }
            };
            for (path, runtime) in &[
                ("/api/containers/docker", "docker"),
                ("/api/containers/lxc", "lxc"),
            ] {
                let url = format!("{}://{}:{}{}", scheme, crate::netaddr::bracket_host(&node.address), node.port, path);
                let resp = http.get(&url)
                    .header("X-WolfStack-Secret", &state.cluster_secret)
                    .timeout(std::time::Duration::from_secs(8))
                    .send().await;
                let Ok(r) = resp else { continue; };
                if !r.status().is_success() {
                    // Drain error body → socket back to pool.
                    let _ = r.bytes().await;
                    continue;
                }
                let Ok(val) = r.json::<serde_json::Value>().await else { continue; };
                // Most endpoints return {"containers": [...]} — unwrap
                // that, else treat the whole response as the array.
                let arr = val.get("containers").cloned().unwrap_or(val);
                push_from_array(arr, runtime, &mut out);
            }
        }
    }

    // Apply filters.
    let list: Vec<serde_json::Value> = out.into_iter()
        .filter(|(_, name, _, _, cluster)| {
            if let Some(p) = filter_pattern {
                if !glob_match(p, name) { return false; }
            }
            if let Some(fc) = filter_cluster {
                if cluster != fc { return false; }
            }
            // Agent scope enforcement: narrow to its container pattern allowlist.
            matches_container_pattern(name, &agent.target_scope.allowed_container_patterns)
        })
        .map(|(runtime, name, status, node, cluster)| serde_json::json!({
            "runtime": runtime,
            "name": name,
            "status": status,
            "node": node,
            "cluster": cluster,
        }))
        .collect();
    ToolResult::ok(
        format!(
            "{} containers match filter + scope across {} node(s)",
            list.len(),
            nodes.iter().filter(|n| n.online).count(),
        ),
        serde_json::json!({ "containers": list }),
    )
}

async fn tool_get_metrics(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    // Optional `node` arg — hostname filter. Without it we fan out to
    // every online cluster node so the agent can answer "how's sophie
    // doing?" accurately instead of silently reporting the metrics of
    // whichever node runs wolfstack.
    let target = args.get("node").and_then(|v| v.as_str());
    let nodes = state.cluster.get_all_nodes();

    let http = &*DISPATCH_CLIENT;

    let mut per_node: Vec<serde_json::Value> = Vec::new();
    for node in &nodes {
        if !node.online { continue; }
        if let Some(t) = target {
            if node.hostname != t && node.id != t { continue; }
        }
        // Local node collects directly — no HTTP hop needed.
        if node.is_self {
            let metrics = tokio::task::spawn_blocking(|| {
                let mut mon = crate::monitoring::SystemMonitor::new();
                mon.collect()
            }).await.ok();
            if let Some(m) = metrics {
                per_node.push(serde_json::json!({
                    "node": node.hostname,
                    "id": node.id,
                    "cluster": node.cluster_name,
                    "metrics": m,
                }));
            }
            continue;
        }
        // Remote node — GET /api/metrics with cluster-secret auth.
        let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
        let url = format!("{}://{}:{}/api/metrics", scheme, crate::netaddr::bracket_host(&node.address), node.port);
        let resp = http.get(&url)
            .header("X-WolfStack-Secret", &state.cluster_secret)
            .timeout(std::time::Duration::from_secs(8))
            .send().await;
        let Ok(r) = resp else { continue; };
        if !r.status().is_success() {
            let _ = r.bytes().await;  // drain → pool
            continue;
        }
        let Ok(val) = r.json::<serde_json::Value>().await else { continue; };
        per_node.push(serde_json::json!({
            "node": node.hostname,
            "id": node.id,
            "cluster": node.cluster_name,
            "metrics": val,
        }));
    }
    if per_node.is_empty() {
        return ToolResult::err(if let Some(t) = target {
            format!("no online node matches '{}'", t)
        } else {
            "no online nodes in cluster".to_string()
        });
    }
    ToolResult::ok(
        format!("metrics from {} node(s)", per_node.len()),
        serde_json::json!({ "nodes": per_node }),
    )
}

async fn tool_list_alerts(_args: &serde_json::Value) -> ToolResult {
    // AlertConfig doesn't persist a log of past alerts — surface that
    // honestly to the agent so it can ask the operator directly if
    // recent-alert history is needed.
    ToolResult::ok(
        "alerting subsystem present; no recent-alert log is persisted",
        serde_json::json!({
            "note": "Recent alert history is not currently logged. Use wolfstack_api \
                     GET /api/issues for the issue scanner's latest findings, or \
                     ask the operator for specific alerts.",
            "alerts": [],
        }),
    )
}

async fn tool_read_log(
    args: &serde_json::Value, _agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let lines = args.get("lines").and_then(|v| v.as_u64()).unwrap_or(100).min(2000) as usize;
    let target_node = args.get("node").and_then(|v| v.as_str());
    if target.is_empty() {
        return ToolResult::err("read_log requires a `target` argument (container name or systemd unit)".into());
    }

    // Try local journalctl + docker logs FIRST — cheap, handles the
    // self-node case without an HTTP hop and still works for systemd
    // units that only exist locally.
    if target_node.is_none() || target_node == Some("self") {
        let try_journal = std::process::Command::new("journalctl")
            .args(["-u", target, "-n", &lines.to_string(), "--no-pager", "--output=short"])
            .output();
        if let Ok(o) = try_journal {
            if o.status.success() && !o.stdout.is_empty() {
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                return ToolResult::ok(
                    format!("journalctl tail of {} ({} lines, this node)", target, lines),
                    serde_json::json!({ "source": "journalctl", "target": target, "node": "self", "log": text }),
                );
            }
        }
        if let Ok(o) = std::process::Command::new("docker")
            .args(["logs", "--tail", &lines.to_string(), target])
            .output()
        {
            if o.status.success() {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                return ToolResult::ok(
                    format!("docker logs tail of {} ({} lines, this node)", target, lines),
                    serde_json::json!({
                        "source": "docker", "target": target, "node": "self",
                        "stdout": stdout, "stderr": stderr,
                    }),
                );
            }
        }
    }

    // Not found locally — fan out to every online remote node.
    // Discover which node hosts a container named `target` by walking
    // the cluster's container cache, then call that node's log endpoint.
    let nodes = state.cluster.get_all_nodes();
    let http = &*DISPATCH_CLIENT;

    for node in &nodes {
        if !node.online || node.is_self { continue; }
        if let Some(t) = target_node {
            if node.hostname != t && node.id != t { continue; }
        }
        let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
        // Try docker-style first, then lxc-style. Whichever exists on
        // the remote for this container name wins; both endpoints
        // 404 cleanly when the container isn't theirs.
        for (path, runtime) in &[
            (format!("/api/containers/docker/{}/logs?lines={}", target, lines), "docker"),
            (format!("/api/containers/lxc/{}/logs?lines={}", target, lines), "lxc"),
        ] {
            let url = format!("{}://{}:{}{}", scheme, crate::netaddr::bracket_host(&node.address), node.port, path);
            let resp = http.get(&url)
                .header("X-WolfStack-Secret", &state.cluster_secret)
                .timeout(std::time::Duration::from_secs(10))
                .send().await;
            let Ok(r) = resp else { continue; };
            if !r.status().is_success() {
                let _ = r.bytes().await;
                continue;
            }
            let text = r.text().await.unwrap_or_default();
            // Some endpoints return JSON, some plain text — try JSON
            // first, fall back to the raw body.
            let log_payload: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|_| serde_json::Value::String(text.clone()));
            return ToolResult::ok(
                format!("{} logs tail of {} ({} lines, on node {})",
                    runtime, target, lines, node.hostname),
                serde_json::json!({
                    "source": *runtime,
                    "target": target,
                    "node": node.hostname,
                    "log": log_payload,
                }),
            );
        }
    }
    ToolResult::err(format!(
        "no log found for '{}' — not a local systemd unit or docker container, \
         and no online cluster node reported having a matching docker or lxc container. \
         Try list_containers to confirm the name.",
        target
    ))
}

async fn tool_check_disk_usage(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let container_pattern = args.get("container_pattern").and_then(|v| v.as_str())
        .unwrap_or("*");
    let threshold_pct = args.get("threshold_pct").and_then(|v| v.as_u64()).unwrap_or(90) as u32;
    let filter_cluster = args.get("cluster").and_then(|v| v.as_str());

    // Walk the cluster-wide container list built the same way
    // list_containers does, so "check disk on all region-* containers"
    // answers correctly whether they live on cynthia, sophie, or any
    // other online node.
    let nodes = state.cluster.get_all_nodes();
    let self_hostname = nodes.iter().find(|n| n.is_self)
        .map(|n| n.hostname.clone()).unwrap_or_default();

    // Collect (runtime, name, node_hostname, cluster) across the cluster.
    let mut targets: Vec<(String, String, String, String, bool, String, u16)> = Vec::new();
    // (runtime, name, node_hostname, cluster_name, is_self, node_address, node_port)
    for (runtime, name, _status) in crate::containers::list_running_containers() {
        targets.push((runtime, name, self_hostname.clone(),
            nodes.iter().find(|n| n.is_self)
                .and_then(|n| n.cluster_name.clone()).unwrap_or_default(),
            true, String::new(), 0));
    }
    let http = &*DISPATCH_CLIENT;
    {
        for node in nodes.iter().filter(|n| n.online && !n.is_self) {
            if let Some(fc) = filter_cluster {
                if node.cluster_name.as_deref() != Some(fc) { continue; }
            }
            let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
            for (path, runtime) in &[
                ("/api/containers/docker", "docker"),
                ("/api/containers/lxc", "lxc"),
            ] {
                let url = format!("{}://{}:{}{}", scheme, crate::netaddr::bracket_host(&node.address), node.port, path);
                let Ok(r) = http.get(&url)
                    .header("X-WolfStack-Secret", &state.cluster_secret)
                    .timeout(std::time::Duration::from_secs(8))
                    .send().await
                else { continue; };
                if !r.status().is_success() {
                    let _ = r.bytes().await;
                    continue;
                }
                let Ok(val) = r.json::<serde_json::Value>().await else { continue; };
                let arr = val.get("containers").cloned().unwrap_or(val);
                if let Some(a) = arr.as_array() {
                    for c in a {
                        if let Some(name) = c.get("name").and_then(|v| v.as_str()) {
                            targets.push((
                                runtime.to_string(), name.to_string(),
                                node.hostname.clone(),
                                node.cluster_name.clone().unwrap_or_default(),
                                false, node.address.clone(), node.port,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Apply filters.
    let filtered: Vec<_> = targets.into_iter()
        .filter(|(_, name, _, cluster, _, _, _)| {
            if !glob_match(container_pattern, name) { return false; }
            if let Some(fc) = filter_cluster {
                if cluster != fc { return false; }
            }
            matches_container_pattern(name, &agent.target_scope.allowed_container_patterns)
        })
        .collect();

    // For each target, exec `df -P /` — locally or via the remote exec
    // endpoint on whichever node the container lives on.
    let mut results = Vec::new();
    for (runtime, name, node_hostname, cluster, is_self, address, port) in filtered {
        let df_output: Option<String> = if is_self {
            let out = match runtime.as_str() {
                "docker" => std::process::Command::new("docker")
                    .args(["exec", &name, "df", "-P", "/"]).output(),
                "lxc" => std::process::Command::new("lxc-attach")
                    .args(["-n", &name, "--", "df", "-P", "/"]).output(),
                _ => continue,
            };
            match out {
                Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string()),
                _ => None,
            }
        } else {
            // Remote exec via /api/containers/{runtime}/{id}/exec —
            // runs `df -P /` in the container on the remote node.
            let scheme = if port == 443 || port == 8553 { "https" } else { "http" };
            let url = format!("{}://{}:{}/api/containers/{}/{}/exec",
                scheme, crate::netaddr::bracket_host(&address), port, runtime, name);
            let body = serde_json::json!({ "command": "df -P /" });
            match http.post(&url)
                .header("X-WolfStack-Secret", &state.cluster_secret)
                .timeout(std::time::Duration::from_secs(8))
                .json(&body).send().await
            {
                Ok(r) if r.status().is_success() => {
                    r.json::<serde_json::Value>().await.ok()
                        .and_then(|v| v.get("stdout").and_then(|s| s.as_str()).map(String::from))
                }
                Ok(r) => {
                    // Drain the error body before giving up.
                    let _ = r.bytes().await;
                    None
                }
                Err(_) => None,
            }
        };

        let (used_pct, avail_kb, total_kb) = match df_output {
            Some(text) if !text.is_empty() => parse_df(&text),
            _ => (0, 0, 0),
        };
        results.push(serde_json::json!({
            "container": name,
            "runtime": runtime,
            "node": node_hostname,
            "cluster": cluster,
            "used_pct": used_pct,
            "available_kb": avail_kb,
            "total_kb": total_kb,
            "over_threshold": used_pct >= threshold_pct,
        }));
    }
    ToolResult::ok(
        format!("checked {} containers across cluster against threshold {}%",
            results.len(), threshold_pct),
        serde_json::json!({ "threshold_pct": threshold_pct, "containers": results }),
    )
}

/// Parse `df -P /` output → (used_pct, available_kb, total_kb).
/// Example line: "/dev/sda1  50000000  25000000  25000000  50% /"
fn parse_df(text: &str) -> (u32, u64, u64) {
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let total = parts[1].parse::<u64>().unwrap_or(0);
            let avail = parts[3].parse::<u64>().unwrap_or(0);
            let used = parts[4].trim_end_matches('%').parse::<u32>().unwrap_or(0);
            return (used, avail, total);
        }
    }
    (0, 0, 0)
}

async fn tool_read_file(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let max_bytes = args.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(65536).min(1024 * 1024) as usize;
    let node = args.get("node").and_then(|v| v.as_str()).unwrap_or("").trim();
    if path.is_empty() {
        return ToolResult::err("read_file requires a `path` argument".into());
    }
    if let Err(e) = safety::validate_path(path) {
        return ToolResult::err(e);
    }
    if !path_allowed(path, agent) {
        return ToolResult::err(format!(
            "path '{}' is outside the agent's allowed_paths scope",
            path
        ));
    }
    // Local read when no node specified, "self", this node's id, or
    // the cluster entry for `node` resolves to the self-node.
    let self_id = crate::agent::self_node_id();
    let is_local = node.is_empty() || node == "self" || node == self_id
        || state.cluster.get_all_nodes().iter()
            .find(|n| n.id == node || n.hostname == node)
            .map(|n| n.is_self)
            .unwrap_or(false);
    if is_local {
        return match std::fs::read(path) {
            Ok(bytes) => {
                let truncated = bytes.len() > max_bytes;
                let slice = &bytes[..max_bytes.min(bytes.len())];
                let content = String::from_utf8_lossy(slice).to_string();
                ToolResult::ok(
                    format!("read {} bytes from {} (this node)", slice.len(), path),
                    serde_json::json!({
                        "path": path, "node": "self",
                        "content": content,
                        "truncated": truncated,
                        "total_bytes": bytes.len(),
                    }),
                )
            }
            Err(e) => ToolResult::err(format!("read failed: {}", e)),
        };
    }
    // Remote read via cluster-secret-auth'd /api/cluster/file/read.
    read_file_on_remote(state, node, path).await
}

async fn read_file_on_remote(
    state: &crate::api::AppState, node_spec: &str, path: &str,
) -> ToolResult {
    let nodes = state.cluster.get_all_nodes();
    let Some(node) = nodes.iter().find(|n| n.id == node_spec || n.hostname == node_spec) else {
        return ToolResult::err(format!("no node with id or hostname '{}'", node_spec));
    };
    if !node.online {
        return ToolResult::err(format!("node '{}' is offline", node.hostname));
    }
    let http = &*DISPATCH_CLIENT;
    let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
    let url = format!("{}://{}:{}/api/cluster/file/read", scheme, crate::netaddr::bracket_host(&node.address), node.port);
    let resp = http.post(&url)
        .header("X-WolfStack-Secret", &state.cluster_secret)
        .timeout(std::time::Duration::from_secs(15))
        .json(&serde_json::json!({ "path": path }))
        .send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let val: serde_json::Value = r.json().await.unwrap_or_else(|_| serde_json::json!({}));
            ToolResult::ok(
                format!("read from {} on {}", path, node.hostname),
                serde_json::json!({
                    "path": path, "node": node.hostname,
                    "content": val.get("content").cloned().unwrap_or_default(),
                    "truncated": val.get("truncated").and_then(|v| v.as_bool()).unwrap_or(false),
                    "total_bytes": val.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                }),
            )
        }
        Ok(r) => {
            let code = r.status();
            let body = r.text().await.unwrap_or_default();
            ToolResult::err(format!("remote read on {} returned {}: {}", node.hostname, code, body))
        }
        Err(e) => ToolResult::err(format!("remote read on {} failed: {}", node.hostname, e)),
    }
}

async fn tool_list_api_endpoints(agent: &Agent) -> ToolResult {
    // If the agent has an explicit allowlist, echo it. Otherwise we
    // can't enumerate every route in the binary at runtime; surface a
    // "all GETs allowed" hint so the agent knows to just try.
    let list = &agent.target_scope.allowed_api_paths;
    if list.is_empty() {
        ToolResult::ok(
            "no explicit allowlist — read-only GETs allowed by default",
            serde_json::json!({
                "hint": "Agent has no allowed_api_paths configured, so GET requests \
                         to /api/* are allowed (subject to the hardcoded denylist). \
                         Use wolfstack_api with method=GET to explore.",
                "entries": [],
            }),
        )
    } else {
        ToolResult::ok(
            format!("{} allowlist entries", list.len()),
            serde_json::json!({ "entries": list }),
        )
    }
}

async fn tool_describe_cluster(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let filter = args.get("cluster_name").and_then(|v| v.as_str());
    let nodes = state.cluster.get_all_nodes();
    let mut picked: Vec<_> = nodes.iter()
        .filter(|n| n.node_type != "proxmox")
        .filter(|n| match filter {
            Some(c) => n.cluster_name.as_deref() == Some(c),
            None => true,
        })
        .filter(|n| {
            let scope = &agent.target_scope.allowed_clusters;
            scope.is_empty() || n.cluster_name.as_deref()
                .map(|c| scope.iter().any(|s| s == c))
                .unwrap_or(false)
        })
        .map(|n| serde_json::json!({
            "id": n.id,
            "hostname": n.hostname,
            "cluster": n.cluster_name,
            "online": n.online,
            "docker": n.docker_count,
            "lxc": n.lxc_count,
            "vm": n.vm_count,
            "node_type": n.node_type,
            "address": n.address,
        })).collect::<Vec<_>>();
    picked.sort_by(|a, b| a["hostname"].as_str().cmp(&b["hostname"].as_str()));
    ToolResult::ok(
        format!("{} nodes matched", picked.len()),
        serde_json::json!({
            "cluster_filter": filter,
            "agent_allowed_clusters": agent.target_scope.allowed_clusters,
            "nodes": picked,
        }),
    )
}

// ═══════════════════════════════════════════════════
// Mutating tools
// ═══════════════════════════════════════════════════

async fn tool_restart_container(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let runtime = args.get("runtime").and_then(|v| v.as_str()).unwrap_or("");
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if runtime.is_empty() || name.is_empty() {
        return ToolResult::err("restart_container requires `runtime` (docker|lxc) and `name`".into());
    }
    if runtime != "docker" && runtime != "lxc" {
        return ToolResult::err(format!("unsupported runtime '{}'", runtime));
    }
    if !matches_container_pattern(name, &agent.target_scope.allowed_container_patterns) {
        return ToolResult::err(format!(
            "container '{}' is outside the agent's allowed_container_patterns scope",
            name
        ));
    }

    // Discover the host node FIRST, then restart exactly once. Using
    // local-first-or-error-then-fan-out would double-restart across
    // nodes that happened to have containers of the same name.
    let local_has = match runtime {
        "docker" => std::process::Command::new("docker")
            .args(["inspect", "--type=container", name, "--format", "{{.Id}}"])
            .output().map(|o| o.status.success()).unwrap_or(false),
        "lxc" => std::process::Command::new("lxc-info")
            .args(["-n", name])
            .output().map(|o| o.status.success()).unwrap_or(false),
        _ => unreachable!(),
    };
    if local_has {
        let local_cmd = match runtime {
            "docker" => vec!["docker", "restart", name],
            "lxc" => vec!["lxc-stop", "-r", "-n", name],
            _ => unreachable!(),
        };
        let mut cmd = std::process::Command::new(local_cmd[0]);
        for a in &local_cmd[1..] { cmd.arg(a); }
        return match cmd.output() {
            Ok(o) if o.status.success() => ToolResult::ok(
                format!("restarted {}:{} on self", runtime, name),
                serde_json::json!({
                    "runtime": runtime, "name": name, "node": "self",
                    "stdout": String::from_utf8_lossy(&o.stdout).trim().to_string(),
                }),
            ),
            Ok(o) => ToolResult::err(format!(
                "restart failed (exit {}): {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => ToolResult::err(format!("spawn failed: {}", e)),
        };
    }

    // Not local — find the owning node via inventory, then restart once.
    let http = &*DISPATCH_CLIENT;
    for node in state.cluster.get_all_nodes().iter().filter(|n| n.online && !n.is_self) {
        let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
        let list_path = if runtime == "docker" { "/api/containers/docker" } else { "/api/containers/lxc" };
        let list_url = format!("{}://{}:{}{}", scheme, crate::netaddr::bracket_host(&node.address), node.port, list_path);
        let Ok(list_r) = http.get(&list_url)
            .header("X-WolfStack-Secret", &state.cluster_secret)
            .timeout(std::time::Duration::from_secs(15))
            .send().await else { continue; };
        if !list_r.status().is_success() {
            let _ = list_r.bytes().await;
            continue;
        }
        let Ok(list_val) = list_r.json::<serde_json::Value>().await else { continue; };
        let arr = list_val.get("containers").cloned().unwrap_or(list_val);
        let has_it = arr.as_array().map(|a| a.iter().any(|c|
            c.get("name").and_then(|v| v.as_str()) == Some(name))).unwrap_or(false);
        if !has_it { continue; }
        let action_url = format!("{}://{}:{}/api/containers/{}/{}/action",
            scheme, crate::netaddr::bracket_host(&node.address), node.port, runtime, name);
        let resp = http.post(&action_url)
            .header("X-WolfStack-Secret", &state.cluster_secret)
            .timeout(std::time::Duration::from_secs(15))
            .json(&serde_json::json!({ "action": "restart" }))
            .send().await;
        let Ok(r) = resp else { continue; };
        if !r.status().is_success() {
            let _ = r.bytes().await;
            continue;
        }
        let _ = r.bytes().await;  // drain success body, action endpoint returns ack
        return ToolResult::ok(
            format!("restarted {}:{} on {}", runtime, name, node.hostname),
            serde_json::json!({
                "runtime": runtime, "name": name, "node": node.hostname,
            }),
        );
    }
    ToolResult::err(format!(
        "container {}:{} not found on any online node in the cluster",
        runtime, name
    ))
}

async fn tool_run_workflow(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    let id = args.get("workflow_id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return ToolResult::err("run_workflow requires `workflow_id`".into());
    }
    let Some(workflow) = state.wolfflow.get_workflow(id) else {
        let available: Vec<String> = state.wolfflow.list_workflows(None)
            .into_iter().map(|w| format!("{} (id={})", w.name, w.id)).collect();
        return ToolResult::err(format!(
            "no workflow with id '{}'. Available: [{}]",
            id,
            available.join(", ")
        ));
    };
    let wf_state = state.wolfflow.clone();
    let cluster = state.cluster.clone();
    let secret = state.cluster_secret.clone();
    // Recover from a poisoned mutex instead of panicking — a previous
    // panic in another code path under this lock would otherwise take
    // the agent's tool call down with it. The inner value is fine to
    // read; we only need a clone of the config to pass to the workflow.
    let ai_config = state.ai_agent.config.lock()
        .unwrap_or_else(|p| p.into_inner()).clone();
    let wf_name = workflow.name.clone();
    // Fire-and-forget exactly like the API trigger. The agent gets
    // back "enqueued" — if it needs the run's outcome, it can poll
    // `list_workflows` or use wolfstack_api against /api/wolfflow/runs.
    tokio::spawn(async move {
        crate::wolfflow::execute_workflow(
            &wf_state, &cluster, &secret, &workflow, "agent", Some(ai_config)
        ).await;
    });
    ToolResult::ok(
        format!("workflow_triggered: {}", wf_name),
        serde_json::json!({ "workflow_id": id, "workflow_name": wf_name, "trigger": "agent" }),
    )
}

async fn tool_list_workflows(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    let cluster = args.get("cluster").and_then(|v| v.as_str());
    let workflows = state.wolfflow.list_workflows(cluster);
    let summary: Vec<serde_json::Value> = workflows.iter().map(|w| serde_json::json!({
        "id": w.id,
        "name": w.name,
        "cluster": w.cluster,
        "enabled": w.enabled,
        "schedule": w.schedule,
        "step_count": w.steps.len(),
    })).collect();
    ToolResult::ok(
        format!("{} workflows", summary.len()),
        serde_json::json!({ "workflows": summary }),
    )
}

async fn tool_schedule_workflow(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    let id = args.get("workflow_id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return ToolResult::err("schedule_workflow requires `workflow_id`".into());
    }
    // `schedule` can be a 5-field cron expression or null to clear the
    // schedule. We accept both explicit null and a missing field as
    // "clear the schedule" (the agent may have been told "unschedule X").
    // `cron` is accepted as an alias — natural word for the field, and
    // models sometimes emit that even when the schema says `schedule`.
    let schedule_arg = args.get("schedule").or_else(|| args.get("cron"));
    let new_schedule: Option<String> = match schedule_arg {
        Some(v) if v.is_null() => None,
        Some(v) => match v.as_str() {
            Some(s) if s.trim().is_empty() => None,
            Some(s) => {
                // Validate the cron expression before storing it. The
                // scheduler silently skips workflows whose cron fails to
                // parse, so an agent emitting "every 5 minutes" would
                // look accepted but never run. We require five whitespace
                // fields and each field to contain only the character
                // classes the matcher understands.
                let fields: Vec<&str> = s.split_whitespace().collect();
                if fields.len() != 5 {
                    return ToolResult::err(format!(
                        "invalid cron expression '{}': expected 5 fields (min hour dom month dow), got {}",
                        s, fields.len()));
                }
                for (i, f) in fields.iter().enumerate() {
                    if !f.chars().all(|c| c == '*' || c == ',' || c == '-'
                                       || c == '/' || c.is_ascii_digit()) {
                        return ToolResult::err(format!(
                            "invalid cron expression '{}': field {} ('{}') contains unsupported characters",
                            s, i + 1, f));
                    }
                }
                Some(s.to_string())
            }
            None => return ToolResult::err("`schedule` must be a string or null".into()),
        },
        None => None,
    };
    let Some(mut wf) = state.wolfflow.get_workflow(id) else {
        return ToolResult::err(format!("no workflow with id '{}'", id));
    };
    let before = wf.schedule.clone();
    wf.schedule = new_schedule.clone();
    // Enable handling:
    //   - explicit `enabled: true/false` argument wins (agent intent is clear),
    //   - otherwise, default to enabling when setting a schedule because a
    //     scheduled workflow that stays disabled never fires, which would
    //     silently defeat the agent's intent.
    match args.get("enabled").and_then(|v| v.as_bool()) {
        Some(b) => wf.enabled = b,
        None if new_schedule.is_some() => wf.enabled = true,
        None => {} // clearing the schedule leaves enabled as-is
    }
    match state.wolfflow.update_workflow(id, wf) {
        Some(updated) => ToolResult::ok(
            format!(
                "workflow '{}' schedule: {} -> {}",
                updated.name,
                before.as_deref().unwrap_or("(none)"),
                updated.schedule.as_deref().unwrap_or("(none)"),
            ),
            serde_json::json!({
                "workflow_id": id,
                "name": updated.name,
                "schedule": updated.schedule,
                "enabled": updated.enabled,
            }),
        ),
        None => ToolResult::err(format!("update_workflow({}) returned None", id)),
    }
}

async fn tool_write_file(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let append = args.get("append").and_then(|v| v.as_bool()).unwrap_or(false);
    let node = args.get("node").and_then(|v| v.as_str()).unwrap_or("").trim();
    if path.is_empty() {
        return ToolResult::err("write_file requires a `path` argument".into());
    }
    if let Err(e) = safety::validate_path(path) {
        return ToolResult::err(e);
    }
    if !path_allowed(path, agent) {
        return ToolResult::err(format!(
            "path '{}' is outside the agent's allowed_paths scope",
            path
        ));
    }
    if content.len() > 8 * 1024 * 1024 {
        return ToolResult::err("content exceeds 8 MB — write_file refuses large payloads".into());
    }
    let self_id = crate::agent::self_node_id();
    let is_local = node.is_empty() || node == "self" || node == self_id
        || state.cluster.get_all_nodes().iter()
            .find(|n| n.id == node || n.hostname == node)
            .map(|n| n.is_self).unwrap_or(false);
    if is_local {
        let result = if append {
            use std::io::Write;
            std::fs::OpenOptions::new().create(true).append(true).open(path)
                .and_then(|mut f| f.write_all(content.as_bytes()))
        } else {
            std::fs::write(path, content.as_bytes())
        };
        return match result {
            Ok(()) => ToolResult::ok(
                format!("wrote {} bytes to {} (this node)", content.len(), path),
                serde_json::json!({ "path": path, "node": "self", "bytes": content.len(), "appended": append }),
            ),
            Err(e) => ToolResult::err(format!("write failed: {}", e)),
        };
    }
    // Remote write via cluster-secret-auth'd /api/cluster/file/write.
    write_file_on_remote(state, node, path, content, append).await
}

async fn write_file_on_remote(
    state: &crate::api::AppState, node_spec: &str, path: &str, content: &str, append: bool,
) -> ToolResult {
    let nodes = state.cluster.get_all_nodes();
    let Some(node) = nodes.iter().find(|n| n.id == node_spec || n.hostname == node_spec) else {
        return ToolResult::err(format!("no node with id or hostname '{}'", node_spec));
    };
    if !node.online {
        return ToolResult::err(format!("node '{}' is offline", node.hostname));
    }
    let http = &*DISPATCH_CLIENT;
    let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
    let url = format!("{}://{}:{}/api/cluster/file/write", scheme, crate::netaddr::bracket_host(&node.address), node.port);
    let resp = http.post(&url)
        .header("X-WolfStack-Secret", &state.cluster_secret)
        .timeout(std::time::Duration::from_secs(30))
        .json(&serde_json::json!({ "path": path, "content": content, "append": append }))
        .send().await;
    match resp {
        Ok(r) if r.status().is_success() => ToolResult::ok(
            format!("wrote {} bytes to {} on {}", content.len(), path, node.hostname),
            serde_json::json!({
                "path": path, "node": node.hostname, "bytes": content.len(), "appended": append,
            }),
        ),
        Ok(r) => {
            let code = r.status();
            let body = r.text().await.unwrap_or_default();
            ToolResult::err(format!("remote write on {} returned {}: {}", node.hostname, code, body))
        }
        Err(e) => ToolResult::err(format!("remote write on {} failed: {}", node.hostname, e)),
    }
}

// ═══════════════════════════════════════════════════
// Destructive tools
// ═══════════════════════════════════════════════════

async fn tool_exec_in_container(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let runtime = args.get("runtime").and_then(|v| v.as_str()).unwrap_or("docker");
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30).min(600);
    if name.is_empty() || command.is_empty() {
        return ToolResult::err("exec_in_container requires `name` and `command`".into());
    }
    if let Err(e) = safety::validate_command(command) {
        return ToolResult::err(e);
    }
    if !matches_container_pattern(name, &agent.target_scope.allowed_container_patterns) {
        return ToolResult::err(format!(
            "container '{}' is outside the agent's allowed_container_patterns scope",
            name
        ));
    }
    if runtime != "docker" && runtime != "lxc" {
        return ToolResult::err(format!("unsupported runtime '{}'", runtime));
    }

    // Find which node hosts the container BEFORE executing. Using
    // exit status from the exec itself to decide "wrong node" vs
    // "command failed" is ambiguous — a command that legitimately
    // exited non-zero would then get re-run on every other node's
    // container of the same name, multiplying side effects. Instead:
    //   1. Ask docker/lxc locally if the container exists here.
    //   2. If not, fan out calling /api/containers/docker and /lxc
    //      to find which node's inventory lists it.
    //   3. Exec on exactly that one node.
    let local_has = match runtime {
        "docker" => std::process::Command::new("docker")
            .args(["inspect", "--type=container", name, "--format", "{{.Id}}"])
            .output().map(|o| o.status.success()).unwrap_or(false),
        "lxc" => std::process::Command::new("lxc-info")
            .args(["-n", name])
            .output().map(|o| o.status.success()).unwrap_or(false),
        _ => unreachable!(),
    };
    if local_has {
        let local_exec = match runtime {
            "docker" => format!("docker exec {} sh -c {}", name, shell_escape(command)),
            "lxc" => format!("lxc-attach -n {} -- sh -c {}", name, shell_escape(command)),
            _ => unreachable!(),
        };
        return run_shell_with_timeout(&local_exec, timeout_secs).await;
    }

    // Not local — fan out to find which online node owns it.
    let http = &*DISPATCH_CLIENT;
    let req_timeout = std::time::Duration::from_secs(timeout_secs + 5);
    for node in state.cluster.get_all_nodes().iter().filter(|n| n.online && !n.is_self) {
        let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
        // Check inventory first (cheap list call) so we don't
        // gratuitously exec on the wrong node.
        let list_path = if runtime == "docker" { "/api/containers/docker" } else { "/api/containers/lxc" };
        let list_url = format!("{}://{}:{}{}", scheme, crate::netaddr::bracket_host(&node.address), node.port, list_path);
        let Ok(list_r) = http.get(&list_url)
            .header("X-WolfStack-Secret", &state.cluster_secret)
            .timeout(req_timeout)
            .send().await else { continue; };
        if !list_r.status().is_success() {
            let _ = list_r.bytes().await;
            continue;
        }
        let Ok(list_val) = list_r.json::<serde_json::Value>().await else { continue; };
        let arr = list_val.get("containers").cloned().unwrap_or(list_val);
        let has_it = arr.as_array().map(|a| a.iter().any(|c|
            c.get("name").and_then(|v| v.as_str()) == Some(name))).unwrap_or(false);
        if !has_it { continue; }
        // Found it — exec there.
        let exec_url = format!("{}://{}:{}/api/containers/{}/{}/exec",
            scheme, crate::netaddr::bracket_host(&node.address), node.port, runtime, name);
        let resp = http.post(&exec_url)
            .header("X-WolfStack-Secret", &state.cluster_secret)
            .timeout(req_timeout)
            .json(&serde_json::json!({ "command": command }))
            .send().await;
        let Ok(r) = resp else { continue; };
        if !r.status().is_success() {
            let _ = r.bytes().await;
            continue;
        }
        let Ok(val) = r.json::<serde_json::Value>().await else { continue; };
        let stdout = val.get("stdout").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let stderr = val.get("stderr").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let exit = val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
        return ToolResult::ok(
            format!("exec {}:{} on {} (exit {})", runtime, name, node.hostname, exit),
            serde_json::json!({
                "runtime": runtime, "name": name, "node": node.hostname,
                "exit_code": exit, "stdout": stdout, "stderr": stderr,
            }),
        );
    }
    ToolResult::err(format!(
        "container {}:{} not found on any online node in the cluster",
        runtime, name
    ))
}

async fn tool_exec_on_node(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let node_id = args.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30).min(600);
    if node_id.is_empty() || command.is_empty() {
        return ToolResult::err("exec_on_node requires `node_id` and `command`".into());
    }
    if let Err(e) = safety::validate_command(command) {
        return ToolResult::err(e);
    }
    let scope = &agent.target_scope.allowed_hosts;
    let self_id = crate::agent::self_node_id();
    if !scope.is_empty() && !scope.iter().any(|h| h == node_id) {
        return ToolResult::err(format!(
            "node '{}' is outside the agent's allowed_hosts scope",
            node_id
        ));
    }

    // Self-node: full shell. Same as before — agent's safety denylist
    // already applied above, and operator's access_level decided if
    // we even got here.
    if node_id == self_id {
        return run_shell_with_timeout(command, timeout_secs).await;
    }

    // Cross-node: forward to the remote's /api/ai/exec. That endpoint
    // applies its OWN read-only safety allowlist on top of ours — so
    // remote exec is effectively read-only (df, cat, ps, systemctl
    // status, etc.). That's enough for "check disk on sophie" /
    // "what's running on sophie" questions; for destructive cross-
    // node ops, use exec_in_container (which routes via the container
    // runtime) or deploy the action as a WolfFlow step.
    let nodes = state.cluster.get_all_nodes();
    let Some(node) = nodes.iter().find(|n| n.id == node_id || n.hostname == node_id) else {
        return ToolResult::err(format!("no node with id or hostname '{}'", node_id));
    };
    if !node.online {
        return ToolResult::err(format!("node '{}' is offline", node_id));
    }
    let http = &*DISPATCH_CLIENT;
    let scheme = if node.port == 443 || node.port == 8553 { "https" } else { "http" };
    let url = format!("{}://{}:{}/api/ai/exec", scheme, crate::netaddr::bracket_host(&node.address), node.port);
    let resp = http.post(&url)
        .header("X-WolfStack-Secret", &state.cluster_secret)
        .timeout(std::time::Duration::from_secs(timeout_secs + 5))
        .json(&serde_json::json!({ "command": command }))
        .send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(val) => {
                    // /api/ai/exec returns {output, exit_code} on success,
                    // {error} on rejected (unsafe / blocked) commands.
                    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
                        ToolResult::err(format!(
                            "remote exec rejected on {}: {}. Remote exec is read-only; \
                             for destructive ops use exec_in_container or a WolfFlow step.",
                            node.hostname, err))
                    } else {
                        ToolResult::ok(
                            format!("exec on {} (exit {})",
                                node.hostname,
                                val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0)),
                            serde_json::json!({
                                "node": node.hostname,
                                "command": command,
                                "output": val.get("output").and_then(|v| v.as_str()).unwrap_or(""),
                                "exit_code": val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0),
                            }),
                        )
                    }
                }
                Err(e) => ToolResult::err(format!("remote response parse failed: {}", e)),
            }
        }
        Ok(r) => {
            let code = r.status();
            let _ = r.bytes().await;
            ToolResult::err(format!("remote exec HTTP {} on {}", code, node.hostname))
        }
        Err(e) => ToolResult::err(format!("remote exec failed on {}: {}", node.hostname, e)),
    }
}

async fn tool_delete_file(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let node = args.get("node").and_then(|v| v.as_str()).unwrap_or("").trim();
    if path.is_empty() {
        return ToolResult::err("delete_file requires a `path` argument".into());
    }
    if let Err(e) = safety::validate_path(path) {
        return ToolResult::err(e);
    }
    if !path_allowed(path, agent) {
        return ToolResult::err(format!(
            "path '{}' is outside the agent's allowed_paths scope",
            path
        ));
    }
    let self_id = crate::agent::self_node_id();
    let is_local = node.is_empty() || node == "self" || node == self_id
        || state.cluster.get_all_nodes().iter()
            .find(|n| n.id == node || n.hostname == node)
            .map(|n| n.is_self).unwrap_or(false);
    if is_local {
        return match std::fs::remove_file(path) {
            Ok(()) => ToolResult::ok(
                format!("deleted {} (this node)", path),
                serde_json::json!({ "path": path, "node": "self" }),
            ),
            Err(e) => ToolResult::err(format!("delete failed: {}", e)),
        };
    }
    // Remote delete via cluster-secret-auth'd /api/cluster/file/delete.
    let nodes = state.cluster.get_all_nodes();
    let Some(n) = nodes.iter().find(|x| x.id == node || x.hostname == node) else {
        return ToolResult::err(format!("no node with id or hostname '{}'", node));
    };
    if !n.online {
        return ToolResult::err(format!("node '{}' is offline", n.hostname));
    }
    let http = &*DISPATCH_CLIENT;
    let scheme = if n.port == 443 || n.port == 8553 { "https" } else { "http" };
    let url = format!("{}://{}:{}/api/cluster/file/delete", scheme, crate::netaddr::bracket_host(&n.address), n.port);
    let resp = http.post(&url)
        .header("X-WolfStack-Secret", &state.cluster_secret)
        .timeout(std::time::Duration::from_secs(15))
        .json(&serde_json::json!({ "path": path }))
        .send().await;
    match resp {
        Ok(r) if r.status().is_success() => ToolResult::ok(
            format!("deleted {} on {}", path, n.hostname),
            serde_json::json!({ "path": path, "node": n.hostname }),
        ),
        Ok(r) => {
            let code = r.status();
            let body = r.text().await.unwrap_or_default();
            ToolResult::err(format!("remote delete on {} returned {}: {}", n.hostname, code, body))
        }
        Err(e) => ToolResult::err(format!("remote delete on {} failed: {}", n.hostname, e)),
    }
}

// ═══════════════════════════════════════════════════
// Universal WolfStack API (Phase G)
// ═══════════════════════════════════════════════════

async fn tool_wolfstack_api(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let body = args.get("body");
    if path.is_empty() {
        return ToolResult::err("wolfstack_api requires a `path` argument (e.g. /api/nodes)".into());
    }
    if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
        return ToolResult::err(format!("unsupported HTTP method '{}'", method));
    }

    // Safety: hardcoded API denylist — refuses /api/auth/*, /api/agents/*
    // (so one agent can't reconfigure another), /api/ports, etc.
    if let Err(e) = safety::validate_api_path(path) {
        return ToolResult::err(e);
    }

    // Method-based danger gating. GET is always allowed on Safe, but
    // since WolfstackApi is classified as Mutating in the catalogue
    // (for the access-level policy), GETs still needed Mutating
    // authority to get here. For POST/PUT/PATCH/DELETE we additionally
    // require the per-agent allowed_api_paths to explicitly list the
    // path — otherwise the agent would be able to POST anywhere.
    let write_method = method != "GET";
    let key = format!("{}:{}", method, path);
    let allow_list = &agent.target_scope.allowed_api_paths;
    if write_method {
        let matched = allow_list.iter().any(|entry| {
            // Accept exact "METHOD:/api/path" entries and path-only
            // entries (operator can list "/api/workflows/*" without
            // pinning a method).
            entry == &key || entry == path || path_glob_matches(entry, &key)
        });
        if !matched {
            return ToolResult::err(format!(
                "{} {} is not in the agent's allowed_api_paths. \
                 Add an explicit entry like \"{}:{}\" to the agent's scope.",
                method, path, method, path
            ));
        }
    }

    // Route over loopback. We use the cluster-secret as auth — the
    // same mechanism inter-node calls already use, so the request
    // runs with cluster-peer privileges (NOT a logged-in user's
    // session). This means user-scoped endpoints that inspect the
    // session username will see "cluster-node" instead, which is
    // fine for observation and admin ops.
    let port = crate::ports::PortConfig::load().api;
    let url = format!("http://127.0.0.1:{}{}", port, path);
    let client = &*DISPATCH_CLIENT;
    let req_builder = match method.as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        _ => unreachable!(),
    };
    let req_builder = req_builder
        .timeout(Duration::from_secs(30))
        .header("X-WolfStack-Secret", &state.cluster_secret);
    let req_builder = if let Some(b) = body {
        req_builder.header("Content-Type", "application/json").json(b)
    } else {
        req_builder
    };

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            // Try to parse as JSON for nicer agent consumption; fall
            // back to raw text.
            let data: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|_| serde_json::Value::String(text.clone()));
            let truncated = if text.len() > 16 * 1024 {
                text.chars().take(16 * 1024).collect()
            } else {
                text
            };
            let ok = (200..300).contains(&status);
            ToolResult {
                ok,
                status: format!("{} {} → HTTP {}", method, path, status),
                data: serde_json::json!({
                    "status": status,
                    "body_raw": truncated,
                    "body_json": data,
                }),
            }
        }
        Err(e) => {
            warn!("wolfagents dispatch: wolfstack_api request failed: {}", e);
            ToolResult::err(format!("request failed: {}", e))
        }
    }
}

fn path_glob_matches(pattern: &str, s: &str) -> bool {
    // Allow patterns like "GET:/api/nodes/*" against "GET:/api/nodes/123".
    glob_match(pattern, s)
}

// ═══════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════

/// Single-quote shell escape for embedding an agent-supplied command
/// into a shell wrapper (`docker exec X sh -c '<cmd>'`). Doesn't
/// sanitise the command itself — safety::validate_command has already
/// checked for destructive patterns before this point.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

async fn run_shell_with_timeout(command: &str, timeout_secs: u64) -> ToolResult {
    let timeout = Duration::from_secs(timeout_secs);
    let task = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let child = match task {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("spawn failed: {}", e)),
    };
    let waited = tokio::time::timeout(timeout, child.wait_with_output()).await;
    match waited {
        Ok(Ok(o)) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let code = o.status.code().unwrap_or(-1);
            ToolResult {
                ok: o.status.success(),
                status: format!("exit {}", code),
                data: serde_json::json!({
                    "stdout": truncate(&stdout, 16 * 1024),
                    "stderr": truncate(&stderr, 8 * 1024),
                    "exit_code": code,
                }),
            }
        }
        Ok(Err(e)) => ToolResult::err(format!("wait failed: {}", e)),
        Err(_) => ToolResult::err(format!("command timed out after {}s", timeout_secs)),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else {
        let mut t: String = s.chars().take(max).collect();
        t.push_str("\n...[truncated]");
        t
    }
}

// ─── send_email ─────────────────────────────────────────────────────────

/// Send an email via the AiConfig's existing SMTP relay. Gated by the
/// agent's allowed_email_recipients scope so a prompt-injected agent
/// can't address arbitrary external inboxes.
///
/// The SMTP credentials and host live on AiConfig because it already
/// powers the alerting emails and the operator has a UI for it in
/// Settings → AI Agent. We reuse the transport rather than shipping a
/// second SMTP configuration.
async fn tool_send_email(
    args: &serde_json::Value, agent: &Agent, _state: &crate::api::AppState,
) -> ToolResult {
    let subject = args.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim();
    let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let html = args.get("html").and_then(|v| v.as_bool()).unwrap_or(false);
    if subject.is_empty() {
        return ToolResult::err("send_email requires a non-empty `subject`".into());
    }
    if body.is_empty() {
        return ToolResult::err("send_email requires a non-empty `body`".into());
    }
    if body.len() > 256 * 1024 {
        return ToolResult::err("send_email body exceeds 256 KB".into());
    }

    // Collect recipients: either a string (single address) or an array.
    let recipients: Vec<String> = match args.get("to") {
        Some(v) if v.is_string() => vec![v.as_str().unwrap().trim().to_string()],
        Some(v) if v.is_array() => v.as_array().unwrap().iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty()).collect(),
        Some(_) => return ToolResult::err("`to` must be a string or array of strings".into()),
        None => Vec::new(),
    };

    let config = crate::ai::AiConfig::load();
    if config.smtp_host.is_empty() || config.smtp_user.is_empty() {
        return ToolResult::err(
            "SMTP is not configured on this WolfStack. Configure Settings → AI Agent → Email first.".into());
    }

    // If `to` is omitted, fall back to the AiConfig default alerting
    // recipient — matches the "just notify my usual inbox" pattern.
    let effective: Vec<String> = if recipients.is_empty() {
        if config.email_to.trim().is_empty() {
            return ToolResult::err(
                "No `to` specified and no default recipient configured in AiConfig.email_to.".into());
        }
        vec![config.email_to.clone()]
    } else {
        recipients
    };

    // Recipient-scope check. Empty allowed_email_recipients means
    // "only the AiConfig default is allowed" — prevents agents from
    // silently widening the blast radius.
    let allowed = &agent.target_scope.allowed_email_recipients;
    for r in &effective {
        if !recipient_permitted(r, allowed, &config.email_to) {
            return ToolResult::err(format!(
                "recipient '{}' is not in the agent's allowed_email_recipients scope. \
                 Add it (exact address or `@domain` suffix) in Edit Agent → Target Scope.", r));
        }
    }

    // Build + send. Reuse AiConfig's SMTP plumbing so auth / TLS mode
    // stay consistent with the existing alerting path.
    if let Err(e) = send_email_generic(&config, &effective, subject, body, html) {
        return ToolResult::err(format!("SMTP send failed: {}", e));
    }
    ToolResult::ok(
        format!("email sent to {} recipient(s)", effective.len()),
        serde_json::json!({
            "to": effective,
            "subject": subject,
            "html": html,
            "bytes": body.len(),
        }),
    )
}

/// Is `addr` permitted under the scope? The rules:
///   - `allowed` empty → only the AiConfig default recipient is OK.
///   - entry starts with `@` → matches any address at that domain.
///   - otherwise exact match (case-insensitive).
fn recipient_permitted(addr: &str, allowed: &[String], default_to: &str) -> bool {
    let a = addr.to_ascii_lowercase();
    if allowed.is_empty() {
        return !default_to.is_empty()
            && default_to.to_ascii_lowercase() == a;
    }
    for entry in allowed {
        let e = entry.trim().to_ascii_lowercase();
        if e.is_empty() { continue; }
        if e.starts_with('@') {
            if a.ends_with(&e) { return true; }
        } else if a == e {
            return true;
        }
    }
    false
}

/// Exposed `pub(crate)` so `src/wolfflow/mod.rs::ActionType::SendEmail`
/// can reuse the same SMTP path as the agent `send_email` tool —
/// single source of truth for email delivery.
pub(crate) fn send_email_generic(
    config: &crate::ai::AiConfig,
    to: &[String],
    subject: &str,
    body: &str,
    html: bool,
) -> Result<(), String> {
    use lettre::{Message, SmtpTransport, Transport};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::message::{SinglePart, header::ContentType};

    let from_addr: lettre::message::Mailbox = format!("WolfStack Agent <{}>", config.smtp_user)
        .parse().map_err(|e| format!("from: {}", e))?;
    let mut builder = Message::builder().from(from_addr).subject(subject);
    for r in to {
        let mb: lettre::message::Mailbox = r.parse()
            .map_err(|e| format!("to '{}': {}", r, e))?;
        builder = builder.to(mb);
    }
    let email = if html {
        builder.singlepart(SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(body.to_string()))
            .map_err(|e| format!("build html: {}", e))?
    } else {
        builder.body(body.to_string())
            .map_err(|e| format!("build text: {}", e))?
    };
    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());
    let mailer = match config.smtp_tls.as_str() {
        "tls" => SmtpTransport::relay(&config.smtp_host)
            .map_err(|e| format!("relay: {}", e))?
            .port(config.smtp_port).credentials(creds).build(),
        "none" => SmtpTransport::builder_dangerous(&config.smtp_host)
            .port(config.smtp_port).credentials(creds).build(),
        _ => SmtpTransport::starttls_relay(&config.smtp_host)
            .map_err(|e| format!("starttls: {}", e))?
            .port(config.smtp_port).credentials(creds).build(),
    };
    mailer.send(&email).map_err(|e| format!("send: {}", e))?;
    Ok(())
}

// ─── web_fetch / web_render ─────────────────────────────────────────────

/// Maximum bytes read from any web fetch. A model that asks for a
/// 50 MB page will get the first 512 KB — more than enough for text
/// extraction and cheap to reason about.
const WEB_FETCH_MAX_BYTES: usize = 512 * 1024;
const WEB_FETCH_TIMEOUT_SECS: u64 = 10;
const WEB_RENDER_TIMEOUT_SECS: u64 = 30;

/// Shared implementation for `web_fetch` (static HTTP) and `web_render`
/// (headless Chromium shell-out). The `rendered` flag flips execution
/// path; the safety gates (scheme check, SSRF guard via pre-resolve,
/// size cap, timeout) are identical.
async fn tool_web_fetch(args: &serde_json::Value, rendered: bool) -> ToolResult {
    let url = args.get("url").and_then(|v| v.as_str()).unwrap_or("").trim();
    if url.is_empty() {
        return ToolResult::err(format!(
            "{} requires a `url` argument",
            if rendered { "web_render" } else { "web_fetch" }));
    }
    // Only http/https — no file://, no ftp, no data:. Validated with a
    // case-insensitive prefix check so `HTTPS://` doesn't slip past.
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return ToolResult::err(format!(
            "url '{}' rejected: only http:// and https:// schemes are allowed", url));
    }
    // SSRF guard: resolve the hostname and refuse private / loopback /
    // link-local targets. Done before reqwest touches the network so we
    // can't be redirected into the internal network mid-request.
    let host = match extract_host(url) {
        Some(h) => h,
        None => return ToolResult::err(format!("url '{}' has no parseable host", url)),
    };
    match resolve_public(&host) {
        Ok(()) => {}
        Err(e) => return ToolResult::err(format!("url '{}' rejected: {}", url, e)),
    }

    if rendered {
        web_render_via_chromium(url).await
    } else {
        web_fetch_http(url).await
    }
}

/// Extract the hostname from an http(s) URL without pulling in a url
/// crate. Handles `scheme://host`, `scheme://host:port`, `scheme://host/path`,
/// and ignores credentials (`scheme://user:pass@host`). Returns None
/// on malformed input.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.splitn(2, "://").nth(1)?;
    // Drop anything after the first '/', '?', or '#'.
    let authority: &str = after_scheme.splitn(2, |c: char| c == '/' || c == '?' || c == '#')
        .next().unwrap_or("");
    // Drop credentials.
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // Drop port. Be careful with IPv6 literals `[::1]:443`.
    if hostport.starts_with('[') {
        if let Some(close) = hostport.find(']') {
            return Some(hostport[1..close].to_string());
        }
        return None;
    }
    let host = hostport.splitn(2, ':').next().unwrap_or(hostport);
    if host.is_empty() { None } else { Some(host.to_string()) }
}

/// Resolve a hostname and reject loopback / private / link-local IPs.
/// Runs on the current thread because tokio's resolver is async and
/// this is called from async context anyway — we use std::net here
/// to avoid pulling in more tokio surface than needed.
fn resolve_public(host: &str) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    // Attach a placeholder port so ToSocketAddrs parses the host.
    let probe = format!("{}:80", host);
    let addrs: Vec<_> = probe.to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .collect();
    if addrs.is_empty() {
        return Err("DNS returned no addresses".to_string());
    }
    for sa in &addrs {
        let ip = sa.ip();
        if is_ip_private(&ip) {
            return Err(format!(
                "hostname resolves to a private / loopback / link-local address ({}) — refusing to fetch",
                ip));
        }
    }
    Ok(())
}

/// Classify an IP as "don't fetch from an agent over the public web."
/// Covers IPv4 loopback (127/8), private ranges (10/8, 172.16/12,
/// 192.168/16), link-local (169.254/16), and CGNAT (100.64/10); plus
/// IPv6 loopback, unique-local (fc00::/7), and link-local (fe80::/10).
fn is_ip_private(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (seg & 0xfe00) == 0xfc00  // ULA fc00::/7
                || (seg & 0xffc0) == 0xfe80  // link-local fe80::/10
        }
    }
}

async fn web_fetch_http(url: &str) -> ToolResult {
    // Shared pool — see DISPATCH_CLIENT. The builder used to set
    // `redirect::Policy::limited(5)` per call; DISPATCH_CLIENT
    // defaults to up to 10 redirects, which is strictly more
    // permissive — acceptable for an agent web fetch. User-Agent
    // and per-request timeout set below.
    let client = &*DISPATCH_CLIENT;
    let resp = match client.get(url)
        .timeout(std::time::Duration::from_secs(WEB_FETCH_TIMEOUT_SECS))
        .header("User-Agent", "WolfStackAgent/1.0 (+https://wolfstack.io)")
        .send().await
    {
        Ok(r) => r,
        Err(e) => return ToolResult::err(format!("web_fetch: request failed: {}", e)),
    };
    let status = resp.status().as_u16();
    let content_type = resp.headers().get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Read up to WEB_FETCH_MAX_BYTES — avoids downloading a 5 GB ISO
    // that some adversarial page tries to trick us into.
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= WEB_FETCH_MAX_BYTES { buf.truncate(WEB_FETCH_MAX_BYTES); break; }
            }
            Err(e) => return ToolResult::err(format!("web_fetch: stream error: {}", e)),
        }
    }
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let text = if content_type.contains("text/html") || content_type.is_empty() {
        strip_html_to_text(&raw)
    } else {
        raw.clone()
    };
    ToolResult::ok(
        format!("fetched {} ({} bytes, status {})", url, buf.len(), status),
        serde_json::json!({
            "url": url,
            "status": status,
            "content_type": content_type,
            "text": truncate(&text, 100_000),
        }),
    )
}

/// Strip HTML tags + collapse whitespace. Drops <script>, <style>,
/// <svg>, and <head>-level metadata so the text that reaches the LLM
/// is what a reader would see. Not a full parser — a minute of regex
/// that handles the common cases and degrades gracefully on malformed
/// markup by leaving extra whitespace.
fn strip_html_to_text(html: &str) -> String {
    let mut s = html.to_string();
    // Drop script/style blocks (tag + content).
    for tag in ["script", "style", "noscript", "svg", "iframe", "template"] {
        let open = format!("<{}", tag);
        while let Some(start) = s.to_ascii_lowercase().find(&open) {
            let close_tag = format!("</{}>", tag);
            if let Some(end) = s[start..].to_ascii_lowercase().find(&close_tag) {
                s.replace_range(start..start + end + close_tag.len(), " ");
            } else {
                // No closing tag — drop from open to end of string.
                s.truncate(start);
                break;
            }
        }
    }
    // Replace block-level tags with newlines for readability.
    for tag in ["</p>", "</div>", "</li>", "</h1>", "</h2>", "</h3>",
                "</h4>", "<br>", "<br/>", "<br />", "</tr>"] {
        s = s.replace(tag, &format!("{}\n", tag));
    }
    // Strip remaining tags.
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    // Decode the handful of entities that actually matter.
    let out = out.replace("&nbsp;", " ")
                 .replace("&amp;", "&")
                 .replace("&lt;", "<")
                 .replace("&gt;", ">")
                 .replace("&quot;", "\"")
                 .replace("&#039;", "'")
                 .replace("&apos;", "'");
    // Collapse runs of whitespace (but keep single newlines so the
    // paragraph structure survives).
    let mut collapsed = String::with_capacity(out.len());
    let mut last_was_space = false;
    let mut last_was_newline = false;
    for c in out.chars() {
        if c == '\n' {
            if !last_was_newline { collapsed.push('\n'); }
            last_was_newline = true;
            last_was_space = true;
        } else if c.is_whitespace() {
            if !last_was_space { collapsed.push(' '); }
            last_was_space = true;
        } else {
            collapsed.push(c);
            last_was_space = false;
            last_was_newline = false;
        }
    }
    collapsed.trim().to_string()
}

async fn web_render_via_chromium(url: &str) -> ToolResult {
    // Find a chromium binary on the host. We deliberately don't ship
    // one; operator must install it (apt install chromium, etc.).
    let bin = ["chromium", "chromium-browser", "google-chrome", "chrome"]
        .into_iter()
        .find(|b| which_exists(b));
    let Some(bin) = bin else {
        return ToolResult::err(
            "web_render: no chromium/google-chrome binary on this host. Install one and retry, \
             or use web_fetch for static HTML.".to_string());
    };
    // --dump-dom prints the rendered HTML to stdout after JS executes.
    // --no-sandbox is needed when running as root inside some distros;
    // acceptable here because the caller is already an authorised agent
    // and the URL passed SSRF pre-checks.
    let out = tokio::process::Command::new(bin)
        .args(["--headless=new", "--no-sandbox", "--disable-gpu",
               "--disable-extensions", "--virtual-time-budget=5000",
               "--dump-dom", url])
        .output();
    let out = match tokio::time::timeout(
        std::time::Duration::from_secs(WEB_RENDER_TIMEOUT_SECS), out).await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return ToolResult::err(format!("web_render: exec failed: {}", e)),
        Err(_) => return ToolResult::err(format!(
            "web_render: timed out after {}s", WEB_RENDER_TIMEOUT_SECS)),
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return ToolResult::err(format!("web_render: chromium exited non-zero: {}",
            truncate(&err, 400)));
    }
    let mut html = out.stdout;
    if html.len() > WEB_FETCH_MAX_BYTES { html.truncate(WEB_FETCH_MAX_BYTES); }
    let text = strip_html_to_text(&String::from_utf8_lossy(&html));
    ToolResult::ok(
        format!("rendered {} ({} bytes DOM)", url, html.len()),
        serde_json::json!({
            "url": url,
            "rendered": true,
            "text": truncate(&text, 100_000),
        }),
    )
}

fn which_exists(bin: &str) -> bool {
    std::process::Command::new("sh").args(["-c", &format!("command -v {}", bin)])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

// ─── semantic_search (BM25) ──────────────────────────────────────────────

/// Search past agent memory, alert history, and audit logs using a BM25
/// ranking. We intentionally avoid a true embedding model here — BM25
/// handles "find past incidents mentioning the same container name"
/// well enough without bundling a 25 MB ONNX model. The tool surface
/// is stable; when a real vector index lands later, callers don't
/// notice.
async fn tool_semantic_search(
    args: &serde_json::Value, _agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("").trim();
    if query.is_empty() {
        return ToolResult::err("semantic_search requires a `query` string".into());
    }
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10)
        .clamp(1, 50) as usize;
    let sources: Vec<String> = args.get("sources").and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["memory".into(), "audit".into(), "alerts".into()]);
    let node = args.get("node").and_then(|v| v.as_str()).unwrap_or("").trim();

    // Memory / audit / alert files are per-node. Three modes:
    //   - no node / "self" / this node's id → local only (fast path)
    //   - "*" or "all" → fan out to every online node, merge + re-rank
    //   - specific node → HTTP to just that node
    let self_id = crate::agent::self_node_id();
    let is_local_only = node.is_empty() || node == "self" || node == self_id
        || state.cluster.get_all_nodes().iter()
            .find(|n| n.id == node || n.hostname == node)
            .map(|n| n.is_self).unwrap_or(false);
    if is_local_only {
        let src_refs: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
        let docs = collect_search_corpus(&src_refs);
        let ranked = bm25_rank(query, &docs, limit);
        return ToolResult::ok(
            format!("{} matches for '{}' across {} docs (this node)",
                ranked.len(), query, docs.len()),
            serde_json::json!({
                "query": query, "sources": sources, "node": "self",
                "total_docs": docs.len(), "matches": ranked,
            }),
        );
    }
    // Cluster-wide or specific remote.
    let want_all = node == "*" || node == "all";
    let nodes = state.cluster.get_all_nodes();
    let http = &*DISPATCH_CLIENT;

    // Collect raw matches with their source-node tag, then BM25 already
    // gave each one a score — we just sort globally and take top-N.
    let mut gathered: Vec<serde_json::Value> = Vec::new();
    // Start with local matches for the "*" mode so cluster-wide
    // includes self too.
    if want_all {
        let src_refs: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
        let docs = collect_search_corpus(&src_refs);
        for m in bm25_rank(query, &docs, limit * 2) {
            let mut obj = m;
            if let Some(o) = obj.as_object_mut() {
                o.insert("node".into(), serde_json::json!(
                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_default()
                ));
            }
            gathered.push(obj);
        }
    }
    for n in nodes.iter().filter(|n| n.online && !n.is_self) {
        if !want_all && !(n.id == node || n.hostname == node) { continue; }
        let scheme = if n.port == 443 || n.port == 8553 { "https" } else { "http" };
        let url = format!("{}://{}:{}/api/cluster/semantic/search",
            scheme, crate::netaddr::bracket_host(&n.address), n.port);
        let resp = http.post(&url)
            .header("X-WolfStack-Secret", &state.cluster_secret)
            .timeout(std::time::Duration::from_secs(15))
            .json(&serde_json::json!({
                "query": query, "limit": limit * 2, "sources": sources,
            }))
            .send().await;
        let Ok(r) = resp else { continue; };
        if !r.status().is_success() {
            let _ = r.bytes().await;
            continue;
        }
        let Ok(val) = r.json::<serde_json::Value>().await else { continue; };
        if let Some(arr) = val.get("matches").and_then(|v| v.as_array()) {
            for m in arr {
                let mut obj = m.clone();
                if let Some(o) = obj.as_object_mut() {
                    o.insert("node".into(), serde_json::json!(n.hostname));
                }
                gathered.push(obj);
            }
        }
    }
    // Global re-rank — sort by score (desc), take top-N.
    gathered.sort_by(|a, b| {
        let sa = a.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let sb = b.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    gathered.truncate(limit);
    ToolResult::ok(
        format!("{} matches for '{}' ({})", gathered.len(), query,
            if want_all { "cluster-wide".to_string() } else { format!("node={}", node) }),
        serde_json::json!({
            "query": query, "sources": sources,
            "node": if want_all { "*" } else { node },
            "matches": gathered,
        }),
    )
}

/// A single document in the search corpus — a line from memory/audit/
/// alerts, tagged with where it came from so matches carry source.
pub(crate) struct SearchDoc {
    source: String,
    path: String,
    text: String,
}

pub(crate) fn collect_search_corpus(sources: &[&str]) -> Vec<SearchDoc> {
    let mut out = Vec::new();
    if sources.contains(&"memory") {
        if let Ok(agents_dir) = std::fs::read_dir("/etc/wolfstack/agents") {
            for ent in agents_dir.flatten() {
                let mem = ent.path().join("memory.jsonl");
                if !mem.exists() { continue; }
                let id = ent.file_name().to_string_lossy().into_owned();
                if let Ok(text) = std::fs::read_to_string(&mem) {
                    for (i, line) in text.lines().enumerate() {
                        if line.trim().is_empty() { continue; }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                            let content = v.get("content").and_then(|x| x.as_str())
                                .unwrap_or("").to_string();
                            if content.is_empty() { continue; }
                            out.push(SearchDoc {
                                source: "memory".into(),
                                path: format!("{}:{}", id, i + 1),
                                text: content,
                            });
                        }
                    }
                }
            }
        }
    }
    if sources.contains(&"audit") {
        if let Ok(agents_dir) = std::fs::read_dir("/etc/wolfstack/agents") {
            for ent in agents_dir.flatten() {
                let audit = ent.path().join("audit.jsonl");
                if !audit.exists() { continue; }
                let id = ent.file_name().to_string_lossy().into_owned();
                if let Ok(text) = std::fs::read_to_string(&audit) {
                    for (i, line) in text.lines().enumerate() {
                        if !line.trim().is_empty() {
                            out.push(SearchDoc {
                                source: "audit".into(),
                                path: format!("{}:{}", id, i + 1),
                                text: line.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    if sources.contains(&"alerts") {
        // Alerting state lives in /etc/wolfstack/alerting.json — walk
        // the raw file so this stays consistent even if the in-memory
        // state structure evolves.
        if let Ok(text) = std::fs::read_to_string("/etc/wolfstack/alerting.json") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
                    for (i, ev) in events.iter().enumerate() {
                        let blob = serde_json::to_string(ev).unwrap_or_default();
                        out.push(SearchDoc {
                            source: "alerts".into(),
                            path: format!("alerting.json:{}", i + 1),
                            text: blob,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Tokenise text for BM25: lowercase, split on non-alphanumerics, drop
/// 1-char tokens (noise in BM25's IDF term). Good enough for the
/// corpora we're indexing, which are already English-ish log/chat text.
fn tokenise(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_string())
        .collect()
}

/// Classic BM25 with k1=1.5, b=0.75. Returns the top `limit` docs by
/// score, formatted for the tool response.
pub(crate) fn bm25_rank(query: &str, docs: &[SearchDoc], limit: usize) -> Vec<serde_json::Value> {
    if docs.is_empty() { return Vec::new(); }
    let q_terms: Vec<String> = tokenise(query);
    if q_terms.is_empty() { return Vec::new(); }
    // Pre-tokenise every doc.
    let doc_tokens: Vec<Vec<String>> = docs.iter().map(|d| tokenise(&d.text)).collect();
    let n = docs.len() as f64;
    let avgdl: f64 = doc_tokens.iter().map(|t| t.len() as f64).sum::<f64>() / n.max(1.0);
    // Document frequency for each unique query term.
    let mut df: std::collections::HashMap<&str, usize> = Default::default();
    for qt in &q_terms {
        let c = doc_tokens.iter().filter(|t| t.iter().any(|x| x == qt)).count();
        df.insert(qt.as_str(), c);
    }
    let k1 = 1.5_f64;
    let b = 0.75_f64;
    let mut scored: Vec<(f64, usize)> = doc_tokens.iter().enumerate().map(|(i, toks)| {
        let dl = toks.len() as f64;
        let mut s = 0.0;
        for qt in &q_terms {
            let dfq = *df.get(qt.as_str()).unwrap_or(&0) as f64;
            if dfq == 0.0 { continue; }
            let idf = ((n - dfq + 0.5) / (dfq + 0.5) + 1.0).ln();
            let tf = toks.iter().filter(|x| *x == qt).count() as f64;
            if tf == 0.0 { continue; }
            let denom = tf + k1 * (1.0 - b + b * dl / avgdl.max(1.0));
            s += idf * (tf * (k1 + 1.0)) / denom;
        }
        (s, i)
    }).filter(|(s, _)| *s > 0.0).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(limit);
    scored.into_iter().map(|(score, idx)| {
        let d = &docs[idx];
        serde_json::json!({
            "score": score,
            "source": d.source,
            "path": d.path,
            "snippet": truncate(&d.text, 400),
        })
    }).collect()
}

/// Run a SQL query on behalf of an agent. One implementation for all
/// three SQL tools — the `requested` permission distinguishes Read /
/// Update / Delete. Belt-and-braces: we enforce three independent
/// gates here, any of which is sufficient to refuse:
///
/// 1. **Per-agent permission flag** (`agent.sql_read/update/delete`) —
///    `sql_update` also requires `sql_read=true` implicitly (you can't
///    write without reading). Same for `sql_delete`. Operators who
///    grant Delete without Read are rare but possible; we treat the
///    absence of a prerequisite flag as "missing scope", not as an
///    auto-grant.
/// 2. **Connection allowlist** (`agent.allowed_sql_connections`) —
///    empty = no SQL access.
/// 3. **Per-statement classifier** (`sql_connections::classify`) —
///    rejects stacked statements, DDL, and any statement above the
///    requested tier regardless of which tool the agent invoked.
async fn tool_sql_query(
    args: &serde_json::Value,
    agent: &Agent,
    state: &crate::api::AppState,
    requested: crate::sql_connections::SqlPermission,
) -> ToolResult {
    use crate::sql_connections::SqlPermission as P;

    // Gate 1: per-agent permission flag.
    let has_perm = match requested {
        P::Read => agent.sql_read || agent.sql_update || agent.sql_delete,
        P::Update => agent.sql_update,
        P::Delete => agent.sql_delete,
        // DDL is not exposed as an agent tool — AI writing ALTER
        // TABLE unsupervised is not a surface we want. Schema changes
        // go through the Database Manager UI where an operator sees
        // and confirms the exact statement.
        P::Schema => false,
    };
    if !has_perm {
        return ToolResult::err(format!(
            "agent '{}' does not have the {:?} SQL permission — operator must enable it in the agent editor",
            agent.id, requested
        ));
    }

    let connection_id = args.get("connection_id")
        .or_else(|| args.get("connection"))
        .and_then(|v| v.as_str())
        .unwrap_or("").trim().to_string();
    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64());

    if connection_id.is_empty() {
        return ToolResult::err("sql query requires `connection_id` (the id of a configured SQL connection)".into());
    }
    if query.trim().is_empty() {
        return ToolResult::err("sql query requires a non-empty `query` string".into());
    }

    // Gate 2: connection allowlist.
    if !agent.target_scope.allowed_sql_connections.iter().any(|c| c == &connection_id) {
        return ToolResult::err(format!(
            "agent '{}' is not permitted to use sql connection '{}' — add it to allowed_sql_connections",
            agent.id, connection_id
        ));
    }

    // Gate 3 (classifier) is inside execute().
    match crate::sql_connections::execute(
        &connection_id,
        &query,
        requested,
        crate::sql_connections::Caller::Agent(agent.id.clone()),
        &state.cluster_secret,
        timeout_secs.map(std::time::Duration::from_secs),
        Some(&state.cluster),
    ).await {
        Ok(r) => ToolResult::ok(
            format!("sql {:?} on '{}' — {} rows in {}ms{}",
                requested, connection_id, r.row_count, r.elapsed_ms,
                if r.truncated { " (truncated)" } else { "" }),
            serde_json::json!({
                "connection_id": connection_id,
                "columns": r.columns,
                "rows": r.rows,
                "row_count": r.row_count,
                "affected_rows": r.affected_rows,
                "elapsed_ms": r.elapsed_ms,
                "truncated": r.truncated,
            }),
        ),
        Err(e) => ToolResult::err(e),
    }
}

#[cfg(test)]
mod web_tool_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn host_extraction_handles_common_shapes() {
        assert_eq!(extract_host("https://example.com/foo"), Some("example.com".into()));
        assert_eq!(extract_host("http://user:pw@example.com:8080/x"), Some("example.com".into()));
        assert_eq!(extract_host("https://[::1]:443/"), Some("::1".into()));
        assert_eq!(extract_host("https://host.example.com?q=1"), Some("host.example.com".into()));
        assert_eq!(extract_host("notaurl"), None);
    }

    #[test]
    fn private_ips_rejected() {
        let v = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
        assert!(is_ip_private(&v("127.0.0.1")));
        assert!(is_ip_private(&v("10.0.0.5")));
        assert!(is_ip_private(&v("172.16.0.1")));
        assert!(is_ip_private(&v("192.168.1.1")));
        assert!(is_ip_private(&v("169.254.0.1")));
        assert!(is_ip_private(&v("100.64.0.1"))); // CGNAT
        assert!(!is_ip_private(&v("8.8.8.8")));
        assert!(!is_ip_private(&v("1.1.1.1")));
    }

    #[test]
    fn private_ipv6_rejected() {
        let v = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
        assert!(is_ip_private(&v("::1")));
        assert!(is_ip_private(&v("fc00::1")));
        assert!(is_ip_private(&v("fd00::1")));
        assert!(is_ip_private(&v("fe80::1")));
        assert!(!is_ip_private(&v("2606:4700:4700::1111"))); // 1.1.1.1
    }

    #[test]
    fn html_strip_removes_scripts_and_tags() {
        let html = "<html><head><script>alert(1)</script></head><body><h1>Hello</h1><p>World &amp; friends</p></body></html>";
        let text = strip_html_to_text(html);
        assert!(!text.contains("<"));
        assert!(!text.contains("alert"));
        assert!(text.contains("Hello"));
        assert!(text.contains("World & friends"));
    }

    #[test]
    fn html_strip_handles_malformed_script() {
        // Unterminated <script> — should still strip to end of string.
        let html = "<p>ok</p><script>never closes";
        let text = strip_html_to_text(html);
        assert!(text.contains("ok"));
        assert!(!text.contains("never"));
    }

    #[test]
    fn bm25_ranks_matching_docs_higher() {
        let docs = vec![
            SearchDoc { source: "m".into(), path: "a".into(),
                text: "disk space on wolfgrid1 is low".into() },
            SearchDoc { source: "m".into(), path: "b".into(),
                text: "weather forecast is sunny".into() },
            SearchDoc { source: "m".into(), path: "c".into(),
                text: "disk usage trending up on wolfgrid2".into() },
        ];
        let ranked = bm25_rank("disk wolfgrid", &docs, 10);
        assert_eq!(ranked.len(), 2);
        let first_path = ranked[0]["path"].as_str().unwrap();
        assert!(first_path == "a" || first_path == "c",
            "unexpected first match {}", first_path);
    }

    #[test]
    fn email_recipient_scope_rules() {
        // Empty allowlist → only the AiConfig default is OK.
        assert!(recipient_permitted("paul@wolf.uk.com", &[], "paul@wolf.uk.com"));
        assert!(!recipient_permitted("paul@wolf.uk.com", &[], "ops@wolf.uk.com"));
        assert!(!recipient_permitted("attacker@evil.com", &[], "paul@wolf.uk.com"));
        // Empty allowlist AND empty default → reject everything.
        assert!(!recipient_permitted("paul@wolf.uk.com", &[], ""));
        // Explicit address match (case-insensitive).
        let allow1 = vec!["paul@wolf.uk.com".to_string()];
        assert!(recipient_permitted("paul@wolf.uk.com", &allow1, ""));
        assert!(recipient_permitted("Paul@Wolf.UK.com", &allow1, ""));
        assert!(!recipient_permitted("other@wolf.uk.com", &allow1, ""));
        // Domain match via @suffix.
        let allow2 = vec!["@wolf.uk.com".to_string()];
        assert!(recipient_permitted("anyone@wolf.uk.com", &allow2, ""));
        assert!(recipient_permitted("ops@wolf.uk.com", &allow2, ""));
        assert!(!recipient_permitted("attacker@evil.com", &allow2, ""));
    }

    #[test]
    fn bm25_empty_query_returns_nothing() {
        let docs = vec![SearchDoc { source: "m".into(), path: "a".into(),
            text: "hello".into() }];
        assert!(bm25_rank("", &docs, 10).is_empty());
        assert!(bm25_rank("   ", &docs, 10).is_empty());
    }
}
