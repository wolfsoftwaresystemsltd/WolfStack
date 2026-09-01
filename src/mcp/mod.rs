// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! MCP-shaped tool surface. Exposes a subset of WolfStack's read-only
//! operational capabilities as tools that external agent harnesses
//! (Claude Desktop, Continue, etc.) can call over HTTP.
//!
//! This is **not a full MCP server** today — the protocol also
//! requires an initialise handshake and specific transports (stdio
//! for local, HTTP/SSE for remote). Today we expose the two
//! shape-compatible endpoints:
//!
//! * `POST /api/mcp/tools/list` → `{ "tools": [...] }`
//! * `POST /api/mcp/tools/call` → `{ "content": [...] }`
//!
//! Response payloads match MCP's `tools/list` and `tools/call` JSON
//! shapes so a future transport wrapper can route transparently.
//! The tool set is intentionally small and **read-only** — no
//! restart_container, no run_workflow. Those need more thought
//! about authorisation scope across an external agent surface;
//! we'll layer them in when the MCP transport work lands.
//!
//! Security:
//!
//! * Callers authenticate with a standard WolfStack session cookie
//!   (same as the dashboard). A future API-key path will make
//!   headless agent integration cleaner — for now an agent can use
//!   the cookie from a dashboard login session.
//! * Tool names are a fixed enum — unknown names are rejected before
//!   any argument parsing, same defensive shape as
//!   `wolfagents::tools` and `installer::packages`.
//! * Read-only — worst case is a caller scraping cluster state they
//!   could already see in the UI.

use serde::{Deserialize, Serialize};

/// Body of a `tools/call` request — MCP-shaped.
#[derive(Debug, Deserialize)]
pub struct ToolCall {
    pub name: String,
    /// Free-form JSON per the MCP schema. Current tools take no
    /// arguments so the dispatch branches don't read it — kept so the
    /// protocol surface is complete when we add argumented tools
    /// (list_containers runtime filter, get_metrics node selector,
    /// etc.) without breaking clients authored today.
    #[serde(default)]
    #[allow(dead_code)]
    pub arguments: serde_json::Value,
}

/// Single tool descriptor returned by `tools/list`.
#[derive(Debug, Serialize)]
pub struct ToolDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

/// All tools MCP exposes. Hand-written JSON Schema so we don't pull
/// in a schema crate just to document three functions.
pub fn catalogue() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            name: "list_nodes",
            description: "List every cluster node with id, hostname, online state, cluster membership, and workload counts.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDescriptor {
            name: "get_metrics",
            description: "Current CPU, memory, and disk usage for the WolfStack node serving this request. Cluster-wide metrics require polling list_nodes then calling get_metrics against each node's URL.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDescriptor {
            name: "list_containers_local",
            description: "Docker + LXC containers running on the local node (the one answering this request). For cluster-wide coverage the caller should iterate nodes themselves.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
    ]
}

/// Execute a tool call. Validates the name and hands off to a
/// per-tool handler. Returns an MCP-shaped content array so a caller
/// can render it the same way whether they're calling us directly or
/// via a future stdio wrapper.
pub async fn dispatch(
    call: ToolCall,
    state: &crate::api::AppState,
) -> Result<serde_json::Value, String> {
    let result: serde_json::Value = match call.name.as_str() {
        "list_nodes" => tool_list_nodes(state)?,
        "get_metrics" => tool_get_metrics().await?,
        "list_containers_local" => tool_list_containers_local()?,
        other => return Err(format!("unknown tool '{}'", other)),
    };
    // MCP's tools/call response shape: { content: [{type: "text", text: "..."}] }
    // We serialise the result as pretty-printed JSON in a single text
    // block. Agents tend to parse it with their own JSON mode anyway.
    let text = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|_| result.to_string());
    Ok(serde_json::json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

fn tool_list_nodes(state: &crate::api::AppState) -> Result<serde_json::Value, String> {
    let nodes = state.cluster.get_all_nodes();
    let out: Vec<serde_json::Value> = nodes.iter()
        .filter(|n| n.node_type != "proxmox")
        .map(|n| serde_json::json!({
        "id": n.id,
        "hostname": n.hostname,
        "address": n.address,
        "port": n.port,
        "online": n.online,
        "is_self": n.is_self,
        "cluster": n.cluster_name,
        "node_type": n.node_type,
        "docker_count": n.docker_count,
        "lxc_count": n.lxc_count,
        "vm_count": n.vm_count,
    })).collect();
    Ok(serde_json::json!({ "nodes": out }))
}

async fn tool_get_metrics() -> Result<serde_json::Value, String> {
    // SystemMonitor::collect is sync and walks /proc + sysfs via
    // sysinfo; take it off the async executor to avoid blocking.
    let metrics = tokio::task::spawn_blocking(|| {
        let mut mon = crate::monitoring::SystemMonitor::new();
        mon.collect()
    }).await.map_err(|e| format!("metrics task panicked: {}", e))?;
    serde_json::to_value(&metrics)
        .map_err(|e| format!("serialize metrics: {}", e))
}

fn tool_list_containers_local() -> Result<serde_json::Value, String> {
    let items = crate::containers::list_running_containers();
    let out: Vec<serde_json::Value> = items.into_iter()
        .map(|(runtime, name, status)| serde_json::json!({
            "runtime": runtime,
            "name": name,
            "status": status,
        }))
        .collect();
    Ok(serde_json::json!({ "containers": out }))
}
