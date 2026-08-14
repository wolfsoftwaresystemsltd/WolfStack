// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfAgents — named AI agents with persistent memory and a tool
//! allowlist. This is the "WolfPack" surface — each agent is a
//! long-lived persona you can address by name (via the REST API,
//! WolfFlow's AgentChat step, a Discord channel binding, or the MCP
//! tool surface).
//!
//! Design choices:
//!
//! * **One agent = one system prompt + one model + one memory file**.
//!   System prompt is stable (the agent's "personality"); model can be
//!   changed freely (Claude for reasoning, Gemini for speed, local
//!   model when offline). Memory lives at
//!   `/etc/wolfstack/agents/<id>/memory.jsonl` as appended JSON lines
//!   so a crash mid-write loses at most one exchange.
//!
//! * **Memory is bounded** by `memory_max_lines`. When loading we
//!   tail the last N lines; when writing we don't truncate (the file
//!   IS the audit log — you can always scroll back). Default 40
//!   (~20 exchanges) balances context cost vs recall.
//!
//! * **Tools gated per agent**. `allowed_tools` lists the names of
//!   tools the agent may invoke. Starts empty — new agents are pure
//!   chatters until the operator turns on specific tools.
//!
//! * **Optional Discord channel binding**. When set, the Discord
//!   receiver loop routes messages in that channel to this agent and
//!   posts the reply back.

pub mod agent_loop;
pub mod dispatch;
pub mod pending;
pub mod safety;
pub mod tools;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Discord binding — agent reads and replies in one channel.
/// `bot_token` is optional: when present the agent runs on its OWN
/// Discord bot (separate gateway session). When absent WolfStack uses
/// the global token from AlertConfig so the existing single-bot
/// deployments keep working unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordBinding {
    /// Discord channel ID (snowflake, as a string).
    pub channel_id: String,
    /// Human label for the UI — e.g. "#ops-alerts in Wolf Labs".
    #[serde(default)]
    pub channel_label: String,
    /// Optional per-agent bot token. Empty/None = inherit the global
    /// AlertConfig.discord_bot_token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<String>,
}

/// Telegram binding — agent reads and replies in one chat (DM or
/// group). Chat IDs are int64 but Telegram's API returns them as
/// numbers and accepts them as either number or string; we store as
/// string so negative group-chat IDs don't lose precision.
/// `bot_token` is optional: when present the agent runs on its OWN
/// Telegram bot (separate long-polling task). When absent WolfStack
/// uses the global AlertConfig.telegram_bot_token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramBinding {
    pub chat_id: String,
    #[serde(default)]
    pub chat_label: String,
    /// Optional per-agent bot token. Empty/None = inherit the global
    /// AlertConfig.telegram_bot_token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<String>,
}

/// WhatsApp binding via Twilio. The "number" is the user's WhatsApp
/// phone in E.164 format (prefixed with `whatsapp:` per Twilio's
/// convention, e.g. `whatsapp:+14155551234`). WolfStack replies from
/// the Twilio-configured WhatsApp sender — set separately in Twilio
/// config fields, not on the agent.
/// `twilio_sid` + `twilio_auth` are optional per-agent overrides —
/// when both are set WolfStack uses them for the outbound reply
/// (webhook validation still uses the auth token that Twilio signs
/// with, so set the override auth to match your Twilio sub-account).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppBinding {
    pub number: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twilio_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twilio_auth: Option<String>,
}

/// How much authority the agent has over mutating/destructive tools.
/// Paired with the per-tool danger classification in
/// [`tools::Danger`] to decide whether a given call runs freely,
/// needs operator approval, or is refused outright. Defaults to
/// `ReadOnly` so a newly-created agent can never surprise an
/// operator with a write by accident.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AccessLevel {
    /// Safe tools only (list/get/metrics). Any mutating or
    /// destructive tool call is refused before it runs.
    #[default]
    ReadOnly,
    /// Safe + mutating tools run freely. Destructive tools need
    /// operator approval via the confirmation queue.
    ReadWrite,
    /// Every non-safe tool needs operator approval. Use for agents
    /// with a wide tool grant but low trust.
    ConfirmAll,
    /// Godmode — every tool runs without prompting (still within the
    /// per-agent allowlist + target scope + hardcoded safety
    /// denylist, which NO access level can bypass). Use sparingly.
    Trusted,
}


/// Per-agent target scope — where the agent is allowed to look and
/// act. Every mutating tool checks its arguments against this before
/// execution. An empty vec means "no constraint on this axis" so
/// the defaults are safely-wide rather than safely-narrow — pair
/// this with a restrictive `access_level` for a sensible default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetScope {
    /// Cluster names the agent can see or act within (matched against
    /// `Node.cluster_name`). Empty = all clusters.
    #[serde(default)]
    pub allowed_clusters: Vec<String>,
    /// Glob-style patterns (`regions*`, `*-prod`) matched against
    /// container names. Empty = all containers/VMs.
    #[serde(default)]
    pub allowed_container_patterns: Vec<String>,
    /// Specific node IDs the agent can touch via exec_on_node or
    /// direct node-scoped API calls. Empty = all nodes.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Filesystem prefixes for write/delete/exec path arguments —
    /// e.g. `/home/wolfgrid1/assetcache` lets the agent clean that
    /// directory but not touch `/etc` or `/root`. Empty = no path
    /// restriction (still subject to the hardcoded safety denylist).
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// API path regex allowlist for the `wolfstack_api` tool. Each
    /// entry is `"<METHOD>:<regex>"` e.g. `"GET:^/api/nodes$"`.
    /// Empty = all GETs allowed (read-only), POST/PUT/DELETE require
    /// at least one explicit match.
    #[serde(default)]
    pub allowed_api_paths: Vec<String>,
    /// Email recipients the `send_email` tool may address. Each entry
    /// is either a full address (`paul@wolf.uk.com`, exact match) or a
    /// domain match (`@wolf.uk.com`, matches any local-part at that
    /// domain). Empty = the tool uses the AiConfig default `email_to`
    /// only. This keeps a prompt-injected agent from emailing arbitrary
    /// external addresses.
    #[serde(default)]
    pub allowed_email_recipients: Vec<String>,
    /// IDs of SQL connections (from `src/sql_connections`) this agent
    /// may target. Empty = no SQL access. The connection list is
    /// configured globally in Settings → SQL Connections; this
    /// allowlist is how operators give agent X access to DB Y
    /// without also giving it access to DB Z. Combined with the
    /// three per-agent `sql_read` / `sql_update` / `sql_delete`
    /// booleans below, the agent can do exactly what the operator
    /// permits — no more.
    #[serde(default)]
    pub allowed_sql_connections: Vec<String>,
}

/// One named agent. Persisted as an entry in
/// `/etc/wolfstack/agents.json` (a `Vec<Agent>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// Stable ID — short alphanumeric, used in URLs + the chat hook.
    pub id: String,
    /// Display name shown in the UI + at the start of Discord replies.
    pub name: String,
    /// Visual identity — a short string (emoji, or 1–2 chars) that the
    /// UI paints inside the 36×36 gradient tile on the agent card and
    /// next to chat replies. Absent = the default wolf 🐺 so existing
    /// installs look unchanged.
    #[serde(default)]
    pub avatar: Option<String>,
    /// The agent's personality / role. Fed as the `system` prompt on
    /// every turn. Keep it specific — "You are Spitfire, the incident
    /// commander. You answer in one sentence. If asked to do
    /// something, ask a clarifying question first unless the intent
    /// is unambiguous." beats "You are a helpful assistant."
    pub system_prompt: String,
    /// LLM model identifier. Provider-specific (claude-opus-4-7,
    /// gemini-2.5-pro, llama3:70b, etc.).
    pub model: String,
    /// Which provider the model belongs to — `"claude"`, `"gemini"`,
    /// `"openrouter"`, or `"local"`. Mirrors `ai::AiConfig::provider`.
    pub provider: String,
    /// Names of tools (from the registry) this agent is allowed to
    /// invoke. Empty = chat-only, no side effects.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// How much authority the agent has over mutating/destructive
    /// tools. Defaults to ReadOnly so a newly-created agent can never
    /// surprise an operator.
    #[serde(default)]
    pub access_level: AccessLevel,
    /// Per-agent scope — where the agent is allowed to look + act.
    /// Empty scope = no constraint on that axis (rely on access_level
    /// and the hardcoded safety denylist for safety).
    #[serde(default)]
    pub target_scope: TargetScope,
    /// Prepend the WolfStack knowledge base + a live cluster snapshot
    /// to every turn so the agent understands the platform it's
    /// running on. Operators who want to save tokens can disable; by
    /// default we pay the ~4k-token overhead because uninformed
    /// agents waste more tokens flailing through tool calls than the
    /// KB costs.
    #[serde(default = "default_true_fn")]
    pub include_cluster_context: bool,
    /// Max lines of memory (one JSONL line = one role+content pair)
    /// to feed back into the model on each turn. Higher = better
    /// recall, more tokens per call.
    #[serde(default = "default_memory_max_lines")]
    pub memory_max_lines: usize,
    /// Optional Discord channel binding — the Discord receiver (when
    /// enabled) routes messages here.
    #[serde(default)]
    pub discord: Option<DiscordBinding>,
    /// Optional Telegram chat binding — the Telegram receiver routes
    /// messages in this chat (DM or group) to this agent.
    #[serde(default)]
    pub telegram: Option<TelegramBinding>,
    /// Optional WhatsApp binding (via Twilio). Inbound messages from
    /// this number land here; replies go through the Twilio WhatsApp
    /// sender configured in AlertConfig.
    #[serde(default)]
    pub whatsapp: Option<WhatsAppBinding>,
    /// When this agent was created (unix seconds). Used for the UI
    /// "created N days ago" hint.
    #[serde(default)]
    pub created_at: u64,
    /// Last turn's timestamp — surfaced on the agent card so
    /// operators can see who's active vs dormant.
    #[serde(default)]
    pub last_active_at: Option<u64>,
    /// SQL query permissions — granular because "read-only" is a
    /// different risk class from "can delete rows". Each flag gates
    /// the matching agent tool (`sql_read`, `sql_update`,
    /// `sql_delete`); the sqlparser dialect classifier inside
    /// `sql_connections::execute` enforces the same tiering at the
    /// query level so a typo can't slip a DELETE through a
    /// read-only channel. Granting `sql_update` or `sql_delete`
    /// also requires `access_level >= ReadWrite` — we check both.
    #[serde(default)]
    pub sql_read: bool,
    #[serde(default)]
    pub sql_update: bool,
    #[serde(default)]
    pub sql_delete: bool,
}

fn default_memory_max_lines() -> usize { 40 }
fn default_true_fn() -> bool { true }

const AGENTS_FILE: &str = "/etc/wolfstack/agents.json";
const AGENTS_DIR: &str = "/etc/wolfstack/agents";

/// Single lock guarding both `agents.json` reads and writes. Contention
/// is negligible (this isn't a hot path) and it lets us treat the file
/// as single-writer without coordinating via advisory fcntl.
static AGENTS_LOCK: Mutex<()> = Mutex::new(());

/// Load every agent from disk. Returns an empty list if the file
/// doesn't exist yet (first-run state).
pub fn load_all() -> Vec<Agent> {
    let _g = AGENTS_LOCK.lock().unwrap();
    std::fs::read_to_string(AGENTS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Look up one agent by id. Returns None if no match — caller
/// renders that as 404.
pub fn load(id: &str) -> Option<Agent> {
    load_all().into_iter().find(|a| a.id == id)
}

/// Persist the full agents list. Creates `/etc/wolfstack/agents.json`
/// via a temp-file-then-rename dance so a crash mid-write can't leave
/// a half-written file that refuses to parse on next boot. Sets
/// mode 0o600 on the file since it can contain sensitive system
/// prompts that reveal operational detail about the cluster (which
/// alerts matter, which hosts run what, etc.) — /etc/wolfstack as a
/// whole is 755 so without this the file would be world-readable.
pub fn save_all(agents: &[Agent]) -> Result<(), String> {
    let _g = AGENTS_LOCK.lock().unwrap();
    if let Some(parent) = Path::new(AGENTS_FILE).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create config dir: {}", e))?;
    }
    let json = serde_json::to_string_pretty(agents)
        .map_err(|e| format!("serialize: {}", e))?;
    let tmp = format!("{}.tmp", AGENTS_FILE);
    std::fs::write(&tmp, json).map_err(|e| format!("write tmp: {}", e))?;
    tighten_perms(&tmp, 0o600);
    std::fs::rename(&tmp, AGENTS_FILE)
        .map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

/// Apply restrictive unix perms to a file. No-op on non-unix (which
/// doesn't apply for WolfStack but the cfg gate keeps cargo check
/// happy on weird cross-compile targets).
#[cfg(unix)]
fn tighten_perms(path: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn tighten_perms(_path: &str, _mode: u32) {}

/// Same idea for a directory — restrict to owner rwx.
#[cfg(unix)]
fn tighten_dir_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn tighten_dir_perms(_path: &Path) {}

/// One-shot migration for agents created before v18.6.1, when the
/// default for new agents was an empty `allowed_tools` list. The
/// expected UX changed to "tick all tools on by default; operator
/// unchecks what they don't want", so pre-existing agents silently
/// ran tool-less and refused every tool call — which looked to users
/// like the AI was lying about sending emails. This rewrites any
/// assignment whose `allowed_tools` is empty to the full registry.
///
/// Safe to re-run: idempotent (no-op once every agent has a populated
/// list). Runs once at `main.rs` startup, before the API starts
/// accepting requests.
pub fn migrate_empty_allowed_tools() -> bool {
    let mut agents = load_all();
    let mut changed = 0usize;
    let all_tools: Vec<String> = tools::ToolId::ALL.iter()
        .map(|t| t.as_str().to_string()).collect();
    for a in agents.iter_mut() {
        if a.allowed_tools.is_empty() {
            a.allowed_tools = all_tools.clone();
            changed += 1;
        }
    }
    if changed > 0 {
        if let Err(e) = save_all(&agents) {
            tracing::warn!("wolfagents: failed to save tool migration: {}", e);
            return false;
        }
        tracing::info!(
            "wolfagents: migrated {} agents from empty allowed_tools to full catalogue",
            changed);
        true
    } else {
        false
    }
}

/// Insert or update one agent (matched by id). Convenience wrapper
/// over load_all+save_all so the API handlers stay readable.
pub fn upsert(agent: Agent) -> Result<(), String> {
    let mut agents = load_all();
    if let Some(idx) = agents.iter().position(|a| a.id == agent.id) {
        agents[idx] = agent;
    } else {
        agents.push(agent);
    }
    save_all(&agents)
}

/// Remove an agent by id. Also removes the memory + audit directory
/// so the agent's identifier can be reused cleanly if the operator
/// wants to.
pub fn delete(id: &str) -> Result<(), String> {
    let mut agents = load_all();
    let before = agents.len();
    agents.retain(|a| a.id != id);
    if agents.len() == before {
        return Err(format!("agent '{}' not found", id));
    }
    save_all(&agents)?;
    // Memory directory. Failure here is non-fatal — the agent is
    // already gone from the registry so it won't show up in the UI.
    let mem_dir = agent_dir(id);
    if mem_dir.exists() {
        let _ = std::fs::remove_dir_all(&mem_dir);
    }
    Ok(())
}

/// Compute the on-disk directory for an agent's memory + audit log.
fn agent_dir(id: &str) -> PathBuf {
    PathBuf::from(AGENTS_DIR).join(id)
}

fn memory_path(id: &str) -> PathBuf {
    agent_dir(id).join("memory.jsonl")
}

/// A single persisted turn. Mirrors `ai::ChatMessage` but also carries
/// a timestamp so we can render "2h ago" in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub role: String,       // "user" | "assistant"
    pub content: String,
    pub ts: u64,            // unix seconds
}

/// Append one entry to the agent's JSONL memory file. Creates the
/// parent directory on first use. Failures are surfaced to the caller
/// so a transient disk issue shows up as a chat error rather than
/// silent context loss.
fn append_memory(id: &str, entry: &MemoryEntry) -> Result<(), String> {
    let dir = agent_dir(id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create agent dir: {}", e))?;
    // 0o700 the dir so its contents aren't world-readable — chat
    // history can include operational detail (which hosts are slow,
    // which secrets an AI was asked about) that shouldn't leak to
    // other local users. /etc/wolfstack itself is 755 by default so
    // without this we inherit world-readable perms.
    tighten_dir_perms(&dir);
    let path = memory_path(id);
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open memory file: {}", e))?;
    let line = serde_json::to_string(entry)
        .map_err(|e| format!("serialize entry: {}", e))?;
    writeln!(f, "{}", line).map_err(|e| format!("append memory: {}", e))?;
    // Tighten perms on every write (idempotent) so rotation or
    // externally-touched files don't drift back to world-readable.
    tighten_perms(path.to_string_lossy().as_ref(), 0o600);
    Ok(())
}

/// Read the last `max_lines` entries from the agent's memory file.
/// The file grows forever (it IS the audit log) so we stream + keep a
/// rolling buffer rather than parsing the whole thing into memory.
pub fn load_recent_memory(id: &str, max_lines: usize) -> Vec<MemoryEntry> {
    let path = memory_path(id);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    // Simple tail-N — file is JSONL so line-based is fine. Memory for
    // tens of MB logs is acceptable; if it ever gets huge we can
    // switch to seek-from-end.
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].iter()
        .filter_map(|l| serde_json::from_str::<MemoryEntry>(l).ok())
        .collect()
}

/// Send a message to the agent and return the assistant's reply.
/// Appends both the user message and the reply to the agent's memory
/// log. Also bumps `last_active_at` on the agent record so the UI can
/// show activity.
///
/// For Phase 2 this is text-only — no tool use yet (that's Phase 4).
/// Good enough to prove the agent surface works end-to-end: you can
/// create an agent, chat to it over HTTP, and the conversation
/// persists across restarts.
/// Per-agent rate limiting — stops a rogue authenticated user (or a
/// runaway Discord-routed spam) from burning unbounded AI tokens.
/// Token-bucket shape: `CHAT_BUDGET_PER_MIN` refills every 60s.
/// Values are picked conservatively; operators who want looser limits
/// can edit the const and rebuild. A DoS via this endpoint is at
/// worst "some chats get rejected for 60s" — no resource exhaustion.
const CHAT_BUDGET_PER_MIN: u32 = 20;
static CHAT_BUDGETS: Mutex<Option<std::collections::HashMap<String, (std::time::Instant, u32)>>>
    = Mutex::new(None);

fn consume_chat_budget(agent_id: &str) -> Result<(), String> {
    let mut guard = CHAT_BUDGETS.lock().unwrap();
    if guard.is_none() { *guard = Some(std::collections::HashMap::new()); }
    let map = guard.as_mut().unwrap();
    let now = std::time::Instant::now();
    let entry = map.entry(agent_id.to_string())
        .or_insert_with(|| (now, CHAT_BUDGET_PER_MIN));
    // Refill if the one-minute window has elapsed.
    if now.duration_since(entry.0).as_secs() >= 60 {
        *entry = (now, CHAT_BUDGET_PER_MIN);
    }
    if entry.1 == 0 {
        let wait = 60u64.saturating_sub(now.duration_since(entry.0).as_secs());
        return Err(format!(
            "agent rate limit reached — try again in {}s (limit: {} chats/min)",
            wait, CHAT_BUDGET_PER_MIN));
    }
    entry.1 -= 1;
    Ok(())
}

/// Chat with an agent by id. Dispatches to either the full Claude
/// tool_use loop (when the agent is on Claude + has tools allowlisted)
/// or a plain single-shot chat (every other path). Memory + audit +
/// rate-limiting happen around either shape identically.
///
/// Takes an explicit `AppState` because the tool dispatcher needs
/// cluster state, router state, and the cluster secret. Legacy
/// callers that don't have AppState handy can use
/// `chat_with_agent_simple` which falls back to no-tools mode.
/// Which surface the chat turn originated from. Lets the mirror skip
/// the originating surface — otherwise Telegram-initiated turns would
/// loop back to Telegram (dashboard mirror echoes the user's question
/// and the reply, Telegram user then sees both the natural reply AND
/// the mirrored pair) and make the chat unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatSurface {
    Dashboard,
    Telegram,
    Discord,
    WhatsApp,
}

pub async fn chat_with_agent_full(
    agent_id: &str,
    message: &str,
    state: &crate::api::AppState,
    surface: ChatSurface,
) -> Result<String, String> {
    // Check agent exists BEFORE consuming the rate-limit budget.
    // Otherwise an attacker probing random IDs would populate the
    // bucket map indefinitely.
    let mut agent = load(agent_id)
        .ok_or_else(|| format!("agent '{}' not found", agent_id))?;
    if message.len() > 64 * 1024 {
        return Err("message exceeds 64 KB — split into smaller prompts".to_string());
    }
    consume_chat_budget(agent_id)?;

    let recent = load_recent_memory(agent_id, agent.memory_max_lines);
    let history: Vec<crate::ai::ChatMessage> = recent.into_iter()
        .map(|m| crate::ai::ChatMessage {
            role: m.role,
            content: m.content,
            timestamp: (m.ts as i64).saturating_mul(1000),
        })
        .collect();

    // Run the full tool_use loop. For Claude + tools this kicks off
    // a multi-round dispatch; for every other provider it falls back
    // to plain simple_chat inside the loop.
    let turn = agent_loop::run_turn(&agent, history, message, state).await?;
    let reply = turn.response.clone();

    // Persist exchange.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Err(e) = append_memory(agent_id, &MemoryEntry {
        role: "user".to_string(),
        content: message.to_string(),
        ts: now,
    }) {
        tracing::warn!("wolfagents: failed to append user turn: {}", e);
    }
    if let Err(e) = append_memory(agent_id, &MemoryEntry {
        role: "assistant".to_string(),
        content: reply.clone(),
        ts: now,
    }) {
        tracing::warn!("wolfagents: failed to append assistant turn: {}", e);
    }

    agent.last_active_at = Some(now);
    if let Err(e) = upsert(agent.clone()) {
        tracing::warn!("wolfagents: failed to bump last_active_at: {}", e);
    }

    // Mirror the exchange to any bound external chat surface EXCEPT
    // the one this turn came from. Dashboard turns go to every bound
    // surface; Telegram turns mirror to Discord (but not back to
    // Telegram — the natural reply already landed there), etc. This
    // enables cross-surface bridging while preventing the duplicate-
    // post feedback loop we had in v18.7.8.
    mirror_exchange_to_surfaces(&agent, message, &reply, surface);

    Ok(reply)
}

/// Post the user question + assistant reply to every external chat
/// surface the agent is bound to. Fire-and-forget — failures are
/// logged but don't propagate to the dashboard caller. Bot-authored
/// messages are filtered by `from.is_bot` in the receivers, so
/// mirroring our own posts back can't produce a reply loop.
fn mirror_exchange_to_surfaces(agent: &Agent, user_msg: &str, reply: &str, origin: ChatSurface) {
    // Telegram — skip if the turn originated from Telegram so we don't
    // echo the natural reply back into the same chat.
    if origin == ChatSurface::Telegram { /* skip */ }
    else if let Some(tg) = agent.telegram.clone() {
        let bot_token = resolved_telegram_token(&tg);
        let user_msg = user_msg.to_string();
        let reply = reply.to_string();
        let agent_id = agent.id.clone();
        tokio::spawn(async move {
            if bot_token.trim().is_empty() { return; }
            let Ok(chat_id) = tg.chat_id.parse::<i64>() else {
                tracing::warn!("wolfagents mirror: bad telegram chat_id on agent {}", agent_id);
                return;
            };
            // Reuse the telegram_bot module's shared pool instead of
            // building a new Client per mirror. Cheap Arc clone.
            let http = reqwest::Client::clone(&crate::telegram_bot::TELEGRAM_CLIENT);
            let q = format!("👤 {}", truncate_for_chat(&user_msg, 3500));
            let a = truncate_for_chat(&reply, 3900);
            if let Err(e) = crate::telegram_bot::send_telegram_message(
                &http, &bot_token, chat_id, &q).await
            {
                tracing::warn!("wolfagents mirror (telegram): {}", e);
            }
            if let Err(e) = crate::telegram_bot::send_telegram_message(
                &http, &bot_token, chat_id, &a).await
            {
                tracing::warn!("wolfagents mirror (telegram): {}", e);
            }
        });
    }
    // Discord — skip if the turn came from Discord.
    if origin == ChatSurface::Discord { /* skip */ }
    else if let Some(d) = agent.discord.clone() {
        let bot_token = resolved_discord_token(&d);
        let user_msg = user_msg.to_string();
        let reply = reply.to_string();
        let agent_id = agent.id.clone();
        tokio::spawn(async move {
            if bot_token.trim().is_empty() { return; }
            // Reuse discord_bot's shared pool. Cheap Arc clone.
            let http = reqwest::Client::clone(&crate::discord_bot::DISCORD_CLIENT);
            let q = format!("👤 {}", truncate_for_chat(&user_msg, 1900));
            let a = truncate_for_chat(&reply, 1900);
            if let Err(e) = crate::discord_bot::send_discord_message(
                &http, &bot_token, &d.channel_id, &q).await
            {
                tracing::warn!("wolfagents mirror (discord) for {}: {}", agent_id, e);
            }
            if let Err(e) = crate::discord_bot::send_discord_message(
                &http, &bot_token, &d.channel_id, &a).await
            {
                tracing::warn!("wolfagents mirror (discord) for {}: {}", agent_id, e);
            }
        });
    }
    // WhatsApp — not mirrored. Twilio's WhatsApp API only allows
    // outbound messages within a 24-hour window following an inbound
    // message from the same user, and we don't track the last-inbound
    // number per agent. Dashboard replies therefore stay on the
    // dashboard; the agent still replies to WhatsApp-initiated
    // conversations via the TwiML webhook path.
}

fn resolved_telegram_token(tg: &TelegramBinding) -> String {
    if let Some(t) = &tg.bot_token {
        let t = t.trim();
        if !t.is_empty() { return t.to_string(); }
    }
    crate::alerting::AlertConfig::load().telegram_bot_token
}

fn resolved_discord_token(d: &DiscordBinding) -> String {
    if let Some(t) = &d.bot_token {
        let t = t.trim();
        if !t.is_empty() { return t.to_string(); }
    }
    crate::alerting::AlertConfig::load().discord_bot_token
}

fn truncate_for_chat(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let mut out: String = s.chars().take(max).collect();
    out.push_str("\n…(truncated)");
    out
}

/// Legacy no-AppState entry point for callers that only need basic
/// chat (Discord / Telegram / WhatsApp receivers, which don't have
/// AppState in their handler scope). Falls back to simple_chat so
/// tool access is unavailable — we ship this knowingly because the
/// chat surfaces are lower-risk than the dashboard.
pub async fn chat_with_agent(agent_id: &str, message: &str) -> Result<String, String> {
    let mut agent = load(agent_id)
        .ok_or_else(|| format!("agent '{}' not found", agent_id))?;
    if message.len() > 64 * 1024 {
        return Err("message exceeds 64 KB — split into smaller prompts".to_string());
    }
    consume_chat_budget(agent_id)?;

    let recent = load_recent_memory(agent_id, agent.memory_max_lines);
    let history: Vec<crate::ai::ChatMessage> = recent.into_iter()
        .map(|m| crate::ai::ChatMessage {
            role: m.role,
            content: m.content,
            timestamp: (m.ts as i64).saturating_mul(1000),
        })
        .collect();
    let mut cfg = crate::ai::AiConfig::load();
    if !agent.provider.is_empty() { cfg.provider = agent.provider.clone(); }
    if !agent.model.is_empty() { cfg.model = agent.model.clone(); }

    let reply = crate::ai::simple_chat(&cfg, &agent.system_prompt, &history, message).await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Err(e) = append_memory(agent_id, &MemoryEntry {
        role: "user".to_string(),
        content: message.to_string(),
        ts: now,
    }) {
        tracing::warn!("wolfagents: failed to append user turn: {}", e);
    }
    if let Err(e) = append_memory(agent_id, &MemoryEntry {
        role: "assistant".to_string(),
        content: reply.clone(),
        ts: now,
    }) {
        tracing::warn!("wolfagents: failed to append assistant turn: {}", e);
    }

    agent.last_active_at = Some(now);
    if let Err(e) = upsert(agent) {
        tracing::warn!("wolfagents: failed to bump last_active_at: {}", e);
    }

    Ok(reply)
}

/// Generate a short, stable id for a new agent. Used when the UI
/// doesn't supply one on create. Random enough for small-scale use;
/// collisions are checked by upsert via name-based matching wouldn't
/// help here since names aren't unique.
pub fn generate_id() -> String {
    use std::time::SystemTime;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let hex = format!("{:x}", n);
    let len = hex.len();
    let tail = if len > 10 { &hex[len - 10..] } else { &hex };
    format!("agent-{}", tail)
}

/// Fresh-new agent with sensible defaults. Used by the create API so
/// the UI can show "create" as a one-click + name action, with full
/// customisation in the edit view afterwards.
pub fn new_default(name: String) -> Agent {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cfg = crate::ai::AiConfig::load();
    Agent {
        id: generate_id(),
        name,
        // Avatar unset — the frontend picks a built-in wolf deterministically
        // from the agent id until the operator overrides it.
        avatar: None,
        system_prompt: "You are a helpful operations assistant running inside WolfStack. \
                        Answer concisely. When you're unsure, say so rather than guessing."
            .to_string(),
        model: cfg.model,
        provider: cfg.provider,
        allowed_tools: Vec::new(),
        access_level: AccessLevel::ReadOnly,
        target_scope: TargetScope::default(),
        include_cluster_context: true,
        memory_max_lines: default_memory_max_lines(),
        discord: None,
        telegram: None,
        whatsapp: None,
        created_at: now,
        last_active_at: None,
        // SQL permissions default off; operator explicitly opts in via
        // the Edit Agent dialog once they've also picked which
        // connections the agent can touch.
        sql_read: false,
        sql_update: false,
        sql_delete: false,
    }
}
