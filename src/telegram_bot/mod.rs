// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Telegram receiver — long-polls the Bot API for messages in chats
//! bound to WolfAgents and replies with the agent's response.
//!
//! Much simpler than the Discord gateway: Telegram exposes HTTP
//! long-polling (`getUpdates`) so we just issue one outstanding GET
//! per tick, handle whatever comes back, and use `offset` to
//! acknowledge. No gateway, no heartbeat, no session resume.
//!
//! Security posture:
//!
//! * **Bot token** lives in `AlertConfig.telegram_bot_token` — same
//!   field already used for outbound alerts. The receiver will only
//!   run when the operator toggles it on (separate flag so users who
//!   only want outbound alerts don't get surprised inbound flows).
//! * **Abuse guard**: same `chat_with_agent` rate limit as Discord.
//! * **Authorisation model**: chat binding on the agent. Only
//!   messages in the bound chat_id route to the agent. Telegram DMs
//!   and groups both work — the chat_id identifies either.
//! * **Bot reply loop**: we skip messages where `from.is_bot` is
//!   true, same as Discord.

use actix_web::web;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Shared HTTP client across every Telegram bot polling task. Each
/// bot was building its own per-task Client; a shared pool means we
/// keep one connection pool total (per operator typically runs 1–3
/// bots). Timeout is set per request — getUpdates uses 65s (long-poll
/// deadline + slack), send_message uses the default 30s.
pub(crate) static TELEGRAM_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

type AppData = web::Data<crate::api::AppState>;

/// Minimal shape of a Telegram `Message`. Only fields we route on.
#[derive(Debug, Clone, Deserialize)]
struct TgMessage {
    message_id: i64,
    #[serde(default)]
    text: Option<String>,
    chat: TgChat,
    from: Option<TgUser>,
}

#[derive(Debug, Clone, Deserialize)]
struct TgChat {
    id: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct TgUser {
    #[serde(default)]
    is_bot: bool,
}

/// `getUpdates` response envelope.
#[derive(Debug, Deserialize)]
struct TgUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<TgUpdate>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgUpdate {
    update_id: i64,
    /// Direct message (DM with the bot, group chat where the bot is a
    /// member). Present for chats of type `private`, `group`,
    /// `supergroup`.
    #[serde(default)]
    message: Option<TgMessage>,
    /// Channel post (the bot has been added as admin of a broadcast
    /// channel). Telegram delivers this as `channel_post`, NOT
    /// `message` — that's why a bot silently ignores channel traffic
    /// when the code only looks at `message`. Same payload shape,
    /// so we reuse TgMessage.
    #[serde(default)]
    channel_post: Option<TgMessage>,
}

/// Payload sent to `sendMessage`. We only use `chat_id` + `text` — no
/// formatting, no reply markup. Keeps rendering surprises minimal.
#[derive(Debug, Serialize)]
struct TgSendMessage<'a> {
    chat_id: i64,
    text: &'a str,
}

/// One long-polling cycle: issue a `getUpdates` with a 50-second
/// timeout, dispatch any received messages, advance `offset` past
/// the last update, return the new offset.
async fn poll_once(
    http: &reqwest::Client,
    bot_token: &str,
    offset: i64,
    state: &AppData,
) -> Result<i64, String> {
    let url = format!(
        "https://api.telegram.org/bot{}/getUpdates?timeout=50&offset={}",
        bot_token, offset
    );
    let resp = http.get(&url)
        .timeout(Duration::from_secs(65))
        .send().await
        .map_err(|e| format!("http: {}", e))?;
    let status = resp.status();
    let body: TgUpdatesResponse = resp.json().await
        .map_err(|e| format!("decode: {}", e))?;
    if !status.is_success() || !body.ok {
        return Err(format!(
            "Telegram API {}: {}",
            status.as_u16(),
            body.description.unwrap_or_default()
        ));
    }
    let mut next_offset = offset;
    for upd in body.result {
        // Always advance past this update so retries don't replay it,
        // even if we decide not to process it.
        next_offset = next_offset.max(upd.update_id + 1);
        // Accept message (DM / group) or channel_post (broadcast
        // channel). The payload shape is identical, so we normalise
        // to a single variable and route downstream the same way.
        let Some(msg) = upd.message.or(upd.channel_post) else { continue; };
        let Some(text) = msg.text.clone() else { continue; };
        if let Some(from) = &msg.from {
            // Bot's own posts (including our own mirrors) carry
            // from.is_bot = true. Skipping them stops reply loops.
            if from.is_bot { continue; }
        }
        let chat_id = msg.chat.id;
        // Route to the agent bound to this chat AND this bot. Two agents
        // may share a chat_id string on different bots, so we must match
        // on both — otherwise bot X would reply for agent B that's
        // actually on bot Y.
        let global_token = crate::alerting::AlertConfig::load().telegram_bot_token;
        let agents = crate::wolfagents::load_all();
        let Some(agent) = agents.iter().find(|a| {
            let Some(tg) = &a.telegram else { return false; };
            if tg.chat_id != chat_id.to_string() { return false; }
            let agent_token = tg.bot_token.as_deref()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or(global_token.as_str());
            agent_token == bot_token
        }).cloned() else { continue; };
        let http_reply = http.clone();
        let token = bot_token.to_string();
        let content = text;
        let s = state.clone();
        tokio::spawn(async move {
            handle_telegram_chat(http_reply, &token, &agent, chat_id, content, msg.message_id, s).await;
        });
    }
    Ok(next_offset)
}

/// Run one agent turn for a Telegram message and post the reply back
/// to the same chat. Truncates over-long replies at 4000 chars
/// (Telegram's 4096 cap with a safety margin + a suffix so the user
/// knows it was clipped).
async fn handle_telegram_chat(
    http: reqwest::Client,
    bot_token: &str,
    agent: &crate::wolfagents::Agent,
    chat_id: i64,
    content: String,
    _source_msg_id: i64,
    state: AppData,
) {
    let content = content.trim();
    if content.is_empty() { return; }
    // Route through the full tool-use loop — the surface-initiated
    // chat was previously falling back to simple_chat, which meant
    // Telegram-originated turns couldn't call tools. Gemini in
    // particular rejected that shape with UNEXPECTED_TOOL_CALL when
    // the system prompt advertised tools that weren't registered.
    // Now every turn gets the same dispatcher the dashboard uses.
    let reply = match crate::wolfagents::chat_with_agent_full(
        &agent.id, content, state.get_ref(),
        crate::wolfagents::ChatSurface::Telegram,
    ).await {
        Ok(r) => r,
        Err(e) => format!("(agent error) {}", e),
    };
    // Telegram caps at 4096 chars per message; chunk instead of
    // truncating so long agent outputs (log tails, diagnostic dumps)
    // arrive intact. Paragraph-aware so markdown and code blocks
    // survive the split.
    for chunk in chunk_for_telegram(&reply) {
        if let Err(e) = send_telegram_message(&http, bot_token, chat_id, &chunk).await {
            warn!("telegram_bot: reply failed for agent {} chat {}: {}",
                agent.id, chat_id, e);
            break;
        }
    }
}

/// Split `text` into Telegram-sized chunks (&lt;= 4000 chars each, a
/// safety margin under the 4096 hard cap for variable-width chars).
/// Same strategy as the Discord chunker: prefer paragraph boundaries,
/// fall back to lines, then raw char-boundary cuts. Always returns at
/// least one element.
fn chunk_for_telegram(text: &str) -> Vec<String> {
    const LIMIT: usize = 4000;
    if text.is_empty() { return vec![String::new()]; }
    if text.chars().count() <= LIMIT { return vec![text.to_string()]; }
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for para in text.split("\n\n") {
        let needed = para.chars().count() + if current.is_empty() { 0 } else { 2 };
        if !current.is_empty() && current.chars().count() + needed > LIMIT {
            out.push(std::mem::take(&mut current));
        }
        if para.chars().count() <= LIMIT {
            if !current.is_empty() { current.push_str("\n\n"); }
            current.push_str(para);
            continue;
        }
        if !current.is_empty() { out.push(std::mem::take(&mut current)); }
        for line in para.split('\n') {
            if current.chars().count() + line.chars().count() + 1 > LIMIT && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            if line.chars().count() <= LIMIT {
                if !current.is_empty() { current.push('\n'); }
                current.push_str(line);
                continue;
            }
            let mut remaining = line;
            while remaining.chars().count() > LIMIT {
                let cut = remaining.char_indices().nth(LIMIT).map(|(i, _)| i).unwrap_or(remaining.len());
                if !current.is_empty() { out.push(std::mem::take(&mut current)); }
                out.push(remaining[..cut].to_string());
                remaining = &remaining[cut..];
            }
            if !remaining.is_empty() {
                if !current.is_empty() { current.push('\n'); }
                current.push_str(remaining);
            }
        }
    }
    if !current.is_empty() { out.push(current); }
    if out.is_empty() { out.push(String::new()); }
    out
}

pub async fn send_telegram_message(
    http: &reqwest::Client,
    bot_token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let payload = TgSendMessage { chat_id, text };
    let resp = http.post(&url)
        .json(&payload)
        .send().await
        .map_err(|e| format!("http: {}", e))?;
    let status = resp.status();
    // `.text()` drains the body regardless of status, so the
    // connection returns to the pool cleanly in both arms.
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Telegram API {}: {}", status.as_u16(), body.chars().take(200).collect::<String>()));
    }
    Ok(())
}

/// Supervisor: reconciles the set of bot tokens WolfStack needs to
/// long-poll. Every 30 seconds it asks (a) AlertConfig for the global
/// fallback token and the receiver-enabled flag, and (b) agents.json
/// for every per-agent `telegram.bot_token` override. For each unique
/// token it keeps one polling task running; tokens that disappear from
/// the desired set get their tasks aborted. This lets operators pair
/// each agent with its own @BotFather bot — one agent → one bot →
/// one @-mention in any chat that bot is added to.
pub async fn supervise_forever(state: AppData) {
    tokio::time::sleep(Duration::from_secs(30)).await;
    use std::collections::HashMap;
    use tokio::task::JoinHandle;
    let mut running: HashMap<String, JoinHandle<()>> = HashMap::new();
    loop {
        let desired = desired_token_set();
        // Spawn tasks for newly-desired tokens.
        for token in &desired {
            if !running.contains_key(token) {
                let tok = token.clone();
                let s = state.clone();
                info!("telegram_bot: starting long-poll task for bot ending …{}", tok_tail(&tok));
                let handle = tokio::spawn(async move { long_poll_forever(tok, s).await; });
                running.insert(token.clone(), handle);
            }
        }
        // Abort tasks whose tokens are no longer in the desired set.
        let stale: Vec<String> = running.keys()
            .filter(|k| !desired.contains(*k))
            .cloned().collect();
        for token in stale {
            if let Some(h) = running.remove(&token) {
                info!("telegram_bot: stopping long-poll task for bot ending …{}", tok_tail(&token));
                h.abort();
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// Compute the set of bot tokens that should have an active long-poll
/// right now. Global token counts only when the receiver flag is on;
/// per-agent override tokens always count because the agent wouldn't
/// have set one if they didn't want it running.
fn desired_token_set() -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let cfg = crate::alerting::AlertConfig::load();
    if cfg.telegram_receiver_enabled && !cfg.telegram_bot_token.trim().is_empty() {
        out.insert(cfg.telegram_bot_token.clone());
    }
    for agent in crate::wolfagents::load_all() {
        if let Some(tg) = &agent.telegram
            && let Some(t) = &tg.bot_token {
                let t = t.trim();
                if !t.is_empty() { out.insert(t.to_string()); }
            }
    }
    out
}

/// Last 6 chars of a bot token — enough to distinguish in logs without
/// leaking the full credential.
fn tok_tail(t: &str) -> String {
    t.chars().rev().take(6).collect::<String>().chars().rev().collect()
}

/// Per-token polling loop — runs until aborted by the supervisor.
/// Each bot keeps its own `offset` so Telegram's ack semantics are
/// correct per-bot (offsets are scoped to the bot that issued them).
async fn long_poll_forever(bot_token: String, state: AppData) {
    // Shared pool — see TELEGRAM_CLIENT. Every bot task reuses it.
    let http = &*TELEGRAM_CLIENT;
    let mut offset: i64 = 0;
    loop {
        match poll_once(http, &bot_token, offset, &state).await {
            Ok(next) => { offset = next; }
            Err(e) => {
                warn!("telegram_bot (bot …{}): poll error — {}", tok_tail(&bot_token), e);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}
