// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WhatsApp receiver via Twilio. Twilio's WhatsApp API uses webhooks
//! — they POST `application/x-www-form-urlencoded` to a URL we
//! expose, and we reply via their REST API.
//!
//! This module provides two pieces the API layer wires together:
//!
//! 1. `validate_twilio_signature(auth_token, url, params_iter, header)`
//!    — HMAC-SHA1 validator for the `X-Twilio-Signature` header. The
//!    webhook endpoint MUST call this before doing anything with the
//!    request; without it the webhook is a public "chat to any agent
//!    as the attacker's chosen phone number" endpoint.
//!
//! 2. `handle_inbound(from, body) -> Option<String>` — given the
//!    sender and body, resolve to an agent, run the chat turn, return
//!    the reply text (or None if no agent bound). Called from the
//!    actix handler.
//!
//! 3. `send_reply(http, to, text)` — push a reply back to Twilio so
//!    they deliver it to the WhatsApp user.
//!
//! **Why Twilio specifically:** the official WhatsApp Business API
//! goes through Meta-approved providers (Twilio, 360dialog, etc.).
//! Twilio has the cleanest Rust-friendly shape (plain HTTP + webhook
//! with a well-documented HMAC) and a free sandbox so operators can
//! try it without commercial onboarding. Unofficial "whatsapp-web"
//! libraries are deliberately not used — they violate Meta's ToS,
//! risk banning the phone number, and break every few months.

use sha1::Sha1;
use hmac::{Hmac, Mac};
use tracing::warn;

type HmacSha1 = Hmac<Sha1>;

/// Validate a Twilio webhook signature per
/// <https://www.twilio.com/docs/usage/webhooks/webhooks-security>.
///
/// The algorithm:
/// 1. Start with the full URL (including query string) Twilio posted to.
/// 2. Sort POST params by key, concatenate `keyvalue` for each one.
/// 3. HMAC-SHA1 the url+params with the account's auth token.
/// 4. Base64-encode.
/// 5. Compare (constant-time) to the `X-Twilio-Signature` header.
///
/// Params come in as a slice of (String, String) so the caller can
/// pass the parsed form body directly.
pub fn validate_twilio_signature(
    auth_token: &str,
    webhook_url: &str,
    params: &[(String, String)],
    signature_header: &str,
) -> bool {
    if auth_token.is_empty() {
        warn!("whatsapp_bot: refusing signature check with empty auth token");
        return false;
    }
    let mut sorted: Vec<&(String, String)> = params.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut signed = String::with_capacity(webhook_url.len() + 64);
    signed.push_str(webhook_url);
    for (k, v) in sorted {
        signed.push_str(k);
        signed.push_str(v);
    }
    let mut mac = match HmacSha1::new_from_slice(auth_token.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signed.as_bytes());
    let expected = base64_encode(&mac.finalize().into_bytes());
    // Constant-time compare — subtle-crypto style. For HMAC-SHA1
    // (20 bytes → 28-char base64) the time cost is trivial; the
    // important bit is not short-circuiting on first mismatch.
    constant_time_eq(expected.as_bytes(), signature_header.as_bytes())
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Resolve an inbound WhatsApp message to an agent reply. Returns
/// None when no agent is bound to the sender number — the webhook
/// responds with empty TwiML in that case so Twilio doesn't retry.
pub async fn handle_inbound(
    from: &str,
    body: &str,
    state: &crate::api::AppState,
) -> Option<String> {
    let body = body.trim();
    if body.is_empty() { return None; }
    // Find the agent bound to this phone number. Binding stores the
    // `whatsapp:+E164` form which matches what Twilio sends as `From`.
    let agents = crate::wolfagents::load_all();
    let agent = agents.iter().find(|a|
        a.whatsapp.as_ref().map(|w| w.number.as_str()) == Some(from)
    )?.clone();
    // Full tool-use loop so WhatsApp-originated chats can actually act
    // on cluster state rather than falling back to tool-less
    // simple_chat (which was triggering UNEXPECTED_TOOL_CALL with
    // Gemini when the system prompt advertised tools).
    let reply = match crate::wolfagents::chat_with_agent_full(
        &agent.id, body, state,
        crate::wolfagents::ChatSurface::WhatsApp,
    ).await {
        Ok(r) => r,
        Err(e) => format!("(agent error) {}", e),
    };
    // WhatsApp messages cap at 4096 chars in TwiML replies; give a
    // comfortable margin and a suffix so recipients see clipping
    // happened.
    let out = if reply.len() > 3800 {
        format!("{}\n…(truncated)", &reply[..3800])
    } else {
        reply
    };
    Some(out)
}

/// Post a reply back to a WhatsApp user via Twilio's REST API.
/// Returns Err on any non-2xx response (caller logs). Used when the
/// webhook-reply path isn't enough — e.g. an async agent response
/// that takes longer than Twilio's webhook timeout.
///
/// The webhook itself can reply synchronously via TwiML in the
/// response body (see `api::whatsapp_webhook`); this function is for
/// future "agent sends unprompted message" flows (operator-triggered
/// "summarise status daily", scheduled alerts to specific users, etc.)
/// where we need to push rather than reply.
#[allow(dead_code)]
pub async fn send_reply(
    http: &reqwest::Client,
    account_sid: &str,
    auth_token: &str,
    from: &str,
    to: &str,
    text: &str,
) -> Result<(), String> {
    if account_sid.is_empty() || auth_token.is_empty() || from.is_empty() {
        return Err("Twilio credentials not fully configured".to_string());
    }
    let url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        account_sid
    );
    let form = [
        ("From", from),
        ("To", to),
        ("Body", text),
    ];
    let resp = http.post(&url)
        .basic_auth(account_sid, Some(auth_token))
        .form(&form)
        .send().await
        .map_err(|e| format!("http: {}", e))?;
    let status = resp.status();
    // `.text()` drains regardless of status — socket returns to pool.
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "Twilio API {}: {}",
            status.as_u16(),
            body.chars().take(200).collect::<String>()
        ));
    }
    Ok(())
}

/// TwiML response builder — dead-simple XML. We only ever send a
/// single `<Message>` so there's no need for a full XML serializer;
/// manually escaping the reply body keeps the dependency surface
/// minimal.
pub fn twiml_reply(text: &str) -> String {
    let escaped = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Response><Message>{}</Message></Response>",
        escaped
    )
}

/// TwiML "no reply" response — used when no agent is bound to the
/// sender. Twilio accepts an empty `<Response/>` and doesn't retry,
/// which is what we want; silently dropping the HTTP request would
/// trigger Twilio's retry policy.
pub fn twiml_empty() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response/>".to_string()
}
