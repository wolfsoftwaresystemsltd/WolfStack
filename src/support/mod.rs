// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Support tickets — thin proxy from this node to the WolfStack support ticket
//! API on wolfstack.org. The node authenticates itself with its licence key
//! (when licensed) and/or its declared GitHub sponsor login; the server is
//! authoritative for entitlement. Mirrors the daily licence-heartbeat pattern
//! in `compat::report_license_heartbeat` (read the licence key off disk, POST
//! over a shared ipv4-only client to wolfstack.org).

use serde_json::{Map, Value};

const TICKET_API_URL: &str = "https://wolfstack.org/adminsys/ticket-api.php";

/// Shared client — wolfstack.org has a valid public cert, so verification stays
/// on (this carries the licence key, like the heartbeat).
static SUPPORT_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    crate::api::ipv4_only_client_builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Who this node can authenticate as. `(license_key, github_login)` — at least
/// one is `Some` when entitled. Licensed = a valid licence on disk; sponsor =
/// the operator has declared a GitHub sponsor login (honour-system locally, but
/// the server verifies it against the synced sponsor list).
pub fn credentials() -> Option<(Option<String>, Option<String>)> {
    let license_key = if crate::compat::platform_ready() {
        std::fs::read_to_string(crate::compat::dm_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    let cfg = crate::patreon::PatreonConfig::load();
    let github_login = if cfg.github_sponsor {
        cfg.github_sponsor_login.and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() { None } else { Some(t) }
        })
    } else {
        None
    };

    if license_key.is_some() || github_login.is_some() {
        Some((license_key, github_login))
    } else {
        None
    }
}

/// True when this node can use support (licence or declared sponsor).
pub fn entitled() -> bool {
    credentials().is_some()
}

/// Forward an action to the ticket API, injecting our credentials. `extra`
/// carries the action-specific fields (subject/body/ticket_id). Returns the
/// parsed JSON response, or a human error.
pub async fn call(action: &str, mut extra: Map<String, Value>) -> Result<Value, String> {
    let (license_key, github_login) = credentials()
        .ok_or("Support is available to WolfStack licence holders and GitHub sponsors.")?;

    extra.insert("action".to_string(), Value::String(action.to_string()));
    if let Some(lk) = license_key {
        extra.insert("license_key".to_string(), Value::String(lk));
    }
    if let Some(gh) = github_login {
        extra.insert("github_login".to_string(), Value::String(gh));
    }

    let resp = SUPPORT_CLIENT
        .post(TICKET_API_URL)
        .json(&Value::Object(extra))
        .send()
        .await
        .map_err(|e| format!("Could not reach the support service: {}", e))?;

    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("Support service returned an unreadable response: {}", e))?;

    if !status.is_success() {
        return Err(body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Support request failed")
            .to_string());
    }
    Ok(body)
}
