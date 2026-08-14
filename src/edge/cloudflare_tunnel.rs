// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Cloudflare Tunnel API client. Endpoints verified against the
//! Cloudflare developer docs ("Create a Tunnel via API" guide at
//! developers.cloudflare.com/cloudflare-one/connections/connect-
//! networks/get-started/create-remote-tunnel-api/).
//!
//! Cloudflare Tunnel is a fundamentally different ingress model from
//! the DNS/LB providers: there's no public IP on the origin. The
//! WolfStack node runs `cloudflared` which maintains an outbound TCP
//! tunnel to Cloudflare's network; requests come back through that
//! tunnel. Net effect: works behind CGNAT, no port-forward needed.
//!
//! API used:
//!
//!   Base: https://api.cloudflare.com/client/v4
//!   Auth: Authorization: Bearer <token>
//!
//!   POST /accounts/{account_id}/cfd_tunnel
//!     body: {"name": "...", "config_src": "cloudflare"}
//!     returns: {id, token, ...}
//!
//!   PUT  /accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations
//!     body: {"config": {"ingress": [{hostname, service}, {service: "http_status:404"}]}}
//!
//!   GET  /accounts/{account_id}/cfd_tunnel/{tunnel_id}/token
//!     returns: token string (used by `cloudflared service install <token>`)
//!
//!   POST /zones/{zone_id}/dns_records
//!     body: {type: "CNAME", name, content: "{tunnel_id}.cfargotunnel.com", proxied: true}
//!
//!   DELETE /accounts/{account_id}/cfd_tunnel/{tunnel_id}
//!     tear-down (only after deleting linked DNS records).
//!
//! Token spec required: "Cloudflare Tunnel: Edit" + "DNS: Edit" on
//! the target zone(s).

// Full client surface — install_cloudflared_service / get_tunnel_token
// / delete_tunnel / ping are reached via the install + teardown REST
// endpoints that round out the v23.2 surface.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareTunnelCreds {
    pub account_id: String,
    pub api_token: String,
}

impl CloudflareTunnelCreds {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(v.clone()).map_err(|e| {
            format!("cloudflare-tunnel credentials: expected {{\"account_id\":\"…\",\"api_token\":\"…\"}}: {}", e)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: String,
    /// Connector token returned at create-time. Pass to
    /// `cloudflared service install <token>`. Cloudflare also exposes
    /// a separate /token endpoint to fetch this later; we cache the
    /// create-time value so we don't need a second round trip.
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TunnelEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Tunnel,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfigEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct CfError { #[serde(default)] code: i64, #[serde(default)] message: String }

fn cferrs(errs: &[CfError]) -> String {
    if errs.is_empty() {
        return "cloudflare returned success=false with no error detail".into();
    }
    errs.iter().map(|e| format!("[{}] {}", e.code, e.message)).collect::<Vec<_>>().join("; ")
}

/// Ingress rule for a tunnel. The PUT-configurations endpoint
/// REQUIRES the last entry to be a "catch-all" with no `hostname`
/// and `service: "http_status:404"` — Cloudflare's tunnel router
/// rejects configurations missing this final fall-through.
#[derive(Debug, Clone, Serialize)]
pub struct IngressRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

// ─── Public API ─────────────────────────────────────────────────────────

pub async fn create_tunnel(creds: &CloudflareTunnelCreds, name: &str) -> Result<Tunnel, String> {
    let url = format!("{}/accounts/{}/cfd_tunnel", API_BASE, urlencode(&creds.account_id));
    let body = serde_json::json!({
        "name": name,
        "config_src": "cloudflare",  // remotely-managed config (vs "local")
    });
    let env: TunnelEnvelope = http_post(creds, &url, &body).await?;
    if !env.success { return Err(cferrs(&env.errors)); }
    Ok(env.result)
}

/// Fetch the connector token for an existing tunnel — usable to
/// run `cloudflared service install <token>` later.
pub async fn get_tunnel_token(creds: &CloudflareTunnelCreds, tunnel_id: &str) -> Result<String, String> {
    let url = format!("{}/accounts/{}/cfd_tunnel/{}/token", API_BASE, urlencode(&creds.account_id), urlencode(tunnel_id));
    let env: TokenEnvelope = http_get(creds, &url).await?;
    if !env.success { return Err(cferrs(&env.errors)); }
    Ok(env.result)
}

pub async fn put_tunnel_configuration(
    creds: &CloudflareTunnelCreds,
    tunnel_id: &str,
    ingress: &[IngressRule],
) -> Result<(), String> {
    let url = format!(
        "{}/accounts/{}/cfd_tunnel/{}/configurations",
        API_BASE, urlencode(&creds.account_id), urlencode(tunnel_id)
    );
    // Cloudflare requires the catch-all as the last entry; add one
    // automatically if the caller forgot.
    let mut rules: Vec<&IngressRule> = ingress.iter().collect();
    let need_fallback = rules.last().map(|r| r.hostname.is_some()).unwrap_or(true);
    let fallback = IngressRule { hostname: None, service: "http_status:404".into(), path: None };
    if need_fallback {
        rules.push(&fallback);
    }
    let body = serde_json::json!({ "config": { "ingress": rules } });
    let env: ConfigEnvelope = http_put(creds, &url, &body).await?;
    if !env.success { return Err(cferrs(&env.errors)); }
    Ok(())
}

pub async fn delete_tunnel(creds: &CloudflareTunnelCreds, tunnel_id: &str) -> Result<(), String> {
    let url = format!("{}/accounts/{}/cfd_tunnel/{}", API_BASE, urlencode(&creds.account_id), urlencode(tunnel_id));
    http_delete(creds, &url).await
}

/// Create the public CNAME pointing at `<tunnel_id>.cfargotunnel.com`
/// so traffic to `hostname` flows through the tunnel. zone_id is the
/// Cloudflare zone id (resolved via the cloudflare DNS client's
/// `lookup_zone_id` — same token works for both surfaces).
pub async fn create_tunnel_cname(
    creds: &CloudflareTunnelCreds,
    zone_id: &str,
    hostname: &str,
    tunnel_id: &str,
) -> Result<(), String> {
    let url = format!("{}/zones/{}/dns_records", API_BASE, urlencode(zone_id));
    let body = serde_json::json!({
        "type": "CNAME",
        "name": hostname,
        "content": format!("{}.cfargotunnel.com", tunnel_id),
        "proxied": true,
        "ttl": 1,
    });
    // Reuse the cloudflare DNS module's POST helper indirectly: we
    // do our own here to avoid pulling its dependency surface.
    let _: serde_json::Value = http_post(creds, &url, &body).await?;
    Ok(())
}

/// Install + run cloudflared on the local host using the given token.
/// This is the side-effect that turns the tunnel from "exists in
/// Cloudflare" to "actually serving traffic". Runs synchronously and
/// returns the install transcript. The caller should run this inside
/// a `web::block` since `cloudflared service install` shells out to
/// systemd.
pub fn install_cloudflared_service(token: &str) -> Result<String, String> {
    use std::process::Command;
    // Validate the token doesn't have shell metachars — it's
    // interpolated into argv but we defence-in-depth anyway.
    if token.is_empty() || token.contains(|c: char| c.is_ascii_whitespace() || c == '\'' || c == '"' || c == ';' || c == '$' || c == '`') {
        return Err("invalid tunnel token".into());
    }

    // cloudflared install: download if missing, install service, start.
    // We use the official cloudflared package when available; the
    // setup.sh download path is documented in the operator's notes.
    if Command::new("cloudflared").arg("--version").output()
        .map(|o| !o.status.success()).unwrap_or(true)
    {
        return Err("cloudflared binary not found. Install it first: see https://github.com/cloudflare/cloudflared#installing-cloudflared".into());
    }
    let out = Command::new("cloudflared")
        .args(["service", "install", token])
        .output()
        .map_err(|e| format!("spawn cloudflared service install: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(format!("cloudflared service install failed:\n{}\n{}", stdout.trim_end(), stderr.trim_end()));
    }
    // Belt-and-braces start (some distros' service install doesn't
    // start the unit automatically).
    let _ = Command::new("systemctl").args(["enable", "--now", "cloudflared"]).output();
    Ok(format!("cloudflared installed and started.\n{}{}", stdout, stderr))
}

pub async fn ping(creds: &CloudflareTunnelCreds) -> Result<(), String> {
    let url = format!("{}/accounts/{}/cfd_tunnel?per_page=1", API_BASE, urlencode(&creds.account_id));
    let resp = client().get(&url).bearer_auth(&creds.api_token).send().await
        .map_err(|e| format!("cloudflare-tunnel ping: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("cloudflare-tunnel ping: HTTP {}: {}", status, truncate(&text, 200)));
    }
    Ok(())
}

// ─── Internals ──────────────────────────────────────────────────────────

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client builder")
}

async fn http_get<T: for<'de> Deserialize<'de>>(creds: &CloudflareTunnelCreds, url: &str) -> Result<T, String> {
    let resp = client().get(url).bearer_auth(&creds.api_token).send().await
        .map_err(|e| format!("cf-tunnel GET {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("cf-tunnel GET {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("cf-tunnel GET {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_post<T: for<'de> Deserialize<'de>>(creds: &CloudflareTunnelCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().post(url).bearer_auth(&creds.api_token).json(body).send().await
        .map_err(|e| format!("cf-tunnel POST {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("cf-tunnel POST {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("cf-tunnel POST {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_put<T: for<'de> Deserialize<'de>>(creds: &CloudflareTunnelCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().put(url).bearer_auth(&creds.api_token).json(body).send().await
        .map_err(|e| format!("cf-tunnel PUT {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("cf-tunnel PUT {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("cf-tunnel PUT {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_delete(creds: &CloudflareTunnelCreds, url: &str) -> Result<(), String> {
    let resp = client().delete(url).bearer_auth(&creds.api_token).send().await
        .map_err(|e| format!("cf-tunnel DELETE {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("cf-tunnel DELETE {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let cut: String = s.chars().take(max).collect();
    format!("{}…", cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creds_parse() {
        let v = serde_json::json!({"account_id":"abc","api_token":"tok"});
        let c = CloudflareTunnelCreds::from_value(&v).unwrap();
        assert_eq!(c.account_id, "abc");
        assert_eq!(c.api_token, "tok");
    }

    #[test]
    fn install_rejects_invalid_token() {
        // No shell metachars allowed in the token before we shell out.
        assert!(install_cloudflared_service("").is_err());
        assert!(install_cloudflared_service("good; rm -rf /").is_err());
        assert!(install_cloudflared_service("good`whoami`").is_err());
    }
}
