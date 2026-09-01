// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! DigitalOcean v2 Load Balancer client. Endpoints + body shapes
//! verified against the DigitalOcean public OpenAPI spec.
//!
//! API surface:
//!
//!   Base: https://api.digitalocean.com/v2
//!   Auth: Authorization: Bearer <token>
//!
//!   GET    /load_balancers                              list (filter client-side by name)
//!   POST   /load_balancers                              create
//!   GET    /load_balancers/{id}                         read
//!   POST   /load_balancers/{id}/droplets                add droplet_ids
//!   DELETE /load_balancers/{id}/droplets                remove droplet_ids (BODY required on DELETE)
//!   DELETE /load_balancers/{id}                         tear-down
//!
//! Note: DigitalOcean's LB targets are *droplets* by ID. WolfStack
//! nodes that aren't DigitalOcean droplets can't be added — for
//! non-DO origins use the Hetzner LB or DnsRoundRobin path instead.
//! This is a doc'd limitation surfaced to the operator in the UI.

// Full client surface — see the corresponding allow on hetzner_lb.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.digitalocean.com/v2";

// DigitalOcean credentials are the same shape used by the DNS API —
// one token, both surfaces. Re-export so the cloud-providers store
// can carry a single CloudProvider entry for "DigitalOcean" that
// services both edge strategies.
pub use crate::edge::digitalocean_dns::DigitalOceanCreds;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancer {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub droplet_ids: Vec<u64>,
    #[serde(default)]
    pub region: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct LbEnvelope { load_balancer: LoadBalancer }

#[derive(Debug, Clone, Deserialize)]
struct LbListEnvelope { #[serde(default)] load_balancers: Vec<LoadBalancer> }

// ─── Public API ─────────────────────────────────────────────────────────

pub async fn find_by_name(creds: &DigitalOceanCreds, name: &str) -> Result<Option<LoadBalancer>, String> {
    // DO doesn't support ?name= filter on /load_balancers — list and
    // filter client-side. Operators rarely have hundreds of LBs in
    // one project so the cost is fine.
    let url = format!("{}/load_balancers?per_page=200", API_BASE);
    let env: LbListEnvelope = http_get(creds, &url).await?;
    Ok(env.load_balancers.into_iter().find(|lb| lb.name == name))
}

pub async fn create_lb(
    creds: &DigitalOceanCreds,
    name: &str,
    region: &str,                       // "nyc3" / "lon1" / etc.
    droplet_ids: &[u64],
    https_passthrough: bool,
) -> Result<LoadBalancer, String> {
    let url = format!("{}/load_balancers", API_BASE);
    let mut forwarding_rules = vec![serde_json::json!({
        "entry_protocol": "http",
        "entry_port": 80,
        "target_protocol": "http",
        "target_port": 80,
        "certificate_id": "",
        "tls_passthrough": false,
    })];
    if https_passthrough {
        forwarding_rules.push(serde_json::json!({
            "entry_protocol": "https",
            "entry_port": 443,
            "target_protocol": "https",
            "target_port": 443,
            "tls_passthrough": true,
        }));
    }
    let body = serde_json::json!({
        "name": name,
        "region": region,
        "size_unit": 1,
        "forwarding_rules": forwarding_rules,
        "health_check": {
            "protocol": "http",
            "port": 80,
            "path": "/",
            "check_interval_seconds": 10,
            "response_timeout_seconds": 5,
            "healthy_threshold": 3,
            "unhealthy_threshold": 3,
        },
        "sticky_sessions": { "type": "none" },
        "droplet_ids": droplet_ids,
    });
    let env: LbEnvelope = http_post(creds, &url, &body).await?;
    Ok(env.load_balancer)
}

pub async fn read_lb(creds: &DigitalOceanCreds, lb_id: &str) -> Result<LoadBalancer, String> {
    let url = format!("{}/load_balancers/{}", API_BASE, urlencode(lb_id));
    let env: LbEnvelope = http_get(creds, &url).await?;
    Ok(env.load_balancer)
}

pub async fn add_droplets(creds: &DigitalOceanCreds, lb_id: &str, droplet_ids: &[u64]) -> Result<(), String> {
    let url = format!("{}/load_balancers/{}/droplets", API_BASE, urlencode(lb_id));
    let body = serde_json::json!({ "droplet_ids": droplet_ids });
    http_post_nobody(creds, &url, &body).await
}

pub async fn remove_droplets(creds: &DigitalOceanCreds, lb_id: &str, droplet_ids: &[u64]) -> Result<(), String> {
    let url = format!("{}/load_balancers/{}/droplets", API_BASE, urlencode(lb_id));
    let body = serde_json::json!({ "droplet_ids": droplet_ids });
    // DigitalOcean is one of the providers that REQUIRES a body on a
    // DELETE — most clients ignore that, hence the dedicated helper.
    http_delete_with_body(creds, &url, &body).await
}

pub async fn delete_lb(creds: &DigitalOceanCreds, lb_id: &str) -> Result<(), String> {
    let url = format!("{}/load_balancers/{}", API_BASE, urlencode(lb_id));
    let resp = client().delete(&url).bearer_auth(&creds.api_token).send().await
        .map_err(|e| format!("digitalocean-lb DELETE: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("digitalocean-lb DELETE {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    Ok(())
}

pub async fn ping(creds: &DigitalOceanCreds) -> Result<usize, String> {
    let url = format!("{}/load_balancers?per_page=1", API_BASE);
    let env: LbListEnvelope = http_get(creds, &url).await?;
    Ok(env.load_balancers.len())
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

async fn http_get<T: for<'de> Deserialize<'de>>(creds: &DigitalOceanCreds, url: &str) -> Result<T, String> {
    let resp = client().get(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .send().await
        .map_err(|e| format!("digitalocean-lb GET {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("digitalocean-lb GET {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("digitalocean-lb GET {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_post<T: for<'de> Deserialize<'de>>(creds: &DigitalOceanCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().post(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("digitalocean-lb POST {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("digitalocean-lb POST {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("digitalocean-lb POST {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_post_nobody(creds: &DigitalOceanCreds, url: &str, body: &serde_json::Value) -> Result<(), String> {
    let resp = client().post(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("digitalocean-lb POST {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("digitalocean-lb POST {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    Ok(())
}

async fn http_delete_with_body(creds: &DigitalOceanCreds, url: &str, body: &serde_json::Value) -> Result<(), String> {
    let resp = client().delete(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("digitalocean-lb DELETE {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("digitalocean-lb DELETE {}: HTTP {}: {}", url, status, truncate(&text, 200)));
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
