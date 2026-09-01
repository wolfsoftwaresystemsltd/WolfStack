// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! DigitalOcean v2 DNS API client. Endpoints + shapes verified
//! against the DigitalOcean public OpenAPI spec (downloaded from
//! api-engineering.nyc3.cdn.digitaloceanspaces.com).
//!
//! API surface:
//!
//!   Base: https://api.digitalocean.com/v2
//!   Auth: Authorization: Bearer <token>
//!
//!   GET    /domains/{domain}/records?type=A&name=<fqdn>
//!   POST   /domains/{domain}/records            body: {type, name, data, ttl}
//!   DELETE /domains/{domain}/records/{id}
//!
//! Important name semantics: DigitalOcean records take either:
//!   • a *fully qualified* `name` ending with the zone — e.g.
//!     "api.example.com" — OR
//!   • the bare host portion — e.g. "api".
//! Either works for create. The list response always returns the
//! shortened form ("api", or "@" for the apex).

// Full client surface.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.digitalocean.com/v2";

#[derive(Debug, Clone, Deserialize)]
pub struct DigitalOceanCreds {
    pub api_token: String,
}

impl DigitalOceanCreds {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(v.clone()).map_err(|e| {
            format!("digitalocean credentials: expected {{\"api_token\":\"…\"}}: {}", e)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// DigitalOcean record IDs are integers.
    #[serde(default)]
    pub id: u64,
    #[serde(default, rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub name: String,
    /// IP for A records; target for CNAME etc. DigitalOcean calls
    /// this field `data`, not "content"/"value".
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub ttl: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordsEnvelope { #[serde(default)] domain_records: Vec<DnsRecord> }

#[derive(Debug, Clone, Deserialize)]
struct SingleRecordEnvelope { domain_record: DnsRecord }

#[derive(Debug, Clone, Deserialize)]
struct Domain { #[serde(default)] name: String }

#[derive(Debug, Clone, Deserialize)]
struct DomainsEnvelope { #[serde(default)] domains: Vec<Domain> }

// ─── Public API ─────────────────────────────────────────────────────────

/// DigitalOcean uses the domain *name* (e.g. "example.com") as the
/// path parameter — there's no separate "zone id". This call exists
/// so we can verify the token has access to the zone before trying
/// to read records, and to make error messages clearer than "404".
pub async fn zone_exists(creds: &DigitalOceanCreds, zone: &str) -> Result<bool, String> {
    let url = format!("{}/domains/{}", API_BASE, urlencode(zone));
    match http_status(creds, &url).await? {
        200 => Ok(true),
        404 => Ok(false),
        other => Err(format!("digitalocean GET /domains/{}: HTTP {}", zone, other)),
    }
}

pub async fn list_a_records_for_fqdn(
    creds: &DigitalOceanCreds, zone: &str, fqdn: &str,
) -> Result<Vec<DnsRecord>, String> {
    // DO supports `?type=A&name=<fqdn>` filtering on the records
    // endpoint — saves us fetching every record then matching client-
    // side.
    let url = format!(
        "{}/domains/{}/records?type=A&name={}&per_page=200",
        API_BASE,
        urlencode(zone),
        urlencode(fqdn),
    );
    let env: RecordsEnvelope = http_get(creds, &url).await?;
    Ok(env.domain_records)
}

pub async fn create_a_record(
    creds: &DigitalOceanCreds, zone: &str, fqdn: &str, ip: &str, ttl: u32,
) -> Result<DnsRecord, String> {
    let url = format!("{}/domains/{}/records", API_BASE, urlencode(zone));
    // DO accepts either shortened ("api") or FQDN ("api.example.com")
    // — pass the FQDN through so the operator can spot it in the DO
    // web UI without mental mapping.
    let body = serde_json::json!({
        "type": "A",
        "name": fqdn,
        "data": ip,
        "ttl": ttl.max(30),
    });
    let env: SingleRecordEnvelope = http_post(creds, &url, &body).await?;
    Ok(env.domain_record)
}

pub async fn delete_record(creds: &DigitalOceanCreds, zone: &str, record_id: u64) -> Result<(), String> {
    let url = format!("{}/domains/{}/records/{}", API_BASE, urlencode(zone), record_id);
    http_delete(creds, &url).await
}

/// `GET /v2/domains?per_page=1` — cheap proof-of-token-validity.
pub async fn ping(creds: &DigitalOceanCreds) -> Result<usize, String> {
    let url = format!("{}/domains?per_page=1", API_BASE);
    let env: DomainsEnvelope = http_get(creds, &url).await?;
    Ok(env.domains.len())
}

// ─── Internals ──────────────────────────────────────────────────────────

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client builder")
}

async fn http_get<T: for<'de> Deserialize<'de>>(creds: &DigitalOceanCreds, url: &str) -> Result<T, String> {
    let resp = client().get(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .send().await
        .map_err(|e| format!("digitalocean GET {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("digitalocean GET {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("digitalocean GET {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_post<T: for<'de> Deserialize<'de>>(creds: &DigitalOceanCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().post(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("digitalocean POST {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("digitalocean POST {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("digitalocean POST {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_delete(creds: &DigitalOceanCreds, url: &str) -> Result<(), String> {
    let resp = client().delete(url)
        .bearer_auth(&creds.api_token)
        .send().await
        .map_err(|e| format!("digitalocean DELETE {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("digitalocean DELETE {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    Ok(())
}

async fn http_status(creds: &DigitalOceanCreds, url: &str) -> Result<u16, String> {
    let resp = client().get(url)
        .bearer_auth(&creds.api_token)
        .send().await
        .map_err(|e| format!("digitalocean GET {}: {}", url, e))?;
    Ok(resp.status().as_u16())
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
        let v = serde_json::json!({"api_token": "tok"});
        assert_eq!(DigitalOceanCreds::from_value(&v).unwrap().api_token, "tok");
    }

    #[test]
    fn creds_reject_missing() {
        assert!(DigitalOceanCreds::from_value(&serde_json::json!({})).is_err());
    }

    #[test]
    fn url_encoding_passes_safe() {
        assert_eq!(urlencode("api.example.com"), "api.example.com");
        assert_eq!(urlencode("with space"), "with%20space");
    }
}
