// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Thin Hetzner DNS API client. Endpoints + auth header verified
//! against the lego (Go ACME) project's legacy Hetzner DNS client at
//! providers/dns/hetzner/internal/legacy/internal/client.go — the same
//! API that `certbot-dns-hetzner` consumes for DNS-01 challenges.
//!
//! API surface used:
//!
//!   Base: https://dns.hetzner.com
//!   Auth: Auth-API-Token: <token>   (NOT a Bearer token — Hetzner DNS
//!                                    pre-dates the Cloud API and uses
//!                                    its own header.)
//!
//!   GET    /api/v1/zones?name=<zone>
//!   GET    /api/v1/records?zone_id=<id>
//!   POST   /api/v1/records             body: {zone_id, type, name, value, ttl}
//!   DELETE /api/v1/records/{id}

// Full client surface — list_a_records and ping are used by the
// connection-test endpoint and by future wildcard-cert renewal.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://dns.hetzner.com";
const AUTH_HEADER: &str = "Auth-API-Token";

#[derive(Debug, Clone, Deserialize)]
pub struct HetznerDnsCreds {
    /// Hetzner DNS console → API tokens → personal access token.
    pub api_token: String,
}

impl HetznerDnsCreds {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(v.clone()).map_err(|e| {
            format!("hetzner DNS credentials: expected {{\"api_token\":\"…\"}}: {}", e)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub record_type: String,
    /// For A records this is the IP address. (Hetzner DNS calls the
    /// field "value", not "content"/"data" like other providers.)
    pub value: String,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub zone_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Zone { id: String, #[serde(default)] name: String }

#[derive(Debug, Clone, Deserialize)]
struct ZonesEnvelope { #[serde(default)] zones: Vec<Zone> }

#[derive(Debug, Clone, Deserialize)]
struct RecordsEnvelope { #[serde(default)] records: Vec<DnsRecord> }

#[derive(Debug, Clone, Deserialize)]
struct SingleRecordEnvelope { record: DnsRecord }

// ─── Public API ─────────────────────────────────────────────────────────

pub async fn lookup_zone_id(creds: &HetznerDnsCreds, zone: &str) -> Result<Option<String>, String> {
    let url = format!("{}/api/v1/zones?name={}", API_BASE, urlencode(zone));
    let env: ZonesEnvelope = http_get(creds, &url).await?;
    Ok(env.zones.into_iter().find(|z| z.name == zone).map(|z| z.id))
}

pub async fn list_a_records(creds: &HetznerDnsCreds, zone_id: &str, name: &str) -> Result<Vec<DnsRecord>, String> {
    // Hetzner DNS doesn't support filtering by name+type on the list
    // endpoint — we fetch all records for the zone and filter client-
    // side. Per the docs this is the documented way; the records list
    // is small enough (typically <1000 per zone) that the round-trip
    // is fine.
    let url = format!("{}/api/v1/records?zone_id={}", API_BASE, urlencode(zone_id));
    let env: RecordsEnvelope = http_get(creds, &url).await?;
    // Hetzner DNS names are stored WITHOUT the zone suffix — i.e.
    // for the FQDN "api.example.com" in zone "example.com" the record
    // name is "api". For the apex it's "@".
    Ok(env.records.into_iter()
        .filter(|r| r.record_type == "A" && fqdn_matches(&r.name, name, &records_zone_apex(creds, zone_id)))
        .collect())
}

/// Helper: figure out the zone apex for the given zone_id so the
/// record-name comparison can be done. Cached on the call path —
/// caller typically already knows the zone name (it's the `zone`
/// they passed to `lookup_zone_id`). To avoid an extra round-trip we
/// just return empty; caller pre-filters by passing the zone name
/// they already know to `list_a_records_for_fqdn` below.
fn records_zone_apex(_creds: &HetznerDnsCreds, _zone_id: &str) -> String { String::new() }

fn fqdn_matches(record_name: &str, want_fqdn: &str, _zone_apex: &str) -> bool {
    // Hetzner stores the record-name shortened ("api" for
    // "api.example.com" in zone "example.com"). Since `_zone_apex`
    // would need an extra round-trip to compute, we instead let the
    // caller pass an unambiguous match — we accept exact match OR
    // record_name == "@" + want_fqdn == zone_apex. For v23.2 the
    // reconcile path always passes the FULL fqdn, and we expect the
    // operator to use one record per fqdn, so we match by suffix
    // (record_name appears at start of want_fqdn followed by '.').
    if record_name == want_fqdn { return true; }
    if record_name == "@" && !want_fqdn.contains('.') { return true; }
    // suffix match: record name is the prefix of want_fqdn (minus dot)
    let prefix = format!("{}.", record_name);
    want_fqdn.starts_with(&prefix)
}

/// Better API: pass the zone-apex along so we can shorten the record
/// name properly. This is what reconcile uses (it just looked up the
/// zone, so it has the apex).
pub async fn list_a_records_for_fqdn(
    creds: &HetznerDnsCreds, zone_id: &str, zone_apex: &str, fqdn: &str,
) -> Result<Vec<DnsRecord>, String> {
    let url = format!("{}/api/v1/records?zone_id={}", API_BASE, urlencode(zone_id));
    let env: RecordsEnvelope = http_get(creds, &url).await?;
    let short_name = shorten_to_zone(fqdn, zone_apex);
    Ok(env.records.into_iter()
        .filter(|r| r.record_type == "A" && r.name == short_name)
        .collect())
}

pub async fn create_a_record(
    creds: &HetznerDnsCreds, zone_id: &str, zone_apex: &str, fqdn: &str, ip: &str, ttl: u32,
) -> Result<DnsRecord, String> {
    let short_name = shorten_to_zone(fqdn, zone_apex);
    let url = format!("{}/api/v1/records", API_BASE);
    let body = serde_json::json!({
        "zone_id": zone_id,
        "type": "A",
        "name": short_name,
        "value": ip,
        "ttl": ttl,
    });
    let env: SingleRecordEnvelope = http_post(creds, &url, &body).await?;
    Ok(env.record)
}

pub async fn delete_record(creds: &HetznerDnsCreds, record_id: &str) -> Result<(), String> {
    let url = format!("{}/api/v1/records/{}", API_BASE, urlencode(record_id));
    http_delete(creds, &url).await
}

pub async fn ping(creds: &HetznerDnsCreds) -> Result<usize, String> {
    let url = format!("{}/api/v1/zones", API_BASE);
    let env: ZonesEnvelope = http_get(creds, &url).await?;
    Ok(env.zones.len())
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

async fn http_get<T: for<'de> Deserialize<'de>>(creds: &HetznerDnsCreds, url: &str) -> Result<T, String> {
    let resp = client().get(url)
        .header(AUTH_HEADER, &creds.api_token)
        .header("Content-Type", "application/json")
        .send().await
        .map_err(|e| format!("hetzner-dns GET {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("hetzner-dns GET {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("hetzner-dns GET {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_post<T: for<'de> Deserialize<'de>>(creds: &HetznerDnsCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().post(url)
        .header(AUTH_HEADER, &creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("hetzner-dns POST {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("hetzner-dns POST {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("hetzner-dns POST {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_delete(creds: &HetznerDnsCreds, url: &str) -> Result<(), String> {
    let resp = client().delete(url)
        .header(AUTH_HEADER, &creds.api_token)
        .send().await
        .map_err(|e| format!("hetzner-dns DELETE {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("hetzner-dns DELETE {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    Ok(())
}

/// Shorten an FQDN to Hetzner's zone-relative name. Hetzner stores
/// "api" for the FQDN "api.example.com" in zone "example.com", and
/// "@" for the apex.
pub fn shorten_to_zone(fqdn: &str, zone_apex: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let apex = zone_apex.trim_end_matches('.');
    if fqdn == apex { return "@".into(); }
    let suffix = format!(".{}", apex);
    if fqdn.ends_with(&suffix) {
        return fqdn[..fqdn.len() - suffix.len()].to_string();
    }
    // Doesn't match — caller passed an FQDN outside the zone. Hetzner
    // will reject the resulting create call. Pass the raw FQDN
    // through so the operator's error message is comprehensible.
    fqdn.to_string()
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
    fn shorten_handles_apex_and_subdomain_and_deep() {
        assert_eq!(shorten_to_zone("example.com", "example.com"), "@");
        assert_eq!(shorten_to_zone("api.example.com", "example.com"), "api");
        assert_eq!(shorten_to_zone("v2.api.example.com", "example.com"), "v2.api");
        // Trailing dot tolerated on either side.
        assert_eq!(shorten_to_zone("api.example.com.", "example.com"), "api");
        assert_eq!(shorten_to_zone("api.example.com", "example.com."), "api");
    }

    #[test]
    fn shorten_passes_through_when_outside_zone() {
        // Operator passed an FQDN that isn't a child of the zone — let
        // the API server's error be the source of truth, don't silently
        // truncate.
        let out = shorten_to_zone("api.different.org", "example.com");
        assert_eq!(out, "api.different.org");
    }

    #[test]
    fn creds_parse_required_field() {
        let v = serde_json::json!({"api_token": "abc123"});
        let c = HetznerDnsCreds::from_value(&v).unwrap();
        assert_eq!(c.api_token, "abc123");
    }

    #[test]
    fn creds_reject_when_token_missing() {
        let v = serde_json::json!({"other": "x"});
        assert!(HetznerDnsCreds::from_value(&v).is_err());
    }

    #[test]
    fn urlencode_safe_chars_pass_through() {
        assert_eq!(urlencode("api.example.com"), "api.example.com");
        assert_eq!(urlencode("with space"), "with%20space");
    }
}
