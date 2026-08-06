// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Thin Cloudflare API client — just the DNS-record CRUD the edge
//! reconciler needs. Not a full SDK; we hit four endpoints:
//!
//!   GET    /zones?name=<zone>                 → resolve zone id
//!   GET    /zones/{zone}/dns_records?name=&type=A
//!   POST   /zones/{zone}/dns_records          → create A record
//!   PATCH  /zones/{zone}/dns_records/{id}     → update (proxied/ttl)
//!   DELETE /zones/{zone}/dns_records/{id}     → remove A record
//!
//! Credentials: stored shape is `{"account_id":"...", "api_token":"..."}`
//! (the account_id is informational for the UI — only the token matters
//! for API calls). Token needs `Zone:Read` + `DNS:Edit` scopes on the
//! relevant zones.

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The stored credential JSON is `{"account_id": "...", "api_token": "..."}`
/// (one shape shared with the tunnel client, which needs the account id).
/// This DNS client only uses the token — serde ignores the extra key.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareCreds {
    pub api_token: String,
}

impl CloudflareCreds {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(v.clone()).map_err(|e| {
            format!("cloudflare credentials: expected {{\"account_id\":\"…\",\"api_token\":\"…\"}}: {}", e)
        })
    }
}

/// One A-record as Cloudflare returns it. We only care about a few
/// fields — id (for delete/update), content (the IP), proxied flag,
/// ttl. Other fields are tolerated via `#[serde(default)]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsRecord {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub record_type: String,
    /// The IP for an A record, hostname for CNAME etc.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub ttl: u32,
}

// ─── API surface ────────────────────────────────────────────────────────

/// Resolve a zone name (e.g. "example.com") to its Cloudflare zone id.
/// Returns None when the token has no access to that zone — caller
/// surfaces that as "the API token doesn't cover this domain" rather
/// than a generic error.
pub async fn lookup_zone_id(creds: &CloudflareCreds, zone: &str) -> Result<Option<String>, String> {
    let url = format!("{}/zones?name={}&status=active", API_BASE, urlencode(zone));
    let body: ZonesEnvelope = http_get(creds, &url).await?;
    if !body.success {
        return Err(cloudflare_errs(&body.errors));
    }
    Ok(body.result.into_iter().next().map(|z| z.id))
}

/// List the A records for a given fully-qualified name within a zone.
/// Cloudflare returns paginated results; we ask for per_page=100 which
/// is enough — operators rarely have >100 records for one FQDN.
pub async fn list_a_records(creds: &CloudflareCreds, zone_id: &str, name: &str) -> Result<Vec<DnsRecord>, String> {
    list_records(creds, zone_id, name, "A").await
}

/// List records of a given type for a fully-qualified name within a
/// zone. Used by the A-record reconcile path (`type=A`) and the
/// teardown path which also has to scrub CNAMEs left over from
/// CloudflareTunnel.
pub async fn list_records(
    creds: &CloudflareCreds, zone_id: &str, name: &str, record_type: &str,
) -> Result<Vec<DnsRecord>, String> {
    let url = format!(
        "{}/zones/{}/dns_records?type={}&name={}&per_page=100",
        API_BASE, zone_id, urlencode(record_type), urlencode(name)
    );
    let body: RecordsEnvelope = http_get(creds, &url).await?;
    if !body.success {
        return Err(cloudflare_errs(&body.errors));
    }
    Ok(body.result)
}

/// Create an A record. `proxied=true` enables the orange-cloud
/// (Cloudflare's L7 proxy + CDN + DDoS); false leaves DNS unproxied.
pub async fn create_a_record(
    creds: &CloudflareCreds,
    zone_id: &str,
    name: &str,
    ip: &str,
    ttl: u32,
    proxied: bool,
) -> Result<DnsRecord, String> {
    // Cloudflare requires ttl >= 60 for proxied=false (and ignores ttl
    // for proxied=true — it forces "auto"). Floor it.
    let ttl_eff = if proxied { 1 } else { ttl.max(60) };
    let url = format!("{}/zones/{}/dns_records", API_BASE, zone_id);
    let body = serde_json::json!({
        "type": "A",
        "name": name,
        "content": ip,
        "ttl": ttl_eff,
        "proxied": proxied,
    });
    let env: SingleRecordEnvelope = http_post(creds, &url, &body).await?;
    if !env.success {
        return Err(cloudflare_errs(&env.errors));
    }
    Ok(env.result)
}

/// Delete an A record by id.
pub async fn delete_record(creds: &CloudflareCreds, zone_id: &str, record_id: &str) -> Result<(), String> {
    let url = format!("{}/zones/{}/dns_records/{}", API_BASE, zone_id, record_id);
    let env: DeleteEnvelope = http_delete(creds, &url).await?;
    if !env.success {
        return Err(cloudflare_errs(&env.errors));
    }
    Ok(())
}

/// Verify a token works by listing the first page of zones it can see.
/// Used by the Settings → Cloud Providers "Test connection" button.
pub async fn ping(creds: &CloudflareCreds) -> Result<usize, String> {
    let url = format!("{}/zones?per_page=1", API_BASE);
    let body: ZonesEnvelope = http_get(creds, &url).await?;
    if !body.success {
        return Err(cloudflare_errs(&body.errors));
    }
    // We can't get a total-zones count from per_page=1 without
    // paginating; just return the page count, which is at least
    // "the token sees some zones".
    Ok(body.result.len())
}

// ─── Internals ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ZonesEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Vec<Zone>,
}
#[derive(Deserialize)]
struct Zone { id: String }

#[derive(Deserialize)]
struct RecordsEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Vec<DnsRecord>,
}

#[derive(Deserialize)]
struct SingleRecordEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: DnsRecord,
}
impl Default for DnsRecord {
    fn default() -> Self {
        DnsRecord { id: String::new(), name: String::new(), record_type: String::new(), content: String::new(), proxied: false, ttl: 0 }
    }
}

#[derive(Deserialize)]
struct DeleteEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Deserialize, Debug)]
struct CfError {
    code: i64,
    message: String,
}

fn cloudflare_errs(errs: &[CfError]) -> String {
    if errs.is_empty() {
        return "cloudflare returned success=false with no error detail".into();
    }
    errs.iter()
        .map(|e| format!("[{}] {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn client() -> reqwest::Client {
    // Short timeout — DNS calls should be <2s. Keep retries to the
    // caller; this client just talks plain HTTPS.
    reqwest::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client builder cannot fail on this config")
}

async fn http_get<T: for<'de> Deserialize<'de>>(creds: &CloudflareCreds, url: &str) -> Result<T, String> {
    let resp = client().get(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .send().await
        .map_err(|e| format!("cloudflare GET {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() && text.is_empty() {
        return Err(format!("cloudflare GET {}: HTTP {}", url, status));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("cloudflare GET {}: bad JSON ({}): {}", url, e, truncate(&text, 200)))
}

async fn http_post<T: for<'de> Deserialize<'de>>(creds: &CloudflareCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().post(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("cloudflare POST {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() && text.is_empty() {
        return Err(format!("cloudflare POST {}: HTTP {}", url, status));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("cloudflare POST {}: bad JSON ({}): {}", url, e, truncate(&text, 200)))
}

async fn http_delete<T: for<'de> Deserialize<'de>>(creds: &CloudflareCreds, url: &str) -> Result<T, String> {
    let resp = client().delete(url)
        .bearer_auth(&creds.api_token)
        .send().await
        .map_err(|e| format!("cloudflare DELETE {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() && text.is_empty() {
        return Err(format!("cloudflare DELETE {}: HTTP {}", url, status));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("cloudflare DELETE {}: bad JSON ({}): {}", url, e, truncate(&text, 200)))
}

fn urlencode(s: &str) -> String {
    // Limited URL encoder — just for the bits Cloudflare puts in
    // query strings (zone names + record names). Letters, digits,
    // and . - _ pass through; everything else gets %xx.
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
    fn creds_parse_required_fields() {
        // The stored shape carries account_id (the tunnel client uses it);
        // this DNS client only needs the token and must tolerate the extra key.
        let v = serde_json::json!({"account_id": "abc", "api_token": "tok"});
        let c = CloudflareCreds::from_value(&v).unwrap();
        assert_eq!(c.api_token, "tok");
    }

    #[test]
    fn creds_reject_when_token_missing() {
        let v = serde_json::json!({"account_id": "abc"});
        assert!(CloudflareCreds::from_value(&v).is_err());
    }

    #[test]
    fn creds_token_alone_is_enough() {
        let v = serde_json::json!({"api_token": "tok"});
        assert!(CloudflareCreds::from_value(&v).is_ok());
    }

    #[test]
    fn urlencode_passes_safe_chars() {
        assert_eq!(urlencode("api.example.com"), "api.example.com");
        assert_eq!(urlencode("with-dash_under"), "with-dash_under");
    }

    #[test]
    fn urlencode_escapes_unsafe() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a&b"), "a%26b");
    }
}
