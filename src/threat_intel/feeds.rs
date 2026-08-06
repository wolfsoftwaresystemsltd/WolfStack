// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Threat-intelligence feed providers.
//!
//! Each provider implements `FeedProvider`. The `fetch` method returns
//! the IPs/CIDRs the provider considers malicious as two sorted sets
//! (v4 and v6). The orchestrator unions all enabled providers and
//! deduplicates.
//!
//! Network calls go through `reqwest` with a 30s timeout. Failures are
//! reported per-provider — one feed being down doesn't poison the rest.

use std::collections::BTreeSet;
use std::time::Duration;

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of a single provider fetch.
pub struct FetchResult {
    pub v4: BTreeSet<String>,
    pub v6: BTreeSet<String>,
}

impl FetchResult {
    pub fn empty() -> Self { Self { v4: BTreeSet::new(), v6: BTreeSet::new() } }
    pub fn total(&self) -> usize { self.v4.len() + self.v6.len() }
}

/// Each provider has a stable string ID (used as the key in
/// `ThreatIntelConfig.providers`) and a fetch impl. `display_name` and
/// `requires_api_key` are read by the UI tab (Stage 5).
#[allow(dead_code)]
pub struct FeedProvider {
    pub id: &'static str,
    pub display_name: &'static str,
    /// Whether this provider needs an API key to function.
    pub requires_api_key: bool,
    pub fetch: fn(&super::ProviderConfig) -> Result<FetchResult, String>,
}

/// Enumerate all known providers. The order here drives the UI rendering.
pub fn all_providers() -> &'static [FeedProvider] {
    &PROVIDERS
}

const PROVIDERS: &[FeedProvider] = &[
    FeedProvider {
        id: "spamhaus_drop",
        display_name: "Spamhaus DROP/EDROP",
        requires_api_key: false,
        fetch: fetch_spamhaus_drop,
    },
    FeedProvider {
        id: "firehol_level1",
        display_name: "FireHOL Level 1",
        requires_api_key: false,
        fetch: fetch_firehol_level1,
    },
    FeedProvider {
        id: "crowdsec_community",
        display_name: "CrowdSec community blocklist",
        requires_api_key: true,
        fetch: fetch_crowdsec_community,
    },
    FeedProvider {
        id: "abuseipdb",
        display_name: "AbuseIPDB",
        requires_api_key: true,
        fetch: fetch_abuseipdb,
    },
];

/// Get a provider by ID. Reserved for the per-provider "Test now" UI
/// action; not currently called from production code paths.
#[allow(dead_code)]
pub fn provider_by_id(id: &str) -> Option<&'static FeedProvider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

// ═══════════════════════════════════════════════
// ─── Shared helpers ───
// ═══════════════════════════════════════════════

fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(FETCH_TIMEOUT)
        .user_agent(format!("WolfStack/{} (threat-intel)", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("build http client: {}", e))
}

/// Parse a plain-text feed where each line is an IP or CIDR. Lines starting
/// with `#`, `;` or whitespace-only are skipped. Tokens after the first
/// whitespace are stripped (Spamhaus inlines comments after the CIDR).
fn parse_text_feed(body: &str) -> FetchResult {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Drop inline trailing comments / extra columns.
        let token = line.split_whitespace().next().unwrap_or("");
        if token.is_empty() { continue; }
        match classify(token) {
            Some(IpKind::V4) => { v4.insert(token.to_string()); }
            Some(IpKind::V6) => { v6.insert(token.to_string()); }
            None => { /* unparseable — skip silently */ }
        }
    }
    FetchResult { v4, v6 }
}

#[derive(Copy, Clone)]
enum IpKind { V4, V6 }

/// Decide whether `s` looks like a v4 or v6 address/CIDR. Returns None
/// if it parses as neither.
fn classify(s: &str) -> Option<IpKind> {
    let body = s.split('/').next().unwrap_or(s);
    if let Ok(ip) = body.parse::<std::net::IpAddr>() {
        return Some(match ip {
            std::net::IpAddr::V4(_) => IpKind::V4,
            std::net::IpAddr::V6(_) => IpKind::V6,
        });
    }
    None
}

// ═══════════════════════════════════════════════
// ─── Provider: Spamhaus DROP / EDROP ───
// ═══════════════════════════════════════════════

const SPAMHAUS_DROP_URL: &str = "https://www.spamhaus.org/drop/drop.txt";
const SPAMHAUS_EDROP_URL: &str = "https://www.spamhaus.org/drop/edrop.txt";
const SPAMHAUS_DROPV6_URL: &str = "https://www.spamhaus.org/drop/dropv6.txt";

fn fetch_spamhaus_drop(cfg: &super::ProviderConfig) -> Result<FetchResult, String> {
    if !cfg.enabled { return Ok(FetchResult::empty()); }
    let client = http_client()?;
    let mut combined = FetchResult::empty();
    for url in [SPAMHAUS_DROP_URL, SPAMHAUS_EDROP_URL, SPAMHAUS_DROPV6_URL] {
        let body = client.get(url).send()
            .map_err(|e| format!("Spamhaus GET {}: {}", url, e))?
            .error_for_status()
            .map_err(|e| format!("Spamhaus {} returned: {}", url, e))?
            .text()
            .map_err(|e| format!("Spamhaus body read: {}", e))?;
        let parsed = parse_text_feed(&body);
        combined.v4.extend(parsed.v4);
        combined.v6.extend(parsed.v6);
    }
    Ok(combined)
}

// ═══════════════════════════════════════════════
// ─── Provider: FireHOL Level 1 ───
// ═══════════════════════════════════════════════

/// Curated by FireHOL — a union of the most consistent attack-source feeds.
/// IPv4 only.
const FIREHOL_LEVEL1_URL: &str =
    "https://iplists.firehol.org/files/firehol_level1.netset";

fn fetch_firehol_level1(cfg: &super::ProviderConfig) -> Result<FetchResult, String> {
    if !cfg.enabled { return Ok(FetchResult::empty()); }
    let url = if cfg.url_override.is_empty() { FIREHOL_LEVEL1_URL } else { cfg.url_override.as_str() };
    let client = http_client()?;
    let body = client.get(url).send()
        .map_err(|e| format!("FireHOL GET {}: {}", url, e))?
        .error_for_status()
        .map_err(|e| format!("FireHOL {} returned: {}", url, e))?
        .text()
        .map_err(|e| format!("FireHOL body read: {}", e))?;
    Ok(parse_text_feed(&body))
}

// ═══════════════════════════════════════════════
// ─── Provider: CrowdSec community blocklist ───
// ═══════════════════════════════════════════════
//
// CrowdSec's community blocklist is served at:
//   https://api.crowdsec.net/v3/decisions/stream  (with API key)
// Free for community accounts. Returns JSON; we only care about the
// "new" array (pruning is handled by our atomic ipset swap each refresh).

const CROWDSEC_URL: &str = "https://api.crowdsec.net/v3/decisions/stream?startup=true";

fn fetch_crowdsec_community(cfg: &super::ProviderConfig) -> Result<FetchResult, String> {
    if !cfg.enabled { return Ok(FetchResult::empty()); }
    if cfg.api_key.is_empty() {
        return Err("CrowdSec community blocklist requires an API key — get one at https://app.crowdsec.net/".to_string());
    }
    let url = if cfg.url_override.is_empty() { CROWDSEC_URL } else { cfg.url_override.as_str() };
    let client = http_client()?;
    let body = client.get(url)
        .header("X-Api-Key", &cfg.api_key)
        .send()
        .map_err(|e| format!("CrowdSec GET: {}", e))?
        .error_for_status()
        .map_err(|e| format!("CrowdSec returned: {}", e))?
        .text()
        .map_err(|e| format!("CrowdSec body read: {}", e))?;

    // Parse JSON: { "new": [{ "value": "1.2.3.4", "type": "ip", ... }, ...], ... }
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("CrowdSec JSON parse: {}", e))?;
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    if let Some(arr) = json.get("new").and_then(|v| v.as_array()) {
        for entry in arr {
            let value = match entry.get("value").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            // Skip non-IP decisions (CrowdSec also publishes ranges, AS, country bans we don't ingest).
            let scope = entry.get("scope").and_then(|v| v.as_str()).unwrap_or("");
            if !scope.eq_ignore_ascii_case("ip") && !scope.eq_ignore_ascii_case("range") {
                continue;
            }
            match classify(value) {
                Some(IpKind::V4) => { v4.insert(value.to_string()); }
                Some(IpKind::V6) => { v6.insert(value.to_string()); }
                None => {}
            }
        }
    }
    Ok(FetchResult { v4, v6 })
}

// ═══════════════════════════════════════════════
// ─── Provider: AbuseIPDB ───
// ═══════════════════════════════════════════════
//
// AbuseIPDB's blacklist endpoint:
//   https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90
// Requires an API key (free tier gives 1000 req/day, ~100k IPs).

const ABUSEIPDB_URL: &str =
    "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&plaintext=true";

fn fetch_abuseipdb(cfg: &super::ProviderConfig) -> Result<FetchResult, String> {
    if !cfg.enabled { return Ok(FetchResult::empty()); }
    if cfg.api_key.is_empty() {
        return Err("AbuseIPDB requires an API key — register at https://www.abuseipdb.com/account/api".to_string());
    }
    let url = if cfg.url_override.is_empty() { ABUSEIPDB_URL } else { cfg.url_override.as_str() };
    let client = http_client()?;
    let body = client.get(url)
        .header("Key", &cfg.api_key)
        .header("Accept", "text/plain")
        .send()
        .map_err(|e| format!("AbuseIPDB GET: {}", e))?
        .error_for_status()
        .map_err(|e| format!("AbuseIPDB returned: {}", e))?
        .text()
        .map_err(|e| format!("AbuseIPDB body read: {}", e))?;
    Ok(parse_text_feed(&body))
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_text_feed_basic() {
        let body = "# header comment\n\n203.0.113.0/24\n198.51.100.5\n; another comment\n\
                    2001:db8::/32\n  not-an-ip  \n";
        let r = parse_text_feed(body);
        assert!(r.v4.contains("203.0.113.0/24"));
        assert!(r.v4.contains("198.51.100.5"));
        assert!(r.v6.contains("2001:db8::/32"));
        assert_eq!(r.v4.len(), 2);
        assert_eq!(r.v6.len(), 1);
    }

    #[test]
    fn test_parse_text_feed_inline_comment() {
        // Spamhaus DROP includes "; SBL12345" after the CIDR
        let body = "203.0.113.0/24 ; SBL12345\n198.51.100.0/24 ; SBL67890\n";
        let r = parse_text_feed(body);
        assert!(r.v4.contains("203.0.113.0/24"));
        assert!(r.v4.contains("198.51.100.0/24"));
        assert_eq!(r.v4.len(), 2);
    }

    #[test]
    fn test_classify() {
        assert!(matches!(classify("8.8.8.8"), Some(IpKind::V4)));
        assert!(matches!(classify("8.8.8.0/24"), Some(IpKind::V4)));
        assert!(matches!(classify("::1"), Some(IpKind::V6)));
        assert!(matches!(classify("2001:db8::/32"), Some(IpKind::V6)));
        assert!(classify("not-an-ip").is_none());
        assert!(classify("").is_none());
    }

    #[test]
    fn test_provider_lookup() {
        assert_eq!(provider_by_id("spamhaus_drop").map(|p| p.id), Some("spamhaus_drop"));
        assert_eq!(provider_by_id("firehol_level1").map(|p| p.id), Some("firehol_level1"));
        assert!(provider_by_id("nonexistent").is_none());
    }

    #[test]
    fn test_disabled_provider_returns_empty() {
        let cfg = super::super::ProviderConfig { enabled: false, api_key: String::new(), url_override: String::new() };
        let r = fetch_firehol_level1(&cfg).expect("disabled fetch must succeed-empty");
        assert_eq!(r.total(), 0);
    }

    #[test]
    fn test_api_key_required_providers_error_without_key() {
        let cfg = super::super::ProviderConfig { enabled: true, api_key: String::new(), url_override: String::new() };
        assert!(fetch_crowdsec_community(&cfg).is_err());
        assert!(fetch_abuseipdb(&cfg).is_err());
    }
}
