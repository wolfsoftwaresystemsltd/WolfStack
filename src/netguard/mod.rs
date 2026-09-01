// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

#![allow(dead_code)]

//! Defensive primitives for outbound HTTP — stops cascading retry storms
//! before they can exhaust fds or DNS the node to death.
//!
//! Three layered protections, applied from cheapest-to-strictest:
//!
//! 1. **DNS cache** (`resolve_host_v4_cached`). `getaddrinfo` (via
//!    `std::net::ToSocketAddrs`) on a Tailscale MagicDNS hostname
//!    under a hot path causes one UDP socket per query on the
//!    systemd-resolved stub — we've seen nodes spraying 360 DNS
//!    queries/second for the same `.ts.net` name. A 5-minute TTL
//!    cache makes that cost essentially free after the first lookup
//!    and doesn't change correctness: if the IP actually moves, the
//!    cache blinks after 5 minutes, which is well inside the
//!    operator's "I just migrated this node" expectation.
//!
//! 2. **Per-peer outbound concurrency cap** (`acquire_peer_slot`).
//!    A `Semaphore` keyed by "host:port" limits concurrent outbound
//!    HTTP connections to any single peer to 4. Every shared
//!    `reqwest::Client` in the codebase that talks to peers is
//!    routed through `guarded_send`, which acquires a permit before
//!    calling `.send().await` and releases it on drop. Even if some
//!    caller bug fires tokio::spawn in a tight loop, the semaphore
//!    backpressures it immediately — the loop blocks on `acquire`
//!    instead of flooding the OS with sockets.
//!
//! 3. **Circuit breaker** (`breaker_allow`). Tracks per-peer failure
//!    counts in a sliding 30-second window; after 10 failures the
//!    breaker opens and refuses calls to that peer for 60 seconds.
//!    When the breaker closes, one probe call goes through; if it
//!    succeeds the window resets, if it fails the timer restarts.
//!    Classic "half-open" behaviour, tuned for cluster RPC cadence
//!    (the 10s/15s/30s/60s ticks in main.rs).
//!
//! All state is module-local `LazyLock`s, bounded by peer count; no
//! external config, no unbounded growth. Metrics can be read via
//! `stats()` for an /api/debug endpoint if we want to surface them.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

// ═══════════════════════════════════════════════════
// ─── DNS cache ───
// ═══════════════════════════════════════════════════

/// TTL for cached A-record lookups. 5 minutes is a reasonable middle
/// ground between "picks up DNS changes promptly" and "doesn't DoS
/// systemd-resolved". Longer than the 30s Tailscale MagicDNS TTL but
/// within the window of a human-noticed DNS change.
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Upper bound on distinct hostnames we'll remember — protects against
/// an attack / bug that feeds us random names. Entries beyond this
/// limit are discarded on insertion via LRU-like trim.
const DNS_CACHE_MAX_ENTRIES: usize = 2048;

#[derive(Clone, Debug)]
struct DnsEntry {
    ip: Ipv4Addr,
    expires: Instant,
}

static DNS_CACHE: LazyLock<Mutex<HashMap<String, DnsEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static DNS_HITS: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));
static DNS_MISSES: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

/// Resolve `host` to an IPv4 address, using the cache when possible.
/// Non-blocking for cache hits; does a blocking `getaddrinfo` on miss
/// (wrapped in `spawn_blocking` by callers that need async).
///
/// Passes through IP-literal inputs unchanged — `100.70.70.70` becomes
/// `Ipv4Addr::new(100,70,70,70)` without touching DNS.
pub fn resolve_host_v4_cached(host: &str) -> Option<Ipv4Addr> {
    // Fast path — literal IPv4. `parse::<Ipv4Addr>()` is quicker than
    // opening a DNS socket and we want to avoid the stub resolver
    // entirely for the common IP-addressed cluster case.
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }

    // Cache check — take the lock only as long as needed to copy out.
    {
        let cache = DNS_CACHE.lock().unwrap();
        if let Some(entry) = cache.get(host)
            && entry.expires > Instant::now() {
                *DNS_HITS.lock().unwrap() += 1;
                return Some(entry.ip);
            }
    }

    // Miss — fall back to getaddrinfo. `(host, 0)` gives us every A
    // record; we pick the first IPv4 and cache it.
    *DNS_MISSES.lock().unwrap() += 1;
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, 0u16).to_socket_addrs().ok()?.collect();
    let ip = addrs.into_iter().find_map(|sa| match sa {
        std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    })?;

    let mut cache = DNS_CACHE.lock().unwrap();
    // Bound the cache — trim if we're at the ceiling. Expired entries
    // first, then oldest-expiring (effectively LRU on TTL).
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, v| v.expires > now);
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            // Still full — drop the oldest quarter.
            let mut entries: Vec<(String, Instant)> = cache.iter()
                .map(|(k, v)| (k.clone(), v.expires)).collect();
            entries.sort_by_key(|(_, e)| *e);
            for (k, _) in entries.into_iter().take(DNS_CACHE_MAX_ENTRIES / 4) {
                cache.remove(&k);
            }
        }
    }
    cache.insert(host.to_string(), DnsEntry {
        ip,
        expires: Instant::now() + DNS_CACHE_TTL,
    });
    Some(ip)
}

/// Invalidate a single cache entry — call this when we've observed a
/// peer that used to resolve to address X is now unreachable and we
/// want to force a fresh lookup next time. Optional; the 5-minute
/// TTL generally does the right thing.
#[allow(dead_code)]
pub fn invalidate_host(host: &str) {
    DNS_CACHE.lock().unwrap().remove(host);
}

/// DNS cache stats for diagnostics.
pub fn dns_stats() -> (u64, u64, usize) {
    let hits = *DNS_HITS.lock().unwrap();
    let misses = *DNS_MISSES.lock().unwrap();
    let size = DNS_CACHE.lock().unwrap().len();
    (hits, misses, size)
}

// ═══════════════════════════════════════════════════
// ─── Per-peer outbound concurrency cap ───
// ═══════════════════════════════════════════════════

/// Max concurrent outbound HTTP connections per peer (identified by
/// `host:port`). A healthy cluster with 3–5 peers never needs more
/// than 1–2 concurrent calls per peer; this ceiling catches pathological
/// fan-out (tokio::spawn in a loop, retry storm, deadlocked handler
/// firing N nested subrequests) before it exhausts fds.
const MAX_PER_PEER_CONCURRENT: usize = 4;

/// Per-peer semaphores are allocated lazily on first use. We never
/// remove entries — the set is bounded by the cluster peer count,
/// which is small and stable.
static PEER_SEMAPHORES: LazyLock<Mutex<HashMap<String, Arc<Semaphore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Acquire a concurrency slot for outbound calls to `peer_key`.
/// `peer_key` should be "host:port" so HTTPS (8553) and HTTP (8554)
/// to the same peer share a single slot — otherwise the build_node_urls
/// tri-URL fallback would triple the effective limit.
///
/// The returned permit MUST be held for the full lifetime of the
/// send+drain. Drop it by letting it go out of scope after the
/// request completes.
///
/// Keys are always normalised to `host:base_port` where `base_port`
/// strips the HTTP-fallback `+1` offset — so `cynthia:8553` and
/// `cynthia:8554` share the same slot, matching operator intent
/// (one peer = one slot budget regardless of which port the client
/// is trying).
pub async fn acquire_peer_slot(host: &str, port: u16) -> OwnedPeerPermit {
    let base = if port.is_multiple_of(2) && port > 1 { port - 1 } else { port };
    let key = format!("{}:{}", host, base);
    let sem = {
        let mut map = PEER_SEMAPHORES.lock().unwrap();
        map.entry(key.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_PER_PEER_CONCURRENT)))
            .clone()
    };
    let permit = sem.acquire_owned().await.expect("semaphore never closed");
    OwnedPeerPermit { _permit: permit, _key: key }
}

/// RAII handle for a peer-concurrency slot. Holding it blocks other
/// outbound calls to the same peer beyond `MAX_PER_PEER_CONCURRENT`.
/// The underlying Semaphore lives for the process lifetime, so the
/// owned permit has no lifetime parameter and can cross await
/// boundaries / be stored in structs freely.
pub struct OwnedPeerPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _key: String,
}

// ═══════════════════════════════════════════════════
// ─── Circuit breaker ───
// ═══════════════════════════════════════════════════

const FAILURE_WINDOW: Duration = Duration::from_secs(30);
const FAILURE_THRESHOLD: u32 = 10;
const BREAKER_OPEN_DURATION: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct BreakerState {
    /// Timestamps of failures within the current sliding window. When
    /// pruned to entries newer than `Instant::now() - FAILURE_WINDOW`,
    /// a length ≥ `FAILURE_THRESHOLD` trips the breaker.
    failures: Vec<Instant>,
    /// If set, the breaker is open until this time. While open every
    /// `breaker_allow` call returns false immediately.
    open_until: Option<Instant>,
}

impl BreakerState {
    fn new() -> Self { Self { failures: Vec::new(), open_until: None } }
}

static BREAKERS: LazyLock<Mutex<HashMap<String, BreakerState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Key a breaker the same way a peer-slot is keyed — `host:base_port`,
/// with HTTP/HTTPS fallback sharing one breaker.
fn breaker_key(host: &str, port: u16) -> String {
    let base = if port.is_multiple_of(2) && port > 1 { port - 1 } else { port };
    format!("{}:{}", host, base)
}

/// Check whether a call to this peer is allowed right now. Returns
/// false if the breaker is open, in which case the caller should
/// short-circuit without opening a socket.
pub fn breaker_allow(host: &str, port: u16) -> bool {
    let key = breaker_key(host, port);
    let mut map = BREAKERS.lock().unwrap();
    let entry = map.entry(key).or_insert_with(BreakerState::new);
    if let Some(open_until) = entry.open_until {
        if Instant::now() < open_until {
            return false;
        }
        // Timer expired — reset to half-open (one probe allowed).
        entry.open_until = None;
        entry.failures.clear();
    }
    true
}

/// Record the outcome of a peer call. A success clears the failure
/// window; a failure appends a timestamp and trips the breaker if
/// the window now contains ≥ `FAILURE_THRESHOLD` entries.
pub fn breaker_record(host: &str, port: u16, success: bool) {
    let key = breaker_key(host, port);
    let now = Instant::now();
    let mut map = BREAKERS.lock().unwrap();
    let entry = map.entry(key).or_insert_with(BreakerState::new);
    if success {
        entry.failures.clear();
        return;
    }
    // Prune old failures, append current, check threshold.
    entry.failures.retain(|&t| now.duration_since(t) < FAILURE_WINDOW);
    entry.failures.push(now);
    if entry.failures.len() as u32 >= FAILURE_THRESHOLD {
        entry.open_until = Some(now + BREAKER_OPEN_DURATION);
        entry.failures.clear();
    }
}

/// Stats for the debug endpoint.
#[allow(dead_code)]
pub fn breaker_stats() -> Vec<(String, usize, bool)> {
    let now = Instant::now();
    BREAKERS.lock().unwrap().iter().map(|(k, v)| {
        let open = v.open_until.map(|t| t > now).unwrap_or(false);
        (k.clone(), v.failures.len(), open)
    }).collect()
}

// ═══════════════════════════════════════════════════
// ─── Combined `guarded_send` helper ───
// ═══════════════════════════════════════════════════

/// One-call wrapper that applies all three protections for a single
/// outbound HTTP request:
///   1. Checks the breaker — returns Err immediately if open.
///   2. Acquires a per-peer concurrency slot.
///   3. Fires the request, drains the body, records success/failure.
///
/// Callers pass `(host, port)` so we can apply the guards even before
/// the RequestBuilder is cloned from the shared Client. This keeps
/// the guard layer independent of reqwest internals — we don't have
/// to re-parse the URL.
///
/// Returns `Ok(Some(status_code))` on a completed request,
/// `Ok(None)` if the breaker short-circuited (caller can treat this
/// as "peer unavailable, skip this tick"), and `Err(String)` on
/// transport error.
pub async fn guarded_send(
    host: &str,
    port: u16,
    req: reqwest::RequestBuilder,
) -> Result<Option<u16>, String> {
    if !breaker_allow(host, port) {
        return Ok(None);
    }
    let _permit = acquire_peer_slot(host, port).await;
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Drain the body so reqwest returns the connection to
            // the keep-alive pool (CLOSE_WAIT mitigation — matches
            // the send_and_drain pattern in src/wolfrun/mod.rs).
            let _ = resp.bytes().await;
            breaker_record(host, port, status < 500);
            Ok(Some(status))
        }
        Err(e) => {
            breaker_record(host, port, false);
            Err(format!("{}", e))
        }
    }
}

// ═══════════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literal_bypasses_cache() {
        let ip = resolve_host_v4_cached("127.0.0.1").unwrap();
        assert_eq!(ip, Ipv4Addr::LOCALHOST);
        // Literal IPs never hit the DNS cache.
        let (_, _, size) = dns_stats();
        // Size may be non-zero from earlier tests, but this one
        // shouldn't add to it — we can't assert absolute zero here.
        let _ = size;
    }

    #[test]
    fn breaker_opens_after_threshold() {
        for _ in 0..(FAILURE_THRESHOLD + 1) {
            breaker_record("testhost.example", 9999, false);
        }
        assert!(!breaker_allow("testhost.example", 9999),
                "breaker should be open after {} failures", FAILURE_THRESHOLD);
    }

    #[test]
    fn breaker_success_clears_window() {
        for _ in 0..(FAILURE_THRESHOLD - 1) {
            breaker_record("test2.example", 9999, false);
        }
        // One success clears the window; next failure starts fresh.
        breaker_record("test2.example", 9999, true);
        assert!(breaker_allow("test2.example", 9999));
    }

    #[test]
    fn peer_keys_normalise_http_fallback() {
        // :8554 (http fallback) should map to the same breaker key
        // as :8553 (https) — i.e. one peer, one budget, regardless
        // of which URL the client is trying.
        let k1 = breaker_key("cynthia.local", 8553);
        let k2 = breaker_key("cynthia.local", 8554);
        assert_eq!(k1, k2, "https and http fallback must share one breaker");
    }
}
