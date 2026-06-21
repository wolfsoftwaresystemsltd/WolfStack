// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Cluster-join security hardening.
//!
//! This module backs the hardened node-join handshake. It owns three
//! pieces of state that the join flow needs but that don't belong in the
//! sprawling `api` module:
//!
//!   1. **One-time, short-TTL join tokens** — an operator can mint a token
//!      that is valid for ~15 minutes and is consumed on the first
//!      successful join. The classic static per-install token in
//!      `/etc/wolfstack/join-token` still works (backward compat); a
//!      one-time token is an *additional*, tighter option.
//!   2. **The local "allow re-cluster" override** — a flag set by a LOCAL
//!      admin on the target so that a node already in cluster A can be
//!      deliberately re-homed into cluster B. Without it, a join request
//!      from a different cluster is hard-blocked, so a remote attacker
//!      holding a stolen secret cannot silently move a live node.
//!   3. **The cluster fingerprint** — a stable, non-secret identifier the
//!      joiner and the operator can see/log so a join isn't blindly
//!      trusting whatever answered. Derived from the active cluster secret
//!      so it's stable for a given cluster yet reveals nothing usable.
//!
//! The Tolkien-flavoured internal name for the override marker is the
//! "open-gate" — the gate of Moria opens only to one who speaks the word
//! locally. (LOTR flavour per project convention; never on the wire.)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a freshly-minted one-time join token stays valid.
const ONE_TIME_TTL: Duration = Duration::from_secs(15 * 60);

/// How long a local re-cluster override stays armed before it self-expires.
/// Bounds the window in which a node already in a cluster can be re-homed, so
/// an override armed and then forgotten (or a crash before the join arrives)
/// can't become a standing hole an attacker exploits days later.
const OVERRIDE_TTL_SECS: u64 = 30 * 60;

/// Wall-clock unix seconds (override marker persists across restarts, so it
/// must use the wall clock, not a monotonic Instant).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Local marker file: when present, this node will accept a join request
/// that would otherwise be hard-blocked because the node already belongs
/// to a (different) cluster. Created only by a LOCAL admin via the
/// override endpoint; consumed (deleted) on the next successful re-cluster
/// so it can't linger as a standing hole.
fn override_marker_path() -> String {
    "/etc/wolfstack/allow-recluster".to_string()
}

/// A pending one-time join token's expiry instant. The token string
/// itself is the HashMap key.
struct PendingToken {
    expires: Instant,
}

/// In-memory store of single-use, TTL-bounded tokens. Kept in-memory only:
/// these are deliberately ephemeral and a process restart invalidating them is
/// the safe failure mode — an operator simply mints a fresh one. Keyed by the
/// token string itself for O(1) verify+consume. The TTL is per-store: join
/// tokens use 15 min (`new()`); bootstrap grants use a much shorter window
/// (`with_ttl`) since they're consumed seconds after minting.
pub struct OneTimeTokens {
    inner: Mutex<HashMap<String, PendingToken>>,
    ttl: Duration,
}

impl Default for OneTimeTokens {
    fn default() -> Self {
        Self::with_ttl(ONE_TIME_TTL)
    }
}

impl OneTimeTokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store with a custom TTL (e.g. a short window for bootstrap grants).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Mint a new one-time token, store it with this store's TTL, and
    /// return the plaintext (shown to the operator ONCE). Also prunes any
    /// already-expired entries so the map can't grow without bound.
    /// Returns `Err` if the system CSPRNG is unavailable — we refuse to
    /// mint a low-entropy token (a predictable join token is a security
    /// hole) rather than fall back to a weak source.
    pub fn mint(&self) -> Result<String, String> {
        let token = generate_token()?;
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        prune_expired(&mut guard);
        guard.insert(
            token.clone(),
            PendingToken {
                expires: Instant::now() + self.ttl,
            },
        );
        Ok(token)
    }

    /// Verify `provided` against the pending one-time tokens. On a match
    /// that is NOT expired, the token is CONSUMED (removed) and `true` is
    /// returned — single-use. An expired or unknown token returns `false`
    /// (and expired ones are pruned). Each candidate is compared with the
    /// constant-time `validate_cluster_secret`; we scan EVERY entry without
    /// short-circuiting so total time doesn't reveal the matched token's
    /// position in iteration order.
    pub fn verify_and_consume(&self, provided: &str) -> bool {
        if provided.is_empty() {
            return false;
        }
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        prune_expired(&mut guard);
        // Scan all entries; record the matching KEY without early-exit.
        let now = Instant::now();
        let mut matched: Option<String> = None;
        for (token, pending) in guard.iter() {
            // Always run the constant-time compare; fold the (non-secret)
            // expiry into the decision afterwards so an unexpired vs expired
            // hit costs the same comparison work.
            let eq = crate::auth::validate_cluster_secret(provided, token);
            if eq && pending.expires > now {
                matched = Some(token.clone());
            }
        }
        if let Some(key) = matched {
            guard.remove(&key);
            true
        } else {
            false
        }
    }

    /// Atomically verify AND remove a matching non-expired token, returning
    /// its expiry so the caller can `reinsert` it if a LATER handshake step
    /// fails (so a failed admin attempt doesn't burn the operator's token).
    /// This is the concurrency-safe single-use primitive: the match + removal
    /// happen under one lock, so two racing requests with the same token can
    /// never both succeed — only the first `take` returns Some. Prefer this
    /// over is_valid()+verify_and_consume() for the handshake.
    pub fn take(&self, provided: &str) -> Option<Instant> {
        if provided.is_empty() {
            return None;
        }
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        prune_expired(&mut guard);
        let now = Instant::now();
        let mut matched: Option<String> = None;
        for (token, pending) in guard.iter() {
            let eq = crate::auth::validate_cluster_secret(provided, token);
            if eq && pending.expires > now {
                matched = Some(token.clone());
            }
        }
        matched.and_then(|key| guard.remove(&key).map(|p| p.expires))
    }

    /// Reinsert a previously-`take`n token with its original expiry, after a
    /// later handshake step failed. Dropped silently if already expired.
    pub fn reinsert(&self, token: &str, expires: Instant) {
        if Instant::now() >= expires {
            return;
        }
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.insert(token.to_string(), PendingToken { expires });
    }

    /// Number of currently-valid (non-expired) pending tokens — for status
    /// display. Prunes as a side effect.
    pub fn pending_count(&self) -> usize {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        prune_expired(&mut guard);
        guard.len()
    }
}

fn prune_expired(map: &mut HashMap<String, PendingToken>) {
    let now = Instant::now();
    map.retain(|_, p| p.expires > now);
}

/// Generate a 64-hex-char token from /dev/urandom (same shape/strength as
/// the static per-install join token). Returns `Err` if the CSPRNG can't
/// be read — never falls back to a low-entropy source, because a
/// predictable join token would defeat the whole point.
pub fn generate_token() -> Result<String, String> {
    use std::fmt::Write;
    use std::io::Read;
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    f.read_exact(&mut buf)
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    let mut token = String::with_capacity(64);
    for b in &buf {
        let _ = write!(token, "{:02x}", b);
    }
    Ok(token)
}

/// Stable, non-secret cluster fingerprint: SHA-256 of a domain-separated
/// view of the ACTIVE cluster secret, hex-encoded and truncated to 16
/// chars for display. Same secret → same fingerprint, so two nodes in the
/// same cluster (sharing the secret) print the same value, while the raw
/// secret is never recoverable from it. The domain-separation prefix means
/// the fingerprint can never be replayed as the secret itself.
pub fn cluster_fingerprint() -> String {
    use sha2::{Digest, Sha256};
    let secret = crate::auth::load_cluster_secret();
    let mut hasher = Sha256::new();
    hasher.update(b"wolfstack-cluster-fingerprint-v1:");
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    use std::fmt::Write;
    for b in digest.iter().take(8) {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Is the local re-cluster override currently armed AND still within its TTL?
/// The marker stores the unix-seconds arm time; an override older than
/// OVERRIDE_TTL_SECS is treated as not-armed and pruned, so a forgotten
/// override (or one left armed when the process crashed before a join) can't
/// become a standing hole.
pub fn recluster_override_armed() -> bool {
    let path = override_marker_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let armed_at = content.trim().parse::<u64>().unwrap_or(0);
    let now = now_unix();
    // armed_at == 0 (unparseable/legacy "1" marker) or stale → not armed.
    if armed_at == 0 || now.saturating_sub(armed_at) > OVERRIDE_TTL_SECS {
        let _ = std::fs::remove_file(&path);
        return false;
    }
    true
}

/// Arm the local re-cluster override (called by a LOCAL admin on the
/// target). Stores the arm timestamp (0600) so it self-expires after
/// OVERRIDE_TTL_SECS — it's a security-sensitive marker.
pub fn arm_recluster_override() -> Result<(), String> {
    crate::paths::write_secure(&override_marker_path(), &now_unix().to_string())
        .map_err(|e| format!("Cannot arm re-cluster override: {}", e))
}

/// Disarm / consume the local re-cluster override. Best-effort: a missing
/// file is success (the desired end state is "not armed").
pub fn clear_recluster_override() {
    let _ = std::fs::remove_file(override_marker_path());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_token_mint_verify_consume() {
        let store = OneTimeTokens::new();
        let t = store.mint().expect("CSPRNG available in test env");
        assert_eq!(t.len(), 64, "token should be 64 hex chars");
        assert_eq!(store.pending_count(), 1);
        // First use consumes it.
        assert!(store.verify_and_consume(&t));
        // Second use fails — single-use.
        assert!(!store.verify_and_consume(&t));
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn take_is_atomic_single_use() {
        let store = OneTimeTokens::new();
        let t = store.mint().expect("CSPRNG available in test env");
        // First take consumes it and returns the expiry.
        let exp = store.take(&t);
        assert!(exp.is_some(), "first take returns the token's expiry");
        // A racing second take gets nothing — single-use is atomic.
        assert!(store.take(&t).is_none(), "second take must fail");
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn reinsert_restores_after_failed_step() {
        let store = OneTimeTokens::new();
        let t = store.mint().expect("CSPRNG available in test env");
        let exp = store.take(&t).expect("taken");
        assert!(store.take(&t).is_none(), "consumed by first take");
        // Simulate a later handshake step failing → reinsert with its expiry.
        store.reinsert(&t, exp);
        assert!(store.take(&t).is_some(), "token restored and usable again");
        // An already-expired reinsert is dropped.
        store.reinsert("stale", Instant::now() - Duration::from_secs(1));
        assert!(store.take("stale").is_none());
    }

    #[test]
    fn one_time_token_unknown_rejected() {
        let store = OneTimeTokens::new();
        let _ = store.mint().expect("CSPRNG available in test env");
        assert!(!store.verify_and_consume("deadbeef"));
        assert!(!store.verify_and_consume(""));
        // The minted token is untouched by the failed attempts.
        assert_eq!(store.pending_count(), 1);
    }

    #[test]
    fn one_time_token_expires() {
        let store = OneTimeTokens::new();
        // Manually insert an already-expired token to exercise the prune
        // path without sleeping 15 minutes.
        {
            let mut g = store.inner.lock().unwrap();
            g.insert(
                "expired".to_string(),
                PendingToken {
                    expires: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        assert!(!store.verify_and_consume("expired"));
        assert_eq!(store.pending_count(), 0, "expired token pruned");
    }

    #[test]
    fn fingerprint_is_stable_and_not_the_secret() {
        let a = cluster_fingerprint();
        let b = cluster_fingerprint();
        assert_eq!(a, b, "fingerprint stable for same secret");
        assert_eq!(a.len(), 16);
        assert_ne!(a, crate::auth::load_cluster_secret());
    }
}
