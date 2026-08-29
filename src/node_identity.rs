// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Per-node asymmetric identity for inter-node requests.
//!
//! ## Why
//!
//! The cluster secret is ONE symmetric value shared by every node. Any
//! request carrying it is "a peer" — no node can tell which peer, and a
//! copy of the secret taken from one node's config, environment, logs or
//! backup is as good as being a node. The 2026-08-29 report by
//! @baeseungwon1010 (second revision of GHSA-r3mw-2wmq-j6jg) made the
//! consequence concrete: every attribution the operator gate relies on
//! (`X-WolfStack-Proxied` / `X-WolfStack-Actor`) is a header a
//! secret-holder can type.
//!
//! This module gives each node an Ed25519 keypair. The private key never
//! leaves the box (`{config_dir}/node-key`, mode 0600). Peers learn the
//! public key from the node's own status report and pin it in
//! `nodes.json`. Every inter-node request then carries a signature that
//! proves *which* node sent it, bound to the intended destination and a
//! timestamp+nonce so it cannot be replayed to another node or later.
//!
//! ## What it must never do: break an existing cluster
//!
//! Two modes, chosen by the operator, default **Transition**:
//!
//! * **Transition** — keys are generated and exchanged automatically. A
//!   signed request from a pinned key yields a verified node identity; an
//!   unsigned request (older peer, an operator's own script, a curl
//!   helper) or a request whose signature does not verify (reinstalled
//!   node, clock skew) is logged and handled exactly as today — the
//!   cluster secret alone is still accepted. Nothing that works today
//!   stops working.
//! * **Strict** — opt-in from Settings → Security once every peer shows
//!   a pinned key. A secret without a valid signature from a pinned node
//!   is refused everywhere except the join handshake. Only in this mode
//!   is a leaked secret worthless on its own.
//!
//! Wire format (all values in headers, the body is not signed — TLS
//! already gives integrity; the signature's job is identity):
//!
//! ```text
//! X-WolfStack-Node:  <sender self_id>
//! X-WolfStack-Ts:    <unix seconds>
//! X-WolfStack-Nonce: <16 random bytes, base64>
//! X-WolfStack-Dest:  <destination node self_id, "" if the sender could not resolve it>
//! X-WolfStack-Sig:   base64(Ed25519(canonical))
//! canonical = "wolfstack-peer-v1\n{node}\n{ts}\n{nonce}\n{dest}"
//! ```
//!
//! The destination binding is what stops a compromised peer C from
//! forwarding node A's headers to node B: A signed `dest = C`, and B
//! only accepts `dest = B`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

/// Signed headers are valid for this long either side of the receiver's
/// clock. Generous enough for an unsynchronised homelab, short enough
/// that the nonce cache stays small.
pub const MAX_SKEW_SECS: u64 = 300;

const HDR_NODE: &str = "X-WolfStack-Node";
const HDR_TS: &str = "X-WolfStack-Ts";
const HDR_NONCE: &str = "X-WolfStack-Nonce";
const HDR_DEST: &str = "X-WolfStack-Dest";
const HDR_SIG: &str = "X-WolfStack-Sig";
const CANONICAL_PREFIX: &str = "wolfstack-peer-v1";

fn b64() -> base64::engine::GeneralPurpose { base64::engine::general_purpose::STANDARD }

struct Identity {
    key: Ed25519KeyPair,
    pubkey_b64: String,
    self_id: String,
}

static IDENTITY: OnceLock<Identity> = OnceLock::new();
static CLUSTER: OnceLock<Arc<crate::agent::ClusterState>> = OnceLock::new();

/// Nonces seen inside the skew window, with the unix second they expire.
static SEEN_NONCES: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// Set when a verify() call succeeds, so the UI can show "this node has
/// seen a signed request" without another round trip.
static LAST_VERIFIED: RwLock<Option<(String, u64)>> = RwLock::new(None);

fn key_path() -> String {
    format!("{}/node-key", crate::paths::get().config_dir)
}

fn mode_path() -> String {
    format!("{}/node-signatures.json", crate::paths::get().config_dir)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ─── Key management ───────────────────────────────────────────────────

/// Load this node's keypair from disk, generating one on first start.
/// Idempotent; safe to call once at startup before the cluster state
/// exists. Failure is logged and leaves the node unsigned — it keeps
/// working as an ordinary secret-authenticated peer.
pub fn init(self_id: &str) -> Result<(), String> {
    if IDENTITY.get().is_some() {
        return Ok(());
    }
    let path = key_path();
    let pkcs8: Vec<u8> = match std::fs::read_to_string(&path) {
        Ok(s) => b64().decode(s.trim())
            .map_err(|e| format!("node-key at {} is not base64: {}", path, e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let rng = ring::rand::SystemRandom::new();
            let doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| "Ed25519 key generation failed".to_string())?;
            let bytes = doc.as_ref().to_vec();
            crate::local_ca::write_secret_file(&path, b64().encode(&bytes).as_bytes())?;
            tracing::info!("node identity: generated Ed25519 key at {}", path);
            bytes
        }
        Err(e) => return Err(format!("read {}: {}", path, e)),
    };
    let key = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| format!("node-key at {} is not a valid Ed25519 PKCS#8 key", path))?;
    let pubkey_b64 = b64().encode(key.public_key().as_ref());
    let _ = IDENTITY.set(Identity { key, pubkey_b64, self_id: self_id.to_string() });
    Ok(())
}

/// Hand the module the cluster state so it can resolve destinations and
/// pinned public keys. Called once after `ClusterState` is built.
pub fn register_cluster(cluster: Arc<crate::agent::ClusterState>) {
    let _ = CLUSTER.set(cluster);
}

/// This node's public key, base64 — advertised in every status report.
pub fn self_pubkey() -> Option<String> {
    IDENTITY.get().map(|i| i.pubkey_b64.clone())
}

// ─── Mode ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Sign and verify when possible; never refuse a secret-authed request
    /// for lack of a signature. The default, forever, unless an operator
    /// chooses otherwise.
    Transition,
    /// A cluster secret is only honoured together with a valid signature
    /// from a pinned node key (join handshake excepted).
    Strict,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct ModeFile {
    #[serde(default)]
    required: bool,
}

/// `WOLFSTACK_NODE_SIGNATURES=required|off` overrides the on-disk setting,
/// so a locked-out operator can always recover over SSH without editing
/// JSON: `off` forces Transition.
pub fn mode() -> Mode {
    match std::env::var("WOLFSTACK_NODE_SIGNATURES").as_deref() {
        Ok("required") => return Mode::Strict,
        Ok("off") => return Mode::Transition,
        _ => {}
    }
    let f: ModeFile = std::fs::read_to_string(mode_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if f.required { Mode::Strict } else { Mode::Transition }
}

/// Persist the operator's choice. Refuses Strict while any WolfStack peer
/// has no pinned key — turning it on would cut that peer off.
pub fn set_mode(strict: bool) -> Result<(), String> {
    if strict {
        let missing = peers_without_key();
        if !missing.is_empty() {
            return Err(format!(
                "cannot require node signatures: no key pinned yet for {}. \
                 Upgrade those nodes and wait one poll cycle, or remove them.",
                missing.join(", ")));
        }
    }
    let json = serde_json::to_string_pretty(&ModeFile { required: strict })
        .map_err(|e| e.to_string())?;
    std::fs::write(mode_path(), json).map_err(|e| format!("write {}: {}", mode_path(), e))
}

/// WolfStack peers (not self, not Proxmox entries) that have not yet
/// advertised a public key.
pub fn peers_without_key() -> Vec<String> {
    let Some(c) = CLUSTER.get() else { return Vec::new() };
    c.get_all_nodes().into_iter()
        .filter(|n| !n.is_self && n.node_type == "wolfstack")
        .filter(|n| n.pubkey.as_deref().map(str::is_empty).unwrap_or(true))
        .map(|n| if n.hostname.is_empty() { n.id.clone() } else { n.hostname.clone() })
        .collect()
}

/// Requests to these paths are how a node first proves itself; they can
/// never require a pinned key because none exists yet.
pub fn path_exempt_from_strict(path: &str) -> bool {
    matches!(path,
        "/api/cluster/join-handshake"
        | "/api/cluster/verify-token"
        | "/api/cluster/secret/receive"
        | "/api/cluster/bootstrap-add")
}

// ─── Signing ──────────────────────────────────────────────────────────

fn canonical(node: &str, ts: u64, nonce: &str, dest: &str) -> String {
    format!("{}\n{}\n{}\n{}\n{}", CANONICAL_PREFIX, node, ts, nonce, dest)
}

/// Resolve the node we are about to call from the URL host: our own
/// record for loopback/local addresses, otherwise the peer whose address,
/// public IP, migration address or WolfNet IP matches. `None` when the
/// host is not a node we know — the signature then carries an empty
/// destination, which a Strict receiver refuses.
pub fn dest_for_host(host: &str) -> Option<String> {
    let host = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    let c = CLUSTER.get()?;
    if host == "127.0.0.1" || host == "::1" || host == "localhost"
        || crate::agent::local_ipv4_addrs().contains(&host)
    {
        return Some(c.self_id.clone());
    }
    let wolfnet_owner = crate::api::lookup_address_by_wolfnet_ip(&host);
    for n in c.get_all_nodes() {
        let matches = n.address.eq_ignore_ascii_case(&host)
            || n.public_ip.as_deref().map(|p| p.eq_ignore_ascii_case(&host)).unwrap_or(false)
            || n.migration_address.as_deref().map(|p| p.eq_ignore_ascii_case(&host)).unwrap_or(false)
            || wolfnet_owner.as_deref().map(|a| a.eq_ignore_ascii_case(&n.address)).unwrap_or(false);
        if matches {
            return Some(n.self_id.clone().filter(|s| !s.is_empty()).unwrap_or(n.id));
        }
    }
    None
}

/// Signed identity headers for a request to `dest_host`. `None` when this
/// node has no key (init failed) — the caller then sends the secret alone,
/// exactly as before this module existed.
pub fn sign_for_host(dest_host: &str) -> Option<Vec<(&'static str, String)>> {
    let id = IDENTITY.get()?;
    let dest = dest_for_host(dest_host).unwrap_or_default();
    let mut nonce_bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce_bytes).ok()?;
    let nonce = b64().encode(nonce_bytes);
    let ts = now();
    let sig = id.key.sign(canonical(&id.self_id, ts, &nonce, &dest).as_bytes());
    Some(vec![
        (HDR_NODE, id.self_id.clone()),
        (HDR_TS, ts.to_string()),
        (HDR_NONCE, nonce),
        (HDR_DEST, dest),
        (HDR_SIG, b64().encode(sig.as_ref())),
    ])
}

fn host_of_url(url: &str) -> String {
    let after = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    let hostport = after.split('/').next().unwrap_or(after);
    if let Some(rest) = hostport.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    match hostport.rfind(':') {
        Some(p) if !hostport[..p].contains(':') => hostport[..p].to_string(),
        _ => hostport.to_string(),
    }
}

/// `-H` pairs for a shelled-out curl: the secret plus, when this node has
/// a key, the signature headers for `url`.
pub fn curl_headers(secret: &str, url: &str) -> Vec<String> {
    let mut out = vec![format!("X-WolfStack-Secret: {}", secret)];
    if let Some(hs) = sign_for_host(&host_of_url(url)) {
        out.extend(hs.into_iter().map(|(k, v)| format!("{}: {}", k, v)));
    }
    out
}

/// `curl_headers` as exactly six `-H` values so a fixed `.args([...])`
/// array can splice them in. When this node has no key the five
/// signature slots hold an inert marker header instead of the signature,
/// so the argument count never changes.
pub fn curl_headers_padded(secret: &str, url: &str) -> [String; 6] {
    let mut v = curl_headers(secret, url);
    while v.len() < 6 {
        v.push("X-WolfStack-Unsigned: 1".to_string());
    }
    let mut it = v.into_iter();
    std::array::from_fn(|_| it.next().unwrap_or_default())
}

/// Header pairs for a raw HTTP/WebSocket client (tungstenite): the secret
/// plus the signature for `url`.
pub fn raw_headers(secret: &str, url: &str) -> Vec<(&'static str, String)> {
    let mut out = vec![("X-WolfStack-Secret", secret.to_string())];
    if let Some(hs) = sign_for_host(&host_of_url(url)) {
        out.extend(hs);
    }
    out
}

/// The one way to authenticate an outbound reqwest call to a peer.
/// Replaces every hand-written `.peer_auth(…)`; a
/// build-time test (`tests/peer_auth_sweep.rs`) keeps it that way.
pub trait PeerAuth {
    fn peer_auth(self, secret: impl AsRef<str>) -> Self;
}

impl PeerAuth for reqwest::RequestBuilder {
    fn peer_auth(self, secret: impl AsRef<str>) -> Self {
        // The builder does not expose its URL; a cloned probe does. A
        // streaming body cannot be cloned, so call `peer_auth` BEFORE
        // `.body(stream)` / `.multipart(form)` — every current caller
        // does — or the request is signed without a destination, which a
        // Strict receiver refuses.
        let host = self.try_clone()
            .and_then(|b| b.build().ok())
            .map(|r| r.url().host_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let mut b = self.header("X-WolfStack-Secret", secret.as_ref());
        if let Some(hs) = sign_for_host(&host) {
            for (k, v) in hs {
                b = b.header(k, v);
            }
        }
        b
    }
}

impl PeerAuth for reqwest::blocking::RequestBuilder {
    fn peer_auth(self, secret: impl AsRef<str>) -> Self {
        let host = self.try_clone()
            .and_then(|b| b.build().ok())
            .map(|r| r.url().host_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let mut b = self.header("X-WolfStack-Secret", secret.as_ref());
        if let Some(hs) = sign_for_host(&host) {
            for (k, v) in hs {
                b = b.header(k, v);
            }
        }
        b
    }
}

// ─── Verification ─────────────────────────────────────────────────────

/// Outcome of checking a request's signature headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// Signature verified against the pinned key: the request came from
    /// this node (by self_id).
    Node(String),
    /// No signature headers at all.
    Unsigned,
    /// Signature headers present but wrong — the reason, for the log.
    Bad(String),
}

fn header<'a>(req: &'a actix_web::HttpRequest, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).map(str::trim)
}

fn pinned_pubkey(node_id: &str) -> Option<String> {
    let c = CLUSTER.get()?;
    c.get_all_nodes().into_iter()
        .find(|n| n.id == node_id || n.self_id.as_deref() == Some(node_id))
        .and_then(|n| n.pubkey)
        .filter(|k| !k.is_empty())
}

/// Record a nonce; false if it was already seen inside the window.
fn nonce_fresh(nonce: &str, ts: u64) -> bool {
    let mut guard = match SEEN_NONCES.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = now();
    if map.len() > 4096 {
        map.retain(|_, exp| *exp > now);
    }
    if let Some(exp) = map.get(nonce)
        && *exp > now
    {
        return false;
    }
    map.insert(nonce.to_string(), ts + MAX_SKEW_SECS);
    true
}

/// The five identity headers of one request, as received.
pub struct SignedParts<'a> {
    pub node: &'a str,
    pub ts: &'a str,
    pub nonce: &'a str,
    pub dest: &'a str,
    pub sig: &'a str,
}

/// Pure check, independent of actix: used by `verify_request` and the
/// unit tests. `our_id` is the receiver's self_id; `pubkey_b64` the
/// sender's pinned key.
pub fn verify_parts(our_id: &str, pubkey_b64: &str, p: &SignedParts<'_>, now_secs: u64) -> Result<(), String> {
    let SignedParts { node, ts: ts_str, nonce, dest, sig: sig_b64 } = *p;
    let ts: u64 = ts_str.parse().map_err(|_| "timestamp is not a number".to_string())?;
    if ts.abs_diff(now_secs) > MAX_SKEW_SECS {
        return Err(format!("timestamp skew {}s exceeds {}s — check NTP on both nodes",
            ts.abs_diff(now_secs), MAX_SKEW_SECS));
    }
    if dest != our_id {
        return Err(if dest.is_empty() {
            "signature carries no destination (sender could not resolve this node's address)".to_string()
        } else {
            format!("signature is addressed to node {} — not this node", dest)
        });
    }
    let pk = b64().decode(pubkey_b64).map_err(|_| "pinned public key is not base64".to_string())?;
    let sig = b64().decode(sig_b64).map_err(|_| "signature is not base64".to_string())?;
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(canonical(node, ts, nonce, dest).as_bytes(), &sig)
        .map_err(|_| "signature does not verify against the pinned key".to_string())
}

/// Check the identity headers on an inbound request. Cheap when absent.
///
/// The outcome is cached in the request's extensions: a handler that
/// tries one auth gate and falls back to another must see the same
/// answer twice, not "replayed nonce" the second time.
pub fn verify_request(req: &actix_web::HttpRequest) -> Verified {
    use actix_web::HttpMessage;
    if let Some(cached) = req.extensions().get::<Verified>() {
        return cached.clone();
    }
    let v = verify_request_uncached(req);
    req.extensions_mut().insert(v.clone());
    v
}

fn verify_request_uncached(req: &actix_web::HttpRequest) -> Verified {
    let (Some(node), Some(ts), Some(nonce), Some(sig)) =
        (header(req, HDR_NODE), header(req, HDR_TS), header(req, HDR_NONCE), header(req, HDR_SIG))
    else {
        return Verified::Unsigned;
    };
    let dest = header(req, HDR_DEST).unwrap_or("");
    let Some(c) = CLUSTER.get() else {
        return Verified::Bad("cluster state not initialised".to_string());
    };
    let Some(pk) = pinned_pubkey(node) else {
        return Verified::Bad(format!("no public key pinned for node {}", node));
    };
    if let Err(e) = verify_parts(&c.self_id, &pk, &SignedParts { node, ts, nonce, dest, sig }, now()) {
        return Verified::Bad(e);
    }
    if !nonce_fresh(nonce, ts.parse().unwrap_or(0)) {
        return Verified::Bad("replayed nonce".to_string());
    }
    if let Ok(mut w) = LAST_VERIFIED.write() {
        *w = Some((node.to_string(), now()));
    }
    Verified::Node(node.to_string())
}

/// Status for the Security page.
pub fn status() -> serde_json::Value {
    let last = LAST_VERIFIED.read().ok().and_then(|g| g.clone());
    serde_json::json!({
        "mode": mode(),
        "env_override": std::env::var("WOLFSTACK_NODE_SIGNATURES").ok(),
        "self_has_key": IDENTITY.get().is_some(),
        "self_pubkey": self_pubkey(),
        "peers_without_key": peers_without_key(),
        "last_verified_node": last.as_ref().map(|(n, _)| n.clone()),
        "last_verified_at": last.map(|(_, t)| t),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Ed25519KeyPair, String) {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let pk = b64().encode(key.public_key().as_ref());
        (key, pk)
    }

    fn signed(key: &Ed25519KeyPair, node: &str, ts: u64, nonce: &str, dest: &str) -> String {
        b64().encode(key.sign(canonical(node, ts, nonce, dest).as_bytes()).as_ref())
    }

    #[allow(clippy::too_many_arguments)]
    fn check(our: &str, pk: &str, node: &str, ts: &str, nonce: &str, dest: &str, sig: &str, now: u64) -> Result<(), String> {
        verify_parts(our, pk, &SignedParts { node, ts, nonce, dest, sig }, now)
    }

    #[test]
    fn roundtrip_verifies() {
        let (k, pk) = keypair();
        let sig = signed(&k, "ws-a", 1000, "n1", "ws-b");
        assert!(check("ws-b", &pk, "ws-a", "1000", "n1", "ws-b", &sig, 1010).is_ok());
    }

    #[test]
    fn wrong_destination_is_refused() {
        // The property that stops a compromised peer relaying A's headers
        // to a third node: A signed dest=C, B must refuse it.
        let (k, pk) = keypair();
        let sig = signed(&k, "ws-a", 1000, "n1", "ws-c");
        let e = check("ws-b", &pk, "ws-a", "1000", "n1", "ws-c", &sig, 1000).unwrap_err();
        assert!(e.contains("not this node"), "{}", e);
    }

    #[test]
    fn empty_destination_is_refused() {
        let (k, pk) = keypair();
        let sig = signed(&k, "ws-a", 1000, "n1", "");
        assert!(check("ws-b", &pk, "ws-a", "1000", "n1", "", &sig, 1000).is_err());
    }

    #[test]
    fn skew_beyond_window_is_refused() {
        let (k, pk) = keypair();
        let sig = signed(&k, "ws-a", 1000, "n1", "ws-b");
        assert!(check("ws-b", &pk, "ws-a", "1000", "n1", "ws-b", &sig, 1000 + MAX_SKEW_SECS + 1).is_err());
        assert!(check("ws-b", &pk, "ws-a", "1000", "n1", "ws-b", &sig, 1000 + MAX_SKEW_SECS).is_ok());
    }

    #[test]
    fn tampered_field_or_wrong_key_is_refused() {
        let (k, pk) = keypair();
        let (_, other_pk) = keypair();
        let sig = signed(&k, "ws-a", 1000, "n1", "ws-b");
        // Claiming to be another node with A's signature.
        assert!(check("ws-b", &pk, "ws-x", "1000", "n1", "ws-b", &sig, 1000).is_err());
        // A's headers checked against someone else's pinned key.
        assert!(check("ws-b", &other_pk, "ws-a", "1000", "n1", "ws-b", &sig, 1000).is_err());
        // Garbage signature.
        assert!(check("ws-b", &pk, "ws-a", "1000", "n1", "ws-b", "AAAA", 1000).is_err());
    }

    #[test]
    fn nonce_replay_is_refused() {
        let t = now();
        assert!(nonce_fresh("test-nonce-unique-1", t));
        assert!(!nonce_fresh("test-nonce-unique-1", t));
    }

    #[test]
    fn host_of_url_handles_ipv6_and_ports() {
        assert_eq!(host_of_url("https://10.0.0.5:8553/api/x"), "10.0.0.5");
        assert_eq!(host_of_url("http://[fd00::1]:8554/api/x"), "fd00::1");
        assert_eq!(host_of_url("https://node.example:8553"), "node.example");
    }
}
