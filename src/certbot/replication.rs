// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Cluster replication of issued certificates.
//!
//! `/api/certs/cluster` already shows every cert on every node on one
//! screen, but deliberately never moved key material — so a cert issued
//! on node A was unusable by a WolfProxy on node B, which builds its
//! paths as `/etc/letsencrypt/live/<name>/fullchain.pem` and found
//! nothing there. This module is the opt-in that closes that gap.
//!
//! ## Shape
//!
//! One node OWNS a cert (it holds the certbot renewal config and is the
//! only node that talks to the ACME CA for it). Peers hold read-only
//! REPLICAS. Replicas are written as plain files into the same
//! `/etc/letsencrypt/live/<name>/` layout so every downstream consumer —
//! `list_certs`, WolfProxy, WolfHost — works unchanged.
//!
//! Crucially a replica gets **no `/etc/letsencrypt/renewal/<name>.conf`**,
//! and `certbot renew` iterates renewal configs, not `live/`. So a replica
//! is inert by construction: the peer can never try to renew someone
//! else's cert, and two nodes can never race the same lineage.
//!
//! ## Renewal re-replication
//!
//! The hard part. A cert can be renewed by WolfStack's API, by the daily
//! `certbot renew` task, by the distro's own systemd timer, or by an
//! operator running certbot by hand — most of those never tell WolfStack.
//! So replication is NOT event-driven off our own renew path. Instead the
//! owner periodically fingerprints each replicated cert and compares it
//! with what each peer reports holding; any difference is pushed. That
//! catches every renewal path including ones we don't control, and it
//! self-heals — a rebuilt peer reports nothing and receives everything.
//! The API renew/issue handlers additionally kick a reconcile immediately
//! so the operator sees it propagate without waiting for the timer.
//!
//! ## Opt-in
//!
//! Presence of a cert name in `ReplicationConfig::certs` IS the opt-in;
//! an empty list means the feature does nothing. There is deliberately no
//! separate master switch to drift out of sync with the per-cert list.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{reload_proxy, CertbotConfig, LE_LIVE_DIR};

/// Owner-side: which of this node's certs are pushed to peers.
const CONFIG_PATH: &str = "/etc/wolfstack/cert-replication.json";
/// Receiver-side: which certs on this node arrived from a peer.
const REPLICA_STATE_PATH: &str = "/etc/wolfstack/cert-replicas.json";
/// certbot's renewal configs. Presence of `<name>.conf` is what makes a
/// cert locally OWNED — the single fact that stops us overwriting a
/// peer's own certbot-managed lineage with a replica.
pub(super) const LE_RENEWAL_DIR: &str = "/etc/letsencrypt/renewal";

/// The four PEMs certbot puts in a lineage directory. `cert.pem` is
/// required by `list_certs` (it skips any directory without one), so a
/// replica that omitted it would be invisible in the UI.
const PEM_FILES: [&str; 4] = ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"];

// ─────────────────────────── config ───────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Cert names (certbot lineage names) this node replicates outward.
    #[serde(default)]
    pub certs: Vec<String>,
}

impl ReplicationConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(CONFIG_PATH, json)
            .map_err(|e| format!("write {}: {}", CONFIG_PATH, e))
    }

    pub fn is_replicated(&self, name: &str) -> bool {
        self.certs.iter().any(|c| c == name)
    }
}

// ──────────────────────── receiver state ────────────────────────

/// One replica held on this node. Kept so the UI can badge the row
/// ("Replica of ws-1") and refuse Renew, and so pruning knows which
/// owner a given replica came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaRecord {
    pub name: String,
    pub source_node_id: String,
    pub source_hostname: String,
    /// SHA-256 over fullchain+privkey — matched against the owner's to
    /// decide whether a push is needed.
    pub digest: String,
    pub received_at: String,
    pub expires: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicaStore {
    #[serde(default)]
    pub replicas: Vec<ReplicaRecord>,
}

impl ReplicaStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(REPLICA_STATE_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(REPLICA_STATE_PATH, json)
            .map_err(|e| format!("write {}: {}", REPLICA_STATE_PATH, e))
    }

    pub fn get(&self, name: &str) -> Option<&ReplicaRecord> {
        self.replicas.iter().find(|r| r.name == name)
    }

    pub fn is_replica(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    fn upsert(&mut self, rec: ReplicaRecord) {
        match self.replicas.iter_mut().find(|r| r.name == rec.name) {
            Some(existing) => *existing = rec,
            None => self.replicas.push(rec),
        }
    }
}

// ──────────────────────── wire format ────────────────────────

/// A cert in transit. Carries all four PEMs so the receiver reproduces
/// certbot's layout byte-for-byte rather than trying to re-derive
/// `chain` by splitting `fullchain`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBundle {
    pub name: String,
    pub cert_pem: String,
    pub chain_pem: String,
    pub fullchain_pem: String,
    pub privkey_pem: String,
    /// SHA-256 of fullchain+privkey, hex. Recomputed on receipt and
    /// compared — a mismatch means truncation or tampering in transit.
    pub digest: String,
    pub expires: String,
    pub source_node_id: String,
    pub source_hostname: String,
}

/// What a peer reports back so the owner can diff without shipping any
/// key material.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicaState {
    /// name → digest, for replicas this node currently holds.
    #[serde(default)]
    pub replicas: BTreeMap<String, String>,
    /// Lineage names this node OWNS (has a certbot renewal config for).
    /// The owner uses this to report a conflict rather than repeatedly
    /// failing to push.
    #[serde(default)]
    pub owned: Vec<String>,
}

// ──────────────────────── name safety ────────────────────────

/// A cert name arrives over the network and is joined onto
/// `/etc/letsencrypt/live/`, so it is a path-traversal vector. certbot
/// lineage names are the first `-d` domain with any `*.` prefix stripped
/// (`certbot/_internal/client.py:575-579`), so a strict host-label
/// allowlist covers every real name including wildcard lineages.
pub fn is_safe_cert_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "README"
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Resolve `<live>/<name>` and prove the result is still under `<live>`.
/// Belt-and-braces behind `is_safe_cert_name` — the allowlist already
/// makes traversal impossible, but this survives someone later relaxing
/// the allowlist without re-reasoning about the path join.
fn lineage_dir(name: &str) -> Result<PathBuf, String> {
    if !is_safe_cert_name(name) {
        return Err(format!("unsafe certificate name '{}'", name));
    }
    let base = Path::new(LE_LIVE_DIR);
    let dir = base.join(name);
    if dir.parent() != Some(base) {
        return Err(format!("certificate name '{}' escapes {}", name, LE_LIVE_DIR));
    }
    Ok(dir)
}

/// True when certbot owns this lineage on THIS node.
pub fn is_locally_owned(name: &str) -> bool {
    if !is_safe_cert_name(name) {
        return false;
    }
    Path::new(LE_RENEWAL_DIR).join(format!("{}.conf", name)).exists()
}

// ──────────────────────── digest + read ────────────────────────

/// SHA-256 over the chain and the key, length-prefixed.
///
/// The length prefix is not decoration: hashing the two fields
/// concatenated makes `("ab", "c")` and `("a", "bc")` collide, so a byte
/// notionally moving from one field to the other would leave the digest
/// unchanged and the reconcile would report "in sync" for content that
/// isn't. Domain-separating the fields removes the whole class.
///
/// Digests are only ever compared between nodes, never persisted as a
/// migration-sensitive value — a mismatch simply triggers a re-push — so
/// changing this formula costs nothing beyond one extra push per cert.
pub fn digest_of(fullchain: &str, privkey: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((fullchain.len() as u64).to_le_bytes());
    h.update(fullchain.as_bytes());
    h.update((privkey.len() as u64).to_le_bytes());
    h.update(privkey.as_bytes());
    hex::encode(h.finalize())
}

/// Read a lineage off disk into a bundle ready to push.
pub fn read_bundle(name: &str, source_node_id: &str, source_hostname: &str) -> Result<CertBundle, String> {
    let dir = lineage_dir(name)?;
    let mut pems: BTreeMap<&str, String> = BTreeMap::new();
    for f in PEM_FILES {
        // read_to_string follows certbot's live/ symlinks into archive/,
        // so this works for a normally-issued cert as well as a replica.
        let p = dir.join(f);
        let body = std::fs::read_to_string(&p)
            .map_err(|e| format!("read {}: {}", p.display(), e))?;
        if body.trim().is_empty() {
            return Err(format!("{} is empty", p.display()));
        }
        pems.insert(f, body);
    }
    let fullchain = pems["fullchain.pem"].clone();
    let privkey = pems["privkey.pem"].clone();
    let (_domains, expires, _days) = super::probe_cert(&dir.join("cert.pem"));
    Ok(CertBundle {
        name: name.to_string(),
        cert_pem: pems["cert.pem"].clone(),
        chain_pem: pems["chain.pem"].clone(),
        digest: digest_of(&fullchain, &privkey),
        fullchain_pem: fullchain,
        privkey_pem: privkey,
        expires,
        source_node_id: source_node_id.to_string(),
        source_hostname: source_hostname.to_string(),
    })
}

/// Report what this node holds, for an owner to diff against.
pub fn local_state() -> ReplicaState {
    let store = ReplicaStore::load();
    let mut replicas = BTreeMap::new();
    for r in &store.replicas {
        // Trust the FILES, not the recorded digest — if an operator
        // hand-edited or restored a lineage the stored digest would be
        // stale and we'd wrongly report "in sync" forever.
        match lineage_dir(&r.name) {
            Ok(dir) => {
                let fc = std::fs::read_to_string(dir.join("fullchain.pem")).unwrap_or_default();
                let pk = std::fs::read_to_string(dir.join("privkey.pem")).unwrap_or_default();
                if fc.is_empty() || pk.is_empty() {
                    continue; // gone from disk → owner re-pushes
                }
                replicas.insert(r.name.clone(), digest_of(&fc, &pk));
            }
            Err(_) => continue,
        }
    }
    let owned = super::list_certs()
        .into_iter()
        .map(|c| c.name)
        .filter(|n| is_locally_owned(n))
        .collect();
    ReplicaState { replicas, owned }
}

// ──────────────────────── receiver: apply ────────────────────────

pub struct Applied {
    pub changed: bool,
}

/// Serialises the load-modify-save of the replica store.
///
/// Two peers can push different certs at the same moment; without this
/// both would `load()` the same snapshot and the second `save()` would
/// drop the first's record. The files would still be on disk, so the
/// symptom is subtle: `local_state` stops reporting that cert, the owner
/// re-pushes it every pass, `apply_bundle` sees the bytes already match
/// and reports `changed: false` — a push loop that never converges.
static STORE_LOCK: Mutex<()> = Mutex::new(());

/// Write an incoming bundle into `/etc/letsencrypt/live/<name>/`.
///
/// Refuses when the lineage is locally owned — overwriting a peer's own
/// certbot-managed cert (and its private key) with a replica would be
/// destructive and would then fight that node's own renewals.
pub fn apply_bundle(bundle: &CertBundle) -> Result<Applied, String> {
    let dir = lineage_dir(&bundle.name)?;

    if is_locally_owned(&bundle.name) {
        return Err(format!(
            "'{}' is issued and renewed by THIS node (certbot renewal config present) — \
             refusing to overwrite it with a replica from {}. Stop replicating this cert \
             from the other node, or delete the local lineage first.",
            bundle.name, bundle.source_hostname
        ));
    }

    // Integrity: the digest is computed over the same two PEMs on both
    // ends, so a mismatch means the payload didn't survive the trip.
    let actual = digest_of(&bundle.fullchain_pem, &bundle.privkey_pem);
    if actual != bundle.digest {
        return Err(format!(
            "digest mismatch for '{}' (sent {}, computed {}) — payload corrupt, not written",
            bundle.name, bundle.digest, actual
        ));
    }
    validate_pem(&bundle.cert_pem, "CERTIFICATE", "cert.pem")?;
    validate_pem(&bundle.fullchain_pem, "CERTIFICATE", "fullchain.pem")?;
    validate_private_key(&bundle.privkey_pem)?;

    // Unchanged? Do nothing — this keeps the reconcile loop from
    // rewriting files and reloading the proxy on every pass.
    let existing_fc = std::fs::read_to_string(dir.join("fullchain.pem")).unwrap_or_default();
    let existing_pk = std::fs::read_to_string(dir.join("privkey.pem")).unwrap_or_default();
    if !existing_fc.is_empty()
        && !existing_pk.is_empty()
        && digest_of(&existing_fc, &existing_pk) == bundle.digest
    {
        return Ok(Applied { changed: false });
    }

    // Held across the file writes AND the store update so a concurrent
    // push for another cert can't interleave and lose this record.
    // Everything below is plain blocking IO on one thread — no await —
    // so a std Mutex is the right tool here.
    let _guard = STORE_LOCK.lock().map_err(|e| format!("replica store lock: {e}"))?;

    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;

    // privkey stays 0600; the public halves are 0644 so a non-root
    // proxy worker can still read the chain, matching certbot's own
    // permissions on live/.
    write_pem(&dir.join("privkey.pem"), &bundle.privkey_pem, 0o600)?;
    write_pem(&dir.join("cert.pem"), &bundle.cert_pem, 0o644)?;
    write_pem(&dir.join("chain.pem"), &bundle.chain_pem, 0o644)?;
    write_pem(&dir.join("fullchain.pem"), &bundle.fullchain_pem, 0o644)?;

    let mut store = ReplicaStore::load();
    store.upsert(ReplicaRecord {
        name: bundle.name.clone(),
        source_node_id: bundle.source_node_id.clone(),
        source_hostname: bundle.source_hostname.clone(),
        digest: bundle.digest.clone(),
        received_at: chrono::Utc::now().to_rfc3339(),
        expires: bundle.expires.clone(),
    });
    store.save()?;

    Ok(Applied { changed: true })
}

/// Drop replicas that came from `source_node_id` and are no longer in
/// its replicate list — i.e. the operator turned replication off for
/// that cert, or deleted it on the owner.
///
/// Only ever touches lineages recorded as replicas FROM THAT OWNER, so
/// it can't delete a locally-issued cert or another node's replica.
pub fn prune(source_node_id: &str, keep: &[String]) -> Result<Vec<String>, String> {
    let _guard = STORE_LOCK.lock().map_err(|e| format!("replica store lock: {e}"))?;
    let mut store = ReplicaStore::load();
    let doomed = doomed_names(&store, source_node_id, keep);
    if doomed.is_empty() {
        return Ok(Vec::new());
    }
    let mut removed = Vec::new();
    for name in &doomed {
        // Paranoia: never remove a lineage that has since become locally
        // owned (operator issued their own cert with the same name).
        if is_locally_owned(name) {
            continue;
        }
        if let Ok(dir) = lineage_dir(name) {
            let _ = std::fs::remove_dir_all(&dir);
        }
        removed.push(name.clone());
    }
    store
        .replicas
        .retain(|r| !removed.iter().any(|n| n == &r.name));
    store.save()?;
    Ok(removed)
}

/// Which replicas from `source_node_id` are no longer wanted.
///
/// Split out of `prune` deliberately: this is the function that
/// authorises `remove_dir_all` on a certificate directory, so the
/// selection rule gets direct tests rather than being reachable only
/// through code that touches the real filesystem.
fn doomed_names(store: &ReplicaStore, source_node_id: &str, keep: &[String]) -> Vec<String> {
    store
        .replicas
        .iter()
        .filter(|r| r.source_node_id == source_node_id && !keep.iter().any(|k| k == &r.name))
        .map(|r| r.name.clone())
        .collect()
}

/// Reload the proxy so a freshly written replica is actually served.
pub fn reload_after_replica() {
    let cfg = CertbotConfig::load();
    if let Err(e) = reload_proxy(&cfg) {
        tracing::warn!("cert replication: proxy reload failed: {}", e);
    }
}

// ──────────────────────── helpers ────────────────────────

fn write_pem(path: &Path, body: &str, mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Write to a temp file in the same directory then rename, so a
    // reader (nginx reloading) never sees a half-written key.
    let tmp = path.with_extension("tmp-wolfstack");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("open {}: {}", tmp.display(), e))?;
        f.write_all(body.as_bytes())
            .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
        f.sync_all().map_err(|e| format!("sync {}: {}", tmp.display(), e))?;
    }
    // mode= is ignored when the temp file already existed, so enforce.
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename into {}: {}", path.display(), e))?;
    Ok(())
}

fn validate_pem(body: &str, label: &str, what: &str) -> Result<(), String> {
    let begin = format!("-----BEGIN {}-----", label);
    if !body.contains(&begin) {
        return Err(format!("{} does not contain a PEM {} block", what, label));
    }
    Ok(())
}

/// Accept any of the private-key PEM spellings certbot may emit (RSA,
/// EC, or PKCS#8) rather than pinning one and rejecting valid keys.
fn validate_private_key(body: &str) -> Result<(), String> {
    const LABELS: [&str; 3] = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];
    if LABELS.iter().any(|l| body.contains(&format!("-----BEGIN {}-----", l))) {
        Ok(())
    } else {
        Err("privkey.pem does not contain a PEM private key block".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_names() {
        for bad in [
            "../../etc/shadow",
            "..",
            ".",
            "a/b",
            "/etc/passwd",
            ".hidden",
            "README",
            "",
            "name with space",
            "semi;colon",
            "star*glob",
            "back\\slash",
            "new\nline",
        ] {
            assert!(!is_safe_cert_name(bad), "should reject {:?}", bad);
            assert!(lineage_dir(bad).is_err(), "lineage_dir should reject {:?}", bad);
        }
    }

    #[test]
    fn accepts_real_certbot_lineage_names() {
        // Plain host, wildcard lineage (certbot strips the "*." prefix),
        // certbot's -0001 suffix, and an underscore label.
        for good in [
            "wolfstack-1.wolf.uk.com",
            "wolf.uk.com",
            "example.com-0001",
            "my_cert",
            "a",
        ] {
            assert!(is_safe_cert_name(good), "should accept {:?}", good);
            let dir = lineage_dir(good).expect("safe name resolves");
            assert!(dir.starts_with(LE_LIVE_DIR), "{:?} escaped live dir", dir);
        }
    }

    #[test]
    fn digest_covers_both_key_and_chain() {
        let a = digest_of("chain-a", "key-1");
        assert_eq!(a, digest_of("chain-a", "key-1"), "must be stable");
        assert_ne!(a, digest_of("chain-b", "key-1"), "chain change must show");
        assert_ne!(a, digest_of("chain-a", "key-2"), "key change must show");
    }

    #[test]
    fn digest_is_not_confusable_by_field_shifting() {
        // Concatenating without a separator would make ("ab","c") and
        // ("a","bc") collide; assert they don't.
        assert_ne!(digest_of("ab", "c"), digest_of("a", "bc"));
    }

    #[test]
    fn private_key_labels_accepted() {
        for l in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
            let pem = format!("-----BEGIN {}-----\nx\n-----END {}-----\n", l, l);
            assert!(validate_private_key(&pem).is_ok(), "should accept {}", l);
        }
        assert!(validate_private_key("-----BEGIN CERTIFICATE-----").is_err());
        assert!(validate_private_key("").is_err());
    }

    #[test]
    fn pem_validation_rejects_wrong_block() {
        assert!(validate_pem("-----BEGIN CERTIFICATE-----", "CERTIFICATE", "cert.pem").is_ok());
        assert!(validate_pem("not a pem", "CERTIFICATE", "cert.pem").is_err());
    }

    #[test]
    fn replication_config_opt_in_is_the_list() {
        let mut cfg = ReplicationConfig::default();
        assert!(cfg.certs.is_empty(), "feature is off by default");
        assert!(!cfg.is_replicated("wolf.uk.com"));
        cfg.certs.push("wolf.uk.com".into());
        assert!(cfg.is_replicated("wolf.uk.com"));
        assert!(!cfg.is_replicated("other.com"));
    }

    fn rec(name: &str, owner: &str) -> ReplicaRecord {
        ReplicaRecord {
            name: name.into(),
            source_node_id: owner.into(),
            source_hostname: format!("host-{}", owner),
            digest: "d".into(),
            received_at: "t".into(),
            expires: "e".into(),
        }
    }

    #[test]
    fn prune_only_targets_the_asking_owners_replicas() {
        let store = ReplicaStore {
            replicas: vec![rec("a.com", "n1"), rec("b.com", "n1"), rec("c.com", "n2")],
        };
        // n1 still wants a.com — so only b.com goes, and n2's c.com is
        // untouched even though n1 never mentioned it.
        let doomed = doomed_names(&store, "n1", &["a.com".to_string()]);
        assert_eq!(doomed, vec!["b.com".to_string()]);
    }

    #[test]
    fn prune_with_empty_keep_drops_all_of_that_owners_replicas_only() {
        let store = ReplicaStore {
            replicas: vec![rec("a.com", "n1"), rec("b.com", "n1"), rec("c.com", "n2")],
        };
        let doomed = doomed_names(&store, "n1", &[]);
        assert_eq!(doomed, vec!["a.com".to_string(), "b.com".to_string()]);
        assert!(!doomed.contains(&"c.com".to_string()), "must never touch another owner's replica");
    }

    #[test]
    fn prune_is_a_noop_when_everything_is_still_wanted() {
        let store = ReplicaStore { replicas: vec![rec("a.com", "n1")] };
        assert!(doomed_names(&store, "n1", &["a.com".to_string()]).is_empty());
        // An owner we hold nothing from can't cause deletions either.
        assert!(doomed_names(&store, "unknown-node", &[]).is_empty());
    }

    #[test]
    fn replica_store_upsert_replaces_not_duplicates() {
        let mut s = ReplicaStore::default();
        let mk = |d: &str| ReplicaRecord {
            name: "x.com".into(),
            source_node_id: "n1".into(),
            source_hostname: "ws-1".into(),
            digest: d.into(),
            received_at: "now".into(),
            expires: "later".into(),
        };
        s.upsert(mk("aaa"));
        s.upsert(mk("bbb"));
        assert_eq!(s.replicas.len(), 1, "same name must not duplicate");
        assert_eq!(s.get("x.com").unwrap().digest, "bbb");
        assert!(s.is_replica("x.com"));
        assert!(!s.is_replica("y.com"));
    }
}
