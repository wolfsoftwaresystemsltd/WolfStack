// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Root SSH authorised-key management for the host, plus the one
//! definition of "what is an SSH public key" that every surface
//! shares.
//!
//! ## Why this module exists
//!
//! Three places needed to recognise a public key — the hosting
//! portal's customer-facing add form, the tamper detector's drift
//! analysis, and this host-level manager. Three copies of the
//! accepted-type list would drift apart, and the two that disagreed
//! would disagree silently. One definition, three callers.
//!
//! ## The reseed contract
//!
//! Every mutation here re-anchors the tamper-detection baseline for
//! `/root/.ssh/authorized_keys` in the same operation. That is the
//! whole point of routing key changes through WolfStack: a change
//! made *through* the tool is never drift, so `predictive::
//! tamper_detection` never has to guess whether the operator meant
//! it. What that detector still flags is, by construction, an
//! out-of-band edit — which is exactly the thing worth alarming on.
//!
//! ## Injection safety
//!
//! authorized_keys is line-oriented, so a newline smuggled into a
//! key or its label would append an attacker-chosen second entry —
//! including one carrying `command=` options. Nothing the caller
//! supplies is written verbatim: `validate` parses the input into
//! (type, blob, comment) and every write rebuilds the line from
//! those parsed fields.

use serde::{Deserialize, Serialize};

/// The file this module owns. Root's keys only — the same path
/// `predictive::tamper_detection::ROOT_AUTHORIZED_KEYS` watches, so
/// the two stay in lockstep.
pub const ROOT_AUTHORIZED_KEYS: &str = "/root/.ssh/authorized_keys";
const ROOT_SSH_DIR: &str = "/root/.ssh";

/// Key types WolfStack accepts, everywhere. Kept identical to what
/// the hosting portal validates on paste so a key that works for a
/// container also works for a host.
/// Source: wolfhost/portal/ssh_keys.rs:45-49 (add handler validation).
///
/// Deliberately excluded: OpenSSH certificate types
/// (`ssh-rsa-cert-v01@openssh.com`), `cert-authority` and
/// `principals=` lines. They delegate trust rather than name one
/// key, and nothing in WolfStack issues or tracks SSH CAs.
pub fn is_public_key_type(t: &str) -> bool {
    t == "ssh-rsa"
        || t == "ssh-ed25519"
        || t == "ssh-dss"
        || t.starts_with("ecdsa-")
        || t.starts_with("sk-")
}

/// One parsed authorized_keys entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub key_type: String,
    /// Base64 blob, verified decodable.
    pub blob: String,
    /// Trailing comment/label. May be empty.
    pub comment: String,
}

impl PublicKey {
    /// Render as a single authorized_keys line. Built from parsed
    /// fields only — never from caller-supplied text.
    pub fn to_line(&self) -> String {
        if self.comment.is_empty() {
            format!("{} {}", self.key_type, self.blob)
        } else {
            format!("{} {} {}", self.key_type, self.blob, self.comment)
        }
    }

    /// Hex SHA-256 of the decoded blob. Same convention the hosting
    /// portal displays for a container's keys, so an operator can
    /// match a host key and a container key by eye.
    /// Source: wolfhost/provisioning/native_tools.rs:924-933 key_fingerprint().
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.blob).unwrap_or_default()
    }
}

/// Hex SHA-256 of a decoded key blob. `None` when the blob isn't
/// valid base64 — which means it isn't a usable key either.
pub fn fingerprint(blob: &str) -> Option<String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(blob).ok()?;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&raw);
    Some(format!("{:x}", h.finalize()))
}

/// Parse one authorized_keys line. `None` for blanks, comments, and
/// anything that isn't a bare `<type> <blob> [comment]` — notably
/// options-carrying lines (`command="…" ssh-rsa …`), which are
/// deliberately out of scope rather than silently mangled.
pub fn parse_line(line: &str) -> Option<PublicKey> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let mut parts = t.split_whitespace();
    let key_type = parts.next()?;
    let blob = parts.next()?;
    if !is_public_key_type(key_type) || blob.is_empty() {
        return None;
    }
    // Must decode, or it's not a key we can fingerprint or trust.
    fingerprint(blob)?;
    Some(PublicKey {
        key_type: key_type.to_string(),
        blob: blob.to_string(),
        comment: parts.collect::<Vec<_>>().join(" "),
    })
}

/// Strip characters that have no business in a label. Purely
/// cosmetic — the injection-relevant case (control characters) is
/// rejected outright by `validate` rather than silently flattened,
/// so the operator finds out instead of ending up with a key whose
/// comment quietly swallowed half their input.
fn sanitize_comment(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | ' '))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Validate pasted key material for the add path. `label`, when
/// non-empty, replaces whatever comment the pasted key carried so
/// the operator's naming wins.
pub fn validate(public_key: &str, label: &str) -> Result<PublicKey, String> {
    let trimmed = public_key.trim();
    if trimmed.is_empty() {
        return Err("Public key is empty".into());
    }
    if trimmed.lines().count() > 1 {
        return Err("Paste a single public key — multi-line input is not accepted".into());
    }
    let mut key = parse_line(trimmed).ok_or_else(|| {
        "Not a valid OpenSSH public key. Expected `<type> <base64> [comment]` with a type of \
         ssh-rsa, ssh-ed25519, ssh-dss, ecdsa-… or sk-… (certificate and options-carrying \
         lines are not supported)."
            .to_string()
    })?;
    // A newline in the label is the one input that could append an
    // entry the operator never approved. Refuse it by name rather
    // than flattening it into a comment that silently contains
    // someone else's key material.
    if label.chars().any(|c| c.is_control()) {
        return Err("Label must not contain line breaks or control characters".into());
    }
    let label = sanitize_comment(label);
    if !label.is_empty() {
        key.comment = label;
    } else {
        key.comment = sanitize_comment(&key.comment);
    }
    Ok(key)
}

/// One key as reported to the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKey {
    /// Hex SHA-256 of the decoded blob. Stable across nodes, so it
    /// doubles as the identifier for fleet-wide removal.
    pub fingerprint: String,
    pub key_type: String,
    pub comment: String,
}

/// What `add_root_key` did. Distinguished so a fleet add across
/// nodes that already hold the key reports "unchanged" rather than
/// a misleading "added" or an outright failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    AlreadyPresent,
}

fn read_authorized_keys() -> Result<String, String> {
    match std::fs::read_to_string(ROOT_AUTHORIZED_KEYS) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("read {}: {}", ROOT_AUTHORIZED_KEYS, e)),
    }
}

/// Replace authorized_keys atomically, then re-anchor the tamper
/// baseline so this change never reads as drift.
///
/// The temp file is created in the same directory (rename across
/// filesystems fails) and carries the final mode BEFORE the rename,
/// so the file is never briefly world-readable.
fn write_authorized_keys(content: &str, actor: &str, reason: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(ROOT_SSH_DIR)
        .map_err(|e| format!("create {}: {}", ROOT_SSH_DIR, e))?;
    let _ = std::fs::set_permissions(ROOT_SSH_DIR, std::fs::Permissions::from_mode(0o700));

    let tmp = format!("{}.wolfstack.tmp", ROOT_AUTHORIZED_KEYS);
    std::fs::write(&tmp, content).map_err(|e| format!("write {}: {}", tmp, e))?;
    if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("chmod {}: {}", tmp, e));
    }
    if let Err(e) = std::fs::rename(&tmp, ROOT_AUTHORIZED_KEYS) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename into place: {}", e));
    }

    // Re-anchor the baseline. A failure here is NOT fatal to the key
    // change (the key is already live and the operator asked for it),
    // but it does mean tamper detection will flag this edit, so it is
    // surfaced loudly rather than swallowed.
    if let Err(e) = crate::predictive::baselines::reseed(ROOT_AUTHORIZED_KEYS, actor, reason) {
        tracing::error!(
            "ssh_keys: {} updated but baseline reseed FAILED ({}). Tamper detection will \
             report this as drift until the baseline is re-anchored.",
            ROOT_AUTHORIZED_KEYS, e,
        );
        return Err(format!(
            "Key change applied, but re-anchoring the tamper baseline failed: {}. \
             The change is live; tamper detection will flag it until you reseed.",
            e
        ));
    }
    Ok(())
}

/// Every key currently authorised for root on this host.
///
/// Lines this module can't parse (options-carrying entries, CA
/// delegations, junk) are counted but not returned — they're
/// reported separately so the UI can say "2 entries not shown"
/// instead of pretending the file holds only what it lists.
pub fn list_root_keys() -> Result<(Vec<HostKey>, usize), String> {
    let body = read_authorized_keys()?;
    let mut keys = Vec::new();
    let mut unmanaged = 0usize;
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match parse_line(t) {
            Some(k) => keys.push(HostKey {
                fingerprint: k.fingerprint(),
                key_type: k.key_type,
                comment: k.comment,
            }),
            None => unmanaged += 1,
        }
    }
    Ok((keys, unmanaged))
}

/// Compute the new file contents after adding `key`. `None` means
/// the key is already authorised and the file must be left untouched.
///
/// Pure so the append rules — dedup by fingerprint, and the
/// missing-trailing-newline case — are testable without a real
/// /root/.ssh on the machine running the tests.
fn apply_add(existing: &str, key: &PublicKey) -> Option<String> {
    let fp = key.fingerprint();
    if existing.lines().filter_map(parse_line).any(|k| k.fingerprint() == fp) {
        return None;
    }
    // Preserve the file byte-for-byte and append. A file not ending
    // in a newline would otherwise splice our key type onto the
    // previous entry's comment and silently corrupt both.
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&key.to_line());
    out.push('\n');
    Some(out)
}

/// Compute the new file contents after removing the key whose
/// fingerprint starts with `fingerprint`. Returns the new contents,
/// the key that was removed, and how many managed keys remain — the
/// caller needs that count for the lockout guard.
///
/// Blank lines, comments and entries this module doesn't manage are
/// preserved verbatim: this removes one key, it does not tidy the
/// operator's file.
fn apply_remove(
    existing: &str,
    fingerprint: &str,
) -> Result<(String, PublicKey, usize), String> {
    let mut kept: Vec<String> = Vec::new();
    let mut removed: Option<PublicKey> = None;
    let mut remaining_keys = 0usize;
    for line in existing.lines() {
        match parse_line(line) {
            Some(k) if k.fingerprint().starts_with(fingerprint) && removed.is_none() => {
                removed = Some(k);
            }
            Some(_) => {
                remaining_keys += 1;
                kept.push(line.to_string());
            }
            None => kept.push(line.to_string()),
        }
    }
    let removed = removed.ok_or_else(|| "No key with that fingerprint on this host".to_string())?;
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok((out, removed, remaining_keys))
}

/// Authorise `key` for root. Idempotent: a key already present is
/// reported as `AlreadyPresent` and the file is left untouched.
pub fn add_root_key(key: &PublicKey, actor: &str) -> Result<AddOutcome, String> {
    let fp = key.fingerprint();
    if fp.is_empty() {
        return Err("Key blob could not be fingerprinted".into());
    }
    let body = read_authorized_keys()?;
    let Some(out) = apply_add(&body, key) else {
        return Ok(AddOutcome::AlreadyPresent);
    };

    write_authorized_keys(
        &out,
        actor,
        &format!("SSH key added via WolfStack ({})", short_fp(&fp)),
    )?;
    tracing::info!(
        "ssh_keys: authorised {} {} for root (by {})",
        key.key_type, short_fp(&fp), actor,
    );
    Ok(AddOutcome::Added)
}

/// De-authorise the key with this fingerprint.
///
/// Refuses to remove the last remaining key when password
/// authentication is off, because that combination locks every
/// operator out of the host permanently and a fleet-wide remove
/// would do it to every node at once. `force` overrides, for the
/// operator who genuinely has console access.
pub fn remove_root_key(fingerprint: &str, actor: &str, force: bool) -> Result<(), String> {
    if fingerprint.is_empty() || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid key fingerprint".into());
    }
    let fingerprint = fingerprint.to_ascii_lowercase();
    let body = read_authorized_keys()?;
    let (out, removed, remaining_keys) = apply_remove(&body, &fingerprint)?;

    if remaining_keys == 0 && !force {
        let password_auth =
            crate::security::sshd_effective("passwordauthentication").as_deref() == Some("yes");
        if !password_auth {
            return Err(
                "REFUSED: this is the last authorised key and password authentication is \
                 disabled, so removing it would permanently lock you out of this host. Add \
                 another key first, enable password authentication, or re-run with force."
                    .into(),
            );
        }
    }

    write_authorized_keys(
        &out,
        actor,
        &format!("SSH key removed via WolfStack ({})", short_fp(&removed.fingerprint())),
    )?;
    tracing::warn!(
        "ssh_keys: de-authorised {} {} for root (by {})",
        removed.key_type, short_fp(&removed.fingerprint()), actor,
    );
    Ok(())
}

/// Display form of a fingerprint — full hex is 64 characters and
/// unreadable in a log line.
pub fn short_fp(fp: &str) -> String {
    fp.chars().take(16).collect()
}

/// Effective sshd settings that decide whether keys actually work.
/// Surfaced with the key list so the UI can warn when the operator
/// is adding keys to a host that won't accept them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshdKeyPosture {
    pub pubkey_authentication: bool,
    pub password_authentication: bool,
    pub permit_root_login: String,
}

pub fn sshd_key_posture() -> SshdKeyPosture {
    SshdKeyPosture {
        // Absent from `sshd -T` output means we couldn't read the
        // effective config; assume the permissive default rather than
        // showing a scary warning we can't substantiate.
        pubkey_authentication: crate::security::sshd_effective("pubkeyauthentication")
            .as_deref()
            != Some("no"),
        password_authentication: crate::security::sshd_effective("passwordauthentication")
            .as_deref()
            == Some("yes"),
        permit_root_login: crate::security::sshd_effective("permitrootlogin")
            .unwrap_or_else(|| "unknown".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(seed: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(seed.as_bytes())
    }

    #[test]
    fn parses_a_plain_key() {
        let line = format!("ssh-ed25519 {} paul@wolf", blob("k1"));
        let k = parse_line(&line).expect("plain key parses");
        assert_eq!(k.key_type, "ssh-ed25519");
        assert_eq!(k.comment, "paul@wolf");
        assert_eq!(k.to_line(), line);
    }

    #[test]
    fn parses_key_without_comment() {
        let line = format!("ssh-rsa {}", blob("k1"));
        let k = parse_line(&line).expect("comment is optional");
        assert_eq!(k.comment, "");
        assert_eq!(k.to_line(), line);
    }

    #[test]
    fn rejects_options_carrying_and_malformed_lines() {
        assert!(parse_line(&format!("command=\"/bin/sh\" ssh-rsa {} x", blob("k"))).is_none());
        assert!(parse_line("ssh-rsa !!!not-base64!!! x").is_none());
        assert!(parse_line("ssh-rsa").is_none());
        assert!(parse_line("# a comment").is_none());
        assert!(parse_line("   ").is_none());
        assert!(parse_line(&format!("ssh-rsa-cert-v01@openssh.com {} x", blob("k"))).is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_type_independent() {
        let a = parse_line(&format!("ssh-ed25519 {} one", blob("same"))).unwrap();
        let b = parse_line(&format!("ssh-ed25519 {} two", blob("same"))).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint(),
            "the comment is a label — it must not change a key's identity");
        let c = parse_line(&format!("ssh-ed25519 {} one", blob("different"))).unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn validate_label_overrides_pasted_comment() {
        let pasted = format!("ssh-ed25519 {} laptop@home", blob("k1"));
        let k = validate(&pasted, "ci-deploy").unwrap();
        assert_eq!(k.comment, "ci-deploy");
    }

    #[test]
    fn validate_keeps_pasted_comment_when_label_is_blank() {
        let pasted = format!("ssh-ed25519 {} laptop@home", blob("k1"));
        let k = validate(&pasted, "").unwrap();
        assert_eq!(k.comment, "laptop@home");
    }

    #[test]
    fn validate_rejects_newline_injection_in_the_label() {
        // Unrejected, this label is the one input that could append a
        // SECOND authorised key the operator never approved.
        let pasted = format!("ssh-ed25519 {} x", blob("k1"));
        let evil = format!("mine\nssh-rsa {} attacker", blob("evil"));
        let err = validate(&pasted, &evil).expect_err("newline in a label must be refused");
        assert!(err.contains("line breaks"), "error should name the cause: {}", err);
    }

    #[test]
    fn rendered_lines_are_always_single_line() {
        // Belt and braces on the property that actually matters: no
        // accepted input may produce more than one authorized_keys
        // entry, whatever it contained.
        let pasted = format!("ssh-ed25519 {} x", blob("k1"));
        for label in ["ok", "with spaces", "quote\"and=equals", "tab\there"] {
            if let Ok(k) = validate(&pasted, label) {
                assert_eq!(k.to_line().lines().count(), 1, "label {:?} split the line", label);
                assert!(!k.to_line().contains('"'), "label {:?} kept a quote", label);
            }
        }
    }

    #[test]
    fn validate_rejects_multi_line_and_empty_input() {
        let two = format!("ssh-ed25519 {} a\nssh-rsa {} b", blob("k1"), blob("k2"));
        assert!(validate(&two, "").is_err());
        assert!(validate("   ", "").is_err());
        assert!(validate("not-a-key at all", "").is_err());
    }

    // ── file-content rules ───────────────────────────────────────
    //
    // apply_add / apply_remove are split out from the I/O precisely
    // so these run without a real /root/.ssh on the test machine.

    fn key(seed: &str, comment: &str) -> PublicKey {
        parse_line(&format!("ssh-ed25519 {} {}", blob(seed), comment)).unwrap()
    }

    #[test]
    fn add_appends_when_file_has_no_trailing_newline() {
        // Without the newline fix-up this splices the new key type
        // onto the previous entry's comment and corrupts both.
        let existing = format!("ssh-rsa {} first", blob("a"));
        let out = apply_add(&existing, &key("b", "second")).expect("new key is added");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("first"));
        assert!(lines[1].contains("second"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn add_to_empty_file_produces_one_line() {
        let out = apply_add("", &key("a", "only")).expect("added");
        assert_eq!(out.lines().count(), 1);
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn add_is_idempotent_on_fingerprint_not_comment() {
        let existing = format!("ssh-ed25519 {} original-label\n", blob("a"));
        // Same key material, different label — still the same key, so
        // re-adding must not create a duplicate grant.
        assert!(apply_add(&existing, &key("a", "different-label")).is_none());
        assert!(apply_add(&existing, &key("b", "other")).is_some());
    }

    #[test]
    fn remove_preserves_comments_blanks_and_unmanaged_entries() {
        let existing = format!(
            "# team keys\n\nssh-ed25519 {} keep\nssh-ed25519 {} drop\ncommand=\"/bin/sh\" ssh-rsa {} restricted\n",
            blob("a"), blob("b"), blob("c"),
        );
        let target = fingerprint(&blob("b")).unwrap();
        let (out, removed, remaining) = apply_remove(&existing, &target).unwrap();
        assert_eq!(removed.comment, "drop");
        assert_eq!(remaining, 1, "only the other managed key remains");
        assert!(out.contains("# team keys"), "comments must survive");
        assert!(out.contains("restricted"), "unmanaged entries must survive");
        assert!(out.contains("keep"));
        assert!(!out.contains(&blob("b")), "the removed key must be gone");
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn remove_accepts_a_shortened_fingerprint() {
        let existing = format!("ssh-ed25519 {} one\n", blob("a"));
        let short = short_fp(&fingerprint(&blob("a")).unwrap());
        let (_, removed, remaining) = apply_remove(&existing, &short).unwrap();
        assert_eq!(removed.comment, "one");
        assert_eq!(remaining, 0, "caller needs this to trigger the lockout guard");
    }

    #[test]
    fn remove_reports_a_missing_key_rather_than_silently_succeeding() {
        let existing = format!("ssh-ed25519 {} one\n", blob("a"));
        let err = apply_remove(&existing, &fingerprint(&blob("zzz")).unwrap()).unwrap_err();
        assert!(err.contains("No key with that fingerprint"),
            "the fleet summary keys off this exact wording: {}", err);
    }

    #[test]
    fn remove_takes_only_the_first_match() {
        // A file listing the same key twice loses one entry per call,
        // never both — the caller's count stays truthful.
        let existing = format!("ssh-ed25519 {} a\nssh-ed25519 {} a\n", blob("a"), blob("a"));
        let (out, _, remaining) = apply_remove(&existing, &fingerprint(&blob("a")).unwrap()).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert_eq!(remaining, 1);
    }

    #[test]
    fn removing_the_only_key_empties_the_file_cleanly() {
        let existing = format!("ssh-ed25519 {} one\n", blob("a"));
        let (out, _, remaining) = apply_remove(&existing, &fingerprint(&blob("a")).unwrap()).unwrap();
        assert_eq!(out, "", "no stray newline left behind");
        assert_eq!(remaining, 0);
    }

    #[test]
    fn accepted_types_match_the_portal_validator() {
        // Source: wolfhost/portal/ssh_keys.rs:45-49
        assert!(is_public_key_type("ssh-rsa"));
        assert!(is_public_key_type("ssh-ed25519"));
        assert!(is_public_key_type("ssh-dss"));
        assert!(is_public_key_type("ecdsa-sha2-nistp256"));
        assert!(is_public_key_type("sk-ssh-ed25519@openssh.com"));
        assert!(!is_public_key_type("command=\"/bin/sh\""));
        assert!(!is_public_key_type("ssh-rsa-ish"));
    }
}
