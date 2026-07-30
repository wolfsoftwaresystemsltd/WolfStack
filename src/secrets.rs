// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Redaction of credential-bearing fields in JSON that leaves this process.
//!
//! `/etc/wolfstack/backups.json` shipped 0644 root:root with `pbs_password`
//! in cleartext, so any local user could read the backup server's password —
//! and the same cleartext was copied into every daily snapshot under
//! `/etc/wolfstack/config-backups/` (production report, 3-node "wolf" cluster,
//! 2026-07-30). Permissions are fixed at the writer (`paths::write_secure`) and
//! for existing installs by `paths::harden_existing`; this module handles the
//! other half — never handing the values to a browser, an export, or a log line
//! in the first place.
//!
//! Matching is by NAME SUBSTRING, deliberately, rather than a list of known
//! fields. The credential fields here are already spelled five different ways
//! (`pbs_password`, `smb_password`, `secret_key`, `access_key`,
//! `pbs_token_secret`) and an exact-name list is a list someone forgets to
//! update — the next storage backend adds a sixth spelling and it leaks. A
//! substring rule fails safe: an unrecognised `*_password` is masked because it
//! matches, not because anyone remembered it.

/// What a redacted value is replaced with. Also the sentinel the WRITE side
/// recognises as "the operator did not retype the secret — keep the stored
/// one", which is why one constant serves both directions: a read side and a
/// write side that disagreed about the placeholder would silently save the
/// literal bullets as the password.
///
/// Same glyph as [`crate::storage::REDACTED_SECRET`], which solves the same
/// problem for storage mounts.
pub const REDACTED: &str = "••••••••";

/// True when a field name looks like it carries a credential.
///
/// The rule is `pass | secret | token | key` anywhere in the lowercased name,
/// minus names ending `_name`: `pbs_token_name` is the token's IDENTIFIER, the
/// username half of the pair, and masking it would show the operator bullets
/// where a name belongs while telling an attacker nothing. That exemption is
/// itself a rule rather than a list, so it cannot rot the way an allowlist of
/// secret fields would.
pub fn is_secret_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with("_name") {
        return false;
    }
    lower.contains("pass")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("key")
}

/// Replace every credential-looking string in `value` with [`REDACTED`],
/// recursing through objects and arrays.
///
/// An EMPTY string is left empty. The edit dialogs use "is there a stored
/// secret?" to choose between "leave blank to keep unchanged" and "enter
/// password", so masking a never-set field would claim every schedule had
/// credentials it does not have — the same reasoning as
/// `storage::list_mounts_redacted`.
///
/// Non-string values under a matching key (a bool like `pbs_file_level_set`
/// cannot be a credential) are left alone, so the shape the UI parses is
/// unchanged.
pub fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                match val {
                    // A credential-named STRING is the only thing masked; a bool
                    // like `pbs_file_level_set` under a matching name cannot be
                    // a secret and keeps the shape the UI parses.
                    serde_json::Value::String(s) if is_secret_field(key) => {
                        if !s.is_empty() {
                            *s = REDACTED.to_string();
                        }
                    }
                    other => redact_json(other),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_json(item);
            }
        }
        _ => {}
    }
}

/// Serialize `value` with every credential-looking field redacted.
///
/// Returns `serde_json::Value` rather than the concrete type because redaction
/// is lossy — handing back a `BackupSchedule` whose `pbs_password` is literally
/// "••••••••" invites someone to pass it to code that tries to authenticate
/// with it. A `Value` cannot be mistaken for a usable config.
pub fn to_redacted_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    let mut v = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    redact_json(&mut v);
    v
}

/// Put stored secrets back wherever the incoming value is the [`REDACTED`]
/// sentinel, so a round-trip through the UI cannot blank a credential the
/// operator never touched.
///
/// Walks `incoming` and `stored` in parallel by key. A field the operator
/// genuinely cleared arrives as an empty string, not as the sentinel, so
/// clearing a credential still works.
pub fn restore_redacted(incoming: &mut serde_json::Value, stored: &serde_json::Value) {
    match (incoming, stored) {
        (serde_json::Value::Object(new_map), serde_json::Value::Object(old_map)) => {
            for (key, new_val) in new_map.iter_mut() {
                let old_val = match old_map.get(key) {
                    Some(v) => v,
                    None => continue,
                };
                match (new_val, old_val) {
                    (serde_json::Value::String(n), serde_json::Value::String(o))
                        if is_secret_field(key) =>
                    {
                        if n == REDACTED {
                            *n = o.clone();
                        }
                    }
                    (new_val, old_val) => restore_redacted(new_val, old_val),
                }
            }
        }
        (serde_json::Value::Array(new_items), serde_json::Value::Array(old_items)) => {
            for (i, item) in new_items.iter_mut().enumerate() {
                if let Some(old) = old_items.get(i) {
                    restore_redacted(item, old);
                }
            }
        }
        _ => {}
    }
}

/// Blank any value that is still the [`REDACTED`] sentinel after
/// [`restore_redacted`] has had its turn.
///
/// The sentinel must never reach disk. `restore_redacted` covers the normal
/// edit — sentinel in, stored value back — but not a sentinel arriving for a
/// field with no stored counterpart: a brand-new schedule, a storage type
/// switched from `local` to `pbs`, a replayed request. Persisting the bullets
/// there would write a password of "••••••••" and the nightly backup would
/// fail authentication at 02:00 with a credential nobody typed. Blanking makes
/// it an empty credential instead, which the existing `merge_pbs_secrets` path
/// then fills from the saved connection.
pub fn clear_sentinels(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                match val {
                    serde_json::Value::String(s) => {
                        if s == REDACTED {
                            s.clear();
                        }
                    }
                    other => clear_sentinels(other),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                clear_sentinels(item);
            }
        }
        _ => {}
    }
}

/// Take the secrets an incoming object left as sentinels from `stored`, then
/// guarantee no sentinel survives. The pair callers want at a write boundary.
///
/// `T` round-trips through `serde_json::Value` so the substring rule applies to
/// whatever fields the type happens to have, including ones added later.
pub fn merge_incoming_secrets<T>(incoming: &T, stored: Option<&T>) -> Result<T, String>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut new_val = serde_json::to_value(incoming)
        .map_err(|e| format!("Failed to serialize for secret merge: {}", e))?;
    if let Some(old) = stored {
        let old_val = serde_json::to_value(old)
            .map_err(|e| format!("Failed to serialize stored value for secret merge: {}", e))?;
        restore_redacted(&mut new_val, &old_val);
    }
    clear_sentinels(&mut new_val);
    serde_json::from_value(new_val)
        .map_err(|e| format!("Failed to rebuild value after secret merge: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every credential spelling seen in the production report, plus one
    /// nobody has written yet — the point of the substring rule is that the
    /// last one is covered without anyone adding it here.
    #[test]
    fn every_credential_spelling_is_matched() {
        for name in [
            "pbs_password", "smb_password", "secret_key", "access_key",
            "pbs_token_secret", "password", "api_key", "auth_token",
            "PBS_PASSWORD", "SecretKey",
            "future_backend_passphrase", // invented: must still match
        ] {
            assert!(is_secret_field(name), "{} must be treated as a secret", name);
        }
    }

    #[test]
    fn identifiers_and_ordinary_fields_are_not_masked() {
        for name in [
            "pbs_token_name", // the username half of a token pair
            "pbs_server", "pbs_datastore", "pbs_user", "pbs_namespace",
            "bucket", "region", "endpoint", "path", "name", "id", "enabled",
        ] {
            assert!(!is_secret_field(name), "{} must NOT be masked", name);
        }
    }

    #[test]
    fn redacts_nested_and_leaves_empty_alone() {
        let mut v = json!({
            "schedules": [{
                "name": "nightly",
                "storage": {
                    "type": "pbs",
                    "pbs_server": "pbs.example.com",
                    "pbs_password": "hunter2",
                    "pbs_token_name": "backup@pbs!wolfstack",
                    "secret_key": "",
                    "pbs_file_level": true
                }
            }]
        });
        redact_json(&mut v);
        let s = &v["schedules"][0]["storage"];
        assert_eq!(s["pbs_password"], REDACTED);
        assert_eq!(s["pbs_server"], "pbs.example.com", "hostname is not a secret");
        assert_eq!(s["pbs_token_name"], "backup@pbs!wolfstack", "identifier stays readable");
        assert_eq!(s["secret_key"], "", "never-set stays empty, not bulleted");
        assert_eq!(s["pbs_file_level"], true, "non-strings under a matching key are untouched");
    }

    #[test]
    fn a_redacted_round_trip_keeps_the_stored_secret() {
        let stored = json!({"storage": {"pbs_password": "hunter2", "pbs_server": "old"}});
        let mut incoming = json!({"storage": {"pbs_password": REDACTED, "pbs_server": "new"}});
        restore_redacted(&mut incoming, &stored);
        assert_eq!(incoming["storage"]["pbs_password"], "hunter2");
        assert_eq!(incoming["storage"]["pbs_server"], "new", "non-secrets still update");
    }

    /// Clearing a credential must remain possible — an empty string is the
    /// operator deliberately removing it, not a sentinel to paper over.
    #[test]
    fn an_explicitly_cleared_secret_is_not_restored() {
        let stored = json!({"pbs_password": "hunter2"});
        let mut incoming = json!({"pbs_password": ""});
        restore_redacted(&mut incoming, &stored);
        assert_eq!(incoming["pbs_password"], "", "operator cleared it; keep it cleared");
    }

    #[test]
    fn a_new_secret_overwrites_the_stored_one() {
        let stored = json!({"pbs_password": "old"});
        let mut incoming = json!({"pbs_password": "new"});
        restore_redacted(&mut incoming, &stored);
        assert_eq!(incoming["pbs_password"], "new");
    }

    /// The regression that would have destroyed every operator's credentials:
    /// the edit dialog re-posts the schedule it was shown, so once the read
    /// side masks, an edit sends bullets back. Without the restore this saves
    /// "••••••••" as the password and the 02:00 run fails to authenticate.
    #[test]
    fn editing_a_schedule_does_not_overwrite_the_password_with_bullets() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Storage { pbs_server: String, pbs_password: String, retention: u32 }

        let stored = Storage {
            pbs_server: "pbs.example.com".into(),
            pbs_password: "hunter2".into(),
            retention: 7,
        };
        // What the browser sends back after being shown the redacted version,
        // having changed only the retention.
        let from_browser: Storage = serde_json::from_value(json!({
            "pbs_server": "pbs.example.com",
            "pbs_password": REDACTED,
            "retention": 14
        })).unwrap();

        let merged = merge_incoming_secrets(&from_browser, Some(&stored)).unwrap();
        assert_eq!(merged.pbs_password, "hunter2", "the stored password survives an edit");
        assert_eq!(merged.retention, 14, "the actual edit still applies");
    }

    /// A sentinel with nothing to restore from must not be persisted verbatim.
    #[test]
    fn a_sentinel_with_no_stored_counterpart_is_blanked_not_saved() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Storage { pbs_password: String }
        let incoming: Storage = serde_json::from_value(json!({"pbs_password": REDACTED})).unwrap();
        let merged = merge_incoming_secrets(&incoming, None).unwrap();
        assert_eq!(merged.pbs_password, "", "bullets must never reach disk");
    }

    #[test]
    fn clear_sentinels_reaches_nested_values() {
        let mut v = json!({"a": {"pbs_password": REDACTED}, "b": [{"secret_key": REDACTED}]});
        clear_sentinels(&mut v);
        assert_eq!(v["a"]["pbs_password"], "");
        assert_eq!(v["b"][0]["secret_key"], "");
    }

    #[test]
    fn to_redacted_json_masks_a_serialized_struct() {
        #[derive(serde::Serialize)]
        struct S { pbs_server: String, pbs_password: String }
        let v = to_redacted_json(&S {
            pbs_server: "pbs.example.com".into(),
            pbs_password: "hunter2".into(),
        });
        assert_eq!(v["pbs_password"], REDACTED);
        assert_eq!(v["pbs_server"], "pbs.example.com");
    }
}
