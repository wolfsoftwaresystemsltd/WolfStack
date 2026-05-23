// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Centralised audit of "committed-default" secrets and weak at-rest
//! crypto. Single source of truth used by:
//!
//!   • The security scanner (`src/security.rs`) — surfaces findings
//!     in System Check.
//!   • The audit endpoint (`/api/security/secret-audit`) — read by
//!     the dashboard banner and the Settings → Security page.
//!   • The compat heartbeat (`src/compat/mod.rs`) — sends the finding
//!     count back to wolfstack.org so fleet-wide adoption of the
//!     migration can be measured before tightening defaults further
//!     (Stage 4 of the cluster-secret migration plan).
//!
//! Everything in here is read-only. No file mutations, no key changes,
//! no behaviour-altering code paths. Adding a check here cannot break
//! an existing install — worst case, a check returns a wrong finding
//! and the operator sees a banner they shouldn't.

use serde::Serialize;
use std::path::Path;

/// Severity ranking, mirrored into the frontend banner colour:
///   • `Compromise` → red banner, blocks dismissal until clicked-through
///   • `High`       → yellow banner, dismissible per-session
///   • `Info`       → no banner, surfaces only in Settings → Security
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Compromise,
    High,
    /// Reserved for future per-finding informational entries that
    /// surface in Settings → Security but never trigger a banner.
    /// Currently unused — every shipped finding is High or above —
    /// but the variant is part of the wire shape for the audit
    /// endpoint and tests pattern-match on it, so removing it would
    /// be a breaking change. `dead_code` is suppressed deliberately.
    #[allow(dead_code)]
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable kebab-case identifier — used by the frontend to decide
    /// which "Learn more" doc to link to and which migration button
    /// to surface. NEVER renamed once shipped (would break stored
    /// dismissals).
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Operator-facing remediation guidance. Plain text — the frontend
    /// is responsible for any escaping when it renders this into the
    /// banner / Settings panel.
    pub remediation: String,
}

/// Inspect this install and return any findings that match. Cheap —
/// reads at most a handful of file metadata entries. Safe to call
/// from any thread, on any cadence.
pub fn audit() -> Vec<Finding> {
    let mut out = Vec::new();
    check_cluster_secret_default(&mut out);
    check_xor_dns_creds(&mut out);
    check_xor_cloud_creds(&mut out);
    check_xor_xo_tokens(&mut out);
    check_plaintext_backup_creds(&mut out);
    out
}

/// Count of findings at `High` or above. Used by the heartbeat to
/// report fleet-wide exposure without sending any identifying detail
/// about which findings or what they cover.
pub fn finding_count() -> u32 {
    audit().iter().filter(|f| !matches!(f.severity, Severity::Info)).count() as u32
}

/// True if the active cluster secret is the built-in default. The
/// dashboard banner and the heartbeat both flip on this — and it's
/// the gating condition for the Stage 5 rejection logic.
pub fn is_using_default_cluster_secret() -> bool {
    let active = crate::auth::load_cluster_secret();
    active == crate::auth::default_cluster_secret()
}

// ─── Individual checks ──────────────────────────────────────────

fn check_cluster_secret_default(out: &mut Vec<Finding>) {
    if !is_using_default_cluster_secret() { return; }
    out.push(Finding {
        id: "cluster-secret-default",
        severity: Severity::Compromise,
        title: "Cluster secret is the built-in default".into(),
        detail: "The inter-node authentication secret is the value shipped \
                 in every WolfStack binary. Any attacker who downloads \
                 WolfStack — or who reads the source on GitHub — has the \
                 same key your cluster uses to authorise X-WolfStack-Secret \
                 calls between nodes.".into(),
        remediation: "Settings → Security → Rotate cluster secret. The \
                      coordinated rotation pushes a fresh per-install \
                      secret to every peer in one click; existing peers \
                      keep working until the new secret is acknowledged \
                      cluster-wide.".into(),
    });
}

// At-rest credential findings — interim shape. The Stage 1-5 migration
// surfaces these so operators KNOW about the exposure even though the
// one-click migration UI (deobfuscate v1 XOR → re-encrypt v2 AES) is a
// scoped follow-up. Per finding, the remediation text points operators
// at the manual mitigation: rotate the credential at the provider end
// AND restrict filesystem access to /etc/wolfstack/. That closes the
// exposure without waiting for the migration UI.
//
// When the migration ships, only the remediation strings change — the
// finding ids stay stable so dashboards / dismissals are preserved.

fn check_xor_dns_creds(out: &mut Vec<Finding>) {
    let p = "/etc/wolfstack/dns-providers.json";
    if !Path::new(p).exists() { return; }
    // Skip the finding once every entry in the file has been migrated
    // to v2 — the migration UI's success state is operator-visible
    // when this clears.
    if !crate::at_rest_crypto::file_has_legacy_v1_entries(p) { return; }
    out.push(Finding {
        id: "dns-creds-legacy-xor",
        severity: Severity::High,
        title: "DNS provider credentials use legacy obfuscation".into(),
        detail: "Stored DNS provider API tokens (Cloudflare, Route53, \
                 Hetzner, etc.) at /etc/wolfstack/dns-providers.json \
                 are XOR-obfuscated with a static key baked into the \
                 WolfStack binary. Anyone who reads the source can \
                 reverse the obfuscation — the only effective defence \
                 today is filesystem permissions on /etc/wolfstack/.".into(),
        remediation: "Mitigation today: (1) confirm /etc/wolfstack/ is \
                      mode 0700 owned by root; (2) rotate the DNS \
                      provider tokens at the provider's console and \
                      paste the new values into Settings → Certificates \
                      → DNS Providers — the new tokens are written with \
                      the same obfuscation, but rotating limits how \
                      long any previously-exfiltrated values stay valid. \
                      To migrate stored entries to AES-256-GCM keyed off this \
                      install's cluster secret, click 'Migrate at-rest \
                      credentials to AES' on this page — backs up every file \
                      first; safe to re-run.".into(),
    });
}

fn check_xor_cloud_creds(out: &mut Vec<Finding>) {
    let p = "/etc/wolfstack/cloud-providers.json";
    if !Path::new(p).exists() { return; }
    if !crate::at_rest_crypto::file_has_legacy_v1_entries(p) { return; }
    out.push(Finding {
        id: "cloud-creds-legacy-xor",
        severity: Severity::High,
        title: "Cloud provider credentials use legacy obfuscation".into(),
        detail: "Stored cloud provider tokens (DigitalOcean, Hetzner \
                 Cloud, Cloudflare account credentials) at \
                 /etc/wolfstack/cloud-providers.json are XOR-obfuscated \
                 with a static key baked into the WolfStack binary. \
                 Same exposure pattern as the DNS credentials finding."
            .into(),
        remediation: "Mitigation today: (1) confirm /etc/wolfstack/ is \
                      mode 0700 owned by root; (2) rotate the cloud \
                      provider tokens at the provider's console and \
                      re-paste them in Settings → Edge → Cloud Providers. \
                      A migration to AES-256-GCM is a planned follow-up.".into(),
    });
}

fn check_plaintext_backup_creds(out: &mut Vec<Finding>) {
    // Round-2 audit finding: backup-config.json holds S3 access_key /
    // secret_key, PBS user/token/password, SMB user/password as
    // plaintext serde fields. Worse than the XOR-protected stores
    // because there's no obfuscation at all — `cat
    // /etc/wolfstack/backup-config.json` reveals everything. Surfaced
    // here so operators know; not migrated automatically because
    // backup credentials are the operator's last line of disaster
    // recovery and a format-change bug would block restores.
    //
    // W3 fix: only fire if the file actually contains populated
    // credential fields. An operator with the file but no
    // destinations configured shouldn't see a finding they can't fix.
    let path = "/etc/wolfstack/backup-config.json";
    if !Path::new(path).exists() { return; }
    let raw = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return };
    let has_populated_cred = ["access_key", "secret_key", "pbs_password",
                              "pbs_token_secret", "smb_password"]
        .iter()
        .any(|field| {
            // Look for `"<field>": "<non-empty>"` anywhere in the file.
            let needle = format!("\"{}\":", field);
            raw.split(&needle)
                .skip(1)
                .any(|after| {
                    let trimmed = after.trim_start();
                    // Non-empty value would be `"something"`; empty is `""`.
                    trimmed.starts_with("\"") && !trimmed.starts_with("\"\"")
                })
        });
    if !has_populated_cred { return; }
    out.push(Finding {
        id: "backup-creds-plaintext",
        severity: Severity::High,
        title: "Backup storage credentials stored as plaintext".into(),
        detail: "Backup destination credentials (S3 access/secret keys, \
                 PBS user/token/password, SMB user/password) at \
                 /etc/wolfstack/backup-config.json are stored as \
                 plaintext serde fields with no encryption or \
                 obfuscation. Any read access to the file — backup \
                 leaks, misconfigured rsync, stolen disk image, \
                 path-traversal bugs — exposes the full credential.".into(),
        remediation: "Mitigation today: (1) confirm /etc/wolfstack/ is \
                      mode 0700 owned by root and the file is mode 0600; \
                      (2) prefer scoped credentials (IAM roles, PBS API \
                      tokens with restricted scope) over long-lived \
                      root-equivalent keys; (3) rotate the credentials at \
                      the storage backend's console regularly. \
                      Automatic encryption to AES-256-GCM keyed off the \
                      per-install cluster secret is intentionally NOT \
                      part of the same release as the cluster-secret \
                      migration — backup credentials are too critical to \
                      risk a format change without operator-explicit \
                      pre-flight + restore-tested rollout.".into(),
    });
}

fn check_xor_xo_tokens(out: &mut Vec<Finding>) {
    let xo_paths = ["/etc/wolfstack/xo_pools.json", "/etc/wolfstack/xo_tokens.json"];
    if !xo_paths.iter().any(|p| Path::new(p).exists()) { return; }
    // Auto-clear once every entry has been migrated to v2 (across
    // both possible filenames).
    if !xo_paths.iter().any(|p| crate::at_rest_crypto::file_has_legacy_v1_entries(p)) {
        return;
    }
    out.push(Finding {
        id: "xo-tokens-legacy-xor",
        severity: Severity::High,
        title: "Xen Orchestra tokens use legacy obfuscation".into(),
        detail: "Stored Xen Orchestra bearer tokens at \
                 /etc/wolfstack/xo_pools.json / xo_tokens.json are \
                 XOR-obfuscated with a static key baked into the \
                 WolfStack binary. Same exposure pattern as DNS / cloud \
                 credentials.".into(),
        remediation: "Mitigation today: (1) confirm /etc/wolfstack/ is \
                      mode 0700 owned by root; (2) revoke the affected \
                      XO bearer tokens at Xen Orchestra's Settings → \
                      Tokens and mint fresh ones to paste into Settings \
                      → XCP-ng. A migration to AES-256-GCM is a planned \
                      follow-up.".into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_serialises_snake_case() {
        let f = Finding {
            id: "x", severity: Severity::Compromise,
            title: "t".into(), detail: "d".into(), remediation: "r".into(),
        };
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"severity\":\"compromise\""), "got {}", j);
    }

    #[test]
    fn finding_count_matches_audit_high_and_above() {
        // Pure-function consistency check: finding_count() must equal
        // the count of audit() findings whose severity is High or
        // Compromise. We don't assert what audit() returns on this
        // host (depends on /etc/wolfstack/ state), only that the two
        // functions agree.
        let direct = audit().iter()
            .filter(|f| !matches!(f.severity, Severity::Info))
            .count() as u32;
        assert_eq!(finding_count(), direct);
    }
}
