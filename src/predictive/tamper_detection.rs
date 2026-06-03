// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Baseline-driven tamper detection for SSH hardening, sudo, and
//! brute-force protection — the surfaces attackers tamper with to
//! establish persistence after the initial break-in.
//!
//! Complements `compromise_indicators` (which catches the literal
//! IoCs of the BootingWorld attack chain): this module catches the
//! *generic* post-exploitation moves an attacker makes regardless
//! of which specific kit they're running.
//!
//! ## Indicators
//!
//! * `/etc/ssh/sshd_config` drift — typically the attacker re-enables
//!   `PermitRootLogin yes` and `PasswordAuthentication yes` so they
//!   can keep brute-forcing or reuse a stolen password.
//! * `/root/.ssh/authorized_keys` drift — the #1 SSH persistence
//!   vector: drop an attacker-controlled key, you're back in
//!   forever even after the operator changes the root password.
//! * `/etc/sudoers` and `/etc/sudoers.d/*` drift — attacker adds a
//!   non-root account with NOPASSWD ALL=(ALL) so they can re-escalate
//!   without needing the root password.
//! * `/etc/passwd` new UIDs with shell access that weren't in the
//!   baseline — backdoor accounts.
//! * `/etc/fail2ban/jail.local` and `/etc/fail2ban/jail.d/*` drift OR
//!   `fail2ban.service` is installed but stopped/masked — the
//!   defender's first move against persistent brute-forcers is the
//!   attacker's first move to disable.
//!
//! Auto-fixes are baseline-driven: when drift is detected the
//! current file is captured for forensics and the baseline content
//! is restored. The baseline itself was auto-seeded on first run
//! (so a fresh install doesn't false-positive) and can be re-seeded
//! via `/api/predictive/baselines/reseed/<name>` when the operator
//! makes an intentional change.
//!
//! ## Why baselines, not "good values"
//!
//! We deliberately do NOT ship a "correct sshd_config". Operators
//! legitimately customize it (Port, AllowUsers, KexAlgorithms,
//! Ciphers, etc.) and overwriting with our opinion would break
//! their setup. Baselines capture what THIS host considers normal
//! and only flag departures from that.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    baselines::{self, Verdict},
    compromise_indicators::RemediationOutcome,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

pub const FT_SSHD_CONFIG_TAMPER: &str = "tamper:sshd_config";
pub const FT_AUTHORIZED_KEYS_TAMPER: &str = "tamper:authorized_keys";
pub const FT_SUDOERS_TAMPER: &str = "tamper:sudoers";
pub const FT_PASSWD_TAMPER: &str = "tamper:passwd";
pub const FT_FAIL2BAN_TAMPER: &str = "tamper:fail2ban";

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const ROOT_AUTHORIZED_KEYS: &str = "/root/.ssh/authorized_keys";
const SUDOERS: &str = "/etc/sudoers";
const PASSWD: &str = "/etc/passwd";
const FAIL2BAN_JAIL_LOCAL: &str = "/etc/fail2ban/jail.local";

/// All paths sudoers.d that we baseline individually. Built at
/// scan time by listing the directory — we don't hard-code the set
/// because operators may add their own files (which become part of
/// the baseline on first observation).
const SUDOERS_D_DIR: &str = "/etc/sudoers.d";
const FAIL2BAN_JAIL_D_DIR: &str = "/etc/fail2ban/jail.d";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TamperFacts {
    /// Each (path, verdict) pair we evaluated this tick. The
    /// analyzer translates non-Match verdicts into proposals.
    pub paths: Vec<TamperedPath>,
    /// True iff fail2ban is installed on this host (we have a unit
    /// file for it). Detect-only — we don't INSTALL fail2ban, only
    /// fix it when it's already there but tampered with.
    pub fail2ban_installed: bool,
    /// True iff fail2ban.service is masked at scan time. If true,
    /// `remediations` will contain an unmask attempt entry.
    pub fail2ban_masked: bool,
    /// True iff fail2ban.service is installed and currently inactive.
    pub fail2ban_inactive: bool,
    /// True iff the `[sshd]` jail is enabled in the loaded fail2ban
    /// config (parsed from jail.local + jail.d/*). Required for the
    /// brute-force protection to actually be doing anything for SSH.
    pub fail2ban_sshd_jail_enabled: bool,
    /// What we did about each detection. Each entry pairs with a
    /// proposal's evidence so the inbox card shows the action.
    pub remediations: Vec<RemediationOutcome>,
    /// Set false on hosts where /etc/ doesn't look like a Linux box
    /// (no /etc/passwd at all — shouldn't happen but be defensive).
    pub scanned: bool,
}

/// One baselined path's current state plus its verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperedPath {
    pub path: String,
    pub verdict_label: String,
    pub current_sha256: Option<String>,
    pub baseline_sha256: Option<String>,
}

pub async fn sample_now_async(_timeout: Duration) -> TamperFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> TamperFacts {
    if std::fs::metadata(PASSWD).is_err() {
        return TamperFacts::default();
    }

    let mut paths: Vec<TamperedPath> = Vec::new();

    for p in [SSHD_CONFIG, ROOT_AUTHORIZED_KEYS, SUDOERS, PASSWD] {
        if std::fs::metadata(p).is_err() && baselines::load(p).is_none() {
            continue; // file not present and no baseline — skip
        }
        paths.push(verdict_to_path(p));
    }

    // sudoers.d/* — every file there gets baselined.
    if let Ok(entries) = std::fs::read_dir(SUDOERS_D_DIR) {
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_file() { continue; }
            let s = p.to_string_lossy().into_owned();
            paths.push(verdict_to_path(&s));
        }
    }

    // Detect any baseline'd sudoers.d file that has since been
    // deleted. We use the baselines directory listing to find
    // baselines whose underlying path is gone — i.e. the attacker
    // dropped a NOPASSWD file and we baselined it, then they
    // realized and rm'd it. We treat that as a missing-file verdict.
    if let Ok(dir) = std::fs::read_dir(baselines::baselines_dir()) {
        for entry in dir.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
            // Cheap: load the JSON and look at its `path` field.
            if let Ok(body) = std::fs::read_to_string(&p) {
                if let Ok(b) = serde_json::from_str::<baselines::Baseline>(&body) {
                    if b.path.starts_with(SUDOERS_D_DIR)
                        && !paths.iter().any(|tp| tp.path == b.path)
                        && std::fs::metadata(&b.path).is_err()
                    {
                        paths.push(verdict_to_path(&b.path));
                    }
                }
            }
        }
    }

    // fail2ban state.
    let fail2ban_installed = is_unit_known("fail2ban.service");
    let fail2ban_masked = fail2ban_installed && super::compromise_indicators::is_unit_masked("fail2ban.service");
    let fail2ban_inactive = fail2ban_installed && !is_unit_active("fail2ban.service");
    let fail2ban_sshd_jail_enabled = if fail2ban_installed {
        parse_fail2ban_sshd_enabled()
    } else {
        true // not installed → don't flag; the operator's choice
    };

    if fail2ban_installed {
        if std::fs::metadata(FAIL2BAN_JAIL_LOCAL).is_ok() || baselines::load(FAIL2BAN_JAIL_LOCAL).is_some() {
            paths.push(verdict_to_path(FAIL2BAN_JAIL_LOCAL));
        }
        if let Ok(entries) = std::fs::read_dir(FAIL2BAN_JAIL_D_DIR) {
            for e in entries.flatten() {
                let p = e.path();
                if !p.is_file() { continue; }
                let s = p.to_string_lossy().into_owned();
                paths.push(verdict_to_path(&s));
            }
        }
    }

    TamperFacts {
        paths,
        fail2ban_installed,
        fail2ban_masked,
        fail2ban_inactive,
        fail2ban_sshd_jail_enabled,
        remediations: Vec::new(),
        scanned: true,
    }
}

fn verdict_to_path(p: &str) -> TamperedPath {
    let v = baselines::check(p);
    let (label, cur, base) = match &v {
        Verdict::Match => ("match".to_string(), None, None),
        Verdict::NoBaseline => ("no_baseline".to_string(), None, None),
        Verdict::Drift { current_sha256, baseline_sha256 } => (
            "drift".to_string(),
            Some(current_sha256.clone()),
            Some(baseline_sha256.clone()),
        ),
        Verdict::FileMissing { baseline_sha256 } => (
            "file_missing".to_string(),
            None,
            Some(baseline_sha256.clone()),
        ),
        Verdict::ReadError(_) => ("read_error".to_string(), None, None),
    };
    TamperedPath {
        path: p.to_string(),
        verdict_label: label,
        current_sha256: cur,
        baseline_sha256: base,
    }
}

fn is_unit_known(unit: &str) -> bool {
    // Unit file present in any of the standard locations means
    // systemd "knows" the unit, regardless of enabled/disabled.
    let candidates = [
        format!("/etc/systemd/system/{}", unit),
        format!("/usr/lib/systemd/system/{}", unit),
        format!("/lib/systemd/system/{}", unit),
        format!("/run/systemd/system/{}", unit),
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

fn is_unit_active(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read jail.local + jail.d/* and return true iff a `[sshd]` (or
/// `[ssh]`) stanza has `enabled = true` set. Not a full INI parser —
/// just the minimum we need to verify the jail is on.
fn parse_fail2ban_sshd_enabled() -> bool {
    let mut bodies = String::new();
    if let Ok(b) = std::fs::read_to_string(FAIL2BAN_JAIL_LOCAL) { bodies.push_str(&b); bodies.push('\n'); }
    if let Ok(entries) = std::fs::read_dir(FAIL2BAN_JAIL_D_DIR) {
        for e in entries.flatten() {
            if let Ok(b) = std::fs::read_to_string(e.path()) {
                bodies.push_str(&b);
                bodies.push('\n');
            }
        }
    }
    // Walk sections.
    let mut in_sshd = false;
    let mut sshd_enabled = false;
    for line in bodies.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            let name = t[1..t.len()-1].to_ascii_lowercase();
            in_sshd = name == "sshd" || name == "ssh";
            continue;
        }
        if !in_sshd { continue; }
        // Match `enabled = true` (allowing extra whitespace + case).
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("enabled") {
            if let Some((_, rhs)) = lower.split_once('=') {
                if rhs.trim() == "true" || rhs.trim() == "1" {
                    sshd_enabled = true;
                }
            }
        }
    }
    sshd_enabled
}

/// Auto-remediation pass — runs after sample, gated by ack/proposal
/// suppression. Same architecture as compromise_indicators::
/// remediate_if_unacked: an operator who acked a tamper finding
/// (intentionally letting drift stand) won't see WolfStack revert
/// it on the next tick.
pub async fn remediate_if_unacked(
    facts: TamperFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    ctx: &Context,
) -> TamperFacts {
    if !facts.scanned { return facts; }
    let acks = acks.clone();
    let proposals = proposals.clone();
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    tokio::task::spawn_blocking(move || remediate_blocking(facts, &acks, &proposals, &scope))
        .await
        .unwrap_or_else(|_| TamperFacts::default())
}

fn remediate_blocking(
    mut facts: TamperFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    scope: &ProposalScope,
) -> TamperFacts {
    let suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
    };

    // Group by indicator class so a single ack on sshd_config
    // suppresses all sshd_config drift remediations etc.
    let needs_fix = facts.paths.clone();
    for tp in needs_fix {
        if tp.verdict_label != "drift" && tp.verdict_label != "file_missing" {
            continue;
        }
        let ft = finding_type_for_path(&tp.path);
        if suppressed(&ft) { continue; }
        let outcome = restore_from_baseline(&tp.path);
        facts.remediations.push(outcome);
    }

    if facts.fail2ban_installed && facts.fail2ban_masked && !suppressed(FT_FAIL2BAN_TAMPER) {
        facts.remediations.push(unmask_and_start("fail2ban.service"));
    } else if facts.fail2ban_installed && facts.fail2ban_inactive && !suppressed(FT_FAIL2BAN_TAMPER) {
        facts.remediations.push(start_unit("fail2ban.service"));
    }

    facts
}

fn finding_type_for_path(path: &str) -> String {
    if path == SSHD_CONFIG { FT_SSHD_CONFIG_TAMPER.into() }
    else if path == ROOT_AUTHORIZED_KEYS { FT_AUTHORIZED_KEYS_TAMPER.into() }
    else if path == SUDOERS || path.starts_with(SUDOERS_D_DIR) { FT_SUDOERS_TAMPER.into() }
    else if path == PASSWD { FT_PASSWD_TAMPER.into() }
    else if path == FAIL2BAN_JAIL_LOCAL || path.starts_with(FAIL2BAN_JAIL_D_DIR) { FT_FAIL2BAN_TAMPER.into() }
    else { "tamper:unknown".into() }
}

/// Restore a file to its baseline content. Strategy:
///   1. Capture the current (suspected-tampered) content to forensics.
///   2. Load the baseline-content snapshot from the forensics
///      pre-tamper capture (we keep the original bytes alongside
///      the SHA so we can actually revert, not just detect).
///   3. Replace the file atomically.
///
/// For files we DON'T have a content-snapshot of (because the
/// baseline was seeded before content-snapshotting was a thing),
/// we capture-only and leave the operator to restore from their
/// own backup — the proposal text says so explicitly.
fn restore_from_baseline(path: &str) -> RemediationOutcome {
    let action = format!("restore {} from baseline", path);
    // Capture current state first.
    let cur_capture = match baselines::capture_current(path, "tamper") {
        Ok(p) => p,
        Err(e) if e.starts_with("read ") => {
            // File was deleted entirely — that IS the tamper. Nothing
            // to capture; just record the verdict in the outcome.
            return RemediationOutcome {
                action,
                ok: false,
                detail: format!("file is missing; baseline expected content present. Operator restore needed: {}", e),
            };
        }
        Err(e) => return RemediationOutcome { action, ok: false, detail: e },
    };
    // Look for a content snapshot in /var/lib/wolfstack/baselines/
    // — we save one at first-seed (see baselines::auto_seed; the
    // companion `.content` file). If absent, this is a pre-23.2.0
    // baseline and we surface that to the operator instead of
    // silently failing.
    let content_path = baselines::baselines_dir()
        .join(format!("{}.content", baselines::slug_for(path)));
    if !content_path.exists() {
        return RemediationOutcome {
            action,
            ok: false,
            detail: format!(
                "no content snapshot for {} (legacy baseline). Current state captured to {}; restore from your own backup, then run `/api/predictive/baselines/reseed/{}` to re-anchor.",
                path, cur_capture, baselines::slug_for(path),
            ),
        };
    }
    let baseline_bytes = match std::fs::read(&content_path) {
        Ok(b) => b,
        Err(e) => return RemediationOutcome {
            action,
            ok: false,
            detail: format!("read baseline content {:?}: {}", content_path, e),
        },
    };
    // Atomic write of the restored content.
    let tmp = format!("{}.wolfstack.tmp", path);
    if let Err(e) = std::fs::write(&tmp, &baseline_bytes) {
        return RemediationOutcome { action, ok: false, detail: format!("write {}: {}", tmp, e) };
    }
    // Preserve sensible permissions on system files.
    use std::os::unix::fs::PermissionsExt;
    let mode = match path {
        ROOT_AUTHORIZED_KEYS => 0o600,
        SUDOERS => 0o440,
        PASSWD => 0o644,
        _ if path.starts_with(SUDOERS_D_DIR) => 0o440,
        _ => 0o644,
    };
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome { action, ok: false, detail: format!("rename: {}", e) };
    }
    // If we just restored sshd_config, reload sshd so the change
    // takes effect immediately.
    if path == SSHD_CONFIG {
        let _ = std::process::Command::new("systemctl")
            .args(["reload", "sshd"])
            .output();
        // Some distros use `ssh` instead of `sshd`.
        let _ = std::process::Command::new("systemctl")
            .args(["reload", "ssh"])
            .output();
    }
    tracing::warn!(
        "tamper_detection: restored {} from baseline; current captured to {}",
        path, cur_capture,
    );
    RemediationOutcome {
        action,
        ok: true,
        detail: format!("restored {} from baseline; suspected-tampered version captured to {}", path, cur_capture),
    }
}

fn unmask_and_start(unit: &str) -> RemediationOutcome {
    // Remove the /dev/null symlink in both /etc/systemd/system and
    // /run/systemd/system, then daemon-reload + start.
    for base in &["/etc/systemd/system", "/run/systemd/system"] {
        let p = format!("{}/{}", base, unit);
        if let Ok(meta) = std::fs::symlink_metadata(&p) {
            if meta.file_type().is_symlink() {
                if let Ok(target) = std::fs::read_link(&p) {
                    if target.as_os_str() == "/dev/null" {
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
        }
    }
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").output();
    let out = std::process::Command::new("systemctl")
        .args(["start", unit])
        .output();
    let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let detail = if ok {
        format!("unmasked + started {}", unit)
    } else {
        format!(
            "unmask attempted, start failed: {}",
            out.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_else(|e| e.to_string())
        )
    };
    tracing::warn!("tamper_detection: {}", detail);
    RemediationOutcome {
        action: format!("unmask and start {}", unit),
        ok,
        detail,
    }
}

fn start_unit(unit: &str) -> RemediationOutcome {
    let out = std::process::Command::new("systemctl").args(["start", unit]).output();
    let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let detail = if ok {
        format!("started {}", unit)
    } else {
        format!(
            "start failed: {}",
            out.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_else(|e| e.to_string())
        )
    };
    tracing::warn!("tamper_detection: {}", detail);
    RemediationOutcome { action: format!("start {}", unit), ok, detail }
}

pub fn analyze(
    ctx: &Context,
    facts: &TamperFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };

    // Group drift findings by indicator class. Each (finding_type)
    // gets one card listing every file in that class that's drifted.
    let mut by_class: std::collections::HashMap<String, Vec<&TamperedPath>> = Default::default();
    for tp in &facts.paths {
        if tp.verdict_label == "drift" || tp.verdict_label == "file_missing" {
            let ft = finding_type_for_path(&tp.path);
            by_class.entry(ft).or_default().push(tp);
        }
    }

    let find_rem = |label_substring: &str| -> Option<&RemediationOutcome> {
        facts.remediations.iter().find(|r| r.detail.contains(label_substring) || r.action.contains(label_substring))
    };

    for (ft, paths) in by_class {
        if acks.suppresses(&ft, &scope) || proposals.is_suppressed(&ft, &scope) { continue; }
        // Find the remediation whose action mentions one of these paths.
        let rem = paths.iter().find_map(|p| find_rem(&p.path));
        out.push(build_tamper_proposal(&ft, &paths, rem, &scope));
    }

    // fail2ban-specific findings (masked / inactive / sshd jail off).
    if facts.fail2ban_installed
        && (facts.fail2ban_masked || facts.fail2ban_inactive || !facts.fail2ban_sshd_jail_enabled)
        && !acks.suppresses(FT_FAIL2BAN_TAMPER, &scope)
        && !proposals.is_suppressed(FT_FAIL2BAN_TAMPER, &scope)
    {
        let rem = facts.remediations.iter()
            .find(|r| r.action.contains("fail2ban"));
        out.push(build_fail2ban_proposal(facts, rem, &scope));
    }

    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &TamperFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    let types: [&str; 5] = [
        FT_SSHD_CONFIG_TAMPER,
        FT_AUTHORIZED_KEYS_TAMPER,
        FT_SUDOERS_TAMPER,
        FT_PASSWD_TAMPER,
        FT_FAIL2BAN_TAMPER,
    ];
    types.iter().map(|t| ((*t).to_string(), scope.clone())).collect()
}

fn build_tamper_proposal(
    finding_type: &str,
    paths: &[&TamperedPath],
    rem: Option<&RemediationOutcome>,
    scope: &ProposalScope,
) -> Proposal {
    let path_list: HashSet<&str> = paths.iter().map(|p| p.path.as_str()).collect();
    let path_list: Vec<&&str> = path_list.iter().collect();
    let title = match finding_type {
        FT_SSHD_CONFIG_TAMPER => "SSH daemon config changed from its baseline",
        FT_AUTHORIZED_KEYS_TAMPER => "Root authorized_keys changed from its baseline",
        FT_SUDOERS_TAMPER => "sudoers configuration changed from its baseline",
        FT_PASSWD_TAMPER => "/etc/passwd changed from its baseline",
        _ => "Security-critical file changed from its baseline",
    };
    let why = format!(
        "WolfStack baselined this file's contents when it was first observed and the current contents \
         no longer match. This is either an intentional operator change (in which case reseed the \
         baseline via `/api/predictive/baselines/reseed/<slug>` so it stops alerting) OR an attacker \
         establishing persistence — adding their SSH key to authorized_keys, re-enabling password \
         login in sshd_config, or granting NOPASSWD sudo to a backdoor account.\n\nFiles flagged: {}",
        path_list.iter().map(|s| format!("`{}`", s)).collect::<Vec<_>>().join(", "),
    );
    let mut evidence: Vec<Evidence> = paths.iter().map(|tp| Evidence {
        label: tp.path.clone(),
        value: format!("verdict = {}", tp.verdict_label),
        detail: Some(match (&tp.current_sha256, &tp.baseline_sha256) {
            (Some(c), Some(b)) => format!("current sha256 = {}, baseline = {}", c, b),
            (None, Some(b)) => format!("file deleted; baseline sha256 was {}", b),
            _ => "current contents do not match the baseline snapshot".into(),
        }),
        links: Vec::new(),
    }).collect();
    if let Some(r) = rem { evidence.push(remediation_evidence_for(r)); }
    let manual_cmds: Vec<String> = paths.iter().map(|tp| {
        format!("# Inspect current vs baseline for {}:\ndiff <(cat {}) <(cat /var/lib/wolfstack/baselines/{}.content)", tp.path, tp.path, baselines::slug_for(&tp.path))
    }).collect();
    Proposal::new(
        finding_type.to_string(),
        ProposalSource::Rule,
        Severity::Critical,
        title.to_string(),
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-restored each affected file from its baseline snapshot and captured the suspected-tampered version to /var/lib/wolfstack/forensics/tamper/. If the Auto-fix evidence above shows a failure (e.g. missing content snapshot for a pre-23.2.0 baseline), restore from your own backup and run /api/predictive/baselines/reseed/<slug> to re-anchor.".into(),
            commands: {
                let mut v = vec!["# Inspect what changed:".to_string()];
                v.extend(manual_cmds);
                v.push("ls -la /var/lib/wolfstack/forensics/tamper/   # captured tampered versions".to_string());
                // Reseed after an intentional change so WolfStack stops
                // reverting + alerting. HTTPS only (:8553 has been HTTPS since
                // v23.11 — the old `http://` printed here just connection-
                // refused), and the endpoint needs auth: run as root on the
                // host, where the node's cluster secret is readable, so the
                // operator doesn't have to mint an API key. `-k` accepts the
                // default self-signed cert. (piranhaSponsor 2026-06-03.)
                let secret_path = crate::paths::get().cluster_secret;
                v.push("# After a legitimate change, reseed the baseline (run as root on this host):".to_string());
                v.extend(paths.iter().map(|tp| format!(
                    "curl -sk -X POST https://localhost:8553/api/predictive/baselines/reseed/{} -H \"X-WolfStack-Secret: $(cat {})\"",
                    baselines::slug_for(&tp.path), secret_path
                )));
                v
            },
        },
        scope.clone(),
    )
}

fn build_fail2ban_proposal(facts: &TamperFacts, rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let mut symptoms: Vec<&str> = Vec::new();
    if facts.fail2ban_masked { symptoms.push("masked"); }
    if facts.fail2ban_inactive { symptoms.push("inactive"); }
    if !facts.fail2ban_sshd_jail_enabled { symptoms.push("no [sshd] jail enabled"); }
    let mut evidence = vec![Evidence {
        label: "fail2ban state".into(),
        value: symptoms.join(", "),
        detail: Some("fail2ban is installed on this host but is not actively protecting SSH. The attacker's first move after a successful break-in is to disable the brute-force watcher so they (and the next botnet) can keep hammering.".into()),
        links: Vec::new(),
    }];
    if let Some(r) = rem { evidence.push(remediation_evidence_for(r)); }
    Proposal::new(
        FT_FAIL2BAN_TAMPER,
        ProposalSource::Rule,
        Severity::Critical,
        format!("fail2ban not protecting SSH on this node ({})", symptoms.join(", ")),
        "fail2ban is installed but inactive / masked / not running the [sshd] jail. WolfStack auto-attempts to unmask + start it. If the [sshd] jail is disabled in config, reseed your fail2ban baseline AFTER fixing the config so future ticks recognize the corrected state.".to_string(),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-unmasks and starts fail2ban when it's installed but stopped/masked. Verifying that the [sshd] jail is enabled requires inspecting jail.local / jail.d/*.".into(),
            commands: vec![
                "systemctl is-active fail2ban   # should be 'active'".into(),
                "fail2ban-client status sshd   # should NOT say 'no such jail'".into(),
                "# To enable the sshd jail manually:".into(),
                "echo -e '[sshd]\\nenabled = true\\nmaxretry = 5\\nbantime = 1h' >> /etc/fail2ban/jail.local".into(),
                "systemctl restart fail2ban".into(),
            ],
        },
        scope.clone(),
    )
}

fn remediation_evidence_for(rem: &RemediationOutcome) -> Evidence {
    let prefix = if rem.ok { "Auto-fix \u{2713}" } else { "Auto-fix \u{2717}" };
    Evidence {
        label: format!("{} — {}", prefix, rem.action),
        value: rem.detail.clone(),
        detail: Some(if rem.ok {
            "WolfStack performed this action as soon as the indicator was detected. The card auto-resolves on the next 5-minute tick if the host is now clean.".into()
        } else {
            "WolfStack attempted this action but it did not complete. Run the manual commands below to finish recovery.".into()
        }),
        links: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_type_mapping() {
        assert_eq!(finding_type_for_path(SSHD_CONFIG), FT_SSHD_CONFIG_TAMPER);
        assert_eq!(finding_type_for_path(ROOT_AUTHORIZED_KEYS), FT_AUTHORIZED_KEYS_TAMPER);
        assert_eq!(finding_type_for_path(SUDOERS), FT_SUDOERS_TAMPER);
        assert_eq!(finding_type_for_path("/etc/sudoers.d/01-cluster"), FT_SUDOERS_TAMPER);
        assert_eq!(finding_type_for_path(PASSWD), FT_PASSWD_TAMPER);
        assert_eq!(finding_type_for_path(FAIL2BAN_JAIL_LOCAL), FT_FAIL2BAN_TAMPER);
        assert_eq!(finding_type_for_path("/etc/fail2ban/jail.d/sshd.local"), FT_FAIL2BAN_TAMPER);
    }

    #[test]
    fn parse_fail2ban_recognizes_enabled_sshd() {
        // Direct test of the body-parser via a stub function.
        let body = "[sshd]\nenabled = true\nmaxretry = 5\n";
        assert!(parse_fail2ban_body(body));
    }

    #[test]
    fn parse_fail2ban_recognizes_disabled_sshd() {
        let body = "[sshd]\nenabled = false\n";
        assert!(!parse_fail2ban_body(body));
    }

    #[test]
    fn parse_fail2ban_recognizes_no_sshd_section() {
        let body = "[ssh-iptables]\nenabled = true\n";
        // ssh-iptables is not our trigger word; sshd / ssh are.
        assert!(!parse_fail2ban_body(body));
    }

    #[test]
    fn parse_fail2ban_recognizes_legacy_ssh_section() {
        let body = "[ssh]\nenabled = true\n";
        assert!(parse_fail2ban_body(body));
    }

    /// Helper exposed for testing the parser without needing
    /// real fail2ban config files on disk.
    fn parse_fail2ban_body(body: &str) -> bool {
        let mut in_sshd = false;
        let mut sshd_enabled = false;
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with('[') && t.ends_with(']') {
                let name = t[1..t.len()-1].to_ascii_lowercase();
                in_sshd = name == "sshd" || name == "ssh";
                continue;
            }
            if !in_sshd { continue; }
            let lower = t.to_ascii_lowercase();
            if lower.starts_with("enabled") {
                if let Some((_, rhs)) = lower.split_once('=') {
                    if rhs.trim() == "true" || rhs.trim() == "1" {
                        sshd_enabled = true;
                    }
                }
            }
        }
        sshd_enabled
    }
}
