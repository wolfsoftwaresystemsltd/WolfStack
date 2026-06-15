// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Proposal data model + ProposalStore.
//!
//! A `Proposal` is the unit of inbox-surfaced advice. Every analyzer
//! emits these; the orchestrator dedups them by (finding_type, scope)
//! so the same recurring issue updates the existing entry instead of
//! piling up. The store is the single source of truth for what's
//! pending the operator's attention.
//!
//! ## Why dedup keys are (finding_type, scope) and not random IDs
//!
//! The disk-fill analyzer reruns every five minutes. If it created a
//! fresh Proposal each cycle, the operator's inbox would gain twelve
//! identical entries an hour for the same disk. Keying by
//! `(finding_type, scope)` means the second-and-onward sightings
//! *update* the original entry — keeping `created_at` fixed (so the
//! age in the UI represents "how long has this been an issue") while
//! refreshing severity, evidence, and `updated_at`.

#[cfg(test)]
use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User-facing severity tier. Drives inbox sort order, badge colour,
/// and (later) which notification channels fire.
///
/// `Info` proposals are emitted but conventionally hidden from the
/// default inbox view — useful for baseline-posture reporting without
/// crying wolf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Warn,
    Info,
}

impl Severity {
    /// Sort key — Critical first, Info last. Used by the inbox.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Warn => 2,
            Severity::Info => 3,
        }
    }
}

/// Where the proposal came from. AI-source proposals carry a visual
/// distinction in the UI and start one severity tier lower than their
/// computed value until the rule's accept-ratio earns parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalSource {
    Rule,
    Ai,
}

/// What the operator should do. v1 emits `Manual` — operator runs the
/// commands themselves. v2 will introduce `OneClick` proposals whose
/// `handler_id` references an existing one-click-fix endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemediationPlan {
    /// Operator executes manually. The UI shows `instructions` as
    /// prose and `commands` as copy-pasteable monospace.
    Manual {
        instructions: String,
        commands: Vec<String>,
    },
    /// Click Approve → dispatch to a pre-allowlisted handler. Not
    /// used by any v1 analyzer — defined now so the data model is
    /// stable when v2 wires the first OneClick analyzer.
    OneClick {
        handler_id: String,
        params: serde_json::Value,
    },
}

/// One supporting fact attached to a proposal. Rendered as a small
/// chip in the inbox card. Always has a label and a value; `detail`
/// is for the "expand" panel.
///
/// `links` carries authoritative external references (e.g. vendor
/// advisories, distro security trackers) and is rendered as small
/// pill links beside the chip. Used by the OSV analyzer to surface
/// mitigation guidance for unpatched CVEs without us synthesising the
/// advice ourselves. Empty for analyzers that don't have references
/// to surface — `skip_serializing_if = "Vec::is_empty"` keeps the
/// JSON wire size unchanged for those callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<EvidenceLink>,
}

/// One labelled URL attached to an [`Evidence`] entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLink {
    /// Short human label for the chip. The OSV analyzer uses values
    /// like "Advisory", "Fix", "Web", or a derived host name.
    pub label: String,
    pub url: String,
}

/// Where in the cluster the proposal applies. `resource_id` is the
/// finer-grained anchor (mount point, container id, certificate name)
/// that distinguishes one finding from another at the same node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProposalScope {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}

/// Lifecycle of a proposal in the inbox.
///
/// `Pending` is the initial state — visible to the operator, awaiting
/// action. `Snoozed` hides it from the inbox until `until` passes,
/// at which point the next analyzer run that re-detects the issue
/// will flip it back to Pending. `Dismissed` is permanent ("not a
/// real issue, stop showing me"). `Approved` records the outcome of
/// a successful (or failed) one-click apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Snoozed { until: DateTime<Utc> },
    Approved { applied_at: DateTime<Utc>, outcome: ApprovalOutcome },
    Dismissed { reason: String, dismissed_at: DateTime<Utc> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// Operator ran the suggested remediation and confirmed.
    Applied,
    /// Operator clicked apply but the dispatched handler errored
    /// (v2-only — v1 proposals are `Manual`, never one-click).
    Failed { error: String },
    /// Analyzer noticed the condition cleared on its own (e.g. disk
    /// freed, container restart-loop stopped). No operator action.
    /// Distinguished from `Applied` so the audit trail keeps the
    /// closed-loop signal honest.
    ConditionCleared,
}

/// One inbox entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub finding_type: String,
    pub source: ProposalSource,
    pub severity: Severity,
    pub title: String,
    pub why: String,
    pub evidence: Vec<Evidence>,
    pub remediation: RemediationPlan,
    pub scope: ProposalScope,
    pub status: ProposalStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Proposal {
    /// Build a fresh `Pending` proposal. Caller fills in the
    /// finding-specific fields; this fixes id + timestamps + status.
    pub fn new(
        finding_type: impl Into<String>,
        source: ProposalSource,
        severity: Severity,
        title: impl Into<String>,
        why: impl Into<String>,
        evidence: Vec<Evidence>,
        remediation: RemediationPlan,
        scope: ProposalScope,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            finding_type: finding_type.into(),
            source,
            severity,
            title: title.into(),
            why: why.into(),
            evidence,
            remediation,
            scope,
            status: ProposalStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }

    /// Stable identity for dedup. Two proposals collide iff their
    /// finding_type and scope match.
    pub fn dedup_key(&self) -> (String, ProposalScope) {
        (self.finding_type.clone(), self.scope.clone())
    }
}

/// On-disk persistence of the inbox. JSON file under
/// `/etc/wolfstack/predictive_proposals.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProposalStore {
    /// `proposals` is a flat list rather than a HashMap because order
    /// of insertion matters for stable inbox UX and serde-default
    /// HashMap iteration order would shuffle entries on every save.
    #[serde(default)]
    pub proposals: Vec<Proposal>,
}

/// File location for the proposal store. Top-level fn so tests can
/// inject a temp path via the env var.
pub fn proposals_file() -> PathBuf {
    if let Ok(p) = std::env::var("WOLFSTACK_PROPOSALS_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from("/etc/wolfstack/predictive_proposals.json")
}

impl ProposalStore {
    pub fn load() -> Self {
        let path = proposals_file();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = proposals_file();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write proposals file: {}", e))?;
        Ok(())
    }

    /// Insert or update by dedup key. Returns the canonical id of
    /// the upserted record. If a `Snoozed` or `Dismissed` proposal
    /// exists for the same key, it's preserved unchanged — the
    /// operator's prior decision wins until snooze expires or the
    /// dismissal is explicitly cleared.
    ///
    /// On update of a `Pending` entry: `created_at` is preserved
    /// (so the inbox shows "this has been a problem for N days"),
    /// `updated_at`/`severity`/`evidence`/`why` are refreshed.
    /// True when a proposal with this dedup key already exists (any
    /// status). Lets callers tell a genuinely NEW upsert from a refresh
    /// of a standing one — the orchestrator logs only the former.
    pub fn contains_key(&self, key: &(String, ProposalScope)) -> bool {
        self.proposals.iter().any(|p| p.dedup_key() == *key)
    }

    /// Grace window after an operator marks a finding "applied", during
    /// which the finding is neither re-surfaced (`upsert`) nor rebuilt by
    /// analyzers (`is_suppressed`). Must comfortably exceed the package
    /// index refresh throttle (default ~6h) so the condition can actually
    /// be re-verified before we nag again. See `upsert` for the storm this
    /// prevents.
    const APPLIED_GRACE_HOURS: i64 = 12;

    pub fn upsert(&mut self, incoming: Proposal) -> String {
        let key = incoming.dedup_key();
        if let Some(existing) = self.proposals.iter_mut()
            .find(|p| p.dedup_key() == key)
        {
            // Operator action stands until expiry — never overwrite.
            match &existing.status {
                ProposalStatus::Snoozed { until } if *until > Utc::now() => {
                    return existing.id.clone();
                }
                ProposalStatus::Dismissed { .. } => {
                    return existing.id.clone();
                }
                // A finding the operator just marked "applied" must NOT be
                // resurrected to Pending on every tick. The vuln sampler
                // reads the package manager's *cached* index (refreshed at
                // most ~6h) and kernel updates stay "pending" until a
                // reboot, so the condition reads true long after the apply.
                // Without this grace the proposal ping-pongs Approved↔Pending
                // every 5-min tick which, via the cluster inbox fan-out,
                // pegs CPU fleet-wide. It re-surfaces after the window if
                // the condition is genuinely still true (apply didn't take).
                ProposalStatus::Approved { applied_at, outcome: ApprovalOutcome::Applied }
                    if *applied_at + chrono::Duration::hours(Self::APPLIED_GRACE_HOURS) > Utc::now() =>
                {
                    return existing.id.clone();
                }
                _ => {}
            }
            // Refresh in place — preserve id and created_at.
            existing.severity = incoming.severity;
            existing.title = incoming.title;
            existing.why = incoming.why;
            existing.evidence = incoming.evidence;
            existing.remediation = incoming.remediation;
            existing.source = incoming.source;
            existing.status = ProposalStatus::Pending;
            existing.updated_at = Utc::now();
            existing.id.clone()
        } else {
            let id = incoming.id.clone();
            self.proposals.push(incoming);
            id
        }
    }

    /// Auto-resolve `Pending` proposals whose (finding_type, scope)
    /// pair was *covered* by an analyzer in this tick but not
    /// re-emitted — i.e. the analyzer looked at the resource and
    /// found nothing wrong, so the previously-pending finding has
    /// cleared. Records as `Approved { outcome: ConditionCleared }`
    /// so the audit trail shows the operator didn't apply anything;
    /// the system noticed the issue resolved on its own.
    ///
    /// Without this, a disk that was filling and then got cleaned up
    /// would leave its proposal sitting in the inbox until the
    /// 90-day retention sweep — confusing the operator and erasing
    /// the closed-loop signal that the analyzer is working.
    ///
    /// `covered_scopes` is the set of `(finding_type, scope)` pairs
    /// the analyzer evaluated this tick (regardless of whether it
    /// emitted a proposal for them). The orchestrator builds this
    /// from the analyzer's input list, NOT from its output — that's
    /// what makes the auto-resolve work.
    ///
    /// Returns the number of proposals auto-resolved.
    pub fn auto_resolve_cleared(
        &mut self,
        covered: &[(String, ProposalScope)],
        emitted: &[(String, ProposalScope)],
    ) -> usize {
        let mut count = 0;
        for p in &mut self.proposals {
            if !matches!(p.status, ProposalStatus::Pending) { continue; }
            let key = (p.finding_type.clone(), p.scope.clone());
            // Was this (finding, scope) under the analyzer's eye
            // this tick but NOT re-emitted? If so, the condition has
            // cleared — auto-resolve.
            let was_considered = covered.iter().any(|c| *c == key);
            let was_emitted = emitted.iter().any(|e| *e == key);
            if was_considered && !was_emitted {
                p.status = ProposalStatus::Approved {
                    applied_at: Utc::now(),
                    outcome: ApprovalOutcome::ConditionCleared,
                };
                p.updated_at = Utc::now();
                count += 1;
            }
        }
        count
    }

    /// Returns true if there's an active suppression for this
    /// (finding_type, scope) — either a Snoozed proposal whose snooze
    /// hasn't expired, or a Dismissed proposal. Analyzers query this
    /// to skip building proposals that would be filtered out anyway.
    pub fn is_suppressed(&self, finding_type: &str, scope: &ProposalScope) -> bool {
        let now = Utc::now();
        self.proposals.iter().any(|p| {
            p.finding_type == finding_type
                && p.scope == *scope
                && match &p.status {
                    ProposalStatus::Snoozed { until } => *until > now,
                    ProposalStatus::Dismissed { .. } => true,
                    // Stay suppressed during the post-apply grace window so
                    // analyzers don't rebuild the finding every tick (which
                    // is what feeds the resurrection storm — see `upsert`).
                    ProposalStatus::Approved { applied_at, outcome: ApprovalOutcome::Applied } =>
                        *applied_at + chrono::Duration::hours(Self::APPLIED_GRACE_HOURS) > now,
                    _ => false,
                }
        })
    }

    /// Inbox view: pending + currently-snoozed-but-not-expired,
    /// sorted by (severity rank, then most-recent updated_at first).
    pub fn inbox(&self) -> Vec<&Proposal> {
        let now = Utc::now();
        let mut out: Vec<&Proposal> = self.proposals.iter()
            .filter(|p| match &p.status {
                ProposalStatus::Pending => true,
                ProposalStatus::Snoozed { until } => *until > now,
                _ => false,
            })
            .collect();
        out.sort_by(|a, b| {
            a.severity.rank().cmp(&b.severity.rank())
                .then_with(|| b.updated_at.cmp(&a.updated_at))
        });
        out
    }

    pub fn get(&self, id: &str) -> Option<&Proposal> {
        self.proposals.iter().find(|p| p.id == id)
    }

    pub fn snooze(&mut self, id: &str, until: DateTime<Utc>) -> Result<(), String> {
        let p = self.proposals.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| format!("proposal {} not found", id))?;
        p.status = ProposalStatus::Snoozed { until };
        p.updated_at = Utc::now();
        Ok(())
    }

    pub fn dismiss(&mut self, id: &str, reason: impl Into<String>) -> Result<(), String> {
        let p = self.proposals.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| format!("proposal {} not found", id))?;
        p.status = ProposalStatus::Dismissed {
            reason: reason.into(),
            dismissed_at: Utc::now(),
        };
        p.updated_at = Utc::now();
        Ok(())
    }

    pub fn record_approval(&mut self, id: &str, outcome: ApprovalOutcome) -> Result<(), String> {
        let p = self.proposals.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| format!("proposal {} not found", id))?;
        p.status = ProposalStatus::Approved {
            applied_at: Utc::now(),
            outcome,
        };
        p.updated_at = Utc::now();
        Ok(())
    }

    /// Drop `Approved` and `Dismissed` proposals whose
    /// `updated_at` is older than `days`. Pending and active-Snoozed
    /// entries are never pruned regardless of age — they're still
    /// surfaced in the inbox and dropping them would drop live
    /// state. Returns the number of entries removed.
    ///
    /// Called periodically from the orchestrator so the store
    /// doesn't grow unboundedly across years of operator use.
    pub fn prune_resolved_older_than(&mut self, days: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        let before = self.proposals.len();
        self.proposals.retain(|p| match &p.status {
            ProposalStatus::Approved { .. } | ProposalStatus::Dismissed { .. } => {
                p.updated_at >= cutoff
            }
            _ => true,
        });
        before - self.proposals.len()
    }

    /// Test-only per-rule statistics. Used by the trust-calibration
    /// test cases to assert "rules that get dismissed often should
    /// auto-quiet"; the production auto-quiet path consumes
    /// `proposals` directly so this aggregator isn't on a live
    /// code path.
    #[cfg(test)]
    pub fn stats_by_rule(&self) -> HashMap<String, RuleStats> {
        let mut out: HashMap<String, RuleStats> = HashMap::new();
        for p in &self.proposals {
            let s = out.entry(p.finding_type.clone()).or_default();
            s.fired += 1;
            match &p.status {
                ProposalStatus::Approved { .. } => s.approved += 1,
                ProposalStatus::Snoozed { .. } => s.snoozed += 1,
                ProposalStatus::Dismissed { reason, .. } => {
                    s.dismissed += 1;
                    s.dismiss_reasons.push(reason.clone());
                }
                ProposalStatus::Pending => s.pending += 1,
            }
        }
        out
    }
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    pub fired: u64,
    pub approved: u64,
    pub snoozed: u64,
    pub dismissed: u64,
    pub pending: u64,
    pub dismiss_reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn scope(node: &str, resource: Option<&str>) -> ProposalScope {
        ProposalScope { node_id: node.into(), resource_id: resource.map(|s| s.into()) }
    }

    fn fake_proposal(finding: &str, sev: Severity, sc: ProposalScope) -> Proposal {
        Proposal::new(
            finding,
            ProposalSource::Rule,
            sev,
            "title",
            "why",
            vec![],
            RemediationPlan::Manual { instructions: "do thing".into(), commands: vec![] },
            sc,
        )
    }

    #[test]
    fn upsert_dedups_on_finding_type_and_scope() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));

        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        store.upsert(fake_proposal("disk_fill_eta", Severity::High, s.clone()));

        assert_eq!(store.proposals.len(), 1);
        assert_eq!(store.proposals[0].severity, Severity::High);
    }

    #[test]
    fn upsert_preserves_created_at_on_refresh() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));

        let mut first = fake_proposal("disk_fill_eta", Severity::Warn, s.clone());
        // Pretend this finding has been around for two days.
        first.created_at = Utc::now() - Duration::days(2);
        let original_created = first.created_at;
        store.upsert(first);

        store.upsert(fake_proposal("disk_fill_eta", Severity::High, s.clone()));

        assert_eq!(store.proposals[0].created_at, original_created,
            "created_at should be preserved on refresh so the inbox \
             can show 'this has been a problem for N days'");
    }

    #[test]
    fn upsert_does_not_clobber_dismissed_proposal() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        store.dismiss(&id, "intentionally fills, log rotation handles it").unwrap();

        // Analyzer re-fires next cycle — must NOT resurrect.
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        assert_eq!(store.proposals.len(), 1);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Dismissed { .. }));
    }

    #[test]
    fn upsert_does_not_clobber_active_snooze() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        store.snooze(&id, Utc::now() + Duration::hours(4)).unwrap();

        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        match &store.proposals[0].status {
            ProposalStatus::Snoozed { .. } => {}
            other => panic!("expected snooze preserved, got {:?}", other),
        }
        // Severity must not have updated either — operator's snooze
        // means "I know, leave me alone".
        assert_eq!(store.proposals[0].severity, Severity::Warn);
    }

    #[test]
    fn expired_snooze_allows_refresh() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        // Snooze in the past — already expired.
        store.snooze(&id, Utc::now() - Duration::minutes(1)).unwrap();

        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
        assert_eq!(store.proposals[0].severity, Severity::Critical);
    }

    #[test]
    fn upsert_does_not_resurrect_recently_applied() {
        // The CPU-storm regression: marking a vuln "applied" then having
        // the analyzer re-fire (cached pkg index still shows it pending)
        // must NOT flip it back to Pending — it stays Approved during grace.
        let mut store = ProposalStore::default();
        let s = scope("node-a", None);
        store.upsert(fake_proposal("host_security_updates_pending", Severity::High, s.clone()));
        let id = store.proposals[0].id.clone();
        store.record_approval(&id, ApprovalOutcome::Applied).unwrap();

        // Analyzer re-fires next tick — condition still reads true.
        store.upsert(fake_proposal("host_security_updates_pending", Severity::High, s.clone()));

        assert_eq!(store.proposals.len(), 1);
        assert!(matches!(store.proposals[0].status,
            ProposalStatus::Approved { outcome: ApprovalOutcome::Applied, .. }),
            "a just-applied finding must not be resurrected to Pending every tick");
        // And the analyzer should skip rebuilding it entirely during grace.
        assert!(store.is_suppressed("host_security_updates_pending", &s));
    }

    #[test]
    fn applied_finding_resurfaces_after_grace_expires() {
        // If the apply genuinely didn't take, the finding must come back
        // after the grace window so the operator isn't left blind.
        let mut store = ProposalStore::default();
        let s = scope("node-a", None);
        store.upsert(fake_proposal("host_security_updates_pending", Severity::High, s.clone()));
        // Simulate an apply that happened longer ago than the grace window.
        store.proposals[0].status = ProposalStatus::Approved {
            applied_at: Utc::now() - Duration::hours(ProposalStore::APPLIED_GRACE_HOURS + 1),
            outcome: ApprovalOutcome::Applied,
        };

        assert!(!store.is_suppressed("host_security_updates_pending", &s));
        store.upsert(fake_proposal("host_security_updates_pending", Severity::Critical, s.clone()));
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending),
            "an applied finding still true after the grace window must re-surface");
    }

    #[test]
    fn is_suppressed_honors_snooze_and_dismissal() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));

        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();

        assert!(!store.is_suppressed("disk_fill_eta", &s));

        store.snooze(&id, Utc::now() + Duration::hours(2)).unwrap();
        assert!(store.is_suppressed("disk_fill_eta", &s));

        // Different finding_type for same scope — not suppressed.
        assert!(!store.is_suppressed("memory_pressure", &s));
    }

    #[test]
    fn inbox_sorts_critical_first() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("a", Severity::Warn,
            scope("n", Some("/a"))));
        store.upsert(fake_proposal("b", Severity::Critical,
            scope("n", Some("/b"))));
        store.upsert(fake_proposal("c", Severity::Info,
            scope("n", Some("/c"))));

        let inbox = store.inbox();
        assert_eq!(inbox[0].finding_type, "b");
        assert_eq!(inbox[1].finding_type, "a");
        assert_eq!(inbox[2].finding_type, "c");
    }

    #[test]
    fn dismissed_proposals_excluded_from_inbox() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("a", Severity::Warn,
            scope("n", Some("/a"))));
        let id = store.proposals[0].id.clone();
        store.dismiss(&id, "ack").unwrap();

        assert_eq!(store.inbox().len(), 0);
    }

    #[test]
    fn auto_resolve_clears_pending_when_condition_gone() {
        let mut store = ProposalStore::default();
        let s_disk = scope("n", Some("/var"));
        let s_mem = scope("n", Some("postgres"));

        // Two pending findings.
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s_disk.clone()));
        store.upsert(fake_proposal("memory_pressure", Severity::Warn, s_mem.clone()));

        // Analyzer considered both this tick but only re-emitted memory.
        let covered = vec![
            ("disk_fill_eta".to_string(), s_disk.clone()),
            ("memory_pressure".to_string(), s_mem.clone()),
        ];
        let emitted = vec![
            ("memory_pressure".to_string(), s_mem.clone()),
        ];

        let n = store.auto_resolve_cleared(&covered, &emitted);
        assert_eq!(n, 1, "exactly one proposal should auto-resolve");

        // Disk one is now Approved-with-ConditionCleared, memory still Pending.
        let disk = store.proposals.iter()
            .find(|p| p.finding_type == "disk_fill_eta").unwrap();
        match &disk.status {
            ProposalStatus::Approved { outcome, .. } => {
                assert!(matches!(outcome, ApprovalOutcome::ConditionCleared));
            }
            other => panic!("expected Approved/ConditionCleared, got {:?}", other),
        }
        let mem = store.proposals.iter()
            .find(|p| p.finding_type == "memory_pressure").unwrap();
        assert!(matches!(mem.status, ProposalStatus::Pending));
    }

    #[test]
    fn auto_resolve_does_not_touch_uncovered_pending() {
        // Critical safety property: if the analyzer didn't run at
        // all (data source unavailable), it covers NO scopes — and
        // we MUST NOT auto-resolve everything. Pending proposals
        // for scopes the analyzer didn't consider stay Pending.
        let mut store = ProposalStore::default();
        let s = scope("n", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        // Empty covered list (analyzer didn't run / data missing).
        let n = store.auto_resolve_cleared(&[], &[]);
        assert_eq!(n, 0, "an analyzer that ran on nothing must not resolve anything");
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
    }

    #[test]
    fn auto_resolve_skips_snoozed_and_dismissed() {
        let mut store = ProposalStore::default();
        let s = scope("n", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        store.snooze(&id, Utc::now() + Duration::hours(4)).unwrap();

        // Analyzer considered the scope but didn't emit (cleared
        // condition). Snoozed proposal must stay Snoozed — operator
        // intent dominates.
        let covered = vec![("disk_fill_eta".to_string(), s.clone())];
        let n = store.auto_resolve_cleared(&covered, &[]);
        assert_eq!(n, 0);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Snoozed { .. }));
    }

    #[test]
    fn prune_drops_old_resolved_keeps_pending() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("a", Severity::Warn, scope("n", Some("/old-dismissed"))));
        store.upsert(fake_proposal("b", Severity::Warn, scope("n", Some("/old-approved"))));
        store.upsert(fake_proposal("c", Severity::Warn, scope("n", Some("/recent-dismissed"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/pending"))));

        let id_a = store.proposals[0].id.clone();
        let id_b = store.proposals[1].id.clone();
        let id_c = store.proposals[2].id.clone();
        store.dismiss(&id_a, "old").unwrap();
        store.record_approval(&id_b, ApprovalOutcome::Applied).unwrap();
        store.dismiss(&id_c, "recent").unwrap();

        // Backdate a and b by 100 days; leave c and d at "now".
        store.proposals[0].updated_at = Utc::now() - Duration::days(100);
        store.proposals[1].updated_at = Utc::now() - Duration::days(100);

        let dropped = store.prune_resolved_older_than(30);
        assert_eq!(dropped, 2, "old resolved entries should be pruned");

        let remaining: Vec<&str> = store.proposals.iter()
            .map(|p| p.scope.resource_id.as_deref().unwrap_or(""))
            .collect();
        assert!(remaining.contains(&"/recent-dismissed"));
        assert!(remaining.contains(&"/pending"),
            "pending entries must NEVER be pruned regardless of age");
    }

    #[test]
    fn stats_classify_each_status() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/a"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/b"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/c"))));

        let id_b = store.proposals[1].id.clone();
        let id_c = store.proposals[2].id.clone();
        store.dismiss(&id_b, "false positive").unwrap();
        store.record_approval(&id_c, ApprovalOutcome::Applied).unwrap();

        let stats = store.stats_by_rule();
        let s = stats.get("d").unwrap();
        assert_eq!(s.fired, 3);
        assert_eq!(s.dismissed, 1);
        assert_eq!(s.approved, 1);
        assert_eq!(s.pending, 1);
        assert_eq!(s.dismiss_reasons, vec!["false positive".to_string()]);
    }
}
