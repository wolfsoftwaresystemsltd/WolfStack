// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! WolfNotify — event notification for containers and VMs.
//!
//! ## Why this exists
//!
//! Nothing in WolfStack noticed a container going down. `alert_containers`
//! reads as though it did, but it only gates per-container *memory* findings
//! (`predictive::container_memory`); the threshold dispatch beside it in
//! `main.rs` is marked RETIRED. A container that exited non-zero, was
//! OOM-killed, failed its healthcheck or sat in a restart loop was silent.
//!
//! ## What this is NOT
//!
//! Not a second notification system. `alerting.rs` already delivers to Discord,
//! Slack, Telegram, ntfy and email with masked secrets and working retries; a
//! parallel subsystem would mean two secret stores and two places to look when
//! something failed to page you. This module supplies the two halves alerting
//! lacks — an **event source** and a **rule layer** — and hands the result to
//! `alerting::dispatch_to_selected`.
//!
//! ## Shape
//!
//! ```text
//!   docker events ──→ NotifyEvent ──→ evaluate() ──→ dispatch_to_selected()
//!   egress probes ──┘                 (pure)         (existing, alerting.rs)
//! ```
//!
//! [`evaluate`] is deliberately pure: an event plus a rule set in, matches out,
//! with no clock, filesystem or network. Cooldown state and timestamps are
//! passed in by the caller. The hard cases — "3 failures in 10 minutes", glob
//! matching on names — are then testable without a running daemon.
//!
//! See `docs/wolfnotify-design.md` for the full design and the phases beyond
//! this one.

pub mod source_docker;
pub mod source_poll;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::alerting::Channel;

/// What happened. Deliberately small and stable — everything else is an
/// attribute of the event, not a new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Clean stop — exit 0, or an operator action.
    ObjectStopped,
    /// Exit non-zero, crash, or a VM entering a failed state.
    ObjectFailed,
    /// The kernel OOM-killed the workload.
    ObjectOomKilled,
    /// A healthcheck transitioned to unhealthy.
    ObjectHealthFailed,
    /// Repeated restarts inside a window — invisible before this module.
    ObjectRestartLooping,
    /// Back up. Lets a rule close the incident it opened.
    ObjectStarted,
    /// Lost outbound connectivity *from inside the object's network*. The
    /// silent failure: the container is `Up`, healthy by every state check,
    /// and useless. State monitoring is structurally blind to this.
    ObjectEgressFailed,
    /// Outbound connectivity returned.
    ObjectEgressRestored,
    /// The event source itself died or stopped reporting. Must be alertable:
    /// a monitor the operator has learned to trust, which has silently
    /// stopped, is worse than no monitor at all.
    SourceDegraded,
}

impl EventKind {
    /// Whether this event represents a return to health, and so should close
    /// rather than open an incident.
    pub fn is_recovery(self) -> bool {
        matches!(self, EventKind::ObjectStarted | EventKind::ObjectEgressRestored)
    }

    /// Short human label used in notification titles.
    pub fn label(self) -> &'static str {
        match self {
            EventKind::ObjectStopped => "stopped",
            EventKind::ObjectFailed => "failed",
            EventKind::ObjectOomKilled => "OOM-killed",
            EventKind::ObjectHealthFailed => "unhealthy",
            EventKind::ObjectRestartLooping => "restart-looping",
            EventKind::ObjectStarted => "started",
            EventKind::ObjectEgressFailed => "lost outbound connectivity",
            EventKind::ObjectEgressRestored => "regained outbound connectivity",
            EventKind::SourceDegraded => "monitoring degraded",
        }
    }
}

/// A single observed occurrence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyEvent {
    pub kind: EventKind,
    pub node: String,
    /// `docker`, `libvirt`, `lxc`, `pve`.
    pub backend: String,
    /// Container or VM name.
    pub object: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub restart_count: Option<u32>,
    /// Unix seconds. Passed in rather than read from a clock so evaluation
    /// stays pure and testable.
    pub timestamp: u64,
    #[serde(default)]
    pub message: String,
}

/// Where a rule lives and is evaluated. The operator's choice, per rule —
/// there is no globally correct answer, so we don't impose one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// This node only.
    #[default]
    Node,
    /// Replicated to every node, last-write-wins on `version` — the same
    /// mechanism as AuthConfig and the threat-intel allowlists.
    Cluster,
}

/// How much rule the operator wanted. Simple is not a lesser mode: it is the
/// default and must be completable without reading documentation. Advanced is
/// an explicit opt-in to condition combining, windows and counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Simple,
    Advanced,
}

/// What a rule fires on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchSpec {
    /// Empty means "any event kind".
    #[serde(default)]
    pub events: Vec<EventKind>,
    /// Empty means "any backend".
    #[serde(default)]
    pub backends: Vec<String>,
    /// Globs against the object name. Empty means "any object".
    #[serde(default)]
    pub objects: Vec<String>,
    /// Every entry must be present and equal on the event. Empty means "any".
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Globs against the node name. Empty means "any node".
    #[serde(default)]
    pub nodes: Vec<String>,
}

fn default_true() -> bool { true }
fn default_cooldown() -> u64 { 900 }

/// One operator-defined rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default, rename = "match")]
    pub match_spec: MatchSpec,
    /// Channels this rule routes to. Empty means "every configured channel",
    /// so a rule written before routing existed still delivers.
    #[serde(default)]
    pub channels: Vec<Channel>,
    /// Seconds of silence per (rule, object) after firing. Per-OBJECT, not per
    /// rule: one flapping container must not mute its healthy neighbours,
    /// which is the mistake that gets notification systems switched off.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    /// Optional WolfFlow to run on match — the "do something about it" bridge.
    #[serde(default)]
    pub run_flow: Option<String>,
}

impl NotifyRule {
    /// Channels to deliver on, resolving "empty means all".
    pub fn resolved_channels(&self) -> Vec<Channel> {
        if self.channels.is_empty() {
            Channel::ALL.to_vec()
        } else {
            self.channels.clone()
        }
    }
}

/// Persisted rule set. `version` carries the same last-write-wins semantics as
/// the other replicated config, so cluster-scoped rules can be synced without
/// inventing a new mechanism.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyRules {
    #[serde(default)]
    pub rules: Vec<NotifyRule>,
    #[serde(default)]
    pub version: u64,
}

fn rules_path() -> String {
    format!("{}/notify-rules.json", crate::paths::get().config_dir)
}

impl NotifyRules {
    pub fn load() -> Self {
        match std::fs::read_to_string(rules_path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                tracing::warn!("notify-rules.json parse error ({}), using none", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let mut stamped = self.clone();
        stamped.version = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let json = serde_json::to_string_pretty(&stamped).map_err(|e| e.to_string())?;
        // 0600 — rules can name hosts and objects an operator would rather not
        // publish, and sit beside the channel secrets they route to.
        crate::paths::write_secure(&rules_path(), &json)
            .map_err(|e| format!("Failed to write notify rules: {}", e))
    }
}

/// Glob match supporting `*` only — enough for `*-db`, `prod-*`, `*`.
///
/// Deliberately not a regex: rules are typed by operators under pressure, and a
/// mistyped regex that silently matches nothing is a notification that never
/// arrives. `*` is predictable and hard to get subtly wrong.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else {
            match value[pos..].find(part) {
                Some(found) => pos += found + part.len(),
                None => return false,
            }
        }
    }
    // A trailing non-`*` segment must land at the end.
    if let Some(last) = parts.last()
        && !last.is_empty()
        && !value.ends_with(last)
    {
        return false;
    }
    true
}

fn any_glob(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob_match(p, value))
}

/// Does `rule` match `event`? Ignores enabled/cooldown — those are the
/// caller's concern, kept out so this stays a pure predicate.
pub fn rule_matches(rule: &NotifyRule, event: &NotifyEvent) -> bool {
    let m = &rule.match_spec;
    if !m.events.is_empty() && !m.events.contains(&event.kind) {
        return false;
    }
    if !m.backends.is_empty() && !m.backends.iter().any(|b| b == &event.backend) {
        return false;
    }
    if !any_glob(&m.objects, &event.object) {
        return false;
    }
    if !any_glob(&m.nodes, &event.node) {
        return false;
    }
    for (k, v) in &m.labels {
        if event.labels.get(k).map(String::as_str) != Some(v.as_str()) {
            return false;
        }
    }
    true
}

/// Key identifying a cooldown bucket: per rule AND per object.
pub fn cooldown_key(rule: &NotifyRule, event: &NotifyEvent) -> String {
    format!("{}::{}::{}", rule.id, event.node, event.object)
}

/// Which rules should fire for this event.
///
/// `last_fired` maps [`cooldown_key`] to the unix second a rule last fired for
/// that object; entries older than the rule's cooldown are ignored. Recovery
/// events bypass the cooldown — telling someone a thing came back is never
/// noise, and suppressing it strands an open incident.
pub fn evaluate<'a>(
    event: &NotifyEvent,
    rules: &'a [NotifyRule],
    last_fired: &HashMap<String, u64>,
) -> Vec<&'a NotifyRule> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .filter(|r| rule_matches(r, event))
        .filter(|r| {
            if event.kind.is_recovery() {
                return true;
            }
            match last_fired.get(&cooldown_key(r, event)) {
                Some(&last) => event.timestamp.saturating_sub(last) >= r.cooldown_secs,
                None => true,
            }
        })
        .collect()
}

/// Title and body for a matched event.
pub fn render(event: &NotifyEvent, rule: &NotifyRule) -> (String, String) {
    let title = format!(
        "{} {} {}",
        if event.kind.is_recovery() { "✅" } else { "⚠️" },
        event.object,
        event.kind.label()
    );
    let mut body = format!(
        "{} `{}` on node `{}` {}.",
        event.backend, event.object, event.node, event.kind.label()
    );
    if let Some(code) = event.exit_code {
        body.push_str(&format!("\nExit code: {}", code));
    }
    if let Some(n) = event.restart_count {
        body.push_str(&format!("\nRestarts: {}", n));
    }
    if !event.message.is_empty() {
        body.push_str(&format!("\n{}", event.message));
    }
    body.push_str(&format!("\n\nRule: {}", rule.name));
    (title, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind, object: &str) -> NotifyEvent {
        NotifyEvent {
            kind,
            node: "wolfstack-2".into(),
            backend: "docker".into(),
            object: object.into(),
            labels: HashMap::new(),
            exit_code: None,
            restart_count: None,
            timestamp: 1_000,
            message: String::new(),
        }
    }

    fn rule(id: &str, spec: MatchSpec) -> NotifyRule {
        NotifyRule {
            id: id.into(),
            name: format!("rule {}", id),
            enabled: true,
            scope: Scope::Node,
            mode: Mode::Simple,
            match_spec: spec,
            channels: vec![],
            cooldown_secs: 900,
            run_flow: None,
        }
    }

    // ── glob ──

    #[test]
    fn glob_star_matches_everything() {
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn glob_prefix_and_suffix() {
        assert!(glob_match("prod-*", "prod-web"));
        assert!(!glob_match("prod-*", "dev-web"));
        assert!(glob_match("*-db", "customer-db"));
        assert!(!glob_match("*-db", "db-customer"));
    }

    #[test]
    fn glob_exact_when_no_star() {
        assert!(glob_match("speedtest-tracker", "speedtest-tracker"));
        assert!(!glob_match("speedtest", "speedtest-tracker"));
    }

    #[test]
    fn glob_middle_star() {
        assert!(glob_match("prod-*-db", "prod-eu-db"));
        assert!(!glob_match("prod-*-db", "prod-eu-cache"));
    }

    // ── matching ──

    #[test]
    fn empty_match_spec_matches_any_event() {
        // A rule with no filters is "tell me about everything" — it must not
        // silently match nothing.
        let r = rule("a", MatchSpec::default());
        assert!(rule_matches(&r, &ev(EventKind::ObjectFailed, "web")));
    }

    #[test]
    fn event_kind_filter_is_respected() {
        let r = rule("a", MatchSpec { events: vec![EventKind::ObjectFailed], ..Default::default() });
        assert!(rule_matches(&r, &ev(EventKind::ObjectFailed, "web")));
        assert!(!rule_matches(&r, &ev(EventKind::ObjectStopped, "web")));
    }

    #[test]
    fn labels_must_all_match() {
        let mut want = HashMap::new();
        want.insert("tier".to_string(), "prod".to_string());
        let r = rule("a", MatchSpec { labels: want, ..Default::default() });

        let mut e = ev(EventKind::ObjectFailed, "web");
        assert!(!rule_matches(&r, &e), "missing label must not match");
        e.labels.insert("tier".into(), "dev".into());
        assert!(!rule_matches(&r, &e), "wrong label value must not match");
        e.labels.insert("tier".into(), "prod".into());
        assert!(rule_matches(&r, &e));
    }

    // ── cooldown ──

    #[test]
    fn cooldown_suppresses_a_repeat_for_the_same_object() {
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let mut fired = HashMap::new();
        let e = ev(EventKind::ObjectFailed, "web");
        fired.insert(cooldown_key(&r, &e), 900u64);   // 100s ago, cooldown 900
        assert!(evaluate(&e, &rules, &fired).is_empty());
    }

    #[test]
    fn cooldown_is_per_object_not_per_rule() {
        // The property that decides whether this feature survives contact with
        // a flapping container: one noisy object must not mute the rest.
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let noisy = ev(EventKind::ObjectFailed, "flapping");
        let quiet = ev(EventKind::ObjectFailed, "healthy-neighbour");
        let mut fired = HashMap::new();
        fired.insert(cooldown_key(&r, &noisy), 900u64);

        assert!(evaluate(&noisy, &rules, &fired).is_empty(), "noisy object stays suppressed");
        assert_eq!(evaluate(&quiet, &rules, &fired).len(), 1, "neighbour must still alert");
    }

    #[test]
    fn cooldown_expires() {
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let mut e = ev(EventKind::ObjectFailed, "web");
        let mut fired = HashMap::new();
        fired.insert(cooldown_key(&r, &e), 0u64);
        e.timestamp = 1_000;   // 1000s later, cooldown 900
        assert_eq!(evaluate(&e, &rules, &fired).len(), 1);
    }

    #[test]
    fn recovery_bypasses_cooldown() {
        // Suppressing "it came back" leaves an incident open forever.
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let e = ev(EventKind::ObjectStarted, "web");
        let mut fired = HashMap::new();
        fired.insert(cooldown_key(&r, &e), 999u64);
        assert_eq!(evaluate(&e, &rules, &fired).len(), 1);
    }

    #[test]
    fn disabled_rules_never_fire() {
        let mut r = rule("a", MatchSpec::default());
        r.enabled = false;
        assert!(evaluate(&ev(EventKind::ObjectFailed, "web"), &[r], &HashMap::new()).is_empty());
    }

    // ── routing ──

    #[test]
    fn no_channels_means_every_channel() {
        // A rule written before routing existed, or left blank, must still
        // deliver rather than silently going nowhere.
        let r = rule("a", MatchSpec::default());
        assert_eq!(r.resolved_channels().len(), Channel::ALL.len());
    }

    #[test]
    fn explicit_channels_are_honoured() {
        let mut r = rule("a", MatchSpec::default());
        r.channels = vec![Channel::Ntfy];
        assert_eq!(r.resolved_channels(), vec![Channel::Ntfy]);
    }

    #[test]
    fn egress_failure_is_a_first_class_event() {
        // The silent failure: container Up, healthy, and unable to reach out.
        let r = rule("a", MatchSpec {
            events: vec![EventKind::ObjectEgressFailed],
            ..Default::default()
        });
        assert!(rule_matches(&r, &ev(EventKind::ObjectEgressFailed, "speedtest-tracker")));
        assert!(!rule_matches(&r, &ev(EventKind::ObjectStarted, "speedtest-tracker")));
    }
}

// ─── Runner ───

/// Consume events from every available source, evaluate rules, and deliver.
///
/// Rules are re-read per event rather than cached: events are rare (a busy node
/// sees a handful an hour), and it means an operator editing
/// `notify-rules.json` sees the effect immediately instead of after a restart.
pub async fn handle_event(
    event: NotifyEvent,
    last_fired: &mut HashMap<String, u64>,
) {
    let rules = NotifyRules::load();
    if rules.rules.is_empty() {
        return;
    }
    let matched = evaluate(&event, &rules.rules, last_fired);
    if matched.is_empty() {
        return;
    }
    let cfg = crate::alerting::AlertConfig::load();
    for rule in matched {
        let (title, body) = render(&event, rule);
        // Recovery is informational; a failure should be able to cut through
        // a phone's do-not-disturb, which is what ntfy priority 5 is for.
        let priority = if event.kind.is_recovery() { 3 } else { 5 };
        crate::alerting::dispatch_to_selected(
            &cfg, &rule.resolved_channels(), &title, &body, priority,
        ).await;
        last_fired.insert(cooldown_key(rule, &event), event.timestamp);
        tracing::info!(
            "notify: rule '{}' fired for {} {} ({})",
            rule.name, event.backend, event.object, event.kind.label()
        );
    }
}

/// Supervised `docker events` tail. Restarts with backoff; a source that has
/// silently stopped is worse than no source, so persistent failure is itself
/// reported through the rule engine as [`EventKind::SourceDegraded`].
pub async fn run_docker_source(node: String) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let mut last_fired: HashMap<String, u64> = HashMap::new();
    let mut tracker = source_docker::RestartTracker::default();
    let mut backoff_secs = 5u64;
    let mut degraded_reported = false;

    loop {
        if std::process::Command::new("docker").arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
            // No docker on this node — nothing to watch, and nothing broken.
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            continue;
        }

        let child = Command::new("docker")
            .args(["events", "--format", "{{json .}}"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)   // never leak the child if this task is cancelled
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("notify: could not start docker events: {}", e);
                report_degraded(&node, &mut degraded_reported, &mut last_fired, &e.to_string()).await;
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(300);
                continue;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                let _ = child.kill().await;
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                continue;
            }
        };

        // Connected: reset the backoff and clear any degraded state.
        backoff_secs = 5;
        degraded_reported = false;
        tracing::info!("notify: docker event source connected");

        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Some(event) = source_docker::parse_docker_event(&line, &node) else {
                continue;
            };

            // Restart-loop detection sits here rather than in the parser: it
            // needs state across events, which the parser deliberately has none of.
            if event.kind == EventKind::ObjectFailed {
                let count = tracker.record(&event.object, event.timestamp, 600);
                if count >= 3 {
                    let mut loop_event = event.clone();
                    loop_event.kind = EventKind::ObjectRestartLooping;
                    loop_event.restart_count = Some(count as u32);
                    handle_event(loop_event, &mut last_fired).await;
                }
            } else if event.kind == EventKind::ObjectStarted {
                tracker.clear(&event.object);
            }

            handle_event(event, &mut last_fired).await;
        }

        // Stream ended — usually the daemon restarting.
        let _ = child.kill().await;
        tracing::warn!("notify: docker event stream ended, reconnecting in {}s", backoff_secs);
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(300);
    }
}

/// Report that a source is not reporting — once per outage, not per retry.
async fn report_degraded(
    node: &str,
    already: &mut bool,
    last_fired: &mut HashMap<String, u64>,
    detail: &str,
) {
    if *already {
        return;
    }
    *already = true;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    handle_event(
        NotifyEvent {
            kind: EventKind::SourceDegraded,
            node: node.to_string(),
            backend: "docker".into(),
            object: "docker-events".into(),
            labels: HashMap::new(),
            exit_code: None,
            restart_count: None,
            timestamp: now,
            message: detail.to_string(),
        },
        last_fired,
    )
    .await;
}

// ─── AI drafting ───

/// Pull the first balanced JSON object out of an LLM reply.
///
/// Models wrap JSON in ```json fences, prefix it with "Here's the rule:", or
/// both, depending on provider and mood. Scanning for a balanced object is the
/// only thing that survives all of them — and it must ignore braces inside
/// strings, or a rule whose name contains one truncates the parse.
pub fn extract_json_object(reply: &str) -> Option<&str> {
    let bytes = reply.as_bytes();
    let start = reply.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for i in start..bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            if escaped { escaped = false; }
            else if c == '\\' { escaped = true; }
            else if c == '"' { in_string = false; }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&reply[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// System prompt for drafting a probe. Enumerates the vocabulary explicitly —
/// a model inventing an event kind produces a rule that parses and never fires.
pub fn ai_system_prompt() -> String {
    let events = [
        "object_failed", "object_oom_killed", "object_health_failed",
        "object_restart_looping", "object_stopped", "object_started",
        "object_egress_failed", "object_egress_restored", "source_degraded",
    ].join(", ");
    format!(
        "You turn a plain-English request into ONE WolfStack notification rule.\n\
         Reply with a single JSON object and nothing else — no prose, no code fences.\n\n\
         Schema:\n\
         {{\n\
           \"id\": string (short slug),\n\
           \"name\": string (human label),\n\
           \"enabled\": bool,\n\
           \"scope\": \"node\" | \"cluster\",\n\
           \"mode\": \"simple\",\n\
           \"match\": {{\n\
             \"events\": [ {} ],\n\
             \"backends\": [\"docker\"],\n\
             \"objects\": [glob strings, * wildcard],\n\
             \"labels\": {{key: value}},\n\
             \"nodes\": [glob strings]\n\
           }},\n\
           \"channels\": [\"discord\"|\"slack\"|\"telegram\"|\"ntfy\"],\n\
           \"cooldown_secs\": integer\n\
         }}\n\n\
         Rules:\n\
         - Use ONLY the event names listed. Never invent one.\n\
         - An empty array means \"match anything\", so leave it empty rather than guessing.\n\
         - \"mode\" must be \"simple\": advanced conditions are not implemented yet.\n\
         - Default cooldown_secs to 900 unless the request implies otherwise.\n\
         - If the request does not name channels, leave \"channels\" empty (all configured channels).",
        events
    )
}

/// Draft a rule from a description. Returns the rule for the operator to
/// review — deliberately NOT saved. An auto-installed rule that quietly
/// matches nothing is the worst outcome this subsystem can produce.
pub async fn ai_draft_rule(description: &str) -> Result<NotifyRule, String> {
    let cfg = crate::ai::AiConfig::load();
    let reply = crate::ai::simple_chat(&cfg, &ai_system_prompt(), &[], description).await?;
    let json = extract_json_object(&reply)
        .ok_or_else(|| format!("the model did not return JSON: {}", reply.chars().take(160).collect::<String>()))?;
    let mut rule: NotifyRule = serde_json::from_str(json)
        .map_err(|e| format!("drafted rule did not fit the schema ({}): {}", e, json))?;
    // Never let the model decide these two.
    rule.mode = Mode::Simple;
    if rule.id.trim().is_empty() {
        rule.id = format!("probe-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    }
    Ok(rule)
}

#[cfg(test)]
mod ai_tests {
    use super::*;

    #[test]
    fn extracts_bare_json() {
        assert_eq!(extract_json_object(r#"{"a":1}"#), Some(r#"{"a":1}"#));
    }

    #[test]
    fn extracts_json_from_code_fences_and_prose() {
        // The two most common ways a model ignores "JSON only".
        let reply = "Here's the rule:\n```json\n{\"name\":\"db\"}\n```\nHope that helps!";
        assert_eq!(extract_json_object(reply), Some(r#"{"name":"db"}"#));
    }

    #[test]
    fn handles_nested_objects() {
        let reply = r#"{"match":{"labels":{"tier":"prod"}},"id":"x"}"#;
        assert_eq!(extract_json_object(reply), Some(reply));
    }

    #[test]
    fn a_brace_inside_a_string_does_not_truncate() {
        // A rule named `db {prod}` would otherwise cut the parse short and
        // produce a confusing schema error instead of a working rule.
        let reply = r#"{"name":"db {prod}","id":"x"}"#;
        assert_eq!(extract_json_object(reply), Some(reply));
    }

    #[test]
    fn an_escaped_quote_does_not_confuse_the_scanner() {
        let reply = r#"{"name":"say \"hi\"","id":"x"}"#;
        assert_eq!(extract_json_object(reply), Some(reply));
    }

    #[test]
    fn returns_none_when_there_is_no_json() {
        assert!(extract_json_object("I'm sorry, I can't do that.").is_none());
        assert!(extract_json_object("{unterminated").is_none());
    }

    #[test]
    fn the_prompt_lists_every_event_kind() {
        // A model that invents an event name yields a rule that parses and
        // never fires, so the vocabulary must be stated in full.
        let p = ai_system_prompt();
        for e in ["object_failed", "object_oom_killed", "object_restart_looping",
                  "object_egress_failed", "source_degraded"] {
            assert!(p.contains(e), "prompt is missing {}", e);
        }
    }
}

/// Poll LXC, libvirt and Proxmox for state changes.
///
/// Runs alongside the Docker event source, covering every backend that has no
/// event stream to subscribe to. Cadence is fixed at 60s: fast enough that an
/// outage is noticed promptly, slow enough that it costs nothing on a node with
/// hundreds of containers (the LXC snapshot reuses the shared listing cache).
pub async fn run_poll_sources(node: String) {
    use std::collections::HashMap;

    let mut last_fired: HashMap<String, u64> = HashMap::new();
    // None = never polled. The FIRST poll of each backend only seeds the
    // baseline and emits nothing; otherwise every daemon restart would report
    // every stopped container on the node as a fresh event.
    let mut prev: HashMap<&'static str, source_poll::StateMap> = HashMap::new();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Snapshots shell out, so keep them off the async worker threads.
        let snaps: Vec<(&'static str, source_poll::StateMap)> =
            match tokio::task::spawn_blocking(|| {
                vec![
                    ("lxc", source_poll::snapshot_lxc()),
                    ("libvirt", source_poll::snapshot_libvirt()),
                    ("pve", source_poll::snapshot_pve()),
                ]
            }).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("notify: poll snapshot task failed: {}", e);
                    continue;
                }
            };

        for (backend, now_map) in snaps {
            // A backend with no tooling installed reports nothing, forever —
            // don't let that look like "everything disappeared".
            if now_map.is_empty() && !prev.contains_key(backend) {
                continue;
            }
            match prev.get(backend) {
                None => {
                    tracing::info!(
                        "notify: {} poll seeded with {} object(s)", backend, now_map.len()
                    );
                }
                Some(prev_map) => {
                    for event in source_poll::diff_states(prev_map, &now_map, backend, &node, now_ts) {
                        handle_event(event, &mut last_fired).await;
                    }
                }
            }
            prev.insert(backend, now_map);
        }
    }
}
