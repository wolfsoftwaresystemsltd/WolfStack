// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Docker event source for WolfNotify.
//!
//! Tails `docker events --format '{{json .}}'` and turns container state
//! changes into [`NotifyEvent`]s.
//!
//! ## Wire format
//!
//! Verified against a live daemon (docker 29.7.1, 2026-08-06) rather than
//! assumed — two details would have been got wrong otherwise:
//!
//! 1. **`Action` carries a `:` suffix** for some events —
//!    `"exec_create: sh -c …"`, `"health_status: unhealthy"`. Matching the raw
//!    string misses every health transition.
//! 2. **`Actor.Attributes` mixes the container's labels with built-in
//!    attributes** (`name`, `image`, `exitCode`, `execID`). A rule matching
//!    `tier=prod` reads the same map as one matching `image`.
//!
//! `exitCode` arrives as a *string* (`"3"`), and `time` is unix seconds.
//!
//! A captured `docker run --rm --label tier=test <img> sh -c 'exit 3'`
//! produced, in order: `create`, `attach`, `start`, `die` (exitCode 3),
//! `destroy`. The tests below use those exact lines.
//!
//! ## Supervision
//!
//! The stream dies whenever the daemon restarts. A source that has quietly
//! stopped is worse than no source at all — the operator has learned to trust
//! it — so the runner restarts with backoff and emits
//! [`EventKind::SourceDegraded`] when it cannot.

use std::collections::HashMap;

use super::{EventKind, NotifyEvent};

/// Parse one `--format '{{json .}}'` line into an event.
///
/// Returns `None` for anything not worth notifying on — non-container events,
/// exec/attach chatter, and the `create`/`destroy` bookends that always
/// accompany a `die`.
pub fn parse_docker_event(line: &str, node: &str) -> Option<NotifyEvent> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if v["Type"].as_str()? != "container" {
        return None;
    }

    // "health_status: unhealthy" -> ("health_status", "unhealthy")
    let raw_action = v["Action"].as_str()?;
    let (action, detail) = match raw_action.split_once(':') {
        Some((a, d)) => (a.trim(), d.trim()),
        None => (raw_action.trim(), ""),
    };

    let attrs: HashMap<String, String> = v["Actor"]["Attributes"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let object = attrs.get("name")?.clone();
    let exit_code = attrs.get("exitCode").and_then(|s| s.parse::<i64>().ok());

    let kind = match action {
        // A clean exit is not a failure. Conflating them is how a notification
        // channel becomes noise the operator mutes.
        "die" => match exit_code {
            Some(0) => EventKind::ObjectStopped,
            _ => EventKind::ObjectFailed,
        },
        "oom" => EventKind::ObjectOomKilled,
        "health_status" if detail == "unhealthy" => EventKind::ObjectHealthFailed,
        "start" => EventKind::ObjectStarted,
        // create/destroy/attach/exec_*/kill/stop: either bookends around a die
        // we already report, or operator noise.
        _ => return None,
    };

    Some(NotifyEvent {
        kind,
        node: node.to_string(),
        backend: "docker".into(),
        object,
        labels: attrs,
        exit_code,
        restart_count: None,
        timestamp: v["time"].as_u64().unwrap_or(0),
        message: if detail.is_empty() { String::new() } else { detail.to_string() },
    })
}

/// Tracks repeated failures per object so a restart loop — the single most
/// useful signal, and invisible before this module — can be reported as one
/// event rather than N indistinguishable failures.
#[derive(Debug, Default)]
pub struct RestartTracker {
    /// object -> failure timestamps inside the window.
    seen: HashMap<String, Vec<u64>>,
}

impl RestartTracker {
    /// Record a failure and report the count inside `window_secs`.
    ///
    /// State is deliberately in memory and reconstructable: a restart loop that
    /// is forgotten across a daemon restart re-detects itself within a window,
    /// which is a far better trade than persisting state we'd then have to keep
    /// correct.
    pub fn record(&mut self, object: &str, now: u64, window_secs: u64) -> usize {
        let entry = self.seen.entry(object.to_string()).or_default();
        entry.retain(|t| now.saturating_sub(*t) <= window_secs);
        entry.push(now);
        entry.len()
    }

    /// Forget an object that has come back up.
    pub fn clear(&mut self, object: &str) {
        self.seen.remove(object);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured verbatim from docker 29.7.1 on 2026-08-06 —
    // `docker run --rm --name wolfstack-notify-probe --label tier=test <img> sh -c 'exit 3'`
    const DIE: &str = r#"{"Type":"container","Action":"die","Actor":{"ID":"abc","Attributes":{"exitCode":"3","image":"archlinux:latest","name":"wolfstack-notify-probe","tier":"test"}},"scope":"local","time":1786039803}"#;
    const START: &str = r#"{"Type":"container","Action":"start","Actor":{"ID":"abc","Attributes":{"image":"archlinux:latest","name":"wolfstack-notify-probe","tier":"test"}},"scope":"local","time":1786039802}"#;
    const CREATE: &str = r#"{"Type":"container","Action":"create","Actor":{"ID":"abc","Attributes":{"image":"archlinux:latest","name":"wolfstack-notify-probe","tier":"test"}},"scope":"local","time":1786039802}"#;
    const EXEC_DIE: &str = r#"{"Type":"container","Action":"exec_die","Actor":{"ID":"abc","Attributes":{"exitCode":"0","execID":"x","name":"wolfstack-browser","image":"i"}},"scope":"local","time":1786039656}"#;
    const HEALTH_BAD: &str = r#"{"Type":"container","Action":"health_status: unhealthy","Actor":{"ID":"abc","Attributes":{"name":"web","image":"i"}},"scope":"local","time":1786039900}"#;
    const HEALTH_OK: &str = r#"{"Type":"container","Action":"health_status: healthy","Actor":{"ID":"abc","Attributes":{"name":"web","image":"i"}},"scope":"local","time":1786039900}"#;
    const NETWORK: &str = r#"{"Type":"network","Action":"connect","Actor":{"ID":"n","Attributes":{"name":"bridge"}},"scope":"local","time":1786039900}"#;

    #[test]
    fn nonzero_exit_is_a_failure() {
        let e = parse_docker_event(DIE, "wolfstack-2").expect("should parse");
        assert_eq!(e.kind, EventKind::ObjectFailed);
        assert_eq!(e.object, "wolfstack-notify-probe");
        assert_eq!(e.exit_code, Some(3));
        assert_eq!(e.backend, "docker");
        assert_eq!(e.timestamp, 1786039803);
    }

    #[test]
    fn clean_exit_is_a_stop_not_a_failure() {
        // Conflating these is how the channel becomes noise and gets muted.
        let clean = DIE.replace(r#""exitCode":"3""#, r#""exitCode":"0""#);
        let e = parse_docker_event(&clean, "n").expect("should parse");
        assert_eq!(e.kind, EventKind::ObjectStopped);
    }

    #[test]
    fn container_labels_are_available_for_matching() {
        // The `tier=test` label must survive so a rule can match on it.
        let e = parse_docker_event(DIE, "n").expect("should parse");
        assert_eq!(e.labels.get("tier").map(String::as_str), Some("test"));
    }

    #[test]
    fn health_transition_is_parsed_despite_the_colon_suffix() {
        // Action is "health_status: unhealthy" — matching the raw string would
        // miss every health event there is.
        let e = parse_docker_event(HEALTH_BAD, "n").expect("should parse");
        assert_eq!(e.kind, EventKind::ObjectHealthFailed);
        assert_eq!(e.message, "unhealthy");
    }

    #[test]
    fn becoming_healthy_is_not_an_alert() {
        assert!(parse_docker_event(HEALTH_OK, "n").is_none());
    }

    #[test]
    fn start_is_a_recovery_event() {
        let e = parse_docker_event(START, "n").expect("should parse");
        assert_eq!(e.kind, EventKind::ObjectStarted);
        assert!(e.kind.is_recovery());
    }

    #[test]
    fn bookend_and_exec_noise_is_ignored() {
        // create/destroy bracket every die; exec_* fires constantly for any
        // container WolfStack itself pokes at (the browser containers emit it
        // every few seconds). Reporting these would drown the real signal.
        assert!(parse_docker_event(CREATE, "n").is_none());
        assert!(parse_docker_event(EXEC_DIE, "n").is_none());
    }

    #[test]
    fn non_container_events_are_ignored() {
        assert!(parse_docker_event(NETWORK, "n").is_none());
    }

    #[test]
    fn garbage_lines_do_not_panic() {
        // The stream is a child process; a partial line on daemon restart must
        // not take the source down.
        assert!(parse_docker_event("", "n").is_none());
        assert!(parse_docker_event("not json", "n").is_none());
        assert!(parse_docker_event(r#"{"Type":"container"}"#, "n").is_none());
    }

    #[test]
    fn restart_tracker_counts_inside_the_window() {
        let mut t = RestartTracker::default();
        assert_eq!(t.record("web", 100, 600), 1);
        assert_eq!(t.record("web", 200, 600), 2);
        assert_eq!(t.record("web", 300, 600), 3);
    }

    #[test]
    fn restart_tracker_forgets_outside_the_window() {
        let mut t = RestartTracker::default();
        t.record("web", 100, 600);
        // 1000s later the earlier failure is irrelevant — this is a fresh
        // incident, not a loop.
        assert_eq!(t.record("web", 1100, 600), 1);
    }

    #[test]
    fn restart_tracker_is_per_object() {
        let mut t = RestartTracker::default();
        t.record("noisy", 100, 600);
        t.record("noisy", 200, 600);
        assert_eq!(t.record("quiet", 200, 600), 1, "objects must not share a counter");
    }

    #[test]
    fn recovery_clears_the_restart_history() {
        let mut t = RestartTracker::default();
        t.record("web", 100, 600);
        t.record("web", 200, 600);
        t.clear("web");
        assert_eq!(t.record("web", 300, 600), 1);
    }
}
