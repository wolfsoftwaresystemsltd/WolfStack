// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Shared disk-fill verdict computation.
//!
//! Extracted from `disk_fill.rs` so the host, Docker, and LXC
//! analyzers (and any future filesystem-shaped analyzer — VM disk,
//! cgroup limits, etc.) all reach the same answer when handed the
//! same samples + current state. Never duplicate the math.
//!
//! ## Tier thresholds
//!
//! | ETA to target (or 100% if already past) | Severity   |
//! |-----------------------------------------|------------|
//! | < 6 h                                   | `Critical` |
//! | < 48 h                                  | `High`     |
//! | < 7 d                                   | `Warn`     |
//! | ≥ 7 d                                   | suppressed |
//!
//! Already at/past target with non-positive slope → `Warn` with
//! `eta_hours = None` ("flat full" — at the cliff but not getting
//! worse). Already past target with positive slope → ETA-to-100%.
//!
//! These rationales are explained per constant in `disk_fill.rs`'s
//! module doc; this file owns the actual constants now.

use std::collections::VecDeque;

use crate::predictive::metrics::{MetricSample, linear_fit};
use crate::predictive::proposal::Severity;

/// We need at least this many samples to trust a regression. With
/// fewer, slope is dominated by sampling noise.
pub const MIN_SAMPLES: usize = 3;

/// Samples must span at least this long before we'll fit a line.
/// Below 30 min the analyzer would hallucinate trend from noise.
pub const MIN_SPAN_MINUTES: i64 = 30;

/// Don't surface anything beyond this horizon — past 7 days the
/// linear extrapolation is dominated by long-term cycles (weekly
/// log rotation, cron sweeps) rather than the near-term trajectory.
pub const MAX_HORIZON_HOURS: f64 = 24.0 * 7.0;

/// Severity boundaries (in hours of ETA).
pub const CRITICAL_HOURS: f64 = 6.0;
pub const HIGH_HOURS: f64 = 48.0;

/// Don't bother predicting on resources below this used-percent —
/// even with steep growth they're not the issue today, and noisy
/// growth curves on near-empty resources produce silly ETAs.
pub const MIN_USED_PCT: f64 = 50.0;

/// Default fill target used by host/Docker/LXC analyzers. Already-
/// past-target resources fall through to the ETA-to-100% branch.
pub const FILL_TARGET_PCT: f64 = 95.0;

/// One verdict from the regression. Carried by the analyzer into
/// the proposal builder.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub severity: Severity,
    /// Hours-to-target. `None` when the resource is already at/past
    /// `target` with non-positive slope ("flat full").
    pub eta_hours: Option<f64>,
    pub slope_pct_per_hour: f64,
    pub samples_used: usize,
    pub span_minutes: i64,
}

/// Compute a verdict from a sample series + current usage state.
///
/// Pure function — no I/O, no clocks. Trivially testable.
///
/// Returns `None` when:
/// - fewer than `MIN_SAMPLES` samples
/// - sample-window shorter than `MIN_SPAN_MINUTES`
/// - the linear fit can't produce a slope (zero x-variance)
/// - currently below target AND slope ≤ 0 (shrinking — no problem)
/// - currently below target AND projected ETA exceeds the horizon
///   (so far in the future the trend is meaningless)
pub fn compute_verdict(
    samples: &VecDeque<MetricSample>,
    used_pct_now: f64,
    target_pct: f64,
) -> Option<Verdict> {
    if samples.len() < MIN_SAMPLES { return None; }
    let span = samples.back()?.ts - samples.front()?.ts;
    if span.num_minutes() < MIN_SPAN_MINUTES { return None; }

    let (slope_per_sec, _intercept) = linear_fit(samples)?;
    let slope_per_hour = slope_per_sec * 3600.0;

    // Already past target — flat/shrinking still warrants a Warn
    // because it's an at-the-cliff state even if not getting worse.
    if used_pct_now >= target_pct {
        if slope_per_hour <= 0.0 {
            return Some(Verdict {
                severity: Severity::Warn,
                eta_hours: None,
                slope_pct_per_hour: slope_per_hour,
                samples_used: samples.len(),
                span_minutes: span.num_minutes(),
            });
        }
        let eta_hours = (100.0 - used_pct_now) / slope_per_hour;
        return Some(Verdict {
            severity: severity_from_eta(eta_hours),
            eta_hours: Some(eta_hours.max(0.0)),
            slope_pct_per_hour: slope_per_hour,
            samples_used: samples.len(),
            span_minutes: span.num_minutes(),
        });
    }

    // Below target — only interesting if growing.
    if slope_per_hour <= 0.0 { return None; }

    let eta_hours = (target_pct - used_pct_now) / slope_per_hour;
    if eta_hours > MAX_HORIZON_HOURS { return None; }

    Some(Verdict {
        severity: severity_from_eta(eta_hours),
        eta_hours: Some(eta_hours),
        slope_pct_per_hour: slope_per_hour,
        samples_used: samples.len(),
        span_minutes: span.num_minutes(),
    })
}

pub fn severity_from_eta(eta_hours: f64) -> Severity {
    if eta_hours < CRITICAL_HOURS { Severity::Critical }
    else if eta_hours < HIGH_HOURS { Severity::High }
    else { Severity::Warn }
}

/// Render hours into a compact human label suitable for proposal
/// titles: "45 min", "12.3 h", "2.1 days".
pub fn humanise_hours(h: f64) -> String {
    if h < 1.0 { format!("{:.0} min", (h * 60.0).max(1.0)) }
    else if h < 24.0 { format!("{:.1} h", h) }
    else { format!("{:.1} days", h / 24.0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn buf(growth_pct_per_h: f64, n: usize, start_pct: f64, cadence_min: i64) -> VecDeque<MetricSample> {
        let mut out = VecDeque::new();
        let now = Utc::now();
        let total_min = (n as i64 - 1) * cadence_min;
        for i in 0..n {
            let ts = now - Duration::minutes(total_min - i as i64 * cadence_min);
            let elapsed_h = (i as i64 * cadence_min) as f64 / 60.0;
            out.push_back(MetricSample { ts, value: start_pct + growth_pct_per_h * elapsed_h });
        }
        out
    }

    #[test]
    fn severity_thresholds_match_constants() {
        assert_eq!(severity_from_eta(2.0), Severity::Critical);
        assert_eq!(severity_from_eta(CRITICAL_HOURS - 0.01), Severity::Critical);
        assert_eq!(severity_from_eta(CRITICAL_HOURS), Severity::High);
        assert_eq!(severity_from_eta(HIGH_HOURS - 0.01), Severity::High);
        assert_eq!(severity_from_eta(HIGH_HOURS), Severity::Warn);
        assert_eq!(severity_from_eta(96.0), Severity::Warn);
    }

    #[test]
    fn refuses_too_few_samples() {
        let s = buf(2.0, 2, 70.0, 30);
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn refuses_too_short_span() {
        let s = buf(2.0, 5, 70.0, 5); // 20 min span < 30
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn refuses_below_target_shrinking() {
        let s = buf(-1.0, 6, 75.0, 10);
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn refuses_eta_beyond_horizon() {
        // 0.05 %/h × 25 = 500 h ≫ 168 h horizon
        let s = buf(0.05, 8, 70.0, 10);
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn fast_growth_critical() {
        // 5 %/h → 25/5 = 5 h to target → Critical
        let s = buf(5.0, 8, 65.0, 10);
        let v = compute_verdict(&s, 70.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn slow_growth_warn() {
        // 0.5 %/h → 50 h → Warn (between HIGH_HOURS=48 and horizon)
        let s = buf(0.5, 8, 69.0, 10);
        let v = compute_verdict(&s, 70.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
    }

    #[test]
    fn already_past_target_flat_warn() {
        let s = buf(0.0, 8, 96.0, 10);
        let v = compute_verdict(&s, 96.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
        assert!(v.eta_hours.is_none());
    }

    #[test]
    fn already_past_target_growing_uses_100_pct() {
        // 96% used, 0.5%/h → 4/0.5 = 8 h → High
        let s = buf(0.5, 8, 95.5, 10);
        let v = compute_verdict(&s, 96.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::High);
        assert!(v.eta_hours.unwrap() < HIGH_HOURS);
    }

    #[test]
    fn humanise_minutes() {
        assert_eq!(humanise_hours(0.5), "30 min");
        assert_eq!(humanise_hours(0.0), "1 min");
        assert!(humanise_hours(2.5).contains("h"));
        assert!(humanise_hours(72.0).contains("days"));
    }
}
