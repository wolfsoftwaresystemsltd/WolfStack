// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Rolling metrics history for trend-based analyzers.
//!
//! Disk-fill prediction needs at least three samples spanning ~30
//! minutes to produce a meaningful linear extrapolation. The existing
//! `alerting.rs` works on point-in-time thresholds, not trends, so it
//! has nothing to feed the predictive layer. This module is the
//! minimum-viable history layer: a bounded ring buffer per
//! (resource, metric_name) pair, persisted to disk so a restart
//! doesn't blind the analyzer for the next 24 cycles.
//!
//! ## Capacity
//!
//! Default 288 samples × 5 min cadence = 24 hours of history per
//! metric. Linear regression doesn't benefit from longer windows
//! (older data is less representative of current growth). At 288
//! `f64`s per metric × ~50 mounts on a busy node × ~10 metrics
//! eventually = ~1.4 MB on disk — small enough that we don't need a
//! database.
//!
//! ## Linear regression
//!
//! Ordinary least squares over `(seconds_since_oldest, value)`. The
//! slope is values-per-second; the intercept is the value at the
//! oldest sample. Rejecting fewer than three samples or a zero/near-
//! zero variance window is the analyzer's job, not the regressor's.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 24 hours at 5-min cadence.
pub const DEFAULT_CAPACITY: usize = 288;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    pub ts: DateTime<Utc>,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsHistory {
    /// `resource → metric_name → samples` (oldest first).
    #[serde(default)]
    pub by_resource: HashMap<String, HashMap<String, VecDeque<MetricSample>>>,
    #[serde(default = "default_capacity")]
    pub capacity: usize,
}

fn default_capacity() -> usize { DEFAULT_CAPACITY }

impl Default for MetricsHistory {
    fn default() -> Self {
        Self { by_resource: HashMap::new(), capacity: DEFAULT_CAPACITY }
    }
}

pub fn history_file() -> PathBuf {
    if let Ok(p) = std::env::var("WOLFSTACK_PREDICTIVE_HISTORY_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from("/etc/wolfstack/predictive_history.json")
}

impl MetricsHistory {
    pub fn load() -> Self {
        let path = history_file();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = history_file();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write predictive history: {}", e))?;
        Ok(())
    }

    pub fn record(&mut self, resource: &str, metric: &str, value: f64) {
        self.record_at(resource, metric, value, Utc::now());
    }

    /// Record with explicit timestamp — used by tests to seed
    /// historical data without sleeping.
    pub fn record_at(&mut self, resource: &str, metric: &str, value: f64, ts: DateTime<Utc>) {
        let buf = self.by_resource
            .entry(resource.to_string()).or_default()
            .entry(metric.to_string()).or_default();
        buf.push_back(MetricSample { ts, value });
        while buf.len() > self.capacity {
            buf.pop_front();
        }
    }

    pub fn samples(&self, resource: &str, metric: &str) -> Option<&VecDeque<MetricSample>> {
        self.by_resource.get(resource).and_then(|m| m.get(metric))
    }

    /// Drop history for resources we no longer see (a mount got
    /// unmounted, a container got deleted). Keeps the file from
    /// growing forever as the cluster churns.
    pub fn retain_resources<F: Fn(&str) -> bool>(&mut self, keep: F) {
        self.by_resource.retain(|k, _| keep(k));
    }
}

/// Ordinary-least-squares linear fit over the `(seconds_since_first,
/// value)` series. Returns `(slope_per_second, intercept)` or `None`
/// when the series can't produce a meaningful line:
///
/// - fewer than 2 samples
/// - all timestamps identical (zero x-variance — slope undefined)
///
/// All-equal *values* (zero y-variance) returns `Some((0.0, value))`,
/// which is correct: the line is flat. Callers decide whether a flat
/// or shrinking trend is interesting.
pub fn linear_fit(samples: &VecDeque<MetricSample>) -> Option<(f64, f64)> {
    if samples.len() < 2 { return None; }
    let t0 = samples.front()?.ts;

    let xs: Vec<f64> = samples.iter()
        .map(|s| (s.ts - t0).num_milliseconds() as f64 / 1000.0)
        .collect();
    let ys: Vec<f64> = samples.iter().map(|s| s.value).collect();

    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;

    let mut num = 0.0;
    let mut denom = 0.0;
    for (x, y) in xs.iter().zip(ys.iter()) {
        let dx = x - mean_x;
        num += dx * (y - mean_y);
        denom += dx * dx;
    }
    if denom == 0.0 { return None; }

    let slope = num / denom;
    let intercept = mean_y - slope * mean_x;
    Some((slope, intercept))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn record_appends_and_capacity_caps() {
        let mut h = MetricsHistory { capacity: 3, ..Default::default() };
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            h.record("/var", "disk_used_pct", v);
        }
        let samples = h.samples("/var", "disk_used_pct").unwrap();
        assert_eq!(samples.len(), 3);
        let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
        assert_eq!(values, vec![3.0, 4.0, 5.0]);
    }

    #[test]
    fn samples_for_missing_returns_none() {
        let h = MetricsHistory::default();
        assert!(h.samples("nope", "metric").is_none());
    }

    #[test]
    fn linear_fit_too_few_samples() {
        let mut buf: VecDeque<MetricSample> = VecDeque::new();
        assert!(linear_fit(&buf).is_none());
        buf.push_back(MetricSample { ts: Utc::now(), value: 1.0 });
        assert!(linear_fit(&buf).is_none());
    }

    #[test]
    fn linear_fit_perfect_line_recovers_slope() {
        let t0 = Utc::now();
        let mut buf: VecDeque<MetricSample> = VecDeque::new();
        // Disk filling at 1% per minute → 1/60 per second.
        for i in 0..6 {
            buf.push_back(MetricSample {
                ts: t0 + Duration::minutes(i),
                value: 50.0 + i as f64,
            });
        }
        let (slope, intercept) = linear_fit(&buf).expect("fit");
        // 1% per 60s = 0.01666… per second
        assert!((slope - (1.0 / 60.0)).abs() < 1e-9, "slope = {}", slope);
        assert!((intercept - 50.0).abs() < 1e-9, "intercept = {}", intercept);
    }

    #[test]
    fn linear_fit_flat_series_is_zero_slope() {
        let t0 = Utc::now();
        let mut buf: VecDeque<MetricSample> = VecDeque::new();
        for i in 0..5 {
            buf.push_back(MetricSample {
                ts: t0 + Duration::minutes(i),
                value: 42.0,
            });
        }
        let (slope, intercept) = linear_fit(&buf).expect("fit");
        assert!(slope.abs() < 1e-12);
        assert!((intercept - 42.0).abs() < 1e-12);
    }

    #[test]
    fn linear_fit_zero_x_variance_is_none() {
        let t = Utc::now();
        let mut buf: VecDeque<MetricSample> = VecDeque::new();
        buf.push_back(MetricSample { ts: t, value: 1.0 });
        buf.push_back(MetricSample { ts: t, value: 2.0 });
        assert!(linear_fit(&buf).is_none(),
            "identical timestamps should refuse to fit a line");
    }

    #[test]
    fn retain_drops_stale_resources() {
        let mut h = MetricsHistory::default();
        h.record("/var", "disk", 1.0);
        h.record("/old-mount", "disk", 1.0);
        h.retain_resources(|r| r != "/old-mount");
        assert!(h.samples("/var", "disk").is_some());
        assert!(h.samples("/old-mount", "disk").is_none());
    }
}
