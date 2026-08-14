// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Rolling 7-day metric baseline for the AI agent.
//!
//! Every health check pushes a sample here, trimmed to 7 days. The agent
//! gets a short delta summary (now vs ~24h / ~7d ago) in its prompt so
//! it can flag drift the static thresholds don't catch — e.g. disk
//! filling at 1 GB/day, container count creeping up, CPU trending high
//! long before it hits 80%.

use serde::{Deserialize, Serialize};

const WINDOW_SECS: i64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub ts: i64,
    pub cpu_pct: f32,
    pub mem_used_gb: f64,
    pub mem_total_gb: f64,
    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
    pub docker_count: u32,
    pub lxc_count: u32,
    pub vm_count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    #[serde(default)]
    pub samples: Vec<Sample>,
}

fn baseline_path() -> String { crate::paths::get().ai_baseline.clone() }

impl Baseline {
    pub fn load() -> Self {
        match std::fs::read_to_string(baseline_path()) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&baseline_path(), json).map_err(|e| e.to_string())
    }

    /// Append a sample and drop anything older than the 7-day window.
    pub fn push(&mut self, s: Sample) {
        self.samples.push(s);
        let cutoff = chrono::Utc::now().timestamp() - WINDOW_SECS;
        self.samples.retain(|x| x.ts >= cutoff);
    }

    /// Return the sample closest to `age_secs` before the most recent one,
    /// or None if the baseline doesn't go back that far.
    fn sample_around(&self, age_secs: i64) -> Option<&Sample> {
        let latest = self.samples.last()?;
        let target = latest.ts - age_secs;
        // Require at least 80% of the requested age — avoids calling a
        // 2-hour-old sample "24h ago" just because nothing older exists.
        let min_age = (age_secs as f64 * 0.8) as i64;
        self.samples.iter()
            .filter(|s| latest.ts - s.ts >= min_age)
            .min_by_key(|s| (s.ts - target).abs())
    }

    /// Human-readable deltas: current vs ~24h and ~7d ago. Returns an
    /// empty string if there's no prior sample to compare against (first
    /// run, fresh install).
    pub fn deltas_summary(&self) -> String {
        let now = match self.samples.last() {
            Some(s) => s,
            None => return String::new(),
        };
        let d1 = self.sample_around(24 * 3600);
        let d7 = self.sample_around(7 * 24 * 3600);
        if d1.is_none() && d7.is_none() { return String::new(); }

        let mut out = String::from("\nRolling baseline (current vs past):\n");
        let fmt_pct = |cur: f32, old: f32| -> String {
            let diff = cur - old;
            if diff.abs() < 0.5 { "stable".to_string() }
            else { format!("{:+.0}pp", diff) }
        };
        let fmt_gb = |cur: f64, old: f64| -> String {
            let diff = cur - old;
            if diff.abs() < 0.1 { "stable".to_string() }
            else { format!("{:+.1} GB", diff) }
        };
        let fmt_u32 = |cur: u32, old: u32| -> String {
            if cur == old { "unchanged".to_string() }
            else { format!("{:+}", cur as i64 - old as i64) }
        };

        let row = |label: &str, cur_fmt: &str, d1_fmt: Option<String>, d7_fmt: Option<String>| -> String {
            let d1 = d1_fmt.map(|s| format!("24h {}", s)).unwrap_or_default();
            let d7 = d7_fmt.map(|s| format!("7d {}", s)).unwrap_or_default();
            let parts: Vec<String> = [d1, d7].into_iter().filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                format!("  {}: {}\n", label, cur_fmt)
            } else {
                format!("  {}: {} ({})\n", label, cur_fmt, parts.join(", "))
            }
        };

        out.push_str(&row("CPU",
            &format!("{:.0}%", now.cpu_pct),
            d1.map(|p| fmt_pct(now.cpu_pct, p.cpu_pct)),
            d7.map(|p| fmt_pct(now.cpu_pct, p.cpu_pct)),
        ));
        out.push_str(&row("Memory",
            &format!("{:.1}/{:.1} GB", now.mem_used_gb, now.mem_total_gb),
            d1.map(|p| fmt_gb(now.mem_used_gb, p.mem_used_gb)),
            d7.map(|p| fmt_gb(now.mem_used_gb, p.mem_used_gb)),
        ));
        out.push_str(&row("Disk",
            &format!("{:.1}/{:.1} GB", now.disk_used_gb, now.disk_total_gb),
            d1.map(|p| fmt_gb(now.disk_used_gb, p.disk_used_gb)),
            d7.map(|p| fmt_gb(now.disk_used_gb, p.disk_used_gb)),
        ));
        out.push_str(&row("Docker containers",
            &format!("{}", now.docker_count),
            d1.map(|p| fmt_u32(now.docker_count, p.docker_count)),
            d7.map(|p| fmt_u32(now.docker_count, p.docker_count)),
        ));
        out.push_str(&row("LXC containers",
            &format!("{}", now.lxc_count),
            d1.map(|p| fmt_u32(now.lxc_count, p.lxc_count)),
            d7.map(|p| fmt_u32(now.lxc_count, p.lxc_count)),
        ));
        out.push_str(&row("VMs",
            &format!("{}", now.vm_count),
            d1.map(|p| fmt_u32(now.vm_count, p.vm_count)),
            d7.map(|p| fmt_u32(now.vm_count, p.vm_count)),
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: i64, cpu: f32, disk: f64) -> Sample {
        Sample {
            ts, cpu_pct: cpu,
            mem_used_gb: 4.0, mem_total_gb: 16.0,
            disk_used_gb: disk, disk_total_gb: 100.0,
            docker_count: 5, lxc_count: 2, vm_count: 1,
        }
    }

    #[test]
    fn push_trims_old_samples() {
        let mut b = Baseline::default();
        let now = chrono::Utc::now().timestamp();
        b.samples.push(sample(now - 8 * 24 * 3600, 10.0, 50.0));
        b.samples.push(sample(now - 24 * 3600, 20.0, 55.0));
        b.push(sample(now, 30.0, 60.0));
        assert_eq!(b.samples.len(), 2, "8-day-old sample should be pruned");
    }

    #[test]
    fn deltas_empty_on_first_run() {
        let mut b = Baseline::default();
        b.push(sample(chrono::Utc::now().timestamp(), 30.0, 60.0));
        assert!(b.deltas_summary().is_empty());
    }

    #[test]
    fn deltas_present_with_history() {
        let mut b = Baseline::default();
        let now = chrono::Utc::now().timestamp();
        b.samples.push(sample(now - 7 * 24 * 3600, 20.0, 50.0));
        b.samples.push(sample(now - 24 * 3600, 25.0, 55.0));
        b.samples.push(sample(now, 30.0, 60.0));
        let s = b.deltas_summary();
        assert!(s.contains("CPU"));
        assert!(s.contains("24h"));
        assert!(s.contains("7d"));
    }
}
