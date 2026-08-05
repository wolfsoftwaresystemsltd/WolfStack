// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! System monitoring — collects CPU, RAM, disk, and network stats

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Instant;
use sysinfo::{System, Disks, Networks, MINIMUM_CPU_UPDATE_INTERVAL};


/// Snapshot of system metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub hostname: String,
    pub uptime_secs: u64,
    pub cpu_usage_percent: f32,
    pub cpu_count: usize,
    pub cpu_model: String,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_percent: f32,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disks: Vec<DiskMetrics>,
    pub network: Vec<NetworkMetrics>,
    pub load_avg: LoadAverage,
    pub processes: usize,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    /// Hardware classification: "low", "mid", or "high"
    #[serde(default)]
    pub hardware_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub name: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

/// System monitor that maintains state between polls
pub struct SystemMonitor {
    sys: System,
    disks: Disks,
    networks: Networks,
    /// Counter for slow-path refreshes (processes, disks) — every Nth collect
    tick: u32,
    /// When the CPU counters were last sampled. sysinfo derives CPU% from the
    /// delta between two refreshes, so the gap between them IS the measurement
    /// window — see the guard in `collect()`.
    last_cpu_sample: Instant,
}

/// How often to do the expensive refresh (processes + disk list).
/// At 2s polling interval, 15 ticks = every 30 seconds.
const SLOW_REFRESH_TICKS: u32 = 15;

impl SystemMonitor {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        // Disks deliberately NOT refreshed at construction: sysinfo's disk
        // refresh statvfs()'s every mount, and a dead/starting FUSE mount
        // (/etc/pve while pve-cluster is still coming up, a stale sshfs, …)
        // blocks statvfs UNINTERRUPTIBLY. Constructing the monitor on the
        // startup path then wedges the whole process before the dashboard
        // ever binds (masterpier's athena: 26h dark, 2026-07-03). Start
        // empty and pre-arm `tick` so the FIRST collect() runs the slow-path
        // list refresh — callers on the startup path wrap that collect in a
        // timeout guard, and the polling loop repeats it every ~30s.
        let disks = Disks::new();
        let networks = Networks::new_with_refreshed_list();

        Self {
            sys,
            disks,
            networks,
            tick: SLOW_REFRESH_TICKS,
            // refresh_all() above took the first CPU sample; collect() measures
            // against this instant.
            last_cpu_sample: Instant::now(),
        }
    }

    /// Collect current system metrics
    pub fn collect(&mut self) -> SystemMetrics {
        // sysinfo computes CPU% from the delta between two refreshes, so the
        // elapsed time between them IS the measurement window. Refresh again
        // too soon and the busy-time delta is divided by a near-zero window,
        // which pegs the result at ~100% no matter how idle the box is.
        //
        // The 2s polling loop is never anywhere near that limit, but every
        // one-shot `SystemMonitor::new()` + `collect()` caller landed squarely
        // inside it — the startup collection in main.rs, the MCP metrics tool
        // and the WolfAgents node query. The startup one is the damaging case:
        // its bogus reading is what the node publishes via `cluster.update_self`,
        // so a freshly started or freshly restarted node advertised itself to
        // the whole fleet at ~100% CPU while sitting idle (RutgerDiehard,
        // 2026-08-05: six hosts all reporting 96-100% with `top` showing 76%
        // idle). Restarting the service "fixed" it only until the next startup
        // sample replaced it with another bogus 100%.
        //
        // Wait out the remainder of the interval so the window is real. Every
        // one-shot caller is already on a dedicated thread or spawn_blocking,
        // so this never parks an async worker, and the steady-state pollers
        // never sleep at all.
        let since_last = self.last_cpu_sample.elapsed();
        if since_last < MINIMUM_CPU_UPDATE_INTERVAL {
            std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL - since_last);
        }

        // Fast path (every tick): CPU + memory + network only
        self.sys.refresh_cpu_all();
        self.last_cpu_sample = Instant::now();
        self.sys.refresh_memory();
        self.networks.refresh();

        // Slow path (every ~30s): processes + disk list — these are expensive
        self.tick += 1;
        if self.tick >= SLOW_REFRESH_TICKS {
            self.tick = 0;
            self.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            self.disks.refresh_list();
        }

        let cpu_model = self.sys.cpus().first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let cpu_usage: f32 = self.sys.cpus().iter()
            .map(|c| c.cpu_usage())
            .sum::<f32>() / self.sys.cpus().len().max(1) as f32;

        let disks: Vec<DiskMetrics> = self.disks.iter()
            .filter(|d| {
                let mount = d.mount_point().to_string_lossy();
                !mount.starts_with("/snap") && !mount.starts_with("/boot/efi")
                    && d.total_space() > 0
            })
            .map(|d| {
                let total = d.total_space();
                let available = d.available_space();
                let used = total.saturating_sub(available);
                DiskMetrics {
                    name: d.name().to_string_lossy().to_string(),
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    fs_type: d.file_system().to_string_lossy().to_string(),
                    total_bytes: total,
                    used_bytes: used,
                    available_bytes: available,
                    usage_percent: if total > 0 { (used as f32 / total as f32) * 100.0 } else { 0.0 },
                }
            })
            .collect();

        let network: Vec<NetworkMetrics> = self.networks.iter()
            .filter(|(name, _)| *name != "lo")
            .map(|(name, data)| NetworkMetrics {
                interface: name.clone(),
                rx_bytes: data.total_received(),
                tx_bytes: data.total_transmitted(),
                rx_packets: data.total_packets_received(),
                tx_packets: data.total_packets_transmitted(),
            })
            .collect();

        let load = System::load_average();

        let cpu_count = self.sys.cpus().len();
        let total_memory = self.sys.total_memory();
        let hardware_tier = classify_hardware(cpu_count, total_memory);

        SystemMetrics {
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            uptime_secs: System::uptime(),
            cpu_usage_percent: cpu_usage,
            cpu_count,
            cpu_model,
            memory_total_bytes: total_memory,
            memory_used_bytes: self.sys.used_memory(),
            memory_percent: if total_memory > 0 {
                (self.sys.used_memory() as f32 / total_memory as f32) * 100.0
            } else { 0.0 },
            swap_total_bytes: self.sys.total_swap(),
            swap_used_bytes: self.sys.used_swap(),
            disks,
            network,
            load_avg: LoadAverage {
                one: load.one,
                five: load.five,
                fifteen: load.fifteen,
            },
            processes: self.sys.processes().len(),
            os_name: System::name(),
            os_version: System::os_version(),
            kernel_version: System::kernel_version(),
            hardware_tier,
        }
    }
}

/// A single process entry for top-N display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub memory_percent: f32,
}

impl SystemMonitor {
    /// Get top processes by CPU and memory usage.
    /// Refreshes process list if stale (> 5s since last refresh).
    pub fn top_processes(&mut self, count: usize) -> (Vec<ProcessInfo>, Vec<ProcessInfo>) {
        // Ensure process data is reasonably fresh
        if self.tick > 2 {
            self.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        }
        let total_mem = self.sys.total_memory();
        let cpu_count = self.sys.cpus().len().max(1) as f32;

        let mut procs: Vec<ProcessInfo> = self.sys.processes().values()
            .filter(|p| p.cpu_usage() > 0.0 || p.memory() > 0)
            .map(|p| {
                let mem = p.memory();
                // sysinfo reports per-core CPU (e.g. 400% on 4 cores) — normalise to 0-100%
                let cpu_normalized = p.cpu_usage() / cpu_count;
                ProcessInfo {
                    pid: p.pid().as_u32(),
                    name: p.name().to_string_lossy().to_string(),
                    cpu_percent: cpu_normalized,
                    memory_bytes: mem,
                    memory_percent: if total_mem > 0 { (mem as f32 / total_mem as f32) * 100.0 } else { 0.0 },
                }
            })
            .collect();

        // Top CPU
        procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
        let top_cpu: Vec<ProcessInfo> = procs.iter().take(count).cloned().collect();

        // Top Memory
        procs.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
        let top_mem: Vec<ProcessInfo> = procs.iter().take(count).cloned().collect();

        (top_cpu, top_mem)
    }
}

/// Classify hardware as "low", "mid", or "high" based on CPU cores and RAM
pub fn classify_hardware(cpu_count: usize, total_memory_bytes: u64) -> String {
    let ram_gb = total_memory_bytes / (1024 * 1024 * 1024);
    if cpu_count <= 2 || ram_gb <= 4 {
        "low".into()
    } else if cpu_count <= 4 || ram_gb <= 8 {
        "mid".into()
    } else {
        "high".into()
    }
}

// ─── Historical Metrics ───

/// Maximum number of historical snapshots to keep (300 × 2s = ~10 min)
pub const HISTORY_MAX_SNAPSHOTS: usize = 300;

/// A single disk's usage at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSnapshot {
    pub mount_point: String,
    pub usage_percent: f32,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

/// A point-in-time snapshot of key metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disks: Vec<DiskSnapshot>,
    #[serde(default)]
    pub network_rx_bytes: u64,
    #[serde(default)]
    pub network_tx_bytes: u64,
}

/// Ring buffer of historical metric snapshots
pub struct MetricsHistory {
    snapshots: VecDeque<MetricsSnapshot>,
    max_size: usize,
}

impl MetricsHistory {
    pub fn new() -> Self {
        Self {
            snapshots: VecDeque::with_capacity(HISTORY_MAX_SNAPSHOTS),
            max_size: HISTORY_MAX_SNAPSHOTS,
        }
    }

    /// Record a snapshot from current SystemMetrics
    pub fn push(&mut self, metrics: &SystemMetrics) {
        let (rx_total, tx_total) = metrics.network.iter().fold((0u64, 0u64), |(rx, tx), n| {
            (rx + n.rx_bytes, tx + n.tx_bytes)
        });
        let snap = MetricsSnapshot {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            cpu_percent: metrics.cpu_usage_percent,
            memory_percent: metrics.memory_percent,
            memory_used_bytes: metrics.memory_used_bytes,
            memory_total_bytes: metrics.memory_total_bytes,
            disks: metrics.disks.iter().map(|d| DiskSnapshot {
                mount_point: d.mount_point.clone(),
                usage_percent: d.usage_percent,
                used_bytes: d.used_bytes,
                total_bytes: d.total_bytes,
            }).collect(),
            network_rx_bytes: rx_total,
            network_tx_bytes: tx_total,
        };

        if self.snapshots.len() >= self.max_size {
            self.snapshots.pop_front();
        }
        self.snapshots.push_back(snap);
    }

    /// Get all snapshots
    pub fn get_all(&self) -> Vec<MetricsSnapshot> {
        self.snapshots.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-shot `new()` + `collect()` must still produce a real CPU
    /// measurement.
    ///
    /// sysinfo derives CPU% from the gap between two refreshes. Before the
    /// guard in `collect()`, the one-shot callers (startup metrics, the MCP
    /// metrics tool, WolfAgents) refreshed microseconds after construction and
    /// got ~100% on a completely idle machine — and the startup one is
    /// published to the whole cluster via `update_self`, so every node
    /// advertised itself as pegged right after boot.
    ///
    /// Asserting the elapsed window rather than the returned percentage keeps
    /// this deterministic: a CI box under real load can legitimately report
    /// any value, but the measurement window is ours to guarantee.
    #[test]
    fn one_shot_collect_waits_for_a_real_cpu_window() {
        let start = Instant::now();
        let mut mon = SystemMonitor::new();
        let m = mon.collect();
        println!(
            "one-shot collect: cpu={:.1}% over {:?} ({} cores, load1={:.2})",
            m.cpu_usage_percent, start.elapsed(), m.cpu_count, m.load_avg.one,
        );
        assert!(
            (0.0..=100.0).contains(&m.cpu_usage_percent),
            "cpu_usage_percent {:.1} is outside 0-100 — the averaging or the \
             sampling window is wrong", m.cpu_usage_percent,
        );
        assert!(
            start.elapsed() >= MINIMUM_CPU_UPDATE_INTERVAL,
            "collect() returned after {:?}, which is less than sysinfo's \
             MINIMUM_CPU_UPDATE_INTERVAL ({:?}) — the CPU delta was measured \
             over a near-zero window and the percentage is meaningless",
            start.elapsed(), MINIMUM_CPU_UPDATE_INTERVAL,
        );
    }

    /// The steady-state poller must NOT pay the wait. Callers refreshing on a
    /// 2s loop are already far past the minimum interval, and adding a sleep
    /// to the hot path would slow every node's metrics tick.
    #[test]
    fn steady_state_collect_does_not_sleep() {
        let mut mon = SystemMonitor::new();
        let _ = mon.collect(); // first one may wait — that's the point above
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);

        let start = Instant::now();
        let _ = mon.collect();
        assert!(
            start.elapsed() < MINIMUM_CPU_UPDATE_INTERVAL,
            "collect() slept for {:?} despite the previous sample being older \
             than the minimum interval — the guard should be a no-op here",
            start.elapsed(),
        );
    }
}
