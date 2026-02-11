//! System monitoring — collects CPU, RAM, disk, and network stats

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use sysinfo::{System, Disks, Networks};
use std::time::Instant;

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
    started: Instant,
}

impl SystemMonitor {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        let networks = Networks::new_with_refreshed_list();

        Self {
            sys,
            disks,
            networks,
            started: Instant::now(),
        }
    }

    /// Collect current system metrics
    pub fn collect(&mut self) -> SystemMetrics {
        self.sys.refresh_all();
        self.disks.refresh();
        self.networks.refresh();

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

        SystemMetrics {
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            uptime_secs: self.started.elapsed().as_secs(),
            cpu_usage_percent: cpu_usage,
            cpu_count: self.sys.cpus().len(),
            cpu_model,
            memory_total_bytes: self.sys.total_memory(),
            memory_used_bytes: self.sys.used_memory(),
            memory_percent: if self.sys.total_memory() > 0 {
                (self.sys.used_memory() as f32 / self.sys.total_memory() as f32) * 100.0
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
        }
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
