// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfRun — Native Container Orchestration for WolfStack
//!
//! Schedules Docker and LXC containers across cluster nodes using:
//! - ClusterState for node metrics and health
//! - WolfNet for automatic overlay networking
//! - AppStore manifests for deployment configuration
//!
//! Zero external dependencies — no etcd, kubelet, or CNI plugins.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn, debug};

use crate::agent::ClusterState;

// ─── Data Model ───

/// Container runtime for a service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Runtime {
    Docker,
    Lxc,
}

impl Default for Runtime {
    fn default() -> Self { Runtime::Docker }
}

/// Placement strategy for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Placement {
    /// Schedule on any eligible node (default — spread across nodes)
    Any,
    /// Prefer a specific node but allow others if unavailable
    PreferNode(String),
    /// Only run on a specific node
    RequireNode(String),
}

impl Default for Placement {
    fn default() -> Self { Placement::Any }
}

/// Restart policy for containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

impl Default for RestartPolicy {
    fn default() -> Self { RestartPolicy::Always }
}

/// A single running instance of a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    pub node_id: String,
    pub container_name: String,
    pub wolfnet_ip: Option<String>,
    pub status: String,        // "running", "stopped", "pending", "lost"
    pub last_seen: u64,        // unix timestamp
}

/// LXC-specific configuration for a service
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LxcConfig {
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
    #[serde(default = "default_arch")]
    pub architecture: String,
}
fn default_distro() -> String { "ubuntu".to_string() }
fn default_release() -> String { "jammy".to_string() }
fn default_arch() -> String { "amd64".to_string() }

/// A WolfRun service definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfRunService {
    pub id: String,
    pub name: String,
    /// Docker image (for Docker runtime) or unused for LXC
    pub image: String,
    pub replicas: u32,
    /// Minimum number of replicas (scale-down floor)
    #[serde(default)]
    pub min_replicas: u32,
    /// Maximum number of replicas (scale-up ceiling)
    #[serde(default = "default_max_replicas")]
    pub max_replicas: u32,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub lxc_config: Option<LxcConfig>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    pub cluster_name: String,
    #[serde(default)]
    pub placement: Placement,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    #[serde(default)]
    pub instances: Vec<ServiceInstance>,
    /// Load-balanced virtual IP on WolfNet (auto-assigned)
    #[serde(default)]
    pub service_ip: Option<String>,
    /// Load balancer policy: "round_robin" (default) or "ip_hash" (sticky sessions)
    #[serde(default = "default_lb_policy")]
    pub lb_policy: String,
    /// Allowed node IDs — empty means all nodes are eligible
    #[serde(default)]
    pub allowed_nodes: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

fn default_max_replicas() -> u32 { 10 }
fn default_lb_policy() -> String { "round_robin".to_string() }

// ─── State Management ───

const SERVICES_DIR: &str = "/etc/wolfstack/wolfrun";
const SERVICES_FILE: &str = "/etc/wolfstack/wolfrun/services.json";

/// Shared WolfRun state
pub struct WolfRunState {
    services: RwLock<Vec<WolfRunService>>,
}

impl WolfRunState {
    pub fn new() -> Self {
        let state = Self {
            services: RwLock::new(Vec::new()),
        };
        state.load();
        state
    }

    /// Load services from disk
    fn load(&self) {
        if let Ok(data) = std::fs::read_to_string(SERVICES_FILE) {
            if let Ok(services) = serde_json::from_str::<Vec<WolfRunService>>(&data) {
                let mut svcs = self.services.write().unwrap();
                *svcs = services;
                debug!("WolfRun: loaded {} services from {}", svcs.len(), SERVICES_FILE);
            }
        }
    }

    /// Save services to disk
    fn save(&self) {
        let svcs = self.services.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*svcs) {
            let _ = std::fs::create_dir_all(SERVICES_DIR);
            if let Err(e) = std::fs::write(SERVICES_FILE, json) {
                warn!("WolfRun: failed to save services: {}", e);
            }
        }
    }

    /// List all services, optionally filtered by cluster
    pub fn list(&self, cluster: Option<&str>) -> Vec<WolfRunService> {
        let svcs = self.services.read().unwrap();
        match cluster {
            Some(c) => svcs.iter().filter(|s| s.cluster_name == c).cloned().collect(),
            None => svcs.clone(),
        }
    }

    /// Get a single service by ID
    pub fn get(&self, id: &str) -> Option<WolfRunService> {
        let svcs = self.services.read().unwrap();
        svcs.iter().find(|s| s.id == id).cloned()
    }

    /// Create a new service
    #[allow(clippy::too_many_arguments)]
    pub fn create(&self, name: String, image: String, replicas: u32, cluster_name: String,
                  env: Vec<String>, ports: Vec<String>, volumes: Vec<String>,
                  placement: Placement, restart_policy: RestartPolicy,
                  runtime: Runtime, lxc_config: Option<LxcConfig>) -> WolfRunService {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let id = format!("svc-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        // Allocate a Service VIP on WolfNet for load balancing
        let service_ip = crate::containers::next_available_wolfnet_ip();
        if let Some(ref vip) = service_ip {
            info!("WolfRun: allocated Service VIP {} for {}", vip, name);
        }
        let svc = WolfRunService {
            id: id.clone(),
            name,
            image,
            replicas,
            min_replicas: 0,
            max_replicas: 10,
            runtime,
            lxc_config,
            env,
            ports,
            volumes,
            cluster_name,
            placement,
            restart_policy,
            instances: Vec::new(),
            service_ip,
            lb_policy: "round_robin".to_string(),
            allowed_nodes: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        {
            let mut svcs = self.services.write().unwrap();
            svcs.push(svc.clone());
        }
        self.save();
        info!("WolfRun: created service {} ({})", svc.name, id);
        svc
    }

    /// Delete a service by ID — returns the removed service (caller should stop instances)
    pub fn delete(&self, id: &str) -> Option<WolfRunService> {
        let mut svcs = self.services.write().unwrap();
        let idx = svcs.iter().position(|s| s.id == id);
        let removed = idx.map(|i| svcs.remove(i));
        drop(svcs);
        if removed.is_some() {
            self.save();
            info!("WolfRun: deleted service {}", id);
        }
        removed
    }

    /// Scale a service — updates desired replica count
    pub fn scale(&self, id: &str, replicas: u32) -> bool {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            // Auto-raise max if user is scaling beyond current max
            if replicas > svc.max_replicas {
                svc.max_replicas = replicas;
            }
            let clamped = replicas.max(svc.min_replicas).min(svc.max_replicas);
            svc.replicas = clamped;
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            drop(svcs);
            self.save();
            info!("WolfRun: scaled {} to {} replicas (requested {}, bounds {}-{})", id, clamped, replicas, 0, 10);
            true
        } else {
            false
        }
    }

    /// Update service settings (min, max, desired replicas)
    pub fn update_settings(&self, id: &str, min: Option<u32>, max: Option<u32>, desired: Option<u32>, lb_policy: Option<String>, allowed_nodes: Option<Vec<String>>) -> bool {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            if let Some(mn) = min { svc.min_replicas = mn; }
            if let Some(mx) = max { svc.max_replicas = mx; }
            if let Some(d) = desired { svc.replicas = d; }
            if let Some(p) = lb_policy {
                if p == "ip_hash" || p == "round_robin" { svc.lb_policy = p; }
            }
            if let Some(nodes) = allowed_nodes {
                svc.allowed_nodes = nodes;
            }
            // Enforce: min <= desired <= max
            if svc.min_replicas > svc.max_replicas { svc.min_replicas = svc.max_replicas; }
            svc.replicas = svc.replicas.max(svc.min_replicas).min(svc.max_replicas);
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            drop(svcs);
            self.save();
            true
        } else {
            false
        }
    }

    /// Update image for a service (for rolling updates — Docker only)
    pub fn update_image(&self, id: &str, image: String) -> bool {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            svc.image = image.clone();
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            drop(svcs);
            self.save();
            info!("WolfRun: updated {} image to {}", id, image);
            true
        } else {
            false
        }
    }

    /// Update instances for a service (called by reconciliation)
    pub fn update_instances(&self, id: &str, instances: Vec<ServiceInstance>) {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            svc.instances = instances;
        }
        drop(svcs);
        self.save();
    }

    /// Adopt an existing container as a WolfRun service.
    /// The container is registered as the first running instance.
    pub fn adopt(
        &self,
        name: String,
        container_name: String,
        node_id: String,
        image: String,
        runtime: Runtime,
        cluster_name: String,
        env: Vec<String>,
        ports: Vec<String>,
        volumes: Vec<String>,
    ) -> WolfRunService {
        let id = uuid::Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let instance = ServiceInstance {
            container_name: container_name.clone(),
            node_id,
            status: "running".to_string(),
            wolfnet_ip: None,
            last_seen: now,
        };

        // Allocate a Service VIP on WolfNet for load balancing
        let service_ip = crate::containers::next_available_wolfnet_ip();
        if let Some(ref vip) = service_ip {
            info!("WolfRun: allocated Service VIP {} for adopted container {}", vip, container_name);
        }
        let svc = WolfRunService {
            id: id.clone(),
            name,
            image: image.clone(),
            replicas: 1,
            min_replicas: 1,
            max_replicas: 10,
            runtime: runtime.clone(),
            lxc_config: match &runtime {
                Runtime::Lxc => {
                    // Parse image field like "ubuntu 24.04" into distribution + release
                    let parts: Vec<&str> = image.splitn(2, ' ').collect();
                    Some(LxcConfig {
                        distribution: parts.first().unwrap_or(&"ubuntu").to_string(),
                        release: parts.get(1).unwrap_or(&"24.04").to_string(),
                        architecture: "amd64".to_string(),
                    })
                }
                _ => None,
            },
            env,
            ports,
            volumes,
            cluster_name,
            placement: Placement::Any,
            restart_policy: RestartPolicy::Always,
            instances: vec![instance],
            service_ip,
            lb_policy: "round_robin".to_string(),
            allowed_nodes: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        {
            let mut svcs = self.services.write().unwrap();
            svcs.push(svc.clone());
        }
        self.save();
        info!("WolfRun: adopted container '{}' as service {} ({})", container_name, svc.name, id);
        svc
    }

    /// Add an instance to a service
    pub fn add_instance(&self, service_id: &str, instance: ServiceInstance) {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == service_id) {
            svc.instances.push(instance);
        }
        drop(svcs);
        self.save();
    }

    /// Remove an instance from a service by container name
    pub fn remove_instance(&self, service_id: &str, container_name: &str) {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == service_id) {
            svc.instances.retain(|i| i.container_name != container_name);
        }
        drop(svcs);
        self.save();
    }
}

// ─── Scheduler ───

/// Score a node for scheduling (lower = better)
fn node_score(node: &crate::agent::Node) -> f32 {
    let m = match &node.metrics {
        Some(m) => m,
        None => return f32::MAX,
    };
    // Weighted score: CPU 40%, Memory 40%, Disk 20%
    let cpu = m.cpu_usage_percent;
    let mem = m.memory_percent;
    let disk = m.disks.iter()
        .map(|d| d.usage_percent)
        .fold(0.0_f32, f32::max);
    cpu * 0.4 + mem * 0.4 + disk * 0.2
}

/// Pick the best node for a new container, given the service constraints
pub fn schedule(
    cluster: &ClusterState,
    service: &WolfRunService,
) -> Option<String> {
    let nodes = cluster.get_all_nodes();

    // Filter eligible nodes
    let eligible: Vec<_> = nodes.iter().filter(|n| {
        // Must be online
        if !n.online { return false; }
        // Must have the required runtime
        match service.runtime {
            Runtime::Docker => { if !n.has_docker { return false; } }
            Runtime::Lxc => { if !n.has_lxc { return false; } }
        }
        // Must be in the same cluster
        let node_cluster = n.cluster_name.as_deref().unwrap_or("WolfStack");
        if node_cluster != service.cluster_name { return false; }
        // Must be in the allowed nodes list (if specified)
        if !service.allowed_nodes.is_empty() && !service.allowed_nodes.contains(&n.id) {
            return false;
        }
        // Check placement constraints
        match &service.placement {
            Placement::RequireNode(nid) => n.id == *nid,
            _ => true,
        }
    }).collect();

    if eligible.is_empty() {
        warn!("WolfRun: no eligible nodes for service {} in cluster {}", service.name, service.cluster_name);
        return None;
    }

    // Prefer preferred node if specified
    if let Placement::PreferNode(preferred) = &service.placement {
        if let Some(n) = eligible.iter().find(|n| n.id == *preferred) {
            if n.online {
                return Some(n.id.clone());
            }
        }
    }

    // Spread: penalise nodes that already run instances of this service
    let instance_counts: HashMap<String, usize> = {
        let mut counts = HashMap::new();
        for inst in &service.instances {
            if inst.status == "running" || inst.status == "pending" {
                *counts.entry(inst.node_id.clone()).or_insert(0) += 1;
            }
        }
        counts
    };

    // Score and pick the best node
    eligible.iter()
        .min_by(|a, b| {
            let a_count = *instance_counts.get(&a.id).unwrap_or(&0) as f32 * 100.0;
            let b_count = *instance_counts.get(&b.id).unwrap_or(&0) as f32 * 100.0;
            let a_score = node_score(a) + a_count;
            let b_score = node_score(b) + b_count;
            a_score.partial_cmp(&b_score).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|n| n.id.clone())
}

// ─── Reconciliation Loop ───

/// Get the container list API path for the given runtime
fn container_list_path(runtime: &Runtime) -> &'static str {
    match runtime {
        Runtime::Docker => "/api/containers/docker?all=true",
        Runtime::Lxc => "/api/containers/lxc",
    }
}

/// Get the container action API path for the given runtime
fn container_action_path(runtime: &Runtime, name: &str) -> String {
    match runtime {
        Runtime::Docker => format!("/api/containers/docker/{}/action", name),
        Runtime::Lxc => format!("/api/containers/lxc/{}/action", name),
    }
}

/// Run one reconciliation cycle for all services
pub async fn reconcile(
    wolfrun: &WolfRunState,
    cluster: &ClusterState,
    cluster_secret: &str,
) {
    // Prevent concurrent reconcile runs (race condition causes duplicate creates then scale-down)
    static RECONCILING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if RECONCILING.compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst).is_err() {
        debug!("WolfRun: reconcile already in progress, skipping");
        return;
    }
    // Ensure we release the lock on exit
    struct ReconcileGuard;
    impl Drop for ReconcileGuard {
        fn drop(&mut self) {
            RECONCILING.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let _guard = ReconcileGuard;

    let services = wolfrun.list(None);
    if services.is_empty() { return; }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("WolfRun reconcile: failed to create HTTP client: {}", e);
            return;
        }
    };

    for service in &services {
        // 1. Check actual state — query each instance's node for its container status
        let mut live_instances: Vec<ServiceInstance> = Vec::new();
        let all_nodes = cluster.get_all_nodes();

        for inst in &service.instances {
            let node = all_nodes.iter().find(|n| n.id == inst.node_id);
            match node {
                Some(n) if n.online && n.is_self => {
                    // Local node — query containers directly (avoids HTTP self-call issues)
                    let containers = match service.runtime {
                        Runtime::Docker => crate::containers::docker_list_all(),
                        Runtime::Lxc => crate::containers::lxc_list_all(),
                    };
                    let found = containers.iter().find(|c| c.name == inst.container_name);
                    if let Some(c) = found {
                        // Extract wolfnet IP from ip_address field (format: "10.10.10.5 (wolfnet)" or "192.168.1.1, 10.10.10.5 (wolfnet)")
                        let wolfnet_ip = c.ip_address.split(',')
                            .map(|s| s.trim())
                            .find(|s| s.contains("wolfnet") || s.starts_with("10.10.10."))
                            .map(|s| s.replace(" (wolfnet)", "").trim().to_string())
                            .filter(|s| !s.is_empty());
                        // Fallback: use bridge IP (10.0.3.x) if no wolfnet IP
                        let ip = wolfnet_ip.or_else(|| {
                            c.ip_address.split(',')
                                .map(|s| s.trim().to_string())
                                .find(|s| s.starts_with("10.0.3.") || s.starts_with("10.0.4.") || s.starts_with("192.168."))
                        });
                        live_instances.push(ServiceInstance {
                            node_id: inst.node_id.clone(),
                            container_name: inst.container_name.clone(),
                            wolfnet_ip: ip,
                            status: c.state.to_lowercase(),
                            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        });
                    } else {
                        live_instances.push(ServiceInstance {
                            node_id: inst.node_id.clone(),
                            container_name: inst.container_name.clone(),
                            wolfnet_ip: None,
                            status: "lost".to_string(),
                            last_seen: inst.last_seen,
                        });
                    }
                }
                Some(n) if n.online => {
                    let urls = crate::api::build_node_urls(
                        &n.address, n.port,
                        container_list_path(&service.runtime),
                    );
                    let mut found = false;
                    for url in &urls {
                        match client.get(url)
                            .header("X-WolfStack-Secret", cluster_secret)
                            .send().await
                        {
                            Ok(resp) => {
                                if let Ok(containers) = resp.json::<Vec<serde_json::Value>>().await {
                                    for c in &containers {
                                        let name = c["name"].as_str().unwrap_or("");
                                        if name == inst.container_name {
                                            let state = c["state"].as_str()
                                                .or_else(|| c["status"].as_str())
                                                .unwrap_or("unknown");
                                            let wolfnet_ip = c["wolfnet_ip"].as_str().map(|s| s.to_string());
                                            live_instances.push(ServiceInstance {
                                                node_id: inst.node_id.clone(),
                                                container_name: inst.container_name.clone(),
                                                wolfnet_ip,
                                                status: state.to_lowercase(),
                                                last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                            });
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                    if !found {
                        // Container not found — mark as lost for potential rescheduling
                        live_instances.push(ServiceInstance {
                            node_id: inst.node_id.clone(),
                            container_name: inst.container_name.clone(),
                            wolfnet_ip: None,
                            status: "lost".to_string(),
                            last_seen: inst.last_seen,
                        });
                    }
                }
                _ => {
                    let mut lost = inst.clone();
                    lost.status = "lost".to_string();
                    live_instances.push(lost);
                }
            }
        }

        // Update instances with live state
        wolfrun.update_instances(&service.id, live_instances.clone());

        // Rebuild load balancer rules for this service's VIP
        if let Some(ref vip) = service.service_ip {
            let backend_ips: Vec<String> = live_instances.iter()
                .filter(|i| i.status == "running")
                .filter_map(|i| i.wolfnet_ip.clone())
                .collect();
            rebuild_lb_rules(vip, &backend_ips, &service.ports, &service.lb_policy);
        }

        // 2. Count running instances
        let running = live_instances.iter().filter(|i| i.status == "running").count() as u32;
        let desired = service.replicas;

        // 3. Scale up if under-provisioned
        if running < desired {
            let needed = desired - running;
            info!("WolfRun: service {} ({:?}) needs {} more instances (has {}/{})", service.name, service.runtime, needed, running, desired);

            for i in 0..needed {
                let current = wolfrun.get(&service.id).unwrap_or(service.clone());
                let node_id = match schedule(cluster, &current) {
                    Some(id) => id,
                    None => {
                        warn!("WolfRun: no available node for service {}", service.name);
                        break;
                    }
                };

                let instance_num = current.instances.len() + 1 + i as usize;
                let node = match cluster.get_node(&node_id) {
                    Some(n) => n,
                    None => continue,
                };

                // Pick best clone source: prefer a running instance, fall back to any instance
                let source_instance = live_instances.iter()
                    .find(|i| i.status == "running")
                    .or_else(|| live_instances.first())
                    .or_else(|| service.instances.first());

                let template_name = source_instance
                    .map(|i| i.container_name.clone())
                    .unwrap_or_else(|| service.name.clone());

                // Find which node the template lives on
                let template_node_id = source_instance
                    .map(|i| i.node_id.clone());

                match service.runtime {
                    Runtime::Docker => {
                        let container_name = format!("{}-wolfrun-{}", instance_num, service.name.to_lowercase().replace(' ', "-"));
                        info!("WolfRun: creating Docker container {} on {} ({})", container_name, node.hostname, node_id);

                        let mut env = service.env.clone();
                        env.push(format!("WOLFRUN_SERVICE={}", service.id));
                        env.push(format!("WOLFRUN_SERVICE_NAME={}", service.name));

                        deploy_docker(&client, cluster_secret, &node, &container_name, service, &env, wolfrun, &node_id).await;
                    }
                    Runtime::Lxc => {
                        // LXC: clone from template, deploy to scheduler's target node
                        let source_node_id = template_node_id.clone().unwrap_or(node_id.clone());
                        let clone_name = format!("{}-wolfrun-{}", instance_num, template_name);
                        let target_node_id_final = node_id.clone();

                        info!("WolfRun: cloning LXC '{}' → '{}' (source: {}, target: {})",
                            template_name, clone_name,
                            cluster.get_node(&source_node_id).map(|n| n.hostname.clone()).unwrap_or_default(),
                            node.hostname);

                        let source_node = cluster.get_node(&source_node_id);
                        let same_node = source_node_id == target_node_id_final;

                        let cloned = if same_node {
                            // Same node: simple local or remote clone
                            if node.is_self {
                                // Both source and target are this node
                                let _ = crate::containers::lxc_stop(&template_name);
                                let result = crate::containers::lxc_clone(&template_name, &clone_name);
                                let _ = crate::containers::lxc_start(&template_name);
                                match result {
                                    Ok(msg) => {
                                        info!("WolfRun: local clone success: {}", msg);
                                        // Remove duplicated wolfnet IP marker from template
                                        let _ = std::fs::remove_dir_all(format!("/var/lib/lxc/{}/.wolfnet", clone_name));
                                        let _ = crate::containers::lxc_start(&clone_name);
                                        // Allocate a fresh wolfnet IP for the clone
                                        if let Some(ip) = crate::containers::next_available_wolfnet_ip() {
                                            let _ = crate::containers::lxc_attach_wolfnet(&clone_name, &ip);
                                        }
                                        true
                                    }
                                    Err(e) => {
                                        warn!("WolfRun: local clone failed: {}", e);
                                        false
                                    }
                                }
                            } else if let Some(ref sn) = source_node {
                                // Both source and target on same remote node
                                let clone_path = format!("/api/containers/lxc/{}/clone", template_name);
                                let urls = crate::api::build_node_urls(&sn.address, sn.port, &clone_path);
                                let clone_client = reqwest::Client::builder()
                                    .timeout(std::time::Duration::from_secs(120))
                                    .danger_accept_invalid_certs(true)
                                    .build().unwrap_or_default();
                                let mut ok = false;
                                for url in &urls {
                                    if let Ok(resp) = clone_client.post(url)
                                        .header("X-WolfStack-Secret", cluster_secret)
                                        .json(&serde_json::json!({ "new_name": clone_name }))
                                        .send().await
                                    {
                                        if resp.status().is_success() {
                                            // Start the clone
                                            let sp = format!("/api/containers/lxc/{}/start", clone_name);
                                            let su = crate::api::build_node_urls(&sn.address, sn.port, &sp);
                                            for u in &su {
                                                if clone_client.post(u).header("X-WolfStack-Secret", cluster_secret).send().await.is_ok() { break; }
                                            }
                                            ok = true;
                                        }
                                        break;
                                    }
                                }
                                ok
                            } else { false }
                        } else {
                            // Different nodes: create a fresh container from template on the target node.
                            // This distributes LXC containers across nodes for true load balancing.
                            info!("WolfRun: cross-node LXC — creating fresh container on {}", node.hostname);
                            deploy_lxc(&client, cluster_secret, &node, &clone_name, service, wolfrun, &node_id).await;
                            // deploy_lxc calls add_instance internally on success
                            continue;  // skip the add_instance below
                        };

                        if cloned {
                            wolfrun.add_instance(&service.id, ServiceInstance {
                                node_id: target_node_id_final,
                                container_name: clone_name,
                                wolfnet_ip: None,
                                status: "running".to_string(),
                                last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            });
                        } else {
                            warn!("WolfRun: failed to clone '{}' for service {}", template_name, service.name);
                        }
                    }
                }
            }
        }

        // 4. Scale down if over-provisioned
        if running > desired {
            let excess = running - desired;
            debug!("WolfRun: service {} has {} excess instances (has {}/{})", service.name, excess, running, desired);

            let mut instance_counts: HashMap<String, usize> = HashMap::new();
            for inst in &live_instances {
                if inst.status == "running" {
                    *instance_counts.entry(inst.node_id.clone()).or_insert(0) += 1;
                }
            }

            let mut running_instances: Vec<_> = live_instances.iter()
                .filter(|i| i.status == "running")
                .collect();
            running_instances.sort_by(|a, b| {
                let a_count = instance_counts.get(&a.node_id).unwrap_or(&0);
                let b_count = instance_counts.get(&b.node_id).unwrap_or(&0);
                b_count.cmp(a_count)
            });

            for inst in running_instances.iter().take(excess as usize) {
                // Just un-manage — don't destroy the container. User can always stop it manually.
                info!("WolfRun: removing excess instance {} from orchestration (container kept running)", inst.container_name);
                wolfrun.remove_instance(&service.id, &inst.container_name);
            }
        }

        // 5. Handle stopped containers that should be running (restart policy)
        if matches!(service.restart_policy, RestartPolicy::Always) {
            for inst in &live_instances {
                if inst.status == "exited" || inst.status == "dead" || inst.status == "stopped" {
                    let node = match cluster.get_node(&inst.node_id) {
                        Some(n) => n,
                        None => continue,
                    };

                    info!("WolfRun: restarting stopped container {} on {}", inst.container_name, node.hostname);

                    if node.is_self {
                        match service.runtime {
                            Runtime::Docker => { let _ = crate::containers::docker_start(&inst.container_name); }
                            Runtime::Lxc => { let _ = crate::containers::lxc_start(&inst.container_name); }
                        }
                    } else {
                        let urls = crate::api::build_node_urls(
                            &node.address, node.port,
                            &container_action_path(&service.runtime, &inst.container_name),
                        );
                        let payload = serde_json::json!({ "action": "start" });
                        for url in &urls {
                            if client.post(url)
                                .header("X-WolfStack-Secret", cluster_secret)
                                .header("Content-Type", "application/json")
                                .body(payload.to_string())
                                .send().await
                                .is_ok()
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 6. Clean up lost instances — if a node stays lost for >5 minutes, reschedule
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let lost: Vec<_> = live_instances.iter()
            .filter(|i| i.status == "lost" && now - i.last_seen > 300)
            .cloned()
            .collect();
        for inst in &lost {
            info!("WolfRun: removing lost instance {} (offline >5min)", inst.container_name);
            wolfrun.remove_instance(&service.id, &inst.container_name);
            // The next reconciliation cycle will detect under-provisioning and schedule a replacement
        }
    }
}

// ─── Deployment Helpers ───

/// Deploy a Docker container on a node
async fn deploy_docker(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    service: &WolfRunService,
    env: &[String],
    wolfrun: &WolfRunState,
    node_id: &str,
) {
    let payload = serde_json::json!({
        "name": container_name,
        "image": service.image,
        "ports": service.ports,
        "env": env,
        "volumes": service.volumes,
    });

    if node.is_self {
        let wolfnet_ip = crate::containers::next_available_wolfnet_ip();
        match crate::containers::docker_create(
            container_name, &service.image, &service.ports, env,
            wolfnet_ip.as_deref(), None, None, None, &service.volumes,
        ) {
            Ok(_) => {
                let _ = crate::containers::docker_start(container_name);
                info!("WolfRun: deployed {} locally", container_name);
                wolfrun.add_instance(&service.id, ServiceInstance {
                    node_id: node_id.to_string(),
                    container_name: container_name.to_string(),
                    wolfnet_ip,
                    status: "running".to_string(),
                    last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                });
            }
            Err(e) => warn!("WolfRun: failed to deploy {} locally: {}", container_name, e),
        }
    } else {
        // Pull image on remote node
        let pull_urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/docker/pull");
        let pull_payload = serde_json::json!({ "image": service.image });
        let mut pulled = false;
        for url in &pull_urls {
            if let Ok(resp) = client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&pull_payload)
                .send().await
            {
                if resp.status().is_success() { pulled = true; break; }
            }
        }
        if !pulled {
            warn!("WolfRun: failed to pull image {} on {}", service.image, node.hostname);
            return;
        }

        // Create container on remote node
        let create_urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/docker/create");
        let mut created = false;
        for url in &create_urls {
            if let Ok(resp) = client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&payload)
                .send().await
            {
                if resp.status().is_success() { created = true; break; }
                let body = resp.text().await.unwrap_or_default();
                warn!("WolfRun: create failed on {}: {}", node.hostname, body);
                break;
            }
        }
        if !created {
            warn!("WolfRun: failed to create container {} on {}", container_name, node.hostname);
            return;
        }

        // Start container
        let start_urls = crate::api::build_node_urls(&node.address, node.port,
            &container_action_path(&Runtime::Docker, container_name));
        let start_payload = serde_json::json!({ "action": "start" });
        for url in &start_urls {
            if let Ok(resp) = client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&start_payload)
                .send().await
            {
                if resp.status().is_success() {
                    info!("WolfRun: deployed {} on {}", container_name, node.hostname);
                    break;
                }
            }
        }

        wolfrun.add_instance(&service.id, ServiceInstance {
            node_id: node_id.to_string(),
            container_name: container_name.to_string(),
            wolfnet_ip: None,
            status: "running".to_string(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        });
    }
}

/// Deploy an LXC container on a node
#[allow(dead_code)]
async fn deploy_lxc(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    service: &WolfRunService,
    wolfrun: &WolfRunState,
    node_id: &str,
) {
    let lxc = service.lxc_config.clone().unwrap_or_default();

    if node.is_self {
        match crate::containers::lxc_create(
            container_name, &lxc.distribution, &lxc.release, &lxc.architecture, None,
        ) {
            Ok(_) => {
                let _ = crate::containers::lxc_start(container_name);
                info!("WolfRun: deployed LXC {} locally", container_name);
                wolfrun.add_instance(&service.id, ServiceInstance {
                    node_id: node_id.to_string(),
                    container_name: container_name.to_string(),
                    wolfnet_ip: None,
                    status: "running".to_string(),
                    last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                });
            }
            Err(e) => warn!("WolfRun: failed to deploy LXC {} locally: {}", container_name, e),
        }
    } else {
        let create_urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/lxc/create");
        let payload = serde_json::json!({
            "name": container_name,
            "distribution": lxc.distribution,
            "release": lxc.release,
            "architecture": lxc.architecture,
        });
        let mut created = false;
        for url in &create_urls {
            if let Ok(resp) = client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&payload)
                .send().await
            {
                if resp.status().is_success() { created = true; break; }
                let body = resp.text().await.unwrap_or_default();
                warn!("WolfRun: LXC create failed on {}: {}", node.hostname, body);
                break;
            }
        }
        if !created {
            warn!("WolfRun: failed to create LXC {} on {}", container_name, node.hostname);
            return;
        }

        // Start the LXC container
        let start_urls = crate::api::build_node_urls(&node.address, node.port,
            &container_action_path(&Runtime::Lxc, container_name));
        let start_payload = serde_json::json!({ "action": "start" });
        for url in &start_urls {
            if let Ok(resp) = client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&start_payload)
                .send().await
            {
                if resp.status().is_success() {
                    info!("WolfRun: deployed LXC {} on {}", container_name, node.hostname);
                    break;
                }
            }
        }

        wolfrun.add_instance(&service.id, ServiceInstance {
            node_id: node_id.to_string(),
            container_name: container_name.to_string(),
            wolfnet_ip: None,
            status: "running".to_string(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        });
    }
}

/// Stop and remove a container (Docker or LXC)
#[allow(dead_code)]
async fn stop_and_remove(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    runtime: &Runtime,
) {
    if node.is_self {
        match runtime {
            Runtime::Docker => {
                let _ = crate::containers::docker_stop(container_name);
                let _ = crate::containers::docker_remove(container_name);
            }
            Runtime::Lxc => {
                let _ = crate::containers::lxc_stop(container_name);
                let _ = crate::containers::lxc_destroy(container_name);
            }
        }
    } else {
        let urls = crate::api::build_node_urls(
            &node.address, node.port,
            &container_action_path(runtime, container_name),
        );
        let stop_payload = serde_json::json!({ "action": "stop" });
        for url in &urls {
            if client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&stop_payload)
                .send().await
                .is_ok()
            {
                break;
            }
        }
        let rm_action = match runtime {
            Runtime::Docker => "remove",
            Runtime::Lxc => "destroy",
        };
        let rm_payload = serde_json::json!({ "action": rm_action });
        for url in &urls {
            if client.post(url)
                .header("X-WolfStack-Secret", cluster_secret)
                .json(&rm_payload)
                .send().await
                .is_ok()
            {
                break;
            }
        }
    }
}

/// Public wrapper for stop_and_remove — used by the API delete handler
#[allow(dead_code)]
pub async fn stop_and_remove_pub(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    runtime: &Runtime,
) {
    stop_and_remove(client, cluster_secret, node, container_name, runtime).await;
}

// ─── Load Balancer (iptables round-robin DNAT) ───

/// Rebuild iptables DNAT rules for a service VIP.
/// Supports "round_robin" (nth statistic) and "ip_hash" (source-IP based sticky sessions).
pub fn rebuild_lb_rules(vip: &str, backend_ips: &[String], ports: &[String], lb_policy: &str) {
    // First remove any existing rules for this VIP
    remove_lb_rules_for_vip(vip);

    if backend_ips.is_empty() {
        debug!("WolfRun LB: no backends for VIP {} — skipping", vip);
        return;
    }

    // Make the VIP locally routable so iptables PREROUTING DNAT can intercept it.
    // Using `ip route add local` (instead of `ip addr add`) avoids making it a
    // real interface address — the kernel accepts packets for it without binding
    // to wolfnet0, which prevents ARP/routing conflicts.
    let cidr = format!("{}/32", vip);
    // Remove any stale interface address first (from earlier versions)
    let _ = std::process::Command::new("ip")
        .args(["addr", "del", &cidr, "dev", "wolfnet0"])
        .output();
    // Add as local route (idempotent — replace if exists)
    let _ = std::process::Command::new("ip")
        .args(["route", "replace", "local", &cidr, "dev", "lo"])
        .output();

    // One-time setup: ip_forward + rp_filter + FORWARD chain rules
    use std::sync::atomic::{AtomicBool, Ordering};
    static VIP_INFRA_READY: AtomicBool = AtomicBool::new(false);
    if !VIP_INFRA_READY.load(Ordering::Relaxed) {
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output();
        // Disable reverse path filtering on wolfnet0 — required because after DNAT
        // the source IP is a remote WolfNet peer but the reply goes via a different path
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.wolfnet0.rp_filter=0"])
            .output();
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.all.rp_filter=0"])
            .output();
        // FORWARD rules: wolfnet0 ↔ container bridges AND wolfnet0 ↔ wolfnet0 (hairpin for remote backends)
        for iface_pair in &[
            ("wolfnet0", "docker0"),
            ("wolfnet0", "lxcbr0"),
            ("wolfnet0", "wolfnet0"),  // hairpin: backend on remote node
        ] {
            let check = std::process::Command::new("iptables")
                .args(["-C", "FORWARD", "-i", iface_pair.0, "-o", iface_pair.1, "-j", "ACCEPT"])
                .output();
            if check.map(|o| !o.status.success()).unwrap_or(true) {
                let _ = std::process::Command::new("iptables")
                    .args(["-I", "FORWARD", "-i", iface_pair.0, "-o", iface_pair.1, "-j", "ACCEPT"])
                    .output();
                if iface_pair.0 != iface_pair.1 {
                    let _ = std::process::Command::new("iptables")
                        .args(["-I", "FORWARD", "-i", iface_pair.1, "-o", iface_pair.0, "-j", "ACCEPT"])
                        .output();
                }
            }
        }
        VIP_INFRA_READY.store(true, Ordering::Relaxed);
        info!("WolfRun LB: one-time infra setup complete (ip_forward, rp_filter=0, FORWARD rules)");
    }

    // Send gratuitous ARP in background (don't block the reconcile loop)
    let vip_owned = vip.to_string();
    std::thread::spawn(move || {
        let _ = std::process::Command::new("arping")
            .args(["-U", "-c", "1", "-I", "wolfnet0", &vip_owned])
            .output();
    });

    // Push VIP into local WolfNet routes (cached host IP to avoid spawning a process every cycle)
    use std::sync::OnceLock;
    static HOST_WOLFNET_IP: OnceLock<Option<String>> = OnceLock::new();
    let host_ip = HOST_WOLFNET_IP.get_or_init(|| {
        std::process::Command::new("ip")
            .args(["addr", "show", "wolfnet0"])
            .output()
            .ok()
            .and_then(|o| {
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                text.lines()
                    .find(|l| l.contains("inet "))
                    .and_then(|l| l.trim().split_whitespace().nth(1))
                    .and_then(|s| s.split('/').next())
                    .map(|s| s.to_string())
            })
    });
    if let Some(host_ip) = host_ip {
        let mut routes = std::collections::HashMap::new();
        routes.insert(vip.to_string(), host_ip.clone());
        crate::containers::update_wolfnet_routes(&routes);
        debug!("WolfRun LB: VIP {} → host {} in routes", vip, host_ip);
    }

    let n = backend_ips.len();

    // Parse service ports to get the container-side ports for LB rules
    // Port format is "host_port:container_port" or just "port"
    let lb_ports: Vec<String> = ports.iter().map(|p| {
        if let Some((_host, container)) = p.split_once(':') {
            container.to_string()
        } else {
            p.clone()
        }
    }).collect();

    // Create DNAT rules for both PREROUTING (external) and OUTPUT (local)
    for chain in &["PREROUTING", "OUTPUT"] {
        for (i, backend) in backend_ips.iter().enumerate() {
            let remaining = n - i;

            let mut args: Vec<String> = vec![
                "-t".into(), "nat".into(), "-A".into(), chain.to_string(),
                "-d".into(), vip.to_string(),
            ];

            // Add port matching if service has ports
            if !lb_ports.is_empty() {
                args.extend_from_slice(&["-p".into(), "tcp".into()]);
                if lb_ports.len() == 1 {
                    args.extend_from_slice(&["--dport".into(), lb_ports[0].clone()]);
                } else {
                    args.extend_from_slice(&["-m".into(), "multiport".into(), "--dports".into(), lb_ports.join(",")]);
                }
            }

            // Distribution mode
            if lb_policy == "ip_hash" {
                // ip_hash: use `statistic --mode random` for distribution.
                // conntrack ensures all packets in a connection go to the same
                // backend, giving session stickiness.
                if remaining > 1 {
                    let prob = 1.0 / remaining as f64;
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "random".into(),
                        "--probability".into(), format!("{:.6}", prob),
                    ]);
                }
            } else {
                // round_robin: nth-based distribution
                if remaining > 1 {
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "nth".into(),
                        "--every".into(), remaining.to_string(),
                        "--packet".into(), "0".into(),
                    ]);
                }
            }

            // Add DNAT target
            let dest = if !lb_ports.is_empty() {
                format!("{}:{}", backend, lb_ports[0])
            } else {
                backend.clone()
            };
            args.extend_from_slice(&["-j".into(), "DNAT".into(), "--to-destination".into(), dest]);
            args.extend_from_slice(&["-m".into(), "comment".into(), "--comment".into(), format!("wolfrun-lb-{}", vip)]);

            let output = std::process::Command::new("iptables")
                .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                .output();

            match output {
                Ok(o) if o.status.success() => {},
                Ok(o) => warn!("WolfRun LB: iptables rule failed for {} → {}: {}",
                    vip, backend, String::from_utf8_lossy(&o.stderr)),
                Err(e) => warn!("WolfRun LB: failed to run iptables: {}", e),
            }
        }
    }

    // MASQUERADE for return traffic (per-backend)
    for backend in backend_ips {
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-d", backend,
                "-m", "comment", "--comment", &format!("wolfrun-lb-{}", vip),
                "-j", "MASQUERADE"])
            .output();
    }

    info!("WolfRun LB: {} VIP {} → {} backend(s): {}",
        if n == 1 { "direct" } else { "round-robin" },
        vip, n, backend_ips.join(", "));
}

/// Remove all iptables rules tagged with a WolfRun LB comment for a given VIP
pub fn remove_lb_rules_for_vip(vip: &str) {
    let comment = format!("wolfrun-lb-{}", vip);

    // Remove from nat PREROUTING and POSTROUTING
    for chain in &["PREROUTING", "POSTROUTING", "OUTPUT"] {
        // List rules, find matching ones, remove in reverse order
        loop {
            let output = std::process::Command::new("iptables")
                .args(["-t", "nat", "-L", chain, "--line-numbers", "-n"])
                .output();

            let lines = match output {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => break,
            };

            // Find the first rule with our comment
            let mut found_num: Option<String> = None;
            for line in lines.lines() {
                if line.contains(&comment) {
                    if let Some(num) = line.split_whitespace().next() {
                        if num.parse::<u32>().is_ok() {
                            found_num = Some(num.to_string());
                            break;
                        }
                    }
                }
            }

            match found_num {
                Some(num) => {
                    let _ = std::process::Command::new("iptables")
                        .args(["-t", "nat", "-D", chain, &num])
                        .output();
                }
                None => break, // No more rules for this VIP
            }
        }
    }

    // Remove the VIP local route and any stale interface address (best-effort)
    let cidr = format!("{}/32", vip);
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "local", &cidr, "dev", "lo"])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["addr", "del", &cidr, "dev", "wolfnet0"])
        .output();
}
