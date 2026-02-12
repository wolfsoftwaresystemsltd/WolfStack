//! Agent — handles server-to-server communication
//!
//! Each WolfStack instance runs an agent that:
//! - Reports its metrics to the cluster
//! - Accepts commands from other WolfStack nodes
//! - Discovers other nodes (via WolfNet or direct IP)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{warn, debug};

use crate::monitoring::SystemMetrics;
use crate::installer::ComponentStatus;

/// A node in the WolfStack cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub hostname: String,
    pub address: String,
    pub port: u16,
    pub last_seen: u64,     // unix timestamp
    pub metrics: Option<SystemMetrics>,
    pub components: Vec<ComponentStatus>,
    pub online: bool,
    pub is_self: bool,
    #[serde(default)]
    pub docker_count: u32,
    #[serde(default)]
    pub lxc_count: u32,
    #[serde(default)]
    pub vm_count: u32,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_node_type")]
    pub node_type: String,              // "wolfstack" or "proxmox"
    #[serde(default)]
    pub pve_token: Option<String>,      // PVEAPIToken string
    #[serde(default)]
    pub pve_fingerprint: Option<String>,
    #[serde(default)]
    pub pve_node_name: Option<String>,  // Proxmox node name for API calls
    #[serde(default)]
    pub pve_cluster_name: Option<String>, // User-friendly cluster name for sidebar grouping
    #[serde(default)]
    pub cluster_name: Option<String>,     // Generic cluster name for WolfStack nodes
}

fn default_node_type() -> String { "wolfstack".to_string() }

/// Cluster state
pub struct ClusterState {
    pub nodes: RwLock<HashMap<String, Node>>,
    pub self_id: String,
    pub self_address: String,
    pub port: u16,
}

impl ClusterState {
    const NODES_FILE: &'static str = "/etc/wolfstack/nodes.json";

    pub fn new(self_id: String, self_address: String, port: u16) -> Self {
        let state = Self {
            nodes: RwLock::new(HashMap::new()),
            self_id,
            self_address,
            port,
        };
        // Load persisted remote nodes
        // Load persisted remote nodes
        state.load_nodes();
        // Remove ghost nodes (same IP/port but different ID)
        state.cleanup_ghosts();
        state
    }

    /// Remove ghost nodes: nodes with same hostname or matching self_id pattern but different ID
    fn cleanup_ghosts(&self) {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut nodes = self.nodes.write().unwrap();
        
        // Collect IDs of ghost nodes to remove:
        // - Any non-self WolfStack node whose hostname matches ours (previous restarts of this server)
        // - Any non-self node whose ID matches our self_id (shouldn't happen, but safety)
        let ghost_ids: Vec<String> = nodes.values()
            .filter(|n| {
                if n.is_self || n.id == self.self_id {
                    return false;
                }
                // Ghost: same hostname + same port + wolfstack type
                n.hostname == hostname && n.port == self.port && n.node_type == "wolfstack"
            })
            .map(|n| n.id.clone())
            .collect();

        for id in &ghost_ids {
            nodes.remove(id);
        }

        if !ghost_ids.is_empty() {
            tracing::info!("Cleaned up {} ghost node(s) (hostname={}, port={})", ghost_ids.len(), hostname, self.port);
            // Persist the cleaned-up state
            drop(nodes);
            self.save_nodes();
        }
    }

    /// Load saved remote nodes from disk
    fn load_nodes(&self) {
        if let Ok(data) = std::fs::read_to_string(Self::NODES_FILE) {
            if let Ok(saved) = serde_json::from_str::<Vec<Node>>(&data) {
                let mut nodes = self.nodes.write().unwrap();
                for mut node in saved {
                    node.online = false; // Will be updated by polling
                    node.is_self = false;
                    // Default to WolfStack if no cluster name
                    if node.cluster_name.is_none() {
                         node.cluster_name = Some("WolfStack".to_string());
                    }
                    nodes.insert(node.id.clone(), node);
                }
                debug!("Loaded {} saved nodes from {}", nodes.len(), Self::NODES_FILE);
            }
        }
    }

    /// Save remote nodes to disk
    fn save_nodes(&self) {
        let nodes = self.nodes.read().unwrap();
        let remote_nodes: Vec<&Node> = nodes.values()
            .filter(|n| !n.is_self)
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&remote_nodes) {
            let _ = std::fs::create_dir_all("/etc/wolfstack");
            if let Err(e) = std::fs::write(Self::NODES_FILE, json) {
                warn!("Failed to save nodes: {}", e);
            }
        }
    }

    /// Update this node's own status
    pub fn update_self(&self, metrics: SystemMetrics, components: Vec<ComponentStatus>, docker_count: u32, lxc_count: u32, vm_count: u32, public_ip: Option<String>) {
        let mut nodes = self.nodes.write().unwrap();
        // Fetch existing cluster_name to preserve it, or default to "WolfStack" if missing
        let cluster_name = nodes.get(&self.self_id)
            .and_then(|n| n.cluster_name.clone())
            .or_else(|| Some("WolfStack".to_string()));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        nodes.insert(self.self_id.clone(), Node {
            id: self.self_id.clone(),
            hostname: metrics.hostname.clone(),
            address: self.self_address.clone(),
            port: self.port,
            last_seen: now,
            metrics: Some(metrics),
            components,
            online: true,
            is_self: true,
            docker_count,
            lxc_count,
            vm_count,
            public_ip,
            node_type: "wolfstack".to_string(),
            pve_token: None,
            pve_fingerprint: None,
            pve_node_name: None,

            pve_cluster_name: None,
            cluster_name,
        });
    }

    /// Update a remote node's status
    pub fn update_remote(&self, node: Node) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node.id.clone(), node);
    }

    /// Get all nodes (deduplicated: if a non-self WolfStack node has same hostname+port as self, skip it)
    pub fn get_all_nodes(&self) -> Vec<Node> {
        let nodes = self.nodes.read().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Find self node's hostname and port for dedup
        let self_hostname = nodes.get(&self.self_id).map(|n| n.hostname.clone()).unwrap_or_default();
        let self_port = self.port;
        nodes.values().filter(|n| {
            // Filter out non-self wolfstack nodes that are actually us (duplicate from gossip)
            if !n.is_self && n.id != self.self_id && n.node_type == "wolfstack"
                && n.hostname == self_hostname && n.port == self_port {
                return false;
            }
            true
        }).map(|n| {
            let mut node = n.clone();
            if !node.is_self {
                node.online = now - node.last_seen < 60;
            }
            node
        }).collect()
    }

    /// Get a single node
    pub fn get_node(&self, id: &str) -> Option<Node> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(id).cloned()
    }

    /// Add a server by address — persists to disk
    pub fn add_server(&self, address: String, port: u16, cluster_name: Option<String>) -> String {
        self.add_server_full(address, port, "wolfstack".to_string(), None, None, None, None, cluster_name)
    }

    /// Add a Proxmox server
    pub fn add_proxmox_server(&self, address: String, port: u16, token: String, fingerprint: Option<String>, node_name: String, pve_cluster_name: Option<String>) -> String {
        // Use pve_cluster_name as the generic cluster_name too
        self.add_server_full(address, port, "proxmox".to_string(), Some(token), fingerprint, Some(node_name), pve_cluster_name.clone(), pve_cluster_name)
    }

    /// Add a server with full options (deduplicates by address+port+pve_node_name)
    fn add_server_full(&self, address: String, port: u16, node_type: String, pve_token: Option<String>, pve_fingerprint: Option<String>, pve_node_name: Option<String>, pve_cluster_name: Option<String>, cluster_name: Option<String>) -> String {
        let mut nodes = self.nodes.write().unwrap();
        
        // Dedup: check if a node with the same address+port+node_type already exists
        if let Some(existing) = nodes.values().find(|n| {
            n.address == address && n.port == port && n.node_type == node_type
                && n.pve_node_name == pve_node_name
        }) {
            let existing_id = existing.id.clone();
            debug!("Node already exists at {}:{} (type={}, id={}), skipping add", address, port, node_type, existing_id);
            return existing_id;
        }
        
        let id = format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        nodes.insert(id.clone(), Node {
            id: id.clone(),
            hostname: address.clone(),
            address,
            port,
            last_seen: now,
            metrics: None,
            components: vec![],
            online: false,
            is_self: false,
            docker_count: 0,
            lxc_count: 0,
            vm_count: 0,
            public_ip: None,
            node_type,
            pve_token,
            pve_fingerprint,
            pve_node_name,
            pve_cluster_name,
            cluster_name,
        });
        drop(nodes);
        self.save_nodes();
        id
    }

    /// Remove a server — persists to disk
    pub fn remove_server(&self, id: &str) -> bool {
        let mut nodes = self.nodes.write().unwrap();
        let removed = nodes.remove(id).is_some();
        drop(nodes);
        if removed {
            self.save_nodes();
        }
        removed
    }

    /// Update node settings (token, fingerprint, cluster name)
    pub fn update_node_settings(&self, id: &str, pve_token: Option<String>, pve_fingerprint: Option<Option<String>>, cluster_name: Option<String>) -> bool {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            if let Some(token) = pve_token { node.pve_token = Some(token); }
            if let Some(fp) = pve_fingerprint { node.pve_fingerprint = fp; }
            if let Some(ref name) = cluster_name {
                // Update both cluster_name fields so sidebar grouping works
                node.cluster_name = Some(name.clone());
                if node.node_type == "proxmox" {
                    node.pve_cluster_name = Some(name.clone());
                }
            }
            drop(nodes);
            self.save_nodes();
            true
        } else {
            false
        }
    }
}

/// Message exchanged between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    /// "Hello, here's my status"
    StatusReport {
        node_id: String,
        hostname: String,
        metrics: SystemMetrics,
        components: Vec<ComponentStatus>,
        #[serde(default)]
        docker_count: u32,
        #[serde(default)]
        lxc_count: u32,
        #[serde(default)]
        vm_count: u32,
        #[serde(default)]
        public_ip: Option<String>,
        #[serde(default)]
        known_nodes: Vec<Node>,
    },
    /// "Give me your status"
    StatusRequest,
    /// "Install this component"
    InstallRequest { component: String },
    /// "Start/stop/restart this service"
    ServiceAction { service: String, action: String },
    /// Response
    Response { success: bool, message: String },
}

/// Poll remote nodes for their status
pub async fn poll_remote_nodes(cluster: Arc<ClusterState>, cluster_secret: String, ai_agent: Option<Arc<crate::ai::AiAgent>>) {
    // Snapshot previous online state BEFORE polling
    let previous_states: HashMap<String, (bool, String)> = {
        let nodes = cluster.nodes.read().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        nodes.values()
            .filter(|n| !n.is_self)
            .map(|n| (n.id.clone(), (now - n.last_seen < 60, n.hostname.clone())))
            .collect()
    };

    let nodes = cluster.get_all_nodes();
    for node in nodes {
        if node.is_self { continue; }

        if node.node_type == "proxmox" {
            // ── Poll Proxmox node via PVE API ──
            let token = match &node.pve_token {
                Some(t) if !t.is_empty() => t.clone(),
                _ => { debug!("Skipping PVE node {} — no token", node.id); continue; }
            };
            let pve_name = node.pve_node_name.clone().unwrap_or_else(|| node.hostname.clone());
            let fp = node.pve_fingerprint.as_deref();

            match crate::proxmox::poll_pve_node(&node.address, node.port, &token, fp, &pve_name).await {
                Ok((status, lxc_count, vm_count, fetched_cluster_name)) => {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    let mem_pct = if status.mem_total > 0 {
                        (status.mem_used as f32 / status.mem_total as f32) * 100.0
                    } else { 0.0 };
                    let disk_avail = status.disk_total.saturating_sub(status.disk_used);
                    let disk_pct = if status.disk_total > 0 {
                        (status.disk_used as f32 / status.disk_total as f32) * 100.0
                    } else { 0.0 };

                    let metrics = crate::monitoring::SystemMetrics {
                        hostname: status.hostname.clone(),
                        cpu_usage_percent: status.cpu * 100.0,
                        cpu_count: status.maxcpu as usize,
                        cpu_model: "Proxmox VE".to_string(),
                        memory_total_bytes: status.mem_total,
                        memory_used_bytes: status.mem_used,
                        memory_percent: mem_pct,
                        swap_total_bytes: 0,
                        swap_used_bytes: 0,
                        disks: vec![crate::monitoring::DiskMetrics {
                            name: "rootfs".to_string(),
                            mount_point: "/".to_string(),
                            fs_type: "".to_string(),
                            total_bytes: status.disk_total,
                            used_bytes: status.disk_used,
                            available_bytes: disk_avail,
                            usage_percent: disk_pct,
                        }],
                        network: vec![],
                        load_avg: crate::monitoring::LoadAverage { one: 0.0, five: 0.0, fifteen: 0.0 },
                        processes: 0,
                        uptime_secs: status.uptime,
                        os_name: Some("Proxmox VE".to_string()),
                        os_version: None,
                        kernel_version: None,
                    };

                    // Prefer user's saved cluster name; only use API-fetched name as initial fallback
                    let final_cluster_name = node.pve_cluster_name.clone().or(fetched_cluster_name);

                    cluster.update_remote(Node {
                        id: node.id.clone(),
                        hostname: status.hostname,
                        address: node.address.clone(),
                        port: node.port,
                        last_seen: now,
                        metrics: Some(metrics),
                        components: vec![],
                        online: true,
                        is_self: false,
                        docker_count: 0,
                        lxc_count,
                        vm_count,
                        public_ip: None,
                        node_type: "proxmox".to_string(),
                        pve_token: node.pve_token.clone(),
                        pve_fingerprint: node.pve_fingerprint.clone(),
                        pve_node_name: node.pve_node_name.clone(),
                        pve_cluster_name: final_cluster_name.clone(),
                        cluster_name: final_cluster_name,
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to poll PVE node {} (pve_name={}, addr={}): {}", node.id, pve_name, node.address, e);
                }
            }
            continue;
        }

        // ── Poll WolfStack node via agent ──
        let url = format!("http://{}:{}/api/agent/status", node.address, node.port);
        debug!("Polling remote node {} at {}", node.id, url);

        match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => {
                match client.get(&url)
                    .header("X-WolfStack-Secret", &cluster_secret)
                    .send().await {
                    Ok(resp) => {
                        if let Ok(msg) = resp.json::<AgentMessage>().await {
                            if let AgentMessage::StatusReport { node_id: _, hostname, metrics, components, docker_count, lxc_count, vm_count, public_ip, known_nodes } = msg {
                                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                                cluster.update_remote(Node {
                                    id: node.id.clone(),
                                    hostname,
                                    address: node.address.clone(),
                                    port: node.port,
                                    last_seen: now,
                                    metrics: Some(metrics),
                                    components,
                                    online: true,
                                    is_self: false,
                                    docker_count,
                                    lxc_count,
                                    vm_count,
                                    public_ip: public_ip.clone(),
                                    node_type: "wolfstack".to_string(),
                                    pve_token: None,
                                    pve_fingerprint: None,
                                    pve_node_name: None,
                                    pve_cluster_name: None,
                                    cluster_name: node.cluster_name.clone(),
                                });

                                // Merge known_nodes (gossip) — with dedup by address+port+hostname
                                let current_nodes = cluster.get_all_nodes();
                                let self_hostname = hostname::get()
                                    .map(|h| h.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                for known in known_nodes {
                                    if known.id == cluster.self_id {
                                        continue; // Skip ourselves by ID
                                    }
                                    // Also skip if this is us by hostname+port (gossip may report different address)
                                    if known.node_type == "wolfstack" && known.hostname == self_hostname && known.port == cluster.port {
                                        continue;
                                    }
                                    // Check both ID and address+port+hostname to prevent ghost re-addition
                                    let already_known = current_nodes.iter().any(|n| {
                                        n.id == known.id 
                                        || (n.address == known.address && n.port == known.port && n.pve_node_name == known.pve_node_name)
                                        || (n.hostname == known.hostname && n.port == known.port && n.node_type == known.node_type)
                                    });
                                    if !already_known {
                                        debug!("Discovered new node via gossip from {}: {} ({})", node.id, known.id, known.node_type);
                                        let mut new_node = known.clone();
                                        new_node.online = false; 
                                        new_node.is_self = false;
                                        cluster.update_remote(new_node);
                                        cluster.save_nodes();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to poll {}: {}", node.id, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create HTTP client: {}", e);
            }
        }
    }

    // After polling, detect state changes and send emails
    // Only the node with the lowest ID sends emails to avoid duplicates
    if let Some(ref ai) = ai_agent {
        let config = ai.config.lock().unwrap().clone();
        if config.email_enabled && !config.email_to.is_empty() {
            let current_nodes = cluster.get_all_nodes();
            // Determine if we are the primary alerter (lowest self_id among online nodes)
            let self_id = &cluster.self_id;
            let is_primary = current_nodes.iter()
                .filter(|n| n.online)
                .map(|n| &n.id)
                .min()
                .map(|min_id| min_id == self_id)
                .unwrap_or(true); // If no nodes online, we're it

            if is_primary {
                for node in current_nodes.iter().filter(|n| !n.is_self) {
                    let (was_online, hostname) = previous_states.get(&node.id)
                        .cloned()
                        .unwrap_or((false, node.hostname.clone()));

                    let display_name = if hostname.is_empty() { &node.address } else { &hostname };

                    if was_online && !node.online {
                        // Node went OFFLINE
                        let subject = format!("[WolfStack ALERT] {} has gone offline", display_name);
                        let body = format!(
                            "⚠️ Node Offline Alert\n\n\
                             Hostname: {}\n\
                             Address: {}:{}\n\
                             Status: OFFLINE\n\
                             Time: {}\n\n\
                             This node is no longer responding to cluster health checks.\n\
                             Please investigate immediately.",
                            display_name, node.address, node.port,
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        if let Err(e) = crate::ai::send_alert_email(&config, &subject, &body) {
                            warn!("Failed to send node-offline email for {}: {}", display_name, e);
                        } else {
                            tracing::info!("Sent node-offline alert email for {}", display_name);
                        }
                    } else if !was_online && node.online {
                        // Node came back ONLINE
                        let subject = format!("[WolfStack OK] {} has been restored", display_name);
                        let body = format!(
                            "✅ Node Restored\n\n\
                             Hostname: {}\n\
                             Address: {}:{}\n\
                             Status: ONLINE\n\
                             Time: {}\n\n\
                             This node is responding to cluster health checks again.",
                            display_name, node.address, node.port,
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        if let Err(e) = crate::ai::send_alert_email(&config, &subject, &body) {
                            warn!("Failed to send node-restored email for {}: {}", display_name, e);
                        } else {
                            tracing::info!("Sent node-restored alert email for {}", display_name);
                        }
                    }
                }
            }
        }
    }
}
