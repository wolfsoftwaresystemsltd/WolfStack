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
}

/// Cluster state
pub struct ClusterState {
    pub nodes: RwLock<HashMap<String, Node>>,
    pub self_id: String,
    pub self_address: String,
    pub port: u16,
}

impl ClusterState {
    pub fn new(self_id: String, self_address: String, port: u16) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            self_id,
            self_address,
            port,
        }
    }

    /// Update this node's own status
    pub fn update_self(&self, metrics: SystemMetrics, components: Vec<ComponentStatus>) {
        let mut nodes = self.nodes.write().unwrap();
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
        });
    }

    /// Update a remote node's status
    pub fn update_remote(&self, node: Node) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node.id.clone(), node);
    }

    /// Get all nodes
    pub fn get_all_nodes(&self) -> Vec<Node> {
        let nodes = self.nodes.read().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        nodes.values().map(|n| {
            let mut node = n.clone();
            if !node.is_self {
                node.online = now - node.last_seen < 30;
            }
            node
        }).collect()
    }

    /// Get a single node
    pub fn get_node(&self, id: &str) -> Option<Node> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(id).cloned()
    }

    /// Add a server by address
    pub fn add_server(&self, address: String, port: u16) -> String {
        let id = format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut nodes = self.nodes.write().unwrap();
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
        });
        id
    }

    /// Remove a server
    pub fn remove_server(&self, id: &str) -> bool {
        let mut nodes = self.nodes.write().unwrap();
        nodes.remove(id).is_some()
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
pub async fn poll_remote_nodes(cluster: Arc<ClusterState>) {
    let nodes = cluster.get_all_nodes();
    for node in nodes {
        if node.is_self { continue; }

        let url = format!("http://{}:{}/api/agent/status", node.address, node.port);
        debug!("Polling remote node {} at {}", node.id, url);

        match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => {
                match client.get(&url).send().await {
                    Ok(resp) => {
                        if let Ok(msg) = resp.json::<AgentMessage>().await {
                            if let AgentMessage::StatusReport { node_id: _, hostname, metrics, components } = msg {
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
                                });
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
}
