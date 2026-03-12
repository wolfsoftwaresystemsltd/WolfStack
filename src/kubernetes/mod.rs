// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Kubernetes Management — k3s/k8s cluster provisioning, resource management,
//! and application deployment via kubectl CLI integration.
//!
//! Supports multiple clusters (k3s, k8s, EKS, GKE, AKS) with per-cluster
//! kubeconfig files. All interactions go through `kubectl` CLI rather than
//! the Kubernetes API directly, keeping the dependency footprint small.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{error, info, warn};

const CONFIG_FILE: &str = "/etc/wolfstack/kubernetes.json";

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum K8sClusterType {
    K3s,
    K8s,
    Eks,
    Gke,
    Aks,
    Other,
}

impl std::fmt::Display for K8sClusterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::K3s => write!(f, "k3s"),
            Self::K8s => write!(f, "k8s"),
            Self::Eks => write!(f, "eks"),
            Self::Gke => write!(f, "gke"),
            Self::Aks => write!(f, "aks"),
            Self::Other => write!(f, "other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum K8sNodeRole {
    Server,
    Agent,
}

impl std::fmt::Display for K8sNodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "server"),
            Self::Agent => write!(f, "agent"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sClusterNode {
    pub node_id: String,
    pub role: K8sNodeRole,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sCluster {
    pub id: String,
    pub name: String,
    pub kubeconfig_path: String,
    pub api_url: String,
    pub cluster_type: K8sClusterType,
    pub created_at: String,
    #[serde(default)]
    pub nodes: Vec<K8sClusterNode>,
}

// ─── Runtime Info (returned from kubectl) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNamespace {
    pub name: String,
    pub status: String,
    pub age: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sPod {
    pub name: String,
    pub namespace: String,
    pub status: String,
    pub ready: String,
    pub restarts: u32,
    pub age: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sDeployment {
    pub name: String,
    pub namespace: String,
    pub ready_replicas: u32,
    pub desired_replicas: u32,
    pub available: u32,
    pub age: String,
    #[serde(default)]
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sService {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub cluster_ip: String,
    #[serde(default)]
    pub external_ip: String,
    pub ports: String,
    pub age: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNode {
    pub name: String,
    pub status: String,
    pub roles: String,
    pub version: String,
    pub age: String,
    #[serde(default)]
    pub cpu_capacity: String,
    #[serde(default)]
    pub memory_capacity: String,
    #[serde(default)]
    pub cpu_usage: String,
    #[serde(default)]
    pub memory_usage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sClusterStatus {
    pub healthy: bool,
    pub nodes_ready: u32,
    pub nodes_total: u32,
    pub pods_running: u32,
    pub pods_total: u32,
    pub namespaces: u32,
    pub api_version: String,
}

// ─── Config ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub clusters: Vec<K8sCluster>,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            clusters: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Config Persistence ───
// ═══════════════════════════════════════════════

pub fn load_config() -> KubernetesConfig {
    match fs::read_to_string(CONFIG_FILE) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => KubernetesConfig::default(),
    }
}

pub fn save_config(config: &KubernetesConfig) -> Result<(), String> {
    let dir = Path::new(CONFIG_FILE).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize kubernetes config: {}", e))?;
    fs::write(CONFIG_FILE, json)
        .map_err(|e| format!("Failed to write kubernetes config: {}", e))
}

// ═══════════════════════════════════════════════
// ─── Cluster CRUD ───
// ═══════════════════════════════════════════════

pub fn add_cluster(
    id: String,
    name: String,
    kubeconfig_path: String,
    api_url: String,
    cluster_type: K8sClusterType,
) -> Result<K8sCluster, String> {
    let mut config = load_config();

    if config.clusters.iter().any(|c| c.id == id) {
        return Err(format!("Cluster with id '{}' already exists", id));
    }

    let cluster = K8sCluster {
        id,
        name,
        kubeconfig_path,
        api_url,
        cluster_type,
        created_at: chrono::Utc::now().to_rfc3339(),
        nodes: Vec::new(),
    };

    config.clusters.push(cluster.clone());
    save_config(&config)?;
    info!("Added Kubernetes cluster '{}'", cluster.name);
    Ok(cluster)
}

pub fn remove_cluster(id: &str) -> Result<(), String> {
    let mut config = load_config();
    let before = config.clusters.len();
    config.clusters.retain(|c| c.id != id);
    if config.clusters.len() == before {
        return Err(format!("Cluster '{}' not found", id));
    }
    save_config(&config)?;
    info!("Removed Kubernetes cluster '{}'", id);
    Ok(())
}

pub fn get_cluster(id: &str) -> Option<K8sCluster> {
    let config = load_config();
    config.clusters.into_iter().find(|c| c.id == id)
}

pub fn list_clusters() -> Vec<K8sCluster> {
    load_config().clusters
}

// ═══════════════════════════════════════════════
// ─── kubectl Helper ───
// ═══════════════════════════════════════════════

pub fn kubectl(kubeconfig: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute kubectl: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("kubectl command failed: {}", stderr);
        Err(stderr)
    }
}

// ═══════════════════════════════════════════════
// ─── Provisioning ───
// ═══════════════════════════════════════════════

/// Generate a bash script that installs k3s server on a node.
/// The script installs k3s, waits for it to be ready, and prints the join token.
pub fn provision_k3s_server(node_address: &str, cluster_name: &str) -> Result<String, String> {
    info!(
        "Generating k3s server provisioning script for {} (cluster: {})",
        node_address, cluster_name
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Installing k3s server on {node_address} for cluster '{cluster_name}' ==="

# Install k3s server
curl -sfL https://get.k3s.io | sh -s - server

# Wait for k3s to be ready
echo "Waiting for k3s to be ready..."
for i in $(seq 1 60); do
    if kubectl get nodes &>/dev/null; then
        echo "k3s is ready!"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: k3s failed to start within 60 seconds"
        exit 1
    fi
    sleep 1
done

# Display connection info
echo ""
echo "=== k3s Server Installed Successfully ==="
echo "Kubeconfig: /etc/rancher/k3s/k3s.yaml"
echo "Join token: $(cat /var/lib/rancher/k3s/server/node-token)"
echo "API URL: https://{node_address}:6443"
echo ""
echo "To add agent nodes, run:"
echo "  curl -sfL https://get.k3s.io | K3S_URL=https://{node_address}:6443 K3S_TOKEN=<token> sh -s - agent"
"#,
        node_address = node_address,
        cluster_name = cluster_name,
    );

    Ok(script)
}

/// Generate a bash script that joins a node to a k3s cluster as an agent.
pub fn provision_k3s_agent(
    node_address: &str,
    server_url: &str,
    token: &str,
) -> Result<String, String> {
    info!(
        "Generating k3s agent provisioning script for {} (server: {})",
        node_address, server_url
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Joining {node_address} as k3s agent to {server_url} ==="

# Install k3s agent
curl -sfL https://get.k3s.io | K3S_URL={server_url} K3S_TOKEN={token} sh -s - agent

# Wait for the agent to register
echo "Waiting for k3s agent to register..."
sleep 5

echo ""
echo "=== k3s Agent Installed Successfully ==="
echo "Node {node_address} has joined the cluster as an agent."
echo "Check status on the server with: kubectl get nodes"
"#,
        node_address = node_address,
        server_url = server_url,
        token = token,
    );

    Ok(script)
}

/// Read the k3s join token from a server node.
/// This reads `/var/lib/rancher/k3s/server/node-token` via the local filesystem
/// or falls back to using kubectl to read the node-token secret.
pub fn get_k3s_token(kubeconfig: &str) -> Result<String, String> {
    // Try reading the token file directly (works if running on the server node)
    let token_path = "/var/lib/rancher/k3s/server/node-token";
    if let Ok(token) = fs::read_to_string(token_path) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // Fall back to kubectl — read the k3s token from the node
    warn!("Could not read k3s token file directly, trying kubectl");
    let output = kubectl(
        kubeconfig,
        &[
            "get",
            "secret",
            "-n",
            "kube-system",
            "k3s-serving",
            "-o",
            "jsonpath={.data.token}",
        ],
    )?;

    if output.is_empty() {
        Err("k3s join token not found".to_string())
    } else {
        Ok(output.trim().to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── Resource Queries ───
// ═══════════════════════════════════════════════

/// Helper to compute a human-readable age string from a creation timestamp.
fn compute_age(creation_timestamp: &str) -> String {
    if let Ok(created) = chrono::DateTime::parse_from_rfc3339(creation_timestamp) {
        let duration = chrono::Utc::now().signed_duration_since(created);
        if duration.num_days() > 0 {
            format!("{}d", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{}h", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{}m", duration.num_minutes())
        } else {
            format!("{}s", duration.num_seconds())
        }
    } else {
        "unknown".to_string()
    }
}

pub fn get_namespaces(kubeconfig: &str) -> Vec<K8sNamespace> {
    let args = vec!["get", "namespaces", "-o", "json"];
    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get namespaces: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse namespace JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let status = item["status"]["phase"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();
            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            K8sNamespace { name, status, age }
        })
        .collect()
}

pub fn get_pods(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sPod> {
    let mut args = vec!["get", "pods", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }

    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get pods: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse pod JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let phase = item["status"]["phase"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();

            // Compute ready count
            let container_statuses = item["status"]["containerStatuses"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let total_containers = container_statuses.len();
            let ready_containers = container_statuses
                .iter()
                .filter(|cs| cs["ready"].as_bool().unwrap_or(false))
                .count();
            let ready = format!("{}/{}", ready_containers, total_containers);

            let restarts: u32 = container_statuses
                .iter()
                .map(|cs| cs["restartCount"].as_u64().unwrap_or(0) as u32)
                .sum();

            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            let node = item["spec"]["nodeName"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ip = item["status"]["podIP"]
                .as_str()
                .unwrap_or("")
                .to_string();

            K8sPod {
                name,
                namespace: ns,
                status: phase,
                ready,
                restarts,
                age,
                node,
                ip,
            }
        })
        .collect()
}

pub fn get_deployments(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sDeployment> {
    let mut args = vec!["get", "deployments", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }

    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get deployments: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse deployment JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let desired_replicas = item["spec"]["replicas"].as_u64().unwrap_or(0) as u32;
            let ready_replicas = item["status"]["readyReplicas"].as_u64().unwrap_or(0) as u32;
            let available = item["status"]["availableReplicas"]
                .as_u64()
                .unwrap_or(0) as u32;
            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            // Get the image from the first container spec
            let image = item["spec"]["template"]["spec"]["containers"]
                .as_array()
                .and_then(|containers| containers.first())
                .and_then(|c| c["image"].as_str())
                .unwrap_or("")
                .to_string();

            K8sDeployment {
                name,
                namespace: ns,
                ready_replicas,
                desired_replicas,
                available,
                age,
                image,
            }
        })
        .collect()
}

pub fn get_services(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sService> {
    let mut args = vec!["get", "services", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }

    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get services: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse service JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let service_type = item["spec"]["type"]
                .as_str()
                .unwrap_or("ClusterIP")
                .to_string();
            let cluster_ip = item["spec"]["clusterIP"]
                .as_str()
                .unwrap_or("")
                .to_string();

            // External IP: from status.loadBalancer.ingress or spec.externalIPs
            let external_ip = item["status"]["loadBalancer"]["ingress"]
                .as_array()
                .and_then(|ingresses| ingresses.first())
                .and_then(|ing| ing["ip"].as_str().or_else(|| ing["hostname"].as_str()))
                .or_else(|| {
                    item["spec"]["externalIPs"]
                        .as_array()
                        .and_then(|ips| ips.first())
                        .and_then(|ip| ip.as_str())
                })
                .unwrap_or("<none>")
                .to_string();

            // Format ports as "80:30080/TCP,443:30443/TCP"
            let ports = item["spec"]["ports"]
                .as_array()
                .map(|ports| {
                    ports
                        .iter()
                        .map(|p| {
                            let port = p["port"].as_u64().unwrap_or(0);
                            let node_port = p["nodePort"].as_u64();
                            let protocol = p["protocol"].as_str().unwrap_or("TCP");
                            if let Some(np) = node_port {
                                format!("{}:{}/{}", port, np, protocol)
                            } else {
                                format!("{}/{}", port, protocol)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();

            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            K8sService {
                name,
                namespace: ns,
                service_type,
                cluster_ip,
                external_ip,
                ports,
                age,
            }
        })
        .collect()
}

pub fn get_nodes(kubeconfig: &str) -> Vec<K8sNode> {
    let output = match kubectl(kubeconfig, &["get", "nodes", "-o", "json"]) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get nodes: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse node JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    // Try to get metrics for CPU/memory usage
    let metrics: Option<serde_json::Value> =
        kubectl(kubeconfig, &["top", "nodes", "--no-headers", "-o", "json"])
            .ok()
            .and_then(|o| serde_json::from_str(&o).ok());

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();

            // Status: look at conditions for "Ready"
            let conditions = item["status"]["conditions"].as_array();
            let status = conditions
                .and_then(|conds| {
                    conds.iter().find(|c| c["type"].as_str() == Some("Ready"))
                })
                .map(|c| {
                    if c["status"].as_str() == Some("True") {
                        "Ready".to_string()
                    } else {
                        "NotReady".to_string()
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string());

            // Roles from labels
            let labels = &item["metadata"]["labels"];
            let mut roles = Vec::new();
            if let Some(obj) = labels.as_object() {
                for (key, _) in obj {
                    if key.starts_with("node-role.kubernetes.io/") {
                        if let Some(role) = key.strip_prefix("node-role.kubernetes.io/") {
                            if !role.is_empty() {
                                roles.push(role.to_string());
                            }
                        }
                    }
                }
            }
            let roles_str = if roles.is_empty() {
                "<none>".to_string()
            } else {
                roles.join(",")
            };

            let version = item["status"]["nodeInfo"]["kubeletVersion"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            let cpu_capacity = item["status"]["capacity"]["cpu"]
                .as_str()
                .unwrap_or("0")
                .to_string();
            let memory_capacity = item["status"]["capacity"]["memory"]
                .as_str()
                .unwrap_or("0")
                .to_string();

            // Try to find usage from metrics
            let (cpu_usage, memory_usage) = metrics
                .as_ref()
                .and_then(|m| m["items"].as_array())
                .and_then(|items| {
                    items.iter().find(|mi| {
                        mi["metadata"]["name"].as_str() == Some(&name)
                    })
                })
                .map(|mi| {
                    let cpu = mi["usage"]["cpu"]
                        .as_str()
                        .unwrap_or("0")
                        .to_string();
                    let mem = mi["usage"]["memory"]
                        .as_str()
                        .unwrap_or("0")
                        .to_string();
                    (cpu, mem)
                })
                .unwrap_or_else(|| ("0".to_string(), "0".to_string()));

            K8sNode {
                name,
                status,
                roles: roles_str,
                version,
                age,
                cpu_capacity,
                memory_capacity,
                cpu_usage,
                memory_usage,
            }
        })
        .collect()
}

pub fn get_cluster_status(kubeconfig: &str) -> K8sClusterStatus {
    // Get API version
    let api_version = kubectl(kubeconfig, &["version", "--short", "-o", "json"])
        .ok()
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        .and_then(|v| v["serverVersion"]["gitVersion"].as_str().map(String::from))
        .unwrap_or_else(|| {
            // Fallback: try plain version output
            kubectl(kubeconfig, &["version", "--short"])
                .unwrap_or_else(|_| "unknown".to_string())
                .lines()
                .find(|l| l.contains("Server"))
                .unwrap_or("unknown")
                .to_string()
        });

    // Get nodes
    let nodes = get_nodes(kubeconfig);
    let nodes_total = nodes.len() as u32;
    let nodes_ready = nodes.iter().filter(|n| n.status == "Ready").count() as u32;

    // Get pods
    let pods = get_pods(kubeconfig, None);
    let pods_total = pods.len() as u32;
    let pods_running = pods.iter().filter(|p| p.status == "Running").count() as u32;

    // Get namespaces
    let namespaces = get_namespaces(kubeconfig).len() as u32;

    let healthy = nodes_total > 0 && nodes_ready == nodes_total;

    K8sClusterStatus {
        healthy,
        nodes_ready,
        nodes_total,
        pods_running,
        pods_total,
        namespaces,
        api_version,
    }
}

// ═══════════════════════════════════════════════
// ─── Resource Management ───
// ═══════════════════════════════════════════════

pub fn create_namespace(kubeconfig: &str, name: &str) -> Result<String, String> {
    info!("Creating namespace '{}'", name);
    kubectl(kubeconfig, &["create", "namespace", name])
}

pub fn delete_namespace(kubeconfig: &str, name: &str) -> Result<String, String> {
    info!("Deleting namespace '{}'", name);
    kubectl(kubeconfig, &["delete", "namespace", name])
}

pub fn delete_pod(kubeconfig: &str, name: &str, namespace: &str) -> Result<String, String> {
    info!("Deleting pod '{}' in namespace '{}'", name, namespace);
    kubectl(kubeconfig, &["delete", "pod", name, "-n", namespace])
}

pub fn scale_deployment(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
    replicas: u32,
) -> Result<String, String> {
    info!(
        "Scaling deployment '{}' in namespace '{}' to {} replicas",
        name, namespace, replicas
    );
    let replicas_arg = format!("--replicas={}", replicas);
    kubectl(
        kubeconfig,
        &["scale", "deployment", name, "-n", namespace, &replicas_arg],
    )
}

pub fn delete_deployment(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<String, String> {
    info!("Deleting deployment '{}' in namespace '{}'", name, namespace);
    kubectl(
        kubeconfig,
        &["delete", "deployment", name, "-n", namespace],
    )
}

pub fn restart_deployment(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<String, String> {
    info!(
        "Restarting deployment '{}' in namespace '{}'",
        name, namespace
    );
    kubectl(
        kubeconfig,
        &["rollout", "restart", "deployment", name, "-n", namespace],
    )
}

pub fn delete_service(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<String, String> {
    info!("Deleting service '{}' in namespace '{}'", name, namespace);
    kubectl(
        kubeconfig,
        &["delete", "service", name, "-n", namespace],
    )
}

pub fn get_pod_logs(
    kubeconfig: &str,
    pod: &str,
    namespace: &str,
    container: Option<&str>,
    tail_lines: u32,
) -> Result<String, String> {
    let tail_arg = format!("--tail={}", tail_lines);
    let mut args = vec!["logs", pod, "-n", namespace, &tail_arg];
    if let Some(c) = container {
        args.extend_from_slice(&["-c", c]);
    }
    kubectl(kubeconfig, &args)
}

pub fn apply_yaml(kubeconfig: &str, yaml_content: &str) -> Result<String, String> {
    // Write YAML to a temporary file
    let tmp_path = format!(
        "/tmp/wolfstack-k8s-apply-{}.yaml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    fs::write(&tmp_path, yaml_content)
        .map_err(|e| format!("Failed to write temp YAML file: {}", e))?;

    let result = kubectl(kubeconfig, &["apply", "-f", &tmp_path]);

    // Clean up temp file
    let _ = fs::remove_file(&tmp_path);

    result
}

// ═══════════════════════════════════════════════
// ─── App Deployment ───
// ═══════════════════════════════════════════════

/// Deploy an application to Kubernetes by generating Deployment + Service YAML
/// and applying it. Converts Docker-style port mappings and env vars to k8s format.
///
/// * `ports` — Docker-style port mappings, e.g. ["8080:80", "443:443"]
///   Format: "hostPort:containerPort" where hostPort becomes nodePort
/// * `env` — Docker-style env vars, e.g. ["KEY=value", "DB_HOST=localhost"]
/// * `volumes` — Docker-style volume mounts, e.g. ["/host/path:/container/path"]
pub fn deploy_app_to_k8s(
    kubeconfig: &str,
    app_name: &str,
    container_name: &str,
    namespace: &str,
    image: &str,
    ports: &[String],
    env: &[String],
    volumes: &[String],
    replicas: u32,
) -> Result<String, String> {
    info!(
        "Deploying app '{}' (container: {}, image: {}) to namespace '{}' with {} replicas",
        app_name, container_name, image, namespace, replicas
    );

    // Build container ports YAML
    let container_ports_yaml = if ports.is_empty() {
        String::new()
    } else {
        let port_entries: Vec<String> = ports
            .iter()
            .filter_map(|p| {
                let parts: Vec<&str> = p.split(':').collect();
                let container_port = if parts.len() == 2 {
                    parts[1]
                } else {
                    parts[0]
                };
                container_port
                    .parse::<u32>()
                    .ok()
                    .map(|cp| format!("        - containerPort: {}", cp))
            })
            .collect();
        if port_entries.is_empty() {
            String::new()
        } else {
            format!("        ports:\n{}\n", port_entries.join("\n"))
        }
    };

    // Build env YAML
    let env_yaml = if env.is_empty() {
        String::new()
    } else {
        let env_entries: Vec<String> = env
            .iter()
            .filter_map(|e| {
                let parts: Vec<&str> = e.splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some(format!(
                        "        - name: {}\n          value: \"{}\"",
                        parts[0],
                        parts[1].replace('"', "\\\"")
                    ))
                } else {
                    None
                }
            })
            .collect();
        if env_entries.is_empty() {
            String::new()
        } else {
            format!("        env:\n{}\n", env_entries.join("\n"))
        }
    };

    // Build volume mounts and volumes YAML
    let (volume_mounts_yaml, volumes_yaml) = if volumes.is_empty() {
        (String::new(), String::new())
    } else {
        let mut mounts = Vec::new();
        let mut vols = Vec::new();

        for (i, v) in volumes.iter().enumerate() {
            let parts: Vec<&str> = v.splitn(2, ':').collect();
            if parts.len() == 2 {
                let vol_name = format!("vol-{}", i);
                mounts.push(format!(
                    "        - name: {}\n          mountPath: {}",
                    vol_name, parts[1]
                ));
                vols.push(format!(
                    "      - name: {}\n        hostPath:\n          path: {}",
                    vol_name, parts[0]
                ));
            }
        }

        let mounts_yaml = if mounts.is_empty() {
            String::new()
        } else {
            format!("        volumeMounts:\n{}\n", mounts.join("\n"))
        };
        let vols_yaml = if vols.is_empty() {
            String::new()
        } else {
            format!("      volumes:\n{}\n", vols.join("\n"))
        };
        (mounts_yaml, vols_yaml)
    };

    // Build Service ports YAML
    let service_ports_yaml = if ports.is_empty() {
        String::new()
    } else {
        let svc_port_entries: Vec<String> = ports
            .iter()
            .filter_map(|p| {
                let parts: Vec<&str> = p.split(':').collect();
                if parts.len() == 2 {
                    let host_port = parts[0].parse::<u32>().ok()?;
                    let container_port = parts[1].parse::<u32>().ok()?;
                    // NodePort must be in range 30000-32767; map host ports accordingly
                    let node_port = if host_port >= 30000 && host_port <= 32767 {
                        Some(host_port)
                    } else {
                        None
                    };
                    let mut entry = format!(
                        "  - port: {}\n    targetPort: {}",
                        container_port, container_port
                    );
                    if let Some(np) = node_port {
                        entry.push_str(&format!("\n    nodePort: {}", np));
                    }
                    Some(entry)
                } else {
                    let port = parts[0].parse::<u32>().ok()?;
                    Some(format!("  - port: {}\n    targetPort: {}", port, port))
                }
            })
            .collect();
        if svc_port_entries.is_empty() {
            String::new()
        } else {
            format!("  ports:\n{}\n", svc_port_entries.join("\n"))
        }
    };

    // Assemble the full YAML
    let yaml = format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {container_name}
  namespace: {namespace}
  labels:
    app: {container_name}
    wolfstack/app: {app_name}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {container_name}
  template:
    metadata:
      labels:
        app: {container_name}
    spec:
      containers:
      - name: {container_name}
        image: {image}
{container_ports}{env}{volume_mounts}{volumes_spec}---
apiVersion: v1
kind: Service
metadata:
  name: {container_name}
  namespace: {namespace}
spec:
  selector:
    app: {container_name}
{service_ports}  type: NodePort
"#,
        container_name = container_name,
        namespace = namespace,
        app_name = app_name,
        replicas = replicas,
        image = image,
        container_ports = container_ports_yaml,
        env = env_yaml,
        volume_mounts = volume_mounts_yaml,
        volumes_spec = volumes_yaml,
        service_ports = service_ports_yaml,
    );

    apply_yaml(kubeconfig, &yaml)
}
