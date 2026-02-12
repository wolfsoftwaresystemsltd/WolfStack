#![allow(dead_code)]
use tracing::{info, debug};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Proxmox VE API client for managing remote PVE nodes
pub struct PveClient {
    base_url: String,
    token: String,
    fingerprint: Option<String>,
    node_name: String,
    client: reqwest::Client,
}

/// A VM or container on a Proxmox node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PveGuest {
    pub vmid: u64,
    pub name: String,
    pub status: String,        // "running", "stopped"
    pub guest_type: String,    // "qemu" or "lxc"
    pub cpus: u32,
    pub maxmem: u64,           // bytes
    pub mem: u64,              // current usage bytes
    pub maxdisk: u64,          // bytes
    pub disk: u64,             // current usage bytes
    pub uptime: u64,           // seconds
    pub node: String,          // PVE node name
}

/// Node-level metrics from PVE API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PveNodeStatus {
    pub hostname: String,
    pub cpu: f32,              // 0.0 - 1.0
    pub maxcpu: u32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub uptime: u64,
    pub online: bool,
}

impl PveClient {
    /// Create a new PVE API client
    /// token format: "PVEAPIToken=user@realm!tokenid=uuid"
    pub fn new(address: &str, port: u16, token: &str, fingerprint: Option<&str>, node_name: &str) -> Self {
        let builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true); // PVE often uses self-signed certs

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        Self {
            base_url: format!("https://{}:{}", address, port),
            token: token.to_string(),
            fingerprint: fingerprint.map(|s| s.to_string()),
            node_name: node_name.to_string(),
            client,
        }
    }

    /// Build authorization header
    fn auth_header(&self) -> String {
        // If token already has the prefix, use as-is
        if self.token.starts_with("PVEAPIToken=") {
            self.token.clone()
        } else {
            format!("PVEAPIToken={}", self.token)
        }
    }

    /// GET request to PVE API
    async fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("PVE GET {}", url);

        let resp = self.client.get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("PVE request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE API {} {}: {}", status.as_u16(), path, body));
        }

        let json: serde_json::Value = resp.json().await
            .map_err(|e| format!("PVE JSON parse: {}", e))?;

        Ok(json.get("data").cloned().unwrap_or(json))
    }

    /// POST request to PVE API
    async fn post(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("PVE POST {}", url);

        let resp = self.client.post(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("PVE request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE API {} {}: {}", status.as_u16(), path, body));
        }

        let json: serde_json::Value = resp.json().await
            .map_err(|e| format!("PVE JSON parse: {}", e))?;

        Ok(json.get("data").cloned().unwrap_or(json))
    }

    /// Get node status (CPU, RAM, uptime, etc.)
    /// Tries /nodes/{node}/status first, falls back to /cluster/resources?type=node
    pub async fn get_node_status(&self) -> Result<PveNodeStatus, String> {
        // Try direct node status endpoint first
        match self.get(&format!("/nodes/{}/status", self.node_name)).await {
            Ok(data) => return self.parse_node_status_direct(&data),
            Err(e) => {
                if e.contains("403") || e.contains("Permission") {
                    debug!("Direct node status failed (403), trying /cluster/resources fallback for {}", self.node_name);
                } else {
                    return Err(e); // Non-permission error, don't fallback
                }
            }
        }

        // Fallback: use /cluster/resources?type=node
        let data = self.get("/cluster/resources?type=node").await
            .map_err(|e| format!("Fallback /cluster/resources also failed for {}: {}", self.node_name, e))?;
        
        let arr = data.as_array().ok_or("Expected array from /cluster/resources")?;
        
        // Find our node in the cluster resources
        for item in arr {
            let node = item.get("node").and_then(|n| n.as_str()).unwrap_or("");
            if node == self.node_name {
                let cpu = item.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let maxcpu = item.get("maxcpu").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                let mem_used = item.get("mem").and_then(|v| v.as_u64()).unwrap_or(0);
                let mem_total = item.get("maxmem").and_then(|v| v.as_u64()).unwrap_or(1);
                let disk_used = item.get("disk").and_then(|v| v.as_u64()).unwrap_or(0);
                let disk_total = item.get("maxdisk").and_then(|v| v.as_u64()).unwrap_or(1);
                let uptime = item.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0);
                let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                
                return Ok(PveNodeStatus {
                    hostname: self.node_name.clone(),
                    cpu,
                    maxcpu,
                    mem_used,
                    mem_total,
                    disk_used,
                    disk_total,
                    uptime,
                    online: status == "online",
                });
            }
        }
        
        Err(format!("Node '{}' not found in /cluster/resources", self.node_name))
    }

    /// Parse node status from direct /nodes/{node}/status response
    fn parse_node_status_direct(&self, data: &serde_json::Value) -> Result<PveNodeStatus, String> {
        let cpu = data.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        let maxcpu = data.get("cpuinfo").and_then(|v| v.get("cpus")).and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        let mem_used = data.get("memory").and_then(|v| v.get("used")).and_then(|v| v.as_u64()).unwrap_or(0);
        let mem_total = data.get("memory").and_then(|v| v.get("total")).and_then(|v| v.as_u64()).unwrap_or(1);
        let disk_used = data.get("rootfs").and_then(|v| v.get("used")).and_then(|v| v.as_u64()).unwrap_or(0);
        let disk_total = data.get("rootfs").and_then(|v| v.get("total")).and_then(|v| v.as_u64()).unwrap_or(1);
        let uptime = data.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0);

        Ok(PveNodeStatus {
            hostname: self.node_name.clone(),
            cpu,
            maxcpu,
            mem_used,
            mem_total,
            disk_used,
            disk_total,
            uptime,
            online: true,
        })
    }

    /// List all QEMU VMs on this node
    pub async fn list_vms(&self) -> Result<Vec<PveGuest>, String> {
        let data = self.get(&format!("/nodes/{}/qemu", self.node_name)).await?;
        let arr = data.as_array().ok_or("Expected array from /qemu")?;

        Ok(arr.iter().map(|v| PveGuest {
            vmid: v.get("vmid").and_then(|v| v.as_u64()).unwrap_or(0),
            name: v.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            status: v.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            guest_type: "qemu".to_string(),
            cpus: v.get("cpus").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            maxmem: v.get("maxmem").and_then(|v| v.as_u64()).unwrap_or(0),
            mem: v.get("mem").and_then(|v| v.as_u64()).unwrap_or(0),
            maxdisk: v.get("maxdisk").and_then(|v| v.as_u64()).unwrap_or(0),
            disk: v.get("disk").and_then(|v| v.as_u64()).unwrap_or(0),
            uptime: v.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0),
            node: self.node_name.clone(),
        }).collect())
    }

    /// List all LXC containers on this node
    pub async fn list_containers(&self) -> Result<Vec<PveGuest>, String> {
        let data = self.get(&format!("/nodes/{}/lxc", self.node_name)).await?;
        let arr = data.as_array().ok_or("Expected array from /lxc")?;

        Ok(arr.iter().map(|v| PveGuest {
            vmid: v.get("vmid").and_then(|v| v.as_u64()).unwrap_or(0),
            name: v.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            status: v.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            guest_type: "lxc".to_string(),
            cpus: v.get("cpus").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            maxmem: v.get("maxmem").and_then(|v| v.as_u64()).unwrap_or(0),
            mem: v.get("mem").and_then(|v| v.as_u64()).unwrap_or(0),
            maxdisk: v.get("maxdisk").and_then(|v| v.as_u64()).unwrap_or(0),
            disk: v.get("disk").and_then(|v| v.as_u64()).unwrap_or(0),
            uptime: v.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0),
            node: self.node_name.clone(),
        }).collect())
    }

    /// Get all guests (VMs + containers)
    pub async fn list_all_guests(&self) -> Result<Vec<PveGuest>, String> {
        let (vms, cts) = tokio::join!(self.list_vms(), self.list_containers());
        let mut all = vms.unwrap_or_default();
        all.extend(cts.unwrap_or_default());
        Ok(all)
    }

    /// Perform an action on a guest (start, stop, shutdown, reboot)
    pub async fn guest_action(&self, vmid: u64, guest_type: &str, action: &str) -> Result<String, String> {
        let path = format!("/nodes/{}/{}/{}/status/{}", self.node_name, guest_type, vmid, action);
        let data = self.post(&path).await?;
        let upid = data.as_str().unwrap_or("ok").to_string();
        info!("PVE action {}/{} on {} VMID {}: {}", guest_type, action, self.node_name, vmid, upid);
        Ok(upid)
    }

    /// Test connectivity — try to reach the PVE API
    pub async fn test_connection(&self) -> Result<String, String> {
        let data = self.get("/version").await?;
        let version = data.get("version").and_then(|v| v.as_str()).unwrap_or("unknown");
        let release = data.get("release").and_then(|v| v.as_str()).unwrap_or("");
        Ok(format!("Proxmox VE {} ({})", version, release))
    }

    /// Discover all node names in the PVE cluster
    pub async fn discover_nodes(&self) -> Result<Vec<String>, String> {
        let data = self.get("/nodes").await?;
        let arr = data.as_array().ok_or("Expected array from /nodes")?;
        Ok(arr.iter()
            .filter_map(|v| v.get("node").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .collect())
    }


    /// Get cluster name from /cluster/status
    pub async fn get_cluster_name(&self) -> Result<String, String> {
        let data = self.get("/cluster/status").await?;
        let arr = data.as_array().ok_or("Expected array from /cluster/status")?;
        // Find the entry with type "cluster"
        for item in arr {
            if let Some(type_) = item.get("type").and_then(|t| t.as_str()) {
                if type_ == "cluster" {
                    return Ok(item.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string());
                }
            }
        }
        Ok("standalone".to_string())
    }
}

/// Poll a Proxmox node and return metrics mapped to WolfStack format
pub async fn poll_pve_node(
    address: &str,
    port: u16,
    token: &str,
    fingerprint: Option<&str>,

    node_name: &str,
) -> Result<(PveNodeStatus, u32, u32, Option<String>), String> {
    // Enhanced logging for debugging offline status
    let client = PveClient::new(address, port, token, fingerprint, node_name);
    
    let status = match client.get_node_status().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Proxmox poll failed for {} ({}): get_node_status error: {}", node_name, address, e);
            return Err(e);
        }
    };

    let guests = match client.list_all_guests().await {
        Ok(g) => g,
        Err(e) => {
             tracing::warn!("Proxmox poll warning for {} ({}): list_all_guests failed: {}", node_name, address, e);
             Vec::new()
        }
    };

    let cluster_name = client.get_cluster_name().await.ok(); 

    let lxc_count = guests.iter().filter(|g| g.guest_type == "lxc").count() as u32;
    let vm_count = guests.iter().filter(|g| g.guest_type == "qemu").count() as u32;

    Ok((status, lxc_count, vm_count, cluster_name))
}
