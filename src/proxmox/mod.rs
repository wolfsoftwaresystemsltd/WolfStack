// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

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
    pub cpu: f32,              // 0.0–1.0 fraction of allocated CPUs
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

        Ok(arr.iter().map(|v| {
            let vmid = v.get("vmid").and_then(|v| v.as_u64()).unwrap_or(0);
            // Name fallback: name -> hostname -> "VM {vmid}"
            let name = v.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
                .or_else(|| v.get("hostname").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
                .unwrap_or("").to_string();
            PveGuest {
                vmid,
                name,
                status: v.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                guest_type: "qemu".to_string(),
                cpus: v.get("cpus").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
                cpu: v.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                maxmem: v.get("maxmem").and_then(|v| v.as_u64()).unwrap_or(0),
                mem: v.get("mem").and_then(|v| v.as_u64()).unwrap_or(0),
                maxdisk: v.get("maxdisk").and_then(|v| v.as_u64()).unwrap_or(0),
                disk: v.get("disk").and_then(|v| v.as_u64()).unwrap_or(0),
                uptime: v.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0),
                node: self.node_name.clone(),
            }
        }).collect())
    }

    /// List all LXC containers on this node
    /// Fetches hostname from per-container config if not in the list response
    pub async fn list_containers(&self) -> Result<Vec<PveGuest>, String> {
        let data = self.get(&format!("/nodes/{}/lxc", self.node_name)).await?;
        let arr = data.as_array().ok_or("Expected array from /lxc")?;

        let mut guests: Vec<PveGuest> = arr.iter().map(|v| {
            let vmid = v.get("vmid").and_then(|v| v.as_u64()).unwrap_or(0);
            // Try name and hostname from the list response first
            let name = v.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
                .or_else(|| v.get("hostname").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
                .unwrap_or("").to_string();
            PveGuest {
                vmid,
                name,
                status: v.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                guest_type: "lxc".to_string(),
                cpus: v.get("cpus").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
                cpu: v.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                maxmem: v.get("maxmem").and_then(|v| v.as_u64()).unwrap_or(0),
                mem: v.get("mem").and_then(|v| v.as_u64()).unwrap_or(0),
                maxdisk: v.get("maxdisk").and_then(|v| v.as_u64()).unwrap_or(0),
                disk: v.get("disk").and_then(|v| v.as_u64()).unwrap_or(0),
                uptime: v.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0),
                node: self.node_name.clone(),
            }
        }).collect();

        // For containers with no name, fetch hostname from their individual config
        let unnamed: Vec<usize> = guests.iter().enumerate()
            .filter(|(_, g)| g.name.is_empty())
            .map(|(i, _)| i)
            .collect();

        for idx in unnamed {
            let vmid = guests[idx].vmid;
            if let Ok(cfg) = self.get(&format!("/nodes/{}/lxc/{}/config", self.node_name, vmid)).await {
                if let Some(hostname) = cfg.get("hostname").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    guests[idx].name = hostname.to_string();
                } else if let Some(desc) = cfg.get("description").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    // Fall back to first line of description/notes
                    guests[idx].name = desc.lines().next().unwrap_or("").to_string();
                }
            }
        }

        Ok(guests)
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

    /// Get a termproxy ticket for interactive terminal access to a guest
    /// Returns (port, ticket, user) — port is on the PVE host where the WS is served
    pub async fn termproxy(&self, vmid: u64, guest_type: &str) -> Result<(u16, String, String), String> {
        let path = format!("/nodes/{}/{}/{}/termproxy", self.node_name, guest_type, vmid);
        let data = self.post(&path).await?;
        let port = data.get("port").and_then(|v| v.as_u64())
            .ok_or("Missing port in termproxy response")? as u16;
        let ticket = data.get("ticket").and_then(|v| v.as_str())
            .ok_or("Missing ticket in termproxy response")?.to_string();
        let user = data.get("user").and_then(|v| v.as_str()).unwrap_or("root@pam").to_string();
        info!("PVE termproxy for {}/{} VMID {}: port={}", guest_type, self.node_name, vmid, port);
        Ok((port, ticket, user))
    }

    /// Get a termproxy ticket for the PVE node shell itself (not a guest)
    /// Returns (port, ticket, user)
    pub async fn node_termproxy(&self) -> Result<(u16, String, String), String> {
        let path = format!("/nodes/{}/termproxy", self.node_name);
        let data = self.post(&path).await?;
        let port = data.get("port").and_then(|v| v.as_u64())
            .ok_or("Missing port in node termproxy response")? as u16;
        let ticket = data.get("ticket").and_then(|v| v.as_str())
            .ok_or("Missing ticket in node termproxy response")?.to_string();
        let user = data.get("user").and_then(|v| v.as_str()).unwrap_or("root@pam").to_string();
        info!("PVE node termproxy for {}: port={}", self.node_name, port);
        Ok((port, ticket, user))
    }

    /// Get the base URL of this PVE host
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the PVE node name
    pub fn node_name(&self) -> &str {
        &self.node_name
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


    /// Upload a vzdump archive to Proxmox storage and restore it as a new LXC container.
    /// Returns (new_vmid, message).
    pub async fn upload_and_restore(
        &self,
        archive_bytes: Vec<u8>,
        file_name: &str,
        new_name: &str,
        storage: Option<&str>,
    ) -> Result<(u64, String), String> {
        let storage_id = storage.unwrap_or("local");

        // Build a long-timeout client for large file uploads
        let upload_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(600)) // 10 min
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("Failed to build upload client: {}", e))?;

        // Step 1: Upload the archive to storage via multipart form
        //   POST /api2/json/nodes/{node}/storage/{storage}/upload
        let upload_url = format!(
            "{}/api2/json/nodes/{}/storage/{}/upload",
            self.base_url, self.node_name, storage_id
        );
        info!("PVE: Uploading {} ({} bytes) to {}", file_name, archive_bytes.len(), upload_url);

        let part = reqwest::multipart::Part::bytes(archive_bytes)
            .file_name(file_name.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| format!("MIME error: {}", e))?;

        let form = reqwest::multipart::Form::new()
            .text("content", "vztmpl")
            .part("filename", part);

        let resp = upload_client.post(&upload_url)
            .header("Authorization", self.auth_header())
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("PVE upload failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE upload failed ({}): {}", status.as_u16(), body));
        }
        info!("PVE: Upload complete to {}:{}", storage_id, file_name);

        // Step 2: Get the next available VMID
        let vmid_data = self.get("/cluster/nextid").await
            .map_err(|e| format!("Failed to get next VMID: {}", e))?;
        let new_vmid: u64 = if let Some(s) = vmid_data.as_str() {
            s.trim_matches('"').parse().map_err(|e| format!("Invalid VMID '{}': {}", s, e))?
        } else if let Some(n) = vmid_data.as_u64() {
            n
        } else {
            return Err(format!("Unexpected VMID response: {:?}", vmid_data));
        };

        // Step 3: Restore the container from the uploaded archive
        //   POST /api2/json/nodes/{node}/lxc  with ostemplate, vmid, hostname, storage
        let restore_url = format!(
            "{}/api2/json/nodes/{}/lxc",
            self.base_url, self.node_name
        );
        let ostemplate = format!("{}:vztmpl/{}", storage_id, file_name);
        let restore_storage = storage.unwrap_or("local-lvm");

        info!("PVE: Restoring VMID {} from {} as '{}' on storage {}", new_vmid, ostemplate, new_name, restore_storage);

        let resp = upload_client.post(&restore_url)
            .header("Authorization", self.auth_header())
            .form(&[
                ("vmid", new_vmid.to_string()),
                ("ostemplate", ostemplate.clone()),
                ("hostname", new_name.to_string()),
                ("storage", restore_storage.to_string()),
                ("start", "0".to_string()),
                ("restore", "1".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("PVE restore failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE restore failed ({}): {}", status.as_u16(), body));
        }

        let msg = format!("Container '{}' restored as VMID {} on {} (storage: {})",
            new_name, new_vmid, self.node_name, restore_storage);
        info!("PVE: {}", msg);
        Ok((new_vmid, msg))
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
/// Returns (status, lxc_count, vm_count, cluster_name, guests)
pub async fn poll_pve_node(
    address: &str,
    port: u16,
    token: &str,
    fingerprint: Option<&str>,

    node_name: &str,
) -> Result<(PveNodeStatus, u32, u32, Option<String>, Vec<PveGuest>), String> {
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

    Ok((status, lxc_count, vm_count, cluster_name, guests))
}
