// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Shared HTTP client for every PveClient instance and the ad-hoc
/// upload/preflight/sync calls. Previously every PveClient::new()
/// built a fresh Client (one leaked pool per managed PVE node), and
/// the upload/preflight/sync sites did the same per call.
static PVE_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true) // PVE often uses self-signed certs
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

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
        // Cheap Arc clone of the shared pool — see PVE_CLIENT.
        Self {
            base_url: format!("https://{}:{}", crate::netaddr::bracket_host(address), port),
            token: token.to_string(),
            fingerprint: fingerprint.map(|s| s.to_string()),
            node_name: node_name.to_string(),
            client: reqwest::Client::clone(&PVE_CLIENT),
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
        self.post_form(path, &[]).await
    }

    /// POST with a form-encoded body. PVE's resize/move endpoints take
    /// parameters as form fields, not JSON, so this is the right call
    /// for those.
    async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> Result<serde_json::Value, String> {
        let url = format!("{}/api2/json{}", self.base_url, path);
        let mut req = self.client.post(&url)
            .header("Authorization", self.auth_header());
        if !form.is_empty() {
            req = req.form(form);
        }
        let resp = req.send().await
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

    /// PUT with a form-encoded body — used by /lxc/{id}/resize.
    async fn put_form(&self, path: &str, form: &[(&str, &str)]) -> Result<serde_json::Value, String> {
        let url = format!("{}/api2/json{}", self.base_url, path);
        let resp = self.client.put(&url)
            .header("Authorization", self.auth_header())
            .form(form)
            .send().await
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

        let mut guests: Vec<PveGuest> = arr.iter().map(|v| {
            let vmid = v.get("vmid").and_then(|v| v.as_u64()).unwrap_or(0);
            // Name fallback: name -> hostname -> "VM {vmid}"
            let name = v.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
                .or_else(|| v.get("hostname").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
                .unwrap_or("").to_string();
            // Prefer qmpstatus (actual QEMU process state) over status
            // Some PVE builds (e.g. PiMox on ARM) may not update status reliably
            let status = v.get("qmpstatus").and_then(|v| v.as_str())
                .or_else(|| v.get("status").and_then(|v| v.as_str()))
                .unwrap_or("unknown").to_string();
            PveGuest {
                vmid,
                name,
                status,
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
        }).collect();

        // /qemu list returns `disk: 0` for almost every VM because the
        // host can't see inside the guest's filesystem unless the QEMU
        // guest agent reports it. /status/current pulls the agent-
        // reported value when the agent is running. For VMs without
        // the agent we leave the value at 0 — better honest "unknown"
        // than the misleading near-zero we used to show for full disks.
        let running_indexes: Vec<usize> = guests.iter().enumerate()
            .filter(|(_, g)| g.status == "running")
            .map(|(i, _)| i)
            .collect();
        let status_paths: Vec<String> = running_indexes.iter().map(|idx| {
            format!("/nodes/{}/qemu/{}/status/current", self.node_name, guests[*idx].vmid)
        }).collect();
        let status_futures: Vec<_> = status_paths.iter().map(|p| self.get(p)).collect();
        let status_results = futures::future::join_all(status_futures).await;
        for (i, result) in running_indexes.iter().zip(status_results.into_iter()) {
            if let Ok(s) = result {
                if let Some(d) = s.get("disk").and_then(|v| v.as_u64()) {
                    if d > 0 { guests[*i].disk = d; }
                }
                if let Some(md) = s.get("maxdisk").and_then(|v| v.as_u64()) {
                    if md > 0 { guests[*i].maxdisk = md; }
                }
            }
        }

        Ok(guests)
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

        // The /lxc list endpoint's `disk` field is notoriously unreliable
        // — it's frequently 0 or stale even for running containers, because
        // Proxmox doesn't trigger a fresh stat for the list. The accurate
        // live value comes from /lxc/{vmid}/status/current per container.
        // Without this, the dashboard shows "9% used" on a container that's
        // actually 95% full and no alert fires. We fan out the per-CT
        // status fetches in parallel for running containers only — stopped
        // ones legitimately report no usage.
        let running_indexes: Vec<usize> = guests.iter().enumerate()
            .filter(|(_, g)| g.status == "running")
            .map(|(i, _)| i)
            .collect();
        let status_paths: Vec<String> = running_indexes.iter().map(|idx| {
            format!("/nodes/{}/lxc/{}/status/current", self.node_name, guests[*idx].vmid)
        }).collect();
        let status_futures: Vec<_> = status_paths.iter().map(|p| self.get(p)).collect();
        let status_results = futures::future::join_all(status_futures).await;
        for (i, result) in running_indexes.iter().zip(status_results.into_iter()) {
            if let Ok(s) = result {
                // status/current returns a richer view: `disk` here IS
                // the live rootfs usage. `maxdisk` matches the configured
                // disk size. Prefer these over the list values.
                if let Some(d) = s.get("disk").and_then(|v| v.as_u64()) {
                    guests[*i].disk = d;
                }
                if let Some(md) = s.get("maxdisk").and_then(|v| v.as_u64()) {
                    if md > 0 { guests[*i].maxdisk = md; }
                }
            }
        }

        // For containers with no name, fetch hostname from their individual config
        // Fetch all unnamed configs concurrently for speed on remote servers
        let unnamed: Vec<usize> = guests.iter().enumerate()
            .filter(|(_, g)| g.name.is_empty())
            .map(|(i, _)| i)
            .collect();

        let config_paths: Vec<String> = unnamed.iter().map(|idx| {
            let vmid = guests[*idx].vmid;
            format!("/nodes/{}/lxc/{}/config", self.node_name, vmid)
        }).collect();
        let config_futures: Vec<_> = config_paths.iter().map(|path| {
            self.get(path)
        }).collect();
        let config_results = futures::future::join_all(config_futures).await;

        for (i, result) in unnamed.iter().zip(config_results.into_iter()) {
            if let Ok(cfg) = result {
                if let Some(hostname) = cfg.get("hostname").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    guests[*i].name = hostname.to_string();
                } else if let Some(desc) = cfg.get("description").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    // Fall back to first line of description/notes
                    guests[*i].name = desc.lines().next().unwrap_or("").to_string();
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

        Ok(upid)
    }

    /// Resize an LXC container's disk. `disk` is the volume id from
    /// the config (typically "rootfs", or "mp0", "mp1" ... for extra
    /// mountpoints). `size` is a Proxmox-format string — either a
    /// concrete size like "16G" or a relative grow like "+4G". PVE
    /// refuses shrinks via this endpoint.
    pub async fn lxc_resize_disk(&self, vmid: u64, disk: &str, size: &str) -> Result<String, String> {
        let path = format!("/nodes/{}/lxc/{}/resize", self.node_name, vmid);
        let data = self.put_form(&path, &[("disk", disk), ("size", size)]).await?;
        let upid = data.as_str().unwrap_or("ok").to_string();
        Ok(upid)
    }

    /// Move an LXC container's volume to a different storage pool.
    /// `volume` is the disk id ("rootfs", "mp0", ...). `target_storage`
    /// is the storage id (e.g. "local-zfs", "ceph-pool"). `delete` =
    /// true removes the source after a successful copy. PVE handles
    /// the underlying copy method (zfs send/recv, qcow2 dd, etc).
    pub async fn lxc_move_volume(
        &self, vmid: u64, volume: &str, target_storage: &str, delete: bool,
    ) -> Result<String, String> {
        let path = format!("/nodes/{}/lxc/{}/move_volume", self.node_name, vmid);
        let delete_str = if delete { "1" } else { "0" };
        let data = self.post_form(&path, &[
            ("volume", volume),
            ("storage", target_storage),
            ("delete", delete_str),
        ]).await?;
        let upid = data.as_str().unwrap_or("ok").to_string();
        Ok(upid)
    }

    /// List storage pools available on this PVE node — used for the
    /// "Move to..." dropdown in the WolfStack frontend.
    pub async fn list_storages(&self) -> Result<Vec<serde_json::Value>, String> {
        let path = format!("/nodes/{}/storage", self.node_name);
        let data = self.get(&path).await?;
        let arr = data.as_array().cloned().unwrap_or_default();
        Ok(arr)
    }

    /// Read an LXC container's full config — same data `pct config`
    /// would print, parsed by PVE into a JSON object with keys like
    /// `rootfs`, `cores`, `memory`, etc.
    pub async fn lxc_config(&self, vmid: u64) -> Result<serde_json::Value, String> {
        let path = format!("/nodes/{}/lxc/{}/config", self.node_name, vmid);
        self.get(&path).await
    }

    /// Read a QEMU VM's config. Used by the pool driver to verify
    /// a clone task has settled before pushing further config.
    pub async fn qemu_config(&self, vmid: u64) -> Result<serde_json::Value, String> {
        let path = format!("/nodes/{}/qemu/{}/config", self.node_name, vmid);
        self.get(&path).await
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

        // Shared pool (see PVE_CLIENT) with a per-request 10-minute
        // timeout for large uploads. RequestBuilder::timeout overrides
        // the Client default.
        let upload_client = &*PVE_CLIENT;

        // Step 1: Upload the archive to storage via multipart form
        //   POST /api2/json/nodes/{node}/storage/{storage}/upload
        let upload_url = format!(
            "{}/api2/json/nodes/{}/storage/{}/upload",
            self.base_url, self.node_name, storage_id
        );


        let part = reqwest::multipart::Part::bytes(archive_bytes)
            .file_name(file_name.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| format!("MIME error: {}", e))?;

        let form = reqwest::multipart::Form::new()
            .text("content", "vztmpl")
            .part("filename", part);

        let resp = upload_client.post(&upload_url)
            .header("Authorization", self.auth_header())
            .timeout(Duration::from_secs(600))
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("PVE upload failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE upload failed ({}): {}", status.as_u16(), body));
        }
        // Drain the success body too so the socket returns to the
        // pool. PVE's upload response is a tiny JSON ack we don't
        // need to parse.
        let _ = resp.bytes().await;


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
        // Drain the success body → socket back to pool.
        let _ = resp.bytes().await;

        let msg = format!("Container '{}' restored as VMID {} on {} (storage: {})",
            new_name, new_vmid, self.node_name, restore_storage);

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

    // ─── Pool-driver support: VM clone, cloud-init, lifecycle ──
    //
    // The methods below back `pools::proxmox_driver`. They mirror
    // PVE's documented REST endpoints under
    // `/nodes/{node}/qemu/...`. Source for each call is cited
    // inline.

    /// List QEMU VMs that are templates (template=1). Used to
    /// populate the Pool wizard's template dropdown.
    /// Source: GET /nodes/{node}/qemu — returns array; each row
    /// has `template` = 0/1, `name`, `vmid`.
    pub async fn list_qemu_templates(&self) -> Result<Vec<PveTemplate>, String> {
        let data = self.get(&format!("/nodes/{}/qemu", self.node_name)).await?;
        let arr = data.as_array().ok_or("Expected array from /qemu")?;
        let mut out = Vec::new();
        for v in arr {
            // PVE returns template as 0/1 (number). Some older
            // builds use a stringified "1". Accept both.
            let is_template = v.get("template")
                .and_then(|x| x.as_u64()).map(|n| n == 1).unwrap_or_else(|| {
                    v.get("template").and_then(|x| x.as_str())
                        .map(|s| s == "1").unwrap_or(false)
                });
            if !is_template { continue; }
            let vmid = v.get("vmid").and_then(|x| x.as_u64()).unwrap_or(0);
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(PveTemplate {
                vmid,
                name,
                node: self.node_name.clone(),
            });
        }
        Ok(out)
    }

    /// Allocate the next available VMID across the cluster.
    /// Source: GET /cluster/nextid — returns a stringified integer.
    pub async fn next_vmid(&self) -> Result<u64, String> {
        let data = self.get("/cluster/nextid").await?;
        if let Some(s) = data.as_str() {
            s.trim_matches('"').parse::<u64>()
                .map_err(|e| format!("bad VMID '{}': {}", s, e))
        } else if let Some(n) = data.as_u64() {
            Ok(n)
        } else {
            Err(format!("unexpected /cluster/nextid response: {}", data))
        }
    }

    /// Clone a template VM into a new VM. Returns the UPID — caller
    /// can poll task status for completion (we don't here; subsequent
    /// config calls retry on 4xx until the clone settles).
    /// Source: POST /nodes/{node}/qemu/{templateid}/clone with form
    /// fields newid, name, full=1.
    pub async fn clone_template(&self, template_vmid: u64, new_vmid: u64, new_name: &str)
        -> Result<String, String>
    {
        let path = format!("/nodes/{}/qemu/{}/clone", self.node_name, template_vmid);
        let new_vmid_s = new_vmid.to_string();
        let data = self.post_form(&path, &[
            ("newid", new_vmid_s.as_str()),
            ("name", new_name),
            ("full", "1"),
        ]).await?;
        Ok(data.as_str().unwrap_or("ok").to_string())
    }

    /// Find a storage on this node that has `snippets` in its
    /// content list. We need one to host the cicustom user-data
    /// file. Returns the storage id (e.g. "local") or an error
    /// describing how to enable snippets.
    /// Source: GET /nodes/{node}/storage — each row has a
    /// comma-separated `content` field.
    pub async fn find_snippets_storage(&self) -> Result<String, String> {
        let storages = self.list_storages().await?;
        for s in &storages {
            let content = s.get("content").and_then(|x| x.as_str()).unwrap_or("");
            // PVE returns "iso,vztmpl,backup,snippets" etc.
            if content.split(',').any(|t| t.trim() == "snippets") {
                if let Some(id) = s.get("storage").and_then(|x| x.as_str()) {
                    return Ok(id.to_string());
                }
            }
        }
        Err("No PVE storage on this node has snippets enabled. \
            Enable it via Datacenter → Storage → <select> → Edit → \
            Content (tick \"Snippets\"), or run \
            `pvesm set local --content snippets,vztmpl,backup,iso,images`."
            .into())
    }

    /// Upload a cloud-init user-data file to the chosen snippets
    /// storage. Returns the storage:snippets/<filename> volume id
    /// the cicustom field expects.
    /// Source: POST /nodes/{node}/storage/{storage}/upload —
    /// multipart with `content=snippets` + `filename` part.
    pub async fn upload_snippet(&self, storage: &str, filename: &str, body: &str)
        -> Result<String, String>
    {
        // Filename must be safe — caller passes "userdata-<vmid>.yaml"
        // which we control. Defence in depth: reject anything with
        // path separators or non-printable bytes.
        if filename.contains('/') || filename.contains('\\')
            || filename.chars().any(|c| !c.is_ascii_graphic())
        {
            return Err(format!("unsafe snippet filename: {}", filename));
        }
        let url = format!("{}/api2/json/nodes/{}/storage/{}/upload",
            self.base_url, self.node_name, storage);
        let part = reqwest::multipart::Part::bytes(body.as_bytes().to_vec())
            .file_name(filename.to_string())
            .mime_str("text/plain")
            .map_err(|e| format!("MIME: {}", e))?;
        let form = reqwest::multipart::Form::new()
            .text("content", "snippets")
            .part("filename", part);
        let resp = self.client.post(&url)
            .header("Authorization", self.auth_header())
            .timeout(Duration::from_secs(60))
            .multipart(form)
            .send().await
            .map_err(|e| format!("PVE snippet upload: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE upload {} {}: {}", status.as_u16(), filename, body));
        }
        let _ = resp.bytes().await;
        // Volume id format PVE expects in cicustom: "<storage>:snippets/<filename>"
        Ok(format!("{}:snippets/{}", storage, filename))
    }

    /// Delete a single snippet file from PVE storage. Used during
    /// pool destroy to clean up the cloud-init user-data files —
    /// they contain plaintext bootstrap_token / federation_token /
    /// pool_secret and must not outlive the pool.
    /// Source: DELETE /nodes/{node}/storage/{storage}/content/{volid}
    /// where volid is `<storage>:snippets/<filename>`.
    pub async fn delete_snippet(&self, storage: &str, filename: &str) -> Result<(), String> {
        if filename.contains('/') || filename.contains('\\') {
            return Err(format!("unsafe snippet filename: {}", filename));
        }
        let volid = format!("{}:snippets/{}", storage, filename);
        // urlencode the volid because it contains a colon and slash.
        let encoded = volid.replace(':', "%3A").replace('/', "%2F");
        let path = format!("/nodes/{}/storage/{}/content/{}",
            self.node_name, storage, encoded);
        let url = format!("{}/api2/json{}", self.base_url, path);
        let resp = self.client.delete(&url)
            .header("Authorization", self.auth_header())
            .send().await
            .map_err(|e| format!("PVE delete snippet: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            // 404 is fine — file already gone.
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(());
            }
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE delete snippet {} {}: {}", status.as_u16(), filename, body));
        }
        let _ = resp.bytes().await;
        Ok(())
    }

    /// Push config keys onto a VM (cores, memory, cicustom,
    /// ipconfig0, agent, scsihw, etc). Caller assembles the pairs.
    /// Source: PUT /nodes/{node}/qemu/{vmid}/config — form fields.
    /// Note PVE accepts both PUT and POST for this endpoint; we
    /// use PUT to match the documented "set" shape.
    pub async fn set_vm_config(&self, vmid: u64, kv: &[(&str, &str)])
        -> Result<(), String>
    {
        let path = format!("/nodes/{}/qemu/{}/config", self.node_name, vmid);
        // The config endpoint's response is null (no data) on
        // success; put_form already handles non-success.
        self.put_form(&path, kv).await?;
        Ok(())
    }

    /// Start a VM.
    /// Source: POST /nodes/{node}/qemu/{vmid}/status/start.
    pub async fn start_vm(&self, vmid: u64) -> Result<String, String> {
        let path = format!("/nodes/{}/qemu/{}/status/start", self.node_name, vmid);
        let data = self.post(&path).await?;
        Ok(data.as_str().unwrap_or("ok").to_string())
    }

    /// Stop + delete a VM. PVE accepts `purge=1` to also remove
    /// disk volumes.
    /// Source: DELETE /nodes/{node}/qemu/{vmid}?purge=1.
    pub async fn delete_vm(&self, vmid: u64) -> Result<String, String> {
        let path = format!("/nodes/{}/qemu/{}?purge=1&destroy-unreferenced-disks=1",
            self.node_name, vmid);
        let url = format!("{}/api2/json{}", self.base_url, path);
        let resp = self.client.delete(&url)
            .header("Authorization", self.auth_header())
            .send().await
            .map_err(|e| format!("PVE delete: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("PVE delete {} {}: {}", status.as_u16(), vmid, body));
        }
        let json: serde_json::Value = resp.json().await
            .map_err(|e| format!("PVE delete JSON: {}", e))?;
        Ok(json.get("data").and_then(|d| d.as_str()).unwrap_or("ok").to_string())
    }

    /// Get a VM's IPv4 address via the guest agent. Requires the
    /// VM image to have qemu-guest-agent installed + the VM
    /// configured with `agent: 1`.
    /// Source: GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces
    /// returns { result: [ { name, hardware-address, ip-addresses: [{ip-address, ip-address-type}] } ] }.
    pub async fn vm_guest_ipv4(&self, vmid: u64) -> Result<Option<String>, String> {
        let path = format!("/nodes/{}/qemu/{}/agent/network-get-interfaces",
            self.node_name, vmid);
        // The agent call may return 5xx if the agent isn't yet
        // running — caller treats that as "not ready", not a fault.
        let data = match self.get(&path).await {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        let result = match data.get("result").and_then(|x| x.as_array()) {
            Some(r) => r,
            None => return Ok(None),
        };
        for iface in result {
            // Skip loopback interface — name starts with "lo".
            if iface.get("name").and_then(|x| x.as_str())
                .map(|s| s.starts_with("lo")).unwrap_or(false) {
                continue;
            }
            if let Some(ips) = iface.get("ip-addresses").and_then(|x| x.as_array()) {
                for ip in ips {
                    let kind = ip.get("ip-address-type").and_then(|x| x.as_str()).unwrap_or("");
                    if kind != "ipv4" { continue; }
                    let addr = ip.get("ip-address").and_then(|x| x.as_str()).unwrap_or("");
                    if addr.starts_with("127.") || addr.starts_with("169.254.")
                        || addr.starts_with("10.42.") || addr.is_empty() {
                        continue;
                    }
                    return Ok(Some(addr.to_string()));
                }
            }
        }
        Ok(None)
    }
}

/// Lightweight template descriptor returned by `list_qemu_templates`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PveTemplate {
    pub vmid: u64,
    pub name: String,
    pub node: String,
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
    // Run all PVE API calls concurrently for speed on remote servers
    let client = PveClient::new(address, port, token, fingerprint, node_name);

    let (status_res, guests_res, cluster_name_res) = tokio::join!(
        client.get_node_status(),
        client.list_all_guests(),
        client.get_cluster_name(),
    );

    let status = match status_res {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Proxmox poll failed for {} ({}): get_node_status error: {}", node_name, address, e);
            return Err(e);
        }
    };

    let guests = match guests_res {
        Ok(g) => g,
        Err(e) => {
             tracing::warn!("Proxmox poll warning for {} ({}): list_all_guests failed: {}", node_name, address, e);
             Vec::new()
        }
    };

    let cluster_name = cluster_name_res.ok();

    let lxc_count = guests.iter().filter(|g| g.guest_type == "lxc").count() as u32;
    let vm_count = guests.iter().filter(|g| g.guest_type == "qemu").count() as u32;

    Ok((status, lxc_count, vm_count, cluster_name, guests))
}
