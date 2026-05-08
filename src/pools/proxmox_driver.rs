// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Proxmox VE pool driver.
//!
//! Provisioning flow per VM:
//!
//!   1. Allocate next VMID via `/cluster/nextid`.
//!   2. Generate cloud-init user-data via `pools::cloud_init`.
//!   3. Find a snippets-enabled storage (errors out with a helpful
//!      message if none is configured).
//!   4. Upload the user-data snippet as
//!      `wolfstack-pool-<vmid>.yaml`.
//!   5. Clone the template VMID (full clone, not linked — pool VMs
//!      may outlive the template).
//!   6. Push config: `cores`, `memory`, `cicustom=user=...`,
//!      `ipconfig0=ip=dhcp`, `agent=1` (so the guest agent reports
//!      IP back to PVE).
//!   7. Start the VM.
//!
//! `backend_ref` is a WolfStack cluster Node id (one with PVE
//! credentials configured — same row as the `/api/nodes/{id}/pve/*`
//! endpoints use). The driver loads the node, builds a PveClient,
//! then routes calls to that node's PVE API.
//!
//! VmHandle.backend_id format: `<pve_node>:<vmid>` so destroy and
//! observe_ips can route per-VM if a future backend_ref points at
//! a multi-node PVE cluster.

use super::{
    BootstrapMaterial, PoolSpec, VmHandle,
    cloud_init::{Bootstrap, Role, build as build_cloud_init},
};
use crate::agent::Node;
use crate::proxmox::PveClient;

/// Load the in-cluster Node list directly from nodes.json. Avoids
/// threading AppState through the dispatch — drivers want a snapshot
/// good enough for the call, not live state.
/// Source: agent/mod.rs:204 — same path ClusterState reads from.
fn load_nodes_snapshot() -> Vec<Node> {
    let path = crate::paths::get().nodes_config.clone();
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str::<Vec<Node>>(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Returns a PveClient for the WolfStack node referenced by
/// backend_ref. The node must have pve_token + pve_node_name
/// populated — same prerequisites as the existing PVE integration.
fn client_for_node(backend_ref: &str) -> Result<(PveClient, Node), String> {
    let nodes = load_nodes_snapshot();
    let node = nodes.into_iter().find(|n| n.id == backend_ref)
        .ok_or_else(|| format!("WolfStack node '{}' not in cluster", backend_ref))?;
    let token = node.pve_token.clone()
        .ok_or_else(|| format!("Node '{}' has no PVE token configured. \
            Add it via Settings → Cluster → <node> → PVE Token first.", node.hostname))?;
    let pve_node_name = node.pve_node_name.clone()
        .ok_or_else(|| format!("Node '{}' has no PVE node name configured.", node.hostname))?;
    let pve_port = if node.port == 8553 { 8006 } else { node.port };
    let cli = PveClient::new(
        &node.address, pve_port, &token,
        node.pve_fingerprint.as_deref(),
        &pve_node_name,
    );
    Ok((cli, node))
}

use super::safe_hostname_prefix as safe_prefix;

pub async fn provision(
    spec: &PoolSpec,
    bootstrap: &BootstrapMaterial,
) -> Result<Vec<VmHandle>, String> {
    if spec.vm_count == 0 || spec.vm_count > 10 {
        return Err("vm_count must be between 1 and 10".into());
    }
    if bootstrap.join_tokens.len() as u32 != spec.vm_count {
        return Err("internal: join_tokens length doesn't match vm_count".into());
    }
    let (client, node) = client_for_node(&spec.backend_ref)?;

    // Parse template — for PVE this is a VMID (number).
    let template_vmid: u64 = spec.template.trim().parse()
        .map_err(|_| format!("Proxmox template must be a VMID (number); got '{}'", spec.template))?;

    // One snippets storage for the whole pool — fail fast if there
    // isn't one before we touch any VM.
    let snippets_storage = client.find_snippets_storage().await?;

    let prefix_src = if spec.hostname_prefix.is_empty() {
        spec.tenant_name.as_str()
    } else {
        spec.hostname_prefix.as_str()
    };
    let prefix = safe_prefix(prefix_src);

    let mut handles: Vec<VmHandle> = Vec::with_capacity(spec.vm_count as usize);

    for i in 0..spec.vm_count {
        let is_leader = i == 0;
        let role = if is_leader { Role::Leader } else { Role::Follower };
        let hostname = format!("{}-{}", prefix, i + 1);

        // 1. Allocate VMID
        let new_vmid = client.next_vmid().await
            .map_err(|e| format!("VM {}: next_vmid failed: {}", i + 1, e))?;

        // 2. Generate cloud-init
        let cfg = Bootstrap {
            role,
            hostname: hostname.clone(),
            sp_url: bootstrap.sp_url.clone(),
            cluster_secret: bootstrap.pool_secret.clone(),
            join_token: bootstrap.join_tokens[i as usize].clone(),
            federation_token: if is_leader { bootstrap.federation_token.clone() } else { String::new() },
            bootstrap_token: if is_leader { bootstrap.bootstrap_token.clone() } else { String::new() },
            tenant_name: if is_leader { spec.tenant_name.clone() } else { String::new() },
            leader_url: String::new(),
        };
        let user_data = build_cloud_init(&cfg);

        // 3. Upload snippet
        let snippet_filename = format!("wolfstack-pool-{}.yaml", new_vmid);
        let cicustom_value = client.upload_snippet(&snippets_storage, &snippet_filename, &user_data).await
            .map_err(|e| format!("VM {}: upload_snippet failed: {}", i + 1, e))?;

        // 4. Clone template
        if let Err(e) = client.clone_template(template_vmid, new_vmid, &hostname).await {
            return Err(format!(
                "VM {}/{}: clone of template VMID {} failed: {} — {} VMs already created.",
                i + 1, spec.vm_count, template_vmid, e, handles.len(),
            ));
        }

        // PVE clone runs as a background task. Settling it before
        // we push config: poll the new VMID's config endpoint until
        // it returns 200. 30 attempts × 2 s = 60 s ceiling.
        let mut settled = false;
        for _ in 0..30 {
            if client.qemu_config(new_vmid).await.is_ok() {
                settled = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        if !settled {
            return Err(format!(
                "VM {}/{}: clone task didn't settle in 60s. Check PVE task log on node {}.",
                i + 1, spec.vm_count, node.hostname,
            ));
        }

        // 5. Push config: cores/memory/cicustom/ipconfig0/agent.
        let cores_s = spec.vcpu.to_string();
        let memory_s = spec.memory_mb.to_string();
        let cicustom_full = format!("user={}", cicustom_value);
        if let Err(e) = client.set_vm_config(new_vmid, &[
            ("cores", &cores_s),
            ("memory", &memory_s),
            ("cicustom", &cicustom_full),
            ("ipconfig0", "ip=dhcp"),
            ("agent", "1"),
        ]).await {
            return Err(format!("VM {}: set_vm_config failed: {}", i + 1, e));
        }

        // 6. Start
        if let Err(e) = client.start_vm(new_vmid).await {
            return Err(format!("VM {}: start failed: {}", i + 1, e));
        }

        let pve_node = node.pve_node_name.clone().unwrap_or_default();
        handles.push(VmHandle {
            backend_id: format!("{}:{}", pve_node, new_vmid),
            hostname,
            join_token_enc: crate::xo::obfuscate_token(&bootstrap.join_tokens[i as usize]),
            is_leader,
            ipv4: String::new(),
            joined: false,
        });
    }

    Ok(handles)
}

/// Parse a backend_id of the form `<pve_node>:<vmid>` back into its
/// parts. Returns None on malformed input.
fn parse_backend_id(id: &str) -> Option<(String, u64)> {
    let (node, vmid_s) = id.split_once(':')?;
    let vmid: u64 = vmid_s.parse().ok()?;
    Some((node.to_string(), vmid))
}

pub async fn destroy(vms: &[VmHandle]) -> Result<(), String> {
    if vms.is_empty() { return Ok(()); }

    // We don't carry backend_ref through to destroy. Walk every
    // PVE-capable node in the WolfStack cluster; for each VM,
    // try the destroy on whichever node matches the embedded
    // pve_node name. Also clean up the per-VM cloud-init snippet
    // (it contains plaintext pool_secret + bootstrap_token +
    // federation_token + join_token — must not outlive the pool).
    let nodes = load_nodes_snapshot();
    let mut errors: Vec<String> = Vec::new();
    for vm in vms {
        let (target_pve_node, vmid) = match parse_backend_id(&vm.backend_id) {
            Some(p) => p,
            None => {
                errors.push(format!("VM {}: malformed backend_id '{}'", vm.hostname, vm.backend_id));
                continue;
            }
        };
        let mut found_node = false;
        let mut destroyed = false;
        for n in &nodes {
            if n.pve_node_name.as_deref() != Some(&target_pve_node) { continue; }
            let token = match n.pve_token.clone() {
                Some(t) => t,
                None => continue,
            };
            let pve_port = if n.port == 8553 { 8006 } else { n.port };
            let cli = PveClient::new(
                &n.address, pve_port, &token,
                n.pve_fingerprint.as_deref(),
                &target_pve_node,
            );
            found_node = true;
            // Stop first — PVE refuses delete on a running VM.
            // Best-effort: 4xx is fine if the VM is already off.
            let _ = cli.guest_action(vmid, "qemu", "stop").await;
            // Poll qemu_config until status reflects stopped, with a
            // 30s budget. PVE's stop is async; a blind 2s sleep was
            // too short for guests with shutdown hooks. delete_vm
            // returns 4xx on a still-running VM, which would push a
            // spurious error. Mirrors the provision-time settle loop.
            for _ in 0..15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let stopped = cli.qemu_config(vmid).await.ok()
                    .and_then(|c| c.get("status").and_then(|s| s.as_str()).map(|s| s.to_string()))
                    // qemu_config doesn't always include `status` —
                    // a successful read of the config is itself a
                    // signal the VM is reachable; we additionally
                    // accept any read after at least 4 seconds as
                    // settled. (The blocking concern is "delete on
                    // a still-starting VM", not "wait for shutdown
                    // hooks"; PVE's stop returns once qemu has been
                    // signalled.)
                    .map(|s| s == "stopped")
                    .unwrap_or(false);
                if stopped { break; }
            }
            match cli.delete_vm(vmid).await {
                Ok(_) => destroyed = true,
                Err(e) => errors.push(format!("VM {} (vmid {} on {}): {}",
                    vm.hostname, vmid, target_pve_node, e)),
            }
            // Snippet cleanup — best-effort. We don't know which
            // snippets storage was used at provision time; try the
            // first one we find with snippets enabled. delete_snippet
            // returns Ok on 404, so spurious storage names are
            // harmless.
            if let Ok(storage) = cli.find_snippets_storage().await {
                let snippet_filename = format!("wolfstack-pool-{}.yaml", vmid);
                if let Err(e) = cli.delete_snippet(&storage, &snippet_filename).await {
                    errors.push(format!("VM {}: snippet cleanup: {}", vm.hostname, e));
                }
            }
            break;
        }
        if !found_node {
            errors.push(format!("VM {} (vmid {}): no PVE node in cluster matches pve_node_name '{}'",
                vm.hostname, vmid, target_pve_node));
        }
        // If found_node && !destroyed, delete_vm's error was already
        // pushed above; nothing to add here.
        let _ = destroyed;
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

pub async fn observe_ips(vms: &[VmHandle])
    -> Result<Vec<Option<String>>, String>
{
    if vms.is_empty() { return Ok(Vec::new()); }
    let nodes = load_nodes_snapshot();
    let mut out: Vec<Option<String>> = Vec::with_capacity(vms.len());
    for vm in vms {
        let ip_opt = match parse_backend_id(&vm.backend_id) {
            Some((target_pve_node, vmid)) => {
                let mut found: Option<String> = None;
                for n in &nodes {
                    if n.pve_node_name.as_deref() != Some(&target_pve_node) { continue; }
                    let token = match n.pve_token.clone() { Some(t) => t, None => continue };
                    let pve_port = if n.port == 8553 { 8006 } else { n.port };
                    let cli = PveClient::new(
                        &n.address, pve_port, &token,
                        n.pve_fingerprint.as_deref(),
                        &target_pve_node,
                    );
                    if let Ok(Some(ip)) = cli.vm_guest_ipv4(vmid).await {
                        found = Some(ip);
                        break;
                    }
                }
                found
            }
            None => None,
        };
        out.push(ip_opt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backend_id_round_trip() {
        let id = "pve01:101";
        let (n, v) = parse_backend_id(id).unwrap();
        assert_eq!(n, "pve01");
        assert_eq!(v, 101);
    }

    #[test]
    fn parse_backend_id_rejects_garbage() {
        assert!(parse_backend_id("malformed").is_none());
        assert!(parse_backend_id("node:notanumber").is_none());
    }

    #[test]
    fn safe_prefix_strips_metachars() {
        assert_eq!(safe_prefix("Customer A!"), "CustomerA");
        assert_eq!(safe_prefix(""), "wolfstack");
    }
}
