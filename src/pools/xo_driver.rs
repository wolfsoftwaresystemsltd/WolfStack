// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! XO/XCP-ng pool driver.
//!
//! Wraps `xo::XoClient` to fan out N `create_vm` calls with cloud-init
//! payloads from `pools::cloud_init`. Stateless except for a fresh
//! `XoStore::load` per call — the store is small (one row per
//! registered XO instance) and we'd rather re-read than risk a stale
//! cache.

use super::{
    BootstrapMaterial, PoolSpec, VmHandle,
    cloud_init::{Bootstrap, Role, build as build_cloud_init},
};
use crate::xo::{CreateVmRequest, XoClient, XoStore};

fn client_for(backend_ref: &str) -> Result<XoClient, String> {
    let store = XoStore::load();
    let pool = store.get(backend_ref)
        .ok_or_else(|| format!("XO instance '{}' not registered. \
            Register it under XO Pools first.", backend_ref))?;
    let token = crate::xo::deobfuscate_token(&pool.token_enc);
    if token.is_empty() {
        return Err("XO instance has no usable token (was it ever registered?)".into());
    }
    Ok(XoClient::new(&pool.url, &token))
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
    let client = client_for(&spec.backend_ref)?;
    let prefix_src = if spec.hostname_prefix.is_empty() {
        spec.tenant_name.as_str()
    } else {
        spec.hostname_prefix.as_str()
    };
    let prefix = safe_prefix(prefix_src);

    let mut handles: Vec<VmHandle> = Vec::with_capacity(spec.vm_count as usize);

    // Sequential create. XO accepts parallel calls but a sequential
    // build keeps failure semantics simple: if VM 3 fails, VMs 1 & 2
    // are recorded as handles and the orchestrator decides whether
    // to tear down or leave them. Parallel would force atomic-or-
    // rollback that XO doesn't offer at the REST layer.
    for i in 0..spec.vm_count {
        let is_leader = i == 0;
        let role = if is_leader { Role::Leader } else { Role::Follower };
        let hostname = format!("{}-{}", prefix, i + 1);
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

        let req = CreateVmRequest {
            template_uuid: spec.template.clone(),
            name: hostname.clone(),
            memory_mb: spec.memory_mb,
            cpus: spec.vcpu,
            user_data,
        };
        match client.create_vm(req).await {
            Ok(uuid) => {
                handles.push(VmHandle {
                    backend_id: uuid,
                    hostname,
                    join_token_enc: crate::xo::obfuscate_token(&bootstrap.join_tokens[i as usize]),
                    is_leader,
                    ipv4: String::new(),
                    joined: false,
                });
            }
            Err(e) => {
                return Err(format!(
                    "XO create_vm failed on VM {}/{} ('{}'): {} — \
                     {} VM(s) already created and may need manual cleanup in XO.",
                    i + 1, spec.vm_count, hostname, e, handles.len(),
                ));
            }
        }

        // Best-effort start. Some XO templates leave the new VM
        // halted; some auto-power. A 4xx here is non-fatal — the
        // operator (or orchestrator) can start it later.
        if let Some(h) = handles.last() {
            let _ = client.vm_action(&h.backend_id, "start").await;
        }
    }

    Ok(handles)
}

pub async fn destroy(vms: &[VmHandle]) -> Result<(), String> {
    if vms.is_empty() { return Ok(()); }
    let store = XoStore::load();
    let instances = store.list();
    if instances.is_empty() {
        return Err("no XO instances registered — can't destroy pool VMs".into());
    }
    let mut errors: Vec<String> = Vec::new();
    for vm in vms {
        let mut found = false;
        for inst in &instances {
            let token = crate::xo::deobfuscate_token(&inst.token_enc);
            if token.is_empty() { continue; }
            let cli = XoClient::new(&inst.url, &token);
            // Three-step teardown: hard_shutdown → poll for halted →
            // delete. The hard_shutdown call returns immediately;
            // XO halts the VM async. Calling delete on a running
            // VM returns 4xx, so we poll up to 30s for power_state.
            match cli.vm_action(&vm.backend_id, "hard_shutdown").await {
                Ok(()) => { found = true; }
                Err(e) => {
                    if e.contains("404") || e.to_lowercase().contains("not found") {
                        // Try the next XO instance — VM isn't here.
                        continue;
                    }
                    // Hard error from this instance — might be
                    // already-halted (200) on some XO versions, or
                    // a real fault. Treat as found and try delete.
                    found = true;
                    tracing::info!("pool {} hard_shutdown returned: {} (continuing to delete)",
                        vm.hostname, e);
                }
            }
            // Poll for power_state=Halted before delete. ~30s budget.
            for _ in 0..15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let halted = cli.list_vms().await.ok()
                    .and_then(|v| v.into_iter().find(|x| x.uuid == vm.backend_id))
                    .map(|x| x.power_state == "Halted")
                    .unwrap_or(false);
                if halted { break; }
            }
            if let Err(e) = cli.delete_vm(&vm.backend_id).await {
                errors.push(format!("VM {}: delete: {}", vm.hostname, e));
            }
            break;
        }
        if !found {
            errors.push(format!("VM {} ({}): not found in any registered XO instance",
                vm.hostname, vm.backend_id));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

pub async fn observe_ips(vms: &[VmHandle]) -> Result<Vec<Option<String>>, String> {
    if vms.is_empty() { return Ok(Vec::new()); }
    let store = XoStore::load();
    let instances = store.list();
    let mut all_vms: Vec<crate::xo::XoVm> = Vec::new();
    for inst in &instances {
        let token = crate::xo::deobfuscate_token(&inst.token_enc);
        if token.is_empty() { continue; }
        let cli = XoClient::new(&inst.url, &token);
        if let Ok(v) = cli.list_vms().await {
            all_vms.extend(v);
        }
    }
    let mut out: Vec<Option<String>> = Vec::with_capacity(vms.len());
    for vm in vms {
        let ip = all_vms.iter()
            .find(|x| x.uuid == vm.backend_id)
            .and_then(|x| x.ip_addresses.iter()
                // Filter loopback, link-local, and WolfNet 10.42.x.x
                // (those aren't reachable from the SP).
                .find(|s| !s.starts_with("127.")
                    && !s.starts_with("10.42.")
                    && !s.starts_with("169.254.")
                    && !s.is_empty())
                .cloned());
        out.push(ip);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_prefix_strips_metachars() {
        assert_eq!(safe_prefix("Customer A!"), "CustomerA");
        assert_eq!(safe_prefix(""), "wolfstack");
        assert_eq!(safe_prefix("---"), "---");
        let long = "a".repeat(80);
        assert_eq!(safe_prefix(&long).len(), 58);
    }
}
