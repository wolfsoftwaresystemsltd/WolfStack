// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Native (libvirt / QEMU) pool driver.
//!
//! Provisioning flow per VM:
//!
//!   1. Generate cloud-init NoCloud seed ISO
//!      (`<pool-base>/<vm_name>-seed.iso`) via `cloud-localds`.
//!      Seed contains user-data (from `pools::cloud_init`) +
//!      meta-data (instance-id matching the hostname).
//!   2. Build a `vms::VmConfig` with:
//!        * `import_image = spec.template` (path to a base qcow2)
//!        * `iso_path = seed.iso` (NoCloud cidata)
//!        * cpus / memory / disk_size_gb from spec
//!   3. Call `VmManager::create_vm` — handles libvirt/QEMU split
//!      and disk import + EFI vars (if applicable) for us.
//!   4. Call `VmManager::start_vm`.
//!
//! `spec.template` for native is an absolute path to a base qcow2
//! image (e.g. `/var/lib/wolfstack/templates/ubuntu-22.qcow2`).
//!
//! `backend_ref` is informational here — there's only one host
//! (this one) the native driver provisions on. We accept any
//! string and ignore it (UI passes the WolfStack node id to be
//! consistent with the Proxmox flow).
//!
//! Dep: `cloud-localds` from cloud-utils. setup.sh installs it as
//! part of the pool prerequisites; provision returns a clear error
//! if it's missing rather than fabricating a seed ISO.

use super::{
    BootstrapMaterial, Pool, PoolSpec, VmHandle,
    cloud_init::{Bootstrap, Role, build as build_cloud_init},
};
use crate::vms::manager::{VmConfig, VmManager};

/// Per-pool directory naming. Stable across provision and destroy
/// because both can reach the bootstrap_token (in the persisted
/// pool record). Avoids cross-pool file deletion when two pools
/// happen to have a VM with the same hostname.
fn pool_dir_for(bootstrap_token: &str) -> String {
    format!("{}/ns-{}", POOLS_BASE,
        &bootstrap_token[..16.min(bootstrap_token.len())])
}

const POOLS_BASE: &str = "/var/lib/wolfstack/pools";
const TEMPLATES_DIR: &str = "/var/lib/wolfstack/templates";

/// PATH lookup for an executable. Returns true iff `name` is on
/// $PATH and is an executable file. Avoids pulling in the `which`
/// crate just for one call.
fn command_exists(name: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.permissions().mode() & 0o111 != 0 { return true; }
                }
            }
            #[cfg(not(unix))]
            { return true; }
        }
    }
    false
}

use super::safe_hostname_prefix as safe_prefix;

/// Build the NoCloud seed ISO for a single VM. Returns the
/// absolute path to the generated ISO. Uses `cloud-localds`
/// (from cloud-utils) which is the canonical tool.
///
/// We pass an explicit meta-data file with `instance-id` and
/// `local-hostname`. Without one, cloud-localds writes an empty
/// meta-data and Ubuntu cloud images regenerate the instance-id
/// on every boot — which makes cloud-init think it's a NEW
/// instance every reboot and re-runs `runcmd` (re-running setup.sh
/// and re-POSTing the self-register callback). That's bad. Pinning
/// instance-id to the hostname prevents the re-run.
fn build_seed_iso(pool_id: &str, hostname: &str, user_data: &str) -> Result<String, String> {
    let dir = format!("{}/{}", POOLS_BASE, pool_id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir, e))?;
    let user_data_path = format!("{}/{}-userdata.yaml", dir, hostname);
    let meta_data_path = format!("{}/{}-metadata.yaml", dir, hostname);
    let seed_iso_path = format!("{}/{}-seed.iso", dir, hostname);

    std::fs::write(&user_data_path, user_data)
        .map_err(|e| format!("write user-data: {}", e))?;
    let meta = format!(
        "instance-id: pool-{}\nlocal-hostname: {}\n",
        hostname, hostname,
    );
    std::fs::write(&meta_data_path, &meta)
        .map_err(|e| format!("write meta-data: {}", e))?;

    if !command_exists("cloud-localds") {
        return Err("cloud-localds not installed. Install cloud-utils \
            (apt: cloud-image-utils / cloud-utils, dnf: cloud-utils) \
            on this WolfStack host before provisioning native pools.".into());
    }
    // Form: cloud-localds [seed.iso] [user-data] [meta-data]
    let out = std::process::Command::new("cloud-localds")
        .arg(&seed_iso_path)
        .arg(&user_data_path)
        .arg(&meta_data_path)
        .output()
        .map_err(|e| format!("cloud-localds spawn: {}", e))?;
    if !out.status.success() {
        return Err(format!("cloud-localds failed: {}",
            String::from_utf8_lossy(&out.stderr)));
    }
    // user-data file holds the leader's federation token (if
    // leader) and the shared cluster secret. Tighten perms.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&user_data_path,
            std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&meta_data_path,
            std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&seed_iso_path,
            std::fs::Permissions::from_mode(0o600));
    }
    Ok(seed_iso_path)
}

/// Validate that a template path is under `TEMPLATES_DIR`. Resolves
/// symlinks via canonicalize so a symlink under templates/ pointing
/// at /etc/shadow can't slip past. Returns the canonicalised path.
fn validate_template_path(p: &str) -> Result<std::path::PathBuf, String> {
    let raw = std::path::Path::new(p);
    let canonical = std::fs::canonicalize(raw)
        .map_err(|e| format!("template '{}' not readable: {}", p, e))?;
    let templates_canonical = std::fs::canonicalize(TEMPLATES_DIR)
        .map_err(|e| format!("templates dir '{}' not accessible: {} \
            — create it: `sudo mkdir -p {}`", TEMPLATES_DIR, e, TEMPLATES_DIR))?;
    if !canonical.starts_with(&templates_canonical) {
        return Err(format!(
            "template path must be under '{}' (resolved to '{}')",
            TEMPLATES_DIR, canonical.display(),
        ));
    }
    // Sanity: only accept disk image extensions.
    let ext_ok = canonical.extension().and_then(|s| s.to_str())
        .map(|s| matches!(s.to_lowercase().as_str(), "qcow2" | "img" | "raw"))
        .unwrap_or(false);
    if !ext_ok {
        return Err("template must be a .qcow2 / .img / .raw file".into());
    }
    Ok(canonical)
}

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

    let template_path = validate_template_path(spec.template.trim())?
        .to_string_lossy().to_string();

    // Derive the per-pool directory from the bootstrap_token —
    // stable across provision and destroy. `pool_dir_for` is the
    // single source of truth so destroy() reaches the same dir.
    let pool_dir_full = pool_dir_for(&bootstrap.bootstrap_token);
    let pool_dir_id = pool_dir_full.rsplit('/').next().unwrap_or("").to_string();

    let prefix_src = if spec.hostname_prefix.is_empty() {
        spec.tenant_name.as_str()
    } else {
        spec.hostname_prefix.as_str()
    };
    let prefix = safe_prefix(prefix_src);

    let manager = VmManager::new();
    let mut handles: Vec<VmHandle> = Vec::with_capacity(spec.vm_count as usize);

    for i in 0..spec.vm_count {
        let is_leader = i == 0;
        let role = if is_leader { Role::Leader } else { Role::Follower };
        let hostname = format!("{}-{}", prefix, i + 1);

        // 1. Build cloud-init user-data
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

        // 2. Generate seed ISO
        let seed_iso = build_seed_iso(&pool_dir_id, &hostname, &user_data)
            .map_err(|e| format!("VM {}: {}", i + 1, e))?;

        // 3. VmConfig + create
        let mut vc = VmConfig::new(
            hostname.clone(),
            spec.vcpu,
            spec.memory_mb,
            if spec.disk_gb > 0 { spec.disk_gb } else { 20 },
        );
        vc.import_image = Some(template_path.clone());
        vc.iso_path = Some(seed_iso);
        vc.auto_start = false;

        if let Err(e) = manager.create_vm(vc) {
            return Err(format!(
                "VM {}/{} ('{}'): create_vm failed: {} — {} VMs already created.",
                i + 1, spec.vm_count, hostname, e, handles.len(),
            ));
        }

        // 4. Start it
        if let Err(e) = manager.start_vm(&hostname) {
            return Err(format!("VM {} ('{}'): start_vm failed: {}",
                i + 1, hostname, e));
        }

        handles.push(VmHandle {
            backend_id: hostname.clone(),  // VMs are addressed by name on native
            hostname,
            join_token_enc: crate::xo::obfuscate_token(&bootstrap.join_tokens[i as usize]),
            is_leader,
            ipv4: String::new(),
            joined: false,
        });
    }

    Ok(handles)
}

pub async fn destroy(pool: &Pool) -> Result<(), String> {
    if pool.vms.is_empty() {
        // Still try to remove the pool dir if it exists — provision
        // may have failed before any VM landed.
    }
    let manager = VmManager::new();
    let mut errors: Vec<String> = Vec::new();
    for vm in &pool.vms {
        if let Err(e) = manager.stop_vm(&vm.backend_id, true) {
            if !e.to_lowercase().contains("not found") && !e.to_lowercase().contains("doesn't exist") {
                errors.push(format!("VM {}: stop: {}", vm.hostname, e));
            }
        }
        if let Err(e) = manager.delete_vm(&vm.backend_id) {
            if !e.to_lowercase().contains("not found") && !e.to_lowercase().contains("doesn't exist") {
                errors.push(format!("VM {}: delete: {}", vm.hostname, e));
            }
        }
    }
    // Wipe the per-pool artefact directory wholesale. It contains
    // user-data files with plaintext bootstrap_token / pool_secret /
    // federation_token / join_tokens — must not outlive the pool.
    // remove_dir_all is fine: the directory holds only this pool's
    // files (named per `pool_dir_for(bootstrap_token)`).
    let bootstrap_token = crate::xo::deobfuscate_token(&pool.bootstrap_token_enc);
    if !bootstrap_token.is_empty() {
        let dir = pool_dir_for(&bootstrap_token);
        if std::path::Path::new(&dir).exists() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                errors.push(format!("pool dir cleanup ({}): {}", dir, e));
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

pub async fn observe_ips(vms: &[VmHandle]) -> Result<Vec<Option<String>>, String> {
    // For native VMs, IP discovery options:
    //   * libvirt:    `virsh domifaddr <name>` — works if libvirt
    //                 manages DHCP (default network) or if guest
    //                 has the qemu-guest-agent.
    //   * non-libvirt: ARP scan of the host bridge — flakier.
    //
    // We try `virsh domifaddr` first; if that fails or returns
    // nothing, we leave the IP blank for that VM. The orchestrator
    // re-polls every 30 s, so transient empties are fine.
    let mut out: Vec<Option<String>> = Vec::with_capacity(vms.len());
    for vm in vms {
        out.push(virsh_domifaddr(&vm.backend_id));
    }
    Ok(out)
}

fn virsh_domifaddr(domain: &str) -> Option<String> {
    let raw = std::process::Command::new("virsh")
        .arg("domifaddr").arg(domain)
        .arg("--source").arg("agent")
        .output().ok()?;
    let s = String::from_utf8_lossy(&raw.stdout);
    // Output:
    //   Name       MAC address          Protocol     Address
    //   -----------------------------------------------------
    //   vnet0      52:54:00:aa:bb:cc    ipv4         192.0.2.10/24
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        if parts[2] != "ipv4" { continue; }
        let addr = parts[3].split('/').next()?.to_string();
        if addr.starts_with("127.") || addr.starts_with("169.254.")
            || addr.starts_with("10.42.") || addr.is_empty() {
            continue;
        }
        return Some(addr);
    }
    // Fallback: --source lease (DHCP lease table from libvirt).
    let raw = std::process::Command::new("virsh")
        .arg("domifaddr").arg(domain)
        .arg("--source").arg("lease")
        .output().ok()?;
    let s = String::from_utf8_lossy(&raw.stdout);
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        if parts[2] != "ipv4" { continue; }
        let addr = parts[3].split('/').next()?.to_string();
        if addr.starts_with("127.") || addr.starts_with("169.254.")
            || addr.starts_with("10.42.") || addr.is_empty() {
            continue;
        }
        return Some(addr);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_prefix_strips_metachars() {
        assert_eq!(safe_prefix("Customer A!"), "CustomerA");
        assert_eq!(safe_prefix(""), "wolfstack");
    }
}
