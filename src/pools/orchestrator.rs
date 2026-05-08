// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Pool orchestrator — background task that drives in-flight pools
//! from `provisioning` → `leader_up` → `live`.
//!
//! Runs once every 30 s. Per pool:
//!
//!   * Skips `live`, `failed`, or `destroyed` (terminal).
//!   * Pulls current IPv4 for each VM from the backend driver and
//!     records it in `pool.vms[i].ipv4`. Saves on change.
//!   * For `leader_up` pools (the leader posted to self-register),
//!     for each follower with an IP that hasn't been joined yet,
//!     POSTs `/api/cluster/bootstrap-add` to the leader's URL with
//!     X-WolfStack-Secret = pool_secret.
//!   * Once every follower is `joined`, transitions to `live`.
//!   * Pools without a leader_up after 30 min: → `failed` with
//!     timeout error so the operator sees them.
//!
//! All state changes go through `PoolStore::update` which holds
//! the file mutex, so concurrent orchestrator runs (shouldn't
//! happen — single tokio task — but defensive) don't tear writes.

use crate::pools::{driver_observe_ips, Pool, PoolStore};
use std::time::Duration;

const TICK: Duration = Duration::from_secs(30);
const PROVISION_TIMEOUT_SECS: i64 = 30 * 60; // 30 min from `created_at` to leader_up

/// Spawned by main.rs. Runs forever.
pub async fn run_loop() {
    tracing::info!("pools orchestrator: started (30 s tick)");
    loop {
        tokio::time::sleep(TICK).await;
        if let Err(e) = tick().await {
            tracing::warn!("pools orchestrator tick failed: {}", e);
        }
    }
}

async fn tick() -> Result<(), String> {
    let pools_snapshot = {
        let store = PoolStore::load();
        store.list()
    };
    if pools_snapshot.is_empty() { return Ok(()); }

    for pool in pools_snapshot {
        if matches!(pool.status.as_str(), "live" | "failed" | "destroyed") {
            continue;
        }
        if let Err(e) = drive_pool(&pool).await {
            tracing::warn!("pool {}: orchestrator step failed: {}", pool.id, e);
            // Persist the error message into last_error so the UI
            // shows it. Don't flip to `failed` automatically — the
            // next tick may succeed.
            let mut store = PoolStore::load();
            if let Some(mut latest) = store.get(&pool.id) {
                latest.last_error = e;
                let _ = store.update(latest);
            }
        }
    }
    Ok(())
}

async fn drive_pool(pool: &Pool) -> Result<(), String> {
    // Step 1: refresh IPs from the backend.
    let observed = driver_observe_ips(pool.spec.backend, &pool.vms).await
        .map_err(|e| format!("observe_ips: {}", e))?;
    let mut latest = {
        let store = PoolStore::load();
        store.get(&pool.id).ok_or_else(|| format!("pool {} disappeared", pool.id))?
    };
    let mut changed = false;
    for (i, ip) in observed.iter().enumerate() {
        if let Some(ip) = ip {
            if i < latest.vms.len() && latest.vms[i].ipv4 != *ip {
                latest.vms[i].ipv4 = ip.clone();
                changed = true;
            }
        }
    }
    if changed {
        let mut store = PoolStore::load();
        store.update(latest.clone())?;
    }

    // Step 2: timeout check for stuck-without-leader pools.
    if latest.status == "provisioning" {
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&latest.created_at) {
            let age = chrono::Utc::now().signed_duration_since(created).num_seconds();
            if age > PROVISION_TIMEOUT_SECS {
                latest.status = "failed".into();
                latest.last_error = format!(
                    "Timed out after {}s waiting for leader self-register. \
                     Check leader VM cloud-init logs (/var/log/cloud-init-output.log) \
                     and that this WolfStack's URL ({}) is reachable from the VM.",
                    age, latest.spec.sp_url,
                );
                let mut store = PoolStore::load();
                store.update(latest)?;
                return Ok(());
            }
        }
    }

    // Step 3: if leader has come up, drive follower joins.
    if latest.status == "leader_up" {
        let pool_secret = crate::xo::deobfuscate_token(&latest.pool_secret_enc);
        let leader_url = latest.leader_url.clone();
        if leader_url.is_empty() || pool_secret.is_empty() {
            return Err("leader_up pool missing leader_url or pool_secret".into());
        }
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("HTTP client: {}", e))?;

        let mut all_joined = true;
        for i in 0..latest.vms.len() {
            let vm = latest.vms[i].clone();
            if vm.is_leader || vm.joined { continue; }
            if vm.ipv4.is_empty() {
                all_joined = false;
                continue;
            }
            // Call the leader's bootstrap-add for this follower.
            let join_token = crate::xo::deobfuscate_token(&vm.join_token_enc);
            let body = serde_json::json!({
                "address": vm.ipv4,
                "port": 8553,
                "join_token": join_token,
                "cluster_name": latest.spec.tenant_name,
            });
            let url = format!("{}/api/cluster/bootstrap-add", leader_url.trim_end_matches('/'));
            match client.post(&url)
                .header("X-WolfStack-Secret", &pool_secret)
                .json(&body)
                .send().await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() || status == reqwest::StatusCode::CONFLICT {
                        // 200 OK = added. 409 Conflict = already
                        // in cluster (idempotent re-run). Either way
                        // the follower is in the leader's cluster.
                        latest.vms[i].joined = true;
                        let mut store = PoolStore::load();
                        store.update(latest.clone())?;
                    } else {
                        let body = resp.text().await.unwrap_or_default();
                        all_joined = false;
                        tracing::warn!("pool {}: follower {} bootstrap-add HTTP {}: {}",
                            latest.id, vm.hostname, status,
                            body.chars().take(200).collect::<String>());
                    }
                }
                Err(e) => {
                    all_joined = false;
                    tracing::warn!("pool {}: follower {} bootstrap-add network error: {}",
                        latest.id, vm.hostname, e);
                }
            }
        }
        // If single-VM pool, there are no followers — leader_up
        // becomes live immediately on next tick. Same logic.
        if all_joined {
            latest.status = "live".into();
            latest.live_at = chrono::Utc::now().to_rfc3339();
            latest.last_error = String::new();
            let mut store = PoolStore::load();
            store.update(latest)?;
        }
    }

    Ok(())
}
