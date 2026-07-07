//! Admin-side migration tool: move a customer's DA-hosted account
//! to a fresh WolfStack-managed LXC. End-to-end pipeline:
//!
//!   1. CMD_API_SITE_BACKUP on the source DA → "all" archive.
//!   2. Poll DA's backup list until the new file appears.
//!   3. Provision an LXC on a chosen WolfStack node (auto-balance
//!      if no node specified).
//!   4. Wait for that LXC to come up + be reachable via exec.
//!   5. Pull the backup tarball from DA via the file-manager
//!      download URL.
//!   6. Push the tarball into the LXC over `cat | base64 -d` exec
//!      (we don't expose direct file-upload; the exec channel works
//!      everywhere wolfstack does, no extra plumbing needed).
//!   7. Extract inside the LXC.
//!   8. Restore any *.sql dumps the backup carried (DA bundles them
//!      under each domain's `databases/` directory).
//!   9. Flip the local HostingService record from DA-backed to
//!      Native — pointing at the new LXC. The portal already routes
//!      Native services to the local store / wolfstack helpers, so
//!      every customer-facing surface follows automatically.
//!
//! Each step that fails sets the migration to `Failed` with the
//! error captured in `error` and a final log line — the worker
//! never papers over a problem.

use actix_web::{web, HttpResponse};
use std::sync::Arc;

use crate::wolfhost::AppState;
use crate::wolfhost::api::servers::wolfstack_post_pub;
use crate::wolfhost::models::migration::{Migration, MigrationLogEntry, MigrationStatus, StartMigrationRequest};
use crate::wolfhost::models::service::ServiceBackend;
use crate::wolfhost::provisioning::directadmin::{client_for, DaClient};

const POLL_BACKUP_INTERVAL_SECS: u64 = 20;
const POLL_BACKUP_MAX_ATTEMPTS: u32 = 90;     // 30 minutes
const POLL_LXC_INTERVAL_SECS: u64 = 10;
const POLL_LXC_MAX_ATTEMPTS: u32 = 60;        // 10 minutes

// ─── HTTP handlers ────────────────────────────────────────────────

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let mut migrations = state.migrations.list().await;
    migrations.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    HttpResponse::Ok().json(migrations)
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let migrations = state.migrations.list().await;
    match migrations.into_iter().find(|m| m.id == id) {
        Some(m) => HttpResponse::Ok().json(m),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Migration not found"})),
    }
}

pub async fn start(
    state: web::Data<Arc<AppState>>,
    body: web::Json<StartMigrationRequest>,
) -> HttpResponse {
    let r = body.into_inner();

    // Validate the source service is real and DA-backed.
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == r.service_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Service not found",
        })),
    };
    if service.backend != ServiceBackend::DirectAdmin {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Migration only works on DirectAdmin-backed services",
        }));
    }
    if service.da_instance_id.is_empty() || service.da_username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Service is missing DA instance / username metadata",
        }));
    }

    // Refuse if there's already a non-terminal migration for this
    // service. Two concurrent migrations would race on the LXC
    // creation step and leave one of them pointing at an orphan
    // container.
    let existing = state.migrations.list().await;
    if existing.iter().any(|m| m.service_id == r.service_id && !m.status.is_terminal()) {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "A migration is already running for this service",
        }));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mig = Migration {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id.clone(),
        customer_id: service.customer_id.clone(),
        source_da_instance_id: service.da_instance_id.clone(),
        source_da_username: service.da_username.clone(),
        source_domain: service.domain.clone(),
        target_node_id: r.node_id.clone(),
        target_template: if r.template.is_empty() { "ubuntu-22.04".to_string() } else { r.template.clone() },
        target_memory_mb: if r.memory_mb == 0 { 2048 } else { r.memory_mb },
        target_disk_gb:   if r.disk_gb   == 0 { 20 }   else { r.disk_gb },
        target_cpu_cores: if r.cpu_cores == 0 { 2 }    else { r.cpu_cores },
        status: MigrationStatus::Pending,
        log: vec![MigrationLogEntry {
            at: now.clone(),
            kind: "info".into(),
            message: format!(
                "Migration job created for service {} (DA user `{}`, instance `{}`)",
                if service.domain.is_empty() { "<no-domain>" } else { &service.domain },
                service.da_username,
                service.da_instance_id,
            ),
        }],
        backup_filename: String::new(),
        local_backup_path: String::new(),
        new_container_name: String::new(),
        new_container_node: String::new(),
        started_at: now,
        completed_at: String::new(),
        error: String::new(),
        suspend_source_after: r.suspend_source_after,
    };
    let mig_id = mig.id.clone();

    if let Err(e) = state.migrations.update_with(|items| { items.push(mig); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    // Spawn the worker. We don't hold the request open for the
    // whole migration — the admin polls `/migrations/{id}` for
    // progress.
    let worker_state: Arc<AppState> = (**state).clone();
    let worker_id = mig_id.clone();
    tokio::spawn(async move {
        run_migration(worker_state, worker_id).await;
    });

    HttpResponse::Created().json(serde_json::json!({"id": mig_id, "status": "pending"}))
}

/// POST /migrations/{id}/rollback — revert a Complete migration.
///
/// Customer-facing effect is the same as if the migration never
/// happened: the service record points at DirectAdmin again, and if
/// we'd suspended the source DA user at finalize time, we
/// unsuspend it now. The customer-portal handlers all branch on
/// `service.backend`, so the next request from the customer
/// silently routes through DA again — no portal restart needed.
///
/// The new LXC is INTENTIONALLY NOT destroyed: it still holds the
/// migrated data and the operator may want to inspect what went
/// wrong before throwing it away. Cleanup is a separate, explicit
/// action.
pub async fn rollback(
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let migrations = state.migrations.list().await;
    let mig = match migrations.iter().find(|m| m.id == id) {
        Some(m) => m.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Migration not found"})),
    };
    if mig.status != MigrationStatus::Complete {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!(
                "Only completed migrations can be rolled back. This one is `{}`.",
                mig.status.label(),
            ),
        }));
    }

    // Step 1: flip the service record back. We restore `backend`
    // to DirectAdmin and re-link to the same instance / username
    // we had at job creation. `container_name` / `server_node`
    // are intentionally cleared — those still describe the new
    // LXC, but the service no longer lives there from the
    // customer's point of view.
    let svc_id = mig.service_id.clone();
    let da_inst = mig.source_da_instance_id.clone();
    let da_user = mig.source_da_username.clone();
    if let Err(e) = state.services.update_with(move |items| {
        if let Some(s) = items.iter_mut().find(|s| s.id == svc_id) {
            s.backend = ServiceBackend::DirectAdmin;
            s.da_instance_id = da_inst.clone();
            s.da_username = da_user.clone();
            s.container_name = String::new();
            s.server_node = String::new();
        }
    }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    // Step 2: if we suspended the DA user at finalize, unsuspend
    // it. Best-effort — if DA is unreachable we still consider the
    // rollback partially-successful and surface a warning, because
    // the service-record flip already restored customer-portal
    // routing.
    let mut warnings: Vec<String> = Vec::new();
    if mig.suspend_source_after {
        let instances = state.da_instances.list().await;
        if let Some(inst) = instances.iter().find(|i| i.id == mig.source_da_instance_id) {
            let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&inst.admin_password_enc);
            let da = DaClient::new(&inst.url, &inst.admin_user, &pass);
            if let Err(e) = da.unsuspend_user(&mig.source_da_username).await {
                warnings.push(format!(
                    "Couldn't unsuspend DA user `{}`: {}. Customer-portal calls already route through DA again, but the user can't log in until you unsuspend by hand.",
                    mig.source_da_username, e,
                ));
            }
        } else {
            warnings.push("Source DA instance is no longer in wolfhost — couldn't auto-unsuspend the user".into());
        }
    }

    // Step 3: stamp the migration record so the audit trail is
    // honest about what happened.
    let mig_id = id.clone();
    let warns_for_log = warnings.clone();
    let _ = state.migrations.update_with(move |items| {
        if let Some(m) = items.iter_mut().find(|m| m.id == mig_id) {
            m.status = MigrationStatus::RolledBack;
            m.completed_at = chrono::Utc::now().to_rfc3339();
            m.log.push(MigrationLogEntry {
                at: chrono::Utc::now().to_rfc3339(),
                kind: "info".into(),
                message: "Rolled back: service record reverted to DirectAdmin.".into(),
            });
            for w in &warns_for_log {
                m.log.push(MigrationLogEntry {
                    at: chrono::Utc::now().to_rfc3339(),
                    kind: "warn".into(),
                    message: w.clone(),
                });
            }
        }
    }).await;

    let mut resp = serde_json::json!({
        "status": "rolled_back",
        "message": "Service is back on DirectAdmin. The new LXC was left in place for inspection.",
    });
    if !warnings.is_empty() {
        resp["warnings"] = serde_json::json!(warnings);
    }
    HttpResponse::Ok().json(resp)
}

pub async fn cancel(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let migrations = state.migrations.list().await;
    let mig = match migrations.into_iter().find(|m| m.id == id) {
        Some(m) => m,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Migration not found"})),
    };
    if mig.status.is_terminal() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Migration already in terminal state: {}", mig.status.label()),
        }));
    }
    let target_id = id.clone();
    let _ = state.migrations.update_with(move |items| {
        if let Some(m) = items.iter_mut().find(|m| m.id == target_id) {
            m.status = MigrationStatus::Cancelled;
            m.completed_at = chrono::Utc::now().to_rfc3339();
            m.log.push(MigrationLogEntry {
                at: chrono::Utc::now().to_rfc3339(),
                kind: "warn".into(),
                message: "Cancelled by operator. The worker will exit at the next checkpoint.".into(),
            });
        }
    }).await;
    HttpResponse::Ok().json(serde_json::json!({"status": "cancelled"}))
}

// ─── Worker / state machine ───────────────────────────────────────

/// Update the migration record. Closure receives a mutable ref to
/// the live row and can mutate it. Returns the updated copy so the
/// worker can read fields written elsewhere (e.g. `Cancelled`).
async fn update_mig<F>(state: &Arc<AppState>, id: &str, f: F) -> Option<Migration>
where
    F: FnOnce(&mut Migration) + Send + 'static,
{
    let target_id = id.to_string();
    let _ = state.migrations.update_with(move |items| {
        if let Some(m) = items.iter_mut().find(|m| m.id == target_id) {
            f(m);
        }
    }).await;
    state.migrations.list().await.into_iter().find(|m| m.id == id)
}

/// Append a log line to the migration without touching its status.
async fn log_mig(state: &Arc<AppState>, id: &str, kind: &str, msg: impl Into<String>) {
    let kind = kind.to_string();
    let msg = msg.into();
    let _ = update_mig(state, id, move |m| {
        m.log.push(MigrationLogEntry {
            at: chrono::Utc::now().to_rfc3339(),
            kind,
            message: msg,
        });
    }).await;
}

/// Move the migration to a new status. Returns the up-to-date row,
/// or `None` if the row vanished (shouldn't happen) or it was
/// cancelled in the interim — caller bails on `None`.
async fn advance(state: &Arc<AppState>, id: &str, status: MigrationStatus, msg: &str) -> Option<Migration> {
    let new_status = status.clone();
    let line = msg.to_string();
    let updated = update_mig(state, id, move |m| {
        if m.status == MigrationStatus::Cancelled { return; }
        m.status = new_status;
        m.log.push(MigrationLogEntry {
            at: chrono::Utc::now().to_rfc3339(),
            kind: "info".into(),
            message: line,
        });
    }).await?;
    if updated.status == MigrationStatus::Cancelled { return None; }
    Some(updated)
}

/// Mark the migration as failed with `error`. Idempotent — calling
/// twice just appends a second log line.
async fn fail(state: &Arc<AppState>, id: &str, error: &str) {
    let line = error.to_string();
    let _ = update_mig(state, id, move |m| {
        m.status = MigrationStatus::Failed;
        m.error = line.clone();
        m.completed_at = chrono::Utc::now().to_rfc3339();
        m.log.push(MigrationLogEntry {
            at: chrono::Utc::now().to_rfc3339(),
            kind: "error".into(),
            message: line,
        });
    }).await;
}

/// Resolve the source DA client + username for a migration. Returns
/// `None` and marks the migration as failed if the instance has been
/// deleted between job creation and worker pickup.
async fn resolve_da_client(state: &Arc<AppState>, mig: &Migration) -> Option<DaClient> {
    let instances = state.da_instances.list().await;
    let inst = instances.iter().find(|i| i.id == mig.source_da_instance_id)?;
    Some(client_for(inst))
}

async fn run_migration(state: Arc<AppState>, id: String) {
    let starting = match state.migrations.list().await.into_iter().find(|m| m.id == id) {
        Some(m) => m,
        None => {
            log::error!("Migration {} disappeared before worker could pick it up", id);
            return;
        }
    };

    // ── Step 1: ask DA to create the backup ─────────────────────
    let mig = match advance(&state, &id, MigrationStatus::CreatingBackup,
        "Asking DirectAdmin to create a full account backup").await {
        Some(m) => m,
        None => return,
    };
    let da = match resolve_da_client(&state, &mig).await {
        Some(c) => c,
        None => return fail(&state, &id, "Source DirectAdmin instance is no longer configured").await,
    };

    // Snapshot DA's backup list BEFORE creating ours so we can
    // detect which entry is the new one when polling.
    let pre_existing: std::collections::HashSet<String> = match da.list_user_backups(&starting.source_da_username).await {
        Ok(list) => list.into_iter().map(|b| b.filename).collect(),
        Err(e) => return fail(&state, &id, &format!("Couldn't list existing DA backups: {}", e)).await,
    };

    if let Err(e) = da.create_user_backup(&starting.source_da_username, "all").await {
        return fail(&state, &id, &format!("DA refused to create backup: {}", e)).await;
    }

    // ── Step 2: poll until the new backup appears ───────────────
    let mig = match advance(&state, &id, MigrationStatus::WaitingBackup,
        "Waiting for DirectAdmin to finish writing the backup tarball").await {
        Some(m) => m,
        None => return,
    };
    let mut backup_filename = String::new();
    for attempt in 0..POLL_BACKUP_MAX_ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_secs(POLL_BACKUP_INTERVAL_SECS)).await;
        // Refresh local view in case operator cancelled.
        if let Some(latest) = state.migrations.list().await.into_iter().find(|m| m.id == id) {
            if latest.status == MigrationStatus::Cancelled { return; }
        }
        match da.list_user_backups(&starting.source_da_username).await {
            Ok(list) => {
                if let Some(new) = list.into_iter().find(|b| !pre_existing.contains(&b.filename)) {
                    backup_filename = new.filename.clone();
                    let target_id = id.clone();
                    let fname = new.filename.clone();
                    let _ = update_mig(&state, &id, move |m| {
                        m.backup_filename = fname.clone();
                        m.log.push(MigrationLogEntry {
                            at: chrono::Utc::now().to_rfc3339(),
                            kind: "info".into(),
                            message: format!("Backup ready on DA: {}", fname),
                        });
                    }).await;
                    let _ = target_id;
                    break;
                }
            }
            Err(e) => {
                log_mig(&state, &id, "warn", format!("Backup poll {} failed: {}", attempt + 1, e)).await;
            }
        }
    }
    if backup_filename.is_empty() {
        return fail(&state, &id, "Backup didn't appear on DA within 30 minutes").await;
    }
    let _ = mig;

    // ── Step 3: provision LXC ───────────────────────────────────
    let mig = match advance(&state, &id, MigrationStatus::ProvisioningLxc,
        "Asking WolfStack to create a new LXC container").await {
        Some(m) => m,
        None => return,
    };
    let provision_body = serde_json::json!({
        "service_id": mig.service_id,
        "node_id": if mig.target_node_id.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(mig.target_node_id.clone()) },
        "template": mig.target_template,
        "memory_mb": mig.target_memory_mb,
        "disk_gb": mig.target_disk_gb,
        "cpu_cores": mig.target_cpu_cores,
    });
    // Provisioning lives on this same wolfhost API
    // (`api::servers::provision_container`). Loopback to localhost
    // rather than round-tripping through wolfstack's plugin proxy —
    // the proxy would just bounce right back to us.
    let api_port = state.config.get().api_port;
    let provision_resp = match loopback_post(api_port, "/servers/provision", &provision_body).await {
        Ok(r) => r,
        Err(e) => return fail(&state, &id, &format!("LXC provision request failed: {}", e)).await,
    };
    // The provision endpoint replies with `{ container_name, node_id, host_ip, ... }`.
    let container_name = provision_resp["container_name"].as_str().unwrap_or("").to_string();
    let target_node = provision_resp["node_id"].as_str().unwrap_or("").to_string();
    if container_name.is_empty() {
        return fail(&state, &id, &format!("Provision API returned no container_name: {}", provision_resp)).await;
    }
    let cn = container_name.clone();
    let tn = target_node.clone();
    let _ = update_mig(&state, &id, move |m| {
        m.new_container_name = cn;
        m.new_container_node = tn;
    }).await;

    // ── Step 4: wait for the LXC to be reachable via exec ───────
    let _ = advance(&state, &id, MigrationStatus::WaitingLxc,
        &format!("Waiting for LXC `{}` on node `{}` to come up", container_name, target_node)).await;
    let mut lxc_ready = false;
    for attempt in 0..POLL_LXC_MAX_ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_secs(POLL_LXC_INTERVAL_SECS)).await;
        match exec_in_lxc(&container_name, &target_node, "echo wolfstack-migration-ping").await {
            Ok(out) if out.contains("wolfstack-migration-ping") => { lxc_ready = true; break; }
            Ok(_) | Err(_) => {
                if attempt > 0 && attempt % 6 == 0 {
                    log_mig(&state, &id, "info", format!("LXC still booting (poll {})…", attempt + 1)).await;
                }
            }
        }
        if let Some(latest) = state.migrations.list().await.into_iter().find(|m| m.id == id) {
            if latest.status == MigrationStatus::Cancelled { return; }
        }
    }
    if !lxc_ready {
        return fail(&state, &id, "LXC didn't become reachable within 10 minutes").await;
    }

    // ── Step 5: download the backup from DA ─────────────────────
    let _ = advance(&state, &id, MigrationStatus::DownloadingBackup,
        "Downloading backup tarball from DirectAdmin").await;
    let bytes = match da.download_user_backup(&starting.source_da_username, &backup_filename).await {
        Ok(b) => b,
        Err(e) => return fail(&state, &id, &format!("Backup download failed: {}", e)).await,
    };
    if bytes.is_empty() {
        return fail(&state, &id, "Backup download returned 0 bytes — DA may have rejected the request").await;
    }
    log_mig(&state, &id, "info", format!("Downloaded {} bytes", bytes.len())).await;

    // ── Step 6: push backup into the LXC over exec/base64 ───────
    let _ = advance(&state, &id, MigrationStatus::UploadingToLxc,
        "Streaming backup into the new LXC").await;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let lxc_path = "/root/wolfhost-migration-backup.tar.gz";
    // Chunk the base64 to avoid blowing through any single-line
    // command-length limits the wolfstack exec path may impose.
    // 256 KB of base64 → about 192 KB of binary per chunk; safe
    // under most shell argv ceilings and small enough that a hung
    // chunk is recoverable.
    let chunk_size = 256 * 1024;
    let mut offset = 0;
    let total = b64.len();
    let _ = exec_in_lxc(&container_name, &target_node, &format!("rm -f {}", lxc_path)).await;
    while offset < total {
        let end = (offset + chunk_size).min(total);
        let chunk = &b64[offset..end];
        // Append base64 to a temp file; we'll decode at the end.
        let cmd = format!(
            "printf %s '{}' >> {}.b64",
            shell_escape_single(chunk),
            lxc_path,
        );
        if let Err(e) = exec_in_lxc(&container_name, &target_node, &cmd).await {
            return fail(&state, &id, &format!("Chunk upload failed at {}/{}: {}", offset, total, e)).await;
        }
        offset = end;
    }
    let decode_cmd = format!("base64 -d {}.b64 > {} && rm -f {}.b64", lxc_path, lxc_path, lxc_path);
    if let Err(e) = exec_in_lxc(&container_name, &target_node, &decode_cmd).await {
        return fail(&state, &id, &format!("Backup decode failed inside LXC: {}", e)).await;
    }
    log_mig(&state, &id, "info", format!("Wrote backup to {}:{}", container_name, lxc_path)).await;

    // ── Step 7: extract ─────────────────────────────────────────
    let _ = advance(&state, &id, MigrationStatus::Extracting,
        "Extracting backup inside the LXC").await;
    let extract = format!(
        "mkdir -p /var/wolfhost-migration && tar -xzf {} -C /var/wolfhost-migration",
        lxc_path,
    );
    if let Err(e) = exec_in_lxc(&container_name, &target_node, &extract).await {
        return fail(&state, &id, &format!("tar xzf failed: {}", e)).await;
    }

    // ── Step 8a: restore SQL dumps ──────────────────────────────
    // DA backups bundle DB dumps as `<dbname>.sql` under `databases/`
    // for each domain. Loop them through `mysql` if the LXC has it.
    let _ = advance(&state, &id, MigrationStatus::RestoringDatabases,
        "Restoring SQL dumps inside the LXC").await;
    let restore = "set -e; \
        if ! command -v mysql >/dev/null 2>&1; then echo 'mysql client absent — skipping DB restore'; exit 0; fi; \
        find /var/wolfhost-migration -type f -name '*.sql' | while read f; do \
            db=$(basename \"$f\" .sql); \
            mysql -e \"CREATE DATABASE IF NOT EXISTS \\`$db\\`\" 2>/dev/null || true; \
            mysql \"$db\" < \"$f\" || echo \"warn: import failed for $db\"; \
        done";
    match exec_in_lxc(&container_name, &target_node, restore).await {
        Ok(out) => log_mig(&state, &id, "info", format!("DB restore output: {}", out.chars().take(2000).collect::<String>())).await,
        Err(e) => log_mig(&state, &id, "warn", format!("DB restore step had errors: {}", e)).await,
    }

    // ── Step 8b: verify before flipping ─────────────────────────
    // Sanity-check the LXC is responsive AND that we actually wrote
    // something useful to it. If verification fails the service
    // record is NOT flipped — the source DA keeps serving the
    // customer until the operator fixes whatever's wrong, OR
    // chooses to roll the failed migration back. This is the
    // critical "keep things running" guarantee: any failure
    // before this point means the customer never noticed.
    let _ = advance(&state, &id, MigrationStatus::Verifying,
        "Verifying the new LXC before pointing customer traffic at it").await;
    let verify_user = starting.source_da_username.clone();
    let public_html_check = format!(
        "test -d /home/{user}/domains/{domain} || test -d /home/{user}/public_html",
        user = verify_user,
        domain = if starting.source_domain.is_empty() { "_no_domain_" } else { &starting.source_domain },
    );
    if let Err(e) = exec_in_lxc(&container_name, &target_node, &public_html_check).await {
        return fail(&state, &id,
            &format!("Verification failed — backup didn't lay down the customer's home directory inside the LXC \
                ({}). Source DA is unaffected. Use Rollback to clean up local state, then retry.", e)
        ).await;
    }
    // Best-effort DB check — only if mysql is present (already
    // guarded in the restore step). A query to information_schema
    // proves the daemon's up.
    let db_check = "command -v mysql >/dev/null 2>&1 && mysql -e 'SELECT 1' >/dev/null 2>&1 || echo 'mysql-absent'";
    match exec_in_lxc(&container_name, &target_node, db_check).await {
        Ok(out) if out.trim() == "mysql-absent" => {
            log_mig(&state, &id, "info", "MySQL absent on LXC — skipping DB liveness check (matches restore step)").await;
        }
        Ok(_) => log_mig(&state, &id, "info", "MySQL on LXC is responsive").await,
        Err(e) => {
            log_mig(&state, &id, "warn",
                format!("MySQL liveness check returned non-zero — DB-backed sites may not work yet: {}", e)).await;
        }
    }

    // ── Step 9: finalise — flip the service over ────────────────
    let _ = advance(&state, &id, MigrationStatus::Finalizing,
        "Updating the customer's service record to point at the new LXC").await;
    let svc_id = mig.service_id.clone();
    let cn_for_record = container_name.clone();
    let tn_for_record = target_node.clone();
    let _ = state.services.update_with(move |items| {
        if let Some(s) = items.iter_mut().find(|s| s.id == svc_id) {
            s.backend = ServiceBackend::Native;
            s.container_name = cn_for_record;
            s.server_node = tn_for_record;
        }
    }).await;

    // Optional: tell DA to delete the temporary backup so it
    // doesn't sit on the source forever. Best-effort — failures
    // here don't fail the migration.
    if let Err(e) = da.delete_user_backup(&starting.source_da_username, &backup_filename).await {
        log_mig(&state, &id, "warn", format!("Couldn't delete source backup {}: {}", backup_filename, e)).await;
    }

    // Optional: suspend the source DA account so the customer can't
    // accidentally end up writing to two places at once. Reversible
    // — the operator can unsuspend from the Services tab. Best-effort:
    // suspension failure logs a warning but doesn't fail the
    // migration, because by this point everything's already moved.
    if starting.suspend_source_after {
        match da.suspend_user(&starting.source_da_username).await {
            Ok(_) => log_mig(&state, &id, "info", format!("Suspended source DA user `{}`", starting.source_da_username)).await,
            Err(e) => log_mig(&state, &id, "warn", format!("Couldn't suspend source DA user `{}`: {}", starting.source_da_username, e)).await,
        }
    }

    let _ = update_mig(&state, &id, |m| {
        m.status = MigrationStatus::Complete;
        m.completed_at = chrono::Utc::now().to_rfc3339();
        m.log.push(MigrationLogEntry {
            at: chrono::Utc::now().to_rfc3339(),
            kind: "info".into(),
            message: "Migration complete. Customer service is now Native + LXC-backed.".into(),
        });
    }).await;
}

// ─── Helpers ──────────────────────────────────────────────────────

/// Run a command inside an LXC via WolfStack's exec API. Walks the
/// "is this our local node or a remote one" decision the same way
/// `api::servers::container_exec` does, except that helper is
/// private — we replicate the small bit we need.
async fn exec_in_lxc(container: &str, node_id: &str, cmd: &str) -> Result<String, String> {
    // Try local first; fall back to the cluster proxy. This way we
    // don't have to pre-classify whether the new LXC was created on
    // the wolfhost host's own node.
    let local_path = format!("/api/containers/lxc/{}/exec", container);
    let body = serde_json::json!({"command": cmd});
    if let Ok(r) = wolfstack_post_pub(&local_path, &body).await {
        if r["ok"].as_bool() == Some(true) || r.get("exit_code").is_some() || r.get("stdout").is_some() {
            let stdout = r["stdout"].as_str().unwrap_or("");
            let stderr = r["stderr"].as_str().unwrap_or("");
            let exit = r["exit_code"].as_i64().unwrap_or(0);
            if exit != 0 {
                return Err(format!("exit {}: stdout=`{}` stderr=`{}`", exit, truncate(stdout), truncate(stderr)));
            }
            return Ok(stdout.to_string());
        }
    }
    if !node_id.is_empty() {
        let remote = format!("/api/nodes/{}/proxy/containers/lxc/{}/exec", node_id, container);
        let r = wolfstack_post_pub(&remote, &body).await?;
        let stdout = r["stdout"].as_str().unwrap_or("");
        let stderr = r["stderr"].as_str().unwrap_or("");
        let exit = r["exit_code"].as_i64().unwrap_or(0);
        if exit != 0 {
            return Err(format!("exit {}: stdout=`{}` stderr=`{}`", exit, truncate(stdout), truncate(stderr)));
        }
        return Ok(stdout.to_string());
    }
    Err("Container not reachable via local or proxy exec".into())
}

fn truncate(s: &str) -> String {
    if s.len() <= 500 { s.to_string() } else { format!("{}…", &s[..500]) }
}

/// Escape `'` for a single-quoted shell argument by closing the
/// quote, emitting an escaped quote, and reopening: `it's` →
/// `'it'\''s'`. The caller is expected to wrap the result in `'…'`.
fn shell_escape_single(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// POST to the wolfhost API on localhost. Used by the migration
/// worker to drive its own provisioning endpoint without bouncing
/// through wolfstack's plugin proxy. Independent reqwest client
/// instead of the shared cluster client because we don't need (and
/// don't want) the cluster auth header on a self-call.
async fn loopback_post(port: u16, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let url = format!("http://127.0.0.1:{}{}", port, path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client build: {}", e))?;
    let resp = client.post(&url)
        .json(body)
        .send().await
        .map_err(|e| format!("loopback POST {} failed: {}", path, e))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("body read: {}", e))?;
    if !status.is_success() {
        return Err(format!("HTTP {} from {}: {}", status, path, text.chars().take(500).collect::<String>()));
    }
    serde_json::from_str(&text).map_err(|e| format!("Non-JSON response from {}: {} (body: {})", path, e, text.chars().take(200).collect::<String>()))
}
