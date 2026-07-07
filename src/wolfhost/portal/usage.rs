//! Real resource usage: bandwidth, disk, account counts. DA-backed
//! services pull these straight from DA so the meters reflect what
//! billing will actually charge for. Native services compute disk
//! with `du` inside the container, bandwidth from the container's
//! network counters, and counts from the plugin's own records —
//! same DaUserUsage shape either way.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::DaUserUsage;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

/// GET /api/usage → live usage.
pub async fn get_usage(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => match client.get_user_usage(&username).await {
            Ok(usage) => HttpResponse::Ok().json(usage),
            Err(e) => HttpResponse::BadGateway()
                .json(serde_json::json!({"error": format!("DA usage fetch failed: {}", e)})),
        },
        ToolBackend::Native { service } => {
            let disk_mb = match native_tools::disk_usage_mb(&service).await {
                Ok(d) => d,
                Err(e) => return HttpResponse::BadGateway()
                    .json(serde_json::json!({"error": format!("usage fetch failed: {}", e)})),
            };
            // Bandwidth: cumulative container network counters from
            // WolfStack stats (bytes since container start — the
            // closest native equivalent of DA's monthly meter).
            let mut bandwidth_mb = 0u64;
            if let Ok(stats) = crate::wolfhost::api::servers::wolfstack_get("/api/containers/lxc/stats").await
                && let Some(arr) = stats.as_array()
            {
                for st in arr {
                    if st["name"].as_str() == Some(service.container_name.as_str()) {
                        let bytes = st["net_input"].as_u64().unwrap_or(0)
                            + st["net_output"].as_u64().unwrap_or(0);
                        bandwidth_mb = bytes / (1024 * 1024);
                    }
                }
            }
            // Counts from the plugin's own records.
            let domains = state.domains.list().await.iter()
                .filter(|d| d.service_id == service.id).count() as u32
                + if service.domain.is_empty() { 0 } else { 1 };
            let email_accounts = state.email_accounts.list().await.iter()
                .filter(|a| a.service_id == service.id).count() as u32;
            let mysql_databases = state.databases.list().await.iter()
                .filter(|d| d.service_id == service.id).count() as u32;
            let ftp_accounts = state.ftp_accounts.list().await.iter()
                .filter(|a| a.service_id == service.id).count() as u32;
            let subdomains = native_tools::list_subdomains(&service, &service.domain)
                .await
                .map(|s| s.len() as u32)
                .unwrap_or(0);
            // Quotas from the plan.
            let plan = state.plans.list().await.into_iter().find(|p| p.id == service.plan_id);
            let (disk_quota_mb, bandwidth_quota_mb, vdomains_quota) = match &plan {
                Some(p) => (Some(p.disk_mb), Some(p.bandwidth_mb), Some(p.domains)),
                None => (None, None, None),
            };
            HttpResponse::Ok().json(DaUserUsage {
                bandwidth_mb,
                bandwidth_quota_mb,
                disk_mb,
                disk_quota_mb,
                domains,
                email_accounts,
                mysql_databases,
                ftp_accounts,
                subdomains,
                inodes: 0,
                inodes_quota: None,
                vdomains_quota,
            })
        }
    }
}

/// GET /api/usage/email/{domain} → per-mailbox usage.
pub async fn get_email_usage(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let domain = path.into_inner();
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &domain).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.get_email_usage(&domain).await,
        ToolBackend::Native { service } => native_tools::email_usage(&service, &domain).await,
    };
    match result {
        Ok(usage) => HttpResponse::Ok().json(usage),
        Err(e) => HttpResponse::BadGateway()
            .json(serde_json::json!({"error": format!("email-usage failed: {}", e)})),
    }
}
