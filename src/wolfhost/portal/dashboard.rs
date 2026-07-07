use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::service::{ServiceBackend, ServiceStatus};
use crate::wolfhost::models::ticket::TicketStatus;
use crate::wolfhost::models::invoice::InvoiceStatus;
use crate::wolfhost::provisioning::directadmin::client_for;
use std::sync::Arc;

pub async fn get_dashboard(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let services = state.services.list().await;
    let domains = state.domains.list().await;
    let tickets = state.tickets.list().await;
    let invoices = state.invoices.list().await;
    let plans = state.plans.list().await;
    let da_instances = state.da_instances.list().await;

    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();
    let active_services = my_services.iter().filter(|s| s.status == ServiceStatus::Active).count();
    let open_tickets = tickets.iter()
        .filter(|t| t.customer_id == customer_id && (t.status == TicketStatus::Open || t.status == TicketStatus::InProgress))
        .count();
    let pending_invoices = invoices.iter()
        .filter(|i| i.customer_id == customer_id && (i.status == InvoiceStatus::Pending || i.status == InvoiceStatus::Overdue))
        .count();

    // Per-service usage. For native services we keep using the local
    // usage counters (background tasks populate them from container
    // stats). For DA-backed services those counters are always zero —
    // the authoritative numbers live on the DA box, so we hit
    // CMD_API_SHOW_USER_USAGE for each service. The previous code used
    // the local counters unconditionally, which is why a freshly-
    // connected DA customer saw zero domains and zero usage on the
    // dashboard despite having sites in DA.
    let mut total_disk: u64 = 0;
    let mut total_bandwidth: u64 = 0;
    let mut total_domains: u64 = 0;
    let mut disk_limit: u64 = 0;
    let mut bw_limit: u64 = 0;
    let mut service_details: Vec<serde_json::Value> = Vec::with_capacity(my_services.len());

    for s in &my_services {
        let plan = plans.iter().find(|p| p.id == s.plan_id);
        let plan_name = plan.map(|p| p.name.as_str()).unwrap_or("Unknown");
        let plan_disk = plan.map(|p| p.disk_mb).unwrap_or(0);
        let plan_bw = plan.map(|p| p.bandwidth_mb).unwrap_or(0);

        let mut svc_disk = s.usage.disk_mb;
        let mut svc_bw = s.usage.bandwidth_mb;
        let mut svc_disk_limit = plan_disk;
        let mut svc_bw_limit = plan_bw;
        let mut svc_domains: u64 = 0;
        let mut da_error: Option<String> = None;

        let is_da = s.backend == ServiceBackend::DirectAdmin
            && !s.da_instance_id.is_empty()
            && !s.da_username.is_empty();

        if is_da {
            match da_instances.iter().find(|i| i.id == s.da_instance_id) {
                Some(inst) => {
                    let client = client_for(inst);
                    match client.get_user_usage(&s.da_username).await {
                        Ok(u) => {
                            svc_disk = u.disk_mb;
                            svc_bw = u.bandwidth_mb;
                            svc_domains = u.domains as u64;
                            // Prefer DA's package quotas — they're what
                            // actually limit the customer on the DA box.
                            // Fall back to the plan's limits (which may
                            // be larger / softer) only when DA reports
                            // unlimited (None).
                            if let Some(q) = u.disk_quota_mb { svc_disk_limit = q; }
                            if let Some(q) = u.bandwidth_quota_mb { svc_bw_limit = q; }
                        }
                        Err(e) => {
                            da_error = Some(format!("DA usage fetch failed: {}", e));
                        }
                    }
                }
                None => {
                    da_error = Some("Configured DirectAdmin instance no longer exists".into());
                }
            }
        } else {
            // Native service — count domains from the local store. A
            // single native service typically has one primary domain;
            // we count every Domain row pointing at this service so
            // addon-domain support continues to work.
            svc_domains = domains.iter()
                .filter(|d| d.service_id == s.id)
                .count() as u64;
        }

        total_disk = total_disk.saturating_add(svc_disk);
        total_bandwidth = total_bandwidth.saturating_add(svc_bw);
        total_domains = total_domains.saturating_add(svc_domains);
        disk_limit = disk_limit.saturating_add(svc_disk_limit);
        bw_limit = bw_limit.saturating_add(svc_bw_limit);

        service_details.push(serde_json::json!({
            "id": s.id,
            "domain": s.domain,
            "plan": plan_name,
            "status": s.status,
            "backend": s.backend,
            "disk_used_mb": svc_disk,
            "disk_limit_mb": svc_disk_limit,
            "bandwidth_used_mb": svc_bw,
            "bandwidth_limit_mb": svc_bw_limit,
            "domain_count": svc_domains,
            "next_billing": s.next_billing,
            "container_name": s.container_name,
            "host_ip": s.host_ip,
            "host_hostname": s.host_hostname,
            "ftp_port": s.ftp_port,
            "da_error": da_error,
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "services": service_details,
        "active_services": active_services,
        "total_domains": total_domains,
        "open_tickets": open_tickets,
        "pending_invoices": pending_invoices,
        "disk_used_mb": total_disk,
        "disk_limit_mb": disk_limit,
        "bandwidth_used_mb": total_bandwidth,
        "bandwidth_limit_mb": bw_limit,
    }))
}
