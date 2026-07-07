use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::service::{HostingService, ServiceStatus, ServiceUsage, ServiceBackend, CreateServiceRequest, UpdateServiceRequest, BillingCycle};
use crate::wolfhost::provisioning::directadmin::{DaClient, deobfuscate_password};
use std::sync::Arc;

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let services = state.services.list().await;
    HttpResponse::Ok().json(services)
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let services = state.services.list().await;
    match services.iter().find(|s| s.id == id) {
        Some(s) => HttpResponse::Ok().json(s),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Service not found"})),
    }
}

pub async fn create(state: web::Data<Arc<AppState>>, body: web::Json<CreateServiceRequest>) -> HttpResponse {
    let req = body.into_inner();
    let now = chrono::Utc::now();
    let now_str = now.to_rfc3339();

    // Calculate next billing and expiry
    let (next_billing, expires_at) = match req.billing_cycle {
        BillingCycle::Monthly => {
            let next = now + chrono::Duration::days(30);
            let exp = now + chrono::Duration::days(30);
            (next.to_rfc3339(), exp.to_rfc3339())
        }
        BillingCycle::Yearly => {
            let next = now + chrono::Duration::days(365);
            let exp = now + chrono::Duration::days(365);
            (next.to_rfc3339(), exp.to_rfc3339())
        }
    };

    let service_id = uuid::Uuid::new_v4().to_string();
    let home_dir = format!("/var/www/customers/{}/{}", req.customer_id, service_id);

    // Resolve DA username when backend is DirectAdmin
    let da_username = if req.backend == ServiceBackend::DirectAdmin && !req.da_instance_id.is_empty() {
        if !req.da_username.is_empty() {
            // Use the provided existing DA username
            req.da_username.clone()
        } else {
            // Create a new DA user
            let instances = state.da_instances.list().await;
            let inst = match instances.iter().find(|i| i.id == req.da_instance_id) {
                Some(i) => i.clone(),
                None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "DirectAdmin instance not found"})),
            };

            let pass = deobfuscate_password(&inst.admin_password_enc);
            let da = DaClient::new(&inst.url, &inst.admin_user, &pass);

            // Generate a DA username from the domain (first 8 chars, alphanumeric)
            let da_user: String = req.domain.chars()
                .filter(|c| c.is_alphanumeric())
                .take(8)
                .collect::<String>()
                .to_lowercase();
            let da_user = if da_user.is_empty() {
                format!("user{}", &service_id[..6])
            } else {
                da_user
            };

            // Generate a random password for the DA user
            let da_pass: String = uuid::Uuid::new_v4().to_string().replace('-', "");
            let da_pass = &da_pass[..16];

            let email = format!("admin@{}", if req.domain.is_empty() { "localhost" } else { &req.domain });
            let domain = if req.domain.is_empty() { "localhost" } else { &req.domain };

            if let Err(e) = da.create_user(&da_user, &email, da_pass, domain, "default").await {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to create DA user: {}", e)
                }));
            }

            da_user
        }
    } else {
        String::new()
    };

    let service = HostingService {
        id: service_id.clone(),
        customer_id: req.customer_id,
        plan_id: req.plan_id,
        domain: req.domain,
        status: ServiceStatus::Active,
        billing_cycle: req.billing_cycle,
        next_billing,
        server_node: req.server_node,
        home_dir,
        container_name: String::new(),
        container_ip: String::new(),
        host_ip: String::new(),
        host_hostname: String::new(),
        ftp_port: 0,
        usage: ServiceUsage::default(),
        backend: req.backend,
        da_instance_id: req.da_instance_id,
        da_username,
        created_at: now_str,
        expires_at,
    };

    if let Err(e) = state.services.update_with(|items| {
        items.push(service);
    }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    HttpResponse::Created().json(serde_json::json!({"id": service_id, "status": "created"}))
}

pub async fn update(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateServiceRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();

    let result = state.services.update_with(|items| {
        if let Some(s) = items.iter_mut().find(|s| s.id == id) {
            if let Some(v) = req.domain { s.domain = v; }
            if let Some(v) = req.status { s.status = v; }
            if let Some(v) = req.billing_cycle { s.billing_cycle = v; }
            if let Some(v) = req.plan_id { s.plan_id = v; }
            if let Some(v) = req.server_node {
                if v.is_empty() {
                    // Clearing server_node means container was deleted — clear all container fields
                    s.container_name.clear();
                    s.container_ip.clear();
                    s.host_ip.clear();
                    s.host_hostname.clear();
                    s.ftp_port = 0;
                    s.home_dir.clear();
                }
                s.server_node = v;
            }
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let result = state.services.update_with(|items| {
        items.retain(|s| s.id != id);
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// POST /services/{id}/da/suspend — suspend the service's underlying
/// DirectAdmin user account. Same lever DA's own UI uses (`CMD_API_SELECT_USERS
/// action=suspend`): the user can't log in, mail flow stops, files
/// stay on disk read-only. The wolfhost ServiceStatus is also flipped
/// to Suspended so the dashboard / customer portal both reflect it.
///
/// Reversible via `unsuspend_da`.
pub async fn suspend_da(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == id) {
        Some(s) => s.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Service not found"})),
    };
    if service.backend != ServiceBackend::DirectAdmin || service.da_instance_id.is_empty() || service.da_username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Service is not DirectAdmin-backed"
        }));
    }
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == service.da_instance_id) {
        Some(i) => i,
        None => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "DirectAdmin instance for this service is no longer configured"
        })),
    };
    let pass = deobfuscate_password(&inst.admin_password_enc);
    let da = DaClient::new(&inst.url, &inst.admin_user, &pass);
    if let Err(e) = da.suspend_user(&service.da_username).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("DirectAdmin: {}", e)
        }));
    }
    let svc_id = id.clone();
    let _ = state.services.update_with(move |items| {
        if let Some(s) = items.iter_mut().find(|s| s.id == svc_id) {
            s.status = ServiceStatus::Suspended;
        }
    }).await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "suspended",
        "message": format!("DirectAdmin user `{}` suspended.", service.da_username),
    }))
}

/// POST /services/{id}/da/unsuspend — undo `suspend_da`. Customer
/// can log back in, mail flow resumes.
pub async fn unsuspend_da(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == id) {
        Some(s) => s.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Service not found"})),
    };
    if service.backend != ServiceBackend::DirectAdmin || service.da_instance_id.is_empty() || service.da_username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Service is not DirectAdmin-backed"
        }));
    }
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == service.da_instance_id) {
        Some(i) => i,
        None => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "DirectAdmin instance for this service is no longer configured"
        })),
    };
    let pass = deobfuscate_password(&inst.admin_password_enc);
    let da = DaClient::new(&inst.url, &inst.admin_user, &pass);
    if let Err(e) = da.unsuspend_user(&service.da_username).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("DirectAdmin: {}", e)
        }));
    }
    let svc_id = id.clone();
    let _ = state.services.update_with(move |items| {
        if let Some(s) = items.iter_mut().find(|s| s.id == svc_id) {
            s.status = ServiceStatus::Active;
        }
    }).await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "active",
        "message": format!("DirectAdmin user `{}` re-enabled.", service.da_username),
    }))
}
