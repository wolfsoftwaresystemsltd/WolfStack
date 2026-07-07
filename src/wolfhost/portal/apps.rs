use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::sync::Arc;

/// GET /apps — list available apps
pub async fn list(_req: HttpRequest) -> HttpResponse {
    let apps = crate::wolfhost::provisioning::apps::list_apps();
    let result: Vec<serde_json::Value> = apps.iter().map(|a| {
        serde_json::json!({
            "id": a.id,
            "name": a.name,
            "description": a.description,
            "icon": a.icon,
            "category": a.category,
            "requires_db": a.requires_db,
            "url": a.url,
        })
    }).collect();
    HttpResponse::Ok().json(result)
}

#[derive(Deserialize)]
pub struct InstallRequest {
    pub app_id: String,
    pub service_id: String,
}

/// POST /apps/install — install an app into a customer's container
pub async fn install(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<InstallRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let r = body.into_inner();

    // Verify app exists
    let app = match crate::wolfhost::provisioning::apps::get_app(&r.app_id) {
        Some(a) => a,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Unknown application"})),
    };

    // Verify service belongs to customer and has a container
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == r.service_id && s.customer_id == customer_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Service not found"})),
    };

    if service.container_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Service has no container provisioned"}));
    }

    let container = service.container_name.clone();
    let domain = if service.domain.is_empty() { container.clone() } else { service.domain.clone() };

    // Generate DB credentials if the app needs a database
    let db_name = format!("app_{}", r.app_id);
    let db_user = format!("app_{}", r.app_id);
    let db_pass = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();

    let app_id = r.app_id.clone();
    let app_name = app.name.to_string();
    let resp_db_name = db_name.clone();
    let resp_db_user = db_user.clone();
    let resp_db_pass = db_pass.clone();
    let requires_db = app.requires_db;

    // Run installation in the background
    tokio::spawn(async move {
        log::info!("[{}] Installing {} into container...", container, app_name);
        match crate::wolfhost::provisioning::apps::install_app(&container, &app_id, &domain, &db_name, &db_user, &db_pass) {
            Ok(msg) => log::info!("[{}] {} install complete: {}", container, app_name, msg),
            Err(e) => log::error!("[{}] {} install failed: {}", container, app_name, e),
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "installing",
        "app": app.name,
        "container": service.container_name,
        "message": format!("{} is being installed in the background. This may take a few minutes.", app.name),
        "db_name": if requires_db { &resp_db_name } else { "" },
        "db_user": if requires_db { &resp_db_user } else { "" },
        "db_pass": if requires_db { &resp_db_pass } else { "" },
    }))
}
