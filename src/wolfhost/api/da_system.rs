//! Admin-side service control + DA system info.
//! Restart Apache / Nginx / Exim / MySQL etc. without SSHing in.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::client_for;

#[derive(Deserialize)]
pub struct InstancePath {
    pub instance_id: String,
}

#[derive(Deserialize)]
pub struct ServiceAction {
    pub service: String,
    /// `start`, `stop`, or `restart`.
    pub action: String,
}

pub async fn list_services(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<InstancePath>,
) -> HttpResponse {
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == path.instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);
    match client.list_services().await {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn service_action(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<InstancePath>,
    body: web::Json<ServiceAction>,
) -> HttpResponse {
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == path.instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);
    let result = match body.action.as_str() {
        "start"   => client.start_service(&body.service).await,
        "stop"    => client.stop_service(&body.service).await,
        "restart" => client.restart_service(&body.service).await,
        _ => return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "action must be one of: start, stop, restart"})),
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": body.action})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn system_info(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<InstancePath>,
) -> HttpResponse {
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == path.instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);
    match client.get_system_info().await {
        Ok(info) => HttpResponse::Ok().json(info),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

/// POST /directadmin/{id}/users/{user}/2fa/disable — admin recovery
/// when a customer has lost their TOTP authenticator.
pub async fn disable_2fa(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (instance_id, da_user) = path.into_inner();
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);
    match client.disable_2fa(&da_user).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "2FA disabled"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
