//! REST API for WolfStack dashboard and agent communication

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

use crate::monitoring::SystemMonitor;
use crate::installer;
use crate::agent::{ClusterState, AgentMessage};

/// Shared application state
pub struct AppState {
    pub monitor: std::sync::Mutex<SystemMonitor>,
    pub cluster: Arc<ClusterState>,
}

// ─── Dashboard API ───

/// GET /api/metrics — current system metrics
pub async fn get_metrics(state: web::Data<AppState>) -> HttpResponse {
    let metrics = state.monitor.lock().unwrap().collect();
    HttpResponse::Ok().json(metrics)
}

/// GET /api/nodes — all cluster nodes
pub async fn get_nodes(state: web::Data<AppState>) -> HttpResponse {
    let nodes = state.cluster.get_all_nodes();
    HttpResponse::Ok().json(nodes)
}

/// GET /api/nodes/{id} — single node details
pub async fn get_node(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    match state.cluster.get_node(&id) {
        Some(node) => HttpResponse::Ok().json(node),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Node not found"
        })),
    }
}

/// POST /api/nodes — add a server to the cluster
#[derive(Deserialize)]
pub struct AddServerRequest {
    pub address: String,
    pub port: Option<u16>,
}

pub async fn add_node(state: web::Data<AppState>, body: web::Json<AddServerRequest>) -> HttpResponse {
    let port = body.port.unwrap_or(8553);
    let id = state.cluster.add_server(body.address.clone(), port);
    info!("Added server {} at {}:{}", id, body.address, port);
    HttpResponse::Ok().json(serde_json::json!({
        "id": id,
        "address": body.address,
        "port": port
    }))
}

/// DELETE /api/nodes/{id} — remove a server
pub async fn remove_node(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    if state.cluster.remove_server(&id) {
        HttpResponse::Ok().json(serde_json::json!({ "removed": true }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))
    }
}

// ─── Components API ───

/// GET /api/components — status of all components on this node
pub async fn get_components() -> HttpResponse {
    let status = installer::get_all_status();
    HttpResponse::Ok().json(status)
}

/// POST /api/components/{name}/install — install a component
pub async fn install_component(path: web::Path<String>) -> HttpResponse {
    let name = path.into_inner();
    let component = match name.to_lowercase().as_str() {
        "wolfnet" => installer::Component::WolfNet,
        "wolfproxy" => installer::Component::WolfProxy,
        "wolfserve" => installer::Component::WolfServe,
        "wolfdisk" => installer::Component::WolfDisk,
        "wolfscale" => installer::Component::WolfScale,
        "mariadb" => installer::Component::MariaDB,
        "certbot" => installer::Component::Certbot,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unknown component: {}", name)
        })),
    };

    match installer::install_component(component) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Service Control API ───

#[derive(Deserialize)]
pub struct ServiceActionRequest {
    pub action: String,  // start, stop, restart
}

/// POST /api/services/{name}/action — start/stop/restart a service
pub async fn service_action(
    path: web::Path<String>,
    body: web::Json<ServiceActionRequest>,
) -> HttpResponse {
    let service = path.into_inner();
    let result = match body.action.as_str() {
        "start" => installer::start_service(&service),
        "stop" => installer::stop_service(&service),
        "restart" => installer::restart_service(&service),
        _ => Err(format!("Unknown action: {}", body.action)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Certbot API ───

#[derive(Deserialize)]
pub struct CertRequest {
    pub domain: String,
}

/// POST /api/certificates — request a certificate
pub async fn request_certificate(body: web::Json<CertRequest>) -> HttpResponse {
    match installer::request_certificate(&body.domain) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Agent API (server-to-server) ───

/// GET /api/agent/status — return this node's status (for remote polling)
pub async fn agent_status(state: web::Data<AppState>) -> HttpResponse {
    let metrics = state.monitor.lock().unwrap().collect();
    let components = installer::get_all_status();
    let hostname = metrics.hostname.clone();
    let msg = AgentMessage::StatusReport {
        node_id: state.cluster.self_id.clone(),
        hostname,
        metrics,
        components,
    };
    HttpResponse::Ok().json(msg)
}

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Dashboard
        .route("/api/metrics", web::get().to(get_metrics))
        // Cluster
        .route("/api/nodes", web::get().to(get_nodes))
        .route("/api/nodes", web::post().to(add_node))
        .route("/api/nodes/{id}", web::get().to(get_node))
        .route("/api/nodes/{id}", web::delete().to(remove_node))
        // Components
        .route("/api/components", web::get().to(get_components))
        .route("/api/components/{name}/install", web::post().to(install_component))
        // Services
        .route("/api/services/{name}/action", web::post().to(service_action))
        // Certificates
        .route("/api/certificates", web::post().to(request_certificate))
        // Agent
        .route("/api/agent/status", web::get().to(agent_status));
}
