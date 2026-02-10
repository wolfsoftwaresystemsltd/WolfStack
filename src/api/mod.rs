//! REST API for WolfStack dashboard and agent communication

use actix_web::{web, HttpResponse, HttpRequest, cookie::Cookie};
use serde::Deserialize;
use std::sync::Arc;
use std::process::Command;
use tracing::info;

use crate::monitoring::SystemMonitor;
use crate::installer;
use crate::containers;
use crate::agent::{ClusterState, AgentMessage};
use crate::auth::SessionManager;

/// Shared application state
pub struct AppState {
    pub monitor: std::sync::Mutex<SystemMonitor>,
    pub cluster: Arc<ClusterState>,
    pub sessions: Arc<SessionManager>,
}

// ─── Auth helpers ───

/// Extract session token from cookie
fn get_session_token(req: &HttpRequest) -> Option<String> {
    req.cookie("wolfstack_session")
        .map(|c| c.value().to_string())
}

/// Check if request is authenticated; returns username or error response
fn require_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<String, HttpResponse> {
    match get_session_token(req) {
        Some(token) => {
            match state.sessions.validate(&token) {
                Some(username) => Ok(username),
                None => Err(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Session expired"
                }))),
            }
        }
        None => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        }))),
    }
}

// ─── Auth API ───

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// POST /api/auth/login — authenticate with Linux credentials
pub async fn login(state: web::Data<AppState>, body: web::Json<LoginRequest>) -> HttpResponse {
    if crate::auth::authenticate_user(&body.username, &body.password) {
        let token = state.sessions.create_session(&body.username);
        let cookie = Cookie::build("wolfstack_session", &token)
            .path("/")
            .http_only(true)
            .max_age(actix_web::cookie::time::Duration::hours(8))
            .finish();

        HttpResponse::Ok()
            .cookie(cookie)
            .json(serde_json::json!({
                "success": true,
                "username": body.username
            }))
    } else {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "success": false,
            "error": "Invalid username or password"
        }))
    }
}

/// POST /api/auth/logout — destroy session
pub async fn logout(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Some(token) = get_session_token(&req) {
        state.sessions.destroy(&token);
    }
    let mut cookie = Cookie::build("wolfstack_session", "")
        .path("/")
        .finish();
    cookie.make_removal();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "success": true }))
}

/// GET /api/auth/check — check if session is valid
pub async fn auth_check(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    match require_auth(&req, &state) {
        Ok(username) => HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "username": username
        })),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "authenticated": false
        })),
    }
}

// ─── Dashboard API ───

/// GET /api/metrics — current system metrics
pub async fn get_metrics(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let metrics = state.monitor.lock().unwrap().collect();
    HttpResponse::Ok().json(metrics)
}

/// GET /api/nodes — all cluster nodes
pub async fn get_nodes(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let nodes = state.cluster.get_all_nodes();
    HttpResponse::Ok().json(nodes)
}

/// GET /api/nodes/{id} — single node details
pub async fn get_node(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
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

pub async fn add_node(req: HttpRequest, state: web::Data<AppState>, body: web::Json<AddServerRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
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
pub async fn remove_node(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.cluster.remove_server(&id) {
        HttpResponse::Ok().json(serde_json::json!({ "removed": true }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))
    }
}

// ─── Components API ───

/// GET /api/components — status of all components on this node
pub async fn get_components(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let status = installer::get_all_status();
    HttpResponse::Ok().json(status)
}

/// GET /api/components/{name}/detail — detailed component info with config and logs
pub async fn get_component_detail(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
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

    // Get service status
    let (installed, running, enabled) = installer::check_service(component.service_name());

    // Get config file contents
    let config_path = component.config_path();
    let config_content = if let Some(path) = config_path {
        std::fs::read_to_string(path).ok()
    } else {
        None
    };

    // Get recent journal logs
    let logs = get_service_logs(component.service_name(), 50);

    // Get systemd unit info
    let unit_info = get_unit_info(component.service_name());

    HttpResponse::Ok().json(serde_json::json!({
        "name": component.name(),
        "service": component.service_name(),
        "description": component.description(),
        "installed": installed,
        "running": running,
        "enabled": enabled,
        "config_path": config_path,
        "config": config_content,
        "logs": logs,
        "unit_info": unit_info,
    }))
}

/// PUT /api/components/{name}/config — save component config
#[derive(Deserialize)]
pub struct SaveConfigRequest {
    pub content: String,
}

pub async fn save_component_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SaveConfigRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
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

    let config_path = match component.config_path() {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "This component has no config file"
        })),
    };

    match std::fs::write(config_path, &body.content) {
        Ok(_) => {
            info!("Config saved for {} at {}", component.name(), config_path);
            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Config saved. Restart {} to apply changes.", component.service_name())
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save config: {}", e)
        })),
    }
}

/// POST /api/components/{name}/install — install a component
pub async fn install_component(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
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
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ServiceActionRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
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
pub async fn request_certificate(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CertRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match installer::request_certificate(&body.domain) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Agent API (server-to-server, no auth required) ───

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

// ─── Helpers ───

/// Get recent journal logs for a service
fn get_service_logs(service: &str, lines: u32) -> Vec<String> {
    Command::new("journalctl")
        .args(["-u", service, "--no-pager", "-n", &lines.to_string(), "--output", "short-iso"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Get systemd unit info
fn get_unit_info(service: &str) -> serde_json::Value {
    let get_prop = |prop: &str| -> String {
        Command::new("systemctl")
            .args(["show", service, "-p", prop, "--value"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };

    serde_json::json!({
        "active_state": get_prop("ActiveState"),
        "sub_state": get_prop("SubState"),
        "load_state": get_prop("LoadState"),
        "main_pid": get_prop("MainPID"),
        "memory_current": get_prop("MemoryCurrent"),
        "cpu_usage": get_prop("CPUUsageNSec"),
        "restart_count": get_prop("NRestarts"),
        "active_enter": get_prop("ActiveEnterTimestamp"),
        "description": get_prop("Description"),
    })
}

// ─── Containers API ───

/// GET /api/containers/status — get Docker and LXC runtime status
pub async fn container_runtime_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let docker = containers::docker_status();
    let lxc = containers::lxc_status();
    HttpResponse::Ok().json(serde_json::json!({
        "docker": docker,
        "lxc": lxc,
    }))
}

/// GET /api/containers/docker — list all Docker containers
pub async fn docker_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let containers = containers::docker_list_all();
    HttpResponse::Ok().json(containers)
}

/// GET /api/containers/docker/stats — Docker container stats
pub async fn docker_stats(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let stats = containers::docker_stats();
    HttpResponse::Ok().json(stats)
}

/// GET /api/containers/docker/images — list Docker images
pub async fn docker_images(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let images = containers::docker_images();
    HttpResponse::Ok().json(images)
}

/// GET /api/containers/docker/{id}/logs — get Docker container logs
pub async fn docker_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let logs = containers::docker_logs(&id, 100);
    HttpResponse::Ok().json(serde_json::json!({ "logs": logs }))
}

#[derive(Deserialize)]
pub struct ContainerActionRequest {
    pub action: String,  // start, stop, restart, remove, pause, unpause
}

/// POST /api/containers/docker/{id}/action — control Docker container
pub async fn docker_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ContainerActionRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let result = match body.action.as_str() {
        "start" => containers::docker_start(&id),
        "stop" => containers::docker_stop(&id),
        "restart" => containers::docker_restart(&id),
        "remove" => containers::docker_remove(&id),
        "pause" => containers::docker_pause(&id),
        "unpause" => containers::docker_unpause(&id),
        _ => Err(format!("Unknown action: {}", body.action)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/lxc — list all LXC containers
pub async fn lxc_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let containers = containers::lxc_list_all();
    HttpResponse::Ok().json(containers)
}

/// GET /api/containers/lxc/stats — LXC container stats
pub async fn lxc_stats(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let stats = containers::lxc_stats();
    HttpResponse::Ok().json(stats)
}

/// GET /api/containers/lxc/{name}/logs — get LXC container logs
pub async fn lxc_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let logs = containers::lxc_logs(&name, 100);
    HttpResponse::Ok().json(serde_json::json!({ "logs": logs }))
}

/// GET /api/containers/lxc/{name}/config — get LXC container config
pub async fn lxc_config(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_config(&name) {
        Some(content) => HttpResponse::Ok().json(serde_json::json!({ "config": content })),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Config not found" })),
    }
}

/// PUT /api/containers/lxc/{name}/config — save LXC container config
pub async fn lxc_save_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SaveConfigRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_save_config(&name, &body.content) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/lxc/{name}/action — control LXC container
pub async fn lxc_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ContainerActionRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let result = match body.action.as_str() {
        "start" => containers::lxc_start(&name),
        "stop" => containers::lxc_stop(&name),
        "restart" => containers::lxc_restart(&name),
        "freeze" => containers::lxc_freeze(&name),
        "unfreeze" => containers::lxc_unfreeze(&name),
        "destroy" => containers::lxc_destroy(&name),
        _ => Err(format!("Unknown action: {}", body.action)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct InstallRuntimeRequest {
    pub runtime: String,  // docker or lxc
}

/// POST /api/containers/install — install Docker or LXC
pub async fn install_container_runtime(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InstallRuntimeRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let result = match body.runtime.as_str() {
        "docker" => containers::install_docker(),
        "lxc" => containers::install_lxc(),
        _ => Err(format!("Unknown runtime: {}", body.runtime)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Auth (no auth required)
        .route("/api/auth/login", web::post().to(login))
        .route("/api/auth/logout", web::post().to(logout))
        .route("/api/auth/check", web::get().to(auth_check))
        // Dashboard
        .route("/api/metrics", web::get().to(get_metrics))
        // Cluster
        .route("/api/nodes", web::get().to(get_nodes))
        .route("/api/nodes", web::post().to(add_node))
        .route("/api/nodes/{id}", web::get().to(get_node))
        .route("/api/nodes/{id}", web::delete().to(remove_node))
        // Components
        .route("/api/components", web::get().to(get_components))
        .route("/api/components/{name}/detail", web::get().to(get_component_detail))
        .route("/api/components/{name}/config", web::put().to(save_component_config))
        .route("/api/components/{name}/install", web::post().to(install_component))
        // Services
        .route("/api/services/{name}/action", web::post().to(service_action))
        // Certificates
        .route("/api/certificates", web::post().to(request_certificate))
        // Containers
        .route("/api/containers/status", web::get().to(container_runtime_status))
        .route("/api/containers/install", web::post().to(install_container_runtime))
        // Docker
        .route("/api/containers/docker", web::get().to(docker_list))
        .route("/api/containers/docker/stats", web::get().to(docker_stats))
        .route("/api/containers/docker/images", web::get().to(docker_images))
        .route("/api/containers/docker/{id}/logs", web::get().to(docker_logs))
        .route("/api/containers/docker/{id}/action", web::post().to(docker_action))
        // LXC
        .route("/api/containers/lxc", web::get().to(lxc_list))
        .route("/api/containers/lxc/stats", web::get().to(lxc_stats))
        .route("/api/containers/lxc/{name}/logs", web::get().to(lxc_logs))
        .route("/api/containers/lxc/{name}/config", web::get().to(lxc_config))
        .route("/api/containers/lxc/{name}/config", web::put().to(lxc_save_config))
        .route("/api/containers/lxc/{name}/action", web::post().to(lxc_action))
        // Agent (no auth — used by other WolfStack nodes)
        .route("/api/agent/status", web::get().to(agent_status));
}
