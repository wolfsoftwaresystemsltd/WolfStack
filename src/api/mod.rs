//! REST API for WolfStack dashboard and agent communication

use actix_web::{web, HttpResponse, HttpRequest, cookie::Cookie};
use serde::Deserialize;
use std::sync::Arc;
use std::process::Command;
use tracing::info;

use crate::monitoring::SystemMonitor;
use crate::installer;
use crate::containers;
use crate::storage;
use crate::networking;
use crate::agent::{ClusterState, AgentMessage};
use crate::auth::SessionManager;

mod console;

/// Shared application state
pub struct AppState {
    pub monitor: std::sync::Mutex<SystemMonitor>,
    pub cluster: Arc<ClusterState>,
    pub sessions: Arc<SessionManager>,
    pub vms: std::sync::Mutex<crate::vms::manager::VmManager>,
    pub cluster_secret: String,
}

// ─── Auth helpers ───

/// Extract session token from cookie
fn get_session_token(req: &HttpRequest) -> Option<String> {
    req.cookie("wolfstack_session")
        .map(|c| c.value().to_string())
}

/// Check if request is authenticated; returns username or error response
pub fn require_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<String, HttpResponse> {
    // Accept internal requests from other WolfStack nodes if they provide the cluster secret
    if let Some(val) = req.headers().get("X-WolfStack-Secret") {
        let provided = val.to_str().unwrap_or("");
        if crate::auth::validate_cluster_secret(provided, &state.cluster_secret) {
            return Ok("cluster-node".to_string());
        }
        // Invalid secret — do NOT fall through to session auth
        return Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid cluster secret"
        })));
    }
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

/// Require cluster secret authentication for inter-node endpoints
pub fn require_cluster_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<(), HttpResponse> {
    match req.headers().get("X-WolfStack-Secret") {
        Some(val) => {
            let provided = val.to_str().unwrap_or("");
            if crate::auth::validate_cluster_secret(provided, &state.cluster_secret) {
                Ok(())
            } else {
                Err(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Invalid cluster secret"
                })))
            }
        }
        None => Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Cluster authentication required"
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
pub async fn agent_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let metrics = state.monitor.lock().unwrap().collect();
    let components = installer::get_all_status();
    let hostname = metrics.hostname.clone();
    let docker_count = containers::docker_list_all().len() as u32;
    let lxc_count = containers::lxc_list_all().len() as u32;
    let vm_count = state.vms.lock().unwrap().list_vms().len() as u32;
    let msg = AgentMessage::StatusReport {
        node_id: state.cluster.self_id.clone(),
        hostname,
        metrics,
        components,
        docker_count,
        lxc_count,
        vm_count,
    };
    HttpResponse::Ok().json(msg)
}

/// GET/POST /api/nodes/{id}/proxy/{path:.*} — proxy API calls to a remote node
pub async fn node_proxy(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Bytes,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let (node_id, api_path) = path.into_inner();

    // Find the node
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Node not found"})),
    };

    // If it's the local node, tell frontend to use local API
    if node.is_self {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Use local API for self node"}));
    }

    // Forward to remote node
    let url = format!("http://{}:{}/api/{}", node.address, node.port, api_path);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let method = req.method().clone();
    let mut builder = match method {
        actix_web::http::Method::GET => client.get(&url),
        actix_web::http::Method::POST => client.post(&url),
        actix_web::http::Method::PUT => client.put(&url),
        actix_web::http::Method::DELETE => client.delete(&url),
        _ => client.get(&url),
    };

    // Forward content-type and body
    if let Some(ct) = req.headers().get("content-type") {
        builder = builder.header("content-type", ct.to_str().unwrap_or("application/json"));
    }
    // Cluster secret — remote node validates this instead of session cookie
    builder = builder.header("X-WolfStack-Secret", state.cluster_secret.clone());
    if !body.is_empty() {
        builder = builder.body(body.to_vec());
    }

    match builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.bytes().await {
                Ok(bytes) => HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK))
                    .content_type("application/json")
                    .body(bytes.to_vec()),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Read error: {}", e)})),
            }
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": format!("Proxy error: {}. Is WolfStack running on {}:{}?", e, node.address, node.port)})),
    }
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

/// GET /api/containers/docker/search?q=<query> — search Docker Hub
pub async fn docker_search(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let q = query.get("q").cloned().unwrap_or_default();
    if q.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing query parameter 'q'" }));
    }
    let results = containers::docker_search(&q);
    HttpResponse::Ok().json(results)
}

#[derive(Deserialize)]
pub struct DockerPullRequest {
    pub image: String,
}

/// POST /api/containers/docker/pull — pull a Docker image
pub async fn docker_pull(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DockerPullRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match containers::docker_pull(&body.image) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct DockerCreateRequest {
    pub name: String,
    pub image: String,
    pub ports: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub wolfnet_ip: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_cores: Option<String>,
    pub storage_limit: Option<String>,
    /// Volume mounts: ["host:container", "volume_name:/data", ...]
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// POST /api/containers/docker/create — create a Docker container
pub async fn docker_create(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DockerCreateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let ports = body.ports.as_deref().unwrap_or(&[]);
    let env = body.env.as_deref().unwrap_or(&[]);
    let wolfnet_ip = body.wolfnet_ip.as_deref();
    let memory = body.memory_limit.as_deref();
    let cpus = body.cpu_cores.as_deref();
    let storage = body.storage_limit.as_deref();
    match containers::docker_create(&body.name, &body.image, ports, env, wolfnet_ip, memory, cpus, storage, &body.volumes) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/lxc/templates — list available LXC templates
pub async fn lxc_templates(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let templates = containers::lxc_list_templates();
    HttpResponse::Ok().json(templates)
}

#[derive(Deserialize)]
pub struct LxcCreateRequest {
    pub name: String,
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub wolfnet_ip: Option<String>,
    pub storage_path: Option<String>,
    pub root_password: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_cores: Option<String>,
}

/// POST /api/containers/lxc/create — create an LXC container from template
pub async fn lxc_create(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LxcCreateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let storage = body.storage_path.as_deref();
    match containers::lxc_create(&body.name, &body.distribution, &body.release, &body.architecture, storage) {
        Ok(msg) => {
            let mut messages = vec![msg];

            // Set root password if provided
            if let Some(ref password) = body.root_password {
                if !password.is_empty() {
                    match containers::lxc_set_root_password(&body.name, password) {
                        Ok(pw_msg) => messages.push(pw_msg),
                        Err(e) => messages.push(format!("Password warning: {}", e)),
                    }
                }
            }

            // Set resource limits if provided
            let memory = body.memory_limit.as_deref();
            let cpus = body.cpu_cores.as_deref();
            match containers::lxc_set_resource_limits(&body.name, memory, cpus) {
                Ok(Some(rl_msg)) => messages.push(rl_msg),
                Err(e) => messages.push(format!("Resource limit warning: {}", e)),
                _ => {}
            }

            // Attach WolfNet if requested
            if let Some(ip) = &body.wolfnet_ip {
                if !ip.is_empty() {
                    match containers::lxc_attach_wolfnet(&body.name, ip) {
                        Ok(wn_msg) => messages.push(wn_msg),
                        Err(e) => messages.push(format!("WolfNet warning: {}", e)),
                    }
                }
            }

            HttpResponse::Ok().json(serde_json::json!({ "message": messages.join(" — ") }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfnet/status — get WolfNet networking status for container creation
/// Queries all cluster nodes for used IPs to avoid collisions
pub async fn wolfnet_network_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Collect used IPs from all remote cluster nodes
    let mut remote_used: Vec<u8> = Vec::new();
    let nodes = state.cluster.get_all_nodes();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    for node in &nodes {
        if node.is_self || !node.online { continue; }
        let url = format!("http://{}:{}/api/wolfnet/used-ips", node.address, node.port);
        if let Ok(resp) = client.get(&url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .send().await {
            if let Ok(ips) = resp.json::<Vec<String>>().await {
                for ip_str in ips {
                    let parts: Vec<&str> = ip_str.split('.').collect();
                    if parts.len() == 4 {
                        if let Ok(last) = parts[3].parse::<u8>() {
                            remote_used.push(last);
                        }
                    }
                }
            }
        }
    }

    let status = containers::wolfnet_status(&remote_used);
    HttpResponse::Ok().json(status)
}

/// GET /api/wolfnet/used-ips — returns WolfNet IPs in use on this node (cluster-internal)
pub async fn wolfnet_used_ips_endpoint(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let ips = containers::wolfnet_used_ips();
    HttpResponse::Ok().json(ips)
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

/// DELETE /api/containers/docker/images/{id} — remove a Docker image
pub async fn docker_remove_image(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match containers::docker_remove_image(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
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

#[derive(Deserialize)]
pub struct CloneRequest {
    pub new_name: String,
    pub snapshot: Option<bool>,  // LXC only — use copy-on-write clone
}

#[derive(Deserialize)]
pub struct MigrateRequest {
    pub target_url: String,
    pub remove_source: Option<bool>,
}

/// POST /api/containers/docker/{id}/clone — clone a Docker container
pub async fn docker_clone(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CloneRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match containers::docker_clone(&id, &body.new_name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/docker/{id}/migrate — migrate a Docker container to another node
pub async fn docker_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let remove = body.remove_source.unwrap_or(false);
    match containers::docker_migrate(&id, &body.target_url, remove) {
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

/// POST /api/containers/lxc/{name}/clone — clone an LXC container
pub async fn lxc_clone(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CloneRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let result = if body.snapshot.unwrap_or(false) {
        containers::lxc_clone_snapshot(&name, &body.new_name)
    } else {
        containers::lxc_clone(&name, &body.new_name)
    };
    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Mount / Volume Management Endpoints ───

/// GET /api/containers/docker/{id}/volumes — list Docker container volumes
pub async fn docker_volumes(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mounts = containers::docker_list_volumes(&id);
    HttpResponse::Ok().json(mounts)
}

/// GET /api/containers/lxc/{name}/mounts — list LXC container bind mounts
pub async fn lxc_mounts(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let mounts = containers::lxc_list_mounts(&name);
    HttpResponse::Ok().json(mounts)
}

#[derive(Deserialize)]
pub struct AddMountRequest {
    pub host_path: String,
    pub container_path: String,
    #[serde(default)]
    pub read_only: bool,
}

/// POST /api/containers/lxc/{name}/mounts — add bind mount to LXC container
pub async fn lxc_add_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AddMountRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_add_mount(&name, &body.host_path, &body.container_path, body.read_only) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct RemoveMountRequest {
    pub host_path: String,
}

/// DELETE /api/containers/lxc/{name}/mounts — remove bind mount from LXC container
pub async fn lxc_remove_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RemoveMountRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_remove_mount(&name, &body.host_path) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/docker/import — receive a migrated container image
/// Accepts the tar file as raw body bytes, container name via query param
pub async fn docker_import(
    _req: HttpRequest,
    body: web::Bytes,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    // No auth — this is for inter-node communication during migration
    let container_name = query.get("name")
        .cloned()
        .unwrap_or_else(|| format!("migrated-{}", chrono::Utc::now().timestamp()));

    // Save to temp file
    let tar_path = format!("/tmp/wolfstack-import-{}.tar", container_name);
    if let Err(e) = std::fs::write(&tar_path, &body) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save import file: {}", e)
        }));
    }

    match containers::docker_import_image(&tar_path, &container_name) {
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

#[derive(Deserialize)]
pub struct InstallComponentInContainerRequest {
    pub runtime: String,    // docker or lxc
    pub container: String,  // container name
    pub component: String,  // wolfnet, wolfproxy, etc.
}

/// POST /api/containers/install-component — install a Wolf component inside a container
async fn install_component_in_container(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InstallComponentInContainerRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let runtime = body.runtime.clone();
    let container = body.container.clone();
    let component = body.component.clone();

    // Run in blocking thread since it may take a while
    let result = web::block(move || {
        containers::install_component_in_container(&runtime, &container, &component)
    }).await;

    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// GET /api/containers/running — list all running containers for component install UI
async fn list_running_containers(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let containers = containers::list_running_containers();
    let list: Vec<serde_json::Value> = containers.into_iter().map(|(runtime, name, image)| {
        serde_json::json!({
            "runtime": runtime,
            "name": name,
            "image": image
        })
    }).collect();
    HttpResponse::Ok().json(list)
}

// ─── Networking API ───

/// GET /api/networking/interfaces — list all network interfaces
pub async fn net_list_interfaces(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::list_interfaces())
}

/// GET /api/networking/dns — get DNS configuration
pub async fn net_get_dns(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::get_dns())
}

#[derive(Deserialize)]
pub struct DnsSetRequest {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
}

/// POST /api/networking/dns — set DNS configuration
pub async fn net_set_dns(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<DnsSetRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::set_dns(body.nameservers.clone(), body.search_domains.clone()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet — get WolfNet overlay status
pub async fn net_get_wolfnet(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::get_wolfnet_status())
}

/// GET /api/networking/wolfnet/config — get raw WolfNet config
pub async fn net_get_wolfnet_config(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::get_wolfnet_config() {
        Ok(config) => HttpResponse::Ok().json(serde_json::json!({"config": config})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetConfigSave {
    pub config: String,
}

/// PUT /api/networking/wolfnet/config — save raw WolfNet config
pub async fn net_save_wolfnet_config(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetConfigSave>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::save_wolfnet_config(&body.config) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetAddPeer {
    pub name: String,
    pub endpoint: Option<String>,
    pub ip: Option<String>,
    pub public_key: Option<String>,
}

/// POST /api/networking/wolfnet/peers — add a WolfNet peer
pub async fn net_add_wolfnet_peer(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetAddPeer>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let endpoint = body.endpoint.as_deref().unwrap_or("");
    let ip = body.ip.as_deref().unwrap_or("");
    let public_key = body.public_key.as_deref();
    match networking::add_wolfnet_peer(&body.name, endpoint, ip, public_key) {
        Ok(msg) => {
            let local_info = networking::get_wolfnet_local_info();
            HttpResponse::Ok().json(serde_json::json!({
                "message": msg,
                "local_info": local_info,
            }))
        },
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet/local-info — get this node's WolfNet identity
pub async fn net_get_wolfnet_local_info(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::get_wolfnet_local_info() {
        Some(info) => HttpResponse::Ok().json(info),
        None => HttpResponse::Ok().json(serde_json::json!({"error": "WolfNet not running or status unavailable"})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetRemovePeer {
    pub name: String,
}

/// DELETE /api/networking/wolfnet/peers — remove a WolfNet peer
pub async fn net_remove_wolfnet_peer(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetRemovePeer>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::remove_wolfnet_peer(&body.name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetAction {
    pub action: String,
}

/// POST /api/networking/wolfnet/action — start/stop/restart WolfNet
pub async fn net_wolfnet_action(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetAction>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let allowed = ["start", "stop", "restart", "enable", "disable"];
    if !allowed.contains(&body.action.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid action"}));
    }
    match networking::wolfnet_service_action(&body.action) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet/invite — generate a WolfNet invite token
pub async fn net_wolfnet_invite(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::generate_wolfnet_invite() {
        Ok(invite) => HttpResponse::Ok().json(invite),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet/status-full — get full status including live peers
pub async fn net_wolfnet_status_full(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::get_wolfnet_status_full())
}

#[derive(Deserialize)]
pub struct IpAction {
    pub address: String,
    pub prefix: u32,
}

/// POST /api/networking/interfaces/{name}/ip — add an IP address
pub async fn net_add_ip(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<IpAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::add_ip(&iface, &body.address, body.prefix) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/networking/interfaces/{name}/ip — remove an IP address
pub async fn net_remove_ip(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<IpAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::remove_ip(&iface, &body.address, body.prefix) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct InterfaceStateAction {
    pub up: bool,
}

/// POST /api/networking/interfaces/{name}/state — bring interface up/down
pub async fn net_set_state(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<InterfaceStateAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::set_interface_state(&iface, body.up) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct MtuAction {
    pub mtu: u32,
}

/// POST /api/networking/interfaces/{name}/mtu — set interface MTU
pub async fn net_set_mtu(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<MtuAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::set_mtu(&iface, body.mtu) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct CreateVlanRequest {
    pub parent: String,
    pub vlan_id: u32,
    pub name: Option<String>,
}

/// POST /api/networking/vlans — create a VLAN
pub async fn net_create_vlan(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateVlanRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::create_vlan(&body.parent, body.vlan_id, body.name.as_deref()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/networking/vlans/{name} — delete a VLAN
pub async fn net_delete_vlan(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let name = path.into_inner();
    match networking::delete_vlan(&name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

// ─── Storage Manager API ───

/// GET /api/storage/mounts — list all storage mounts with live status
pub async fn storage_list_mounts(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::list_mounts())
}

/// GET /api/storage/available — list mounted storage suitable for container attachment
pub async fn storage_available_mounts(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::available_mounts())
}

#[derive(Deserialize)]
pub struct CreateMountRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub mount_type: storage::MountType,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub mount_point: String,
    #[serde(default)]
    pub global: bool,
    #[serde(default)]
    pub auto_mount: bool,
    #[serde(default)]
    pub s3_config: Option<storage::S3Config>,
    #[serde(default)]
    pub nfs_options: Option<String>,
    #[serde(default = "default_do_mount")]
    pub do_mount: bool,
}

fn default_do_mount() -> bool { true }

/// POST /api/storage/mounts — create a new storage mount
pub async fn storage_create_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CreateMountRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    
    let mount = storage::StorageMount {
        id: String::new(),
        name: body.name.clone(),
        mount_type: body.mount_type.clone(),
        source: body.source.clone(),
        mount_point: body.mount_point.clone(),
        enabled: true,
        global: body.global,
        auto_mount: body.auto_mount,
        s3_config: body.s3_config.clone(),
        nfs_options: body.nfs_options.clone(),
        status: "unmounted".to_string(),
        error_message: None,
        created_at: String::new(),
    };
    
    let do_mount = body.do_mount;
    // Run on blocking threadpool — mount_s3_via_rust_s3 creates a nested tokio runtime
    // which panics if called directly from an async context
    let result = web::block(move || storage::create_mount(mount, do_mount)).await;
    match result {
        Ok(Ok(created)) => {
            // If global, sync to cluster nodes
            if created.global {
                let _ = sync_mount_to_cluster(&state, &created).await;
            }
            HttpResponse::Ok().json(created)
        }
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// PUT /api/storage/mounts/{id} — update a mount
pub async fn storage_update_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match storage::update_mount(&id, body.into_inner()) {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/storage/mounts/{id} — remove a mount
pub async fn storage_remove_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match storage::remove_mount(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/duplicate — clone a mount entry
pub async fn storage_duplicate_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match storage::duplicate_mount(&id) {
        Ok(dup) => HttpResponse::Ok().json(dup),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/mount — mount a storage entry
pub async fn storage_do_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    // Run on blocking threadpool — mount_s3_via_rust_s3 creates a nested tokio runtime
    // which panics if called directly from an async context
    let result = web::block(move || storage::mount_storage(&id)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// POST /api/storage/mounts/{id}/unmount — unmount a storage entry
pub async fn storage_do_unmount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    let result = web::block(move || storage::unmount_storage(&id)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

#[derive(Deserialize)]
pub struct ImportRcloneRequest {
    pub config: String,
}

/// POST /api/storage/import-rclone — import S3 remotes from rclone.conf content
pub async fn storage_import_rclone(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ImportRcloneRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    
    match storage::import_rclone_config(&body.config) {
        Ok(mounts) => {
            let mut created = Vec::new();
            for mount in mounts {
                match storage::create_mount(mount, false) {
                    Ok(m) => created.push(m),
                    Err(e) => {
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": e,
                            "created": created
                        }));
                    }
                }
            }
            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Imported {} S3 remotes", created.len()),
                "mounts": created
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/sync — sync a global mount to all cluster nodes
pub async fn storage_sync_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    
    let config = storage::load_config();
    let mount = match config.mounts.iter().find(|m| m.id == id) {
        Some(m) => m.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Mount not found" })),
    };
    
    match sync_mount_to_cluster(&state, &mount).await {
        Ok(results) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Sync complete",
            "results": results
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/sync-s3 — sync local changes back to S3 bucket
pub async fn storage_sync_s3(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    
    // Run in blocking thread since S3 upload may take a while
    let result = web::block(move || {
        storage::sync_to_s3(&id)
    }).await;
    
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// POST /api/agent/storage/apply — receive and apply a mount config from another node (cluster-auth)
pub async fn agent_storage_apply(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<storage::StorageMount>,
) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let mount = body.into_inner();
    match storage::create_mount(mount, true) {
        Ok(m) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Mount applied",
            "mount": m
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Helper: push a mount config to all remote cluster nodes
async fn sync_mount_to_cluster(
    state: &web::Data<AppState>,
    mount: &storage::StorageMount,
) -> Result<Vec<serde_json::Value>, String> {
    let nodes = state.cluster.get_all_nodes();
    let mut results = Vec::new();
    
    for node in &nodes {
        if node.is_self { continue; }
        let url = format!("http://{}:{}/api/agent/storage/apply", node.address, node.port);
        let client = reqwest::Client::new();
        match client.post(&url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .json(mount)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                results.push(serde_json::json!({
                    "node": node.hostname,
                    "status": status,
                    "response": body
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "node": node.hostname,
                    "status": "error",
                    "response": e.to_string()
                }));
            }
        }
    }
    
    Ok(results)
}

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .configure(crate::vms::api::config)
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
        .route("/api/containers/install-component", web::post().to(install_component_in_container))
        .route("/api/containers/running", web::get().to(list_running_containers))
        // Docker
        .route("/api/containers/docker", web::get().to(docker_list))
        .route("/api/containers/docker/search", web::get().to(docker_search))
        .route("/api/containers/docker/pull", web::post().to(docker_pull))
        .route("/api/containers/docker/create", web::post().to(docker_create))
        .route("/api/containers/docker/stats", web::get().to(docker_stats))
        .route("/api/containers/docker/images", web::get().to(docker_images))
        .route("/api/containers/docker/images/{id}", web::delete().to(docker_remove_image))
        .route("/api/containers/docker/{id}/logs", web::get().to(docker_logs))
        .route("/api/containers/docker/{id}/action", web::post().to(docker_action))
        .route("/api/containers/docker/{id}/clone", web::post().to(docker_clone))
        .route("/api/containers/docker/{id}/migrate", web::post().to(docker_migrate))
        .route("/api/containers/docker/{id}/volumes", web::get().to(docker_volumes))
        .route("/api/containers/docker/import", web::post().to(docker_import))
        // LXC
        .route("/api/containers/lxc", web::get().to(lxc_list))
        .route("/api/containers/lxc/templates", web::get().to(lxc_templates))
        .route("/api/containers/lxc/create", web::post().to(lxc_create))
        .route("/api/containers/lxc/stats", web::get().to(lxc_stats))
        .route("/api/containers/lxc/{name}/logs", web::get().to(lxc_logs))
        .route("/api/containers/lxc/{name}/config", web::get().to(lxc_config))
        .route("/api/containers/lxc/{name}/config", web::put().to(lxc_save_config))
        .route("/api/containers/lxc/{name}/action", web::post().to(lxc_action))
        .route("/api/containers/lxc/{name}/clone", web::post().to(lxc_clone))
        .route("/api/containers/lxc/{name}/mounts", web::get().to(lxc_mounts))
        .route("/api/containers/lxc/{name}/mounts", web::post().to(lxc_add_mount))
        .route("/api/containers/lxc/{name}/mounts", web::delete().to(lxc_remove_mount))
        // WolfNet
        .route("/api/wolfnet/status", web::get().to(wolfnet_network_status))
        // Storage Manager
        .route("/api/storage/mounts", web::get().to(storage_list_mounts))
        .route("/api/storage/mounts", web::post().to(storage_create_mount))
        .route("/api/storage/available", web::get().to(storage_available_mounts))
        .route("/api/storage/import-rclone", web::post().to(storage_import_rclone))
        .route("/api/storage/mounts/{id}", web::put().to(storage_update_mount))
        .route("/api/storage/mounts/{id}", web::delete().to(storage_remove_mount))
        .route("/api/storage/mounts/{id}/duplicate", web::post().to(storage_duplicate_mount))
        .route("/api/storage/mounts/{id}/mount", web::post().to(storage_do_mount))
        .route("/api/storage/mounts/{id}/unmount", web::post().to(storage_do_unmount))
        .route("/api/storage/mounts/{id}/sync", web::post().to(storage_sync_mount))
        .route("/api/storage/mounts/{id}/sync-s3", web::post().to(storage_sync_s3))
        // Networking
        .route("/api/networking/interfaces", web::get().to(net_list_interfaces))
        .route("/api/networking/dns", web::get().to(net_get_dns))
        .route("/api/networking/dns", web::post().to(net_set_dns))
        .route("/api/networking/wolfnet", web::get().to(net_get_wolfnet))
        .route("/api/networking/wolfnet/config", web::get().to(net_get_wolfnet_config))
        .route("/api/networking/wolfnet/config", web::put().to(net_save_wolfnet_config))
        .route("/api/networking/wolfnet/peers", web::post().to(net_add_wolfnet_peer))
        .route("/api/networking/wolfnet/peers", web::delete().to(net_remove_wolfnet_peer))
        .route("/api/networking/wolfnet/local-info", web::get().to(net_get_wolfnet_local_info))
        .route("/api/networking/wolfnet/action", web::post().to(net_wolfnet_action))
        .route("/api/networking/wolfnet/invite", web::get().to(net_wolfnet_invite))
        .route("/api/networking/wolfnet/status-full", web::get().to(net_wolfnet_status_full))
        .route("/api/networking/interfaces/{name}/ip", web::post().to(net_add_ip))
        .route("/api/networking/interfaces/{name}/ip", web::delete().to(net_remove_ip))
        .route("/api/networking/interfaces/{name}/state", web::post().to(net_set_state))
        .route("/api/networking/interfaces/{name}/mtu", web::post().to(net_set_mtu))
        .route("/api/networking/vlans", web::post().to(net_create_vlan))
        .route("/api/networking/vlans/{name}", web::delete().to(net_delete_vlan))
        // Console WebSocket
        .route("/ws/console/{type}/{name}", web::get().to(console::console_ws))
        // Agent (cluster-secret auth — inter-node communication)
        .route("/api/agent/status", web::get().to(agent_status))
        .route("/api/agent/storage/apply", web::post().to(agent_storage_apply))
        .route("/api/wolfnet/used-ips", web::get().to(wolfnet_used_ips_endpoint))
        // Node proxy — forward API calls to remote nodes (must be last — wildcard path)
        .route("/api/nodes/{id}/proxy/{path:.*}", web::get().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::post().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::put().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::delete().to(node_proxy));
}
