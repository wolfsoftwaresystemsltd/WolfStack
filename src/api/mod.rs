// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! REST API for WolfStack dashboard and agent communication

use actix_web::{web, HttpResponse, HttpRequest, cookie::Cookie};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::process::Command;
use tracing::{info, warn, error};

use crate::monitoring::{SystemMonitor, MetricsHistory};
use crate::installer;
use crate::containers;
use crate::storage;
use crate::networking;
use crate::backup;
use crate::agent::{ClusterState, AgentMessage};
use crate::auth::SessionManager;
use crate::appstore;


mod pve_console;

/// Build ordered URLs to try for inter-node communication.
/// Tries: HTTPS on main port, HTTP on internal port (port+1), HTTP on main port.
/// This ensures both TLS-enabled and HTTP-only nodes are reachable.
pub fn build_node_urls(address: &str, port: u16, path: &str) -> Vec<String> {
    vec![
        format!("https://{}:{}{}", address, port, path),
        format!("http://{}:{}{}", address, port + 1, path),
        format!("http://{}:{}{}", address, port, path),
    ]
}

/// Progress state for PBS restore operations
#[derive(Clone, Serialize, Default)]
pub struct PbsRestoreProgress {
    pub active: bool,
    pub snapshot: String,
    pub progress_text: String,
    pub percentage: Option<f64>,
    pub finished: bool,
    pub success: Option<bool>,
    pub message: String,
    #[serde(skip)]
    pub started_at: Option<std::time::Instant>,
}

/// Shared application state
pub struct AppState {
    pub monitor: std::sync::Mutex<SystemMonitor>,
    pub metrics_history: std::sync::Mutex<MetricsHistory>,
    pub cluster: Arc<ClusterState>,
    pub sessions: Arc<SessionManager>,
    pub vms: std::sync::Mutex<crate::vms::manager::VmManager>,
    pub cluster_secret: String,
    pub join_token: String,
    pub pbs_restore_progress: std::sync::Mutex<PbsRestoreProgress>,
    pub ai_agent: Arc<crate::ai::AiAgent>,
    /// Pre-built agent status response, updated every 2s by background task
    pub cached_status: Arc<std::sync::RwLock<Option<serde_json::Value>>>,
    /// WolfRun orchestration state
    pub wolfrun: Arc<crate::wolfrun::WolfRunState>,
}

/// Load or generate the join token from /etc/wolfstack/join-token
pub fn load_join_token() -> String {
    let path = std::path::Path::new("/etc/wolfstack/join-token");
    if let Ok(token) = std::fs::read_to_string(path) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            info!("Loaded join token from {}", path.display());
            return token;
        }
    }
    // Generate a new token
    use std::fmt::Write;
    let mut token = String::with_capacity(64);
    let random_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        // Use /dev/urandom for cryptographic randomness
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = f.read_exact(&mut buf);
        } else {
            // Fallback: use system time + pid
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let seed = t.as_nanos() ^ (std::process::id() as u128);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((seed >> (i % 16 * 8)) & 0xFF) as u8 ^ (i as u8).wrapping_mul(37);
            }
        }
        buf
    };
    for b in &random_bytes {
        let _ = write!(token, "{:02x}", b);
    }
    // Save it
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    if let Err(e) = std::fs::write(path, &token) {
        warn!("Could not save join token to {}: {}", path.display(), e);
    } else {
        info!("Generated new join token and saved to {}", path.display());
    }
    token
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
    // Check if direct login is disabled on this node
    {
        let nodes = state.cluster.nodes.read().unwrap();
        if let Some(self_node) = nodes.get(&state.cluster.self_id) {
            if self_node.login_disabled {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "success": false,
                    "error": "Direct login is disabled on this server. Access it via the primary dashboard."
                }));
            }
        }
    }
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

/// GET /api/settings/login-disabled — check if direct login is disabled (no auth needed)
pub async fn login_disabled_status(state: web::Data<AppState>) -> HttpResponse {
    let disabled = {
        let nodes = state.cluster.nodes.read().unwrap();
        nodes.get(&state.cluster.self_id).map(|n| n.login_disabled).unwrap_or(false)
    };
    HttpResponse::Ok().json(serde_json::json!({ "login_disabled": disabled }))
}

/// POST /api/settings/login-disabled — set login_disabled on this node (cluster-auth required)
pub async fn set_login_disabled(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    // Accept both cluster auth (from remote dashboard) and session auth (local admin)
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let disabled = body.get("login_disabled").and_then(|v| v.as_bool()).unwrap_or(false);
    {
        let mut nodes = state.cluster.nodes.write().unwrap();
        if let Some(node) = nodes.get_mut(&state.cluster.self_id) {
            node.login_disabled = disabled;
        }
    }
    // Persist to disk
    crate::agent::ClusterState::save_login_disabled_file(disabled);
    info!("Login disabled set to {} via API", disabled);
    HttpResponse::Ok().json(serde_json::json!({ "login_disabled": disabled }))
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

/// GET /api/metrics/history — historical CPU, RAM, disk metrics
pub async fn get_metrics_history(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let history = state.metrics_history.lock().unwrap();
    HttpResponse::Ok().json(history.get_all())
}

/// GET /api/nodes — all cluster nodes
pub async fn get_nodes(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let nodes = state.cluster.get_all_nodes();
    HttpResponse::Ok().json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "nodes": nodes,
    }))
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

/// GET /api/auth/join-token — display this server's join token (session-auth required)
pub async fn get_join_token(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(serde_json::json!({
        "join_token": state.join_token,
    }))
}

/// GET /api/cluster/verify-token?token=xxx — verify a join token (unauthenticated, called by remote servers)
pub async fn verify_join_token(state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let provided = query.get("token").map(|s| s.as_str()).unwrap_or("");
    if provided.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing token parameter" }));
    }
    if provided == state.join_token {
        HttpResponse::Ok().json(serde_json::json!({
            "valid": true,
            "hostname": hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
        }))
    } else {
        HttpResponse::Forbidden().json(serde_json::json!({
            "valid": false,
            "error": "Invalid join token",
        }))
    }
}

/// POST /api/nodes — add a server to the cluster
#[derive(Deserialize)]
pub struct AddServerRequest {
    pub address: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub node_type: Option<String>,       // "wolfstack" (default) or "proxmox"
    #[serde(default)]
    pub join_token: Option<String>,      // Required for WolfStack nodes — validates against remote
    #[serde(default)]
    pub pve_token: Option<String>,       // PVEAPIToken=user@realm!tokenid=uuid
    #[serde(default)]
    pub pve_fingerprint: Option<String>,
    #[serde(default)]
    pub pve_node_name: Option<String>,
    #[serde(default)]
    pub pve_cluster_name: Option<String>, // User-friendly cluster name for sidebar
    #[serde(default)]
    pub cluster_name: Option<String>,     // Generic cluster name for WolfStack nodes
}

pub async fn add_node(req: HttpRequest, state: web::Data<AppState>, body: web::Json<AddServerRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let node_type = body.node_type.as_deref().unwrap_or("wolfstack");

    if node_type == "proxmox" {
        let port = body.port.unwrap_or(8006);
        let token = body.pve_token.clone().unwrap_or_default();
        let fingerprint = body.pve_fingerprint.clone();
        let pve_node_name = body.pve_node_name.clone().unwrap_or_default();
        let cluster_name = body.pve_cluster_name.clone();

        if token.is_empty() || pve_node_name.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Proxmox nodes require pve_token and pve_node_name"
            }));
        }

        // Try to discover all nodes in the cluster
        let client = crate::proxmox::PveClient::new(&body.address, port, &token, fingerprint.as_deref(), &pve_node_name);
        let discovered = client.discover_nodes().await.unwrap_or_default();

        let mut added_ids = Vec::new();
        let mut added_nodes = Vec::new();

        if discovered.len() > 1 {
            // Multi-node cluster — add each discovered node
            for node_name in &discovered {
                let id = state.cluster.add_proxmox_server(
                    body.address.clone(), port, token.clone(),
                    fingerprint.clone(), node_name.clone(), cluster_name.clone(),
                );
                info!("Added Proxmox cluster node {} at {}:{} (node: {})", id, body.address, port, node_name);
                added_ids.push(id);
                added_nodes.push(node_name.clone());
            }
        } else {
            // Single node or discovery failed — add just the specified node
            let id = state.cluster.add_proxmox_server(
                body.address.clone(), port, token, fingerprint,
                pve_node_name.clone(), cluster_name.clone(),
            );
            info!("Added Proxmox node {} at {}:{} (node: {})", id, body.address, port, pve_node_name);
            added_ids.push(id);
            added_nodes.push(pve_node_name.clone());
        }

        HttpResponse::Ok().json(serde_json::json!({
            "ids": added_ids,
            "address": body.address,
            "port": port,
            "node_type": "proxmox",
            "nodes_discovered": added_nodes,
            "cluster_name": cluster_name,
        }))
    } else {
        let port = body.port.unwrap_or(8553);
        let cluster_name = body.cluster_name.clone();

        // Validate join token against the remote server
        let join_token = body.join_token.clone().unwrap_or_default();
        if join_token.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Join token is required. Get it from the remote server's dashboard."
            }));
        }

        // Call the remote server to verify the token
        // Try HTTPS on the given port first (accept self-signed certs), then HTTP on port+1 (inter-node port)
        let verify_path = format!("/api/cluster/verify-token?token={}", join_token);
        let urls = vec![
            format!("https://{}:{}{}", body.address, port, verify_path),
            format!("http://{}:{}{}", body.address, port + 1, verify_path),
            format!("http://{}:{}{}", body.address, port, verify_path),
        ];

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build() {
            Ok(c) => c,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("HTTP client error: {}", e)
                }));
            }
        };

        let mut last_error = String::new();
        let mut verified = false;
        for url in &urls {
            match client.get(url).send().await {
                Ok(resp) => {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if data.get("valid").and_then(|v| v.as_bool()) == Some(true) {
                            info!("Join token verified for {}:{} via {}", body.address, port, url);
                            verified = true;
                            break;
                        } else {
                            let err_msg = data.get("error").and_then(|v| v.as_str()).unwrap_or("Invalid join token");
                            return HttpResponse::Forbidden().json(serde_json::json!({
                                "error": err_msg
                            }));
                        }
                    }
                    // Got a response but couldn't parse — try next URL
                    last_error = format!("Unparseable response from {}", url);
                }
                Err(e) => {
                    last_error = format!("{}", e);
                    // Connection failed — try next URL
                }
            }
        }

        if !verified {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("Cannot reach remote server at {}:{} — {}", body.address, port, last_error)
            }));
        }

        let id = state.cluster.add_server(body.address.clone(), port, cluster_name.clone());
        info!("Added server {} at {}:{} (cluster: {:?})", id, body.address, port, cluster_name);
        HttpResponse::Ok().json(serde_json::json!({
            "id": id,
            "address": body.address,
            "port": port,
            "node_type": "wolfstack",
            "cluster_name": cluster_name,
        }))
    }
}

/// DELETE /api/nodes/{id} — remove a server
pub async fn remove_node(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.cluster.remove_server(&id) {
        // Broadcast deletion to all other online nodes so they don't gossip it back
        let nodes = state.cluster.get_all_nodes();
        let secret = state.cluster_secret.clone();
        let delete_id = id.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            for node in &nodes {
                if node.is_self || !node.online { continue; }
                // Try HTTPS first, then HTTP on port+1, then HTTP on main port
                let urls = build_node_urls(&node.address, node.port, &format!("/api/nodes/{}", delete_id));
                for url in &urls {
                    if let Ok(_) = client.delete(url)
                        .header("X-WolfStack-Secret", &secret)
                        .send()
                        .await
                    {
                        break; // Success, no need to try next URL
                    }
                }
            }
        });
        HttpResponse::Ok().json(serde_json::json!({ "removed": true }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))
    }
}

/// PATCH /api/nodes/{id}/settings — update node settings
#[derive(Deserialize)]
pub struct UpdateNodeSettings {
    pub hostname: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub pve_token: Option<String>,
    pub pve_fingerprint: Option<String>,
    pub pve_cluster_name: Option<String>,
    pub cluster_name: Option<String>,
    pub login_disabled: Option<bool>,
}

pub async fn update_node_settings(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateNodeSettings>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let fp = if body.pve_fingerprint.is_some() {
        Some(body.pve_fingerprint.clone())
    } else {
        None
    };

    // Support updating both pve_cluster_name (for compat) and generic cluster_name
    let cluster_name = body.cluster_name.clone().or(body.pve_cluster_name.clone());

    if state.cluster.update_node_settings(
        &id,
        body.hostname.clone(),
        body.address.clone(),
        body.port,
        body.pve_token.clone(),
        fp,
        cluster_name,
        body.login_disabled,
    ) {
        // Propagate login_disabled to remote node so it takes effect on their login page
        if let Some(disabled) = body.login_disabled {
            let node = state.cluster.get_node(&id);
            if let Some(node) = node {
                if !node.is_self && node.node_type == "wolfstack" {
                    let secret = state.cluster_secret.clone();
                    let address = node.address.clone();
                    let port = node.port;
                    tokio::spawn(async move {
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(5))
                            .danger_accept_invalid_certs(true)
                            .build()
                            .unwrap_or_default();
                        let urls = build_node_urls(&address, port, "/api/settings/login-disabled");
                        let payload = serde_json::json!({ "login_disabled": disabled });
                        for url in &urls {
                            if let Ok(_) = client.post(url)
                                .header("X-WolfStack-Secret", &secret)
                                .header("Content-Type", "application/json")
                                .body(payload.to_string())
                                .send()
                                .await
                            {
                                tracing::info!("Propagated login_disabled={} to {}:{}", disabled, address, port);
                                break;
                            }
                        }
                    });
                }
            }
        }
        HttpResponse::Ok().json(serde_json::json!({ "updated": true }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))
    }
}

/// POST /api/cluster/wolfnet-sync — ensure all WolfStack nodes in a cluster know about each other's WolfNet peers
#[derive(Deserialize)]
pub struct WolfNetSyncRequest {
    pub node_ids: Vec<String>,
}

pub async fn wolfnet_sync_cluster(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetSyncRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let node_ids = &body.node_ids;
    if node_ids.len() < 2 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Need at least 2 nodes to sync"}));
    }

    // Collect WolfNet info from each node
    #[derive(Clone)]
    struct NodeWnInfo {
        hostname: String,
        wolfnet_ip: String,
        public_key: String,
        /// The reachable endpoint (node.address:listen_port) for WolfNet
        endpoint: String,
        is_self: bool,
        address: String,
        port: u16,
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let mut infos: Vec<NodeWnInfo> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for nid in node_ids {
        let node = match state.cluster.get_node(nid) {
            Some(n) => n,
            None => { errors.push(format!("Node {} not found", nid)); continue; }
        };
        if node.node_type != "wolfstack" {
            errors.push(format!("{} is not a WolfStack node", node.hostname));
            continue;
        }

        if node.is_self {
            // Get local info directly
            match networking::get_wolfnet_local_info() {
                Some(info) => {
                    let hostname = info["hostname"].as_str().unwrap_or("").to_string();
                    let address = info["address"].as_str().unwrap_or("").to_string();
                    let public_key = info["public_key"].as_str().unwrap_or("").to_string();
                    let listen_port = info["listen_port"].as_u64().unwrap_or(9600) as u16;
                    if address.is_empty() || public_key.is_empty() {
                        errors.push(format!("{}: WolfNet not configured", node.hostname));
                        continue;
                    }
                    // Use the node's real address (not WolfNet IP) as the endpoint
                    let endpoint = format!("{}:{}", node.address, listen_port);
                    infos.push(NodeWnInfo {
                        hostname,
                        wolfnet_ip: address,
                        public_key,
                        endpoint,
                        is_self: true,
                        address: node.address.clone(),
                        port: node.port,
                    });
                }
                None => {
                    errors.push(format!("{}: WolfNet not running", node.hostname));
                }
            }
        } else {
            // Fetch from remote node — try HTTPS first, then HTTP fallback
            let urls = build_node_urls(&node.address, node.port, "/api/networking/wolfnet/local-info");
            let mut fetched = false;
            for url in &urls {
                match client.get(url)
                    .header("X-WolfStack-Secret", &state.cluster_secret)
                    .send().await
                {
                    Ok(resp) => {
                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                            if info.get("error").is_some() {
                                errors.push(format!("{}: {}", node.hostname, info["error"]));
                                fetched = true;
                                break;
                            }
                            let hostname = info["hostname"].as_str().unwrap_or("").to_string();
                            let address = info["address"].as_str().unwrap_or("").to_string();
                            let public_key = info["public_key"].as_str().unwrap_or("").to_string();
                            let listen_port = info["listen_port"].as_u64().unwrap_or(9600) as u16;
                            if address.is_empty() || public_key.is_empty() {
                                errors.push(format!("{}: WolfNet not configured", node.hostname));
                                fetched = true;
                                break;
                            }
                            let endpoint = format!("{}:{}", node.address, listen_port);
                            infos.push(NodeWnInfo {
                                hostname,
                                wolfnet_ip: address,
                                public_key,
                                endpoint,
                                is_self: false,
                                address: node.address.clone(),
                                port: node.port,
                            });
                            fetched = true;
                            break;
                        }
                    }
                    Err(_) => continue, // Try next URL
                }
            }
            if !fetched {
                errors.push(format!("{}: unreachable on all ports/protocols", node.hostname));
            }
        }
    }

    if infos.len() < 2 {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "error",
            "message": "Could not reach enough nodes to sync",
            "errors": errors,
        }));
    }

    // Now tell each node about every other node
    let mut synced = 0u32;
    let mut skipped = 0u32;

    for i in 0..infos.len() {
        let target = &infos[i];
        for j in 0..infos.len() {
            if i == j { continue; }
            let peer = &infos[j];

            if target.is_self {
                // Add peer locally
                match networking::add_wolfnet_peer(
                    &peer.hostname,
                    &peer.endpoint,
                    &peer.wolfnet_ip,
                    Some(&peer.public_key),
                ) {
                    Ok(_) => { synced += 1; }
                    Err(e) => {
                        if e.contains("already exists") {
                            skipped += 1;
                        } else {
                            errors.push(format!("local add {}: {}", peer.hostname, e));
                        }
                    }
                }
            } else {
                // Add peer on remote node — try HTTPS first, then HTTP fallback
                let urls = build_node_urls(&target.address, target.port, "/api/networking/wolfnet/peers");
                let payload = serde_json::json!({
                    "name": peer.hostname,
                    "endpoint": peer.endpoint,
                    "ip": peer.wolfnet_ip,
                    "public_key": peer.public_key,
                });
                let mut posted = false;
                for url in &urls {
                    match client.post(url)
                        .header("X-WolfStack-Secret", &state.cluster_secret)
                        .header("Content-Type", "application/json")
                        .body(payload.to_string())
                        .send().await
                    {
                        Ok(resp) => {
                            if let Ok(data) = resp.json::<serde_json::Value>().await {
                                if data.get("error").is_some() {
                                    let err = data["error"].as_str().unwrap_or("unknown");
                                    if err.contains("already exists") {
                                        skipped += 1;
                                    } else {
                                        errors.push(format!("{} → {}: {}", target.hostname, peer.hostname, err));
                                    }
                                } else {
                                    synced += 1;
                                }
                            }
                            posted = true;
                            break;
                        }
                        Err(_) => continue, // Try next URL
                    }
                }
                if !posted {
                    errors.push(format!("{} → {}: unreachable on all ports/protocols", target.hostname, peer.hostname));
                }
            }
        }
    }

    info!("WolfNet sync: {} peers added, {} already existed, {} errors", synced, skipped, errors.len());

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "synced": synced,
        "skipped": skipped,
        "nodes_reached": infos.len(),
        "errors": errors,
    }))
}

/// POST /api/cluster/diagnose — manually poll each node and report detailed connectivity info
pub async fn cluster_diagnose(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetSyncRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let node_ids = &body.node_ids;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let mut results = Vec::new();

    for nid in node_ids {
        let node = match state.cluster.get_node(nid) {
            Some(n) => n,
            None => {
                results.push(serde_json::json!({
                    "node_id": nid,
                    "hostname": "unknown",
                    "address": "",
                    "port": 0,
                    "is_self": false,
                    "wolfstack_api": { "reachable": false, "error": "Node not found in cluster" },
                    "wolfnet": { "reachable": false },
                    "last_seen_ago_secs": null,
                }));
                continue;
            }
        };

        let last_seen_ago = if node.last_seen > 0 { Some(now.saturating_sub(node.last_seen)) } else { None };

        if node.is_self {
            results.push(serde_json::json!({
                "node_id": node.id,
                "hostname": node.hostname,
                "address": node.address,
                "port": node.port,
                "is_self": true,
                "wolfstack_api": {
                    "reachable": true,
                    "url_used": "localhost (self)",
                    "status_code": 200,
                    "latency_ms": 0,
                    "error": null,
                },
                "wolfnet": {
                    "ip": "self",
                    "reachable": true,
                    "latency_ms": 0,
                },
                "last_seen_ago_secs": 0,
            }));
            continue;
        }

        // Try HTTP on port+1 first (inter-node), then HTTPS on main port, then HTTP on main port
        let urls = vec![
            format!("http://{}:{}/api/agent/status", node.address, node.port + 1),
            format!("https://{}:{}/api/agent/status", node.address, node.port),
            format!("http://{}:{}/api/agent/status", node.address, node.port),
        ];

        let mut api_result = serde_json::json!({
            "reachable": false,
            "url_used": null,
            "status_code": null,
            "latency_ms": null,
            "error": "Could not reach node on any port/protocol",
        });

        for url in &urls {
            let start = std::time::Instant::now();
            match client.get(url)
                .header("X-WolfStack-Secret", &state.cluster_secret)
                .send().await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let latency = start.elapsed().as_millis() as u64;
                    let body_text = resp.text().await.unwrap_or_default();

                    // Try to parse as AgentMessage
                    let is_valid = serde_json::from_str::<serde_json::Value>(&body_text)
                        .map(|v| v.get("StatusReport").is_some() || v.get("hostname").is_some())
                        .unwrap_or(false);

                    if status == 200 && (is_valid || body_text.contains("hostname")) {
                        api_result = serde_json::json!({
                            "reachable": true,
                            "url_used": url,
                            "status_code": status,
                            "latency_ms": latency,
                            "error": null,
                        });
                        break;
                    } else {
                        // Got a response but not the expected one
                        let snippet = if body_text.len() > 100 { &body_text[..100] } else { &body_text };
                        api_result = serde_json::json!({
                            "reachable": false,
                            "url_used": url,
                            "status_code": status,
                            "latency_ms": latency,
                            "error": format!("HTTP {}: {}", status, snippet.trim()),
                        });
                        // Don't break — try the other port
                    }
                }
                Err(e) => {
                    let latency = start.elapsed().as_millis() as u64;
                    let err_str = format!("{}", e);
                    // Only update if we haven't gotten a better result
                    if api_result.get("status_code").and_then(|v| v.as_u64()).is_none() {
                        api_result = serde_json::json!({
                            "reachable": false,
                            "url_used": url,
                            "status_code": null,
                            "latency_ms": latency,
                            "error": err_str,
                        });
                    }
                }
            }
        }

        // Check WolfNet connectivity by pinging the node's WolfNet IP
        let wolfnet_result = {
            // Get WolfNet peers to find this node's WolfNet IP
            let peers = networking::get_wolfnet_peers_list();
            let wolfnet_ip = peers.iter()
                .find(|p| p.name.contains(&node.hostname) || node.hostname.contains(&p.name))
                .map(|p| p.ip.clone());

            if let Some(ref ip) = wolfnet_ip {
                // Quick ping test (1 packet, 2s timeout)
                let start = std::time::Instant::now();
                let ping_ok = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "2", ip])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                let latency = start.elapsed().as_millis() as u64;
                let ping_latency: Option<u64> = if ping_ok { Some(latency) } else { None };

                serde_json::json!({
                    "ip": ip,
                    "reachable": ping_ok,
                    "latency_ms": ping_latency,
                })
            } else {
                serde_json::json!({
                    "ip": serde_json::Value::Null,
                    "reachable": false,
                    "latency_ms": serde_json::Value::Null,
                })
            }
        };

        results.push(serde_json::json!({
            "node_id": node.id,
            "hostname": node.hostname,
            "address": node.address,
            "port": node.port,
            "is_self": false,
            "wolfstack_api": api_result,
            "wolfnet": wolfnet_result,
            "last_seen_ago_secs": last_seen_ago,
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "results": results }))
}

/// GET /api/nodes/{id}/pve/resources — list VMs and containers on a Proxmox node
pub async fn get_pve_resources(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let node = match state.cluster.get_node(&id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" })),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" })),
    };

    let token = node.pve_token.unwrap_or_default();
    let pve_name = node.pve_node_name.unwrap_or_default();
    let fp = node.pve_fingerprint.as_deref();

    let client = crate::proxmox::PveClient::new(&node.address, node.port, &token, fp, &pve_name);
    match client.list_all_guests().await {
        Ok(guests) => HttpResponse::Ok().json(guests),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/nodes/{id}/pve/{vmid}/{action} — start/stop/restart a Proxmox guest
pub async fn pve_guest_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, vmid_str, action) = path.into_inner();

    let node = match state.cluster.get_node(&id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" })),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" })),
    };

    let vmid: u64 = match vmid_str.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid VMID" })),
    };

    // Validate action
    if !["start", "stop", "shutdown", "reboot", "suspend", "resume"].contains(&action.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid action. Use: start, stop, shutdown, reboot, suspend, resume" }));
    }

    let token = node.pve_token.unwrap_or_default();
    let pve_name = node.pve_node_name.unwrap_or_default();
    let fp = node.pve_fingerprint.as_deref();

    let client = crate::proxmox::PveClient::new(&node.address, node.port, &token, fp, &pve_name);

    // Determine guest type by listing all and finding the VMID
    let guests = client.list_all_guests().await.unwrap_or_default();
    let guest_type = guests.iter()
        .find(|g| g.vmid == vmid)
        .map(|g| g.guest_type.clone())
        .unwrap_or_else(|| "qemu".to_string()); // default to qemu

    match client.guest_action(vmid, &guest_type, &action).await {
        Ok(upid) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "upid": upid,
            "vmid": vmid,
            "action": action
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/nodes/{id}/pve/test — test Proxmox API connection
pub async fn pve_test_connection(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let node = match state.cluster.get_node(&id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" })),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" })),
    };

    let token = node.pve_token.unwrap_or_default();
    let pve_name = node.pve_node_name.unwrap_or_default();
    let fp = node.pve_fingerprint.as_deref();

    let client = crate::proxmox::PveClient::new(&node.address, node.port, &token, fp, &pve_name);
    match client.test_connection().await {
        Ok(version) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "version": version,
            "node_name": pve_name
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
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

// ─── Cron Job Management API ───

#[derive(Deserialize)]
pub struct CronJobRequest {
    pub schedule: String,
    pub command: String,
    #[serde(default)]
    pub comment: String,
    pub index: Option<usize>,
    #[serde(default = "cron_enabled_default")]
    pub enabled: bool,
}

fn cron_enabled_default() -> bool { true }

#[derive(serde::Serialize)]
struct CronEntry {
    index: usize,
    schedule: String,
    command: String,
    comment: String,
    human: String,
    enabled: bool,
    raw: String,
}

fn humanize_schedule(schedule: &str) -> String {
    match schedule.trim() {
        "@reboot" => "On reboot".to_string(),
        "@hourly" => "Every hour".to_string(),
        "@daily" | "@midnight" => "Every day (midnight)".to_string(),
        "@weekly" => "Every week".to_string(),
        "@monthly" => "Every month".to_string(),
        "@yearly" | "@annually" => "Every year".to_string(),
        s => {
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() != 5 { return s.to_string(); }
            let (min, hour, dom, mon, dow) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
            // Common patterns
            if s == "* * * * *" { return "Every minute".to_string(); }
            if min.starts_with("*/") && hour == "*" && dom == "*" && mon == "*" && dow == "*" {
                let n = &min[2..];
                return format!("Every {} minutes", n);
            }
            if min != "*" && hour == "*" && dom == "*" && mon == "*" && dow == "*" {
                return format!("Hourly at :{}", min);
            }
            if min != "*" && hour != "*" && dom == "*" && mon == "*" && dow == "*" {
                return format!("Daily at {}:{}", hour, if min.len() == 1 { format!("0{}", min) } else { min.to_string() });
            }
            if min != "*" && hour != "*" && dom == "*" && mon == "*" && dow != "*" {
                let day = match dow {
                    "0" | "7" => "Sunday", "1" => "Monday", "2" => "Tuesday",
                    "3" => "Wednesday", "4" => "Thursday", "5" => "Friday", "6" => "Saturday",
                    _ => dow,
                };
                return format!("Every {} at {}:{}", day, hour, if min.len() == 1 { format!("0{}", min) } else { min.to_string() });
            }
            if min != "*" && hour != "*" && dom != "*" && mon == "*" && dow == "*" {
                return format!("Monthly on day {} at {}:{}", dom, hour, if min.len() == 1 { format!("0{}", min) } else { min.to_string() });
            }
            s.to_string()
        }
    }
}

fn parse_crontab_line(line: &str, index: usize) -> Option<CronEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() { return None; }

    // Check for disabled entries
    if trimmed.starts_with("# DISABLED: ") {
        let rest = &trimmed["# DISABLED: ".len()..];
        if let Some(entry) = parse_cron_expression(rest, index) {
            return Some(CronEntry { enabled: false, ..entry });
        }
        return None;
    }

    // Skip pure comments
    if trimmed.starts_with('#') { return None; }

    parse_cron_expression(trimmed, index)
}

fn parse_cron_expression(line: &str, index: usize) -> Option<CronEntry> {
    let trimmed = line.trim();
    // Handle @reboot, @hourly, etc.
    if trimmed.starts_with('@') {
        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
        if parts.len() < 2 { return None; }
        let schedule = parts[0].to_string();
        let rest = parts[1].trim();
        let (command, comment) = extract_inline_comment(rest);
        return Some(CronEntry {
            human: humanize_schedule(&schedule),
            index, schedule, command, comment, enabled: true, raw: line.to_string(),
        });
    }

    // Standard 5-field cron
    let parts: Vec<&str> = trimmed.splitn(6, char::is_whitespace).collect();
    if parts.len() < 6 { return None; }
    let schedule = parts[..5].join(" ");
    let rest = parts[5].trim();
    let (command, comment) = extract_inline_comment(rest);
    Some(CronEntry {
        human: humanize_schedule(&schedule),
        index, schedule, command, comment, enabled: true, raw: line.to_string(),
    })
}

fn extract_inline_comment(s: &str) -> (String, String) {
    // Look for # comment at end (not inside quotes)
    if let Some(pos) = s.rfind(" # ") {
        (s[..pos].trim().to_string(), s[pos+3..].trim().to_string())
    } else {
        (s.trim().to_string(), String::new())
    }
}

fn read_crontab() -> (Vec<String>, String) {
    let output = std::process::Command::new("crontab")
        .arg("-l")
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout).to_string();
            let lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
            (lines, raw)
        }
        _ => (vec![], String::new()),
    }
}

fn write_crontab(lines: &[String]) -> Result<(), String> {
    let content = lines.join("\n") + "\n";
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn crontab: {}", e))?;
    use std::io::Write;
    child.stdin.as_mut().unwrap()
        .write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write crontab: {}", e))?;
    let status = child.wait().map_err(|e| format!("crontab error: {}", e))?;
    if status.success() { Ok(()) } else { Err("crontab exited with error".to_string()) }
}

/// GET /api/cron — list cron entries
pub async fn cron_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (lines, raw) = read_crontab();
    let entries: Vec<CronEntry> = lines.iter().enumerate()
        .filter_map(|(i, line)| parse_crontab_line(line, i))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "entries": entries, "raw": raw }))
}

/// POST /api/cron — add or edit a cron entry
pub async fn cron_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CronJobRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (mut lines, _) = read_crontab();
    let comment_suffix = if body.comment.is_empty() { String::new() } else { format!(" # {}", body.comment) };
    let new_line = if body.enabled {
        format!("{} {}{}", body.schedule, body.command, comment_suffix)
    } else {
        format!("# DISABLED: {} {}{}", body.schedule, body.command, comment_suffix)
    };

    if let Some(idx) = body.index {
        if idx < lines.len() {
            lines[idx] = new_line;
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Index out of range" }));
        }
    } else {
        lines.push(new_line);
    }

    match write_crontab(&lines) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "status": "saved" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/cron/{index} — remove a cron entry by line index
pub async fn cron_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<usize>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let idx = path.into_inner();
    let (mut lines, _) = read_crontab();
    if idx >= lines.len() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Index out of range" }));
    }
    lines.remove(idx);
    match write_crontab(&lines) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Certbot API ───

#[derive(Deserialize)]
pub struct CertRequest {
    pub domain: String,
    pub email: String,
}

/// POST /api/certificates — request a certificate
pub async fn request_certificate(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CertRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match installer::request_certificate(&body.domain, &body.email) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/certificates/list — list installed certificates
pub async fn list_certificates(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    // Use the exact same discovery as startup (find_tls_certificate)
    let certs = installer::list_certificates();
    HttpResponse::Ok().json(certs)
}

// ─── Agent API (server-to-server, no auth required) ───

/// GET /api/agent/status — return this node's status (for remote polling)
/// Uses pre-cached data from the 2-second background task for instant responses.
pub async fn agent_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }

    // Return cached status if available (sub-millisecond response)
    if let Ok(cache) = state.cached_status.read() {
        if let Some(ref json) = *cache {
            return HttpResponse::Ok().json(json);
        }
    }

    // Fallback: first request before cache is populated (only happens once at startup)
    let metrics = state.monitor.lock().unwrap().collect();
    let components = installer::get_all_status();
    let hostname = metrics.hostname.clone();
    let docker_count = containers::docker_list_all().len() as u32;
    let lxc_count = containers::lxc_list_all().len() as u32;
    let vm_count = state.vms.lock().unwrap().list_vms().len() as u32;
    let has_docker = containers::docker_status().installed;
    let has_lxc = containers::lxc_status().installed;
    let has_kvm = containers::kvm_installed();
    let public_ip = state.cluster.get_node(&state.cluster.self_id).and_then(|n| n.public_ip);
    let msg = AgentMessage::StatusReport {
        node_id: state.cluster.self_id.clone(),
        hostname,
        metrics,
        components,
        docker_count,
        lxc_count,
        vm_count,
        public_ip,
        known_nodes: state.cluster.get_all_nodes(),
        deleted_ids: state.cluster.get_deleted_ids(),
        wolfnet_ips: containers::wolfnet_used_ips(),
        has_docker,
        has_lxc,
        has_kvm,
    };
    HttpResponse::Ok().json(msg)
}

/// POST /api/install/{tech} — install Docker, LXC, or KVM on this node
pub async fn install_runtime(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let tech = path.into_inner().to_lowercase();

    // Detect distro for package manager
    let distro = installer::detect_distro();
    let (pm, install_flag) = installer::pkg_install_cmd(distro);

    let packages = match tech.as_str() {
        "docker" => {
            // Use Docker's install script for best compatibility
            let result = std::process::Command::new("bash")
                .args(["-c", "curl -fsSL https://get.docker.com | sh"])
                .output();
            match result {
                Ok(o) if o.status.success() => {
                    // Enable and start Docker
                    let _ = std::process::Command::new("systemctl").args(["enable", "--now", "docker"]).output();
                    return HttpResponse::Ok().json(serde_json::json!({
                        "message": "Docker installed and started successfully"
                    }));
                }
                Ok(o) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Docker install failed: {}", String::from_utf8_lossy(&o.stderr))
                    }));
                }
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to run Docker installer: {}", e)
                    }));
                }
            }
        }
        "lxc" => match distro {
            installer::DistroFamily::Debian => "lxc lxc-templates",
            installer::DistroFamily::RedHat => "lxc lxc-templates lxc-extra",
            installer::DistroFamily::Suse => "lxc",
            _ => "lxc",
        },
        "kvm" => match distro {
            installer::DistroFamily::Debian => "qemu-system-x86 qemu-utils libvirt-daemon-system virtinst ovmf",
            installer::DistroFamily::RedHat => "qemu-kvm libvirt virt-install",
            installer::DistroFamily::Suse => "qemu-kvm libvirt virt-install",
            _ => "qemu-system-x86",
        },
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Unknown technology: {}. Use docker, lxc, or kvm.", tech)
            }));
        }
    };

    // Run package install
    let cmd = format!("{} {} {}", pm, install_flag, packages);
    let result = std::process::Command::new("bash")
        .args(["-c", &cmd])
        .output();

    match result {
        Ok(o) if o.status.success() => {
            // Post-install actions
            if tech == "lxc" {
                containers::ensure_lxc_bridge();
            } else if tech == "kvm" {
                let _ = std::process::Command::new("systemctl").args(["enable", "--now", "libvirtd"]).output();
            }
            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("{} installed successfully", tech)
            }))
        }
        Ok(o) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Install failed: {}", String::from_utf8_lossy(&o.stderr))
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to run installer: {}", e)
        })),
    }
}

/// GET /api/geolocate?ip={address} — server-side geolocation proxy
/// Proxies requests to ip-api.com because their free tier is HTTP-only,
/// and browsers block HTTP requests from HTTPS pages (mixed content).
/// Also resolves domain names to IPs before lookup.
pub async fn geolocate(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let ip_or_host = match query.get("ip") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing ip parameter" })),
    };

    // If it's a domain name (not an IP), resolve it to an IP first
    let ip = if ip_or_host.parse::<std::net::IpAddr>().is_ok() {
        ip_or_host
    } else {
        // DNS lookup
        match tokio::net::lookup_host(format!("{}:0", ip_or_host)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    addr.ip().to_string()
                } else {
                    return HttpResponse::Ok().json(serde_json::json!({
                        "status": "fail",
                        "message": "DNS resolution returned no addresses",
                        "query": ip_or_host
                    }));
                }
            }
            Err(e) => {
                return HttpResponse::Ok().json(serde_json::json!({
                    "status": "fail",
                    "message": format!("DNS resolution failed: {}", e),
                    "query": ip_or_host
                }));
            }
        }
    };

    // Call ip-api.com server-side (HTTP is fine from backend)
    let url = format!("http://ip-api.com/json/{}", ip);
    match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => {
            match client.get(&url).send().await {
                Ok(resp) => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(data) => HttpResponse::Ok().json(data),
                        Err(e) => HttpResponse::Ok().json(serde_json::json!({
                            "status": "fail",
                            "message": format!("Failed to parse response: {}", e),
                            "query": ip
                        })),
                    }
                }
                Err(e) => HttpResponse::Ok().json(serde_json::json!({
                    "status": "fail",
                    "message": format!("Request failed: {}", e),
                    "query": ip
                })),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("HTTP client error: {}", e)
        })),
    }
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

    let method = req.method().clone();
    let content_type = req.headers().get("content-type").and_then(|ct| ct.to_str().ok()).unwrap_or("application/json").to_string();
    let body_vec = body.to_vec();

    // Build URLs to try in order (security-first):
    // 1. HTTPS on the main port — preferred, encrypted end-to-end
    // 2. HTTP on internal port (port + 1) — only exists when TLS is on main port,
    //    accessible only via WolfNet (encrypted tunnel) so still secure
    // 3. HTTP on the main port — last resort (dev/local only)
    let internal_port = node.port + 1;
    let qs = req.query_string();
    let query_suffix = if qs.is_empty() { String::new() } else { format!("?{}", qs) };
    let urls = vec![
        format!("https://{}:{}/api/{}{}", node.address, node.port, api_path, query_suffix),
        format!("http://{}:{}/api/{}{}", node.address, internal_port, api_path, query_suffix),
        format!("http://{}:{}/api/{}{}", node.address, node.port, api_path, query_suffix),
    ];

    let timeout_secs = if method == actix_web::http::Method::POST || method == actix_web::http::Method::PUT { 300 } else { 120 };

    // Build a client that accepts self-signed certificates (inter-node traffic)
    // Short connect_timeout so failed URL schemes fail fast without blocking
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let mut last_error = String::new();

    for url in &urls {
        let mut builder = match method {
            actix_web::http::Method::GET => client.get(url),
            actix_web::http::Method::POST => client.post(url),
            actix_web::http::Method::PUT => client.put(url),
            actix_web::http::Method::DELETE => client.delete(url),
            _ => client.get(url),
        };

        builder = builder.header("content-type", &content_type);
        builder = builder.header("X-WolfStack-Secret", state.cluster_secret.clone());
        if !body_vec.is_empty() {
            builder = builder.body(body_vec.clone());
        }

        match builder.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                match resp.bytes().await {
                    Ok(bytes) => {
                        return HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK))
                            .content_type("application/json")
                            .body(bytes.to_vec());
                    }
                    Err(e) => {
                        last_error = format!("Read error from {}: {}", url, e);
                    }
                }
            }
            Err(e) => {
                last_error = format!("{}: {}", url, e);
                // Try next URL
                continue;
            }
        }
    }

    // All URLs failed
    HttpResponse::BadGateway().json(serde_json::json!({
        "error": format!("Could not reach node {} ({}:{}). Tried HTTP/HTTPS on ports {}/{} — last error: {}",
            node.hostname, node.address, node.port, internal_port, node.port, last_error)
    }))
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

    // On Proxmox, pct_create handles password, memory, and CPU natively
    if containers::is_proxmox() {
        let storage = body.storage_path.as_deref();
        let password = body.root_password.as_deref();
        // Parse memory limit (e.g. "512m" -> 512, "2g" -> 2048)
        let memory_mb = body.memory_limit.as_deref().and_then(|m| {
            let m = m.trim().to_lowercase();
            if m.ends_with('g') { m.trim_end_matches('g').parse::<u32>().ok().map(|v| v * 1024) }
            else if m.ends_with('m') { m.trim_end_matches('m').parse::<u32>().ok() }
            else { m.parse::<u32>().ok() }
        });
        let cpu_cores = body.cpu_cores.as_deref().and_then(|c| c.parse::<u32>().ok());

        return match containers::pct_create_api(
            &body.name, &body.distribution, &body.release, &body.architecture,
            storage, password, memory_mb, cpu_cores,
            body.wolfnet_ip.as_deref(),
        ) {
            Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        };
    }

    // Standalone LXC path
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

/// GET /api/storage/list — list available storage locations (Proxmox-aware)
pub async fn storage_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let is_pve = containers::is_proxmox();

    if is_pve {
        // Return Proxmox storage IDs
        let storages = containers::pvesm_list_storage();
        let items: Vec<serde_json::Value> = storages.iter().map(|s| {
            serde_json::json!({
                "id": s.id,
                "type": s.storage_type,
                "status": s.status,
                "total_bytes": s.total_bytes,
                "used_bytes": s.used_bytes,
                "available_bytes": s.available_bytes,
                "content": s.content,
            })
        }).collect();
        HttpResponse::Ok().json(serde_json::json!({
            "proxmox": true,
            "storages": items,
        }))
    } else {
        // Return filesystem-based storage
        let node = state.cluster.get_node(&state.cluster.self_id);
        let disks = node.as_ref().and_then(|n| n.metrics.as_ref())
            .map(|m| &m.disks)
            .cloned()
            .unwrap_or_default();

        let items: Vec<serde_json::Value> = disks.iter()
            .filter(|d| d.available_bytes > 1073741824) // > 1GB free
            .map(|d| serde_json::json!({
                "id": d.mount_point,
                "type": "dir",
                "status": "active",
                "total_bytes": d.total_bytes,
                "used_bytes": d.used_bytes,
                "available_bytes": d.available_bytes,
                "content": ["rootdir", "images"],
            }))
            .collect();
        HttpResponse::Ok().json(serde_json::json!({
            "proxmox": false,
            "storages": items,
        }))
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

/// GET /api/wolfnet/used-ips — returns WolfNet IPs in use on this node
/// No auth required — only returns IP addresses, needed by any WolfNet peer for route discovery
pub async fn wolfnet_used_ips_endpoint(_req: HttpRequest, _state: web::Data<AppState>) -> HttpResponse {
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
    pub storage: Option<String>, // target storage (Proxmox ID or path)
    pub target_node: Option<String>, // clone to a different node in the cluster
}

#[derive(Deserialize)]
pub struct MigrateRequest {
    pub target_node: String,
    pub storage: Option<String>,
    pub new_name: Option<String>,
}

#[derive(Deserialize)]
pub struct MigrateExternalRequest {
    pub target_url: String,
    pub target_token: String,
    pub new_name: Option<String>,
    pub storage: Option<String>,
    pub delete_source: Option<bool>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ImportRequest {
    pub new_name: String,
    pub storage: Option<String>,
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
#[derive(Deserialize)]
pub struct DockerMigrateRequest {
    pub target_url: String,
    pub remove_source: Option<bool>,
}
pub async fn docker_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<DockerMigrateRequest>,
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

    // Remote clone: export → transfer → import on target node
    if let Some(ref target_node_id) = body.target_node {
        return lxc_remote_clone(&state, &name, &body.new_name, target_node_id, body.storage.as_deref()).await;
    }

    // Local clone — lxc-copy requires container to be stopped
    let _ = containers::lxc_stop(&name);
    let storage = body.storage.as_deref();
    let result = if body.snapshot.unwrap_or(false) {
        containers::lxc_clone_snapshot(&name, &body.new_name)
    } else {
        containers::lxc_clone_local(&name, &body.new_name, storage)
    };
    let _ = containers::lxc_start(&name); // restart template
    match result {
        Ok(msg) => {
            // Remove duplicated wolfnet IP marker and allocate fresh one
            let _ = std::fs::remove_dir_all(format!("/var/lib/lxc/{}/.wolfnet", body.new_name));
            let _ = containers::lxc_start(&body.new_name);
            if let Some(ip) = containers::next_available_wolfnet_ip() {
                let _ = containers::lxc_attach_wolfnet(&body.new_name, &ip);
            }
            HttpResponse::Ok().json(serde_json::json!({ "message": msg }))
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Remote clone: export on this node, stream to target, import there
async fn lxc_remote_clone(
    state: &web::Data<AppState>,
    source: &str,
    new_name: &str,
    target_node_id: &str,
    storage: Option<&str>,
) -> HttpResponse {
    // 1. Find target node
    let node = match state.cluster.get_node(target_node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Target node not found"})),
    };
    if node.is_self {
        // Local clone, not remote
        match containers::lxc_clone_local(source, new_name, storage) {
            Ok(msg) => return HttpResponse::Ok().json(serde_json::json!({"message": msg})),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        }
    }

    // 2. Stop container before export
    let _ = containers::lxc_stop(source);

    // 3. Export container
    let (archive_path, meta) = match containers::lxc_export(source) {
        Ok(v) => v,
        Err(e) => {
            let _ = containers::lxc_start(source); // restart on failure
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Export failed: {}", e)}));
        }
    };

    // 4. Read archive
    let archive_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            let _ = containers::lxc_start(source);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to read archive: {}", e)}));
        }
    };

    // 5. Transfer to target
    // For Proxmox-type nodes, WolfStack is also installed on the server but the
    // node is registered with the PVE API port (8006), not the WolfStack port (8553).
    // Build import URLs using the correct WolfStack port.
    let import_urls = if node.node_type == "proxmox" {
        // Proxmox nodes have WolfStack running on port 8553 — try that
        let mut urls = build_node_urls(&node.address, 8553, "/api/containers/lxc/import");
        // Also try 8552 as a fallback WolfStack port
        urls.extend(build_node_urls(&node.address, 8552, "/api/containers/lxc/import"));
        urls
    } else {
        build_node_urls(&node.address, node.port, "/api/containers/lxc/import")
    };

    let storage_val = storage.unwrap_or("").to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600)) // 10 min for large transfers
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let meta_json = serde_json::to_string(&meta).unwrap_or_default();
    let mut last_err: Option<String> = None;

    for import_url in &import_urls {
        let form = reqwest::multipart::Form::new()
            .text("new_name", new_name.to_string())
            .text("storage", storage_val.clone())
            .text("meta", meta_json.clone())
            .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name(file_name.clone()));

        match client.post(import_url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .multipart(form)
            .send()
            .await
        {
            Ok(r) => {
                // Cleanup export
                containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
                let _ = containers::lxc_start(source); // restart source

                if r.status().is_success() {
                    return match r.json::<serde_json::Value>().await {
                        Ok(data) => HttpResponse::Ok().json(serde_json::json!({
                            "message": format!("Container '{}' cloned to '{}' on node '{}'", source, new_name, target_node_id),
                            "detail": data
                        })),
                        Err(_) => HttpResponse::Ok().json(serde_json::json!({
                            "message": format!("Container '{}' cloned to '{}' on node '{}'", source, new_name, target_node_id)
                        })),
                    };
                } else {
                    let err_text = r.text().await.unwrap_or_default();
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Import on target failed: {}", err_text)}));
                }
            }
            Err(e) => {
                last_err = Some(e.to_string());
                continue; // Try next URL
            }
        }
    }

    // All URLs failed
    containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
    let _ = containers::lxc_start(source); // restart source
    HttpResponse::BadGateway().json(serde_json::json!({
        "error": format!("Transfer to {} failed on all ports/protocols: {}", node.address, last_err.unwrap_or_default())
    }))
}

/// POST /api/containers/lxc/{name}/export — export container as downloadable archive
pub async fn lxc_export_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    // Stop, export, restart
    let _ = containers::lxc_stop(&name);
    let (archive_path, meta) = match containers::lxc_export(&name) {
        Ok(v) => v,
        Err(e) => {
            let _ = containers::lxc_start(&name);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
    };
    let _ = containers::lxc_start(&name);

    // Read the file and return as binary download
    match std::fs::read(&archive_path) {
        Ok(bytes) => {
            let filename = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            HttpResponse::Ok()
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .insert_header(("X-Container-Meta", serde_json::to_string(&meta).unwrap_or_default()))
                .content_type("application/octet-stream")
                .body(bytes)
        }
        Err(e) => {
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Read archive: {}", e)}))
        }
    }
}

/// POST /api/containers/lxc/import — import container from uploaded archive (multipart)
pub async fn lxc_import_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    lxc_import_endpoint_inner(&mut payload).await
}

/// POST /api/containers/lxc/{name}/migrate — migrate to another node (clone + destroy source)
pub async fn lxc_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.as_deref().unwrap_or(&name);

    // Clone to target node
    let clone_resp = lxc_remote_clone(&state, &name, new_name, &body.target_node, body.storage.as_deref()).await;

    // If clone succeeded, destroy source
    if clone_resp.status().is_success() {
        let _ = containers::lxc_stop(&name);
        match containers::lxc_destroy(&name) {
            Ok(_) => {
                info!("Migrated '{}' to node '{}' and destroyed source", name, body.target_node);
            }
            Err(e) => {
                tracing::warn!("Migration: clone succeeded but failed to destroy source '{}': {}", name, e);
            }
        }
    }

    clone_resp
}

// ─── Cross-cluster Transfer Tokens ───

static TRANSFER_TOKENS: std::sync::LazyLock<std::sync::Mutex<Vec<TransferToken>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[derive(Clone, Debug)]
struct TransferToken {
    token: String,
    expires: std::time::Instant,
}

/// POST /api/containers/transfer-token — generate a one-time import token
pub async fn generate_transfer_token(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let token = format!("wst_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let expires = std::time::Instant::now() + std::time::Duration::from_secs(1800); // 30 min

    if let Ok(mut tokens) = TRANSFER_TOKENS.lock() {
        // Purge expired
        tokens.retain(|t| t.expires > std::time::Instant::now());
        tokens.push(TransferToken { token: token.clone(), expires });
    }

    HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "expires_in_seconds": 1800,
        "instructions": "Provide this token to the source cluster to authorize a container transfer."
    }))
}

/// Validate and consume a transfer token
fn validate_transfer_token(token: &str) -> bool {
    if let Ok(mut tokens) = TRANSFER_TOKENS.lock() {
        tokens.retain(|t| t.expires > std::time::Instant::now()); // purge expired
        if let Some(pos) = tokens.iter().position(|t| t.token == token) {
            tokens.remove(pos); // consume
            return true;
        }
    }
    false
}

/// POST /api/containers/lxc/import-external — import from external cluster (requires transfer token)
pub async fn lxc_import_external(
    req: HttpRequest,
    _state: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    // Extract token from header
    let token = match req.headers().get("X-Transfer-Token") {
        Some(v) => v.to_str().unwrap_or("").to_string(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "X-Transfer-Token header required"})),
    };

    if !validate_transfer_token(&token) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Invalid or expired transfer token"}));
    }

    info!("External import authorized with transfer token");
    // Delegate to the standard import logic (re-auth not needed — token was validated)
    lxc_import_endpoint_inner(&mut payload).await
}

/// Shared import logic for both internal and external imports
async fn lxc_import_endpoint_inner(
    payload: &mut actix_multipart::Multipart,
) -> HttpResponse {
    let import_dir = std::path::Path::new("/tmp/wolfstack-imports");
    let _ = std::fs::create_dir_all(import_dir);

    let mut new_name = String::new();
    let mut storage = None;
    let mut archive_path = None;

    use futures::StreamExt;
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Multipart error: {}", e)})),
        };

        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "new_name" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                new_name = String::from_utf8_lossy(&buf).trim().to_string();
            }
            "storage" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let s = String::from_utf8_lossy(&buf).trim().to_string();
                if !s.is_empty() { storage = Some(s); }
            }
            "archive" => {
                let filename = field.content_disposition()
                    .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
                    .unwrap_or_else(|| "import.tar.gz".to_string());
                let dest = import_dir.join(&filename);
                let mut file = match std::fs::File::create(&dest) {
                    Ok(f) => f,
                    Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Write error: {}", e)})),
                };
                use std::io::Write;
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk {
                        if let Err(e) = file.write_all(&data) {
                            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Write error: {}", e)}));
                        }
                    }
                }
                archive_path = Some(dest);
            }
            _ => { while let Some(_) = field.next().await {} }
        }
    }

    if new_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "new_name is required"}));
    }
    let archive = match archive_path {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "archive file is required"})),
    };

    match containers::lxc_import(archive.to_str().unwrap(), &new_name, storage.as_deref()) {
        Ok(msg) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::Ok().json(serde_json::json!({"message": msg}))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e}))
        }
    }
}

/// POST /api/containers/lxc/{name}/migrate-external — migrate to external cluster
pub async fn lxc_migrate_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateExternalRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.as_deref().unwrap_or(&name);

    // 1. Stop and export
    let _ = containers::lxc_stop(&name);
    let (archive_path, meta) = match containers::lxc_export(&name) {
        Ok(v) => v,
        Err(e) => {
            let _ = containers::lxc_start(&name);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Export failed: {}", e)}));
        }
    };

    // 2. Read archive
    let archive_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            let _ = containers::lxc_start(&name);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Read archive: {}", e)}));
        }
    };

    // 3. POST to external cluster's import-external endpoint
    let import_url = format!("{}/api/containers/lxc/import-external", body.target_url.trim_end_matches('/'));
    let storage_val = body.storage.as_deref().unwrap_or("").to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .danger_accept_invalid_certs(true) // cross-cluster may have self-signed certs
        .build()
        .unwrap_or_default();

    let form = reqwest::multipart::Form::new()
        .text("new_name", new_name.to_string())
        .text("storage", storage_val)
        .text("meta", serde_json::to_string(&meta).unwrap_or_default())
        .part("archive", reqwest::multipart::Part::bytes(archive_bytes)
            .file_name(archive_path.file_name().unwrap_or_default().to_string_lossy().to_string()));

    let resp = client.post(&import_url)
        .header("X-Transfer-Token", &body.target_token)
        .multipart(form)
        .send()
        .await;

    // Cleanup
    containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));

    match resp {
        Ok(r) => {
            if r.status().is_success() {
                // Optionally destroy source
                if body.delete_source.unwrap_or(false) {
                    let _ = containers::lxc_destroy(&name);
                    info!("Migrated '{}' to external cluster and destroyed source", name);
                } else {
                    let _ = containers::lxc_start(&name);
                }
                HttpResponse::Ok().json(serde_json::json!({
                    "message": format!("Container '{}' transferred to {}", name, body.target_url)
                }))
            } else {
                let _ = containers::lxc_start(&name);
                let err = r.text().await.unwrap_or_default();
                HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("External import failed: {}", err)}))
            }
        }
        Err(e) => {
            let _ = containers::lxc_start(&name);
            HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("Transfer to {} failed: {}", body.target_url, e)
            }))
        }
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

#[derive(Deserialize)]
pub struct DockerUpdateConfigReq {
    pub autostart: Option<bool>,
    pub memory_mb: Option<u64>,
    pub cpus: Option<f32>,
}

pub async fn docker_update_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<DockerUpdateConfigReq>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    
    match containers::docker_update_config(&id, body.autostart, body.memory_mb, body.cpus) {
         Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
         Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/docker/{id}/inspect — inspect raw docker config
pub async fn docker_inspect(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    
    match containers::docker_inspect(&id) {
        Ok(json) => HttpResponse::Ok().json(json),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
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

#[derive(Deserialize)]
pub struct LxcSetAutostartReq {
    pub enabled: bool,
}

pub async fn lxc_set_autostart(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LxcSetAutostartReq>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    
    match containers::lxc_set_autostart(&name, body.enabled) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct LxcSetNetworkLinkReq {
    pub link: String,
}

pub async fn lxc_set_network_link(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LxcSetNetworkLinkReq>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    
    match containers::lxc_set_network_link(&name, &body.link) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/lxc/{name}/parsed-config — get structured config
pub async fn lxc_parsed_config(
    req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_parse_config(&name) {
        Some(cfg) => HttpResponse::Ok().json(cfg),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Config not found" })),
    }
}

/// POST /api/containers/lxc/{name}/settings — update structured settings
pub async fn lxc_update_settings(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<containers::LxcSettingsUpdate>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_update_settings(&name, &body.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfnet/next-ip — find next available WolfNet IP
pub async fn wolfnet_next_ip(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match containers::next_available_wolfnet_ip() {
        Some(ip) => HttpResponse::Ok().json(serde_json::json!({ "ip": ip })),
        None => HttpResponse::Ok().json(serde_json::json!({ "ip": null, "error": "No available IPs in 10.10.10.0/24" })),
    }
}

/// GET /api/network/conflicts — detect duplicate MACs/IPs across LXC containers
pub async fn network_conflicts(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let conflicts = containers::detect_network_conflicts();
    HttpResponse::Ok().json(conflicts)
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

// ─── AI Agent API ───

/// GET /api/ai/config — get AI configuration (keys masked)
pub async fn ai_get_config(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.ai_agent.config.lock().unwrap();
    HttpResponse::Ok().json(config.masked())
}

/// POST /api/ai/config — save AI configuration
pub async fn ai_save_config(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config_json;
    {
        let mut config = state.ai_agent.config.lock().unwrap();

        // Update fields — only update keys if not masked values
        if let Some(v) = body.get("provider").and_then(|v| v.as_str()) {
            config.provider = v.to_string();
        }
        if let Some(v) = body.get("claude_api_key").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.claude_api_key = v.to_string();
            }
        }
        if let Some(v) = body.get("gemini_api_key").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.gemini_api_key = v.to_string();
            }
        }
        if let Some(v) = body.get("model").and_then(|v| v.as_str()) {
            config.model = v.to_string();
        }
        if let Some(v) = body.get("email_enabled").and_then(|v| v.as_bool()) {
            config.email_enabled = v;
        }
        if let Some(v) = body.get("email_to").and_then(|v| v.as_str()) {
            config.email_to = v.to_string();
        }
        if let Some(v) = body.get("smtp_host").and_then(|v| v.as_str()) {
            config.smtp_host = v.to_string();
        }
        if let Some(v) = body.get("smtp_port").and_then(|v| v.as_u64()) {
            config.smtp_port = v as u16;
        }
        if let Some(v) = body.get("smtp_user").and_then(|v| v.as_str()) {
            config.smtp_user = v.to_string();
        }
        if let Some(v) = body.get("smtp_pass").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.smtp_pass = v.to_string();
            }
        }
        if let Some(v) = body.get("smtp_tls").and_then(|v| v.as_str()) {
            config.smtp_tls = v.to_string();
        }
        if let Some(v) = body.get("check_interval_minutes").and_then(|v| v.as_u64()) {
            config.check_interval_minutes = v as u32;
        }
        if let Some(v) = body.get("scan_schedule").and_then(|v| v.as_str()) {
            config.scan_schedule = v.to_string();
        }

        if let Err(e) = config.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }

        // Serialize full config (with real keys) for cluster sync
        config_json = serde_json::to_value(&*config).unwrap_or_default();
    }

    // Broadcast to all online cluster nodes in the background
    let cluster_secret = state.cluster_secret.clone();
    let nodes = state.cluster.get_all_nodes();
    let client = reqwest::Client::new();
    for node in nodes.iter().filter(|n| !n.is_self && n.online) {
        let url = format!("http://{}:{}/api/ai/config/sync", node.address, node.port);
        let secret = cluster_secret.clone();
        let cfg = config_json.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let _ = c.post(&url)
                .header("X-WolfStack-Secret", secret)
                .json(&cfg)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
        });
    }

    HttpResponse::Ok().json(serde_json::json!({"status": "saved"}))
}

/// POST /api/ai/config/sync — receive AI config from another cluster node
pub async fn ai_sync_config(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<crate::ai::AiConfig>,
) -> HttpResponse {
    if let Err(resp) = require_cluster_auth(&req, &state) { return resp; }

    let new_config = body.into_inner();
    if let Err(e) = new_config.save() {
        warn!("Failed to save synced AI config: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    // Update in-memory config
    let mut config = state.ai_agent.config.lock().unwrap();
    *config = new_config;

    info!("AI config synced from cluster node");
    HttpResponse::Ok().json(serde_json::json!({"status": "synced"}))
}

/// POST /api/ai/test-email — send a test email to verify SMTP settings
pub async fn ai_test_email(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let config = state.ai_agent.config.lock().unwrap().clone();

    if !config.email_enabled || config.email_to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Email alerts not enabled or no recipient configured"
        }));
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let version = env!("CARGO_PKG_VERSION");

    let subject = format!("[WolfStack] Test Email from {}", hostname);
    let body = format!(
        "✅ WolfStack Test Email\n\n\
         This is a test email from your WolfStack AI Agent.\n\n\
         Hostname: {}\n\
         Version: {}\n\
         Time: {}\n\n\
         If you received this, your email alert settings are working correctly.",
        hostname, version,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    match crate::ai::send_alert_email(&config, &subject, &body) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "sent",
            "message": format!("Test email sent to {}", config.email_to)
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to send: {}", e)
        })),
    }
}

/// POST /api/ai/chat — send a message to the AI agent
#[derive(Deserialize)]
pub struct AiChatRequest {
    pub message: String,
}

pub async fn ai_chat(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AiChatRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Build server context for the AI
    let server_context = {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let docker_count = crate::containers::docker_list_all().len();
        let lxc_count = crate::containers::lxc_list_all().len();
        let vm_count = state.vms.lock().unwrap().list_vms().len();
        let components = crate::installer::get_all_status();

        let nodes = state.cluster.get_all_nodes();

        // WolfStack nodes summary
        let ws_nodes: Vec<&crate::agent::Node> = nodes.iter().filter(|n| n.node_type != "proxmox").collect();
        let pve_nodes: Vec<&crate::agent::Node> = nodes.iter().filter(|n| n.node_type == "proxmox").collect();

        let node_info = ws_nodes.iter().map(|n| {
            format!("  - {} ({}) [{}]", n.hostname, n.address,
                if n.online { "online" } else { "offline" })
        }).collect::<Vec<_>>().join("\n");

        // Group PVE nodes by cluster
        let mut pve_clusters: std::collections::HashMap<String, Vec<&crate::agent::Node>> = std::collections::HashMap::new();
        for n in &pve_nodes {
            let key = n.pve_cluster_name.clone()
                .or_else(|| n.cluster_name.clone())
                .unwrap_or_else(|| n.address.clone());
            pve_clusters.entry(key).or_default().push(n);
        }

        let pve_info = if pve_clusters.is_empty() {
            "None".to_string()
        } else {
            pve_clusters.iter().map(|(cluster_name, cnodes)| {
                let node_details = cnodes.iter().map(|n| {
                    let metrics_str = if let Some(ref m) = n.metrics {
                        let mem_used_gb = m.memory_used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let mem_total_gb = m.memory_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let root_disk = m.disks.iter().find(|d| d.mount_point == "/").or_else(|| m.disks.first());
                        let disk_info = root_disk.map(|d| {
                            let used_gb = d.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            let total_gb = d.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            format!(", disk {:.1}/{:.1}GB", used_gb, total_gb)
                        }).unwrap_or_default();
                        format!(" — CPU {:.0}%, RAM {:.1}/{:.1}GB{}",
                            m.cpu_usage_percent, mem_used_gb, mem_total_gb, disk_info)
                    } else {
                        String::new()
                    };
                    format!("    - {} (pve_node: {}, {}) [{}] — {} VMs, {} CTs{}",
                        n.hostname, n.pve_node_name.as_deref().unwrap_or("?"),
                        n.address,
                        if n.online { "online" } else { "offline" },
                        n.vm_count, n.lxc_count, metrics_str)
                }).collect::<Vec<_>>().join("\n");
                format!("  Cluster '{}' ({} nodes):\n{}", cluster_name, cnodes.len(), node_details)
            }).collect::<Vec<_>>().join("\n")
        };

        format!(
            "Hostname: {}\nLocal Docker containers: {}\nLocal LXC containers: {}\nLocal VMs: {}\n\
             Components: {}\n\nWolfStack Nodes ({}):\n{}\n\nProxmox Clusters:\n{}",
            hostname, docker_count, lxc_count, vm_count,
            components.iter().map(|c| format!("{:?}: {}", c.component, if c.running { "running" } else { "stopped" })).collect::<Vec<_>>().join(", "),
            ws_nodes.len(), node_info,
            pve_info,
        )
    };

    // Build cluster node list for remote command execution
    let cluster_nodes: Vec<(String, String, String, String)> = {
        let nodes = state.cluster.get_all_nodes();
        nodes.iter()
            .filter(|n| !n.is_self && n.online && n.node_type != "proxmox")
            .map(|n| {
                // When TLS is enabled, main port serves HTTPS; inter-node HTTP is on port+1.
                // Try port+1 first (works for HTTPS nodes), fall back to original port (HTTP-only).
                let url1 = format!("http://{}:{}", n.address, n.port + 1);
                let url2 = format!("http://{}:{}", n.address, n.port);
                (n.id.clone(), n.hostname.clone(), url1, url2)
            })
            .collect()
    };

    match state.ai_agent.chat(&body.message, &server_context, &cluster_nodes, &state.cluster_secret).await {
        Ok(response) => HttpResponse::Ok().json(serde_json::json!({
            "response": response,
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "error": e,
        })),
    }
}

/// POST /api/ai/exec — execute a safe read-only command (used by cluster proxy)
#[derive(Deserialize)]
pub struct AiExecRequest {
    pub command: String,
}

pub async fn ai_exec(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AiExecRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    match crate::ai::execute_safe_command(&body.command) {
        Ok(output) => HttpResponse::Ok().json(serde_json::json!({
            "output": output,
            "exit_code": 0,
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "error": e,
        })),
    }
}

/// GET /api/ai/status — agent status and last health check
pub async fn ai_status(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.ai_agent.config.lock().unwrap();
    let last_check = state.ai_agent.last_health_check.lock().unwrap().clone();
    let alert_count = state.ai_agent.alerts.lock().unwrap().len();
    let history_count = state.ai_agent.chat_history.lock().unwrap().len();

    HttpResponse::Ok().json(serde_json::json!({
        "configured": config.is_configured(),
        "provider": config.provider,
        "model": config.model,
        "last_health_check": last_check,
        "alert_count": alert_count,
        "chat_message_count": history_count,
        "knowledge_base_size": state.ai_agent.knowledge_base.len(),
    }))
}

/// GET /api/ai/alerts — historical alerts
pub async fn ai_alerts(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let alerts = state.ai_agent.alerts.lock().unwrap().clone();
    HttpResponse::Ok().json(alerts)
}

/// GET /api/ai/models?provider=claude|gemini — list available models
pub async fn ai_models(
    req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.ai_agent.config.lock().unwrap().clone();
    let provider = query.get("provider").map(|s| s.as_str()).unwrap_or(&config.provider);
    let api_key = match provider {
        "gemini" => &config.gemini_api_key,
        _ => &config.claude_api_key,
    };
    if api_key.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({ "models": [], "error": "No API key configured for this provider" }));
    }
    match state.ai_agent.list_models(provider, api_key).await {
        Ok(models) => HttpResponse::Ok().json(serde_json::json!({ "models": models })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "models": [], "error": e })),
    }
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

// ─── IP Mapping API ───

#[derive(Deserialize)]
pub struct CreateIpMappingRequest {
    pub public_ip: String,
    pub wolfnet_ip: String,
    pub ports: Option<String>,
    pub dest_ports: Option<String>,
    pub protocol: Option<String>,
    pub label: Option<String>,
}

/// GET /api/networking/ip-mappings — list all IP mappings
pub async fn net_list_ip_mappings(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::list_ip_mappings())
}

/// POST /api/networking/ip-mappings — create an IP mapping
pub async fn net_add_ip_mapping(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateIpMappingRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let protocol = body.protocol.as_deref().unwrap_or("all");
    let label = body.label.as_deref().unwrap_or("");
    match networking::add_ip_mapping(
        &body.public_ip,
        &body.wolfnet_ip,
        body.ports.as_deref(),
        body.dest_ports.as_deref(),
        protocol,
        label,
    ) {
        Ok(mapping) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Mapped {} → {}", mapping.public_ip, mapping.wolfnet_ip),
            "mapping": mapping,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/networking/ip-mappings/{id} — remove an IP mapping
pub async fn net_remove_ip_mapping(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match networking::remove_ip_mapping(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// PUT /api/networking/ip-mappings/{id} — update an existing mapping
pub async fn net_update_ip_mapping(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CreateIpMappingRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    let protocol = body.protocol.as_deref().unwrap_or("all");
    let label = body.label.as_deref().unwrap_or("");
    match networking::update_ip_mapping(
        &id,
        &body.public_ip,
        &body.wolfnet_ip,
        body.ports.as_deref(),
        body.dest_ports.as_deref(),
        protocol,
        label,
    ) {
        Ok(mapping) => HttpResponse::Ok().json(mapping),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/networking/available-ips — detect public + wolfnet IPs for the UI
pub async fn net_available_ips(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(serde_json::json!({
        "public_ips": networking::detect_public_ips(),
        "wolfnet_ips": networking::detect_wolfnet_ips(),
    }))
}

/// GET /api/networking/listening-ports — ports currently in use on server
pub async fn net_listening_ports(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(serde_json::json!({
        "listening": networking::get_listening_ports(),
        "blocked": networking::get_blocked_ports(),
    }))
}

// ─── Backup API ───

#[derive(Deserialize)]
pub struct CreateBackupRequest {
    /// Optional specific target — if omitted, backup everything
    pub target: Option<backup::BackupTarget>,
    pub storage: backup::BackupStorage,
}

#[derive(Deserialize)]
pub struct CreateScheduleRequest {
    pub name: String,
    pub frequency: backup::BackupFrequency,
    pub time: String,
    pub retention: u32,
    pub backup_all: bool,
    #[serde(default)]
    pub targets: Vec<backup::BackupTarget>,
    pub storage: backup::BackupStorage,
    #[serde(default = "default_true")]
    pub enabled: bool,
}
fn default_true() -> bool { true }

/// GET /api/backups — list all backup entries
pub async fn backup_list(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(backup::list_backups())
}

/// POST /api/backups — create a backup now
pub async fn backup_create(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateBackupRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    // If PBS storage selected, merge in saved secrets (frontend doesn't send them)
    let mut storage = body.storage.clone();
    if storage.storage_type == backup::StorageType::Pbs {
        let saved = backup::load_pbs_config();
        if storage.pbs_password.is_empty() && !saved.pbs_password.is_empty() {
            storage.pbs_password = saved.pbs_password;
        }
        if storage.pbs_token_secret.is_empty() && !saved.pbs_token_secret.is_empty() {
            storage.pbs_token_secret = saved.pbs_token_secret;
        }
        // Also fill in any missing connection details from saved config
        if storage.pbs_server.is_empty() { storage.pbs_server = saved.pbs_server; }
        if storage.pbs_datastore.is_empty() { storage.pbs_datastore = saved.pbs_datastore; }
        if storage.pbs_user.is_empty() { storage.pbs_user = saved.pbs_user; }
        if storage.pbs_token_name.is_empty() { storage.pbs_token_name = saved.pbs_token_name; }
        if storage.pbs_fingerprint.is_empty() { storage.pbs_fingerprint = saved.pbs_fingerprint; }
        if storage.pbs_namespace.is_empty() { storage.pbs_namespace = saved.pbs_namespace; }
    }
    let entries = backup::create_backup(body.target.clone(), storage);
    let success_count = entries.iter().filter(|e| e.status == backup::BackupStatus::Completed).count();
    let fail_count = entries.iter().filter(|e| e.status == backup::BackupStatus::Failed).count();
    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("{} backup(s) completed, {} failed", success_count, fail_count),
        "entries": entries,
    }))
}

/// DELETE /api/backups/{id} — delete a backup entry + file
pub async fn backup_delete(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match backup::delete_backup(&path.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/backups/{id}/restore — restore from a backup
pub async fn backup_restore(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match backup::restore_by_id(&path.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/backups/targets — list available backup targets
pub async fn backup_targets(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(backup::list_available_targets())
}

/// GET /api/backups/schedules — list schedules
pub async fn backup_schedules_list(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(backup::list_schedules())
}

/// POST /api/backups/schedules — create or update a schedule
pub async fn backup_schedule_create(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateScheduleRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let schedule = backup::BackupSchedule {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        frequency: body.frequency.clone(),
        time: body.time.clone(),
        retention: body.retention,
        backup_all: body.backup_all,
        targets: body.targets.clone(),
        storage: body.storage.clone(),
        enabled: body.enabled,
        last_run: String::new(),
    };
    match backup::save_schedule(schedule) {
        Ok(s) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Schedule '{}' created", s.name),
            "schedule": s,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/backups/schedules/{id} — delete a schedule
pub async fn backup_schedule_delete(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match backup::delete_schedule(&path.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/backups/import — receive a backup from remote node
pub async fn backup_import(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Bytes,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let filename = query.get("filename")
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("import-{}.tar.gz", chrono::Utc::now().timestamp()));
    match backup::import_backup(&body, &filename) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

// ─── Proxmox Backup Server (PBS) API ───

/// GET /api/backups/pbs/status — check PBS connectivity
pub async fn pbs_status(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    HttpResponse::Ok().json(backup::check_pbs_status(&config))
}

/// GET /api/backups/pbs/snapshots — list all PBS snapshots
pub async fn pbs_snapshots(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    match backup::list_pbs_snapshots(&config) {
        Ok(snapshots) => HttpResponse::Ok().json(snapshots),
        Err(e) => {
            eprintln!("PBS snapshot list failed: {}", e);
            HttpResponse::Ok().json(serde_json::json!([]))
        },
    }
}

#[derive(Deserialize)]
pub struct PbsRestoreRequest {
    pub snapshot: String,
    pub archive: String,
    #[serde(default = "default_pbs_target_dir")]
    pub target_dir: String,
}
fn default_pbs_target_dir() -> String { "/var/lib/wolfstack/restored".to_string() }

/// POST /api/backups/pbs/restore — restore a PBS snapshot (runs in background)
pub async fn pbs_restore(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<PbsRestoreRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    // Check if a restore is already running (auto-expire after 30 min)
    {
        let mut progress = state.pbs_restore_progress.lock().unwrap();
        let stale = progress.started_at
            .map(|t| t.elapsed().as_secs() > 1800)
            .unwrap_or(true);
        if progress.active && !progress.finished && !stale {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "A restore is already in progress",
                "snapshot": progress.snapshot,
            }));
        }
        // Clear stale or finished state
        if stale || progress.finished {
            *progress = PbsRestoreProgress::default();
        }
    }

    let config = backup::load_pbs_config();
    let snapshot = body.snapshot.clone();
    let archive = body.archive.clone();
    let target_dir = body.target_dir.clone();

    // Reset progress state
    {
        let mut progress = state.pbs_restore_progress.lock().unwrap();
        *progress = PbsRestoreProgress {
            active: true,
            snapshot: snapshot.clone(),
            progress_text: "Starting restore...".to_string(),
            percentage: Some(0.0),
            finished: false,
            success: None,
            message: String::new(),
            started_at: Some(std::time::Instant::now()),
        };
    }

    // Spawn background thread
    let state_clone = state.clone();
    std::thread::spawn(move || {
        match backup::restore_from_pbs_with_progress(&config, &snapshot, &archive, &target_dir, |text, pct| {
            if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                progress.progress_text = text;
                progress.percentage = pct;
            }
        }) {
            Ok(msg) => {
                if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                    progress.active = false;
                    progress.finished = true;
                    progress.success = Some(true);
                    progress.message = msg;
                    progress.percentage = Some(100.0);
                    progress.progress_text = "Restore complete!".to_string();
                }
            }
            Err(e) => {
                if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                    progress.active = false;
                    progress.finished = true;
                    progress.success = Some(false);
                    progress.message = e;
                    progress.progress_text = "Restore failed".to_string();
                }
            }
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "started",
        "message": "Restore started in background",
    }))
}

/// GET /api/backups/pbs/restore/progress — poll restore progress
pub async fn pbs_restore_progress(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let progress = state.pbs_restore_progress.lock().unwrap().clone();
    HttpResponse::Ok().json(progress)
}

/// GET /api/backups/pbs/config — get PBS configuration
pub async fn pbs_config_get(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    // Return config without the token secret for security
    HttpResponse::Ok().json(serde_json::json!({
        "pbs_server": config.pbs_server,
        "pbs_datastore": config.pbs_datastore,
        "pbs_user": config.pbs_user,
        "pbs_token_name": config.pbs_token_name,
        "pbs_fingerprint": config.pbs_fingerprint,
        "pbs_namespace": config.pbs_namespace,
        "has_token_secret": !config.pbs_token_secret.is_empty(),
        "has_password": !config.pbs_password.is_empty(),
    }))
}

#[derive(Deserialize)]
pub struct PbsConfigRequest {
    pub pbs_server: String,
    pub pbs_datastore: String,
    pub pbs_user: String,
    #[serde(default)]
    pub pbs_token_name: String,
    #[serde(default)]
    pub pbs_token_secret: String,
    #[serde(default)]
    pub pbs_password: String,
    #[serde(default)]
    pub pbs_fingerprint: String,
    #[serde(default)]
    pub pbs_namespace: String,
}

/// POST /api/backups/pbs/config — save PBS configuration
pub async fn pbs_config_save(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<PbsConfigRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    // Preserve existing secrets if the user didn't re-enter them
    let existing = backup::load_pbs_config();
    let storage = backup::BackupStorage {
        storage_type: backup::StorageType::Pbs,
        pbs_server: body.pbs_server.clone(),
        pbs_datastore: body.pbs_datastore.clone(),
        pbs_user: body.pbs_user.clone(),
        pbs_token_name: body.pbs_token_name.clone(),
        pbs_token_secret: if body.pbs_token_secret.is_empty() {
            existing.pbs_token_secret
        } else {
            body.pbs_token_secret.clone()
        },
        pbs_password: if body.pbs_password.is_empty() {
            existing.pbs_password
        } else {
            body.pbs_password.clone()
        },
        pbs_fingerprint: body.pbs_fingerprint.clone(),
        pbs_namespace: body.pbs_namespace.clone(),
        ..backup::BackupStorage::default()
    };
    match backup::save_pbs_config(&storage) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "PBS configuration saved",
        })),
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

/// GET /api/storage/providers — list installed storage providers
pub async fn storage_list_providers(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::list_providers())
}

/// POST /api/storage/providers/{name}/install — install a storage provider
pub async fn storage_install_provider(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let name = path.into_inner();
    let result = web::block(move || storage::install_provider(&name)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

#[derive(Deserialize)]
pub struct SystemLogsQuery {
    pub lines: Option<usize>,
    pub search: Option<String>,
    pub unit: Option<String>,
}

/// GET /api/system/logs — read system journal logs
pub async fn system_logs(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<SystemLogsQuery>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let lines = query.lines.unwrap_or(200).min(5000);
    let search = query.search.as_deref();
    let unit = query.unit.as_deref();
    let logs = storage::read_system_logs(lines, search, unit);
    HttpResponse::Ok().json(serde_json::json!({
        "lines": logs,
        "count": logs.len(),
    }))
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

// ─── Disk Partition Info ───

/// GET /api/storage/disk-info — list all block devices, partitions, filesystems & free space
pub async fn storage_disk_info(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    // Run lsblk in JSON mode with useful columns
    let lsblk_out = std::process::Command::new("lsblk")
        .args([
            "-J",
            "-o", "NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS,TYPE,HOTPLUG,ROTA,MODEL",
            "--bytes",
        ])
        .output();

    let block_devices: serde_json::Value = match lsblk_out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "blockdevices": [] }))
        }
        _ => serde_json::json!({ "blockdevices": [] }),
    };

    // Run df to get free-space per mount point
    let df_out = std::process::Command::new("df")
        .args(["-B1", "--output=target,avail,size,pcent"])
        .output();

    let mut df_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    if let Ok(o) = df_out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mountpoint = parts[0].to_string();
                let avail_bytes: u64 = parts[1].parse().unwrap_or(0);
                let total_bytes: u64 = parts[2].parse().unwrap_or(0);
                let use_pct = parts[3].trim_end_matches('%');
                let use_pct: f64 = use_pct.parse().unwrap_or(0.0);
                let free_pct = (100.0 - use_pct).max(0.0);
                df_map.insert(mountpoint, serde_json::json!({
                    "avail_bytes": avail_bytes,
                    "total_bytes": total_bytes,
                    "use_pct": use_pct,
                    "free_pct": free_pct,
                }));
            }
        }
    }

    // Walk lsblk tree and flatten into a list of partitions/disks with free-space data
    fn fmt_bytes(b: u64) -> String {
        const TB: u64 = 1_099_511_627_776;
        const GB: u64 = 1_073_741_824;
        const MB: u64 = 1_048_576;
        if b >= TB      { format!("{:.1} TB", b as f64 / TB as f64) }
        else if b >= GB { format!("{:.1} GB", b as f64 / GB as f64) }
        else if b >= MB { format!("{:.1} MB", b as f64 / MB as f64) }
        else            { format!("{} B", b) }
    }

    fn walk_devices(
        devices: &[serde_json::Value],
        df_map: &std::collections::HashMap<String, serde_json::Value>,
        parent_disk: &str,
        parent_model: &str,
        out: &mut Vec<serde_json::Value>,
    ) {
        for dev in devices {
            let name = dev.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let dev_path = format!("/dev/{}", name);
            let size_bytes: u64 = dev.get("size")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .or_else(|| dev.get("size").and_then(|v| v.as_u64()))
                .unwrap_or(0);
            let size_str = fmt_bytes(size_bytes);
            let fstype = dev.get("fstype").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let label  = dev.get("label").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let kind   = dev.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let model  = dev.get("model").and_then(|v| v.as_str()).unwrap_or(parent_model).to_string();
            let hotplug = dev.get("hotplug").and_then(|v| v.as_bool()).unwrap_or(false);
            let rotational = dev.get("rota").and_then(|v| v.as_bool()).unwrap_or(true);

            // Collect mountpoints
            let mounts: Vec<String> = dev.get("mountpoints")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|m| m.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect())
                .unwrap_or_default();

            // Get df data for the first mount point
            let df = mounts.first()
                .and_then(|mp| df_map.get(mp.as_str()))
                .cloned()
                .unwrap_or(serde_json::json!(null));

            let disk_name = if kind == "disk" { name } else { parent_disk };
            let disk_model = if kind == "disk" { &model } else { parent_model };

            out.push(serde_json::json!({
                "device": dev_path,
                "disk": format!("/dev/{}", disk_name),
                "model": disk_model,
                "type": kind,
                "size": size_str,
                "size_bytes": size_bytes,
                "fstype": if fstype.is_empty() { serde_json::json!(null) } else { serde_json::json!(fstype) },
                "label": if label.is_empty() { serde_json::json!(null) } else { serde_json::json!(label) },
                "mountpoints": mounts,
                "hotplug": hotplug,
                "rotational": rotational,
                "df": df,
            }));

            // Recurse into children (partitions)
            if let Some(children) = dev.get("children").and_then(|v| v.as_array()) {
                walk_devices(children, df_map, disk_name, disk_model, out);
            }
        }
    }

    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Some(devs) = block_devices.get("blockdevices").and_then(|v| v.as_array()) {
        walk_devices(devs, &df_map, "", "", &mut entries);
    }

    HttpResponse::Ok().json(serde_json::json!({ "devices": entries }))
}

// ─── ZFS Storage ───

/// GET /api/storage/zfs/status — check if ZFS is available and return overview
pub async fn zfs_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let available = std::process::Command::new("which").arg("zfs").output()
        .map(|o| o.status.success()).unwrap_or(false);

    if !available {
        return HttpResponse::Ok().json(serde_json::json!({
            "available": false,
            "pools": []
        }));
    }

    // Get pool summary
    let pools = zfs_get_pools();
    HttpResponse::Ok().json(serde_json::json!({
        "available": true,
        "pools": pools
    }))
}

/// GET /api/storage/zfs/pools — list all ZFS pools with usage stats
pub async fn zfs_pools(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(zfs_get_pools())
}

/// GET /api/storage/zfs/datasets?pool=POOL — list datasets for a pool
pub async fn zfs_datasets(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = query.get("pool").cloned().unwrap_or_default();
    if pool.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'pool' parameter" }));
    }
    // Validate pool name (alphanumeric, dash, underscore, dot only)
    if !pool.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let output = std::process::Command::new("zfs")
        .args(["list", "-H", "-r", "-o", "name,used,avail,refer,mountpoint,compression,compressratio", &pool])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let datasets: Vec<serde_json::Value> = text.lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    serde_json::json!({
                        "name": parts.get(0).unwrap_or(&""),
                        "used": parts.get(1).unwrap_or(&""),
                        "available": parts.get(2).unwrap_or(&""),
                        "refer": parts.get(3).unwrap_or(&""),
                        "mountpoint": parts.get(4).unwrap_or(&""),
                        "compression": parts.get(5).unwrap_or(&""),
                        "compressratio": parts.get(6).unwrap_or(&""),
                    })
                })
                .collect();
            HttpResponse::Ok().json(datasets)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/zfs/snapshots?dataset=DATASET — list snapshots
pub async fn zfs_snapshots(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let dataset = query.get("dataset").cloned().unwrap_or_default();

    let mut args = vec!["list", "-t", "snapshot", "-H", "-o", "name,creation,used,refer"];
    if !dataset.is_empty() {
        if !dataset.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == '@') {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid dataset name" }));
        }
        args.push("-r");
        args.push(&dataset);
    }

    let output = std::process::Command::new("zfs").args(&args).output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let snapshots: Vec<serde_json::Value> = text.lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    serde_json::json!({
                        "name": parts.get(0).unwrap_or(&""),
                        "creation": parts.get(1).unwrap_or(&""),
                        "used": parts.get(2).unwrap_or(&""),
                        "refer": parts.get(3).unwrap_or(&""),
                    })
                })
                .collect();
            HttpResponse::Ok().json(snapshots)
        }
        Ok(out) => {
            let _err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(Vec::<serde_json::Value>::new()) // empty list if no snapshots
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/storage/zfs/snapshot — create a snapshot
pub async fn zfs_create_snapshot(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let dataset = body.get("dataset").and_then(|v| v.as_str()).unwrap_or("");
    let snap_name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");

    if dataset.is_empty() || snap_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'dataset' or 'name'" }));
    }
    // Validate names
    let valid_chars = |s: &str| s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/');
    if !valid_chars(dataset) || !valid_chars(snap_name) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid characters in dataset or snapshot name" }));
    }

    let snapshot_full = format!("{}@{}", dataset, snap_name);
    let output = std::process::Command::new("zfs")
        .args(["snapshot", &snapshot_full])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "message": format!("Snapshot '{}' created", snapshot_full) }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// DELETE /api/storage/zfs/snapshot — delete a snapshot
pub async fn zfs_delete_snapshot(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let snapshot = body.get("snapshot").and_then(|v| v.as_str()).unwrap_or("");

    if snapshot.is_empty() || !snapshot.contains('@') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid snapshot name (must contain @)" }));
    }
    if !snapshot.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == '@') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid characters in snapshot name" }));
    }

    let output = std::process::Command::new("zfs")
        .args(["destroy", snapshot])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "message": format!("Snapshot '{}' deleted", snapshot) }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// Helper: parse zpool list output into JSON
fn zfs_get_pools() -> Vec<serde_json::Value> {
    let output = std::process::Command::new("zpool")
        .args(["list", "-H", "-o", "name,size,alloc,free,health,fragmentation,capacity,dedup,altroot"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let mut pools: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout).lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    serde_json::json!({
                        "name": parts.get(0).unwrap_or(&""),
                        "size": parts.get(1).unwrap_or(&""),
                        "alloc": parts.get(2).unwrap_or(&""),
                        "free": parts.get(3).unwrap_or(&""),
                        "health": parts.get(4).unwrap_or(&""),
                        "fragmentation": parts.get(5).unwrap_or(&""),
                        "capacity": parts.get(6).unwrap_or(&""),
                        "dedup": parts.get(7).unwrap_or(&"1.00x"),
                        "altroot": parts.get(8).unwrap_or(&"-"),
                    })
                })
                .collect();

            // Enrich each pool with scan/scrub status from `zpool status`
            for pool in &mut pools {
                let pool_name = pool["name"].as_str().unwrap_or("").to_string();
                if let Ok(status_out) = std::process::Command::new("zpool")
                    .args(["status", &pool_name])
                    .output()
                {
                    if status_out.status.success() {
                        let status_text = String::from_utf8_lossy(&status_out.stdout).to_string();
                        // Extract scan line
                        let scan_line = status_text.lines()
                            .find(|l| l.trim_start().starts_with("scan:"))
                            .map(|l| l.trim_start().trim_start_matches("scan:").trim().to_string())
                            .unwrap_or_else(|| "none requested".to_string());
                        // Extract errors line
                        let errors_line = status_text.lines()
                            .find(|l| l.trim_start().starts_with("errors:"))
                            .map(|l| l.trim_start().trim_start_matches("errors:").trim().to_string())
                            .unwrap_or_else(|| "unknown".to_string());

                        pool["scan"] = serde_json::json!(scan_line);
                        pool["errors"] = serde_json::json!(errors_line);
                    }
                }
            }

            pools
        }
        _ => vec![],
    }
}

/// POST /api/storage/zfs/pool/scrub — start or stop a scrub
pub async fn zfs_pool_scrub(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = body.get("pool").and_then(|v| v.as_str()).unwrap_or("").trim();
    let stop = body.get("stop").and_then(|v| v.as_bool()).unwrap_or(false);
    if pool.is_empty() || pool.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let mut args = vec!["scrub"];
    if stop { args.push("-s"); }
    args.push(pool);

    let output = std::process::Command::new("zpool").args(&args).output();
    match output {
        Ok(out) if out.status.success() => {
            let msg = if stop { format!("Scrub stopped on pool '{}'", pool) }
                      else { format!("Scrub started on pool '{}'", pool) };
            HttpResponse::Ok().json(serde_json::json!({ "message": msg }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err.trim() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/zfs/pool/status?pool=POOL — detailed pool status (vdevs, errors, scan)
pub async fn zfs_pool_status(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = query.get("pool").cloned().unwrap_or_default();
    let pool = pool.trim().to_string();
    if pool.is_empty() || pool.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let output = std::process::Command::new("zpool").args(["status", "-v", &pool]).output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "pool": pool,
                "status_text": text,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err.trim() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/zfs/pool/iostat?pool=POOL — pool IO statistics
pub async fn zfs_pool_iostat(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = query.get("pool").cloned().unwrap_or_default();
    let pool = pool.trim().to_string();
    if pool.is_empty() || pool.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let output = std::process::Command::new("zpool").args(["iostat", "-v", &pool]).output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "pool": pool,
                "iostat_text": text,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err.trim() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── File Manager ───

/// Validate and normalize a file path — prevent traversal attacks
fn sanitize_file_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = std::path::Path::new(path);
    // Must be absolute
    if !p.is_absolute() {
        return Err("Path must be absolute".into());
    }
    // Canonicalize to resolve .. and symlinks
    match p.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(_) => {
            // For paths that don't exist yet (e.g., mkdir), check the parent
            if let Some(parent) = p.parent() {
                if let Ok(canonical_parent) = parent.canonicalize() {
                    let file_name = p.file_name().ok_or("Invalid path")?;
                    Ok(canonical_parent.join(file_name))
                } else {
                    Err("Parent directory does not exist".into())
                }
            } else {
                Err("Invalid path".into())
            }
        }
    }
}

/// GET /api/files/browse?path=/some/path — list directory contents
pub async fn files_browse(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = query.get("path").cloned().unwrap_or_else(|| "/".into());

    let canonical = match sanitize_file_path(&path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    if !canonical.is_dir() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a directory" }));
    }

    let mut entries = Vec::new();
    match std::fs::read_dir(&canonical) {
        Ok(dir) => {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let meta = entry.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let modified = meta.as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // Unix permissions
                #[cfg(unix)]
                let permissions = {
                    use std::os::unix::fs::PermissionsExt;
                    meta.as_ref()
                        .map(|m| format!("{:o}", m.permissions().mode() & 0o7777))
                        .unwrap_or_default()
                };
                #[cfg(not(unix))]
                let permissions = String::new();

                let entry_path = canonical.join(&name);
                entries.push(serde_json::json!({
                    "name": name,
                    "path": entry_path.to_string_lossy(),
                    "is_dir": is_dir,
                    "size": if is_dir { 0 } else { size },
                    "modified": modified,
                    "permissions": permissions,
                }));
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Cannot read directory: {}", e)
            }));
        }
    }

    // Sort: directories first, then alphabetically
    entries.sort_by(|a, b| {
        let a_dir = a["is_dir"].as_bool().unwrap_or(false);
        let b_dir = b["is_dir"].as_bool().unwrap_or(false);
        match (a_dir, b_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a["name"].as_str().unwrap_or("")
                .to_lowercase()
                .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "path": canonical.to_string_lossy(),
        "entries": entries,
    }))
}

/// POST /api/files/mkdir — create directory
pub async fn files_mkdir(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" }));
    }

    let canonical = match sanitize_file_path(path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    match std::fs::create_dir_all(&canonical) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Directory created: {}", canonical.display())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create directory: {}", e)
        })),
    }
}

/// POST /api/files/delete — delete file or directory
pub async fn files_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" }));
    }

    let canonical = match sanitize_file_path(path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    // Prevent deleting critical system paths
    let critical = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev", "/var", "/root"];
    if critical.contains(&canonical.to_string_lossy().as_ref()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete system directory" }));
    }

    let result = if canonical.is_dir() {
        std::fs::remove_dir_all(&canonical)
    } else {
        std::fs::remove_file(&canonical)
    };

    match result {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Deleted: {}", canonical.display())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete: {}", e)
        })),
    }
}

/// POST /api/files/rename — rename / move a file or directory
pub async fn files_rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let from = body.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if from.is_empty() || to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'from' or 'to'" }));
    }

    let from_path = match sanitize_file_path(from) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };
    let to_path = match sanitize_file_path(to) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    match std::fs::rename(&from_path, &to_path) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Renamed to {}", to_path.display())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to rename: {}", e)
        })),
    }
}

/// POST /api/files/upload?path=/some/dir — upload file(s) via multipart
pub async fn files_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let dir = query.get("path").cloned().unwrap_or_else(|| "/tmp".into());

    let canonical_dir = match sanitize_file_path(&dir) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    if !canonical_dir.is_dir() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Target is not a directory" }));
    }

    use futures::StreamExt;
    let mut uploaded = Vec::new();

    while let Some(Ok(mut field)) = payload.next().await {
        let filename = field.content_disposition()
            .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
            .unwrap_or_else(|| "upload".to_string());

        // Sanitize filename
        let safe_name = filename.replace("..", "").replace("/", "").replace("\\", "");
        if safe_name.is_empty() { continue; }

        let file_path = canonical_dir.join(&safe_name);
        let mut file = match std::fs::File::create(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Cannot create file {}: {}", safe_name, e)
                }));
            }
        };

        use std::io::Write;
        while let Some(Ok(chunk)) = field.next().await {
            if file.write_all(&chunk).is_err() {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to write file {}", safe_name)
                }));
            }
        }
        uploaded.push(safe_name);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Uploaded {} file(s)", uploaded.len()),
        "files": uploaded,
    }))
}

/// GET /api/files/download?path=/some/file — download a file
pub async fn files_download(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = query.get("path").cloned().unwrap_or_default();
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" }));
    }

    let canonical = match sanitize_file_path(&path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    if !canonical.is_file() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a file" }));
    }

    let filename = canonical.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".into());

    match std::fs::read(&canonical) {
        Ok(data) => HttpResponse::Ok()
            .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
            .insert_header(("Content-Type", "application/octet-stream"))
            .body(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Cannot read file: {}", e)
        })),
    }
}

/// GET /api/files/search?path=/start&query=pattern — recursive search using find
pub async fn files_search(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let search_path = query.get("path").cloned().unwrap_or_else(|| "/".into());
    let search_query = query.get("query").cloned().unwrap_or_default();

    if search_query.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'query'" }));
    }

    let canonical = match sanitize_file_path(&search_path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    // Use find with -iname for case-insensitive matching, limit results
    let output = std::process::Command::new("find")
        .args([canonical.to_str().unwrap_or("/"), "-maxdepth", "8",
               "-iname", &format!("*{}*", search_query),
               "-printf", "%y\t%s\t%T@\t%m\t%p\n"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let mut entries: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .take(100) // cap results
                .map(|line| {
                    let parts: Vec<&str> = line.splitn(5, '\t').collect();
                    let file_type = parts.get(0).unwrap_or(&"f");
                    let size: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let modified: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    let permissions = parts.get(3).unwrap_or(&"").to_string();
                    let full_path = parts.get(4).unwrap_or(&"").to_string();
                    let name = std::path::Path::new(&full_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| full_path.clone());
                    let is_dir = *file_type == "d";

                    serde_json::json!({
                        "name": name,
                        "path": full_path,
                        "is_dir": is_dir,
                        "size": if is_dir { 0 } else { size },
                        "modified": modified as u64,
                        "permissions": permissions,
                    })
                })
                .collect();

            entries.sort_by(|a, b| {
                let ad = a["is_dir"].as_bool().unwrap_or(false);
                let bd = b["is_dir"].as_bool().unwrap_or(false);
                match (ad, bd) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a["name"].as_str().unwrap_or("").to_lowercase()
                        .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
                }
            });

            HttpResponse::Ok().json(serde_json::json!({
                "path": search_path,
                "query": search_query,
                "entries": entries,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "path": search_path,
                "query": search_query,
                "entries": [],
                "warning": err.trim(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/chmod — change permissions on a file or files
pub async fn files_chmod(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    let paths: Vec<String> = body.get("paths")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if mode.is_empty() || paths.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'mode' or 'paths'" }));
    }

    // Validate mode (must be octal like 755 or symbolic like u+x)
    if mode.len() > 10 || mode.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid mode" }));
    }

    let mut results = Vec::new();
    for path in &paths {
        let canonical = match sanitize_file_path(path) {
            Ok(p) => p,
            Err(e) => { results.push(serde_json::json!({"path": path, "error": e})); continue; }
        };
        let output = std::process::Command::new("chmod")
            .args([mode, canonical.to_str().unwrap_or("")])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                results.push(serde_json::json!({"path": path, "ok": true}));
            }
            Ok(out) => {
                results.push(serde_json::json!({"path": path, "error": String::from_utf8_lossy(&out.stderr).trim().to_string()}));
            }
            Err(e) => {
                results.push(serde_json::json!({"path": path, "error": format!("{}", e)}));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "results": results }))
}

/// GET /api/files/docker/browse?container=ID&path=/ — browse files inside a Docker container
pub async fn files_docker_browse(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_else(|| "/".into());

    if container.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" }));
    }

    // Use docker exec to list directory contents with stat-like output
    let output = std::process::Command::new("docker")
        .args(["exec", &container, "find", &path, "-maxdepth", "1", "-mindepth", "1",
               "-printf", "%y\\t%s\\t%T@\\t%m\\t%f\\n"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let mut entries: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.splitn(5, '\t').collect();
                    let file_type = parts.get(0).unwrap_or(&"f");
                    let size: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let modified: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    let permissions = parts.get(3).unwrap_or(&"");
                    let name = parts.get(4).unwrap_or(&"");
                    let is_dir = *file_type == "d";
                    let entry_path = if path.ends_with('/') {
                        format!("{}{}", path, name)
                    } else {
                        format!("{}/{}", path, name)
                    };

                    serde_json::json!({
                        "name": name,
                        "path": entry_path,
                        "is_dir": is_dir,
                        "size": if is_dir { 0 } else { size },
                        "modified": modified as u64,
                        "permissions": permissions,
                    })
                })
                .collect();

            // Sort: directories first, then alphabetically
            entries.sort_by(|a, b| {
                let a_dir = a["is_dir"].as_bool().unwrap_or(false);
                let b_dir = b["is_dir"].as_bool().unwrap_or(false);
                match (a_dir, b_dir) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a["name"].as_str().unwrap_or("")
                        .to_lowercase()
                        .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
                }
            });

            HttpResponse::Ok().json(serde_json::json!({
                "path": path,
                "container": container,
                "entries": entries,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list directory: {}", err.trim())
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to exec into container: {}", e)
        })),
    }
}

/// POST /api/files/docker/mkdir — create directory inside Docker container
pub async fn files_docker_mkdir(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let output = std::process::Command::new("docker")
        .args(["exec", container, "mkdir", "-p", path])
        .output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Directory created: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/docker/delete — delete file/dir inside Docker container
pub async fn files_docker_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let critical = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc", "/sys", "/dev", "/var"];
    if critical.contains(&path) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete system directory" }));
    }

    let output = std::process::Command::new("docker")
        .args(["exec", container, "rm", "-rf", path])
        .output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Deleted: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/docker/rename — rename file/dir inside Docker container
pub async fn files_docker_rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let from = body.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || from.is_empty() || to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing fields" }));
    }

    let output = std::process::Command::new("docker")
        .args(["exec", container, "mv", from, to])
        .output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Renamed to {}", to) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/files/docker/download?container=ID&path=/file — download file from Docker container
pub async fn files_docker_download(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_default();
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    // Use docker cp to a temp file
    let tmp = format!("/tmp/wolfstack-docker-dl-{}", std::process::id());
    let src = format!("{}:{}", container, path);
    let output = std::process::Command::new("docker").args(["cp", &src, &tmp]).output();

    match output {
        Ok(out) if out.status.success() => {
            let filename = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "download".into());

            match std::fs::read(&tmp) {
                Ok(data) => {
                    let _ = std::fs::remove_file(&tmp);
                    HttpResponse::Ok()
                        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                        .insert_header(("Content-Type", "application/octet-stream"))
                        .body(data)
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Read error: {}", e) }))
                }
            }
        }
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": String::from_utf8_lossy(&out.stderr).trim().to_string()
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── LXC File Manager ───

/// Detect if Proxmox `pct` is available, and use `pct exec` if so; else `lxc-attach`.
fn lxc_exec_cmd(container: &str, cmd_args: &[&str]) -> std::process::Command {
    let is_proxmox = std::process::Command::new("which").arg("pct").output()
        .map(|o| o.status.success()).unwrap_or(false);
    let mut cmd;
    if is_proxmox {
        cmd = std::process::Command::new("pct");
        cmd.arg("exec").arg(container).arg("--");
    } else {
        cmd = std::process::Command::new("lxc-attach");
        cmd.arg("-n").arg(container).arg("--");
    }
    for a in cmd_args { cmd.arg(a); }
    cmd
}

/// GET /api/files/lxc/browse?container=NAME&path=/ — browse files inside an LXC container
pub async fn files_lxc_browse(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_else(|| "/".into());

    if container.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" }));
    }

    // Use a POSIX shell one-liner that works everywhere (BusyBox, Alpine, Debian, etc.)
    // Output format per line: TYPE<tab>SIZE<tab>NAME
    // TYPE: d = directory, f = file, l = link
    let script = format!(
        "cd '{}' 2>/dev/null && for f in .* *; do [ \"$f\" = '.' ] || [ \"$f\" = '..' ] || [ \"$f\" = '.*' ] || [ \"$f\" = '*' ] && continue; if [ -L \"$f\" ]; then printf 'l\\t0\\t%s\\n' \"$f\"; elif [ -d \"$f\" ]; then printf 'd\\t0\\t%s\\n' \"$f\"; else s=$(stat -c%s \"$f\" 2>/dev/null || echo 0); printf 'f\\t'\"$s\"'\\t%s\\n' \"$f\"; fi; done",
        path.replace('\'', "'\\''")
    );

    let output = lxc_exec_cmd(&container, &["sh", "-c", &script]).output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut entries: Vec<serde_json::Value> = stdout
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(3, '\t').collect();
                    if parts.len() < 3 { return None; }

                    let file_type = parts[0];
                    let size: u64 = parts[1].parse().unwrap_or(0);
                    let name = parts[2].to_string();

                    if name.is_empty() { return None; }

                    let is_dir = file_type == "d" || file_type == "l";
                    let entry_path = if path.ends_with('/') {
                        format!("{}{}", path, name)
                    } else {
                        format!("{}/{}", path, name)
                    };

                    Some(serde_json::json!({
                        "name": name,
                        "path": entry_path,
                        "is_dir": is_dir,
                        "size": if is_dir { 0 } else { size },
                        "modified": 0,
                        "permissions": "",
                    }))
                })
                .collect();

            entries.sort_by(|a, b| {
                let a_dir = a["is_dir"].as_bool().unwrap_or(false);
                let b_dir = b["is_dir"].as_bool().unwrap_or(false);
                match (a_dir, b_dir) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a["name"].as_str().unwrap_or("")
                        .to_lowercase()
                        .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
                }
            });

            HttpResponse::Ok().json(serde_json::json!({
                "path": path,
                "container": container,
                "entries": entries,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            info!("LXC browse failed for container={} path={}: stderr={} stdout={}", container, path, err.trim(), stdout.trim());
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list directory: {}", err.trim())
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to exec into container: {}", e)
        })),
    }
}

/// POST /api/files/lxc/mkdir — create directory inside LXC container
pub async fn files_lxc_mkdir(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let output = lxc_exec_cmd(container, &["mkdir", "-p", path]).output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Directory created: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/lxc/delete — delete file/dir inside LXC container
pub async fn files_lxc_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let critical = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc", "/sys", "/dev", "/var"];
    if critical.contains(&path) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete system directory" }));
    }

    let output = lxc_exec_cmd(container, &["rm", "-rf", path]).output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Deleted: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/lxc/rename — rename file/dir inside LXC container
pub async fn files_lxc_rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let from = body.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || from.is_empty() || to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing fields" }));
    }

    let output = lxc_exec_cmd(container, &["mv", from, to]).output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Renamed to {}", to) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/files/lxc/download?container=NAME&path=/file — download file from LXC container
pub async fn files_lxc_download(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_default();
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    // Use lxc-attach cat to stream the file content
    let output = lxc_exec_cmd(&container, &["cat", &path]).output();

    match output {
        Ok(out) if out.status.success() => {
            let filename = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "download".into());

            HttpResponse::Ok()
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .insert_header(("Content-Type", "application/octet-stream"))
                .body(out.stdout)
        }
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to read file: {}", String::from_utf8_lossy(&out.stderr).trim())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
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

/// POST /api/upgrade — run the WolfStack upgrade script in the background
// ─── Config Export / Import ───

/// Export all WolfStack configuration as a JSON file
pub async fn config_export(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    info!("Config export requested");

    let mut bundle = serde_json::Map::new();

    // Helper: read a JSON file and insert into bundle
    fn read_json_file(path: &str) -> Option<serde_json::Value> {
        std::fs::read_to_string(path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    // Nodes (cluster links)
    if let Some(v) = read_json_file("/etc/wolfstack/nodes.json") {
        bundle.insert("nodes".into(), v);
    }
    // AI config
    if let Some(v) = read_json_file("/etc/wolfstack/ai-config.json") {
        bundle.insert("ai_config".into(), v);
    }
    // Storage config
    if let Some(v) = read_json_file("/etc/wolfstack/storage.json") {
        bundle.insert("storage_config".into(), v);
    }
    // Backup config (schedules only — strip entries to keep it small)
    if let Some(v) = read_json_file("/etc/wolfstack/backups.json") {
        if let Some(obj) = v.as_object() {
            let mut cleaned = serde_json::Map::new();
            if let Some(schedules) = obj.get("schedules") {
                cleaned.insert("schedules".into(), schedules.clone());
            }
            bundle.insert("backup_config".into(), serde_json::Value::Object(cleaned));
        }
    }
    // IP mappings
    if let Some(v) = read_json_file("/etc/wolfstack/ip-mappings.json") {
        bundle.insert("ip_mappings".into(), v);
    }
    // PBS config
    if let Some(v) = read_json_file("/etc/wolfstack/pbs/config.json") {
        bundle.insert("pbs_config".into(), v);
    }

    // Add metadata
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    bundle.insert("exported_from".into(), serde_json::Value::String(hostname));
    bundle.insert("exported_at".into(), serde_json::Value::String(
        chrono::Utc::now().to_rfc3339()
    ));
    bundle.insert("version".into(), serde_json::Value::String(
        env!("CARGO_PKG_VERSION").to_string()
    ));

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Content-Disposition", "attachment; filename=\"wolfstack-config.json\""))
        .json(serde_json::Value::Object(bundle))
}

/// Import WolfStack configuration from a JSON bundle
pub async fn config_import(
    req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    info!("Config import requested");

    let bundle = body.into_inner();
    let obj = match bundle.as_object() {
        Some(o) => o,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid config bundle — expected JSON object"
        })),
    };

    let mut imported = Vec::new();
    let mut errors = Vec::new();

    // Ensure config dir exists
    let _ = std::fs::create_dir_all("/etc/wolfstack");

    // Import nodes — merge with existing, skip self
    if let Some(nodes_val) = obj.get("nodes") {
        match import_nodes(nodes_val, &state) {
            Ok(count) => imported.push(format!("{} nodes", count)),
            Err(e) => errors.push(format!("nodes: {}", e)),
        }
    }

    // Simple file imports
    let file_imports = [
        ("ai_config", "/etc/wolfstack/ai-config.json", "AI config"),
        ("storage_config", "/etc/wolfstack/storage.json", "storage config"),
        ("ip_mappings", "/etc/wolfstack/ip-mappings.json", "IP mappings"),
    ];

    for (key, path, label) in &file_imports {
        if let Some(val) = obj.get(*key) {
            match write_json_file(path, val) {
                Ok(_) => imported.push(label.to_string()),
                Err(e) => errors.push(format!("{}: {}", label, e)),
            }
        }
    }

    // Reload AI config into the running agent so changes take effect immediately
    if obj.contains_key("ai_config") {
        let reloaded = crate::ai::AiConfig::load();
        let mut cfg = state.ai_agent.config.lock().unwrap();
        *cfg = reloaded;
        info!("AI config reloaded from imported file");
    }

    // Backup config (schedules only)
    if let Some(val) = obj.get("backup_config") {
        // Merge schedules into existing config, keeping existing entries
        let mut config = backup::load_config();
        if let Some(schedules) = val.get("schedules").and_then(|v| v.as_array()) {
            if let Ok(imported_schedules) = serde_json::from_value::<Vec<backup::BackupSchedule>>(
                serde_json::Value::Array(schedules.clone())
            ) {
                let existing_ids: std::collections::HashSet<String> =
                    config.schedules.iter().map(|s| s.id.clone()).collect();
                let mut added = 0;
                for schedule in imported_schedules {
                    if !existing_ids.contains(&schedule.id) {
                        config.schedules.push(schedule);
                        added += 1;
                    }
                }
                if let Err(e) = backup::save_config(&config) {
                    errors.push(format!("backup schedules: {}", e));
                } else {
                    imported.push(format!("{} backup schedules", added));
                }
            }
        }
    }

    // PBS config
    if let Some(val) = obj.get("pbs_config") {
        let _ = std::fs::create_dir_all("/etc/wolfstack/pbs");
        match write_json_file("/etc/wolfstack/pbs/config.json", val) {
            Ok(_) => imported.push("PBS config".into()),
            Err(e) => errors.push(format!("PBS config: {}", e)),
        }
    }

    let summary = if errors.is_empty() {
        format!("Successfully imported: {}", imported.join(", "))
    } else {
        format!("Imported: {}. Errors: {}", imported.join(", "), errors.join(", "))
    };

    info!("Config import result: {}", summary);
    HttpResponse::Ok().json(serde_json::json!({
        "message": summary,
        "imported": imported,
        "errors": errors,
    }))
}

/// Write a serde_json::Value to a file as pretty JSON
fn write_json_file(path: &str, val: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create dir: {}", e))?;
    }
    let json = serde_json::to_string_pretty(val)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    std::fs::write(path, json)
        .map_err(|e| format!("Failed to write {}: {}", path, e))
}

/// Import nodes into the cluster, merging with existing. Returns count of added nodes.
fn import_nodes(nodes_val: &serde_json::Value, state: &web::Data<AppState>) -> Result<usize, String> {
    // Parse as HashMap<String, Node> (same format as nodes.json)
    let import_nodes: std::collections::HashMap<String, crate::agent::Node> =
        serde_json::from_value(nodes_val.clone())
            .map_err(|e| format!("Invalid nodes format: {}", e))?;

    let self_id = &state.cluster.self_id;
    let mut added = 0;

    {
        let mut nodes = state.cluster.nodes.write()
            .map_err(|_| "Failed to acquire lock".to_string())?;
        for (id, mut node) in import_nodes {
            // Skip self
            if id == *self_id {
                continue;
            }
            // Only add if not already present
            if !nodes.contains_key(&id) {
                node.is_self = false;
                node.online = false; // Will be updated on next poll
                nodes.insert(id, node);
                added += 1;
            }
        }
    }

    // Persist
    state.cluster.save_nodes();

    Ok(added)
}

/// POST /api/upgrade — run the WolfStack upgrade script in the background
/// Optional query param: ?channel=beta (defaults to master)
pub async fn system_upgrade(
    req: HttpRequest, state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let channel = query.get("channel").map(|s| s.as_str()).unwrap_or("master");
    let (branch, flag) = if channel == "beta" { ("beta", " --beta") } else { ("master", "") };
    info!("System upgrade triggered via API (channel: {})", branch);

    let cmd = format!(
        "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/{}/setup.sh | sudo bash -s --{}",
        branch, flag
    );

    // Spawn the upgrade script as a detached background process
    match std::process::Command::new("bash")
        .args(["-c", &cmd])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Upgrade started ({} channel) — WolfStack will restart automatically when complete.", branch)
        })),
        Err(e) => {
            error!("Failed to start upgrade: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to start upgrade: {}", e)
            }))
        }
    }
}

// ─── MySQL Database Editor API ───

/// GET /api/mysql/detect — check if MySQL is installed on this node
pub async fn mysql_detect(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(crate::mysql_editor::detect_mysql())
}

/// GET /api/mysql/detect-containers — find MySQL/MariaDB in Docker/LXC containers
pub async fn mysql_detect_containers(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let containers = crate::mysql_editor::detect_mysql_containers();
    HttpResponse::Ok().json(serde_json::json!({ "containers": containers }))
}

#[derive(Deserialize)]
pub struct MysqlConnectRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
}

fn mysql_default_port() -> u16 { 3306 }

/// POST /api/mysql/connect — test a MySQL connection
pub async fn mysql_connect(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlConnectRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    info!("MySQL connect request: host={}, port={}, user={}", body.host, body.port, body.user);

    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: None,
    };

    // Wrap the entire connection test in a 10-second timeout so the handler
    // ALWAYS returns a response — even if mysql_async hangs internally.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::mysql_editor::test_connection(&params),
    ).await;

    match result {
        Ok(Ok(version)) => {
            info!("MySQL connection successful: version={}", version);
            HttpResponse::Ok().json(serde_json::json!({
                "connected": true,
                "version": version,
            }))
        }
        Ok(Err(e)) => {
            error!("MySQL connection failed: {}", e);
            HttpResponse::Ok().json(serde_json::json!({
                "connected": false,
                "error": e,
            }))
        }
        Err(_) => {
            error!("MySQL connect handler timed out after 10s for {}:{}", body.host, body.port);
            HttpResponse::Ok().json(serde_json::json!({
                "connected": false,
                "error": format!("Connection to {}:{} timed out after 10 seconds. Possible causes: host unreachable, firewall blocking port {}, or MySQL not accepting connections.", body.host, body.port, body.port),
            }))
        }
    }
}

#[derive(Deserialize)]
pub struct MysqlCredsRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub database: Option<String>,
}

impl MysqlCredsRequest {
    fn to_params(&self) -> crate::mysql_editor::ConnParams {
        crate::mysql_editor::ConnParams {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            password: self.password.clone(),
            database: self.database.clone(),
        }
    }
}

/// POST /api/mysql/databases — list databases
pub async fn mysql_databases(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlCredsRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        crate::mysql_editor::list_databases(&body.to_params()),
    ).await;
    match result {
        Ok(Ok(dbs)) => HttpResponse::Ok().json(serde_json::json!({ "databases": dbs })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Database list request timed out after 15 seconds" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlTablesRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub database: String,
}

/// POST /api/mysql/tables — list tables in a database
pub async fn mysql_tables(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlTablesRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: Some(body.database.clone()),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        crate::mysql_editor::list_tables(&params, &body.database),
    ).await;
    match result {
        Ok(Ok(tables)) => HttpResponse::Ok().json(serde_json::json!({ "tables": tables })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Table list request timed out after 15 seconds" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlStructureRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub database: String,
    pub table: String,
}

/// POST /api/mysql/structure — get table structure
pub async fn mysql_structure(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlStructureRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: Some(body.database.clone()),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        crate::mysql_editor::table_structure(&params, &body.database, &body.table),
    ).await;
    match result {
        Ok(Ok(cols)) => HttpResponse::Ok().json(serde_json::json!({ "columns": cols })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Structure request timed out after 15 seconds" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlDataRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub database: String,
    pub table: String,
    #[serde(default)]
    pub page: u64,
    #[serde(default = "mysql_default_page_size")]
    pub page_size: u64,
}

fn mysql_default_page_size() -> u64 { 50 }

/// POST /api/mysql/data — get paginated table data
pub async fn mysql_data(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlDataRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: Some(body.database.clone()),
    };
    let page = body.page;
    let page_size = body.page_size;
    let database = body.database.clone();
    let table = body.table.clone();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        crate::mysql_editor::table_data(&params, &database, &table, page, page_size),
    ).await;
    match result {
        Ok(Ok(data)) => HttpResponse::Ok().json(data),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Data request timed out after 30 seconds" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlQueryRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub database: String,
    pub query: String,
}

/// POST /api/mysql/query — execute arbitrary SQL
pub async fn mysql_query(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlQueryRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }


    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: if body.database.is_empty() { None } else { Some(body.database.clone()) },
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        crate::mysql_editor::execute_query(&params, &body.database, &body.query),
    ).await;
    match result {
        Ok(Ok(result)) => HttpResponse::Ok().json(result),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Query timed out after 30 seconds" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlDumpRequest {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub include_data: bool,
}

/// POST /api/mysql/dump — dump database to SQL
pub async fn mysql_dump(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlDumpRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: Some(body.database.clone()),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        crate::mysql_editor::dump_database(&params, &body.database, body.include_data),
    ).await;
    match result {
        Ok(Ok(sql)) => {
            let filename = format!("{}{}.sql",
                body.database,
                if body.include_data { "_full" } else { "_structure" });
            HttpResponse::Ok()
                .content_type("application/sql")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(sql)
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Dump timed out after 120 seconds" })),
    }
}

// ─── App Store ───

/// GET /api/appstore/apps?q=<query>&category=<cat> — list/search available apps
pub async fn appstore_list(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let q = query.get("q").map(|s| s.as_str());
    let cat = query.get("category").map(|s| s.as_str());
    let apps = appstore::list_apps(q, cat);
    HttpResponse::Ok().json(serde_json::json!({ "apps": apps }))
}

/// GET /api/appstore/apps/{id} — get app details
pub async fn appstore_get(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match appstore::get_app(&id) {
        Some(app) => HttpResponse::Ok().json(app),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": format!("App '{}' not found", id) })),
    }
}

#[derive(Deserialize)]
pub struct AppInstallRequest {
    pub target: String,                              // "docker", "lxc", "bare"
    pub container_name: String,                      // name for the container
    #[serde(default)]
    pub inputs: std::collections::HashMap<String, String>,  // user input values
}

/// POST /api/appstore/apps/{id}/install — install an app
pub async fn appstore_install(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AppInstallRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mut inputs = body.inputs.clone();
    // Inject CONTAINER_NAME for ${CONTAINER_NAME} substitution in manifests
    inputs.insert("CONTAINER_NAME".to_string(), body.container_name.clone());

    match appstore::install_app(&id, &body.target, &body.container_name, &inputs) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/appstore/installed — list installed apps
pub async fn appstore_installed(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let apps = appstore::list_installed_apps();
    HttpResponse::Ok().json(serde_json::json!({ "installed": apps }))
}

/// DELETE /api/appstore/installed/{id} — uninstall an app
pub async fn appstore_uninstall(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let install_id = path.into_inner();
    match appstore::uninstall_app(&install_id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Security (Fail2ban, iptables, UFW) ───

/// Helper: check if a command exists on the system
fn command_exists(cmd: &str) -> bool {
    std::process::Command::new("which").arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Helper: run a shell command, return stdout
fn run_shell(cmd: &str) -> Result<String, String> {
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| format!("Failed to execute: {}", e))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(if stderr.is_empty() { "Command failed".into() } else { stderr })
    }
}

/// GET /api/security/status — get fail2ban, iptables, and ufw status
pub async fn security_status(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }

    // Fail2ban
    let f2b_installed = command_exists("fail2ban-client");
    let f2b_status = if f2b_installed {
        match run_shell("fail2ban-client status 2>/dev/null") {
            Ok(out) => Some(out),
            Err(_) => Some("installed but not running".to_string()),
        }
    } else { None };
    let f2b_banned = if f2b_installed {
        run_shell("fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' || fail2ban-client status sshd 2>/dev/null | grep -i 'ban' || echo ''")
            .unwrap_or_default()
    } else { String::new() };
    let f2b_jails = if f2b_installed {
        run_shell("fail2ban-client status 2>/dev/null | grep 'Jail list' | sed 's/.*Jail list:\\s*//' | tr -d '\\t'")
            .unwrap_or_default().trim().to_string()
    } else { String::new() };
    // jail.local config
    let jail_local_exists = std::path::Path::new("/etc/fail2ban/jail.local").exists();
    let jail_local_content = if jail_local_exists {
        std::fs::read_to_string("/etc/fail2ban/jail.local").unwrap_or_default()
    } else { String::new() };
    // Parse key settings from jail.local
    let parse_val = |content: &str, key: &str| -> String {
        content.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find(|l| l.trim().starts_with(key))
            .and_then(|l| l.split('=').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    let bantime = parse_val(&jail_local_content, "bantime");
    let findtime = parse_val(&jail_local_content, "findtime");
    let maxretry = parse_val(&jail_local_content, "maxretry");
    let ignoreip = parse_val(&jail_local_content, "ignoreip");

    // iptables — always available
    let iptables_rules = run_shell("iptables -L -n --line-numbers 2>/dev/null || echo 'iptables not available'")
        .unwrap_or_else(|e| e);

    // UFW
    let ufw_installed = command_exists("ufw");
    let ufw_status = if ufw_installed {
        run_shell("ufw status verbose 2>/dev/null").unwrap_or_else(|e| e)
    } else { String::new() };

    // System updates — detect package manager and count pending updates
    let (pkg_manager, updates_count, updates_list) = if command_exists("apt") {
        let list = run_shell("apt list --upgradable 2>/dev/null | grep -v '^Listing'")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("apt", count, list.trim().to_string())
    } else if command_exists("dnf") {
        let list = run_shell("dnf check-update --quiet 2>/dev/null")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("dnf", count, list.trim().to_string())
    } else if command_exists("yum") {
        let list = run_shell("yum check-update --quiet 2>/dev/null")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("yum", count, list.trim().to_string())
    } else if command_exists("pacman") {
        let list = run_shell("pacman -Qu 2>/dev/null")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("pacman", count, list.trim().to_string())
    } else {
        ("unknown", 0, String::new())
    };

    HttpResponse::Ok().json(serde_json::json!({
        "fail2ban": {
            "installed": f2b_installed,
            "status": f2b_status,
            "banned": f2b_banned,
            "jails": f2b_jails,
            "jail_local_exists": jail_local_exists,
            "bantime": bantime,
            "findtime": findtime,
            "maxretry": maxretry,
            "ignoreip": ignoreip,
        },
        "iptables": {
            "rules": iptables_rules,
        },
        "ufw": {
            "installed": ufw_installed,
            "status": ufw_status,
        },
        "updates": {
            "package_manager": pkg_manager,
            "count": updates_count,
            "list": updates_list,
        }
    }))
}

/// Generate a distro-appropriate jail.local configuration
fn generate_jail_local() -> String {
    // ── Detect distro from /etc/os-release ──
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get_field = |key: &str| -> String {
        for line in os_release.lines() {
            if line.starts_with(key) {
                return line.splitn(2, '=').nth(1).unwrap_or("").trim_matches('"').to_string();
            }
        }
        String::new()
    };
    let distro_id = get_field("ID=").to_lowercase();
    let version_id = get_field("VERSION_ID=");
    let version_num: f32 = version_id.parse().unwrap_or(0.0);

    // ── Determine backend ──
    // Debian 12+, Ubuntu 22.04+, and most modern systemd distros don't ship rsyslog
    // and need backend = systemd to read from journald
    let use_systemd_backend = match distro_id.as_str() {
        "debian" => version_num >= 12.0,
        "ubuntu" => version_num >= 22.04,
        _ => {
            // Check if rsyslog is installed; if not, use systemd
            !std::path::Path::new("/var/log/auth.log").exists()
                || std::path::Path::new("/run/systemd/system").exists()
        }
    };

    // ── Determine banaction ──
    // Debian 13+ defaults to nftables; also check if nft binary exists
    let use_nftables = match distro_id.as_str() {
        "debian" => version_num >= 13.0,
        _ => false,
    } || command_exists("nft");

    let backend = if use_systemd_backend { "systemd" } else { "auto" };
    let banaction = if use_nftables { "nftables-multiport" } else { "iptables-multiport" };

    let mut config = format!(
        "# Generated by WolfStack for {distro} {version}\n\
         # Last generated: {timestamp}\n\n\
         [DEFAULT]\n\
         bantime  = 1h\n\
         findtime = 10m\n\
         maxretry = 5\n\
         ignoreip = 127.0.0.1/8 ::1\n\
         backend  = {backend}\n\
         banaction = {banaction}\n\n\
         [sshd]\n\
         enabled  = true\n\
         port     = ssh\n\
         filter   = sshd\n\
         maxretry = 3\n",
        distro = if distro_id.is_empty() { "unknown".to_string() } else { distro_id.clone() },
        version = version_id,
        timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        backend = backend,
        banaction = banaction,
    );

    // Only set logpath for file-based backends (not systemd)
    if !use_systemd_backend {
        config.push_str("logpath  = /var/log/auth.log\n");
    }

    config
}

/// POST /api/security/fail2ban/install — install fail2ban + create default jail.local
pub async fn security_fail2ban_install(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }

    // Install fail2ban + python3-systemd (needed for systemd backend)
    if let Err(_) = run_shell("apt-get update && apt-get install -y fail2ban python3-systemd") {
        // Try without python3-systemd (may not exist on all distros)
        if let Err(e) = run_shell("apt-get install -y fail2ban") {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
        }
    }

    // Create default jail.local if it doesn't exist
    if !std::path::Path::new("/etc/fail2ban/jail.local").exists() {
        let config = generate_jail_local();
        let _ = std::fs::write("/etc/fail2ban/jail.local", config);
    }

    match run_shell("systemctl enable --now fail2ban && systemctl restart fail2ban") {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/fail2ban/rebuild — regenerate jail.local with distro-appropriate settings
pub async fn security_fail2ban_rebuild(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }

    // Ensure python3-systemd is present
    let _ = run_shell("apt-get install -y python3-systemd 2>/dev/null");

    let config = generate_jail_local();
    if let Err(e) = std::fs::write("/etc/fail2ban/jail.local", &config) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to write jail.local: {}", e)
        }));
    }

    match run_shell("systemctl restart fail2ban") {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "output": out,
            "config": config,
            "message": "jail.local regenerated with distro-appropriate settings"
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "warning": format!("Config written but restart failed: {}", e),
            "config": config
        })),
    }
}


/// GET /api/security/fail2ban/config — read jail.local
pub async fn security_fail2ban_config_get(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let exists = std::path::Path::new("/etc/fail2ban/jail.local").exists();
    let content = if exists {
        std::fs::read_to_string("/etc/fail2ban/jail.local").unwrap_or_default()
    } else { String::new() };
    HttpResponse::Ok().json(serde_json::json!({
        "exists": exists,
        "content": content,
    }))
}

/// POST /api/security/fail2ban/config — save jail.local and restart fail2ban
pub async fn security_fail2ban_config_save(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");
    if content.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Content required" }));
    }
    if let Err(e) = std::fs::write("/etc/fail2ban/jail.local", content) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write: {}", e) }));
    }
    match run_shell("systemctl restart fail2ban") {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "warning": format!("Saved but restart failed: {}", e) })),
    }
}

/// POST /api/security/fail2ban/unban — unban an IP { "ip": "1.2.3.4", "jail": "sshd" }
pub async fn security_fail2ban_unban(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let ip = body.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let jail = body.get("jail").and_then(|v| v.as_str()).unwrap_or("sshd");
    if ip.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "IP required" }));
    }
    // Sanitise IP — allow only digits, dots, colons (IPv6)
    if !ip.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid IP" }));
    }
    match run_shell(&format!("fail2ban-client set {} unbanip {}", jail, ip)) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/ufw/install — install UFW
pub async fn security_ufw_install(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    match run_shell("apt-get update && apt-get install -y ufw") {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/ufw/rule — add a UFW rule { "rule": "allow 22/tcp" }
pub async fn security_ufw_add_rule(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let rule = body.get("rule").and_then(|v| v.as_str()).unwrap_or("");
    if rule.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Rule required" }));
    }
    // Basic sanitisation — only allow alphanumeric, spaces, slashes, dots, colons
    if !rule.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '/' || c == '.' || c == ':') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid rule characters" }));
    }
    match run_shell(&format!("ufw {}", rule)) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/security/ufw/rule — delete a UFW rule { "rule_number": "3" }
pub async fn security_ufw_delete_rule(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let num = body.get("rule_number").and_then(|v| v.as_str()).unwrap_or("");
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Valid rule number required" }));
    }
    match run_shell(&format!("echo y | ufw delete {}", num)) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/ufw/toggle — enable or disable UFW { "enable": true }
pub async fn security_ufw_toggle(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let enable = body.get("enable").and_then(|v| v.as_bool()).unwrap_or(false);
    let cmd = if enable { "echo y | ufw enable" } else { "ufw disable" };
    match run_shell(cmd) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/security/iptables/rules — get iptables rules
pub async fn security_iptables_rules(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let rules = run_shell("iptables -L -n --line-numbers 2>/dev/null")
        .unwrap_or_else(|e| format!("Error: {}", e));
    HttpResponse::Ok().json(serde_json::json!({ "rules": rules }))
}

/// POST /api/security/updates/check — refresh package cache and list pending updates
pub async fn security_check_updates(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let (pkg_manager, output) = if command_exists("apt") {
        let _ = run_shell("apt-get update -qq 2>/dev/null");
        let list = run_shell("apt list --upgradable 2>/dev/null | grep -v '^Listing'")
            .unwrap_or_default();
        ("apt", list)
    } else if command_exists("dnf") {
        let list = run_shell("dnf check-update --quiet 2>/dev/null").unwrap_or_default();
        ("dnf", list)
    } else if command_exists("yum") {
        let list = run_shell("yum check-update --quiet 2>/dev/null").unwrap_or_default();
        ("yum", list)
    } else if command_exists("pacman") {
        let _ = run_shell("pacman -Sy 2>/dev/null");
        let list = run_shell("pacman -Qu 2>/dev/null").unwrap_or_default();
        ("pacman", list)
    } else {
        ("unknown", String::new())
    };
    let count = output.lines().filter(|l| !l.trim().is_empty()).count();
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "package_manager": pkg_manager,
        "count": count,
        "list": output.trim(),
    }))
}

/// POST /api/security/updates/apply — apply all pending updates
pub async fn security_apply_updates(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let cmd = if command_exists("apt") {
        "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1"
    } else if command_exists("dnf") {
        "dnf upgrade -y 2>&1"
    } else if command_exists("yum") {
        "yum update -y 2>&1"
    } else if command_exists("pacman") {
        "pacman -Syu --noconfirm 2>&1"
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "No supported package manager found" }));
    };
    match run_shell(cmd) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Issues Scanner ───

/// Parse human-readable size strings (e.g. "1.2G", "450M", "32K") to MB
fn parse_size_to_mb(s: &str) -> f64 {
    let s = s.trim();
    if s.is_empty() { return 0.0; }
    let (num_str, suffix) = if s.ends_with(|c: char| c.is_alphabetic()) {
        let idx = s.len() - 1;
        (&s[..idx], &s[idx..])
    } else {
        (s, "")
    };
    let num: f64 = num_str.parse().unwrap_or(0.0);
    match suffix.to_uppercase().as_str() {
        "T" => num * 1024.0 * 1024.0,
        "G" => num * 1024.0,
        "M" => num,
        "K" => num / 1024.0,
        "B" => num / (1024.0 * 1024.0),
        _ => num, // assume MB
    }
}

#[derive(Serialize, Clone)]
pub struct Issue {
    pub severity: String,   // "critical", "warning", "info"
    pub category: String,   // "cpu", "memory", "disk", "swap", "load", "service", "container"
    pub title: String,
    pub detail: String,
}

/// Collect system issues (reusable — called by HTTP handler and background scheduler)
pub fn collect_issues(metrics: &crate::monitoring::SystemMetrics) -> Vec<Issue> {
    let mut issues: Vec<Issue> = Vec::new();
    let mem_pct = metrics.memory_percent;

    // ── CPU check ──
    if metrics.cpu_usage_percent > 90.0 {
        issues.push(Issue {
            severity: "critical".into(),
            category: "cpu".into(),
            title: "CPU usage critically high".into(),
            detail: format!("CPU at {:.1}% — system may be unresponsive", metrics.cpu_usage_percent),
        });
    } else if metrics.cpu_usage_percent > 75.0 {
        issues.push(Issue {
            severity: "warning".into(),
            category: "cpu".into(),
            title: "CPU usage elevated".into(),
            detail: format!("CPU at {:.1}% — monitor for sustained load", metrics.cpu_usage_percent),
        });
    }

    // ── Memory check ──
    if mem_pct > 90.0 {
        issues.push(Issue {
            severity: "critical".into(),
            category: "memory".into(),
            title: "Memory usage critically high".into(),
            detail: format!("Memory at {:.1}% — OOM risk", mem_pct),
        });
    } else if mem_pct > 80.0 {
        issues.push(Issue {
            severity: "warning".into(),
            category: "memory".into(),
            title: "Memory usage elevated".into(),
            detail: format!("Memory at {:.1}%", mem_pct),
        });
    }

    // ── Disk checks (free space, not just %) ──
    for disk in &metrics.disks {
        let total_gb = disk.total_bytes as f64 / 1_073_741_824.0;
        let used_gb = disk.used_bytes as f64 / 1_073_741_824.0;
        let free_gb = disk.available_bytes as f64 / 1_073_741_824.0;
        let size_detail = format!("{} — {:.1} GB used / {:.1} GB total ({:.1} GB free, {:.1}%)",
            disk.mount_point, used_gb, total_gb, free_gb, disk.usage_percent);

        if free_gb < 2.0 {
            issues.push(Issue {
                severity: "critical".into(),
                category: "disk".into(),
                title: format!("Disk {} almost full ({:.1} GB free)", disk.mount_point, free_gb),
                detail: size_detail,
            });
        } else if free_gb < 10.0 {
            issues.push(Issue {
                severity: "warning".into(),
                category: "disk".into(),
                title: format!("Disk {} low on space ({:.1} GB free)", disk.mount_point, free_gb),
                detail: size_detail,
            });
        }
    }

    // ── Swap check ──
    if metrics.swap_total_bytes > 0 {
        let swap_pct = (metrics.swap_used_bytes as f64 / metrics.swap_total_bytes as f64) * 100.0;
        if swap_pct > 50.0 {
            issues.push(Issue {
                severity: "warning".into(),
                category: "swap".into(),
                title: "Significant swap usage".into(),
                detail: format!("Swap at {:.1}% — system may be low on RAM", swap_pct),
            });
        }
    }

    // ── Load average check ──
    let cpu_count = metrics.cpu_count.max(1) as f64;
    if metrics.load_avg.one > cpu_count * 2.0 {
        issues.push(Issue {
            severity: "critical".into(),
            category: "load".into(),
            title: "Load average extremely high".into(),
            detail: format!("Load {:.2} ({:.1}× CPU count {})", metrics.load_avg.one, metrics.load_avg.one / cpu_count, metrics.cpu_count),
        });
    } else if metrics.load_avg.one > cpu_count {
        issues.push(Issue {
            severity: "warning".into(),
            category: "load".into(),
            title: "Load average high".into(),
            detail: format!("Load {:.2} (>{} CPUs)", metrics.load_avg.one, metrics.cpu_count),
        });
    }

    // ── Failed systemd services ──
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["--failed", "--no-legend", "--plain"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(unit) = parts.first() {
                if !unit.is_empty() {
                    issues.push(Issue {
                        severity: "warning".into(),
                        category: "service".into(),
                        title: format!("Service {} failed", unit),
                        detail: format!("systemd unit {} is in failed state", unit),
                    });
                }
            }
        }
    }

    // ── Stopped Docker containers ──
    if let Ok(output) = std::process::Command::new("docker")
        .args(["ps", "-a", "--filter", "status=exited", "--format", "{{.Names}}"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stopped: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
        if !stopped.is_empty() {
            issues.push(Issue {
                severity: "info".into(),
                category: "container".into(),
                title: format!("{} stopped Docker container(s)", stopped.len()),
                detail: format!("Stopped: {}", stopped.join(", ")),
            });
        }
    }

    // ── Clearable disk space ──

    // Journal logs
    if let Ok(output) = std::process::Command::new("journalctl")
        .args(["--disk-usage"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "Archived and active journals take up 1.2G in the file system."
        if let Some(size_str) = stdout.split("take up ").nth(1).and_then(|s| s.split(' ').next()) {
            let size_mb = parse_size_to_mb(size_str);
            if size_mb > 500.0 {
                issues.push(Issue {
                    severity: "info".into(),
                    category: "disk".into(),
                    title: format!("Journal logs using {}", size_str),
                    detail: format!("Run 'journalctl --vacuum-size=200M' to reclaim space"),
                });
            }
        }
    }

    // Package cache (apt)
    if let Ok(output) = std::process::Command::new("du")
        .args(["-sh", "/var/cache/apt/archives"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = stdout.split_whitespace().next() {
                let size_mb = parse_size_to_mb(size_str);
                if size_mb > 200.0 {
                    issues.push(Issue {
                        severity: "info".into(),
                        category: "disk".into(),
                        title: format!("APT cache using {}", size_str),
                        detail: "Run 'apt clean' to reclaim space".into(),
                    });
                }
            }
        }
    }

    // Package cache (dnf/yum)
    if let Ok(output) = std::process::Command::new("du")
        .args(["-sh", "/var/cache/dnf"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = stdout.split_whitespace().next() {
                let size_mb = parse_size_to_mb(size_str);
                if size_mb > 200.0 {
                    issues.push(Issue {
                        severity: "info".into(),
                        category: "disk".into(),
                        title: format!("DNF cache using {}", size_str),
                        detail: "Run 'dnf clean all' to reclaim space".into(),
                    });
                }
            }
        }
    }

    // /tmp usage
    if let Ok(output) = std::process::Command::new("du")
        .args(["-sh", "/tmp"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = stdout.split_whitespace().next() {
                let size_mb = parse_size_to_mb(size_str);
                if size_mb > 500.0 {
                    issues.push(Issue {
                        severity: "info".into(),
                        category: "disk".into(),
                        title: format!("/tmp using {}", size_str),
                        detail: "Temporary files may be safe to clean up".into(),
                    });
                }
            }
        }
    }

    // Docker unused images
    if let Ok(output) = std::process::Command::new("docker")
        .args(["system", "df", "--format", "{{.Reclaimable}}"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Sum up any reclaimable amounts
            let mut total_mb = 0.0f64;
            let mut total_str = String::new();
            for line in stdout.lines() {
                let clean = line.trim().split('(').next().unwrap_or("").trim();
                if !clean.is_empty() && clean != "0B" {
                    let mb = parse_size_to_mb(clean);
                    total_mb += mb;
                    if total_str.is_empty() { total_str = clean.to_string(); }
                }
            }
            if total_mb > 500.0 {
                issues.push(Issue {
                    severity: "info".into(),
                    category: "container".into(),
                    title: format!("Docker reclaimable space: {:.0} MB", total_mb),
                    detail: "Run 'docker system prune' to reclaim unused images/containers".into(),
                });
            }
        }
    }

    issues
}

/// GET /api/issues/scan — scan system for issues
pub async fn scan_issues(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let metrics = state.monitor.lock().unwrap().collect();
    let issues = collect_issues(&metrics);

    HttpResponse::Ok().json(serde_json::json!({
        "hostname": metrics.hostname,
        "version": env!("CARGO_PKG_VERSION"),
        "issues": issues,
        "ai_analysis": null,
    }))
}

/// POST /api/issues/clean — run safe cleanup to free disk space
pub async fn clean_system(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let mut cleaned = Vec::new();
    let mut total_freed_mb: f64 = 0.0;

    // ── Journal logs → vacuum to 200M ──
    if let Ok(before_out) = run_shell("journalctl --disk-usage 2>/dev/null") {
        let before_mb = before_out.split("take up ").nth(1)
            .and_then(|s| s.split(' ').next())
            .map(|s| parse_size_to_mb(s))
            .unwrap_or(0.0);

        let _ = run_shell("journalctl --vacuum-size=200M 2>/dev/null");

        let after_mb = run_shell("journalctl --disk-usage 2>/dev/null").ok()
            .and_then(|o| o.split("take up ").nth(1).and_then(|s| s.split(' ').next()).map(|s| parse_size_to_mb(s)))
            .unwrap_or(before_mb);

        let freed = (before_mb - after_mb).max(0.0);
        if freed > 1.0 {
            total_freed_mb += freed;
            cleaned.push(format!("Journal logs: freed {:.0} MB", freed));
        }
    }

    // ── APT cache ──
    if command_exists("apt") {
        let before_mb = run_shell("du -sm /var/cache/apt/archives 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let _ = run_shell("apt-get clean -y 2>/dev/null");
        let _ = run_shell("apt-get autoremove -y 2>/dev/null");

        let after_mb = run_shell("du -sm /var/cache/apt/archives 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let freed = (before_mb - after_mb).max(0.0);
        if freed > 1.0 {
            total_freed_mb += freed;
            cleaned.push(format!("APT cache: freed {:.0} MB", freed));
        }
    }

    // ── DNF/YUM cache ──
    if command_exists("dnf") {
        let before_mb = run_shell("du -sm /var/cache/dnf 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let _ = run_shell("dnf clean all 2>/dev/null");

        let after_mb = run_shell("du -sm /var/cache/dnf 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let freed = (before_mb - after_mb).max(0.0);
        if freed > 1.0 {
            total_freed_mb += freed;
            cleaned.push(format!("DNF cache: freed {:.0} MB", freed));
        }
    } else if command_exists("yum") {
        let _ = run_shell("yum clean all 2>/dev/null");
        cleaned.push("YUM cache: cleaned".into());
    }

    // ── Old kernels (keep current + 1 previous) ──
    if command_exists("apt") {
        let out = run_shell("dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v $(uname -r | sed 's/-generic//') | head -5").ok().unwrap_or_default();
        let old_kernels: Vec<&str> = out.lines().filter(|l| !l.is_empty() && l.contains("linux-image")).collect();
        if !old_kernels.is_empty() {
            for kernel in &old_kernels {
                let _ = run_shell(&format!("DEBIAN_FRONTEND=noninteractive apt-get remove -y {} 2>/dev/null", kernel));
            }
            cleaned.push(format!("Old kernels: removed {} package(s)", old_kernels.len()));
        }
    }

    // ── Docker prune ──
    if command_exists("docker") {
        let out = run_shell("docker system prune -f 2>/dev/null").ok().unwrap_or_default();
        // Parse "Total reclaimed space: 1.23GB" from output
        if let Some(line) = out.lines().find(|l| l.contains("reclaimed space")) {
            if let Some(size_str) = line.split(": ").nth(1) {
                let mb = parse_size_to_mb(size_str.trim());
                if mb > 1.0 {
                    total_freed_mb += mb;
                    cleaned.push(format!("Docker prune: freed {}", size_str.trim()));
                }
            }
        }
    }

    // ── /tmp old files (>7 days) ──
    let _ = run_shell("find /tmp -type f -atime +7 -delete 2>/dev/null");

    if cleaned.is_empty() {
        cleaned.push("System is already clean — nothing to free.".into());
    }

    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "cleaned": cleaned,
        "freed_mb": total_freed_mb.round() as u64,
    }))
}

// ═══════════════════════════════════════════════
// ─── Alerting & Notifications ───
// ═══════════════════════════════════════════════

pub async fn alerts_config_get(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::alerting::AlertConfig::load();
    HttpResponse::Ok().json(config.to_masked_json())
}

pub async fn alerts_config_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::alerting::AlertConfig::load();
    let v = body.into_inner();

    if let Some(enabled) = v.get("enabled").and_then(|v| v.as_bool()) { config.enabled = enabled; }
    if let Some(url) = v.get("discord_webhook").and_then(|v| v.as_str()) { config.discord_webhook = url.to_string(); }
    if let Some(url) = v.get("slack_webhook").and_then(|v| v.as_str()) { config.slack_webhook = url.to_string(); }
    if let Some(token) = v.get("telegram_bot_token").and_then(|v| v.as_str()) { config.telegram_bot_token = token.to_string(); }
    if let Some(id) = v.get("telegram_chat_id").and_then(|v| v.as_str()) { config.telegram_chat_id = id.to_string(); }
    if let Some(t) = v.get("cpu_threshold").and_then(|v| v.as_f64()) { config.cpu_threshold = t as f32; }
    if let Some(t) = v.get("memory_threshold").and_then(|v| v.as_f64()) { config.memory_threshold = t as f32; }
    if let Some(t) = v.get("disk_threshold").and_then(|v| v.as_f64()) { config.disk_threshold = t as f32; }
    if let Some(b) = v.get("alert_node_offline").and_then(|v| v.as_bool()) { config.alert_node_offline = b; }
    if let Some(b) = v.get("alert_node_restored").and_then(|v| v.as_bool()) { config.alert_node_restored = b; }
    if let Some(b) = v.get("alert_cpu").and_then(|v| v.as_bool()) { config.alert_cpu = b; }
    if let Some(b) = v.get("alert_memory").and_then(|v| v.as_bool()) { config.alert_memory = b; }
    if let Some(b) = v.get("alert_disk").and_then(|v| v.as_bool()) { config.alert_disk = b; }
    if let Some(i) = v.get("check_interval_secs").and_then(|v| v.as_u64()) {
        // Clamp to sensible range: 30 seconds to 1 hour
        config.check_interval_secs = i.max(30).min(3600);
    }

    match config.save() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "saved": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

pub async fn alerts_test(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::alerting::AlertConfig::load();
    config.enabled = true; // Force enable for test
    let results = crate::alerting::send_test(&config).await;
    let ok_count = results.iter().filter(|(_, r)| r.is_ok()).count();
    let details: Vec<serde_json::Value> = results.iter().map(|(ch, r)| {
        serde_json::json!({ "channel": ch, "success": r.is_ok(), "error": r.as_ref().err().map(|e| e.to_string()) })
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({ "sent": ok_count, "results": details }))
}

// ─── WolfRun API ───

/// GET /api/wolfrun/services — list all WolfRun services
pub async fn wolfrun_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = req.query_string().split('&')
        .find_map(|p| p.strip_prefix("cluster="))
        .map(|s| s.replace("%20", " "));
    let services = state.wolfrun.list(cluster.as_deref());
    HttpResponse::Ok().json(services)
}

/// GET /api/wolfrun/services/{id} — get a single service
pub async fn wolfrun_get(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match state.wolfrun.get(&path.into_inner()) {
        Some(svc) => HttpResponse::Ok().json(svc),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    }
}

#[derive(Deserialize)]
pub struct WolfRunCreateRequest {
    pub name: String,
    pub image: Option<String>,
    pub replicas: Option<u32>,
    pub cluster_name: String,
    #[serde(default)]
    pub runtime: Option<String>,     // "docker" (default) or "lxc"
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub placement: Option<String>,   // "any", "prefer:<node_id>", "require:<node_id>"
    #[serde(default)]
    pub restart_policy: Option<String>, // "always", "on-failure", "never"
    // LXC-specific
    #[serde(default)]
    pub lxc_distribution: Option<String>,
    #[serde(default)]
    pub lxc_release: Option<String>,
    #[serde(default)]
    pub lxc_architecture: Option<String>,
}

/// POST /api/wolfrun/services — create a new service
pub async fn wolfrun_create(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfRunCreateRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let runtime = match body.runtime.as_deref().unwrap_or("docker") {
        "lxc" => crate::wolfrun::Runtime::Lxc,
        _ => crate::wolfrun::Runtime::Docker,
    };

    // Docker requires an image
    if runtime == crate::wolfrun::Runtime::Docker && body.image.as_deref().unwrap_or("").is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Docker services require an image" }));
    }

    let placement = match body.placement.as_deref() {
        Some(p) if p.starts_with("prefer:") => crate::wolfrun::Placement::PreferNode(p[7..].to_string()),
        Some(p) if p.starts_with("require:") => crate::wolfrun::Placement::RequireNode(p[8..].to_string()),
        _ => crate::wolfrun::Placement::Any,
    };

    let restart_policy = match body.restart_policy.as_deref() {
        Some("on-failure") => crate::wolfrun::RestartPolicy::OnFailure,
        Some("never") => crate::wolfrun::RestartPolicy::Never,
        _ => crate::wolfrun::RestartPolicy::Always,
    };

    let lxc_config = if runtime == crate::wolfrun::Runtime::Lxc {
        Some(crate::wolfrun::LxcConfig {
            distribution: body.lxc_distribution.clone().unwrap_or_else(|| "ubuntu".to_string()),
            release: body.lxc_release.clone().unwrap_or_else(|| "jammy".to_string()),
            architecture: body.lxc_architecture.clone().unwrap_or_else(|| "amd64".to_string()),
        })
    } else {
        None
    };

    let svc = state.wolfrun.create(
        body.name.clone(),
        body.image.clone().unwrap_or_default(),
        body.replicas.unwrap_or(1),
        body.cluster_name.clone(),
        body.env.clone(),
        body.ports.clone(),
        body.volumes.clone(),
        placement,
        restart_policy,
        runtime,
        lxc_config,
    );

    HttpResponse::Ok().json(svc)
}

/// DELETE /api/wolfrun/services/{id} — delete a service and stop all instances
pub async fn wolfrun_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let mut destroyed: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();

    // Clean up cloned containers (names containing "wolfrun") but keep the original template
    if let Some(svc) = state.wolfrun.get(&id) {
        // Clean up LB iptables rules
        if let Some(ref vip) = svc.service_ip {
            crate::wolfrun::remove_lb_rules_for_vip(vip);
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .ok();

        for inst in &svc.instances {
            // Only destroy clones (contain "wolfrun" in name), leave original template
            if !inst.container_name.contains("wolfrun") {
                kept.push(inst.container_name.clone());
                continue;
            }

            if let Some(node) = state.cluster.get_node(&inst.node_id) {
                if node.is_self {
                    match svc.runtime {
                        crate::wolfrun::Runtime::Docker => {
                            let _ = crate::containers::docker_stop(&inst.container_name);
                            let _ = crate::containers::docker_remove(&inst.container_name);
                        }
                        crate::wolfrun::Runtime::Lxc => {
                            let _ = crate::containers::lxc_stop(&inst.container_name);
                            let _ = crate::containers::lxc_destroy(&inst.container_name);
                        }
                    }
                    destroyed.push(inst.container_name.clone());
                } else if let Some(ref c) = client {
                    // Remote node: stop first, then delete
                    let stop_path = match svc.runtime {
                        crate::wolfrun::Runtime::Docker => format!("/api/containers/docker/{}/stop", inst.container_name),
                        crate::wolfrun::Runtime::Lxc => format!("/api/containers/lxc/{}/stop", inst.container_name),
                    };
                    let stop_urls = build_node_urls(&node.address, node.port, &stop_path);
                    for url in &stop_urls {
                        if c.post(url).header("X-WolfStack-Secret", &state.cluster_secret).send().await.is_ok() { break; }
                    }

                    // Now delete/destroy
                    let del_path = match svc.runtime {
                        crate::wolfrun::Runtime::Docker => format!("/api/containers/docker/{}", inst.container_name),
                        crate::wolfrun::Runtime::Lxc => format!("/api/containers/lxc/{}", inst.container_name),
                    };
                    let del_urls = build_node_urls(&node.address, node.port, &del_path);
                    for url in &del_urls {
                        if let Ok(resp) = c.delete(url)
                            .header("X-WolfStack-Secret", &state.cluster_secret)
                            .send().await
                        {
                            if resp.status().is_success() {
                                destroyed.push(inst.container_name.clone());
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    match state.wolfrun.delete(&id) {
        Some(_) => HttpResponse::Ok().json(serde_json::json!({
            "deleted": true,
            "destroyed": destroyed,
            "kept": kept,
        })),
        None => {
            // Log available service IDs for debugging
            let available: Vec<String> = state.wolfrun.list(None).iter().map(|s| format!("{} ({})", s.id, s.name)).collect();
            warn!("WolfRun delete: service '{}' not found. Available: {:?}", id, available);
            HttpResponse::NotFound().json(serde_json::json!({ "error": format!("Service not found: {}", id) }))
        }
    }
}

#[derive(Deserialize)]
pub struct WolfRunActionRequest {
    pub action: String, // start, stop, restart
}

pub async fn wolfrun_service_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunActionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let action = &body.action;

    let svc = match state.wolfrun.get(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    };

    let runtime_path = match svc.runtime {
        crate::wolfrun::Runtime::Docker => "docker",
        crate::wolfrun::Runtime::Lxc => "lxc",
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut ok_count = 0u32;
    let mut fail_count = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for inst in &svc.instances {
        if let Some(node) = state.cluster.get_node(&inst.node_id) {
            if node.is_self {
                // Local container — call functions directly (avoids HTTP self-call issues)
                let result = match (&svc.runtime, action.as_str()) {
                    (crate::wolfrun::Runtime::Docker, "start") => crate::containers::docker_start(&inst.container_name),
                    (crate::wolfrun::Runtime::Docker, "stop") => crate::containers::docker_stop(&inst.container_name),
                    (crate::wolfrun::Runtime::Docker, "restart") => crate::containers::docker_restart(&inst.container_name),
                    (crate::wolfrun::Runtime::Lxc, "start") => crate::containers::lxc_start(&inst.container_name),
                    (crate::wolfrun::Runtime::Lxc, "stop") => crate::containers::lxc_stop(&inst.container_name),
                    (crate::wolfrun::Runtime::Lxc, "restart") => {
                        let _ = crate::containers::lxc_stop(&inst.container_name);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        crate::containers::lxc_start(&inst.container_name)
                    }
                    _ => Err(format!("Unknown action: {}", action)),
                };
                match result {
                    Ok(_) => { ok_count += 1; }
                    Err(e) => {
                        errors.push(format!("{}: {}", inst.container_name, e));
                        fail_count += 1;
                    }
                }
            } else {
                // Remote node
                let api_path = format!("/api/containers/{}/{}/action", runtime_path, inst.container_name);
                let urls = build_node_urls(&node.address, node.port, &api_path);
                let payload = serde_json::json!({ "action": action });
                let mut success = false;
                for url in &urls {
                    match client.post(url)
                        .header("X-WolfStack-Secret", &state.cluster_secret)
                        .json(&payload)
                        .send().await {
                        Ok(resp) if resp.status().is_success() => { success = true; break; }
                        Ok(resp) => {
                            let body = resp.text().await.unwrap_or_default();
                            errors.push(format!("{} on {}: {}", inst.container_name, node.hostname, body));
                        }
                        Err(e) => {
                            errors.push(format!("{} on {}: {}", inst.container_name, node.hostname, e));
                        }
                    }
                }
                if success { ok_count += 1; } else { fail_count += 1; }
            }
        } else {
            errors.push(format!("{}: node not found", inst.container_name));
            fail_count += 1;
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "action": action,
        "ok": ok_count,
        "failed": fail_count,
        "errors": errors,
    }))
}

#[derive(Deserialize)]
pub struct WolfRunPortForwardRequest {
    pub public_ip: String,
    pub ports: Option<String>,       // Source ports on public IP
    pub dest_ports: Option<String>,   // Destination ports on VIP
    pub protocol: String,             // "tcp", "udp", "all"
    pub label: Option<String>,
}

/// POST /api/wolfrun/services/{id}/portforward — add external port forward to service VIP
pub async fn wolfrun_portforward_add(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunPortForwardRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let svc = match state.wolfrun.get(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    };

    let vip = match &svc.service_ip {
        Some(ip) => ip.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Service has no VIP assigned" })),
    };

    let default_label = format!("WolfRun: {}", svc.name);
    let label = body.label.as_deref().unwrap_or(&default_label);

    match crate::networking::add_ip_mapping(
        &body.public_ip,
        &vip,
        body.ports.as_deref(),
        body.dest_ports.as_deref(),
        &body.protocol,
        label,
    ) {
        Ok(mapping) => HttpResponse::Ok().json(mapping),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfrun/services/{id}/portforward — list port forwards for a service
pub async fn wolfrun_portforward_list(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let svc = match state.wolfrun.get(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    };

    let vip = match &svc.service_ip {
        Some(ip) => ip.clone(),
        None => return HttpResponse::Ok().json(serde_json::json!([])),
    };

    // Filter IP mappings that target this service's VIP
    let all_mappings = crate::networking::list_ip_mappings();
    let service_mappings: Vec<_> = all_mappings.into_iter()
        .filter(|m| m.wolfnet_ip == vip)
        .collect();

    HttpResponse::Ok().json(service_mappings)
}

/// DELETE /api/wolfrun/services/{id}/portforward/{rule_id} — remove a port forward
pub async fn wolfrun_portforward_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (_service_id, rule_id) = path.into_inner();

    match crate::networking::remove_ip_mapping(&rule_id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "deleted": true })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct WolfRunScaleRequest {
    pub replicas: u32,
}

/// POST /api/wolfrun/services/{id}/scale — scale replicas
pub async fn wolfrun_scale(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunScaleRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.wolfrun.scale(&id, body.replicas) {
        // Trigger an immediate reconcile in the background (retry if lock held)
        let wolfrun = Arc::clone(&state.wolfrun);
        let cluster = Arc::clone(&state.cluster);
        let secret = state.cluster_secret.clone();
        actix_web::rt::spawn(async move {
            for attempt in 0..3 {
                if attempt > 0 {
                    actix_web::rt::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                crate::wolfrun::reconcile(&wolfrun, &cluster, &secret).await;
            }
        });
        HttpResponse::Ok().json(serde_json::json!({ "scaled": true, "replicas": body.replicas }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" }))
    }
}

#[derive(Deserialize)]
pub struct WolfRunUpdateRequest {
    pub image: Option<String>,
}

/// POST /api/wolfrun/services/{id}/update — rolling update (change image)
pub async fn wolfrun_update(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunUpdateRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if let Some(image) = &body.image {
        if state.wolfrun.update_image(&id, image.clone()) {
            // Clear instances so reconciliation redeploys with new image
            state.wolfrun.update_instances(&id, Vec::new());
            HttpResponse::Ok().json(serde_json::json!({ "updated": true, "image": image }))
        } else {
            HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" }))
        }
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({ "error": "No image specified" }))
    }
}

#[derive(Deserialize)]
pub struct WolfRunSettingsRequest {
    pub min_replicas: Option<u32>,
    pub max_replicas: Option<u32>,
    pub desired: Option<u32>,
    pub lb_policy: Option<String>,
    pub allowed_nodes: Option<Vec<String>>,
}

/// POST /api/wolfrun/services/{id}/settings — update service settings
pub async fn wolfrun_settings(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunSettingsRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.wolfrun.update_settings(&id, body.min_replicas, body.max_replicas, body.desired, body.lb_policy.clone(), body.allowed_nodes.clone()) {
        let wolfrun = Arc::clone(&state.wolfrun);
        let cluster = Arc::clone(&state.cluster);
        let secret = state.cluster_secret.clone();
        actix_web::rt::spawn(async move {
            crate::wolfrun::reconcile(&wolfrun, &cluster, &secret).await;
        });
        if let Some(svc) = state.wolfrun.get(&id) {
            HttpResponse::Ok().json(serde_json::json!({
                "updated": true,
                "replicas": svc.replicas,
                "min_replicas": svc.min_replicas,
                "max_replicas": svc.max_replicas,
                "lb_policy": svc.lb_policy,
                "allowed_nodes": svc.allowed_nodes,
            }))
        } else {
            HttpResponse::Ok().json(serde_json::json!({ "updated": true }))
        }
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" }))
    }
}

#[derive(Deserialize)]
pub struct WolfRunAdoptRequest {
    pub name: String,              // WolfRun service name
    pub container_name: String,    // Existing container name
    pub node_id: String,           // Node where container runs
    pub image: String,             // Container image (for Docker)
    pub runtime: Option<String>,   // "docker" or "lxc"
    pub cluster_name: String,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// POST /api/wolfrun/services/adopt — adopt an existing container into WolfRun
pub async fn wolfrun_adopt(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfRunAdoptRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let runtime = match body.runtime.as_deref().unwrap_or("docker") {
        "lxc" => crate::wolfrun::Runtime::Lxc,
        _ => crate::wolfrun::Runtime::Docker,
    };

    let svc = state.wolfrun.adopt(
        body.name.clone(),
        body.container_name.clone(),
        body.node_id.clone(),
        body.image.clone(),
        runtime,
        body.cluster_name.clone(),
        body.env.clone(),
        body.ports.clone(),
        body.volumes.clone(),
    );

    HttpResponse::Ok().json(svc)
}

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .configure(crate::vms::api::config)
        // Auth (no auth required)
        .route("/api/auth/login", web::post().to(login))
        .route("/api/auth/logout", web::post().to(logout))
        .route("/api/auth/check", web::get().to(auth_check))
        .route("/api/settings/login-disabled", web::get().to(login_disabled_status))
        .route("/api/settings/login-disabled", web::post().to(set_login_disabled))
        // Dashboard
        .route("/api/metrics", web::get().to(get_metrics))
        .route("/api/metrics/history", web::get().to(get_metrics_history))
        .route("/api/auth/join-token", web::get().to(get_join_token))
        // Cluster
        .route("/api/cluster/verify-token", web::get().to(verify_join_token))
        .route("/api/cluster/wolfnet-sync", web::post().to(wolfnet_sync_cluster))
        .route("/api/cluster/diagnose", web::post().to(cluster_diagnose))
        .route("/api/nodes", web::get().to(get_nodes))
        .route("/api/nodes", web::post().to(add_node))
        .route("/api/nodes/{id}", web::get().to(get_node))
        .route("/api/nodes/{id}", web::delete().to(remove_node))
        .route("/api/nodes/{id}/settings", web::patch().to(update_node_settings))
        // Proxmox integration
        .route("/api/nodes/{id}/pve/resources", web::get().to(get_pve_resources))
        .route("/api/nodes/{id}/pve/test", web::post().to(pve_test_connection))
        .route("/api/nodes/{id}/pve/{vmid}/{action}", web::post().to(pve_guest_action))
        // Components
        .route("/api/components", web::get().to(get_components))
        .route("/api/components/{name}/detail", web::get().to(get_component_detail))
        .route("/api/components/{name}/config", web::put().to(save_component_config))
        .route("/api/components/{name}/install", web::post().to(install_component))
        .route("/api/install/{tech}", web::post().to(install_runtime))
        // Services
        .route("/api/services/{name}/action", web::post().to(service_action))
        // Cron Jobs
        .route("/api/cron", web::get().to(cron_list))
        .route("/api/cron", web::post().to(cron_save))
        .route("/api/cron/{index}", web::delete().to(cron_delete))
        // Certificates
        .route("/api/certificates", web::post().to(request_certificate))
        .route("/api/certificates/list", web::get().to(list_certificates))
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
        .route("/api/containers/docker/{id}/config", web::post().to(docker_update_config))
        .route("/api/containers/docker/{id}/inspect", web::get().to(docker_inspect))
        // LXC
        .route("/api/containers/lxc", web::get().to(lxc_list))
        .route("/api/containers/lxc/templates", web::get().to(lxc_templates))
        .route("/api/containers/lxc/create", web::post().to(lxc_create))
        .route("/api/containers/lxc/import", web::post().to(lxc_import_endpoint))
        .route("/api/containers/lxc/import-external", web::post().to(lxc_import_external))
        .route("/api/containers/transfer-token", web::post().to(generate_transfer_token))
        .route("/api/storage/list", web::get().to(storage_list))
        .route("/api/containers/lxc/stats", web::get().to(lxc_stats))
        .route("/api/containers/lxc/{name}/logs", web::get().to(lxc_logs))
        .route("/api/containers/lxc/{name}/config", web::get().to(lxc_config))
        .route("/api/containers/lxc/{name}/config", web::put().to(lxc_save_config))
        .route("/api/containers/lxc/{name}/action", web::post().to(lxc_action))
        .route("/api/containers/lxc/{name}/clone", web::post().to(lxc_clone))
        .route("/api/containers/lxc/{name}/mounts", web::get().to(lxc_mounts))
        .route("/api/containers/lxc/{name}/mounts", web::post().to(lxc_add_mount))
        .route("/api/containers/lxc/{name}/mounts", web::delete().to(lxc_remove_mount))
        .route("/api/containers/lxc/{name}/autostart", web::post().to(lxc_set_autostart))
        .route("/api/containers/lxc/{name}/network-link", web::post().to(lxc_set_network_link))
        .route("/api/containers/lxc/{name}/parsed-config", web::get().to(lxc_parsed_config))
        .route("/api/containers/lxc/{name}/settings", web::post().to(lxc_update_settings))
        .route("/api/containers/lxc/{name}/export", web::post().to(lxc_export_endpoint))
        .route("/api/containers/lxc/{name}/migrate", web::post().to(lxc_migrate))
        .route("/api/containers/lxc/{name}/migrate-external", web::post().to(lxc_migrate_external))
        // Network Conflicts
        .route("/api/network/conflicts", web::get().to(network_conflicts))
        // WolfNet
        .route("/api/wolfnet/status", web::get().to(wolfnet_network_status))
        .route("/api/wolfnet/next-ip", web::get().to(wolfnet_next_ip))
        // AI Agent
        .route("/api/ai/config", web::get().to(ai_get_config))
        .route("/api/ai/config", web::post().to(ai_save_config))
        .route("/api/ai/chat", web::post().to(ai_chat))
        .route("/api/ai/status", web::get().to(ai_status))
        .route("/api/ai/alerts", web::get().to(ai_alerts))
        .route("/api/ai/models", web::get().to(ai_models))
        .route("/api/ai/exec", web::post().to(ai_exec))
        .route("/api/ai/config/sync", web::post().to(ai_sync_config))
        .route("/api/ai/test-email", web::post().to(ai_test_email))
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
        .route("/api/storage/providers", web::get().to(storage_list_providers))
        .route("/api/storage/providers/{name}/install", web::post().to(storage_install_provider))
        .route("/api/system/logs", web::get().to(system_logs))
        // Disk partition info
        .route("/api/storage/disk-info", web::get().to(storage_disk_info))
        // ZFS
        .route("/api/storage/zfs/status", web::get().to(zfs_status))
        .route("/api/storage/zfs/pools", web::get().to(zfs_pools))
        .route("/api/storage/zfs/datasets", web::get().to(zfs_datasets))
        .route("/api/storage/zfs/snapshots", web::get().to(zfs_snapshots))
        .route("/api/storage/zfs/snapshot", web::post().to(zfs_create_snapshot))
        .route("/api/storage/zfs/snapshot", web::delete().to(zfs_delete_snapshot))
        .route("/api/storage/zfs/pool/scrub", web::post().to(zfs_pool_scrub))
        .route("/api/storage/zfs/pool/status", web::get().to(zfs_pool_status))
        .route("/api/storage/zfs/pool/iostat", web::get().to(zfs_pool_iostat))
        // File Manager
        .route("/api/files/browse", web::get().to(files_browse))
        .route("/api/files/mkdir", web::post().to(files_mkdir))
        .route("/api/files/delete", web::post().to(files_delete))
        .route("/api/files/rename", web::post().to(files_rename))
        .route("/api/files/upload", web::post().to(files_upload))
        .route("/api/files/download", web::get().to(files_download))
        .route("/api/files/search", web::get().to(files_search))
        .route("/api/files/chmod", web::post().to(files_chmod))
        // Docker File Manager
        .route("/api/files/docker/browse", web::get().to(files_docker_browse))
        .route("/api/files/docker/mkdir", web::post().to(files_docker_mkdir))
        .route("/api/files/docker/delete", web::post().to(files_docker_delete))
        .route("/api/files/docker/rename", web::post().to(files_docker_rename))
        .route("/api/files/docker/download", web::get().to(files_docker_download))
        // LXC File Manager
        .route("/api/files/lxc/browse", web::get().to(files_lxc_browse))
        .route("/api/files/lxc/mkdir", web::post().to(files_lxc_mkdir))
        .route("/api/files/lxc/delete", web::post().to(files_lxc_delete))
        .route("/api/files/lxc/rename", web::post().to(files_lxc_rename))
        .route("/api/files/lxc/download", web::get().to(files_lxc_download))
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
        // IP Mappings
        .route("/api/networking/ip-mappings", web::get().to(net_list_ip_mappings))
        .route("/api/networking/ip-mappings", web::post().to(net_add_ip_mapping))
        .route("/api/networking/ip-mappings/{id}", web::delete().to(net_remove_ip_mapping))
        .route("/api/networking/ip-mappings/{id}", web::put().to(net_update_ip_mapping))
        .route("/api/networking/available-ips", web::get().to(net_available_ips))
        .route("/api/networking/listening-ports", web::get().to(net_listening_ports))
        // Backups
        .route("/api/backups", web::get().to(backup_list))
        .route("/api/backups", web::post().to(backup_create))
        .route("/api/backups/targets", web::get().to(backup_targets))
        .route("/api/backups/schedules", web::get().to(backup_schedules_list))
        .route("/api/backups/schedules", web::post().to(backup_schedule_create))
        .route("/api/backups/schedules/{id}", web::delete().to(backup_schedule_delete))
        .route("/api/backups/import", web::post().to(backup_import))
        // PBS (Proxmox Backup Server) — must be before {id} routes
        .route("/api/backups/pbs/status", web::get().to(pbs_status))
        .route("/api/backups/pbs/snapshots", web::get().to(pbs_snapshots))
        .route("/api/backups/pbs/restore", web::post().to(pbs_restore))
        .route("/api/backups/pbs/restore/progress", web::get().to(pbs_restore_progress))
        .route("/api/backups/pbs/config", web::get().to(pbs_config_get))
        .route("/api/backups/pbs/config", web::post().to(pbs_config_save))
        // Generic backup {id} routes — after specific routes
        .route("/api/backups/{id}", web::delete().to(backup_delete))
        .route("/api/backups/{id}/restore", web::post().to(backup_restore))
        // Console WebSocket
        .route("/ws/console/{type}/{name}", web::get().to(crate::console::console_ws))
        // Remote Console WebSocket proxy (bridges browser ↔ remote node's console)
        .route("/ws/remote-console/{node_id}/{type}/{name}", web::get().to(crate::console::remote_console_ws))
        // PVE Console WebSocket proxy
        .route("/ws/pve-console/{node_id}/{vmid}", web::get().to(pve_console::pve_console_ws))
        // MySQL Database Editor
        .route("/api/mysql/detect", web::get().to(mysql_detect))
        .route("/api/mysql/detect-containers", web::get().to(mysql_detect_containers))
        .route("/api/mysql/connect", web::post().to(mysql_connect))
        .route("/api/mysql/databases", web::post().to(mysql_databases))
        .route("/api/mysql/tables", web::post().to(mysql_tables))
        .route("/api/mysql/structure", web::post().to(mysql_structure))
        .route("/api/mysql/data", web::post().to(mysql_data))
        .route("/api/mysql/query", web::post().to(mysql_query))
        .route("/api/mysql/dump", web::post().to(mysql_dump))
        // Agent (cluster-secret auth — inter-node communication)
        .route("/api/agent/status", web::get().to(agent_status))
        .route("/api/agent/storage/apply", web::post().to(agent_storage_apply))
        .route("/api/wolfnet/used-ips", web::get().to(wolfnet_used_ips_endpoint))
        // Geolocation proxy (ip-api.com is HTTP-only, browsers block mixed content on HTTPS pages)
        .route("/api/geolocate", web::get().to(geolocate))
        // App Store
        .route("/api/appstore/apps", web::get().to(appstore_list))
        .route("/api/appstore/apps/{id}", web::get().to(appstore_get))
        .route("/api/appstore/apps/{id}/install", web::post().to(appstore_install))
        .route("/api/appstore/installed", web::get().to(appstore_installed))
        .route("/api/appstore/installed/{id}", web::delete().to(appstore_uninstall))
        // System
        .route("/api/config/export", web::get().to(config_export))
        .route("/api/config/import", web::post().to(config_import))
        .route("/api/upgrade", web::post().to(system_upgrade))
        // Issues Scanner
        .route("/api/issues/scan", web::get().to(scan_issues))
        .route("/api/issues/clean", web::post().to(clean_system))
        // Security (Fail2ban, iptables, UFW)
        .route("/api/security/status", web::get().to(security_status))
        .route("/api/security/fail2ban/install", web::post().to(security_fail2ban_install))
        .route("/api/security/fail2ban/rebuild", web::post().to(security_fail2ban_rebuild))
        .route("/api/security/fail2ban/config", web::get().to(security_fail2ban_config_get))
        .route("/api/security/fail2ban/config", web::post().to(security_fail2ban_config_save))
        .route("/api/security/fail2ban/unban", web::post().to(security_fail2ban_unban))
        .route("/api/security/ufw/install", web::post().to(security_ufw_install))
        .route("/api/security/ufw/rule", web::post().to(security_ufw_add_rule))
        .route("/api/security/ufw/rule", web::delete().to(security_ufw_delete_rule))
        .route("/api/security/ufw/toggle", web::post().to(security_ufw_toggle))
        .route("/api/security/iptables/rules", web::get().to(security_iptables_rules))
        .route("/api/security/updates/check", web::post().to(security_check_updates))
        .route("/api/security/updates/apply", web::post().to(security_apply_updates))
        // Alerting
        .route("/api/alerts/config", web::get().to(alerts_config_get))
        .route("/api/alerts/config", web::post().to(alerts_config_save))
        .route("/api/alerts/test", web::post().to(alerts_test))
        // WolfRun — container orchestration
        .route("/api/wolfrun/services", web::get().to(wolfrun_list))
        .route("/api/wolfrun/services", web::post().to(wolfrun_create))
        .route("/api/wolfrun/services/adopt", web::post().to(wolfrun_adopt))
        .route("/api/wolfrun/services/{id}", web::get().to(wolfrun_get))
        .route("/api/wolfrun/services/{id}", web::delete().to(wolfrun_delete))
        .route("/api/wolfrun/services/{id}/scale", web::post().to(wolfrun_scale))
        .route("/api/wolfrun/services/{id}/action", web::post().to(wolfrun_service_action))
        .route("/api/wolfrun/services/{id}/settings", web::post().to(wolfrun_settings))
        .route("/api/wolfrun/services/{id}/update", web::post().to(wolfrun_update))
        .route("/api/wolfrun/services/{id}/portforward", web::get().to(wolfrun_portforward_list))
        .route("/api/wolfrun/services/{id}/portforward", web::post().to(wolfrun_portforward_add))
        .route("/api/wolfrun/services/{id}/portforward/{rule_id}", web::delete().to(wolfrun_portforward_delete))
        // Node proxy — forward API calls to remote nodes (must be last — wildcard path)
        .route("/api/nodes/{id}/proxy/{path:.*}", web::get().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::post().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::put().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::delete().to(node_proxy));
}
