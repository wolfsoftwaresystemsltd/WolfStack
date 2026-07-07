//! SSH public-key management for shell users.
//!
//! DA-backed services proxy to DA; native services manage the
//! container root account's authorized_keys — the customer owns the
//! whole container, and the webmaster user's home is the docroot, so
//! keys must never live there (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct AddKeyRequest {
    pub label: String,
    pub public_key: String,
}

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.list_ssh_keys(&username).await,
        ToolBackend::Native { service } => native_tools::list_ssh_keys(&service).await,
    };
    match result {
        Ok(keys) => HttpResponse::Ok().json(keys),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn add(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<AddKeyRequest>,
) -> HttpResponse {
    let trimmed = body.public_key.trim();
    if !(trimmed.starts_with("ssh-rsa ")
         || trimmed.starts_with("ssh-ed25519 ")
         || trimmed.starts_with("ssh-dss ")
         || trimmed.starts_with("ecdsa-")
         || trimmed.starts_with("sk-"))
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":
                "Public key must be in OpenSSH format (ssh-rsa / ssh-ed25519 / ecdsa-… / sk-…)"
            }));
    }
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.add_ssh_key(&username, &body.label, trimmed).await,
        ToolBackend::Native { service } => native_tools::add_ssh_key(&service, &body.label, trimmed).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "added"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let key_id = path.into_inner();
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.delete_ssh_key(&username, &key_id).await,
        ToolBackend::Native { service } => native_tools::delete_ssh_key(&service, &key_id).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
