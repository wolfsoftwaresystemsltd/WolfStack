//! `.htaccess` directory protection — basic-auth gate on a directory.
//!
//! DA-backed services proxy to DA; native services write the
//! .htaccess + htpasswd pair inside the container
//! (provisioning::native_tools — passwords hashed by htpasswd
//! itself, files kept outside the docroot).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct DomainQuery { pub domain: String }

#[derive(Deserialize)]
pub struct ProtectRequest {
    pub domain: String,
    /// Path within the document root, e.g. `/admin`. Native
    /// validation rejects traversal; DA enforces the same at its end.
    pub path: String,
    /// Realm string shown in the browser's auth prompt.
    pub realm: String,
}

#[derive(Deserialize)]
pub struct AddUserRequest {
    pub domain: String,
    pub path: String,
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub domain: String,
    pub path: String,
}

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<DomainQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.list_protected_dirs(&query.domain).await,
        ToolBackend::Native { service } => native_tools::list_protected_dirs(&service).await,
    };
    match result {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn protect(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<ProtectRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.add_protected_dir(&body.domain, &body.path, &body.realm).await,
        ToolBackend::Native { service } => native_tools::add_protected_dir(&service, &body.path, &body.realm).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "protected"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn add_user(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<AddUserRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => {
            client.add_protected_user(&body.domain, &body.path, &body.username, &body.password).await
        }
        ToolBackend::Native { service } => {
            native_tools::add_protected_user(&service, &body.path, &body.username, &body.password).await
        }
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "user added"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn unprotect(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<DeleteRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.delete_protected_dir(&body.domain, &body.path).await,
        ToolBackend::Native { service } => native_tools::delete_protected_dir(&service, &body.path).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "removed"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
