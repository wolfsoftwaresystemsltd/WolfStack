//! HTTP redirect rules per domain. /old → /new with 301/302.
//!
//! DA-backed services proxy to the DA API; native services manage a
//! marker block in the container's docroot .htaccess
//! (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct DomainQuery { pub domain: String }

#[derive(Deserialize)]
pub struct CreateRequest {
    pub domain: String,
    pub path: String,
    pub destination: String,
    /// 301 (permanent) or 302 (temporary). Defaults to 301 — that's
    /// what most operators want for site reorganisations.
    #[serde(default = "default_redirect_code")] pub code: u16,
}

fn default_redirect_code() -> u16 { 301 }

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
        ToolBackend::Da { client, .. } => client.list_redirects(&query.domain).await,
        ToolBackend::Native { service } => native_tools::list_redirects(&service).await,
    };
    match result {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn create(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<CreateRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    if body.code != 301 && body.code != 302 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "redirect code must be 301 or 302"}));
    }
    let result = match backend {
        ToolBackend::Da { client, .. } => {
            client.create_redirect(&body.domain, &body.path, &body.destination, body.code).await
        }
        ToolBackend::Native { service } => {
            native_tools::create_redirect(&service, &body.path, &body.destination, body.code).await
        }
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<DeleteRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.delete_redirect(&body.domain, &body.path).await,
        ToolBackend::Native { service } => native_tools::delete_redirect(&service, &body.path).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
