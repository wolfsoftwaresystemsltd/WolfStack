//! Per-domain PHP version selector. The customer picks 8.1 / 8.2 /
//! 8.3 etc — available versions come from DA on DA-backed services,
//! or from what's installed in the container on native services
//! (mod_php, switched via a2enmod — provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct DomainQuery { pub domain: String }

#[derive(Deserialize)]
pub struct SetVersionRequest {
    pub domain: String,
    pub version: String,
}

pub async fn list_versions(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.list_php_versions().await,
        ToolBackend::Native { service } => native_tools::list_php_versions(&service).await,
    };
    match result {
        Ok(versions) => HttpResponse::Ok().json(serde_json::json!({"versions": versions})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn get_version(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<DomainQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.get_domain_php_version(&query.domain).await,
        ToolBackend::Native { service } => native_tools::get_php_version(&service).await,
    };
    match result {
        Ok(v) => HttpResponse::Ok().json(serde_json::json!({"domain": query.domain, "version": v})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn set_version(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<SetVersionRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.set_domain_php_version(&body.domain, &body.version).await,
        ToolBackend::Native { service } => native_tools::set_php_version(&service, &body.version).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
