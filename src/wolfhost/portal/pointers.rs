//! Domain pointers / aliases — multiple domain names → same site.
//!
//! DA-backed services proxy to DA; native services get a
//! `ServerAlias` (alias) or a dedicated redirect vhost (pointer) in
//! the container, plus a PowerDNS zone when the platform serves DNS
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
    /// The primary domain the alias should point at.
    pub target: String,
    /// The alias hostname being added.
    pub from: String,
    /// Some DA versions distinguish "alias" (shares everything) from
    /// "pointer" (just a redirect). Default = pointer for safety.
    #[serde(default)] pub is_alias: bool,
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub target: String,
    pub from: String,
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
        ToolBackend::Da { client, .. } => client.list_pointers(&query.domain).await,
        ToolBackend::Native { service } => native_tools::list_pointers(&service, &query.domain).await,
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
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.target).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.create_pointer(&body.target, &body.from, body.is_alias).await,
        ToolBackend::Native { service } => {
            let branding = state.config.get_branding();
            native_tools::create_pointer(
                &service,
                &body.target,
                &body.from,
                body.is_alias,
                (&branding.ns1, &branding.ns2),
            )
            .await
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
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.target).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.delete_pointer(&body.target, &body.from).await,
        ToolBackend::Native { service } => native_tools::delete_pointer(&service, &body.from).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
