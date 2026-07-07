//! Email forwarders — `support@example.com → ops@gmail.com`.
//!
//! All routes are domain-scoped; the resolver verifies the domain
//! actually belongs to the customer before acting. DA-backed
//! services proxy to DA; native services manage the Postfix virtual
//! alias map inside the container (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct ListQuery { pub domain: String }

#[derive(Deserialize)]
pub struct CreateRequest {
    pub domain: String,
    pub user: String,
    /// One or more destination addresses. The portal accepts a
    /// single comma-separated string and splits on the client side
    /// before posting, but we also accept arrays here for non-portal
    /// callers (admin tooling, etc.).
    pub destinations: Vec<String>,
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub domain: String,
    pub user: String,
}

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.list_email_forwarders(&query.domain).await,
        ToolBackend::Native { service } => native_tools::list_forwarders(&service, &query.domain).await,
    };
    match result {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::BadGateway()
            .json(serde_json::json!({"error": format!("list forwarders failed: {}", e)})),
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
    if body.user.trim().is_empty() || body.destinations.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "user and destinations are required"}));
    }
    let result = match backend {
        ToolBackend::Da { client, .. } => {
            client.create_email_forwarder(&body.domain, &body.user, &body.destinations).await
        }
        ToolBackend::Native { service } => {
            native_tools::create_forwarder(&service, &body.domain, &body.user, &body.destinations).await
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
        ToolBackend::Da { client, .. } => client.delete_email_forwarder(&body.domain, &body.user).await,
        ToolBackend::Native { service } => native_tools::delete_forwarder(&service, &body.domain, &body.user).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
