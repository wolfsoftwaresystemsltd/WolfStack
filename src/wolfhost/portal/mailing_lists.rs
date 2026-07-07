//! Mailing lists (Majordomo on DA hosts that have it installed).
//!
//! Native services intentionally do not support mailing lists —
//! there is no Majordomo/Mailman in the native container stack, and
//! a list without subscriber management would be a trap. The list
//! endpoint returns an empty set so the panel renders cleanly, and
//! create/delete return a clear explanation instead of a 404.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use super::da_helper::ToolBackend;

const NATIVE_UNSUPPORTED: &str =
    "Mailing lists require a DirectAdmin-backed service. On this service, use an email forwarder with several destinations for simple distribution lists.";

#[derive(Deserialize)]
pub struct DomainQuery { pub domain: String }

#[derive(Deserialize)]
pub struct CreateRequest {
    pub domain: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub domain: String,
    pub name: String,
}

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<DomainQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => match client.list_mailing_lists(&query.domain).await {
            Ok(lists) => HttpResponse::Ok().json(lists),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { .. } => HttpResponse::Ok().json(serde_json::json!({
            "lists": [],
            "unsupported": NATIVE_UNSUPPORTED,
        })),
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
    match backend {
        ToolBackend::Da { client, .. } => match client.create_mailing_list(&body.domain, &body.name).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { .. } => HttpResponse::BadRequest()
            .json(serde_json::json!({"error": NATIVE_UNSUPPORTED})),
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
    match backend {
        ToolBackend::Da { client, .. } => match client.delete_mailing_list(&body.domain, &body.name).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { .. } => HttpResponse::BadRequest()
            .json(serde_json::json!({"error": NATIVE_UNSUPPORTED})),
    }
}
