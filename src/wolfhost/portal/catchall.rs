//! Catch-all handler + local-mail toggle.
//! Catch-all routes mail to unknown addresses on a domain.
//!
//! DA-backed services proxy to DA; native services manage a
//! `@domain` entry in the Postfix virtual alias map. The local-mail
//! toggle is a DA concept (whether the DA box holds the MX) — native
//! services get a clear not-applicable message.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct DomainQuery { pub domain: String }

#[derive(Deserialize)]
pub struct CatchAllRequest {
    pub domain: String,
    /// `address` (forward), `fail` (550 reject), `blackhole` (silent
    /// drop), or `ignore` (DA default — let the MTA's normal routing
    /// handle it). The portal renders these as a radio group.
    pub mode: String,
    #[serde(default)] pub destination: String,
}

#[derive(Deserialize)]
pub struct LocalMailRequest {
    pub domain: String,
    /// True = this DA host accepts mail for `domain`; False = mail
    /// is delegated to whatever MX the operator points elsewhere.
    pub use_local: bool,
}

pub async fn get_catch_all(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<DomainQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.get_catch_all(&query.domain).await,
        ToolBackend::Native { service } => native_tools::get_catch_all(&service, &query.domain).await,
    };
    match result {
        Ok(c) => HttpResponse::Ok().json(c),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn set_catch_all(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<CatchAllRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    if body.mode == "address" && body.destination.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "address mode requires a destination"}));
    }
    let result = match backend {
        ToolBackend::Da { client, .. } => {
            client.set_catch_all(&body.domain, &body.mode, &body.destination).await
        }
        ToolBackend::Native { service } => {
            native_tools::set_catch_all(&service, &body.domain, &body.mode, &body.destination).await
        }
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn set_local_mail(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<LocalMailRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => match client.set_local_mail(&body.domain, body.use_local).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { .. } => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Local-mail routing is a DirectAdmin setting. On this service, mail delivery follows your domain's MX records — no toggle is needed."
        })),
    }
}
