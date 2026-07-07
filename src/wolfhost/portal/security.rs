//! Per-domain security toggles: force HTTPS, HSTS. Plus 2FA status.
//!
//! 2FA enrolment itself happens in DirectAdmin's UI (it requires a
//! TOTP scan flow we don't want to recreate); the portal here only
//! reports the status. Native services report 2FA as unavailable —
//! the portal login has no customer-side TOTP yet, and pretending
//! otherwise would be worse than saying so.
//!
//! Force-HTTPS and HSTS on native services are .htaccess marker
//! blocks in the container docroot (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct ForceHttpsRequest {
    pub domain: String,
    pub force: bool,
}

#[derive(Deserialize)]
pub struct HstsRequest {
    pub domain: String,
    pub enabled: bool,
}

pub async fn set_force_https(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<ForceHttpsRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.set_force_https(&body.domain, body.force).await,
        ToolBackend::Native { service } => native_tools::set_force_https(&service, body.force).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn set_hsts(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<HstsRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, .. } => client.set_hsts(&body.domain, body.enabled).await,
        ToolBackend::Native { service } => native_tools::set_hsts(&service, body.enabled).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn twofactor_status(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => match client.get_2fa_status(&username).await {
            Ok(s) => HttpResponse::Ok().json(s),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { .. } => {
            HttpResponse::Ok().json(crate::wolfhost::provisioning::directadmin::DaTwoFactorStatus {
                enabled: false,
                method: String::new(),
            })
        }
    }
}
