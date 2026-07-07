//! Customer-driven password changes for hosting resources:
//!   * the customer's main account (DA login, or the portal login
//!     itself on native services)
//!   * an email mailbox
//!   * an FTP account
//!
//! Database-user passwords live in `db_users.rs` next door.
//! Native email changes upsert the Dovecot passwd-file; native FTP
//! changes chpasswd the container system user
//! (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct AccountPasswordRequest {
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct EmailPasswordRequest {
    pub domain: String,
    pub user: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct FtpPasswordRequest {
    pub ftp_user: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct FtpQuotaRequest {
    pub ftp_user: String,
    /// `None` (omit / null) → unlimited.
    pub quota_mb: Option<u64>,
}

fn weak(pw: &str) -> Option<&'static str> {
    if pw.len() < 8 { return Some("password must be at least 8 characters"); }
    if pw.chars().all(|c| c.is_ascii_alphabetic()) { return Some("password must contain a digit or symbol"); }
    None
}

pub async fn change_account(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<AccountPasswordRequest>,
) -> HttpResponse {
    if let Some(reason) = weak(&body.new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": reason}));
    }
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => {
            match client.change_user_password(&username, &body.new_password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            // On native services the "account" credential IS the
            // portal login — same hash the account settings page
            // updates (account.rs change_password), minus the
            // current-password check the DA flow doesn't have either.
            use argon2::{Argon2, PasswordHasher};
            use argon2::password_hash::SaltString;
            use rand::rngs::OsRng;
            let salt = SaltString::generate(&mut OsRng);
            let new_hash = match Argon2::default().hash_password(body.new_password.as_bytes(), &salt) {
                Ok(h) => h.to_string(),
                Err(e) => return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": format!("Hash error: {}", e)})),
            };
            let cid = service.customer_id.clone();
            let result = state.customers.update_with(|items| {
                if let Some(c) = items.iter_mut().find(|c| c.id == cid) {
                    c.password_hash = new_hash.clone();
                }
            }).await;
            match result {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn change_email(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<EmailPasswordRequest>,
) -> HttpResponse {
    if let Some(reason) = weak(&body.new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": reason}));
    }
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => {
            match client.change_email_password(&body.domain, &body.user, &body.new_password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            let address = format!("{}@{}", body.user, body.domain);
            match native_tools::change_email_password(&service, &address, &body.new_password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn change_ftp(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<FtpPasswordRequest>,
) -> HttpResponse {
    if let Some(reason) = weak(&body.new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": reason}));
    }
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => {
            match client.change_ftp_password(&username, &body.ftp_user, &body.new_password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            // Only FTP accounts recorded against this service (or the
            // built-in webmaster user) may be touched.
            let allowed = body.ftp_user == "webmaster"
                || state.ftp_accounts.list().await.iter().any(|a| {
                    a.service_id == service.id && a.username == body.ftp_user
                });
            if !allowed {
                return HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "That FTP account does not belong to this service"}));
            }
            match native_tools::change_ftp_password(&service, &body.ftp_user, &body.new_password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn set_ftp_quota(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<FtpQuotaRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => {
            match client.set_ftp_quota(&username, &body.ftp_user, body.quota_mb).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { .. } => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Per-FTP-account quotas are not supported on this service — the plan's disk limit applies to the whole container."
        })),
    }
}
