//! DirectAdmin-side user backups, served alongside the
//! LXC-container backups in `backups.rs`. The portal calls whichever
//! backend matches the customer's service type.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;

#[derive(Deserialize)]
pub struct CreateRequest {
    /// Comma-separated list of areas to back up. Defaults to "all"
    /// (every area DirectAdmin supports). Common subsets:
    ///   * `domain,subdomain,email,email_data` — websites + mail
    ///   * `database,database_data` — just databases
    #[serde(default = "default_what")] pub what: String,
}

fn default_what() -> String { "all".to_string() }

#[derive(Deserialize)]
pub struct RestoreRequest { pub filename: String }

#[derive(Deserialize)]
pub struct DeleteRequest { pub filename: String }

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let (client, username) = match super::da_helper::resolve_client(&req, &state).await {
        Ok(c) => c, Err(r) => return r,
    };
    match client.list_user_backups(&username).await {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn create(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<CreateRequest>,
) -> HttpResponse {
    let (client, username) = match super::da_helper::resolve_client(&req, &state).await {
        Ok(c) => c, Err(r) => return r,
    };
    match client.create_user_backup(&username, &body.what).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "creating",
            "message": "DirectAdmin is creating a backup in the background. It will appear in the list when complete.",
        })),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn restore(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<RestoreRequest>,
) -> HttpResponse {
    if body.filename.contains("..") || body.filename.contains('/') {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid filename"}));
    }
    let (client, username) = match super::da_helper::resolve_client(&req, &state).await {
        Ok(c) => c, Err(r) => return r,
    };
    match client.restore_user_backup(&username, &body.filename).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "restoring",
            "message": "DirectAdmin is restoring the backup. This may take several minutes.",
        })),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<DeleteRequest>,
) -> HttpResponse {
    if body.filename.contains("..") || body.filename.contains('/') {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid filename"}));
    }
    let (client, username) = match super::da_helper::resolve_client(&req, &state).await {
        Ok(c) => c, Err(r) => return r,
    };
    match client.delete_user_backup(&username, &body.filename).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
