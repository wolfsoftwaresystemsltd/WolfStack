//! Database users (separate from databases). DA models them
//! distinctly so a single MySQL user can be granted access to
//! multiple databases.
//!
//! DA-backed services proxy to DA; native services run the grants
//! against the MariaDB inside the container, and the database being
//! granted must belong to the same customer (checked against the
//! databases store).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::DaDbUser;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct CreateRequest {
    pub database: String,
    pub user: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct PasswordRequest {
    pub user: String,
    pub password: String,
}

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => match client.list_db_users(&username).await {
            Ok(list) => HttpResponse::Ok().json(list),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { service } => {
            // Group the customer's stored databases by their MySQL
            // user — the native equivalent of DA's user→databases map.
            let dbs = state.databases.list().await;
            let mut by_user: std::collections::BTreeMap<String, Vec<String>> = Default::default();
            for d in dbs.iter().filter(|d| d.service_id == service.id) {
                by_user.entry(d.username.clone()).or_default().push(d.name.clone());
            }
            let list: Vec<DaDbUser> = by_user
                .into_iter()
                .map(|(user, databases)| DaDbUser { user, databases })
                .collect();
            HttpResponse::Ok().json(list)
        }
    }
}

pub async fn create(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<CreateRequest>,
) -> HttpResponse {
    if body.password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "password must be at least 8 characters"}));
    }
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => {
            match client.create_db_user(&username, &body.database, &body.user, &body.password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            // The database must be one of this service's own.
            let owns = state.databases.list().await.iter().any(|d| {
                d.service_id == service.id && d.name == body.database
            });
            if !owns {
                return HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "That database does not belong to this service"}));
            }
            match native_tools::create_db_user(&service, &body.database, &body.user, &body.password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn delete(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let db_user = path.into_inner();
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => match client.delete_db_user(&username, &db_user).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { service } => {
            // Refuse to drop a user that still owns one of the
            // service's databases — the databases view manages those.
            let in_use = state.databases.list().await.iter().any(|d| {
                d.service_id == service.id && d.username == db_user
            });
            if in_use {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "That user is the owner of one of your databases — delete the database instead"
                }));
            }
            match native_tools::delete_db_user(&service, &db_user).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn change_password(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<PasswordRequest>,
) -> HttpResponse {
    if body.password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "password must be at least 8 characters"}));
    }
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, username } => {
            match client.change_db_user_password(&username, &body.user, &body.password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "password updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            // Only users tied to this service's databases can be touched.
            let owns = state.databases.list().await.iter().any(|d| {
                d.service_id == service.id && d.username == body.user
            });
            if !owns {
                return HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "That database user does not belong to this service"}));
            }
            match native_tools::change_db_user_password(&service, &body.user, &body.password).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "password updated"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}
