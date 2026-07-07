//! "Open DirectAdmin" — generates a one-time login URL the customer
//! is redirected to. The customer never sees their DA password (and
//! WolfHost never has to display it).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};

use crate::wolfhost::AppState;

/// POST /api/sso/directadmin → `{"url": "https://da.example/CMD_LOGIN?..."}`
///
/// One-shot URL: expires in 60s, can only be used once. The portal
/// opens it in a new tab from a button click.
pub async fn one_time_url(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let (client, username) = match super::da_helper::resolve_client(&req, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match client.create_one_time_login_url(&username).await {
        Ok(url) => HttpResponse::Ok().json(serde_json::json!({"url": url})),
        Err(e) => HttpResponse::BadGateway()
            .json(serde_json::json!({"error": format!("Failed to create login URL: {}", e)})),
    }
}
