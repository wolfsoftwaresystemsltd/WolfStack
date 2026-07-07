use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

const SESSION_LIFETIME_SECS: u64 = 86400; // 24 hours

struct PortalSession {
    customer_id: String,
    created: Instant,
}

pub struct PortalSessionManager {
    sessions: RwLock<HashMap<String, PortalSession>>,
}

impl PortalSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub async fn create_session(&self, customer_id: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let session = PortalSession {
            customer_id: customer_id.to_string(),
            created: Instant::now(),
        };
        self.sessions.write().await.insert(token.clone(), session);
        token
    }

    pub async fn validate(&self, token: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(token) {
            if session.created.elapsed().as_secs() < SESSION_LIFETIME_SECS {
                return Some(session.customer_id.clone());
            }
        }
        None
    }

    pub async fn destroy(&self, token: &str) {
        self.sessions.write().await.remove(token);
    }

    pub async fn cleanup_expired(&self) {
        self.sessions.write().await.retain(|_, s| {
            s.created.elapsed().as_secs() < SESSION_LIFETIME_SECS
        });
    }
}

pub fn get_session_token(req: &HttpRequest) -> Option<String> {
    // Check cookie first
    if let Some(cookie) = req.cookie("wolfhost_session") {
        return Some(cookie.value().to_string());
    }
    // Then check Authorization header
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(val) = auth.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub async fn get_customer_id(req: &HttpRequest, state: &AppState) -> Option<String> {
    let token = get_session_token(req)?;
    state.portal_sessions.validate(&token).await
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login(state: web::Data<Arc<AppState>>, body: web::Json<LoginRequest>) -> HttpResponse {
    let req = body.into_inner();
    let customers = state.customers.list().await;

    let customer = match customers.iter().find(|c| c.email == req.email) {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"})),
    };

    // Verify password
    use argon2::{Argon2, PasswordVerifier, PasswordHash};
    let parsed_hash = match PasswordHash::new(&customer.password_hash) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Invalid password hash"})),
    };

    if Argon2::default().verify_password(req.password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
    }

    // Check account status
    if customer.status != crate::wolfhost::models::customer::CustomerStatus::Active {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Account is suspended or inactive"}));
    }

    let token = state.portal_sessions.create_session(&customer.id).await;

    let mut response = HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "customer": {
            "id": customer.id,
            "email": customer.email,
            "first_name": customer.first_name,
            "last_name": customer.last_name,
            "company": customer.company,
        }
    }));

    // Set cookie
    let cookie = actix_web::cookie::Cookie::build("wolfhost_session", &token)
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(SESSION_LIFETIME_SECS as i64))
        .finish();
    response.add_cookie(&cookie).ok();

    response
}

pub async fn logout(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    if let Some(token) = get_session_token(&req) {
        state.portal_sessions.destroy(&token).await;
    }
    let mut response = HttpResponse::Ok().json(serde_json::json!({"status": "logged_out"}));
    let cookie = actix_web::cookie::Cookie::build("wolfhost_session", "")
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();
    response.add_cookie(&cookie).ok();
    response
}

pub async fn check(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    match get_customer_id(&req, &state).await {
        Some(customer_id) => {
            let customers = state.customers.list().await;
            if let Some(c) = customers.iter().find(|c| c.id == customer_id) {
                HttpResponse::Ok().json(serde_json::json!({
                    "authenticated": true,
                    "customer": {
                        "id": c.id,
                        "email": c.email,
                        "first_name": c.first_name,
                        "last_name": c.last_name,
                        "company": c.company,
                    }
                }))
            } else {
                HttpResponse::Unauthorized().json(serde_json::json!({"authenticated": false}))
            }
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({"authenticated": false})),
    }
}
