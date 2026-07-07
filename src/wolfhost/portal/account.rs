use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub phone: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn get_profile(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let customers = state.customers.list().await;
    match customers.iter().find(|c| c.id == customer_id) {
        Some(c) => HttpResponse::Ok().json(serde_json::json!({
            "id": c.id,
            "email": c.email,
            "first_name": c.first_name,
            "last_name": c.last_name,
            "company": c.company,
            "phone": c.phone,
            "address": c.address,
            "totp_enabled": c.totp_enabled,
            "created_at": c.created_at,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Customer not found"})),
    }
}

pub async fn update_profile(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<UpdateProfileRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let r = body.into_inner();
    let result = state.customers.update_with(|items| {
        if let Some(c) = items.iter_mut().find(|c| c.id == customer_id) {
            if let Some(v) = r.first_name { c.first_name = v; }
            if let Some(v) = r.last_name { c.last_name = v; }
            if let Some(v) = r.company { c.company = v; }
            if let Some(v) = r.phone { c.phone = v; }
            c.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn change_password(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<ChangePasswordRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let r = body.into_inner();

    // Verify current password
    let customers = state.customers.list().await;
    let customer = match customers.iter().find(|c| c.id == customer_id) {
        Some(c) => c.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Customer not found"})),
    };

    use argon2::{Argon2, PasswordVerifier, PasswordHash, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let parsed_hash = match PasswordHash::new(&customer.password_hash) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Invalid stored hash"})),
    };

    if Argon2::default().verify_password(r.current_password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Current password is incorrect"}));
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let new_hash = match Argon2::default().hash_password(r.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Hash error: {}", e)})),
    };

    let result = state.customers.update_with(|items| {
        if let Some(c) = items.iter_mut().find(|c| c.id == customer_id) {
            c.password_hash = new_hash;
            c.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "password_changed"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
