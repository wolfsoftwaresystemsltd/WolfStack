use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::customer::{Customer, CustomerStatus, CreateCustomerRequest, UpdateCustomerRequest};
use std::sync::Arc;

fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Hash error: {}", e))
}

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customers = state.customers.list().await;
    // Return without password hashes
    let safe: Vec<serde_json::Value> = customers.iter().map(|c| {
        serde_json::json!({
            "id": c.id,
            "email": c.email,
            "first_name": c.first_name,
            "last_name": c.last_name,
            "company": c.company,
            "phone": c.phone,
            "status": c.status,
            "totp_enabled": c.totp_enabled,
            "notes": c.notes,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
        })
    }).collect();
    HttpResponse::Ok().json(safe)
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let customers = state.customers.list().await;
    match customers.iter().find(|c| c.id == id) {
        Some(c) => HttpResponse::Ok().json(serde_json::json!({
            "id": c.id,
            "email": c.email,
            "first_name": c.first_name,
            "last_name": c.last_name,
            "company": c.company,
            "phone": c.phone,
            "address": c.address,
            "status": c.status,
            "totp_enabled": c.totp_enabled,
            "notes": c.notes,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Customer not found"})),
    }
}

pub async fn create(state: web::Data<Arc<AppState>>, body: web::Json<CreateCustomerRequest>) -> HttpResponse {
    let req = body.into_inner();

    // Check duplicate email
    let existing = state.customers.list().await;
    if existing.iter().any(|c| c.email == req.email) {
        return HttpResponse::Conflict().json(serde_json::json!({"error": "Email already exists"}));
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let customer = Customer {
        id: uuid::Uuid::new_v4().to_string(),
        email: req.email,
        password_hash,
        first_name: req.first_name,
        last_name: req.last_name,
        company: req.company,
        phone: req.phone,
        address: req.address.unwrap_or_default(),
        status: CustomerStatus::Active,
        totp_secret: String::new(),
        totp_enabled: false,
        notes: req.notes,
        created_at: now.clone(),
        updated_at: now,
    };

    let id = customer.id.clone();
    if let Err(e) = state.customers.update_with(|items| {
        items.push(customer);
    }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    HttpResponse::Created().json(serde_json::json!({"id": id, "status": "created"}))
}

pub async fn update(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateCustomerRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();

    // Hash new password if provided
    let new_hash = if let Some(ref pw) = req.password {
        if !pw.is_empty() {
            match hash_password(pw) {
                Ok(h) => Some(h),
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        } else { None }
    } else { None };

    let result = state.customers.update_with(|items| {
        if let Some(c) = items.iter_mut().find(|c| c.id == id) {
            if let Some(v) = req.email { c.email = v; }
            if let Some(ref v) = new_hash { c.password_hash = v.clone(); }
            if let Some(v) = req.first_name { c.first_name = v; }
            if let Some(v) = req.last_name { c.last_name = v; }
            if let Some(v) = req.company { c.company = v; }
            if let Some(v) = req.phone { c.phone = v; }
            if let Some(v) = req.address { c.address = v; }
            if let Some(v) = req.notes { c.notes = v; }
            if let Some(v) = req.status { c.status = v; }
            c.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let result = state.customers.update_with(|items| {
        items.retain(|c| c.id != id);
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn suspend(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let result = state.customers.update_with(|items| {
        if let Some(c) = items.iter_mut().find(|c| c.id == id) {
            c.status = CustomerStatus::Suspended;
            c.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "suspended"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn unsuspend(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let result = state.customers.update_with(|items| {
        if let Some(c) = items.iter_mut().find(|c| c.id == id) {
            c.status = CustomerStatus::Active;
            c.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "unsuspended"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
