use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::plan::{Plan, CreatePlanRequest, UpdatePlanRequest};
use std::sync::Arc;

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let plans = state.plans.list().await;
    HttpResponse::Ok().json(plans)
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let plans = state.plans.list().await;
    match plans.iter().find(|p| p.id == id) {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Plan not found"})),
    }
}

pub async fn create(state: web::Data<Arc<AppState>>, body: web::Json<CreatePlanRequest>) -> HttpResponse {
    let req = body.into_inner();
    let now = chrono::Utc::now().to_rfc3339();

    let plan = Plan {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        description: req.description,
        price_monthly: req.price_monthly,
        price_yearly: req.price_yearly,
        disk_mb: req.disk_mb,
        bandwidth_mb: req.bandwidth_mb,
        domains: req.domains,
        subdomains: req.subdomains,
        ftp_accounts: req.ftp_accounts,
        email_accounts: req.email_accounts,
        databases: req.databases,
        ssl_certificates: req.ssl_certificates,
        backups: req.backups,
        features: req.features,
        sort_order: req.sort_order,
        active: true,
        created_at: now,
    };

    let id = plan.id.clone();
    if let Err(e) = state.plans.update_with(|items| {
        items.push(plan);
    }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    HttpResponse::Created().json(serde_json::json!({"id": id, "status": "created"}))
}

pub async fn update(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdatePlanRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();

    let result = state.plans.update_with(|items| {
        if let Some(p) = items.iter_mut().find(|p| p.id == id) {
            if let Some(v) = req.name { p.name = v; }
            if let Some(v) = req.description { p.description = v; }
            if let Some(v) = req.price_monthly { p.price_monthly = v; }
            if let Some(v) = req.price_yearly { p.price_yearly = v; }
            if let Some(v) = req.disk_mb { p.disk_mb = v; }
            if let Some(v) = req.bandwidth_mb { p.bandwidth_mb = v; }
            if let Some(v) = req.domains { p.domains = v; }
            if let Some(v) = req.subdomains { p.subdomains = v; }
            if let Some(v) = req.ftp_accounts { p.ftp_accounts = v; }
            if let Some(v) = req.email_accounts { p.email_accounts = v; }
            if let Some(v) = req.databases { p.databases = v; }
            if let Some(v) = req.ssl_certificates { p.ssl_certificates = v; }
            if let Some(v) = req.backups { p.backups = v; }
            if let Some(v) = req.features { p.features = v; }
            if let Some(v) = req.sort_order { p.sort_order = v; }
            if let Some(v) = req.active { p.active = v; }
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let result = state.plans.update_with(|items| {
        items.retain(|p| p.id != id);
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
