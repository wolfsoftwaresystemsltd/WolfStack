use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::config::Branding;
use std::sync::Arc;

pub async fn get(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let branding = state.config.get_branding();
    HttpResponse::Ok().json(branding)
}

pub async fn update(state: web::Data<Arc<AppState>>, body: web::Json<Branding>) -> HttpResponse {
    match state.config.update_branding(body.into_inner()) {
        Ok(_) => {
            let branding = state.config.get_branding();
            HttpResponse::Ok().json(serde_json::json!({
                "status": "saved",
                "branding": branding,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
