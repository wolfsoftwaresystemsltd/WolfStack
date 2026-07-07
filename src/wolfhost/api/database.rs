use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::config::DatabaseConfig;
use std::sync::Arc;

pub async fn get_config(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let db = state.config.get_database();
    // Don't expose the password in GET responses
    HttpResponse::Ok().json(serde_json::json!({
        "enabled": db.enabled,
        "host": db.host,
        "port": db.port,
        "username": db.username,
        "password_set": !db.password.is_empty(),
        "database": db.database,
        "connected": state.db_pool.is_some(),
    }))
}

pub async fn update_config(state: web::Data<Arc<AppState>>, body: web::Json<DatabaseConfig>) -> HttpResponse {
    match state.config.update_database(body.into_inner()) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "saved",
            "note": "Restart the WolfHost handler for changes to take effect."
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(serde::Deserialize)]
pub struct TestRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
}

pub async fn test_connection(body: web::Json<TestRequest>) -> HttpResponse {
    let url = format!(
        "mysql://{}:{}@{}:{}/{}",
        body.username, body.password, body.host, body.port, body.database
    );

    match crate::wolfhost::store::mysql_store::test_connection(&url).await {
        Ok(version) => HttpResponse::Ok().json(serde_json::json!({
            "status": "connected",
            "version": version,
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "status": "failed",
            "error": e,
        })),
    }
}
