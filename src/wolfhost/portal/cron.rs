//! Customer cron jobs.
//!
//! DA-backed services proxy to DA; native services manage the
//! container's `webmaster` crontab with stable per-job ids
//! (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::DaCronJob;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct CreateRequest {
    pub command: String,
    #[serde(default = "star")] pub minute: String,
    #[serde(default = "star")] pub hour: String,
    #[serde(default = "star")] pub day_of_month: String,
    #[serde(default = "star")] pub month: String,
    #[serde(default = "star")] pub day_of_week: String,
}

fn star() -> String { "*".to_string() }

pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.list_cron_jobs(&username).await,
        ToolBackend::Native { service } => native_tools::list_cron_jobs(&service).await,
    };
    match result {
        Ok(jobs) => HttpResponse::Ok().json(jobs),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn create(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<CreateRequest>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    if body.command.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "command is required"}));
    }
    let job = DaCronJob {
        id: String::new(),
        command: body.command.clone(),
        minute: body.minute.clone(),
        hour: body.hour.clone(),
        day_of_month: body.day_of_month.clone(),
        month: body.month.clone(),
        day_of_week: body.day_of_week.clone(),
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.create_cron_job(&username, &job).await,
        ToolBackend::Native { service } => native_tools::create_cron_job(&service, &job).await.map(|_| ()),
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.delete_cron_job(&username, &id).await,
        ToolBackend::Native { service } => native_tools::delete_cron_job(&service, &id).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
