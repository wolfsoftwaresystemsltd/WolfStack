//! SpamAssassin settings: enabled flag, score threshold, action.
//!
//! DA-backed services proxy to DA. Native services run SpamAssassin
//! as a Postfix content_filter inside the container, installed and
//! wired on first enable (provisioning::native_tools — master.cf
//! shape from the Apache SpamAssassin wiki).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::DaSpamSettings;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct UpdateRequest {
    pub enabled: bool,
    /// Spam score threshold (typical range: 3.0 = aggressive,
    /// 5.0 = default, 10.0 = permissive). Higher = more lenient.
    pub score_threshold: f32,
    /// `tag` (mark Subject:) | `subject` (rewrite Subject:) |
    /// `deliver` (deliver as-is) | `delete` (drop on the floor).
    pub action: String,
}

pub async fn get(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.get_spam_settings(&username).await,
        ToolBackend::Native { service } => native_tools::get_spam_settings(&service).await,
    };
    match result {
        Ok(s) => HttpResponse::Ok().json(s),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

pub async fn update(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<UpdateRequest>,
) -> HttpResponse {
    if !(0.0..=15.0).contains(&body.score_threshold) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":
                "score_threshold must be between 0.0 and 15.0"
            }));
    }
    if !["tag","subject","deliver","delete"].contains(&body.action.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":
                "action must be one of: tag, subject, deliver, delete"
            }));
    }
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let settings = DaSpamSettings {
        enabled: body.enabled,
        score_threshold: body.score_threshold,
        action: body.action.clone(),
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.set_spam_settings(&username, &settings).await,
        ToolBackend::Native { service } => native_tools::set_spam_settings(&service, &settings).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
