//! Autoresponders + vacation messages. Two endpoints because DA
//! distinguishes the two: an autoresponder fires on every incoming
//! mail, a vacation has start/end dates and stops automatically.
//!
//! DA-backed services proxy to DA. Native services keep records in
//! the plugin store (`responders` collection) and materialise them
//! as a per-mailbox Dovecot Sieve script
//! (provisioning::native_tools::apply_mailbox_sieve). Native
//! vacation windows apply at date precision — the sieve `currentdate`
//! comparison uses the YYYY-MM-DD part of the supplied timestamps.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::models::service::HostingService;
use crate::wolfhost::provisioning::directadmin::{DaAutoresponder, DaVacation};
use crate::wolfhost::provisioning::native_tools::{self, NativeResponder};
use super::da_helper::ToolBackend;

const RESPONDERS_COLLECTION: &str = "responders";

#[derive(Deserialize)]
pub struct DomainQuery { pub domain: String }

#[derive(Deserialize)]
pub struct AutoresponderCreate {
    pub domain: String,
    pub user: String,
    pub subject: String,
    pub body: String,
    #[serde(default)] pub cc: String,
}

#[derive(Deserialize)]
pub struct VacationCreate {
    pub domain: String,
    pub user: String,
    pub message: String,
    pub start: String, // YYYY-MM-DD HH:MM
    pub end: String,
}

#[derive(Deserialize)]
pub struct UserDelete {
    pub domain: String,
    pub user: String,
}

fn load_responders(state: &AppState) -> Vec<NativeResponder> {
    state.store.load_vec(RESPONDERS_COLLECTION)
}

fn save_responders(state: &AppState, items: &[NativeResponder]) -> Result<(), String> {
    state.store.save_vec(RESPONDERS_COLLECTION, items)
}

/// Re-materialise the sieve script for one mailbox from every record
/// that survives in the store.
async fn regen_sieve(
    state: &AppState,
    service: &HostingService,
    domain: &str,
    user: &str,
) -> Result<(), String> {
    let mailbox: Vec<NativeResponder> = load_responders(state)
        .into_iter()
        .filter(|r| r.service_id == service.id && r.domain == domain && r.user == user)
        .collect();
    native_tools::apply_mailbox_sieve(service, domain, user, &mailbox).await
}

/// Store upsert + sieve regen shared by both create endpoints.
async fn upsert_responder(
    state: &AppState,
    service: &HostingService,
    record: NativeResponder,
) -> Result<(), String> {
    let mut all = load_responders(state);
    all.retain(|r| {
        !(r.service_id == record.service_id
            && r.domain == record.domain
            && r.user == record.user
            && r.kind == record.kind)
    });
    all.push(record.clone());
    save_responders(state, &all)?;
    if let Err(e) = regen_sieve(state, service, &record.domain, &record.user).await {
        // Roll the record back so the store never claims a responder
        // the mail server doesn't have.
        let mut all = load_responders(state);
        all.retain(|r| {
            !(r.service_id == record.service_id
                && r.domain == record.domain
                && r.user == record.user
                && r.kind == record.kind)
        });
        save_responders(state, &all).ok();
        return Err(e);
    }
    Ok(())
}

async fn remove_responder(
    state: &AppState,
    service: &HostingService,
    domain: &str,
    user: &str,
    kind: &str,
) -> Result<(), String> {
    let mut all = load_responders(state);
    let before = all.len();
    all.retain(|r| {
        !(r.service_id == service.id && r.domain == domain && r.user == user && r.kind == kind)
    });
    if all.len() == before {
        return Err("Not found".to_string());
    }
    save_responders(state, &all)?;
    regen_sieve(state, service, domain, user).await
}

pub async fn list_autoresponders(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<DomainQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => match client.list_autoresponders(&query.domain).await {
            Ok(list) => HttpResponse::Ok().json(list),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { service } => {
            let list: Vec<DaAutoresponder> = load_responders(&state)
                .into_iter()
                .filter(|r| r.service_id == service.id && r.domain == query.domain && r.kind == "autoresponder")
                .map(|r| DaAutoresponder { user: r.user, subject: r.subject, body: r.body, cc: r.cc })
                .collect();
            HttpResponse::Ok().json(list)
        }
    }
}

pub async fn create_autoresponder(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<AutoresponderCreate>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => {
            let cc = if body.cc.trim().is_empty() { None } else { Some(body.cc.as_str()) };
            match client.create_autoresponder(&body.domain, &body.user, &body.subject, &body.body, cc).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            if !body.cc.trim().is_empty() {
                // DA's cc sends a copy of the auto-reply elsewhere;
                // the native mail stack (Sieve vacation) has no
                // equivalent — refuse loudly instead of approximating.
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "CC copies of auto-replies are not supported on this service — leave the CC field empty"
                }));
            }
            let record = NativeResponder {
                customer_id: service.customer_id.clone(),
                service_id: service.id.clone(),
                domain: body.domain.clone(),
                user: body.user.clone(),
                subject: body.subject.clone(),
                body: body.body.clone(),
                cc: String::new(),
                start: String::new(),
                end: String::new(),
                kind: "autoresponder".to_string(),
            };
            match upsert_responder(&state, &service, record).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn delete_autoresponder(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<UserDelete>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => match client.delete_autoresponder(&body.domain, &body.user).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { service } => {
            match remove_responder(&state, &service, &body.domain, &body.user, "autoresponder").await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

pub async fn list_vacation(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<DomainQuery>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &query.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => match client.list_vacation_messages(&query.domain).await {
            Ok(list) => HttpResponse::Ok().json(list),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { service } => {
            let list: Vec<DaVacation> = load_responders(&state)
                .into_iter()
                .filter(|r| r.service_id == service.id && r.domain == query.domain && r.kind == "vacation")
                .map(|r| DaVacation { user: r.user, message: r.body, start: r.start, end: r.end })
                .collect();
            HttpResponse::Ok().json(list)
        }
    }
}

pub async fn create_vacation(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<VacationCreate>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => {
            match client.create_vacation(&body.domain, &body.user, &body.message, &body.start, &body.end).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
        ToolBackend::Native { service } => {
            // Sieve compares at date precision — keep the date part.
            let start_date = body.start.split_whitespace().next().unwrap_or("").to_string();
            let end_date = body.end.split_whitespace().next().unwrap_or("").to_string();
            if !valid_date(&start_date) || !valid_date(&end_date) {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "start and end must be YYYY-MM-DD dates"}));
            }
            let record = NativeResponder {
                customer_id: service.customer_id.clone(),
                service_id: service.id.clone(),
                domain: body.domain.clone(),
                user: body.user.clone(),
                subject: "Out of office".to_string(),
                body: body.message.clone(),
                cc: String::new(),
                start: start_date,
                end: end_date,
                kind: "vacation".to_string(),
            };
            match upsert_responder(&state, &service, record).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}

fn valid_date(d: &str) -> bool {
    let bytes = d.as_bytes();
    d.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && d.chars().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() }
        })
}

pub async fn delete_vacation(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<UserDelete>,
) -> HttpResponse {
    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &body.domain).await {
        Ok(b) => b, Err(r) => return r,
    };
    match backend {
        ToolBackend::Da { client, .. } => match client.delete_vacation(&body.domain, &body.user).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
            Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
        },
        ToolBackend::Native { service } => {
            match remove_responder(&state, &service, &body.domain, &body.user, "vacation").await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
            }
        }
    }
}
