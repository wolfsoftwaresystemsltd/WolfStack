use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::ticket::{TicketStatus, TicketMessage, MessageAuthor, UpdateTicketRequest, TicketReplyRequest};
use std::sync::Arc;

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let tickets = state.tickets.list().await;
    // Return summary without full message bodies
    let summary: Vec<serde_json::Value> = tickets.iter().map(|t| {
        serde_json::json!({
            "id": t.id,
            "customer_id": t.customer_id,
            "service_id": t.service_id,
            "subject": t.subject,
            "status": t.status,
            "priority": t.priority,
            "message_count": t.messages.len(),
            "created_at": t.created_at,
            "updated_at": t.updated_at,
        })
    }).collect();
    HttpResponse::Ok().json(summary)
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let tickets = state.tickets.list().await;
    match tickets.iter().find(|t| t.id == id) {
        Some(t) => HttpResponse::Ok().json(t),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Ticket not found"})),
    }
}

pub async fn update(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateTicketRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();

    let result = state.tickets.update_with(|items| {
        if let Some(t) = items.iter_mut().find(|t| t.id == id) {
            if let Some(v) = req.status { t.status = v; }
            if let Some(v) = req.priority { t.priority = v; }
            t.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn reply(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<TicketReplyRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();
    let now = chrono::Utc::now().to_rfc3339();

    let message = TicketMessage {
        id: uuid::Uuid::new_v4().to_string(),
        author: req.author.clone(),
        author_name: req.author_name,
        content: req.content,
        created_at: now.clone(),
    };

    let result = state.tickets.update_with(|items| {
        if let Some(t) = items.iter_mut().find(|t| t.id == id) {
            t.messages.push(message);
            // Auto-update status based on who replied
            match req.author {
                MessageAuthor::Admin => {
                    if t.status == TicketStatus::Open {
                        t.status = TicketStatus::InProgress;
                    }
                }
                MessageAuthor::Customer => {
                    if t.status == TicketStatus::Waiting || t.status == TicketStatus::Resolved {
                        t.status = TicketStatus::Open;
                    }
                }
            }
            t.updated_at = now;
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "replied"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
