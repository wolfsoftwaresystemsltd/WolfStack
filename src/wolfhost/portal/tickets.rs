use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::ticket::{Ticket, TicketStatus, TicketMessage, MessageAuthor, CreateTicketRequest, TicketReplyRequest};
use std::sync::Arc;

pub async fn list(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let tickets = state.tickets.list().await;
    let mine: Vec<serde_json::Value> = tickets.iter()
        .filter(|t| t.customer_id == customer_id)
        .map(|t| serde_json::json!({
            "id": t.id,
            "subject": t.subject,
            "status": t.status,
            "priority": t.priority,
            "message_count": t.messages.len(),
            "created_at": t.created_at,
            "updated_at": t.updated_at,
        }))
        .collect();
    HttpResponse::Ok().json(mine)
}

pub async fn get(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();
    let tickets = state.tickets.list().await;
    match tickets.iter().find(|t| t.id == id && t.customer_id == customer_id) {
        Some(t) => HttpResponse::Ok().json(t),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Ticket not found"})),
    }
}

pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateTicketRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let r = body.into_inner();
    let now = chrono::Utc::now().to_rfc3339();

    // Get customer name
    let customers = state.customers.list().await;
    let author_name = customers.iter()
        .find(|c| c.id == customer_id)
        .map(|c| format!("{} {}", c.first_name, c.last_name))
        .unwrap_or_else(|| "Customer".to_string());

    let ticket = Ticket {
        id: uuid::Uuid::new_v4().to_string(),
        customer_id,
        service_id: r.service_id,
        subject: r.subject,
        status: TicketStatus::Open,
        priority: r.priority,
        messages: vec![TicketMessage {
            id: uuid::Uuid::new_v4().to_string(),
            author: MessageAuthor::Customer,
            author_name,
            content: r.message,
            created_at: now.clone(),
        }],
        created_at: now.clone(),
        updated_at: now,
    };

    let id = ticket.id.clone();
    if let Err(e) = state.tickets.update_with(|items| { items.push(ticket); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

pub async fn reply(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<TicketReplyRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();
    let now = chrono::Utc::now().to_rfc3339();

    let message = TicketMessage {
        id: uuid::Uuid::new_v4().to_string(),
        author: MessageAuthor::Customer,
        author_name: body.author_name.clone(),
        content: body.content.clone(),
        created_at: now.clone(),
    };

    let result = state.tickets.update_with(|items| {
        if let Some(t) = items.iter_mut().find(|t| t.id == id && t.customer_id == customer_id) {
            t.messages.push(message);
            if t.status == TicketStatus::Waiting || t.status == TicketStatus::Resolved {
                t.status = TicketStatus::Open;
            }
            t.updated_at = now;
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "replied"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
