use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::invoice::{Invoice, InvoiceStatus, CreateInvoiceRequest, UpdateInvoiceRequest};
use std::sync::Arc;

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let invoices = state.invoices.list().await;
    HttpResponse::Ok().json(invoices)
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let invoices = state.invoices.list().await;
    match invoices.iter().find(|i| i.id == id) {
        Some(i) => HttpResponse::Ok().json(i),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Invoice not found"})),
    }
}

pub async fn create(state: web::Data<Arc<AppState>>, body: web::Json<CreateInvoiceRequest>) -> HttpResponse {
    let req = body.into_inner();
    let now = chrono::Utc::now().to_rfc3339();

    let invoice = Invoice {
        id: uuid::Uuid::new_v4().to_string(),
        customer_id: req.customer_id,
        service_id: req.service_id,
        amount: req.amount,
        currency: req.currency,
        status: InvoiceStatus::Pending,
        description: req.description,
        issued_at: now,
        due_at: req.due_at,
        paid_at: None,
    };

    let id = invoice.id.clone();
    if let Err(e) = state.invoices.update_with(|items| {
        items.push(invoice);
    }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    HttpResponse::Created().json(serde_json::json!({"id": id, "status": "created"}))
}

pub async fn update(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateInvoiceRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();

    let result = state.invoices.update_with(|items| {
        if let Some(i) = items.iter_mut().find(|i| i.id == id) {
            if let Some(v) = req.status {
                i.status = v.clone();
                if v == InvoiceStatus::Paid && i.paid_at.is_none() {
                    i.paid_at = Some(chrono::Utc::now().to_rfc3339());
                }
            }
            if let Some(v) = req.amount { i.amount = v; }
            if let Some(v) = req.description { i.description = v; }
            if let Some(v) = req.due_at { i.due_at = v; }
            if let Some(v) = req.paid_at { i.paid_at = Some(v); }
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
