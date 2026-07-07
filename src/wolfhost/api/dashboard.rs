use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::invoice::InvoiceStatus;
use crate::wolfhost::models::ticket::TicketStatus;
use crate::wolfhost::models::service::ServiceStatus;
use crate::wolfhost::models::customer::CustomerStatus;
use std::sync::Arc;

pub async fn get_stats(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customers = state.customers.list().await;
    let services = state.services.list().await;
    let invoices = state.invoices.list().await;
    let tickets = state.tickets.list().await;

    let active_customers = customers.iter().filter(|c| c.status == CustomerStatus::Active).count();
    let active_services = services.iter().filter(|s| s.status == ServiceStatus::Active).count();
    let monthly_revenue: f64 = invoices.iter()
        .filter(|i| i.status == InvoiceStatus::Paid)
        .map(|i| i.amount)
        .sum();
    let overdue_invoices = invoices.iter().filter(|i| i.status == InvoiceStatus::Overdue).count();
    let open_tickets = tickets.iter()
        .filter(|t| t.status == TicketStatus::Open || t.status == TicketStatus::InProgress)
        .count();
    let total_disk: u64 = services.iter().map(|s| s.usage.disk_mb).sum();
    let total_bandwidth: u64 = services.iter().map(|s| s.usage.bandwidth_mb).sum();

    HttpResponse::Ok().json(serde_json::json!({
        "total_customers": customers.len(),
        "active_customers": active_customers,
        "total_services": services.len(),
        "active_services": active_services,
        "monthly_revenue": monthly_revenue,
        "overdue_invoices": overdue_invoices,
        "open_tickets": open_tickets,
        "total_disk_mb": total_disk,
        "total_bandwidth_mb": total_bandwidth,
        "currency": state.config.get_branding().currency,
    }))
}

pub async fn get_activity(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customers = state.customers.list().await;
    let tickets = state.tickets.list().await;
    let invoices = state.invoices.list().await;

    // Build a simple activity feed from recent items
    let mut activity: Vec<serde_json::Value> = Vec::new();

    // Recent customers
    for c in customers.iter().rev().take(5) {
        activity.push(serde_json::json!({
            "type": "customer",
            "message": format!("New customer: {} {}", c.first_name, c.last_name),
            "time": c.created_at,
        }));
    }

    // Recent tickets
    for t in tickets.iter().rev().take(5) {
        activity.push(serde_json::json!({
            "type": "ticket",
            "message": format!("Ticket: {}", t.subject),
            "status": t.status,
            "time": t.updated_at,
        }));
    }

    // Recent invoices
    for i in invoices.iter().rev().take(5) {
        activity.push(serde_json::json!({
            "type": "invoice",
            "message": format!("Invoice: {} — {:.2} {}", i.description, i.amount, i.currency),
            "status": i.status,
            "time": i.issued_at,
        }));
    }

    // Sort by time descending
    activity.sort_by(|a, b| {
        let ta = a["time"].as_str().unwrap_or("");
        let tb = b["time"].as_str().unwrap_or("");
        tb.cmp(ta)
    });
    activity.truncate(15);

    HttpResponse::Ok().json(activity)
}
