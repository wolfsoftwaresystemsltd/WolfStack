use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use std::sync::Arc;

pub async fn list(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let invoices = state.invoices.list().await;
    let mine: Vec<_> = invoices.into_iter()
        .filter(|i| i.customer_id == customer_id)
        .collect();
    HttpResponse::Ok().json(mine)
}
