use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::sync::Arc;

/// GET /dns/status — check if PowerDNS is running
pub async fn status(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    let running = crate::wolfhost::provisioning::dns::is_pdns_running();
    let zones = if running {
        crate::wolfhost::provisioning::dns::list_zones().unwrap_or_default()
    } else {
        vec![]
    };

    HttpResponse::Ok().json(serde_json::json!({
        "running": running,
        "zone_count": zones.len(),
        "zones": zones.iter().map(|z| z["name"].as_str().unwrap_or("")).collect::<Vec<_>>(),
    }))
}

/// POST /dns/install — install PowerDNS on the host
pub async fn install(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    tokio::task::spawn_blocking(|| {
        crate::wolfhost::provisioning::dns::install_powerdns()
    }).await.unwrap_or_else(|e| Err(format!("Task failed: {}", e)))
    .map(|_| HttpResponse::Ok().json(serde_json::json!({"status": "installed"})))
    .unwrap_or_else(|e| HttpResponse::InternalServerError().json(serde_json::json!({"error": e})))
}

/// GET /dns/zones — list all DNS zones
pub async fn list_zones(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    match crate::wolfhost::provisioning::dns::list_zones() {
        Ok(zones) => HttpResponse::Ok().json(zones),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /dns/zones/{domain} — get records for a zone
pub async fn get_zone(path: web::Path<String>) -> HttpResponse {
    let domain = path.into_inner();
    match crate::wolfhost::provisioning::dns::get_zone_records(&domain) {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct CreateZoneRequest {
    pub domain: String,
    pub host_ip: String,
}

/// POST /dns/zones — create a zone for a domain
pub async fn create_zone(state: web::Data<Arc<AppState>>, body: web::Json<CreateZoneRequest>) -> HttpResponse {
    let branding = state.config.get_branding();
    let ns1 = if branding.ns1.is_empty() { "ns1.example.com".to_string() } else { branding.ns1 };
    let ns2 = if branding.ns2.is_empty() { "ns2.example.com".to_string() } else { branding.ns2 };

    match crate::wolfhost::provisioning::dns::create_zone(&body.domain, &body.host_ip, &ns1, &ns2) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created", "domain": body.domain})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// DELETE /dns/zones/{domain} — delete a zone
pub async fn delete_zone(path: web::Path<String>) -> HttpResponse {
    let domain = path.into_inner();
    match crate::wolfhost::provisioning::dns::delete_zone(&domain) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct SetRecordRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub content: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_ttl() -> u32 { 3600 }

/// PUT /dns/zones/{domain}/records — add/update a record
pub async fn set_record(path: web::Path<String>, body: web::Json<SetRecordRequest>) -> HttpResponse {
    let domain = path.into_inner();
    match crate::wolfhost::provisioning::dns::set_record(&domain, &body.name, &body.rtype, &body.content, body.ttl) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct DeleteRecordRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
}

/// DELETE /dns/zones/{domain}/records — delete a record
pub async fn delete_record(path: web::Path<String>, body: web::Json<DeleteRecordRequest>) -> HttpResponse {
    let domain = path.into_inner();
    match crate::wolfhost::provisioning::dns::delete_record(&domain, &body.name, &body.rtype) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
