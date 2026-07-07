//! Customer-facing subdomain management.
//!
//! DA distinguishes between "addon" domains (a separate top-level
//! domain owned by the same user) and "subdomains" (a left-label
//! attached to one of the user's existing domains). The portal's
//! existing domains.rs treats subdomains as just another flavour of
//! Add Domain, but DA has dedicated `CMD_API_SUBDOMAINS` endpoints
//! for true subdomains and the customer can't create / list / delete
//! them through the addon-domain form. This module exposes those
//! operations directly.
//!
//! Native services get real subdomains too: a dedicated vhost with
//! docroot `<docroot>/<label>` inside the container plus a PowerDNS
//! A record when the platform serves the zone
//! (provisioning::native_tools).

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::sync::Arc;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct CreateSubdomainRequest {
    /// Parent domain (e.g. `example.com`).
    pub domain: String,
    /// Left-label only (e.g. `dev` for `dev.example.com`).
    pub subdomain: String,
}

#[derive(Deserialize)]
pub struct DeleteSubdomainRequest {
    pub domain: String,
    pub subdomain: String,
}

/// GET /api/subdomains?domain=<parent> — list subdomains of one of
/// the customer's domains.
pub async fn list(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let domain = query.get("domain").cloned().unwrap_or_default();
    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "domain query parameter is required"
        }));
    }

    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &domain).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let (subs, user) = match backend {
        ToolBackend::Da { client, username } => match client.list_subdomains(&domain).await {
            Ok(s) => (s, username),
            Err(e) => return HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("DirectAdmin list_subdomains failed: {}", e)
            })),
        },
        ToolBackend::Native { service } => match native_tools::list_subdomains(&service, &domain).await {
            Ok(s) => (s, String::new()),
            Err(e) => return HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("list_subdomains failed: {}", e)
            })),
        },
    };

    // Wrap each entry as `{ name, fqdn }` so the frontend doesn't
    // have to repeat the join itself.
    let out: Vec<serde_json::Value> = subs.into_iter().map(|s| {
        serde_json::json!({
            "name": s,
            "fqdn": format!("{}.{}", s, domain),
            "parent": domain,
            "user": user,
        })
    }).collect();
    HttpResponse::Ok().json(out)
}

/// POST /api/subdomains — create `<subdomain>.<domain>`. The
/// subdomain string must be the bare label only ("dev"), not a fully
/// qualified name; we strip a trailing parent suffix defensively if
/// the caller sent one.
pub async fn create(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<CreateSubdomainRequest>,
) -> HttpResponse {
    let r = body.into_inner();
    if r.domain.trim().is_empty() || r.subdomain.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Both domain and subdomain are required"
        }));
    }

    let label = r.subdomain
        .trim_end_matches('.')
        .trim_end_matches(&r.domain)
        .trim_end_matches('.')
        .to_string();
    if label.is_empty() || label.contains('.') || label.contains('/') {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Subdomain must be a single DNS label without dots or slashes"
        }));
    }

    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &r.domain).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let result = match backend {
        ToolBackend::Da { client, .. } => client.create_subdomain(&r.domain, &label).await,
        ToolBackend::Native { service } => native_tools::create_subdomain(&service, &r.domain, &label).await,
    };
    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "status": "created",
            "fqdn": format!("{}.{}", label, r.domain),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e
        })),
    }
}

/// DELETE /api/subdomains — remove `<subdomain>.<domain>`. Same
/// label-only convention as `create`. Native deletion keeps the
/// subdomain's files — only the vhost and DNS record go.
pub async fn delete(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<DeleteSubdomainRequest>,
) -> HttpResponse {
    let r = body.into_inner();
    if r.domain.trim().is_empty() || r.subdomain.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Both domain and subdomain are required"
        }));
    }

    let label = r.subdomain
        .trim_end_matches('.')
        .trim_end_matches(&r.domain)
        .trim_end_matches('.')
        .to_string();
    if label.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Empty subdomain label after stripping parent suffix"
        }));
    }

    let backend = match super::da_helper::resolve_backend_for_domain(&req, &state, &r.domain).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let result = match backend {
        ToolBackend::Da { client, .. } => client.delete_subdomain(&r.domain, &label).await,
        ToolBackend::Native { service } => native_tools::delete_subdomain(&service, &r.domain, &label).await,
    };
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "deleted",
            "fqdn": format!("{}.{}", label, r.domain),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e
        })),
    }
}
