//! Portal-side helpers for routing customer requests through to
//! their DirectAdmin instance.
//!
//! Most customer-facing endpoints follow the same five-line dance:
//!   1. Resolve the customer id from the session cookie.
//!   2. Find the customer's DA-backed service.
//!   3. Look up the DirectAdminInstance.
//!   4. Build a DaClient.
//!   5. Call a single DA method and forward the result as JSON.
//!
//! Without these helpers each handler reimplements steps 1-4. With
//! them, every handler is a one-liner around the actual DA call.

use std::sync::Arc;
use actix_web::{HttpRequest, HttpResponse};

use crate::wolfhost::AppState;
use crate::wolfhost::models::directadmin::DirectAdminInstance;
use crate::wolfhost::models::service::{HostingService, ServiceBackend};
use crate::wolfhost::provisioning::directadmin::{client_for, DaClient};

/// Find the DA-backed service belonging to the authenticated customer
/// AND the matching DirectAdminInstance. Returns `Err` with a 401 /
/// 404 response ready to short-circuit-return from the handler.
///
/// Most portal endpoints assume one DA service per customer (which is
/// the WolfHost data model — one Plan → one Service → one DA user).
/// If a customer ever has multiple DA services we'd need a service-id
/// path param; today this picks the first match deterministically.
pub async fn resolve_da(
    req: &HttpRequest,
    state: &AppState,
) -> Result<(DirectAdminInstance, HostingService), HttpResponse> {
    let customer_id = match super::auth::get_customer_id(req, state).await {
        Some(id) => id,
        None => return Err(HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Not authenticated"}))),
    };
    let services = state.services.list().await;
    let svc = services.into_iter().find(|s| {
        s.customer_id == customer_id
            && s.backend == ServiceBackend::DirectAdmin
            && !s.da_instance_id.is_empty()
    });
    let svc = match svc {
        Some(s) => s,
        None => return Err(HttpResponse::NotFound()
            .json(serde_json::json!({"error": "No DirectAdmin service found for this account"}))),
    };
    let instances = state.da_instances.list().await;
    let inst = instances.into_iter().find(|i| i.id == svc.da_instance_id);
    let inst = match inst {
        Some(i) => i,
        None => return Err(HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "DirectAdmin instance for this service is no longer configured"}))),
    };
    Ok((inst, svc))
}

/// Convenience: same as `resolve_da` but returns a ready-to-use
/// `DaClient` plus the DA username we should pass into per-user calls.
pub async fn resolve_client(
    req: &HttpRequest,
    state: &AppState,
) -> Result<(DaClient, String), HttpResponse> {
    let (inst, svc) = resolve_da(req, state).await?;
    Ok((client_for(&inst), svc.da_username))
}

/// Which backend should serve a Hosting-Tools request for this
/// customer. Native services qualify once they have a container —
/// the tools operate inside it. DA keeps priority when a customer
/// somehow has both, preserving the pre-dispatch behaviour.
pub enum ToolBackend {
    Da { client: DaClient, username: String },
    // Boxed: HostingService is ~20 String fields; boxing keeps the
    // enum small (clippy large_enum_variant).
    Native { service: Box<HostingService> },
}

/// Resolve the user-scoped tool backend (cron, SSH keys, logs,
/// spam, account password — things not tied to one domain).
pub async fn resolve_backend(
    req: &HttpRequest,
    state: &AppState,
) -> Result<ToolBackend, HttpResponse> {
    let customer_id = match super::auth::get_customer_id(req, state).await {
        Some(id) => id,
        None => return Err(HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Not authenticated"}))),
    };
    let services = state.services.list().await;
    if let Some(svc) = services.iter().find(|s| {
        s.customer_id == customer_id
            && s.backend == ServiceBackend::DirectAdmin
            && !s.da_instance_id.is_empty()
    }) {
        let instances = state.da_instances.list().await;
        let inst = match instances.into_iter().find(|i| i.id == svc.da_instance_id) {
            Some(i) => i,
            None => return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "DirectAdmin instance for this service is no longer configured"}))),
        };
        return Ok(ToolBackend::Da { client: client_for(&inst), username: svc.da_username.clone() });
    }
    if let Some(svc) = services.into_iter().find(|s| {
        s.customer_id == customer_id
            && s.backend == ServiceBackend::Native
            && !s.container_name.is_empty()
    }) {
        return Ok(ToolBackend::Native { service: Box::new(svc) });
    }
    Err(HttpResponse::NotFound().json(serde_json::json!({
        "error": "No hosting service with a provisioned server was found for this account"
    })))
}

/// Domain-scoped variant: verifies the domain belongs to the
/// customer before resolving. DA ownership is checked live against
/// DA (as before); native ownership against the service's primary
/// domain and the customer's addon-domain records.
pub async fn resolve_backend_for_domain(
    req: &HttpRequest,
    state: &Arc<AppState>,
    domain: &str,
) -> Result<ToolBackend, HttpResponse> {
    let customer_id = match super::auth::get_customer_id(req, state).await {
        Some(id) => id,
        None => return Err(HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Not authenticated"}))),
    };
    let services = state.services.list().await;
    let has_da = services.iter().any(|s| {
        s.customer_id == customer_id
            && s.backend == ServiceBackend::DirectAdmin
            && !s.da_instance_id.is_empty()
    });
    if has_da {
        // Reuse the existing DA path including its live domain check.
        let (client, username, _inst) = resolve_for_domain(req, state, domain).await?;
        return Ok(ToolBackend::Da { client, username });
    }
    let addon_service_id = state
        .domains
        .list()
        .await
        .iter()
        .find(|d| d.customer_id == customer_id && d.name.eq_ignore_ascii_case(domain))
        .map(|d| d.service_id.clone());
    let svc = services.into_iter().find(|s| {
        s.customer_id == customer_id
            && s.backend == ServiceBackend::Native
            && !s.container_name.is_empty()
            && (s.domain.eq_ignore_ascii_case(domain)
                || addon_service_id.as_deref() == Some(s.id.as_str()))
    });
    match svc {
        Some(s) => Ok(ToolBackend::Native { service: Box::new(s) }),
        None => Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": format!("Domain `{}` is not part of this account", domain)
        }))),
    }
}

/// Verify that `domain` belongs to the customer's DA account before
/// running domain-scoped commands. Defends against operator typos and
/// (more importantly) against a curl request crafted to manage a
/// different customer's domain on the same DA instance. Returns Ok
/// with the resolved client + username on success; Err with a 403
/// response otherwise.
pub async fn resolve_for_domain(
    req: &HttpRequest,
    state: &Arc<AppState>,
    domain: &str,
) -> Result<(DaClient, String, DirectAdminInstance), HttpResponse> {
    let (inst, svc) = resolve_da(req, state).await?;
    let client = client_for(&inst);
    // Pull the up-to-date list from DA — the local domains table can
    // lag and false-deny. If the DA call fails we treat it as a hard
    // 502 so the caller surfaces the underlying connection error.
    let domains = match client.list_domains(&svc.da_username).await {
        Ok(d) => d,
        Err(e) => return Err(HttpResponse::BadGateway()
            .json(serde_json::json!({"error": format!("DA list_domains failed: {}", e)}))),
    };
    if !domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
        return Err(HttpResponse::Forbidden()
            .json(serde_json::json!({"error": format!("Domain `{}` is not part of this account", domain)})));
    }
    Ok((client, svc.da_username, inst))
}
