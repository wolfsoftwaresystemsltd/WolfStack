//! Admin endpoints for syncing WolfHost hosting plans onto a
//! DirectAdmin instance as user packages.
//!
//! WolfHost models a `Plan` with resource caps locally; without
//! syncing those onto DA the `package` argument to `create_user`
//! has to point at a package the operator pre-configured by hand.
//! This module bridges the two so an operator can press "Sync" and
//! every WolfHost plan becomes a DA package automatically.

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::{client_for, DaPackage};

#[derive(Deserialize)]
pub struct InstancePath {
    pub instance_id: String,
}

/// GET /directadmin/{id}/packages → list packages currently on DA.
pub async fn list_packages(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<InstancePath>,
) -> HttpResponse {
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == path.instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);
    match client.list_packages().await {
        Ok(list) => HttpResponse::Ok().json(serde_json::json!({"packages": list})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

/// POST /directadmin/{id}/packages/sync → push every WolfHost Plan
/// onto DA as a package. Existing packages with matching names are
/// updated in place; missing ones are created. Returns a per-plan
/// status report so the operator can see which ones need attention.
pub async fn sync_packages(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<InstancePath>,
) -> HttpResponse {
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == path.instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);

    let existing: std::collections::HashSet<String> = client
        .list_packages().await.unwrap_or_default()
        .into_iter().collect();

    // WolfHost's Plan model uses `0` as the sentinel for "no limit"
    // (matching the WolfStack convention). Convert to Option<_> for
    // the DA package, where `None` becomes the literal string
    // "unlimited" on the wire.
    let to_opt_u64 = |n: u64| if n == 0 { None } else { Some(n) };
    let to_opt_u32 = |n: u32| if n == 0 { None } else { Some(n) };

    let plans = state.plans.list().await;
    let mut report: Vec<serde_json::Value> = Vec::new();
    for plan in &plans {
        let pkg_name = sanitize_package_name(&plan.name);
        let pkg = DaPackage {
            name: pkg_name.clone(),
            bandwidth_mb: to_opt_u64(plan.bandwidth_mb),
            quota_mb: to_opt_u64(plan.disk_mb),
            domains: to_opt_u32(plan.domains),
            subdomains: to_opt_u32(plan.subdomains),
            email_accounts: to_opt_u32(plan.email_accounts),
            // WolfHost's Plan model doesn't (yet) split forwarders /
            // mailing lists / autoresponders into separate caps —
            // they're folded into "email_accounts". Pass the same
            // limit through so DA enforces something sensible.
            email_forwarders: to_opt_u32(plan.email_accounts),
            email_mailing_lists: to_opt_u32(plan.email_accounts),
            email_autoresponders: to_opt_u32(plan.email_accounts),
            ftp_accounts: to_opt_u32(plan.ftp_accounts),
            mysql_databases: to_opt_u32(plan.databases),
            inodes: None,
            ssl: plan.ssl_certificates > 0,
            ..DaPackage::default()
        };
        let action_label = if existing.contains(&pkg_name) { "modified" } else { "created" };
        let result = if existing.contains(&pkg_name) {
            client.modify_package(&pkg).await
        } else {
            client.create_package(&pkg).await
        };
        match result {
            Ok(_) => report.push(serde_json::json!({
                "plan_id": plan.id, "plan_name": plan.name, "package": pkg_name,
                "status": action_label,
            })),
            Err(e) => report.push(serde_json::json!({
                "plan_id": plan.id, "plan_name": plan.name, "package": pkg_name,
                "status": "failed", "error": e,
            })),
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "instance": inst.id,
        "synced": report.iter().filter(|r| r["status"] != "failed").count(),
        "failed": report.iter().filter(|r| r["status"] == "failed").count(),
        "results": report,
    }))
}

/// DELETE /directadmin/{id}/packages/{name} → remove a package on DA.
pub async fn delete_package(
    _req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (instance_id, name) = path.into_inner();
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == instance_id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Instance not found"})),
    };
    let client = client_for(&inst);
    match client.delete_package(&name).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}

/// DA package names allow letters, digits, and underscores. Mangle
/// the WolfHost plan name (which can contain anything) into a safe
/// form. Same plan name always produces the same package name so
/// re-syncs find the existing package and modify it in place.
fn sanitize_package_name(plan_name: &str) -> String {
    let mut out = String::new();
    for c in plan_name.chars() {
        if c.is_ascii_alphanumeric() { out.push(c.to_ascii_lowercase()); }
        else if c == ' ' || c == '-' || c == '_' { out.push('_'); }
    }
    if out.is_empty() { out.push_str("plan"); }
    if out.len() > 30 { out.truncate(30); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_package_name_canonical_forms() {
        assert_eq!(sanitize_package_name("Bronze"), "bronze");
        assert_eq!(sanitize_package_name("Pro Plan"), "pro_plan");
        assert_eq!(sanitize_package_name("Pro+ Plan"), "pro_plan");
        assert_eq!(sanitize_package_name(""), "plan");
    }
}
