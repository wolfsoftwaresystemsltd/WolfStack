//! Runtime info exposed to the admin UI — ports, TLS state — so the
//! frontend can build the customer-portal URL without hard-coding
//! anything. The portal lives on a separate port (`portal_port`,
//! default 8443) and may or may not be served over TLS depending on
//! whether WolfStack / Let's Encrypt certificates were available at
//! plugin start. The admin "Open Portal" buttons need both pieces.

use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use std::sync::Arc;

pub async fn get_info(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let cfg = state.config.get();
    HttpResponse::Ok().json(serde_json::json!({
        "api_port": cfg.api_port,
        "portal_port": cfg.portal_port,
        "portal_has_tls": detect_portal_tls(),
    }))
}

/// Mirror of the cert-discovery in `main::run_servers`. Re-evaluating
/// per request is cheap (two `Path::exists` calls plus an optional
/// directory scan) and keeps the admin UI honest if the operator
/// installs a certificate after the plugin started.
fn detect_portal_tls() -> bool {
    let ws_cert = "/etc/wolfstack/cert.pem";
    let ws_key = "/etc/wolfstack/key.pem";
    if std::path::Path::new(ws_cert).exists() && std::path::Path::new(ws_key).exists() {
        return true;
    }
    if let Ok(entries) = std::fs::read_dir("/etc/letsencrypt/live") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("fullchain.pem").exists() && p.join("privkey.pem").exists() {
                return true;
            }
        }
    }
    false
}
