//! Web/error/mail log tail. Read-only — never lets the customer
//! write into the server's log files.
//!
//! DA-backed services proxy to DA; native services tail the
//! container's Apache/mail logs (provisioning::native_tools).

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wolfhost::AppState;
use crate::wolfhost::provisioning::directadmin::DaLogType;
use crate::wolfhost::provisioning::native_tools;
use super::da_helper::ToolBackend;

#[derive(Deserialize)]
pub struct LogQuery {
    pub kind: String,
    /// How many lines from the tail to return. Capped at 5000.
    #[serde(default = "default_lines")] pub lines: u32,
}

fn default_lines() -> u32 { 200 }

pub async fn tail(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<LogQuery>,
) -> HttpResponse {
    let kind = match query.kind.as_str() {
        "access"      => DaLogType::Access,
        "error"       => DaLogType::Error,
        "access_ssl"  => DaLogType::AccessSsl,
        "error_ssl"   => DaLogType::ErrorSsl,
        "mail"        => DaLogType::Mail,
        _ => return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":
                "kind must be one of: access, error, access_ssl, error_ssl, mail"
            })),
    };
    let lines = query.lines.min(5000);
    let backend = match super::da_helper::resolve_backend(&req, &state).await {
        Ok(b) => b, Err(r) => return r,
    };
    let result = match backend {
        ToolBackend::Da { client, username } => client.get_log(&username, kind, lines).await,
        ToolBackend::Native { service } => native_tools::tail_log(&service, &query.kind, lines).await,
    };
    match result {
        Ok(text) => HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(text),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e})),
    }
}
