use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::sync::Arc;
use std::process::Command;

fn is_proxmox() -> bool {
    Command::new("which").arg("pct").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn lxc_exec(container: &str, cmd: &str) -> Result<String, String> {
    let output = if is_proxmox() {
        Command::new("pct")
            .args(&["exec", container, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("pct exec failed: {}", e))?
    } else {
        Command::new("lxc-attach")
            .args(&["-n", container, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("lxc-attach failed: {}", e))?
    };
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[derive(Deserialize)]
pub struct BackupQuery {
    #[serde(default)]
    pub service_id: String,
}

#[derive(Deserialize)]
pub struct CreateBackupRequest {
    pub service_id: String,
    #[serde(default)]
    pub include_db: bool,
}

pub async fn list(req: HttpRequest, state: web::Data<Arc<AppState>>, query: web::Query<BackupQuery>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter()
        .filter(|s| s.customer_id == customer_id)
        .filter(|s| query.service_id.is_empty() || s.id == query.service_id)
        .filter(|s| !s.container_name.is_empty())
        .collect();

    let mut backups = Vec::new();
    for svc in &my_services {
        // List backup files inside the container
        let output = lxc_exec(&svc.container_name,
            "ls -1t /var/backups/wolfhost/ 2>/dev/null"
        ).unwrap_or_default();

        for filename in output.lines() {
            let fname = filename.trim();
            if fname.is_empty() { continue; }

            // Get file size
            let size_str = lxc_exec(&svc.container_name,
                &format!("stat -c%s '/var/backups/wolfhost/{}' 2>/dev/null", fname)
            ).unwrap_or_default();
            let size: u64 = size_str.trim().parse().unwrap_or(0);

            // Get modification time
            let mtime_str = lxc_exec(&svc.container_name,
                &format!("stat -c%Y '/var/backups/wolfhost/{}' 2>/dev/null", fname)
            ).unwrap_or_default();
            let mtime: u64 = mtime_str.trim().parse().unwrap_or(0);

            let includes_db = fname.contains("full") || fname.contains("db");

            backups.push(serde_json::json!({
                "id": format!("{}:{}", svc.container_name, fname),
                "service_id": svc.id,
                "domain": svc.domain,
                "container": svc.container_name,
                "filename": fname,
                "size_bytes": size,
                "created_at": mtime,
                "includes_db": includes_db,
            }));
        }
    }

    // Sort newest first
    backups.sort_by(|a, b| {
        let ta = a["created_at"].as_u64().unwrap_or(0);
        let tb = b["created_at"].as_u64().unwrap_or(0);
        tb.cmp(&ta)
    });

    HttpResponse::Ok().json(backups)
}

/// POST /backups/create — create a new backup
pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateBackupRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == body.service_id && s.customer_id == customer_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Service not found"})),
    };

    if service.container_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No container provisioned"}));
    }

    let container = service.container_name.clone();
    let include_db = body.include_db;
    let domain = service.domain.clone();

    tokio::spawn(async move {
        log::info!("[{}] Creating backup...", container);

        // Create backup directory
        lxc_exec(&container, "mkdir -p /var/backups/wolfhost").ok();

        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let backup_type = if include_db { "full" } else { "files" };
        let filename = format!("{}-{}-{}.tar.gz", domain.replace('.', "_"), backup_type, timestamp);

        if include_db {
            // Dump all databases first
            lxc_exec(&container, &format!(
                "mysqldump --all-databases > /tmp/db_backup.sql 2>/dev/null; \
                 tar -czf '/var/backups/wolfhost/{}' -C / var/www/html tmp/db_backup.sql 2>/dev/null; \
                 rm -f /tmp/db_backup.sql",
                filename
            )).ok();
        } else {
            // Files only
            lxc_exec(&container, &format!(
                "tar -czf '/var/backups/wolfhost/{}' -C / var/www/html 2>/dev/null",
                filename
            )).ok();
        }

        // Clean up old backups (keep last 10)
        lxc_exec(&container,
            "cd /var/backups/wolfhost && ls -1t | tail -n +11 | xargs rm -f 2>/dev/null"
        ).ok();

        log::info!("[{}] Backup created: {}", container, filename);
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "creating",
        "message": "Backup is being created in the background.",
    }))
}

pub async fn restore(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let backup_id = path.into_inner();
    // backup_id format: container_name:filename
    let parts: Vec<&str> = backup_id.splitn(2, ':').collect();
    if parts.len() != 2 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid backup ID"}));
    }
    let container = parts[0];
    let filename = parts[1];

    // Sanitize filename — no path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid filename"}));
    }

    // Verify customer owns this container
    let services = state.services.list().await;
    if !services.iter().any(|s| s.customer_id == customer_id && s.container_name == container) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    let cn = container.to_string();
    let fn_ = filename.to_string();

    tokio::spawn(async move {
        log::info!("[{}] Restoring backup: {}", cn, fn_);

        // Extract the backup
        lxc_exec(&cn, &format!(
            "cd / && tar -xzf '/var/backups/wolfhost/{}' 2>/dev/null",
            fn_
        )).ok();

        // If it includes a DB dump, restore it
        if fn_.contains("full") {
            lxc_exec(&cn,
                "if [ -f /tmp/db_backup.sql ]; then mysql < /tmp/db_backup.sql 2>/dev/null; rm -f /tmp/db_backup.sql; fi"
            ).ok();
        }

        // Fix permissions
        lxc_exec(&cn, "chown -R www-data:www-data /var/www/html").ok();
        lxc_exec(&cn, "systemctl restart apache2 2>/dev/null").ok();

        log::info!("[{}] Backup restored: {}", cn, fn_);
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "restoring",
        "message": "Backup is being restored. Your website files will be updated shortly.",
    }))
}

/// POST /backups/download — download a backup file
pub async fn download(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let backup_id = body["backup_id"].as_str().unwrap_or("");
    let parts: Vec<&str> = backup_id.splitn(2, ':').collect();
    if parts.len() != 2 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid backup ID"}));
    }
    let container = parts[0];
    let filename = parts[1];

    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid filename"}));
    }

    let services = state.services.list().await;
    if !services.iter().any(|s| s.customer_id == customer_id && s.container_name == container) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    // Read file from container
    let output = if is_proxmox() {
        Command::new("pct")
            .args(&["exec", container, "--", "cat", &format!("/var/backups/wolfhost/{}", filename)])
            .output()
    } else {
        Command::new("lxc-attach")
            .args(&["-n", container, "--", "cat", &format!("/var/backups/wolfhost/{}", filename)])
            .output()
    };

    match output {
        Ok(o) if o.status.success() => {
            HttpResponse::Ok()
                .insert_header(("Content-Type", "application/gzip"))
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(o.stdout)
        }
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "Backup file not found"})),
    }
}
