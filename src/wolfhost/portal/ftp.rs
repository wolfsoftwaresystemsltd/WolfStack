use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::ftp::{FtpAccount, FtpStatus, CreateFtpRequest, UpdateFtpRequest};
use crate::wolfhost::models::service::ServiceBackend;
use std::sync::Arc;

fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Hash error: {}", e))
}

pub async fn list(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();
    let mut mine: Vec<serde_json::Value> = Vec::new();

    for svc in &my_services {
        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                if let Ok(ftps) = da.list_ftp_accounts(&svc.da_username).await {
                    for f in ftps {
                        mine.push(serde_json::json!({
                            "id": format!("da-{}-{}", svc.id, f.user),
                            "service_id": svc.id,
                            "username": f.user,
                            "home_dir": f.directory,
                            "quota_mb": 0,
                            "status": "active",
                            "created_at": svc.created_at,
                        }));
                    }
                }
            }
        } else {
            let accounts = state.ftp_accounts.list().await;
            for a in accounts.iter().filter(|a| a.service_id == svc.id && a.customer_id == customer_id) {
                mine.push(serde_json::json!({
                    "id": a.id,
                    "service_id": a.service_id,
                    "username": a.username,
                    "home_dir": a.home_dir,
                    "quota_mb": a.quota_mb,
                    "status": a.status,
                    "created_at": a.created_at,
                }));
            }
        }
    }
    HttpResponse::Ok().json(mine)
}

pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateFtpRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let r = body.into_inner();
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == r.service_id && s.customer_id == customer_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Service not found"})),
    };

    // DirectAdmin backend — create FTP account via DA API
    if service.backend == ServiceBackend::DirectAdmin && !service.da_instance_id.is_empty() {
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == service.da_instance_id) {
            let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);

            let ftp_domain = if service.domain.is_empty() { "default".to_string() } else { service.domain.clone() };
            if let Err(e) = da.create_ftp(&service.da_username, &r.username, &r.password, &ftp_domain).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DirectAdmin: {}", e)}));
            }

            let pw_hash = match hash_password(&r.password) {
                Ok(h) => h,
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            };

            let account = FtpAccount {
                id: uuid::Uuid::new_v4().to_string(),
                service_id: r.service_id,
                customer_id,
                username: r.username,
                password_hash: pw_hash,
                home_dir: r.home_dir,
                quota_mb: r.quota_mb,
                status: FtpStatus::Active,
                created_at: chrono::Utc::now().to_rfc3339(),
            };

            let id = account.id.clone();
            if let Err(e) = state.ftp_accounts.update_with(|items| { items.push(account); }).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
            }
            return HttpResponse::Created().json(serde_json::json!({"id": id}));
        }
    }

    let pw_hash = match hash_password(&r.password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let home = if r.home_dir.is_empty() {
        service.home_dir.clone()
    } else {
        r.home_dir
    };

    // Native backend — actually create the system user vsftpd
    // authenticates against (local_enable=YES — container.rs vsftpd
    // config). Records used to be store-only, which meant the FTP
    // login never worked.
    if service.backend == ServiceBackend::Native {
        if service.container_name.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No container provisioned for this service"
            }));
        }
        if let Err(e) = crate::wolfhost::provisioning::native_tools::create_ftp_user(
            &service, &r.username, &r.password, &home,
        ).await {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
    }

    let account = FtpAccount {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id,
        customer_id,
        username: r.username,
        password_hash: pw_hash,
        home_dir: home,
        quota_mb: r.quota_mb,
        status: FtpStatus::Active,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let id = account.id.clone();
    if let Err(e) = state.ftp_accounts.update_with(|items| { items.push(account); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

pub async fn update(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateFtpRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();
    let r = body.into_inner();

    // Native backend — a password change must reach the container's
    // system user, not just the display record.
    if let Some(pw) = &r.password {
        let accounts = state.ftp_accounts.list().await;
        if let Some(acct) = accounts.iter().find(|a| a.id == id && a.customer_id == customer_id) {
            let services = state.services.list().await;
            if let Some(svc) = services.iter().find(|s| s.id == acct.service_id)
                && svc.backend == ServiceBackend::Native
                && !svc.container_name.is_empty()
                && let Err(e) = crate::wolfhost::provisioning::native_tools::change_ftp_password(
                    svc, &acct.username, pw,
                ).await
            {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
            }
        }
    }

    let result = state.ftp_accounts.update_with(|items| {
        if let Some(a) = items.iter_mut().find(|a| a.id == id && a.customer_id == customer_id) {
            if let Some(pw) = &r.password
                && let Ok(h) = hash_password(pw) { a.password_hash = h; }
            if let Some(v) = r.home_dir { a.home_dir = v; }
            if let Some(v) = r.quota_mb { a.quota_mb = v; }
            if let Some(v) = r.status { a.status = v; }
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();

    // Check if this FTP account belongs to a DA-backed service and delete via DA
    let accounts = state.ftp_accounts.list().await;
    if let Some(acct) = accounts.iter().find(|a| a.id == id && a.customer_id == customer_id) {
        let services = state.services.list().await;
        if let Some(svc) = services.iter().find(|s| s.id == acct.service_id) {
            if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
                let instances = state.da_instances.list().await;
                if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                    let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                    let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);
                    if let Err(e) = da.delete_ftp(&svc.da_username, &acct.username).await {
                        log::error!("DA delete FTP failed: {}", e);
                    }
                }
            } else if svc.backend == ServiceBackend::Native
                && !svc.container_name.is_empty()
                && let Err(e) = crate::wolfhost::provisioning::native_tools::delete_ftp_user(svc, &acct.username).await
            {
                log::error!("[{}] native delete FTP user failed: {}", svc.container_name, e);
            }
        }
    }

    let result = state.ftp_accounts.update_with(|items| {
        items.retain(|a| !(a.id == id && a.customer_id == customer_id));
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
