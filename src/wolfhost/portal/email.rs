use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::email::{EmailAccount, EmailStatus, CreateEmailRequest, UpdateEmailRequest};
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

    let accounts = state.email_accounts.list().await;
    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();

    // Check which services have email enabled (have a container with postfix)
    let email_enabled: Vec<serde_json::Value> = my_services.iter().map(|s| {
        serde_json::json!({
            "service_id": s.id,
            "domain": s.domain,
            "host_ip": s.host_ip,
            "container_name": s.container_name,
            "email_ready": !s.container_name.is_empty(),
        })
    }).collect();

    // Fetch email accounts — live from DA for DA-backed services, local store for native
    let mut mine: Vec<serde_json::Value> = Vec::new();

    for svc in &my_services {
        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                // Get domains for this user, then email accounts per domain
                if let Ok(domains) = da.list_domains(&svc.da_username).await {
                    for domain in &domains {
                        if let Ok(emails) = da.list_email_accounts(domain).await {
                            for e in emails {
                                mine.push(serde_json::json!({
                                    "id": format!("da-{}-{}@{}", svc.id, e.user, e.domain),
                                    "service_id": svc.id,
                                    "address": format!("{}@{}", e.user, e.domain),
                                    "quota_mb": e.quota_mb,
                                    "forwarding": [],
                                    "status": "active",
                                    "created_at": svc.created_at,
                                }));
                            }
                        }
                    }
                }
            }
        } else {
            for a in accounts.iter().filter(|a| a.service_id == svc.id && a.customer_id == customer_id) {
                mine.push(serde_json::json!({
                    "id": a.id,
                    "service_id": a.service_id,
                    "address": a.address,
                    "quota_mb": a.quota_mb,
                    "forwarding": a.forwarding,
                    "status": a.status,
                    "created_at": a.created_at,
                }));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "accounts": mine,
        "services": email_enabled,
    }))
}

/// POST /email-setup — install the mail server on a service's container
pub async fn setup_mail(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let service_id = body["service_id"].as_str().unwrap_or("");
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == service_id && s.customer_id == customer_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Service not found"})),
    };

    // DirectAdmin backend — DA manages its own mail server
    if service.backend == ServiceBackend::DirectAdmin && !service.da_instance_id.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "ready",
            "message": "Email is managed by DirectAdmin. No additional mail server setup required.",
        }));
    }

    if service.container_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No container provisioned for this service"}));
    }

    let container = service.container_name.clone();
    let domain = if service.domain.is_empty() { container.clone() } else { service.domain.clone() };
    let hostname = format!("mail.{}", domain);
    let container_ip = service.container_ip.clone();

    // Run setup in background
    tokio::spawn(async move {
        log::info!("[{}] Setting up mail server for {}", container, domain);
        match crate::wolfhost::provisioning::mail::setup_mail_server(&container, &domain, &hostname) {
            Ok(_) => log::info!("[{}] Mail server ready for {}", container, domain),
            Err(e) => log::error!("[{}] Mail setup failed: {}", container, e),
        }
        // Forward mail ports
        if !container_ip.is_empty() {
            crate::wolfhost::provisioning::mail::setup_mail_forwarding(&container_ip).ok();
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "installing",
        "message": "Mail server (Postfix + Dovecot + DKIM) is being installed. This takes 1-2 minutes.",
    }))
}

/// GET /email-dns/{service_id} — get required DNS records for email
pub async fn get_dns_records(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let service_id = path.into_inner();
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == service_id && s.customer_id == customer_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Service not found"})),
    };

    let domain = &service.domain;
    let host_ip = &service.host_ip;

    // Try to get DKIM record from container
    let dkim = if !service.container_name.is_empty() {
        crate::wolfhost::provisioning::mail::get_dkim_record(&service.container_name, domain).ok()
    } else {
        None
    };

    let mut records = vec![
        serde_json::json!({"type": "MX", "name": "@", "value": format!("mail.{}", domain), "priority": 10, "description": "Mail server"}),
        serde_json::json!({"type": "A", "name": "mail", "value": host_ip, "description": "Mail server IP"}),
        serde_json::json!({"type": "TXT", "name": "@", "value": format!("v=spf1 ip4:{} ~all", host_ip), "description": "SPF — authorizes this server to send email"}),
        serde_json::json!({"type": "TXT", "name": "_dmarc", "value": format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{}", domain), "description": "DMARC policy"}),
    ];

    if let Some(dkim_txt) = dkim {
        records.push(serde_json::json!({
            "type": "TXT",
            "name": "mail._domainkey",
            "value": dkim_txt,
            "description": "DKIM — email signing key"
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "domain": domain,
        "records": records,
        "smtp": { "host": host_ip, "port": 587, "encryption": "STARTTLS" },
        "imap": { "host": host_ip, "port": 993, "encryption": "SSL/TLS" },
        "pop3": { "host": host_ip, "port": 995, "encryption": "SSL/TLS" },
    }))
}

pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateEmailRequest>) -> HttpResponse {
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

    // DirectAdmin backend — create email via DA API
    if service.backend == ServiceBackend::DirectAdmin && !service.da_instance_id.is_empty() {
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == service.da_instance_id) {
            let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);

            // Extract user and domain from address (user@domain.com)
            let parts: Vec<&str> = r.address.splitn(2, '@').collect();
            if parts.len() != 2 {
                return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid email address format"}));
            }
            let (email_user, email_domain) = (parts[0], parts[1]);

            if let Err(e) = da.create_email(email_domain, email_user, &r.password, r.quota_mb).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DirectAdmin: {}", e)}));
            }

            let pw_hash = match hash_password(&r.password) {
                Ok(h) => h,
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            };

            let account = EmailAccount {
                id: uuid::Uuid::new_v4().to_string(),
                service_id: r.service_id,
                customer_id,
                address: r.address,
                password_hash: pw_hash,
                quota_mb: r.quota_mb,
                forwarding: r.forwarding,
                status: EmailStatus::Active,
                created_at: chrono::Utc::now().to_rfc3339(),
            };

            let id = account.id.clone();
            if let Err(e) = state.email_accounts.update_with(|items| { items.push(account); }).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
            }
            return HttpResponse::Created().json(serde_json::json!({"id": id}));
        }
    }

    // Create inside the container
    if !service.container_name.is_empty() {
        let addr = r.address.clone();
        let pass = r.password.clone();
        let cn = service.container_name.clone();
        tokio::spawn(async move {
            crate::wolfhost::provisioning::mail::add_email_account(&cn, &addr, &pass).ok();
        });
    }

    let pw_hash = match hash_password(&r.password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let account = EmailAccount {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id,
        customer_id,
        address: r.address,
        password_hash: pw_hash,
        quota_mb: r.quota_mb,
        forwarding: r.forwarding,
        status: EmailStatus::Active,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let id = account.id.clone();
    if let Err(e) = state.email_accounts.update_with(|items| { items.push(account); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

pub async fn update(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateEmailRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();
    let r = body.into_inner();

    let result = state.email_accounts.update_with(|items| {
        if let Some(a) = items.iter_mut().find(|a| a.id == id && a.customer_id == customer_id) {
            if let Some(pw) = &r.password {
                if let Ok(h) = hash_password(pw) { a.password_hash = h; }
            }
            if let Some(v) = r.quota_mb { a.quota_mb = v; }
            if let Some(v) = r.forwarding { a.forwarding = v; }
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

    // Find the account and remove from container
    let accounts = state.email_accounts.list().await;
    if let Some(acct) = accounts.iter().find(|a| a.id == id && a.customer_id == customer_id) {
        let services = state.services.list().await;
        if let Some(svc) = services.iter().find(|s| s.id == acct.service_id) {
            // DirectAdmin backend — delete email via DA API
            if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
                let instances = state.da_instances.list().await;
                if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                    let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                    let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);
                    let parts: Vec<&str> = acct.address.splitn(2, '@').collect();
                    if parts.len() == 2 {
                        if let Err(e) = da.delete_email(parts[1], parts[0]).await {
                            log::error!("DA delete email failed: {}", e);
                        }
                    }
                }
            } else if !svc.container_name.is_empty() {
                let cn = svc.container_name.clone();
                let addr = acct.address.clone();
                tokio::spawn(async move {
                    crate::wolfhost::provisioning::mail::remove_email_account(&cn, &addr).ok();
                });
            }
        }
    }

    let result = state.email_accounts.update_with(|items| {
        items.retain(|a| !(a.id == id && a.customer_id == customer_id));
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
