use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::certificate::{Certificate, CertificateStatus, CertificateType, CreateCertificateRequest};
use crate::wolfhost::models::service::ServiceBackend;
use serde::Deserialize;
use std::sync::Arc;

/// Body for `POST /api/certificates/upload` — paste a PEM-encoded
/// certificate, private key, and (optionally) CA bundle. DA accepts
/// the three blobs as `CMD_API_SSL` form fields and writes them to
/// the domain's vhost. We never store the cert/key locally; DA owns
/// that. The customer keeps a record of which domain they uploaded
/// for so the SSL list page reflects "custom" vs "Let's Encrypt".
#[derive(Deserialize)]
pub struct UploadCertificateRequest {
    pub service_id: String,
    pub domain: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    #[serde(default)]
    pub ca_bundle_pem: String,
}

/// Body for `DELETE /api/certificates` — remove the active SSL cert
/// for a domain on DA. The matching local Certificate record (if any)
/// is also removed so the SSL tab reflects the change.
#[derive(Deserialize)]
pub struct DeleteCertificateRequest {
    pub service_id: String,
    pub domain: String,
}

pub async fn list(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let certs = state.certificates.list().await;
    let services = state.services.list().await;

    // Enrich with SSL status check
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();
    let mut mine: Vec<serde_json::Value> = Vec::new();

    for svc in &my_services {
        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            // Fetch SSL info live from DA for each domain
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                if let Ok(domains) = da.list_domains(&svc.da_username).await {
                    for domain in &domains {
                        let ssl = da.get_ssl_info(domain).await.unwrap_or(crate::wolfhost::provisioning::directadmin::DaSslInfo {
                            enabled: false, expires: String::new(),
                        });
                        mine.push(serde_json::json!({
                            "id": format!("da-{}-{}", svc.id, domain),
                            "service_id": svc.id,
                            "domain": domain,
                            "cert_type": "letsencrypt",
                            "status": if ssl.enabled { "active" } else { "pending" },
                            "issued_at": "",
                            "expires_at": ssl.expires,
                            "auto_renew": true,
                            "created_at": svc.created_at,
                            "ssl_live": ssl.enabled,
                        }));
                    }
                }
            }
        } else {
            for c in certs.iter().filter(|c| c.service_id == svc.id && c.customer_id == customer_id) {
                let ssl_live = crate::wolfhost::provisioning::container::check_ssl_status(&c.domain);
                mine.push(serde_json::json!({
                    "id": c.id,
                    "service_id": c.service_id,
                    "domain": c.domain,
                    "cert_type": c.cert_type,
                    "status": if ssl_live { "active".to_string() } else { format!("{:?}", c.status).to_lowercase() },
                    "issued_at": c.issued_at,
                    "expires_at": c.expires_at,
                    "auto_renew": c.auto_renew,
                    "created_at": c.created_at,
                    "ssl_live": ssl_live,
                }));
            }
        }
    }
    HttpResponse::Ok().json(mine)
}

pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateCertificateRequest>) -> HttpResponse {
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

    // DirectAdmin backend — request Let's Encrypt via DA API
    if service.backend == ServiceBackend::DirectAdmin && !service.da_instance_id.is_empty() {
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == service.da_instance_id) {
            let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);

            if let Err(e) = da.request_letsencrypt(&r.domain).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DirectAdmin: {}", e)}));
            }

            let now = chrono::Utc::now();
            let cert = Certificate {
                id: uuid::Uuid::new_v4().to_string(),
                service_id: r.service_id.clone(),
                customer_id: customer_id.clone(),
                domain: r.domain.clone(),
                cert_type: r.cert_type.clone(),
                status: CertificateStatus::Active,
                issued_at: now.to_rfc3339(),
                expires_at: (now + chrono::Duration::days(90)).to_rfc3339(),
                auto_renew: r.auto_renew,
                created_at: now.to_rfc3339(),
            };
            let cert_id = cert.id.clone();

            if let Err(e) = state.certificates.update_with(|items| { items.push(cert); }).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
            }

            return HttpResponse::Created().json(serde_json::json!({
                "id": cert_id,
                "status": "active",
                "message": format!("SSL certificate for {} issued via DirectAdmin.", r.domain),
            }));
        }
    }

    if service.container_ip.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Service container is not provisioned yet"}));
    }

    let domain = r.domain.clone();
    let container_ip = service.container_ip.clone();

    // Get the admin's support email for certbot registration
    let support_email = state.config.get_branding().support_email;

    // Create cert record
    let now = chrono::Utc::now();
    let cert = Certificate {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id.clone(),
        customer_id: customer_id.clone(),
        domain: domain.clone(),
        cert_type: r.cert_type.clone(),
        status: CertificateStatus::Pending,
        issued_at: String::new(),
        expires_at: String::new(),
        auto_renew: r.auto_renew,
        created_at: now.to_rfc3339(),
    };
    let cert_id = cert.id.clone();

    if let Err(e) = state.certificates.update_with(|items| { items.push(cert); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    // Run certbot in the background (on the HOST, not inside the container)
    let bg_state = state.clone();
    let bg_cert_id = cert_id.clone();

    tokio::spawn(async move {
        log::info!("Requesting SSL for {} (container_ip: {})", domain, container_ip);

        match crate::wolfhost::provisioning::container::request_ssl_certificate(&domain, &container_ip, &support_email) {
            Ok(msg) => {
                log::info!("SSL issued for {}: {}", domain, msg);
                // Update certificate record
                let expiry = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
                bg_state.certificates.update_with(|items| {
                    if let Some(c) = items.iter_mut().find(|c| c.id == bg_cert_id) {
                        c.status = CertificateStatus::Active;
                        c.issued_at = chrono::Utc::now().to_rfc3339();
                        c.expires_at = expiry;
                    }
                }).await.ok();
            }
            Err(e) => {
                log::error!("SSL failed for {}: {}", domain, e);
                bg_state.certificates.update_with(|items| {
                    if let Some(c) = items.iter_mut().find(|c| c.id == bg_cert_id) {
                        c.status = CertificateStatus::Failed;
                    }
                }).await.ok();
            }
        }
    });

    HttpResponse::Created().json(serde_json::json!({
        "id": cert_id,
        "status": "pending",
        "message": "SSL certificate is being requested via Let's Encrypt. This takes 30-60 seconds.",
    }))
}

pub async fn renew(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();
    let certs = state.certificates.list().await;
    let cert = match certs.iter().find(|c| c.id == id && c.customer_id == customer_id) {
        Some(c) => c.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Certificate not found"})),
    };

    let bg_state = state.clone();
    let bg_cert_id = cert.id.clone();
    let domain = cert.domain.clone();

    tokio::spawn(async move {
        match crate::wolfhost::provisioning::container::renew_certificates() {
            Ok(_) => {
                let expiry = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
                bg_state.certificates.update_with(|items| {
                    if let Some(c) = items.iter_mut().find(|c| c.id == bg_cert_id) {
                        c.status = CertificateStatus::Active;
                        c.expires_at = expiry;
                    }
                }).await.ok();
                log::info!("Certificate renewed for {}", domain);
            }
            Err(e) => log::error!("Certificate renewal failed for {}: {}", domain, e),
        }
    });

    HttpResponse::Ok().json(serde_json::json!({"status": "renewal_started"}))
}

/// POST /api/certificates/upload — paste-in a customer-supplied
/// certificate. DA-backed services proxy to DA; native services get
/// the PEM material installed into the container behind a dedicated
/// :443 vhost (provisioning::native_tools::install_custom_cert),
/// with the config rolled back automatically if Apache rejects it.
pub async fn upload_custom(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<UploadCertificateRequest>,
) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let r = body.into_inner();
    if r.certificate_pem.trim().is_empty() || r.private_key_pem.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Both certificate and private key are required"
        }));
    }

    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == r.service_id && s.customer_id == customer_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Service not found"})),
    };

    if service.backend != ServiceBackend::DirectAdmin || service.da_instance_id.is_empty() {
        // Native service — validate the PEM material here (same
        // openssl parsing the DA ssl-info path uses —
        // directadmin.rs get_ssl_info), then install it into the
        // container.
        if service.container_name.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No container provisioned for this service"
            }));
        }
        // The domain must be this service's primary or one of the
        // customer's addon domains — same ownership bar the
        // domain-scoped tools apply.
        let owns_domain = service.domain.eq_ignore_ascii_case(&r.domain)
            || state.domains.list().await.iter().any(|d| {
                d.customer_id == customer_id
                    && d.service_id == service.id
                    && d.name.eq_ignore_ascii_case(&r.domain)
            });
        if !owns_domain {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": format!("Domain `{}` is not part of this service", r.domain)
            }));
        }
        let x509 = match openssl::x509::X509::from_pem(r.certificate_pem.trim().as_bytes()) {
            Ok(c) => c,
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Certificate is not valid PEM: {}", e)
            })),
        };
        if openssl::pkey::PKey::private_key_from_pem(r.private_key_pem.trim().as_bytes()).is_err() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Private key is not valid PEM"
            }));
        }
        if !r.ca_bundle_pem.trim().is_empty()
            && openssl::x509::X509::from_pem(r.ca_bundle_pem.trim().as_bytes()).is_err()
        {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "CA bundle is not valid PEM"
            }));
        }
        let expires_at = x509.not_after().to_string();
        if let Err(e) = crate::wolfhost::provisioning::native_tools::install_custom_cert(
            &service,
            &r.domain,
            &r.certificate_pem,
            &r.private_key_pem,
            &r.ca_bundle_pem,
        )
        .await
        {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
        let now = chrono::Utc::now().to_rfc3339();
        let cert = Certificate {
            id: uuid::Uuid::new_v4().to_string(),
            service_id: r.service_id.clone(),
            customer_id: customer_id.clone(),
            domain: r.domain.clone(),
            cert_type: CertificateType::Custom,
            status: CertificateStatus::Active,
            issued_at: now.clone(),
            expires_at,
            auto_renew: false,
            created_at: now,
        };
        let cert_id = cert.id.clone();
        if let Err(e) = state.certificates.update_with(|items| { items.push(cert); }).await {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
        return HttpResponse::Created().json(serde_json::json!({
            "id": cert_id,
            "status": "active",
            "message": format!("Custom certificate installed for {}.", r.domain),
        }));
    }

    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == service.da_instance_id) {
        Some(i) => i,
        None => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "DirectAdmin instance for this service is no longer configured"
        })),
    };
    let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&inst.admin_password_enc);
    let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&inst.url, &inst.admin_user, &pass);

    let ca_bundle = if r.ca_bundle_pem.trim().is_empty() { None } else { Some(r.ca_bundle_pem.as_str()) };
    if let Err(e) = da.upload_certificate(&r.domain, &r.certificate_pem, &r.private_key_pem, ca_bundle).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("DirectAdmin rejected certificate: {}", e)
        }));
    }

    // Record the upload locally so the SSL tab can show "custom" cert
    // info even before DA reports back. Expiry is left blank because
    // we don't parse the PEM here; the next `list()` call will pull
    // the live state from DA.
    let now = chrono::Utc::now().to_rfc3339();
    let cert = Certificate {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id.clone(),
        customer_id: customer_id.clone(),
        domain: r.domain.clone(),
        cert_type: CertificateType::Custom,
        status: CertificateStatus::Active,
        issued_at: now.clone(),
        expires_at: String::new(),
        auto_renew: false,
        created_at: now,
    };
    let cert_id = cert.id.clone();
    if let Err(e) = state.certificates.update_with(|items| { items.push(cert); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    HttpResponse::Created().json(serde_json::json!({
        "id": cert_id,
        "status": "active",
        "message": format!("Custom certificate installed for {}.", r.domain),
    }))
}

/// DELETE /api/certificates — remove the active certificate for a
/// domain on DA and any local Certificate records that match. Used
/// by the customer-facing "Remove certificate" button.
pub async fn delete_custom(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    body: web::Json<DeleteCertificateRequest>,
) -> HttpResponse {
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

    if service.backend != ServiceBackend::DirectAdmin || service.da_instance_id.is_empty() {
        // Native service — take the custom-cert vhost + files out of
        // the container. Certbot-issued certs are managed through
        // create()/renew(), not this endpoint.
        if service.container_name.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No container provisioned for this service"
            }));
        }
        // Same ownership bar as upload_custom — the domain must be
        // this service's primary or one of the customer's addons.
        let owns_domain = service.domain.eq_ignore_ascii_case(&r.domain)
            || state.domains.list().await.iter().any(|d| {
                d.customer_id == customer_id
                    && d.service_id == service.id
                    && d.name.eq_ignore_ascii_case(&r.domain)
            });
        if !owns_domain {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": format!("Domain `{}` is not part of this service", r.domain)
            }));
        }
        if let Err(e) = crate::wolfhost::provisioning::native_tools::remove_custom_cert(&service, &r.domain).await {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
    } else {
        let instances = state.da_instances.list().await;
        let inst = match instances.iter().find(|i| i.id == service.da_instance_id) {
            Some(i) => i,
            None => return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "DirectAdmin instance for this service is no longer configured"
            })),
        };
        let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&inst.admin_password_enc);
        let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&inst.url, &inst.admin_user, &pass);
        if let Err(e) = da.delete_certificate(&r.domain).await {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("DirectAdmin: {}", e)
            }));
        }
    }

    // Drop any local cert rows for this customer + domain so the SSL
    // tab matches DA. Don't fail the whole call if this hiccups —
    // the source of truth is DA, the local rows are display cache.
    let cust = customer_id.clone();
    let dom = r.domain.clone();
    let _ = state.certificates.update_with(move |items| {
        items.retain(|c| !(c.customer_id == cust && c.domain == dom));
    }).await;

    HttpResponse::Ok().json(serde_json::json!({
        "status": "removed",
        "message": format!("Certificate removed for {}.", r.domain),
    }))
}
