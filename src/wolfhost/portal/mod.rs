pub mod auth;
pub mod dashboard;
pub mod domains;
pub mod ftp;
pub mod ssl;
pub mod databases;
pub mod email;
pub mod files;
pub mod backups;
pub mod tickets;
pub mod billing;
pub mod account;
pub mod apps;
// DirectAdmin-feature modules — added alongside the originals so the
// existing baseline keeps working unchanged.
pub mod da_helper;
pub mod sso;
pub mod usage;
pub mod forwarders;
pub mod autoresponders;
pub mod catchall;
pub mod php;
pub mod pointers;
pub mod redirects;
pub mod cron;
pub mod ssh_keys;
pub mod mailing_lists;
pub mod spam;
pub mod security;
pub mod protected_dirs;
pub mod logs;
pub mod db_users;
pub mod passwords;
pub mod da_backups;
pub mod subdomains;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Auth (no session required)
        .route("/api/auth/login", web::post().to(auth::login))
        .route("/api/auth/logout", web::post().to(auth::logout))
        .route("/api/auth/check", web::get().to(auth::check))
        // Dashboard
        .route("/api/dashboard", web::get().to(dashboard::get_dashboard))
        // DNS records (customer manages their zone)
        .route("/api/dns/records", web::get().to(dns_records))
        .route("/api/dns/records", web::put().to(dns_set_record))
        .route("/api/dns/records", web::delete().to(dns_delete_record))
        // Domains
        .route("/api/domains", web::get().to(domains::list))
        .route("/api/domains", web::post().to(domains::create))
        .route("/api/domains/{id}", web::put().to(domains::update))
        .route("/api/domains/{id}", web::delete().to(domains::delete))
        // Subdomains — true DA subdomains (a left-label attached to
        // an existing parent), distinct from addon domains.
        .route("/api/subdomains", web::get().to(subdomains::list))
        .route("/api/subdomains", web::post().to(subdomains::create))
        .route("/api/subdomains", web::delete().to(subdomains::delete))
        // FTP
        .route("/api/ftp-accounts", web::get().to(ftp::list))
        .route("/api/ftp-accounts", web::post().to(ftp::create))
        .route("/api/ftp-accounts/{id}", web::put().to(ftp::update))
        .route("/api/ftp-accounts/{id}", web::delete().to(ftp::delete))
        // SSL — Let's Encrypt request, custom-cert paste, removal,
        // renew. `upload` and the new `delete` route only apply to
        // DA-backed services; native services manage SSL via certbot
        // through the `create` flow.
        .route("/api/certificates", web::get().to(ssl::list))
        .route("/api/certificates", web::post().to(ssl::create))
        .route("/api/certificates", web::delete().to(ssl::delete_custom))
        .route("/api/certificates/upload", web::post().to(ssl::upload_custom))
        .route("/api/certificates/{id}/renew", web::post().to(ssl::renew))
        // Databases
        .route("/api/databases", web::get().to(databases::list))
        .route("/api/databases", web::post().to(databases::create))
        .route("/api/databases/{id}", web::delete().to(databases::delete))
        // Email
        .route("/api/email-accounts", web::get().to(email::list))
        .route("/api/email-accounts", web::post().to(email::create))
        .route("/api/email-accounts/{id}", web::put().to(email::update))
        .route("/api/email-accounts/{id}", web::delete().to(email::delete))
        .route("/api/email-setup", web::post().to(email::setup_mail))
        .route("/api/email-dns/{service_id}", web::get().to(email::get_dns_records))
        // Files
        .route("/api/files/list", web::get().to(files::list_files))
        .route("/api/files/read", web::get().to(files::read_file))
        .route("/api/files/download", web::get().to(files::download))
        .route("/api/files/save", web::post().to(files::upload))
        .route("/api/files/delete", web::post().to(files::delete_file))
        .route("/api/files/mkdir", web::post().to(files::mkdir))
        .route("/api/files/rename", web::post().to(files::rename))
        // Backups
        .route("/api/backups", web::get().to(backups::list))
        .route("/api/backups/create", web::post().to(backups::create))
        .route("/api/backups/download", web::post().to(backups::download))
        .route("/api/backups/{id}/restore", web::post().to(backups::restore))
        // Tickets
        .route("/api/tickets", web::get().to(tickets::list))
        .route("/api/tickets", web::post().to(tickets::create))
        .route("/api/tickets/{id}", web::get().to(tickets::get))
        .route("/api/tickets/{id}/reply", web::post().to(tickets::reply))
        // Billing
        .route("/api/invoices", web::get().to(billing::list))
        // Apps
        .route("/api/apps", web::get().to(apps::list))
        .route("/api/apps/install", web::post().to(apps::install))
        // Container stats (for customer dashboard)
        .route("/api/container-stats", web::get().to(container_stats))
        // Account
        .route("/api/account", web::get().to(account::get_profile))
        .route("/api/account", web::put().to(account::update_profile))
        .route("/api/account/password", web::post().to(account::change_password))
        // SSO into DirectAdmin (one-time login URL)
        .route("/api/sso/directadmin", web::post().to(sso::one_time_url))
        // Real DA-side resource usage
        .route("/api/usage", web::get().to(usage::get_usage))
        .route("/api/usage/email/{domain}", web::get().to(usage::get_email_usage))
        // Email forwarders
        .route("/api/email-forwarders", web::get().to(forwarders::list))
        .route("/api/email-forwarders", web::post().to(forwarders::create))
        .route("/api/email-forwarders", web::delete().to(forwarders::delete))
        // Autoresponders + vacation
        .route("/api/autoresponders", web::get().to(autoresponders::list_autoresponders))
        .route("/api/autoresponders", web::post().to(autoresponders::create_autoresponder))
        .route("/api/autoresponders", web::delete().to(autoresponders::delete_autoresponder))
        .route("/api/vacation", web::get().to(autoresponders::list_vacation))
        .route("/api/vacation", web::post().to(autoresponders::create_vacation))
        .route("/api/vacation", web::delete().to(autoresponders::delete_vacation))
        // Catch-all + local mail toggle
        .route("/api/catch-all", web::get().to(catchall::get_catch_all))
        .route("/api/catch-all", web::put().to(catchall::set_catch_all))
        .route("/api/local-mail", web::put().to(catchall::set_local_mail))
        // PHP version per domain
        .route("/api/php/versions", web::get().to(php::list_versions))
        .route("/api/php/domain", web::get().to(php::get_version))
        .route("/api/php/domain", web::put().to(php::set_version))
        // Domain pointers / aliases
        .route("/api/pointers", web::get().to(pointers::list))
        .route("/api/pointers", web::post().to(pointers::create))
        .route("/api/pointers", web::delete().to(pointers::delete))
        // HTTP redirects
        .route("/api/redirects", web::get().to(redirects::list))
        .route("/api/redirects", web::post().to(redirects::create))
        .route("/api/redirects", web::delete().to(redirects::delete))
        // Cron jobs
        .route("/api/cron", web::get().to(cron::list))
        .route("/api/cron", web::post().to(cron::create))
        .route("/api/cron/{id}", web::delete().to(cron::delete))
        // SSH keys
        .route("/api/ssh-keys", web::get().to(ssh_keys::list))
        .route("/api/ssh-keys", web::post().to(ssh_keys::add))
        .route("/api/ssh-keys/{id}", web::delete().to(ssh_keys::delete))
        // Mailing lists
        .route("/api/mailing-lists", web::get().to(mailing_lists::list))
        .route("/api/mailing-lists", web::post().to(mailing_lists::create))
        .route("/api/mailing-lists", web::delete().to(mailing_lists::delete))
        // Spam settings
        .route("/api/spam", web::get().to(spam::get))
        .route("/api/spam", web::put().to(spam::update))
        // Per-domain security toggles + 2FA status
        .route("/api/security/force-https", web::put().to(security::set_force_https))
        .route("/api/security/hsts", web::put().to(security::set_hsts))
        .route("/api/security/2fa-status", web::get().to(security::twofactor_status))
        // .htaccess directory protection
        .route("/api/protected-dirs", web::get().to(protected_dirs::list))
        .route("/api/protected-dirs", web::post().to(protected_dirs::protect))
        .route("/api/protected-dirs/users", web::post().to(protected_dirs::add_user))
        .route("/api/protected-dirs", web::delete().to(protected_dirs::unprotect))
        // Web/error/mail log tail
        .route("/api/logs", web::get().to(logs::tail))
        // Database users (separate from databases)
        .route("/api/db-users", web::get().to(db_users::list))
        .route("/api/db-users", web::post().to(db_users::create))
        .route("/api/db-users/password", web::post().to(db_users::change_password))
        .route("/api/db-users/{id}", web::delete().to(db_users::delete))
        // Password changes for DA-managed resources
        .route("/api/password/account", web::post().to(passwords::change_account))
        .route("/api/password/email", web::post().to(passwords::change_email))
        .route("/api/password/ftp", web::post().to(passwords::change_ftp))
        .route("/api/ftp/quota", web::put().to(passwords::set_ftp_quota))
        // DirectAdmin-side user backups (in addition to the LXC ones)
        .route("/api/da-backups", web::get().to(da_backups::list))
        .route("/api/da-backups/create", web::post().to(da_backups::create))
        .route("/api/da-backups/restore", web::post().to(da_backups::restore))
        .route("/api/da-backups", web::delete().to(da_backups::delete))
        // Config (public, no auth)
        .route("/api/config", web::get().to(get_portal_config));
}

async fn container_stats(req: actix_web::HttpRequest, state: web::Data<std::sync::Arc<crate::wolfhost::AppState>>) -> actix_web::HttpResponse {
    let customer_id = match auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return actix_web::HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    // Find customer's services to get container names
    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();

    // Get all container stats from WolfStack
    let stats = match crate::wolfhost::api::servers::wolfstack_get("/api/containers/lxc/stats").await  {
        Ok(data) => data,
        Err(_) => return actix_web::HttpResponse::Ok().json(serde_json::json!([])),
    };

    let stats_arr = stats.as_array().cloned().unwrap_or_default();

    // Match containers to services using the stored container_name field
    let mut result = Vec::new();
    for svc in &my_services {
        if svc.container_name.is_empty() { continue; }
        for st in &stats_arr {
            let name = st["name"].as_str().unwrap_or("");
            if name == svc.container_name {
                result.push(serde_json::json!({
                    "service_id": svc.id,
                    "domain": svc.domain,
                    "container": name,
                    "status": svc.status,
                    "cpu_percent": st["cpu_percent"],
                    "memory_usage": st["memory_usage"],
                    "memory_limit": st["memory_limit"],
                    "memory_percent": st["memory_percent"],
                    "net_input": st["net_input"],
                    "net_output": st["net_output"],
                    "pids": st["pids"],
                }));
            }
        }
    }

    actix_web::HttpResponse::Ok().json(result)
}

async fn dns_records(req: actix_web::HttpRequest, state: web::Data<std::sync::Arc<crate::wolfhost::AppState>>) -> actix_web::HttpResponse {
    use crate::wolfhost::models::service::ServiceBackend;

    let customer_id = match auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return actix_web::HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();

    // Collect all domains — from service.domain field, from domains store, and from DA
    let mut my_domains: Vec<String> = Vec::new();
    for svc in &my_services {
        // Add the service's primary domain if set
        if !svc.domain.is_empty() && !my_domains.contains(&svc.domain) {
            my_domains.push(svc.domain.clone());
        }

        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            // Get domains live from DA
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                if let Ok(domains) = da.list_domains(&svc.da_username).await {
                    for d in domains {
                        if !my_domains.contains(&d) {
                            my_domains.push(d);
                        }
                    }
                }
            }
        } else {
            // Get domains from local store
            let domains = state.domains.list().await;
            for d in domains.iter().filter(|d| d.service_id == svc.id && d.customer_id == customer_id) {
                if !my_domains.contains(&d.name) {
                    my_domains.push(d.name.clone());
                }
            }
        }
    }

    // Fetch DNS records — from DA for DA services, from PowerDNS for native
    let mut all_records = Vec::new();
    let mut da_domains: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Track which domains are DA-managed
    for svc in &my_services {
        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                if let Ok(domains) = da.list_domains(&svc.da_username).await {
                    for domain in &domains {
                        da_domains.insert(domain.clone());
                        if let Ok(records) = da.list_dns_records(domain).await {
                            for r in records {
                                if r.record_type == "SOA" || r.record_type == "NS" { continue; }
                                let full_name = if r.name.is_empty() || r.name == "@" {
                                    format!("{}.", domain)
                                } else {
                                    format!("{}.{}.", r.name, domain)
                                };
                                all_records.push(serde_json::json!({
                                    "domain": domain,
                                    "name": full_name,
                                    "type": r.record_type,
                                    "content": r.value,
                                    "ttl": r.ttl,
                                    "source": "directadmin",
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // For non-DA domains, use PowerDNS
    for domain in &my_domains {
        if da_domains.contains(domain) { continue; } // Already fetched from DA
        if let Ok(zone) = crate::wolfhost::provisioning::dns::get_zone_records(domain) {
            if let Some(rrsets) = zone["rrsets"].as_array() {
                for rr in rrsets {
                    let rtype = rr["type"].as_str().unwrap_or("");
                    if rtype == "SOA" || rtype == "NS" { continue; }
                    let records = rr["records"].as_array().cloned().unwrap_or_default();
                    for rec in &records {
                        all_records.push(serde_json::json!({
                            "domain": domain,
                            "name": rr["name"].as_str().unwrap_or(""),
                            "type": rtype,
                            "content": rec["content"].as_str().unwrap_or(""),
                            "ttl": rr["ttl"],
                            "source": "powerdns",
                        }));
                    }
                }
            }
        }
    }

    let branding = state.config.get_branding();
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "domains": my_domains,
        "records": all_records,
        "nameservers": [branding.ns1, branding.ns2],
    }))
}

async fn dns_set_record(req: actix_web::HttpRequest, state: web::Data<std::sync::Arc<crate::wolfhost::AppState>>, body: web::Json<serde_json::Value>) -> actix_web::HttpResponse {
    use crate::wolfhost::models::service::ServiceBackend;

    let customer_id = match auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return actix_web::HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let domain = body["domain"].as_str().unwrap_or("");
    let name = body["name"].as_str().unwrap_or("");
    let rtype = body["type"].as_str().unwrap_or("");
    let content = body["content"].as_str().unwrap_or("");
    let ttl = body["ttl"].as_u64().unwrap_or(3600) as u32;

    // Find the service that owns this domain and check if it's DA-backed
    let services = state.services.list().await;
    let da_service = services.iter().find(|s| {
        s.customer_id == customer_id && s.backend == ServiceBackend::DirectAdmin && !s.da_instance_id.is_empty()
    });

    if let Some(svc) = da_service {
        // Route through DirectAdmin DNS API
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
            let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
            // Strip the domain suffix from the name for DA (DA wants just the subdomain part)
            let short_name = name.trim_end_matches('.').trim_end_matches(domain).trim_end_matches('.');
            let short_name = if short_name.is_empty() { "@" } else { short_name };
            return match da.add_dns_record(domain, rtype, short_name, content, ttl).await {
                Ok(_) => actix_web::HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
                Err(e) => actix_web::HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            };
        }
    }

    // Native — verify ownership and use PowerDNS
    let owns_domain = services.iter().any(|s| s.customer_id == customer_id && s.domain == domain)
        || state.domains.list().await.iter().any(|d| d.customer_id == customer_id && d.name == domain);
    if !owns_domain {
        return actix_web::HttpResponse::Forbidden().json(serde_json::json!({"error": "Domain not found"}));
    }

    match crate::wolfhost::provisioning::dns::set_record(domain, name, rtype, content, ttl) {
        Ok(_) => actix_web::HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => actix_web::HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

async fn dns_delete_record(req: actix_web::HttpRequest, state: web::Data<std::sync::Arc<crate::wolfhost::AppState>>, body: web::Json<serde_json::Value>) -> actix_web::HttpResponse {
    use crate::wolfhost::models::service::ServiceBackend;

    let customer_id = match auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return actix_web::HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let domain = body["domain"].as_str().unwrap_or("");
    let name = body["name"].as_str().unwrap_or("");
    let rtype = body["type"].as_str().unwrap_or("");
    let content = body["content"].as_str().unwrap_or("");

    let services = state.services.list().await;
    let da_service = services.iter().find(|s| {
        s.customer_id == customer_id && s.backend == ServiceBackend::DirectAdmin && !s.da_instance_id.is_empty()
    });

    if let Some(svc) = da_service {
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
            let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
            let short_name = name.trim_end_matches('.').trim_end_matches(domain).trim_end_matches('.');
            let short_name = if short_name.is_empty() { "@" } else { short_name };
            return match da.delete_dns_record(domain, rtype, short_name, content).await {
                Ok(_) => actix_web::HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
                Err(e) => actix_web::HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            };
        }
    }

    // Native — verify ownership and use PowerDNS
    let owns_domain = services.iter().any(|s| s.customer_id == customer_id && s.domain == domain)
        || state.domains.list().await.iter().any(|d| d.customer_id == customer_id && d.name == domain);
    if !owns_domain {
        return actix_web::HttpResponse::Forbidden().json(serde_json::json!({"error": "Domain not found"}));
    }

    match crate::wolfhost::provisioning::dns::delete_record(domain, name, rtype) {
        Ok(_) => actix_web::HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => actix_web::HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

async fn get_portal_config(state: web::Data<std::sync::Arc<crate::wolfhost::AppState>>) -> actix_web::HttpResponse {
    let b = state.config.get_branding();
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "company_name": b.company_name,
        "tagline": b.tagline,
        "logo_url": b.logo_url,
        "favicon_emoji": b.favicon_emoji,
        "accent_color": b.accent_color,
        "accent_light": b.accent_light,
        "support_email": b.support_email,
        "support_url": b.support_url,
        "terms_url": b.terms_url,
        "footer_text": b.footer_text,
        "currency": b.currency,
        "custom_css": b.custom_css,
        "ns1": b.ns1,
        "ns2": b.ns2,
    }))
}
