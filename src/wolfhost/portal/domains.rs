use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::domain::{Domain, DomainStatus, DomainType, CreateDomainRequest, UpdateDomainRequest};
use crate::wolfhost::models::service::ServiceBackend;
use std::sync::Arc;

async fn container_exec(container: &str, command: &str, node_id: &str) -> Result<serde_json::Value, String> {
    // Try local first, then node proxy
    let local = format!("/api/containers/lxc/{}/exec", container);
    if let Ok(r) = crate::wolfhost::api::servers::wolfstack_post_pub(&local, &serde_json::json!({"command": command})).await {
        if r["ok"].as_bool() == Some(true) || r.get("exit_code").is_some() {
            return Ok(r);
        }
    }
    if !node_id.is_empty() {
        let remote = format!("/api/nodes/{}/proxy/containers/lxc/{}/exec", node_id, container);
        return crate::wolfhost::api::servers::wolfstack_post_pub(&remote, &serde_json::json!({"command": command})).await;
    }
    Err("Container not reachable".to_string())
}

pub async fn list(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    // Check if customer has any DA-backed services — fetch domains live from DA
    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();

    let mut all_domains = Vec::new();

    for svc in &my_services {
        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            // Fetch live from DirectAdmin
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                if let Ok(domains) = da.list_domains(&svc.da_username).await {
                    for name in domains {
                        all_domains.push(serde_json::json!({
                            "id": format!("da-{}-{}", svc.id, name),
                            "service_id": svc.id,
                            "customer_id": customer_id,
                            "name": name,
                            "domain_type": "primary",
                            "document_root": format!("/home/{}/domains/{}/public_html", svc.da_username, name),
                            "status": "active",
                            "created_at": svc.created_at,
                        }));
                    }
                }
            }
        } else {
            // Native — read from local store
            let domains = state.domains.list().await;
            for d in domains.into_iter().filter(|d| d.service_id == svc.id && d.customer_id == customer_id) {
                all_domains.push(serde_json::to_value(&d).unwrap_or_default());
            }
        }
    }

    HttpResponse::Ok().json(all_domains)
}

pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateDomainRequest>) -> HttpResponse {
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

    // DirectAdmin backend — create domain via DA API
    if service.backend == ServiceBackend::DirectAdmin && !service.da_instance_id.is_empty() {
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == service.da_instance_id) {
            let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);

            if let Err(e) = da.create_domain(&service.da_username, &r.name).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DirectAdmin: {}", e)}));
            }

            let now = chrono::Utc::now().to_rfc3339();
            let domain = Domain {
                id: uuid::Uuid::new_v4().to_string(),
                service_id: r.service_id.clone(),
                customer_id: customer_id.clone(),
                name: r.name.clone(),
                domain_type: r.domain_type.clone(),
                document_root: r.document_root.clone(),
                dns_records: Vec::new(),
                status: DomainStatus::Active,
                created_at: now,
            };

            let id = domain.id.clone();
            if let Err(e) = state.domains.update_with(|items| { items.push(domain); }).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
            }

            return HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "message": format!("Domain {} created via DirectAdmin.", r.name),
            }));
        }
    }

    let domain_name = r.name.clone();
    let doc_root = if r.document_root.is_empty() {
        match r.domain_type {
            DomainType::Subdomain => format!("/var/www/{}", domain_name),
            _ => "/var/www/html".to_string(),
        }
    } else {
        r.document_root.clone()
    };

    let now = chrono::Utc::now().to_rfc3339();
    let domain = Domain {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id.clone(),
        customer_id: customer_id.clone(),
        name: domain_name.clone(),
        domain_type: r.domain_type.clone(),
        document_root: doc_root.clone(),
        dns_records: Vec::new(),
        status: DomainStatus::Active,
        created_at: now,
    };

    let id = domain.id.clone();
    if let Err(e) = state.domains.update_with(|items| { items.push(domain); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    // Provision the domain in the background
    let container = service.container_name.clone();
    let node_id = service.server_node.clone();
    let container_ip = service.container_ip.clone();
    let host_ip = service.host_ip.clone();
    let branding = state.config.get_branding();
    let ns1 = branding.ns1.clone();
    let ns2 = branding.ns2.clone();

    if !container.is_empty() {
        let dn = domain_name.clone();
        let dr = doc_root.clone();
        let dt = r.domain_type.clone();

        tokio::spawn(async move {
            log::info!("Provisioning domain {} on container {}", dn, container);

            // Create document root and Apache vhost inside the container
            let vhost_cmd = match dt {
                DomainType::Subdomain => format!(
                    r#"mkdir -p {dr} && chown www-data:www-data {dr} && \
                    cat > /etc/apache2/sites-available/{dn}.conf << 'EOF'
<VirtualHost *:80>
    ServerName {dn}
    DocumentRoot {dr}
    <Directory {dr}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
if [ -d /etc/apache2/sites-enabled ]; then
    ln -sf /etc/apache2/sites-available/{dn}.conf /etc/apache2/sites-enabled/{dn}.conf
    systemctl reload apache2 2>/dev/null
elif [ -d /etc/httpd/conf.d ]; then
    cp /etc/apache2/sites-available/{dn}.conf /etc/httpd/conf.d/{dn}.conf 2>/dev/null
    systemctl reload httpd 2>/dev/null
fi
echo DONE"#, dn = dn, dr = dr),
                _ => format!(
                    r#"cat > /etc/apache2/sites-available/{dn}.conf << 'EOF'
<VirtualHost *:80>
    ServerName {dn}
    ServerAlias www.{dn}
    DocumentRoot {dr}
    <Directory {dr}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
if [ -d /etc/apache2/sites-enabled ]; then
    ln -sf /etc/apache2/sites-available/{dn}.conf /etc/apache2/sites-enabled/{dn}.conf
    systemctl reload apache2 2>/dev/null
elif [ -d /etc/httpd/conf.d ]; then
    cp /etc/apache2/sites-available/{dn}.conf /etc/httpd/conf.d/{dn}.conf 2>/dev/null
    systemctl reload httpd 2>/dev/null
fi
echo DONE"#, dn = dn, dr = dr),
            };

            container_exec(&container, &vhost_cmd, &node_id).await.ok();

            // Create default index if document root is new
            if dr != "/var/www/html" {
                let index_cmd = format!(
                    r#"if [ ! -f {dr}/index.html ]; then
                        echo '<html><body><h1>{dn}</h1><p>Website ready.</p></body></html>' > {dr}/index.html
                        chown www-data:www-data {dr}/index.html
                    fi"#, dr = dr, dn = dn
                );
                container_exec(&container, &index_cmd, &node_id).await.ok();
            }

            // Create nginx reverse proxy on the host for this domain
            if !container_ip.is_empty() {
                crate::wolfhost::provisioning::container::setup_host_reverse_proxy(&dn, &container_ip).ok();
                log::info!("Reverse proxy created for {} -> {}", dn, container_ip);
            }

            // Create DNS zone if PowerDNS is running
            if !ns1.is_empty() && !host_ip.is_empty() {
                crate::wolfhost::provisioning::dns::create_zone(&dn, &host_ip, &ns1, &ns2).ok();
                log::info!("DNS zone created for {}", dn);
            }

            log::info!("Domain {} provisioned", dn);
        });
    }

    HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": format!("Domain {} added. Apache vhost, reverse proxy, and DNS zone are being configured.", domain_name),
    }))
}

pub async fn update(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateDomainRequest>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();
    let r = body.into_inner();

    let result = state.domains.update_with(|items| {
        if let Some(d) = items.iter_mut().find(|d| d.id == id && d.customer_id == customer_id) {
            if let Some(v) = r.document_root { d.document_root = v; }
            if let Some(v) = r.dns_records { d.dns_records = v; }
            if let Some(v) = r.status { d.status = v; }
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

    // Find the domain to clean up its resources
    let domains = state.domains.list().await;
    if let Some(dom) = domains.iter().find(|d| d.id == id && d.customer_id == customer_id) {
        let domain_name = dom.name.clone();
        let service_id = dom.service_id.clone();

        let services = state.services.list().await;
        if let Some(svc) = services.iter().find(|s| s.id == service_id) {
            // DirectAdmin backend — delete domain via DA API
            if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
                let instances = state.da_instances.list().await;
                if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                    let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                    let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                    if let Err(e) = da.delete_domain(&svc.da_username, &domain_name).await {
                        log::error!("DA delete domain failed: {}", e);
                    }
                }
            } else {
                let container = svc.container_name.clone();
                let node_id = svc.server_node.clone();
                let container_ip = svc.container_ip.clone();

                tokio::spawn(async move {
                    // Remove Apache vhost from container
                    if !container.is_empty() {
                        let rm_cmd = format!(
                            "rm -f /etc/apache2/sites-enabled/{dn}.conf /etc/apache2/sites-available/{dn}.conf /etc/httpd/conf.d/{dn}.conf 2>/dev/null; \
                             systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null",
                            dn = domain_name
                        );
                        container_exec(&container, &rm_cmd, &node_id).await.ok();
                    }

                    // Remove nginx reverse proxy on host
                    crate::wolfhost::provisioning::container::teardown_proxy(&domain_name, &container_ip).ok();

                    // Remove DNS zone
                    crate::wolfhost::provisioning::dns::delete_zone(&domain_name).ok();

                    log::info!("Domain {} removed", domain_name);
                });
            }
        }
    }

    let result = state.domains.update_with(|items| {
        items.retain(|d| !(d.id == id && d.customer_id == customer_id));
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
