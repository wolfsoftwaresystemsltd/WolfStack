use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::directadmin::{DirectAdminInstance, DirectAdminStatus, CreateDirectAdminRequest, UpdateDirectAdminRequest};
use crate::wolfhost::models::service::ServiceBackend;
use crate::wolfhost::provisioning::directadmin::{DaClient, obfuscate_password, deobfuscate_password};
use std::sync::Arc;

pub async fn list(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let instances = state.da_instances.list().await;
    // Mask passwords in response
    let safe: Vec<serde_json::Value> = instances.iter().map(|i| {
        serde_json::json!({
            "id": i.id,
            "name": i.name,
            "url": i.url,
            "admin_user": i.admin_user,
            "node_id": i.node_id,
            "status": i.status,
            "last_sync": i.last_sync,
            "user_count": i.user_count,
            "domain_count": i.domain_count,
            "created_at": i.created_at,
        })
    }).collect();
    HttpResponse::Ok().json(safe)
}

pub async fn create(state: web::Data<Arc<AppState>>, body: web::Json<CreateDirectAdminRequest>) -> HttpResponse {
    let req = body.into_inner();

    // Test connection first
    let da = DaClient::new(&req.url, &req.admin_user, &req.admin_password);
    let test_result = da.test_connection().await;
    let (status, user_count) = match &test_result {
        Ok(msg) => {
            let count = msg.split_whitespace()
                .find_map(|w| w.parse::<u32>().ok())
                .unwrap_or(0);
            (DirectAdminStatus::Online, count)
        }
        Err(_) => (DirectAdminStatus::Error, 0),
    };

    let enc_pass = obfuscate_password(&req.admin_password);

    let instance = DirectAdminInstance {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        url: req.url,
        admin_user: req.admin_user,
        admin_password_enc: enc_pass,
        node_id: req.node_id,
        status,
        last_sync: String::new(),
        user_count,
        domain_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let id = instance.id.clone();
    if let Err(e) = state.da_instances.update_with(|items| { items.push(instance); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    match test_result {
        Ok(msg) => HttpResponse::Created().json(serde_json::json!({"id": id, "status": "online", "message": msg})),
        Err(e) => HttpResponse::Created().json(serde_json::json!({"id": id, "status": "error", "message": e})),
    }
}

pub async fn get(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let instances = state.da_instances.list().await;
    match instances.iter().find(|i| i.id == id) {
        Some(i) => HttpResponse::Ok().json(serde_json::json!({
            "id": i.id,
            "name": i.name,
            "url": i.url,
            "admin_user": i.admin_user,
            "node_id": i.node_id,
            "status": i.status,
            "last_sync": i.last_sync,
            "user_count": i.user_count,
            "domain_count": i.domain_count,
            "created_at": i.created_at,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "DirectAdmin instance not found"})),
    }
}

pub async fn update(state: web::Data<Arc<AppState>>, path: web::Path<String>, body: web::Json<UpdateDirectAdminRequest>) -> HttpResponse {
    let id = path.into_inner();
    let req = body.into_inner();

    let result = state.da_instances.update_with(|items| {
        if let Some(i) = items.iter_mut().find(|i| i.id == id) {
            if let Some(v) = req.name { i.name = v; }
            if let Some(v) = req.url { i.url = v; }
            if let Some(v) = req.admin_user { i.admin_user = v; }
            if let Some(v) = req.admin_password {
                i.admin_password_enc = obfuscate_password(&v);
            }
            if let Some(v) = req.node_id { i.node_id = v; }
        }
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn delete(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();

    // Flip any services using this DA instance back to native
    let _ = state.services.update_with(|items| {
        for s in items.iter_mut() {
            if s.da_instance_id == id {
                s.backend = ServiceBackend::Native;
                s.da_instance_id.clear();
                s.da_username.clear();
            }
        }
    }).await;

    let result = state.da_instances.update_with(|items| {
        items.retain(|i| i.id != id);
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

pub async fn test_connection(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "DirectAdmin instance not found"})),
    };

    let pass = deobfuscate_password(&inst.admin_password_enc);
    let da = DaClient::new(&inst.url, &inst.admin_user, &pass);

    match da.test_connection().await {
        Ok(msg) => {
            // Update status to online
            let _ = state.da_instances.update_with(|items| {
                if let Some(i) = items.iter_mut().find(|i| i.id == id) {
                    i.status = DirectAdminStatus::Online;
                }
            }).await;
            HttpResponse::Ok().json(serde_json::json!({"status": "online", "message": msg}))
        }
        Err(e) => {
            let _ = state.da_instances.update_with(|items| {
                if let Some(i) = items.iter_mut().find(|i| i.id == id) {
                    i.status = DirectAdminStatus::Error;
                }
            }).await;
            HttpResponse::Ok().json(serde_json::json!({"status": "error", "message": e}))
        }
    }
}

/// POST /directadmin/detect — probe a host:port to see if DirectAdmin is running
/// Body: {"url": "https://10.0.0.5:2222", "admin_user": "admin", "admin_password": "pass"}
/// Returns: {"detected": true/false, "user_count": 5, "version": "..."} or error
pub async fn detect(body: web::Json<CreateDirectAdminRequest>, _state: web::Data<Arc<AppState>>) -> HttpResponse {
    let req = body.into_inner();
    let da = DaClient::new(&req.url, &req.admin_user, &req.admin_password);

    match da.test_connection().await {
        Ok(msg) => {
            // Connection succeeded — get user count
            let user_count = da.list_users().await.map(|u| u.len() as u32).unwrap_or(0);
            HttpResponse::Ok().json(serde_json::json!({
                "detected": true,
                "user_count": user_count,
                "message": msg,
            }))
        }
        Err(e) => {
            HttpResponse::Ok().json(serde_json::json!({
                "detected": false,
                "user_count": 0,
                "error": e,
            }))
        }
    }
}

pub async fn scan(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "DirectAdmin instance not found"})),
    };

    let pass = deobfuscate_password(&inst.admin_password_enc);
    let da = DaClient::new(&inst.url, &inst.admin_user, &pass);

    let users = match da.list_users().await {
        Ok(u) => u,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let mut user_summaries = Vec::new();
    for username in &users {
        let config = da.get_user_config(username).await.ok();
        let domains = da.list_domains(username).await.unwrap_or_default();

        let mut email_list = Vec::new();
        for domain in &domains {
            if let Ok(emails) = da.list_email_accounts(domain).await {
                for e in emails {
                    email_list.push(serde_json::json!({
                        "user": e.user,
                        "domain": e.domain,
                        "quota_mb": e.quota_mb,
                    }));
                }
            }
        }

        let databases = da.list_databases(username).await.unwrap_or_default();
        let db_list: Vec<serde_json::Value> = databases.iter().map(|d| {
            serde_json::json!({"name": d.name, "user": d.user})
        }).collect();

        user_summaries.push(serde_json::json!({
            "username": username,
            "domain": config.as_ref().map(|c| c.domain.as_str()).unwrap_or(""),
            "email": config.as_ref().map(|c| c.email.as_str()).unwrap_or(""),
            "suspended": config.as_ref().map(|c| c.suspended).unwrap_or(false),
            "domains": domains,
            "emails": email_list,
            "databases": db_list,
        }));
    }

    // Update instance stats
    let total_domains: usize = user_summaries.iter()
        .filter_map(|u| u["domains"].as_array())
        .map(|a| a.len())
        .sum();
    let user_count = users.len() as u32;
    let domain_count = total_domains as u32;

    let _ = state.da_instances.update_with(move |items| {
        if let Some(i) = items.iter_mut().find(|i| i.id == id) {
            i.user_count = user_count;
            i.domain_count = domain_count;
            i.last_sync = chrono::Utc::now().to_rfc3339();
            i.status = DirectAdminStatus::Online;
        }
    }).await;

    HttpResponse::Ok().json(serde_json::json!({
        "instance": inst.name,
        "users": user_summaries,
    }))
}

pub async fn import(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let instances = state.da_instances.list().await;
    let inst = match instances.iter().find(|i| i.id == id) {
        Some(i) => i.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "DirectAdmin instance not found"})),
    };

    let pass = deobfuscate_password(&inst.admin_password_enc);
    let da = DaClient::new(&inst.url, &inst.admin_user, &pass);

    let users = match da.list_users().await {
        Ok(u) => u,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let mut imported_customers = 0u32;
    let mut imported_services = 0u32;
    let mut imported_domains = 0u32;
    let mut imported_emails = 0u32;
    let mut imported_databases = 0u32;

    for username in &users {
        let config = match da.get_user_config(username).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Create Customer
        let customer_id = uuid::Uuid::new_v4().to_string();
        let customer_email = if config.email.is_empty() {
            format!("{}@{}", username, config.domain)
        } else {
            config.email.clone()
        };

        let customer = crate::wolfhost::models::customer::Customer {
            id: customer_id.clone(),
            email: customer_email,
            password_hash: String::new(), // DA manages auth
            first_name: username.clone(),
            last_name: String::new(),
            company: String::new(),
            phone: String::new(),
            address: crate::wolfhost::models::customer::Address::default(),
            status: if config.suspended {
                crate::wolfhost::models::customer::CustomerStatus::Suspended
            } else {
                crate::wolfhost::models::customer::CustomerStatus::Active
            },
            totp_secret: String::new(),
            totp_enabled: false,
            notes: format!("Imported from DirectAdmin instance '{}'", inst.name),
            created_at: now.clone(),
            updated_at: now.clone(),
        };

        let _ = state.customers.update_with(|items| { items.push(customer); }).await;
        imported_customers += 1;

        // Create HostingService
        let service_id = uuid::Uuid::new_v4().to_string();
        let service = crate::wolfhost::models::service::HostingService {
            id: service_id.clone(),
            customer_id: customer_id.clone(),
            plan_id: String::new(),
            domain: config.domain.clone(),
            status: if config.suspended {
                crate::wolfhost::models::service::ServiceStatus::Suspended
            } else {
                crate::wolfhost::models::service::ServiceStatus::Active
            },
            billing_cycle: crate::wolfhost::models::service::BillingCycle::Monthly,
            next_billing: String::new(),
            server_node: inst.node_id.clone(),
            home_dir: String::new(),
            container_name: String::new(),
            container_ip: String::new(),
            host_ip: String::new(),
            host_hostname: String::new(),
            ftp_port: 0,
            usage: crate::wolfhost::models::service::ServiceUsage::default(),
            backend: ServiceBackend::DirectAdmin,
            da_instance_id: inst.id.clone(),
            da_username: username.clone(),
            created_at: now.clone(),
            expires_at: String::new(),
        };

        let _ = state.services.update_with(|items| { items.push(service); }).await;
        imported_services += 1;

        // Import domains
        let domains = da.list_domains(username).await.unwrap_or_default();
        for domain_name in &domains {
            let domain = crate::wolfhost::models::domain::Domain {
                id: uuid::Uuid::new_v4().to_string(),
                service_id: service_id.clone(),
                customer_id: customer_id.clone(),
                name: domain_name.clone(),
                domain_type: if *domain_name == config.domain {
                    crate::wolfhost::models::domain::DomainType::Primary
                } else {
                    crate::wolfhost::models::domain::DomainType::Addon
                },
                document_root: String::new(),
                dns_records: Vec::new(),
                status: crate::wolfhost::models::domain::DomainStatus::Active,
                created_at: now.clone(),
            };
            let _ = state.domains.update_with(|items| { items.push(domain); }).await;
            imported_domains += 1;

            // Import email accounts for this domain
            if let Ok(emails) = da.list_email_accounts(domain_name).await {
                for e in emails {
                    let account = crate::wolfhost::models::email::EmailAccount {
                        id: uuid::Uuid::new_v4().to_string(),
                        service_id: service_id.clone(),
                        customer_id: customer_id.clone(),
                        address: format!("{}@{}", e.user, e.domain),
                        password_hash: String::new(), // DA manages auth
                        quota_mb: e.quota_mb,
                        forwarding: Vec::new(),
                        status: crate::wolfhost::models::email::EmailStatus::Active,
                        created_at: now.clone(),
                    };
                    let _ = state.email_accounts.update_with(|items| { items.push(account); }).await;
                    imported_emails += 1;
                }
            }
        }

        // Import databases
        if let Ok(dbs) = da.list_databases(username).await {
            for db in dbs {
                let database = crate::wolfhost::models::database::CustomerDatabase {
                    id: uuid::Uuid::new_v4().to_string(),
                    service_id: service_id.clone(),
                    customer_id: customer_id.clone(),
                    name: db.name,
                    db_type: crate::wolfhost::models::database::DatabaseType::MariaDB,
                    username: db.user,
                    password_hash: String::new(), // DA manages auth
                    size_mb: 0,
                    status: crate::wolfhost::models::database::DatabaseStatus::Active,
                    created_at: now.clone(),
                };
                let _ = state.databases.update_with(|items| { items.push(database); }).await;
                imported_databases += 1;
            }
        }
    }

    // Update instance stats
    let inst_id = inst.id.clone();
    let user_count = users.len() as u32;
    let domain_count = imported_domains;
    let _ = state.da_instances.update_with(move |items| {
        if let Some(i) = items.iter_mut().find(|i| i.id == inst_id) {
            i.user_count = user_count;
            i.domain_count = domain_count;
            i.last_sync = chrono::Utc::now().to_rfc3339();
            i.status = DirectAdminStatus::Online;
        }
    }).await;

    HttpResponse::Ok().json(serde_json::json!({
        "status": "imported",
        "customers": imported_customers,
        "services": imported_services,
        "domains": imported_domains,
        "emails": imported_emails,
        "databases": imported_databases,
    }))
}
