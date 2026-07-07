use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::models::database::{CustomerDatabase, DatabaseStatus, DatabaseType, CreateDatabaseRequest};
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

/// Exec a command inside a container via WolfStack API — tries local first, then node proxy
async fn container_exec(container: &str, command: &str, node_id: &str) -> Result<serde_json::Value, String> {
    // Try local first
    let local = format!("/api/containers/lxc/{}/exec", container);
    if let Ok(r) = crate::wolfhost::api::servers::wolfstack_post_pub(&local, &serde_json::json!({"command": command})).await {
        if r["ok"].as_bool() == Some(true) || r.get("exit_code").is_some() {
            return Ok(r);
        }
    }
    // Fall back to node proxy
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

    let services = state.services.list().await;
    let my_services: Vec<_> = services.iter().filter(|s| s.customer_id == customer_id).collect();
    let mut mine: Vec<serde_json::Value> = Vec::new();

    for svc in &my_services {
        if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
            let instances = state.da_instances.list().await;
            if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass);
                if let Ok(dbs) = da.list_databases(&svc.da_username).await {
                    for d in dbs {
                        mine.push(serde_json::json!({
                            "id": format!("da-{}-{}", svc.id, d.name),
                            "service_id": svc.id,
                            "name": d.name,
                            "db_type": "mariadb",
                            "username": d.user,
                            "size_mb": 0,
                            "status": "active",
                            "created_at": svc.created_at,
                        }));
                    }
                }
            }
        } else {
            let dbs = state.databases.list().await;
            for d in dbs.iter().filter(|d| d.service_id == svc.id && d.customer_id == customer_id) {
                mine.push(serde_json::json!({
                    "id": d.id,
                    "service_id": d.service_id,
                    "name": d.name,
                    "db_type": d.db_type,
                    "username": d.username,
                    "size_mb": d.size_mb,
                    "status": d.status,
                    "created_at": d.created_at,
                }));
            }
        }
    }
    HttpResponse::Ok().json(mine)
}

pub async fn create(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<CreateDatabaseRequest>) -> HttpResponse {
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

    // DirectAdmin backend — create database via DA API
    if service.backend == ServiceBackend::DirectAdmin && !service.da_instance_id.is_empty() {
        let instances = state.da_instances.list().await;
        if let Some(da_inst) = instances.iter().find(|i| i.id == service.da_instance_id) {
            let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
            let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);

            if let Err(e) = da.create_database(&service.da_username, &r.name, &r.username, &r.password).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DirectAdmin: {}", e)}));
            }

            let pw_hash = match hash_password(&r.password) {
                Ok(h) => h,
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            };

            let db = CustomerDatabase {
                id: uuid::Uuid::new_v4().to_string(),
                service_id: r.service_id,
                customer_id,
                name: r.name,
                db_type: r.db_type,
                username: r.username,
                password_hash: pw_hash,
                size_mb: 0,
                status: DatabaseStatus::Active,
                created_at: chrono::Utc::now().to_rfc3339(),
            };

            let id = db.id.clone();
            if let Err(e) = state.databases.update_with(|items| { items.push(db); }).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
            }

            return HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "message": "Database created via DirectAdmin.",
            }));
        }
    }

    if service.container_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No container provisioned for this service"}));
    }

    let container = service.container_name.clone();
    let node_id = service.server_node.clone();

    let db_name = r.name.clone();
    let db_user = r.username.clone();
    let db_pass = r.password.clone();
    let db_type = r.db_type.clone();

    let bg_container = container.clone();
    let bg_node = node_id.clone();
    let bg_name = db_name.clone();
    let bg_user = db_user.clone();
    let bg_pass = db_pass.clone();
    let bg_type = db_type.clone();

    tokio::spawn(async move {
        log::info!("[{}] Creating database '{}' (type: {:?})", bg_container, bg_name, bg_type);

        // Install database server if not already installed (distro-agnostic, always favour MariaDB)
        let install_cmd = match bg_type {
            DatabaseType::MariaDB | DatabaseType::MySQL => r#"
                if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then echo "ALREADY_INSTALLED"; else
                    if command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq mariadb-server mariadb-client 2>&1
                    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q mariadb-server mariadb 2>&1
                    elif command -v yum >/dev/null 2>&1; then yum install -y -q mariadb-server mariadb 2>&1
                    elif command -v apk >/dev/null 2>&1; then apk add --no-cache mariadb mariadb-client mariadb-server-utils 2>&1 && /etc/init.d/mariadb setup 2>/dev/null
                    elif command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm mariadb 2>&1 && mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql 2>/dev/null
                    fi
                fi
                if command -v systemctl >/dev/null 2>&1; then systemctl enable mariadb 2>/dev/null; systemctl start mariadb 2>/dev/null
                elif command -v rc-update >/dev/null 2>&1; then rc-update add mariadb 2>/dev/null; rc-service mariadb start 2>/dev/null
                fi
                echo DONE
            "#.to_string(),
            DatabaseType::PostgreSQL => r#"
                if command -v psql >/dev/null 2>&1; then echo "ALREADY_INSTALLED"; else
                    if command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq postgresql 2>&1
                    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q postgresql-server postgresql 2>&1 && postgresql-setup --initdb 2>/dev/null
                    elif command -v yum >/dev/null 2>&1; then yum install -y -q postgresql-server postgresql 2>&1 && postgresql-setup initdb 2>/dev/null
                    elif command -v apk >/dev/null 2>&1; then apk add --no-cache postgresql 2>&1 && /etc/init.d/postgresql setup 2>/dev/null
                    elif command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm postgresql 2>&1 && su - postgres -c 'initdb -D /var/lib/postgres/data' 2>/dev/null
                    fi
                fi
                if command -v systemctl >/dev/null 2>&1; then systemctl enable postgresql 2>/dev/null; systemctl start postgresql 2>/dev/null
                elif command -v rc-update >/dev/null 2>&1; then rc-update add postgresql 2>/dev/null; rc-service postgresql start 2>/dev/null
                fi
                echo DONE
            "#.to_string(),
        };

        match container_exec(&bg_container, &install_cmd, &bg_node).await {
            Ok(r) => {
                let out = r["stdout"].as_str().unwrap_or("");
                if out.contains("DONE") {
                    log::info!("[{}] Database server ready", bg_container);
                } else {
                    log::error!("[{}] Database server install issue: {}", bg_container, out);
                }
            }
            Err(e) => log::error!("[{}] Failed to install DB server: {}", bg_container, e),
        }

        // Sanitize DB name, user, and password for shell safety
        let safe_name = bg_name.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect::<String>();
        let safe_user = bg_user.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect::<String>();
        let safe_pass = bg_pass.replace('\\', "\\\\").replace('\'', "\\'").replace('"', "\\\"").replace('`', "\\`").replace('$', "\\$");

        // Create the database and user
        let create_cmd = match bg_type {
            DatabaseType::MariaDB | DatabaseType::MySQL => format!(
                "mysql -e \"CREATE DATABASE IF NOT EXISTS \\`{name}\\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pass}'; GRANT ALL PRIVILEGES ON \\`{name}\\`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;\" 2>&1 && echo DBCREATED",
                name = safe_name, user = safe_user, pass = safe_pass,
            ),
            DatabaseType::PostgreSQL => format!(
                "su - postgres -c \"psql -c \\\"CREATE USER {user} WITH PASSWORD '{pass}';\\\" 2>/dev/null; psql -c \\\"CREATE DATABASE {name} OWNER {user};\\\" 2>/dev/null\" && echo DBCREATED",
                name = safe_name, user = safe_user, pass = safe_pass,
            ),
        };

        match container_exec(&bg_container, &create_cmd, &bg_node).await {
            Ok(r) => {
                let out = r["stdout"].as_str().unwrap_or("");
                if out.contains("DBCREATED") {
                    log::info!("[{}] Database '{}' created with user '{}'", bg_container, bg_name, bg_user);
                } else {
                    log::error!("[{}] Database creation issue: {} {}", bg_container, out, r["stderr"].as_str().unwrap_or(""));
                }
            }
            Err(e) => log::error!("[{}] Failed to create database: {}", bg_container, e),
        }
    });

    // Save the record
    let pw_hash = match hash_password(&r.password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let db = CustomerDatabase {
        id: uuid::Uuid::new_v4().to_string(),
        service_id: r.service_id,
        customer_id,
        name: db_name,
        db_type,
        username: db_user,
        password_hash: pw_hash,
        size_mb: 0,
        status: DatabaseStatus::Active,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let id = db.id.clone();
    if let Err(e) = state.databases.update_with(|items| { items.push(db); }).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Database is being created. MariaDB will be installed if not already present.",
    }))
}

pub async fn delete(req: HttpRequest, state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let customer_id = match super::auth::get_customer_id(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Not authenticated"})),
    };

    let id = path.into_inner();

    // Find the DB to drop it inside the container
    let dbs = state.databases.list().await;
    if let Some(db) = dbs.iter().find(|d| d.id == id && d.customer_id == customer_id) {
        let services = state.services.list().await;
        if let Some(svc) = services.iter().find(|s| s.id == db.service_id) {
            // DirectAdmin backend — delete database via DA API
            if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
                let instances = state.da_instances.list().await;
                if let Some(da_inst) = instances.iter().find(|i| i.id == svc.da_instance_id) {
                    let da_pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
                    let da = crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &da_pass);
                    if let Err(e) = da.delete_database(&svc.da_username, &db.name).await {
                        log::error!("DA delete database failed: {}", e);
                    }
                }
            } else if !svc.container_name.is_empty() {
                let container = svc.container_name.clone();
                let node_id = svc.server_node.clone();
                let db_name = db.name.clone();
                let db_user = db.username.clone();
                let db_type = db.db_type.clone();

                tokio::spawn(async move {
                    let drop_cmd = match db_type {
                        DatabaseType::MariaDB | DatabaseType::MySQL => format!(
                            "mysql -e \"DROP DATABASE IF EXISTS \\`{}\\`; DROP USER IF EXISTS '{}'@'localhost'; FLUSH PRIVILEGES;\" 2>&1",
                            db_name, db_user
                        ),
                        DatabaseType::PostgreSQL => format!(
                            "su - postgres -c \"psql -c \\\"DROP DATABASE IF EXISTS {};\\\" && psql -c \\\"DROP USER IF EXISTS {};\\\"\" 2>&1",
                            db_name, db_user
                        ),
                    };
                    container_exec(&container, &drop_cmd, &node_id).await.ok();
                    log::info!("[{}] Database '{}' dropped", container, db_name);
                });
            }
        }
    }

    let result = state.databases.update_with(|items| {
        items.retain(|d| !(d.id == id && d.customer_id == customer_id));
    }).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}
