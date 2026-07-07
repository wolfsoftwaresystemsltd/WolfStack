use actix_web::{web, HttpRequest, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::sync::Arc;

/// All file operations are proxied through WolfStack's LXC file API
/// which handles both local and remote containers across the cluster.

fn get_cluster_secret() -> String {
    crate::wolfhost::api::servers::get_cluster_secret()
}

async fn ws_get(path: &str) -> Result<serde_json::Value, String> {
    crate::wolfhost::api::servers::wolfstack_get(path).await
}

async fn ws_post(path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = crate::wolfhost::api::servers::wolfstack_client();
    let secret = get_cluster_secret();
    for url in crate::wolfhost::api::servers::wolfstack_urls(path) {
        match client.post(&url)
            .header("X-WolfStack-Secret", &secret)
            .json(body)
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                return resp.json().await.map_err(|e| format!("WS parse failed: {}", e));
            }
            _ => continue,
        }
    }
    Err(format!("WS POST failed: {}", path))
}

async fn ws_get_bytes(path: &str) -> Result<Vec<u8>, String> {
    let client = crate::wolfhost::api::servers::wolfstack_client();
    let secret = get_cluster_secret();
    for url in crate::wolfhost::api::servers::wolfstack_urls(path) {
        match client.get(&url)
            .header("X-WolfStack-Secret", &secret)
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                return resp.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("WS read failed: {}", e));
            }
            _ => continue,
        }
    }
    Err(format!("WS GET bytes failed: {}", path))
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub service_id: String,
    #[serde(default)]
    pub path: String,
}

#[derive(Deserialize)]
pub struct WriteRequest {
    pub service_id: String,
    pub path: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct PathRequest {
    pub service_id: String,
    pub path: String,
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub service_id: String,
    pub from: String,
    pub to: String,
}

use crate::wolfhost::models::service::ServiceBackend;

enum FileBackend {
    Container(String), // container name
    DirectAdmin(crate::wolfhost::provisioning::directadmin::DaClient),
}

async fn get_file_backend(req: &HttpRequest, state: &AppState, service_id: &str) -> Option<FileBackend> {
    let customer_id = super::auth::get_customer_id(req, state).await?;
    let services = state.services.list().await;
    let svc = services.iter().find(|s| s.id == service_id && s.customer_id == customer_id)?;

    if svc.backend == ServiceBackend::DirectAdmin && !svc.da_instance_id.is_empty() {
        let instances = state.da_instances.list().await;
        let da_inst = instances.iter().find(|i| i.id == svc.da_instance_id)?;
        let pass = crate::wolfhost::provisioning::directadmin::deobfuscate_password(&da_inst.admin_password_enc);
        Some(FileBackend::DirectAdmin(crate::wolfhost::provisioning::directadmin::DaClient::new(&da_inst.url, &da_inst.admin_user, &pass)))
    } else {
        if svc.container_name.is_empty() { return None; }
        Some(FileBackend::Container(svc.container_name.clone()))
    }
}

fn default_path(path: &str) -> String {
    if path.is_empty() || path == "." { "/".to_string() }
    else { path.to_string() }
}

/// GET /files/list — browse directory via WolfStack API or DirectAdmin
pub async fn list_files(req: HttpRequest, state: web::Data<Arc<AppState>>, query: web::Query<FileQuery>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &query.service_id).await {
        Some(b) => b,
        None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Service not found or no container"})),
    };

    let path = default_path(&query.path);

    match backend {
        FileBackend::DirectAdmin(da) => {
            match da.list_files(&path).await {
                Ok(entries) => {
                    let files: Vec<serde_json::Value> = entries.iter().map(|e| {
                        serde_json::json!({
                            "name": e.name,
                            "path": e.path,
                            "is_dir": e.is_dir,
                            "size": e.size,
                        })
                    }).collect();
                    HttpResponse::Ok().json(serde_json::json!({
                        "path": path,
                        "container": "directadmin",
                        "files": files,
                    }))
                }
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
        FileBackend::Container(container) => {
            let url = format!("/api/files/lxc/browse?container={}&path={}",
                urlencoding::encode(&container), urlencoding::encode(&path));
            match ws_get(&url).await {
                Ok(data) => {
                    let entries = data["entries"].as_array().cloned().unwrap_or_default();
                    let files: Vec<serde_json::Value> = entries.iter().map(|e| {
                        serde_json::json!({
                            "name": e["name"],
                            "path": e["path"],
                            "is_dir": e["is_dir"],
                            "size": e["size"],
                        })
                    }).collect();
                    HttpResponse::Ok().json(serde_json::json!({
                        "path": path,
                        "container": container,
                        "files": files,
                    }))
                }
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}

/// GET /files/read — read file
pub async fn read_file(req: HttpRequest, state: web::Data<Arc<AppState>>, query: web::Query<FileQuery>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &query.service_id).await {
        Some(b) => b, None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
    };
    let path = default_path(&query.path);
    match backend {
        FileBackend::DirectAdmin(da) => match da.read_file(&path).await {
            Ok(content) => HttpResponse::Ok().json(serde_json::json!({"content": content, "path": path})),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        },
        FileBackend::Container(container) => {
            let url = format!("/api/files/lxc/read?container={}&path={}", urlencoding::encode(&container), urlencoding::encode(&path));
            match ws_get(&url).await { Ok(data) => HttpResponse::Ok().json(data), Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})) }
        }
    }
}

/// POST /files/save — write file
pub async fn upload(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<WriteRequest>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &body.service_id).await {
        Some(b) => b, None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
    };
    let path = default_path(&body.path);
    match backend {
        FileBackend::DirectAdmin(da) => match da.write_file(&path, &body.content).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "saved"})),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        },
        FileBackend::Container(container) => {
            match ws_post("/api/files/lxc/write", &serde_json::json!({"container": container, "path": path, "content": body.content})).await {
                Ok(data) => HttpResponse::Ok().json(data), Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}

/// GET /files/download — download file
pub async fn download(req: HttpRequest, state: web::Data<Arc<AppState>>, query: web::Query<FileQuery>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &query.service_id).await {
        Some(b) => b, None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
    };
    let path = default_path(&query.path);
    let filename = std::path::Path::new(&path).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_string());
    match backend {
        FileBackend::DirectAdmin(da) => match da.read_file(&path).await {
            Ok(content) => HttpResponse::Ok()
                .insert_header(("Content-Type", "application/octet-stream"))
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(content),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        },
        FileBackend::Container(container) => {
            let url = format!("/api/files/lxc/download?container={}&path={}", urlencoding::encode(&container), urlencoding::encode(&path));
            match ws_get_bytes(&url).await {
                Ok(bytes) => HttpResponse::Ok()
                    .insert_header(("Content-Type", "application/octet-stream"))
                    .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                    .body(bytes),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}

/// POST /files/delete
pub async fn delete_file(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<PathRequest>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &body.service_id).await {
        Some(b) => b, None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
    };
    match backend {
        FileBackend::DirectAdmin(da) => match da.delete_file(&body.path).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted"})),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        },
        FileBackend::Container(container) => {
            match ws_post("/api/files/lxc/delete", &serde_json::json!({"container": container, "path": body.path})).await {
                Ok(data) => HttpResponse::Ok().json(data), Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}

/// POST /files/mkdir
pub async fn mkdir(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<PathRequest>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &body.service_id).await {
        Some(b) => b, None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
    };
    match backend {
        FileBackend::DirectAdmin(da) => match da.mkdir(&body.path).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "created"})),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        },
        FileBackend::Container(container) => {
            match ws_post("/api/files/lxc/mkdir", &serde_json::json!({"container": container, "path": body.path})).await {
                Ok(data) => HttpResponse::Ok().json(data), Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}

/// POST /files/rename
pub async fn rename(req: HttpRequest, state: web::Data<Arc<AppState>>, body: web::Json<RenameRequest>) -> HttpResponse {
    let backend = match get_file_backend(&req, &state, &body.service_id).await {
        Some(b) => b, None => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
    };
    match backend {
        FileBackend::DirectAdmin(da) => match da.rename_file(&body.from, &body.to).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "renamed"})),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        },
        FileBackend::Container(container) => {
            match ws_post("/api/files/lxc/rename", &serde_json::json!({"container": container, "from": body.from, "to": body.to})).await {
                Ok(data) => HttpResponse::Ok().json(data), Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
    }
}
