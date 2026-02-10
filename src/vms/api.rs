use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use crate::api::{AppState, require_auth};
use super::manager::VmConfig;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/vms")
            .route("", web::get().to(list_vms))
            .route("/create", web::post().to(create_vm))
            .route("/{name}/action", web::post().to(vm_action))
            .route("/{name}", web::put().to(update_vm))
            .route("/{name}", web::delete().to(delete_vm))
            .route("/{name}", web::get().to(get_vm))
    );
}

async fn list_vms(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    let vms = manager.list_vms();
    HttpResponse::Ok().json(vms)
}

#[derive(Deserialize)]
struct CreateVmRequest {
    name: String,
    cpus: u32,
    memory_mb: u32,
    disk_size_gb: u32,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
}

async fn create_vm(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CreateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    
    let mut config = VmConfig::new(
        body.name.clone(),
        body.cpus,
        body.memory_mb,
        body.disk_size_gb
    );
    config.iso_path = body.iso_path.clone();
    config.wolfnet_ip = body.wolfnet_ip.clone();

    match manager.create_vm(config) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct UpdateVmRequest {
    cpus: Option<u32>,
    memory_mb: Option<u32>,
    disk_size_gb: Option<u32>,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
}

async fn update_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.update_vm(&name, body.cpus, body.memory_mb, body.iso_path.clone(), 
                            body.wolfnet_ip.clone(), body.disk_size_gb) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn get_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.get_vm(&name) {
        Some(vm) => HttpResponse::Ok().json(vm),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "VM not found" })),
    }
}

async fn delete_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.delete_vm(&name) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct VmActionRequest {
    action: String,
}

async fn vm_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<VmActionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    let result = match body.action.as_str() {
        "start" => manager.start_vm(&name),
        "stop" => manager.stop_vm(&name),
        _ => Err(format!("Unknown action: {}", body.action)),
    };
    
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}
