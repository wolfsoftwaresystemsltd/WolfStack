// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use crate::api::{AppState, require_auth};
use super::manager::{VmConfig, StorageVolume};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/vms")
            .route("", web::get().to(list_vms))
            .route("/create", web::post().to(create_vm))
            .route("/storage", web::get().to(list_storage))
            .route("/{name}/action", web::post().to(vm_action))
            .route("/{name}/logs", web::get().to(vm_logs))
            .route("/{name}/volumes", web::post().to(add_volume))
            .route("/{name}/volumes/{vol}", web::delete().to(remove_volume))
            .route("/{name}/volumes/{vol}/resize", web::post().to(resize_volume))
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

/// List available storage locations on the host
async fn list_storage(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    let locations = manager.list_storage_locations();
    HttpResponse::Ok().json(locations)
}

#[derive(Deserialize)]
struct CreateVmDisk {
    name: String,
    size_gb: u32,
    #[serde(default = "default_storage")]
    storage_path: String,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default = "default_bus")]
    bus: String,
}

fn default_storage() -> String { "/var/lib/wolfstack/vms".to_string() }
fn default_format() -> String { "qcow2".to_string() }
fn default_bus() -> String { "virtio".to_string() }

#[derive(Deserialize)]
struct CreateVmRequest {
    name: String,
    cpus: u32,
    memory_mb: u32,
    disk_size_gb: u32,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
    /// Storage path for the OS disk
    storage_path: Option<String>,
    /// Bus type for OS disk (virtio, ide, sata) — use ide for Windows
    #[serde(default = "default_os_bus")]
    os_disk_bus: String,
    /// Network adapter model (virtio, e1000, rtl8139) — use e1000 for Windows
    #[serde(default = "default_os_bus")]
    net_model: String,
    /// Optional path to VirtIO drivers ISO (for Windows + virtio disk)
    drivers_iso: Option<String>,
    /// Extra disks to create with the VM (Proxmox-style)
    #[serde(default)]
    extra_disks: Vec<CreateVmDisk>,
}

fn default_os_bus() -> String { "virtio".to_string() }

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
    config.storage_path = body.storage_path.clone();
    config.os_disk_bus = body.os_disk_bus.clone();
    config.net_model = body.net_model.clone();
    config.drivers_iso = body.drivers_iso.clone();

    // Convert extra disks from request to StorageVolume structs
    for disk in &body.extra_disks {
        config.extra_disks.push(StorageVolume {
            name: format!("{}-{}", body.name, disk.name),
            size_gb: disk.size_gb,
            storage_path: disk.storage_path.clone(),
            format: disk.format.clone(),
            bus: disk.bus.clone(),
        });
    }

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
    os_disk_bus: Option<String>,
    net_model: Option<String>,
    drivers_iso: Option<String>,
    auto_start: Option<bool>,
}

async fn update_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.update_vm(&name, body.cpus, body.memory_mb, body.iso_path.clone(), 
                            body.wolfnet_ip.clone(), body.disk_size_gb,
                            body.os_disk_bus.clone(), body.net_model.clone(),
                            body.drivers_iso.clone(), body.auto_start) {
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

async fn vm_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    let log_path = manager.base_dir.join(format!("{}.log", name));
    let log_content = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|_| "No logs available for this VM.".to_string());
    
    HttpResponse::Ok().json(serde_json::json!({ "name": name, "logs": log_content }))
}

// ─── Storage Volume Endpoints ───

#[derive(Deserialize)]
struct AddVolumeRequest {
    name: String,
    size_gb: u32,
    storage_path: Option<String>,
    format: Option<String>,
    bus: Option<String>,
}

async fn add_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<AddVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let vm_name = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.add_volume(&vm_name, &body.name, body.size_gb, 
                             body.storage_path.as_deref(), body.format.as_deref(),
                             body.bus.as_deref()) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn remove_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (vm_name, vol_name) = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.remove_volume(&vm_name, &vol_name, true) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct ResizeVolumeRequest {
    size_gb: u32,
}

async fn resize_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<ResizeVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (vm_name, vol_name) = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.resize_volume(&vm_name, &vol_name, body.size_gb) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}
