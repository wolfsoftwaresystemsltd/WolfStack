//! WolfStack — Server Management Platform for the Wolf Software Suite
//!
//! A Proxmox-like management dashboard that:
//! - Monitors system health (CPU, RAM, disk, network)
//! - Installs and manages Wolf suite components (WolfNet, WolfDisk, etc.)
//! - Manages systemd services
//! - Handles SSL certificates via Certbot
//! - Communicates with other WolfStack nodes over WolfNet or direct IP

mod api;
mod agent;
mod auth;
mod monitoring;
mod installer;
mod containers;
mod console;
mod storage;
mod networking;
mod backup;
mod vms;

use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use actix_files;
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;

/// WolfStack — Wolf Software Management Platform
#[derive(Parser)]
#[command(name = "wolfstack", version, about = "Server management for the Wolf software suite")]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value_t = 8553)]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
}

/// Serve the login page for unauthenticated requests to /
async fn index_handler(req: HttpRequest, state: web::Data<api::AppState>) -> HttpResponse {
    // Check if authenticated
    let authenticated = req.cookie("wolfstack_session")
        .and_then(|c| state.sessions.validate(c.value()))
        .is_some();

    let web_dir = find_web_dir();
    if authenticated {
        let path = format!("{}/index.html", web_dir);
        match std::fs::read_to_string(&path) {
            Ok(content) => HttpResponse::Ok().content_type("text/html").body(content),
            Err(_) => HttpResponse::InternalServerError().body("Web UI not found"),
        }
    } else {
        let path = format!("{}/login.html", web_dir);
        match std::fs::read_to_string(&path) {
            Ok(content) => HttpResponse::Ok().content_type("text/html").body(content),
            Err(_) => HttpResponse::InternalServerError().body("Login page not found"),
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wolfstack=info".parse().unwrap())
                .add_directive("actix_web=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // Generate node ID
    let node_id = format!("ws-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    info!("");
    info!("  🐺 WolfStack v{}", env!("CARGO_PKG_VERSION"));
    info!("  ──────────────────────────────────");
    info!("  Node ID:    {}", node_id);
    info!("  Hostname:   {}", hostname);
    info!("  Dashboard:  http://{}:{}", cli.bind, cli.port);

    // Load built-in cluster secret for inter-node authentication
    let cluster_secret = auth::load_cluster_secret();

    // Fetch public IP (best effort)
    let public_ip = match reqwest::Client::builder().timeout(Duration::from_secs(2)).build() {
        Ok(client) => {
            match client.get("https://ifconfig.me/ip").send().await {
                Ok(resp) => resp.text().await.ok(),
                Err(_) => None,
            }
        }
        Err(_) => None,
    };
    if let Some(ip) = &public_ip {
        info!("  Public IP:  {}", ip);
    } else {
        info!("  Public IP:  (detection failed)");
    }
    info!("");

    // Initialize monitoring
    let monitor = monitoring::SystemMonitor::new();

    // Initialize session manager
    let sessions = Arc::new(auth::SessionManager::new());

    // Initialize cluster state
    let cluster = Arc::new(agent::ClusterState::new(
        node_id.clone(),
        cli.bind.clone(),
        cli.port,
    ));

    // Auto-mount storage entries
    storage::auto_mount_all();

    // Restore IP mapping iptables rules
    networking::apply_ip_mappings();

    // Initialize VM manager
    let vms_manager = vms::manager::VmManager::new();

    // Autostart containers & VMs
    containers::lxc_autostart_all();
    vms_manager.autostart_vms();

    // Initial self-update
    {
        let mut mon = monitor;
        let metrics = mon.collect();
        let components = installer::get_all_status();
        let docker_count = containers::docker_list_all().len() as u32;
        let lxc_count = containers::lxc_list_all().len() as u32;
        let vm_count = vms_manager.list_vms().len() as u32;
        cluster.update_self(metrics, components, docker_count, lxc_count, vm_count, public_ip.clone());

        // Create app state
        let app_state = web::Data::new(api::AppState {
            monitor: Mutex::new(mon),
            metrics_history: Mutex::new(monitoring::MetricsHistory::new()),
            cluster: cluster.clone(),
            sessions: sessions.clone(),
            vms: Mutex::new(vms_manager),
            cluster_secret: cluster_secret.clone(),
        });

        // Background: periodic self-monitoring update
        let state_clone = app_state.clone();
        let cluster_clone = cluster.clone();
        // Clone public_ip for the background task
        let public_ip = public_ip.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let (metrics, components) = {
                    let mut monitor = state_clone.monitor.lock().unwrap();
                    let m = monitor.collect();
                    let c = installer::get_all_status();
                    (m, c)
                };
                // Record historical snapshot
                {
                    let mut history = state_clone.metrics_history.lock().unwrap();
                    history.push(&metrics);
                }
                let docker_count = containers::docker_list_all().len() as u32;
                let lxc_count = containers::lxc_list_all().len() as u32;
                let vm_count = state_clone.vms.lock().unwrap().list_vms().len() as u32;
                // Use the initially detected public_ip (cloned into the closure)
                // Note: If public IP changes (dynamic IP), we'd need to re-fetch it periodically.
                // For now, assuming static public IP session.
                cluster_clone.update_self(metrics, components, docker_count, lxc_count, vm_count, public_ip.clone());
            }
        });

        // Background: poll remote nodes
        let cluster_poll = cluster.clone();
        let secret_poll = cluster_secret.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                agent::poll_remote_nodes(cluster_poll.clone(), secret_poll.clone()).await;
            }
        });

        // Background: session cleanup
        let sessions_cleanup = sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                sessions_cleanup.cleanup();
            }
        });

        // Background: backup schedule checker (every 60s)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                backup::check_schedules();
            }
        });

        // Determine web directory
        let web_dir = find_web_dir();
        info!("  Serving web UI from: {}", web_dir);
        info!("");

        // Start HTTP server
        HttpServer::new(move || {
            App::new()
                .app_data(app_state.clone())
                .configure(api::configure)
                .route("/ws/console/{type}/{name}", web::get().to(console::console_ws))
                .route("/", web::get().to(index_handler))
                .service(actix_files::Files::new("/", &web_dir).index_file("login.html"))
        })
        .bind(format!("{}:{}", cli.bind, cli.port))?
        .run()
        .await
    }
}

/// Find the web directory — check multiple locations
fn find_web_dir() -> String {
    let candidates = [
        // Development
        "web",
        // Installed
        "/opt/wolfstack/web",
        "/usr/share/wolfstack/web",
    ];

    for dir in &candidates {
        let path = std::path::Path::new(dir);
        if path.exists() && path.join("index.html").exists() {
            return dir.to_string();
        }
    }

    // Fallback
    "web".to_string()
}
