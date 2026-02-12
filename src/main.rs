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
mod ai;
mod auth;
mod monitoring;
mod installer;
mod containers;
mod console;
mod storage;
mod networking;
mod backup;
mod vms;
mod proxmox;

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

    /// TLS certificate path (PEM). Auto-detected from Let's Encrypt if not set.
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key path (PEM). Auto-detected from Let's Encrypt if not set.
    #[arg(long)]
    tls_key: Option<String>,

    /// Domain name for auto-detecting Let's Encrypt certificates
    #[arg(long)]
    tls_domain: Option<String>,
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

    // Load or generate node ID
    let node_id_file = "/etc/wolfstack/node_id";
    let node_id = if let Ok(content) = std::fs::read_to_string(node_id_file) {
        content.trim().to_string()
    } else {
        let id = format!("ws-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let _ = std::fs::create_dir_all("/etc/wolfstack");
        if let Err(e) = std::fs::write(node_id_file, &id) {
            tracing::error!("Failed to persist node ID: {}", e);
        }
        id
    };
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

        // Initialize AI agent
        let ai_agent = Arc::new(ai::AiAgent::new());

        // Create app state
        let app_state = web::Data::new(api::AppState {
            monitor: Mutex::new(mon),
            metrics_history: Mutex::new(monitoring::MetricsHistory::new()),
            cluster: cluster.clone(),
            sessions: sessions.clone(),
            vms: Mutex::new(vms_manager),
            cluster_secret: cluster_secret.clone(),
            pbs_restore_progress: Mutex::new(Default::default()),
            ai_agent: ai_agent.clone(),
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
        let ai_agent_poll = ai_agent.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                agent::poll_remote_nodes(cluster_poll.clone(), secret_poll.clone(), Some(ai_agent_poll.clone())).await;
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

        // Background: AI health check loop
        let ai_state = app_state.clone();
        let ai_agent_bg = ai_agent.clone();
        tokio::spawn(async move {
            // Wait 30 seconds after startup before first check
            tokio::time::sleep(Duration::from_secs(30)).await;
            loop {
                let (is_configured, interval) = {
                    let config = ai_agent_bg.config.lock().unwrap();
                    let configured = config.is_configured();
                    let mins = if configured { config.check_interval_minutes as u64 * 60 } else { 300u64 };
                    (configured, mins)
                };

                if is_configured {
                    // Build metrics summary with real system data
                    let summary = {
                        let mut monitor = ai_state.monitor.lock().unwrap();
                        let m = monitor.collect();
                        let docker_count = containers::docker_list_all().len() as u32;
                        let lxc_count = containers::lxc_list_all().len() as u32;
                        let vm_count = ai_state.vms.lock().unwrap().list_vms().len() as u32;

                        let mem_used_gb = m.memory_used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let mem_total_gb = m.memory_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let root_disk = m.disks.iter().find(|d| d.mount_point == "/").or_else(|| m.disks.first());
                        let disk_used_gb = root_disk.map(|d| d.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);
                        let disk_total_gb = root_disk.map(|d| d.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);

                        ai::build_metrics_summary(
                            &m.hostname,
                            m.cpu_usage_percent,
                            mem_used_gb, mem_total_gb,
                            disk_used_gb, disk_total_gb,
                            docker_count, lxc_count, vm_count,
                            m.uptime_secs,
                        )
                    };
                    let _ = ai_agent_bg.health_check(&summary).await;
                }

                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Determine web directory
        let web_dir = find_web_dir();
        info!("  Serving web UI from: {}", web_dir);
        info!("");

        // Resolve TLS certificate paths
        let tls_paths = if let (Some(cert), Some(key)) = (&cli.tls_cert, &cli.tls_key) {
            Some((cert.clone(), key.clone()))
        } else {
            installer::find_tls_certificate(cli.tls_domain.as_deref())
        };

        // Try to load TLS config using OpenSSL — fall back to HTTP if anything goes wrong
        let ssl_builder = tls_paths.as_ref().and_then(|(cert_path, key_path)| {
            use openssl::ssl::{SslAcceptor, SslMethod, SslFiletype};

            let mut builder = match SslAcceptor::mozilla_intermediate(SslMethod::tls()) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Failed to create SSL acceptor: {} — falling back to HTTP", e);
                    return None;
                }
            };

            if let Err(e) = builder.set_certificate_chain_file(cert_path) {
                tracing::warn!("Cannot load TLS cert '{}': {} — falling back to HTTP", cert_path, e);
                return None;
            }

            if let Err(e) = builder.set_private_key_file(key_path, SslFiletype::PEM) {
                tracing::warn!("Cannot load TLS key '{}': {} — falling back to HTTP", key_path, e);
                return None;
            }

            Some(builder)
        });

        if let Some(ssl_builder) = ssl_builder {
            let (ref cert_path, ref key_path) = tls_paths.as_ref().unwrap();
            info!("  🔒 TLS enabled");
            info!("     Cert: {}", cert_path);
            info!("     Key:  {}", key_path);
            info!("     HTTPS: https://{}:{}", cli.bind, cli.port);
            info!("     HTTP (inter-node): http://{}:{}", cli.bind, cli.port + 1);
            info!("");

            // Clone web_dir for second closure
            let web_dir2 = web_dir.clone();
            let app_state2 = app_state.clone();

            // Start HTTPS server on main port + HTTP server on port+1 for inter-node
            let https_bind = format!("{}:{}", cli.bind, cli.port);
            let https_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state.clone())
                    .configure(api::configure)
                    .route("/ws/console/{type}/{name}", web::get().to(console::console_ws))
                    .route("/", web::get().to(index_handler))
                    .service(actix_files::Files::new("/", &web_dir).index_file("login.html"))
            })
            .bind_openssl(&https_bind, ssl_builder)
            .map_err(|e| {
                tracing::error!("❌ Failed to bind HTTPS on {}: {}", https_bind, e);
                e
            })?
            .run();

            let http_bind = format!("{}:{}", cli.bind, cli.port + 1);
            let http_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state2.clone())
                    .configure(api::configure)
                    .route("/ws/console/{type}/{name}", web::get().to(console::console_ws))
                    .route("/", web::get().to(index_handler))
                    .service(actix_files::Files::new("/", &web_dir2).index_file("login.html"))
            })
            .bind(&http_bind)
            .map_err(|e| {
                tracing::error!("❌ Failed to bind HTTP on {}: {}", http_bind, e);
                e
            })?
            .run();

            let (r1, r2) = tokio::join!(https_server, http_server);
            r1?;
            r2?;
            Ok(())
        } else {
            if tls_paths.is_some() {
                info!("  ⚠️  TLS certificates found but failed to load — running HTTP only");
            } else {
                info!("  ⚡ HTTP mode (no TLS certificates found)");
            }
            info!("     Dashboard: http://{}:{}", cli.bind, cli.port);
            info!("     Tip: Use the Certificates page to request a Let's Encrypt certificate");
            info!("");

            // Start HTTP server (same as before — no breaking changes)
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
