// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

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
mod mysql_editor;
mod appstore;
mod alerting;
mod wolfrun;
mod statuspage;
mod ceph;
mod configurator;
mod patreon;
mod kubernetes;
mod tui;

use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use actix_files;
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

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

    /// Disable TLS and run in HTTP-only mode
    #[arg(long)]
    no_tls: bool,

    /// Print this server's join token and exit
    #[arg(long)]
    show_token: bool,
}

/// Serve the login page for unauthenticated requests to /
/// Version string used as cache-buster for static assets.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

async fn index_handler(req: HttpRequest, state: web::Data<api::AppState>) -> HttpResponse {
    // Check if authenticated
    let authenticated = req.cookie("wolfstack_session")
        .and_then(|c| state.sessions.validate(c.value()))
        .is_some();

    let web_dir = find_web_dir();
    if authenticated {
        let path = format!("{}/index.html", web_dir);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                // Inject cache-busting version into asset URLs so browsers
                // fetch fresh JS/CSS after an upgrade without Ctrl+Shift+R.
                let content = content
                    .replace("/css/style.css\"", &format!("/css/style.css?v={}\"", APP_VERSION))
                    .replace("/js/app.js\"", &format!("/js/app.js?v={}\"", APP_VERSION));
                HttpResponse::Ok()
                    .content_type("text/html")
                    .insert_header(("Cache-Control", "no-cache"))
                    .body(content)
            }
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
                .add_directive("actix_web=info".parse().unwrap())
                .add_directive("actix_http=error".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // --show-token: print join token and exit (for CLI access without web UI)
    if cli.show_token {
        let token = api::load_join_token();
        println!("{}", token);
        return Ok(());
    }

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

    // Seed LXC storage paths from any mounted storage that has LXC containers
    if let Ok(entries) = std::fs::read_dir("/mnt/wolfstack") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Check if this mount has LXC containers (subdirs with 'config' files)
                if let Ok(subdirs) = std::fs::read_dir(&path) {
                    for sub in subdirs.flatten() {
                        if sub.path().join("config").exists() && sub.path().join("rootfs").exists() {
                            containers::lxc_register_path(&path.to_string_lossy());
                            break;
                        }
                    }
                }
            }
        }
    }

    // Ensure lxcbr0 bridge is up (needed for WolfNet container networking)
    containers::ensure_lxc_bridge();
    // Re-apply host routes for running containers (routes are lost on restart)
    containers::reapply_wolfnet_routes();
    // Set kernel networking prerequisites for WolfNet container routing
    containers::wolfnet_init();

    // Load per-installation cluster secret for inter-node authentication
    let cluster_secret = auth::load_cluster_secret();

    // Fetch public IP (best effort — try multiple services)
    let public_ip = {
        let services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com",
        ];
        let mut detected: Option<String> = None;
        if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(3)).build() {
            for url in &services {
                if let Ok(resp) = client.get(*url).send().await {
                    if resp.status().is_success() {
                        if let Ok(text) = resp.text().await {
                            let ip = text.trim().to_string();
                            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                detected = Some(ip);
                                break;
                            }
                        }
                    }
                }
            }
        }
        detected
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

    // Re-apply WireGuard bridge interfaces (survives reboot)
    networking::apply_all_wireguard_bridges();

    // Re-apply WolfNet routes for k8s deployments (secondary IPs + iptables rules)
    kubernetes::apply_all_wolfnet_routes();

    // Check if TLS will be available (so the frontend knows the correct protocol for URLs)
    let tls_enabled = if cli.no_tls {
        false
    } else if cli.tls_cert.is_some() && cli.tls_key.is_some() {
        true
    } else {
        installer::find_tls_certificate(cli.tls_domain.as_deref()).is_some()
    };

    // Initial self-update
    {
        let mut mon = monitor;
        let metrics = mon.collect();
        let components = installer::get_all_status();
        let docker_count = containers::docker_list_all().len() as u32;
        let lxc_count = containers::lxc_list_all().len() as u32;
        let vm_count = vms_manager.list_vms().len() as u32;
        let has_docker = containers::docker_status().installed;
        let has_lxc = containers::lxc_status().installed;
        let has_kvm = containers::kvm_installed();
        cluster.update_self(metrics, components, docker_count, lxc_count, vm_count, public_ip.clone(), has_docker, has_lxc, has_kvm, tls_enabled);

        // Initialize AI agent
        let ai_agent = Arc::new(ai::AiAgent::new());

        let cached_status: Arc<std::sync::RwLock<Option<serde_json::Value>>> = Arc::new(std::sync::RwLock::new(None));

        // Initialize WolfRun orchestration state
        let wolfrun_state = Arc::new(wolfrun::WolfRunState::new());

        // Initialize Status Page monitoring state
        let statuspage_state = Arc::new(statuspage::StatusPageState::new());

        // Create app state
        let app_state = web::Data::new(api::AppState {
            monitor: Mutex::new(mon),
            metrics_history: Mutex::new(monitoring::MetricsHistory::new()),
            cluster: cluster.clone(),
            sessions: sessions.clone(),
            vms: Mutex::new(vms_manager),
            cluster_secret: cluster_secret.clone(),
            join_token: api::load_join_token(),
            pbs_restore_progress: Mutex::new(Default::default()),
            ai_agent: ai_agent.clone(),
            cached_status: cached_status.clone(),
            wolfrun: wolfrun_state.clone(),
            statuspage: statuspage_state.clone(),
            tls_enabled,
            login_limiter: Arc::new(auth::LoginRateLimiter::new()),
            wireguard_bridges: Arc::new(std::sync::RwLock::new(networking::load_wireguard_bridges())),
            patreon: Arc::new(patreon::PatreonState::new()),
        });

        // Background: periodic self-monitoring update
        let state_clone = app_state.clone();
        let cluster_clone = cluster.clone();
        // Clone public_ip for the background task
        let public_ip = public_ip.clone();
        let cached_status_bg = cached_status.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let (metrics, components) = {
                    let mut monitor = state_clone.monitor.lock().unwrap();
                    let m = monitor.collect();
                    let c = installer::get_all_status_cached();
                    (m, c)
                };
                // Record historical snapshot
                {
                    let mut history = state_clone.metrics_history.lock().unwrap();
                    history.push(&metrics);
                }
                // Use lightweight counts (1 subprocess each) instead of full listing
                // (which spawns 3+ subprocesses per container for docker inspect)
                let docker_count = containers::docker_count();
                let lxc_count = containers::lxc_count();
                let vm_count = state_clone.vms.lock().unwrap().list_vms().len() as u32;
                // Use cached runtime detection (TTL 120s) instead of spawning
                // 'which', 'docker info', etc. on every 2-second cycle
                let has_docker = containers::has_docker_cached();
                let has_lxc = containers::has_lxc_cached();
                let has_kvm = containers::has_kvm_cached();

                // Cache the agent status report for instant polling responses
                let self_id = cluster_clone.self_id.clone();
                let hostname = metrics.hostname.clone();
                let known_nodes = cluster_clone.get_all_nodes();
                let deleted_ids = cluster_clone.get_deleted_ids();
                let msg = agent::AgentMessage::StatusReport {
                    node_id: self_id,
                    hostname,
                    metrics: metrics.clone(),
                    components: components.clone(),
                    docker_count,
                    lxc_count,
                    vm_count,
                    public_ip: public_ip.clone(),
                    known_nodes,
                    deleted_ids,
                    wolfnet_ips: containers::wolfnet_used_ips_cached(),
                    has_docker,
                    has_lxc,
                    has_kvm,
                };
                if let Ok(json) = serde_json::to_value(&msg) {
                    if let Ok(mut cache) = cached_status_bg.write() {
                        *cache = Some(json);
                    }
                }

                cluster_clone.update_self(metrics, components, docker_count, lxc_count, vm_count, public_ip.clone(), has_docker, has_lxc, has_kvm, tls_enabled);
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

        // Background: clean up stale WolfNet kernel routes (every 30s, was every 10s)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                containers::cleanup_stale_wolfnet_routes();
            }
        });

        // Background: session + login rate limiter cleanup
        let sessions_cleanup = sessions.clone();
        let login_limiter_cleanup = app_state.login_limiter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                sessions_cleanup.cleanup();
                login_limiter_cleanup.cleanup();
            }
        });

        // Background: backup schedule checker (every 60s)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                backup::check_schedules();
            }
        });

        // Background: Patreon membership sync (every 24h)
        let patreon_state = app_state.patreon.clone();
        tokio::spawn(async move {
            // Initial delay — let the server settle before first check
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                if patreon_state.config.read().map(|c| c.linked).unwrap_or(false) {
                    match patreon_state.sync_membership().await {
                        Ok(tier) => info!("Patreon tier synced: {:?}", tier),
                        Err(e) => warn!("Patreon sync failed: {}", e),
                    }
                }
                tokio::time::sleep(Duration::from_secs(86400)).await; // 24 hours
            }
        });

        // Background: scheduled issues scan (configurable alerts + daily summary)
        let scan_state = app_state.clone();
        let scan_ai = ai_agent.clone();
        let scan_cluster = cluster.clone();
        let scan_secret = cluster_secret.clone();
        tokio::spawn(async move {
            // Wait 60 seconds after startup before first check
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut last_daily_date = String::new();
            let mut last_scan_time = std::time::Instant::now();
            // Run first scan immediately after startup delay
            let mut should_scan_now = true;
            let http_client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default();
            loop {
                // Re-read config each loop to pick up schedule changes
                let config = scan_ai.config.lock().unwrap().clone();
                let schedule = config.scan_schedule.as_str();

                // Determine scan interval from schedule
                let interval_secs: u64 = match schedule {
                    "hourly" => 3600,
                    "6h"     => 6 * 3600,
                    "12h"    => 12 * 3600,
                    "daily"  => 24 * 3600,
                    _        => 0, // "off" — no scanning
                };

                if interval_secs > 0 && config.email_enabled && !config.email_to.is_empty() {
                    // Check if enough time has passed
                    if should_scan_now || last_scan_time.elapsed().as_secs() >= interval_secs {
                        should_scan_now = false;
                        last_scan_time = std::time::Instant::now();

                        // Collect issues from ALL nodes (local + remote)
                        // Each entry: (cluster_name, hostname, issue)
                        let mut all_issues: Vec<(String, String, api::Issue)> = Vec::new();

                        // Local node
                        let metrics = scan_state.monitor.lock().unwrap().collect();
                        let local_hostname = metrics.hostname.clone();
                        let local_cluster = {
                            let nodes = scan_cluster.get_all_nodes();
                            nodes.iter().find(|n| n.is_self)
                                .and_then(|n| n.cluster_name.clone())
                                .unwrap_or_else(|| "Default".to_string())
                        };
                        for issue in api::collect_issues(&metrics) {
                            all_issues.push((local_cluster.clone(), local_hostname.clone(), issue));
                        }

                        // All remote WolfStack nodes
                        let nodes = scan_cluster.get_all_nodes();
                        for node in nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox") {
                            let cluster = node.cluster_name.clone().unwrap_or_else(|| "Default".to_string());
                            let url = node_api_url(node, "/api/issues/scan");
                            match http_client.get(&url)
                                .header("X-WolfStack-Secret", scan_secret.as_str())
                                .timeout(std::time::Duration::from_secs(30))
                                .send().await
                            {
                                Ok(resp) => {
                                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                                        let node_host = data["hostname"].as_str().unwrap_or(&node.hostname).to_string();
                                        if let Some(issues_arr) = data["issues"].as_array() {
                                            for iv in issues_arr {
                                                if let (Some(sev), Some(cat), Some(title), Some(detail)) = (
                                                    iv["severity"].as_str(), iv["category"].as_str(),
                                                    iv["title"].as_str(), iv["detail"].as_str(),
                                                ) {
                                                    all_issues.push((cluster.clone(), node_host.clone(), api::Issue {
                                                        severity: sev.to_string(), category: cat.to_string(),
                                                        title: title.to_string(), detail: detail.to_string(),
                                                    }));
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Scheduled scan: failed to reach {}: {}", node.hostname, e);
                                }
                            }
                        }

                        // Sort by cluster name, then hostname (alphabetical)
                        all_issues.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

                        let critical_count = all_issues.iter().filter(|(_, _, i)| i.severity == "critical").count();
                        let warning_count = all_issues.iter().filter(|(_, _, i)| i.severity == "warning").count();
                        let info_count = all_issues.iter().filter(|(_, _, i)| i.severity == "info").count();
                        let total_nodes = {
                            let n = scan_cluster.get_all_nodes();
                            n.iter().filter(|nd| nd.node_type != "proxmox").count()
                        };

                        // Helper: format issues grouped by cluster → hostname
                        let format_grouped = |issues: &[(String, String, api::Issue)], filter_sev: Option<&str>| -> String {
                            let mut out = String::new();
                            let mut current_cluster = String::new();
                            let mut current_host = String::new();
                            for (cluster, host, issue) in issues {
                                if let Some(sev) = filter_sev {
                                    if issue.severity != sev { continue; }
                                }
                                if *cluster != current_cluster {
                                    current_cluster = cluster.clone();
                                    current_host.clear();
                                    out.push_str(&format!("\n━━━ {} ━━━\n", cluster));
                                }
                                if *host != current_host {
                                    current_host = host.clone();
                                    out.push_str(&format!("\n  📍 {}\n", host));
                                }
                                let icon = match issue.severity.as_str() {
                                    "critical" => "❌",
                                    "warning" => "⚠️",
                                    _ => "ℹ️",
                                };
                                out.push_str(&format!("    {} {}\n      {}\n", icon, issue.title, issue.detail));
                            }
                            out
                        };

                        // Immediate alert if critical issues found
                        if critical_count > 0 {
                            let subject = format!(
                                "[WolfStack CRITICAL] {} critical issue(s) across {} node(s)",
                                critical_count, total_nodes
                            );
                            let mut body = format!(
                                "🚨 Critical Issues Detected\nTime: {}\nNodes scanned: {}\n",
                                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"), total_nodes
                            );
                            body.push_str(&format_grouped(&all_issues, Some("critical")));
                            if warning_count > 0 {
                                body.push_str(&format!("\n\n⚠️ Also {} warning(s) — see daily report for details.\n", warning_count));
                            }

                            // AI analysis of all critical issues
                            let critical_summary: String = all_issues.iter()
                                .filter(|(_, _, i)| i.severity == "critical")
                                .map(|(_, host, i)| format!("- {} on {}: {}", i.title, host, i.detail))
                                .collect::<Vec<_>>()
                                .join("\n");
                            let ai_suggestion = scan_ai.analyze_issue(
                                &format!(
                                    "These critical issues were detected across a WolfStack cluster. \
                                     For each issue, suggest what the admin should do to fix it:\n\n{}",
                                    critical_summary
                                )
                            ).await.unwrap_or_default();
                            if !ai_suggestion.is_empty() {
                                body.push_str(&format!("\n\n🤖 AI Recommendations:\n{}", ai_suggestion));
                            }

                            body.push_str(&format!("\nWolfStack v{}", env!("CARGO_PKG_VERSION")));
                            if let Err(e) = ai::send_alert_email(&config, &subject, &body) {
                                tracing::warn!("Failed to send critical issues email: {}", e);
                            }

                            // Also send to webhook channels
                            let alert_config = crate::alerting::AlertConfig::load();
                            if alert_config.enabled && alert_config.has_channels() {
                                let s = subject.clone();
                                let b = body.clone();
                                tokio::spawn(async move {
                                    crate::alerting::send_alert(&alert_config, &s, &b).await;
                                });
                            }
                        }

                        // Daily summary — send once per day (first check after midnight UTC)
                        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                        if today != last_daily_date {
                            last_daily_date = today.clone();

                            let subject = format!(
                                "[WolfStack Daily] {} issue(s) across {} node(s)",
                                all_issues.len(), total_nodes
                            );

                            // ─── Build HTML daily report ───
                            let fmt_bytes = |b: u64| -> String {
                                if b == 0 { return "0 B".to_string(); }
                                let units = ["B", "KB", "MB", "GB", "TB"];
                                let i = (b as f64).log(1024.0).floor() as usize;
                                let i = i.min(units.len() - 1);
                                format!("{:.1} {}", b as f64 / 1024f64.powi(i as i32), units[i])
                            };

                            let mut html = String::from(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;margin:0;padding:20px;}
.container{max-width:900px;margin:0 auto;background:#1a1a2e;border-radius:12px;padding:24px;border:1px solid #2a2a3e;}
h1{color:#818cf8;font-size:22px;margin-top:0;}
h2{color:#a5b4fc;font-size:16px;margin:24px 0 12px;border-bottom:1px solid #2a2a3e;padding-bottom:8px;}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;}
th{background:#16162b;color:#a5b4fc;text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid #2a2a3e;}
td{padding:8px 12px;border-bottom:1px solid #1e1e32;}
tr:hover td{background:#1e1e35;}
.badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:11px;font-weight:600;}
.online{background:rgba(34,197,94,0.15);color:#22c55e;}
.offline{background:rgba(239,68,68,0.15);color:#ef4444;}
.running{background:rgba(34,197,94,0.15);color:#22c55e;}
.stopped{background:rgba(156,163,175,0.15);color:#9ca3af;}
.paused{background:rgba(234,179,8,0.15);color:#eab308;}
.frozen{background:rgba(59,130,246,0.15);color:#3b82f6;}
.critical{background:rgba(239,68,68,0.15);color:#ef4444;}
.warning{background:rgba(245,158,11,0.15);color:#f59e0b;}
.info{background:rgba(59,130,246,0.15);color:#3b82f6;}
.bar{height:8px;border-radius:4px;overflow:hidden;background:#2a2a3e;min-width:60px;}
.bar-fill{height:100%;border-radius:4px;}
.meta{color:#888;font-size:11px;}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}
.summary-card{background:#16162b;border:1px solid #2a2a3e;border-radius:8px;padding:12px;text-align:center;}
.summary-value{font-size:24px;font-weight:700;color:#818cf8;}
.summary-label{font-size:11px;color:#888;text-transform:uppercase;margin-top:4px;}
a{color:#eab308;text-decoration:none;}a:hover{text-decoration:underline;}
.ai-box{background:#16162b;border:1px solid #eab308;border-radius:8px;padding:16px;margin-top:16px;white-space:pre-wrap;font-size:13px;line-height:1.6;color:#f0f0f0;}
</style></head><body><div class="container">"#);

                            // Header
                            html.push_str(&format!(
                                r#"<h1>WolfStack Daily Report</h1>
                                <p style="color:#888;margin-top:-8px;">Date: {} &bull; WolfStack v{} &bull; {} node(s) scanned</p>"#,
                                today, env!("CARGO_PKG_VERSION"), total_nodes
                            ));

                            // Summary cards
                            html.push_str(&format!(
                                r#"<div class="summary-grid">
                                <div class="summary-card"><div class="summary-value">{}</div><div class="summary-label">Nodes</div></div>
                                <div class="summary-card"><div class="summary-value" style="color:{}">{}</div><div class="summary-label">Critical</div></div>
                                <div class="summary-card"><div class="summary-value" style="color:{}">{}</div><div class="summary-label">Warnings</div></div>
                                <div class="summary-card"><div class="summary-value" style="color:#3b82f6">{}</div><div class="summary-label">Info</div></div>
                                </div>"#,
                                total_nodes,
                                if critical_count > 0 { "#ef4444" } else { "#22c55e" }, critical_count,
                                if warning_count > 0 { "#f59e0b" } else { "#22c55e" }, warning_count,
                                info_count
                            ));

                            // ─── Node Inventory Table ───
                            let all_nodes = scan_cluster.get_all_nodes();
                            html.push_str(r#"<h2>Node Inventory</h2>
                            <table><thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Docker</th><th>LXC</th><th>VMs</th></tr></thead><tbody>"#);
                            for n in all_nodes.iter().filter(|n| n.node_type != "proxmox") {
                                let status_class = if n.online { "online" } else { "offline" };
                                let status_text = if n.online { "Online" } else { "Offline" };
                                let (cpu_str, mem_str) = if let Some(ref m) = n.metrics {
                                    let cpu = m.cpu_usage_percent;
                                    let mem_pct = if m.memory_total_bytes > 0 {
                                        (m.memory_used_bytes as f64 / m.memory_total_bytes as f64 * 100.0) as u64
                                    } else { 0 };
                                    let cpu_color = if cpu > 80.0 { "#ef4444" } else if cpu > 50.0 { "#f59e0b" } else { "#22c55e" };
                                    let mem_color = if mem_pct > 90 { "#ef4444" } else if mem_pct > 70 { "#f59e0b" } else { "#22c55e" };
                                    (
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{:.0}%</span>"#, cpu.min(100.0), cpu_color, cpu),
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{} / {}</span>"#, mem_pct.min(100), mem_color, fmt_bytes(m.memory_used_bytes), fmt_bytes(m.memory_total_bytes)),
                                    )
                                } else {
                                    ("—".to_string(), "—".to_string())
                                };
                                let addr = if n.address.is_empty() { &n.hostname } else { &n.address };
                                html.push_str(&format!(
                                    r#"<tr><td><strong>{}</strong><br><span class="meta">{}:{}</span></td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                                    n.hostname, addr, n.port, status_class, status_text, cpu_str, mem_str,
                                    if n.has_docker { format!("{}", n.docker_count) } else { "—".to_string() },
                                    if n.has_lxc { format!("{}", n.lxc_count) } else { "—".to_string() },
                                    if n.has_kvm { format!("{}", n.vm_count) } else { "—".to_string() },
                                ));
                            }
                            // PVE nodes as separate rows
                            for n in all_nodes.iter().filter(|n| n.node_type == "proxmox") {
                                let status_class = if n.online { "online" } else { "offline" };
                                let status_text = if n.online { "Online" } else { "Offline" };
                                let (cpu_str, mem_str) = if let Some(ref m) = n.metrics {
                                    let cpu = m.cpu_usage_percent;
                                    let mem_pct = if m.memory_total_bytes > 0 { (m.memory_used_bytes as f64 / m.memory_total_bytes as f64 * 100.0) as u64 } else { 0 };
                                    let cpu_color = if cpu > 80.0 { "#ef4444" } else if cpu > 50.0 { "#f59e0b" } else { "#22c55e" };
                                    let mem_color = if mem_pct > 90 { "#ef4444" } else if mem_pct > 70 { "#f59e0b" } else { "#22c55e" };
                                    (
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{:.0}%</span>"#, cpu.min(100.0), cpu_color, cpu),
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{} / {}</span>"#, mem_pct.min(100), mem_color, fmt_bytes(m.memory_used_bytes), fmt_bytes(m.memory_total_bytes)),
                                    )
                                } else {
                                    ("—".to_string(), "—".to_string())
                                };
                                html.push_str(&format!(
                                    r#"<tr><td><strong>{}</strong> <span class="badge info">PVE</span><br><span class="meta">{}:{}</span></td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}</td><td>—</td><td>{}</td><td>{}</td></tr>"#,
                                    n.hostname, n.address, n.port, status_class, status_text, cpu_str, mem_str, n.lxc_count, n.vm_count,
                                ));
                            }
                            html.push_str("</tbody></table>");

                            // ─── Docker Containers Table ───
                            {
                                let local_docker = crate::containers::docker_list_all();
                                // Also fetch from remote WolfStack nodes
                                let mut all_docker: Vec<(String, crate::containers::ContainerInfo)> = Vec::new();
                                let local_host = {
                                    let nodes = scan_cluster.get_all_nodes();
                                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_else(|| "localhost".to_string())
                                };
                                for c in local_docker {
                                    all_docker.push((local_host.clone(), c));
                                }
                                // Fetch from remote nodes
                                for node in all_nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox" && n.has_docker) {
                                    let url = node_api_url(node, "/api/containers/docker");
                                    if let Ok(resp) = http_client.get(&url)
                                        .header("X-WolfStack-Secret", scan_secret.as_str())
                                        .timeout(std::time::Duration::from_secs(15))
                                        .send().await
                                    {
                                        if let Ok(containers) = resp.json::<Vec<crate::containers::ContainerInfo>>().await {
                                            for c in containers {
                                                all_docker.push((node.hostname.clone(), c));
                                            }
                                        }
                                    }
                                }

                                if !all_docker.is_empty() {
                                    html.push_str(r#"<h2>Docker Containers</h2>
                                    <table><thead><tr><th>Container</th><th>Node</th><th>Image</th><th>State</th><th>IP</th><th>Ports</th></tr></thead><tbody>"#);
                                    for (host, c) in &all_docker {
                                        let state_class = match c.state.as_str() { "running" => "running", "paused" => "paused", _ => "stopped" };
                                        let ports = if c.ports.is_empty() { "—".to_string() } else { c.ports.join(", ") };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong></td><td class="meta">{}</td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td class="meta">{}</td><td class="meta" style="font-size:10px;">{}</td></tr>"#,
                                            c.name, host, c.image, state_class, c.state, if c.ip_address.is_empty() { "—" } else { &c.ip_address }, ports,
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── LXC Containers Table ───
                            {
                                let local_lxc = crate::containers::lxc_list_all();
                                let mut all_lxc: Vec<(String, crate::containers::ContainerInfo)> = Vec::new();
                                let local_host = {
                                    let nodes = scan_cluster.get_all_nodes();
                                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_else(|| "localhost".to_string())
                                };
                                for c in local_lxc {
                                    all_lxc.push((local_host.clone(), c));
                                }
                                for node in all_nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox" && n.has_lxc) {
                                    let url = node_api_url(node, "/api/containers/lxc");
                                    if let Ok(resp) = http_client.get(&url)
                                        .header("X-WolfStack-Secret", scan_secret.as_str())
                                        .timeout(std::time::Duration::from_secs(15))
                                        .send().await
                                    {
                                        if let Ok(containers) = resp.json::<Vec<crate::containers::ContainerInfo>>().await {
                                            for c in containers {
                                                all_lxc.push((node.hostname.clone(), c));
                                            }
                                        }
                                    }
                                }

                                if !all_lxc.is_empty() {
                                    html.push_str(r#"<h2>LXC Containers</h2>
                                    <table><thead><tr><th>Container</th><th>Node</th><th>Version</th><th>State</th><th>IP</th><th>Autostart</th></tr></thead><tbody>"#);
                                    for (host, c) in &all_lxc {
                                        let state_class = match c.state.as_str() { "running" | "RUNNING" => "running", "frozen" | "FROZEN" => "frozen", _ => "stopped" };
                                        let display_name = if c.hostname.is_empty() { &c.name } else { &c.hostname };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong>{}</td><td class="meta">{}</td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td class="meta">{}</td><td>{}</td></tr>"#,
                                            display_name,
                                            if !c.hostname.is_empty() && c.hostname != c.name { format!(r#"<br><span class="meta">CT {}</span>"#, c.name) } else { String::new() },
                                            host,
                                            c.version.as_deref().unwrap_or("—"),
                                            state_class, c.state,
                                            if c.ip_address.is_empty() { "—" } else { &c.ip_address },
                                            if c.autostart { "Yes" } else { "No" },
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── VMs Table (all nodes) ───
                            {
                                let local_vms = scan_state.vms.lock().unwrap().list_vms();
                                let mut all_vms: Vec<(String, crate::vms::manager::VmConfig)> = Vec::new();
                                let local_host = {
                                    let nodes = scan_cluster.get_all_nodes();
                                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_else(|| "localhost".to_string())
                                };
                                for vm in local_vms {
                                    all_vms.push((local_host.clone(), vm));
                                }
                                // Fetch from remote nodes that have KVM
                                for node in all_nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox" && n.has_kvm) {
                                    let url = node_api_url(node, "/api/vms");
                                    if let Ok(resp) = http_client.get(&url)
                                        .header("X-WolfStack-Secret", scan_secret.as_str())
                                        .timeout(std::time::Duration::from_secs(15))
                                        .send().await
                                    {
                                        if let Ok(vms) = resp.json::<Vec<crate::vms::manager::VmConfig>>().await {
                                            for vm in vms {
                                                all_vms.push((node.hostname.clone(), vm));
                                            }
                                        }
                                    }
                                }

                                if !all_vms.is_empty() {
                                    html.push_str(r#"<h2>Virtual Machines</h2>
                                    <table><thead><tr><th>VM</th><th>Node</th><th>State</th><th>CPUs</th><th>Memory</th><th>Disk</th><th>Autostart</th></tr></thead><tbody>"#);
                                    for (host, vm) in &all_vms {
                                        let state_class = if vm.running { "running" } else { "stopped" };
                                        let state_text = if vm.running { "Running" } else { "Stopped" };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong></td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td>{}</td><td>{} MB</td><td>{} GB</td><td>{}</td></tr>"#,
                                            vm.name, host, state_class, state_text, vm.cpus, vm.memory_mb, vm.disk_size_gb,
                                            if vm.auto_start { "Yes" } else { "No" },
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── Kubernetes Clusters Table ───
                            {
                                let k8s_clusters = crate::kubernetes::list_clusters();
                                if !k8s_clusters.is_empty() {
                                    html.push_str(r#"<h2>Kubernetes Clusters</h2>"#);
                                    for cluster in &k8s_clusters {
                                        let status = tokio::task::spawn_blocking({
                                            let kc = cluster.kubeconfig_path.clone();
                                            move || crate::kubernetes::get_cluster_status(&kc)
                                        }).await.unwrap_or(crate::kubernetes::K8sClusterStatus {
                                            healthy: false, nodes_ready: 0, nodes_total: 0,
                                            pods_running: 0, pods_total: 0, namespaces: 0,
                                            api_version: "unknown".to_string(),
                                        });

                                        let health_class = if status.healthy { "online" } else { "critical" };
                                        let health_text = if status.healthy { "Healthy" } else { "Unhealthy" };
                                        html.push_str(&format!(
                                            r#"<p style="margin:12px 0 6px;"><strong>{}</strong> <span class="badge info">{}</span> <span class="badge {}">{}</span> &bull; <span class="meta">{}/{} nodes, {}/{} pods, {} namespaces, API {}</span></p>"#,
                                            cluster.name, cluster.cluster_type, health_class, health_text,
                                            status.nodes_ready, status.nodes_total,
                                            status.pods_running, status.pods_total,
                                            status.namespaces, status.api_version,
                                        ));

                                        // Get pods for this cluster
                                        let pods = tokio::task::spawn_blocking({
                                            let kc = cluster.kubeconfig_path.clone();
                                            move || {
                                                let pods = crate::kubernetes::get_pods(&kc, None);
                                                if pods.is_empty() {
                                                    crate::kubernetes::get_pods_insecure_pub(&kc, None)
                                                } else {
                                                    pods
                                                }
                                            }
                                        }).await.unwrap_or_default();

                                        if !pods.is_empty() {
                                            html.push_str(r#"<table><thead><tr><th>Pod</th><th>Namespace</th><th>Status</th><th>Ready</th><th>Restarts</th><th>Node</th><th>Age</th></tr></thead><tbody>"#);
                                            for p in &pods {
                                                let state_class = match p.status.as_str() { "Running" => "running", "Failed" | "Unknown" => "critical", "Pending" => "warning", "Succeeded" => "info", _ => "stopped" };
                                                html.push_str(&format!(
                                                    r#"<tr><td><strong>{}</strong></td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}{}</td><td class="meta">{}</td><td class="meta">{}</td></tr>"#,
                                                    p.name, p.namespace, state_class, p.status,
                                                    p.ready, p.restarts,
                                                    if p.restarts >= 10 { " ⚠" } else { "" },
                                                    p.node, p.age,
                                                ));
                                            }
                                            html.push_str("</tbody></table>");
                                        }
                                    }
                                }
                            }

                            // ─── Proxmox VE Guests Table ───
                            {
                                let mut pve_guests: Vec<(String, crate::proxmox::PveGuest)> = Vec::new();
                                for node in all_nodes.iter().filter(|n| n.node_type == "proxmox" && n.online) {
                                    if let (Some(token), Some(pve_name)) = (&node.pve_token, &node.pve_node_name) {
                                        let fp = node.pve_fingerprint.as_deref();
                                        if let Ok((_status, _lc, _vc, _cn, guests)) = crate::proxmox::poll_pve_node(&node.address, node.port, token, fp, pve_name).await {
                                            let label = node.pve_cluster_name.as_deref().unwrap_or(&node.hostname);
                                            for g in guests {
                                                pve_guests.push((label.to_string(), g));
                                            }
                                        }
                                    }
                                }
                                if !pve_guests.is_empty() {
                                    html.push_str(r#"<h2>Proxmox VE Guests</h2>
                                    <table><thead><tr><th>Guest</th><th>PVE Node</th><th>Type</th><th>State</th><th>CPUs</th><th>Memory</th><th>Disk</th><th>Uptime</th></tr></thead><tbody>"#);
                                    for (label, g) in &pve_guests {
                                        let state_class = match g.status.as_str() { "running" => "running", "paused" => "paused", _ => "stopped" };
                                        let type_label = if g.guest_type == "qemu" { "VM" } else { "CT" };
                                        let uptime_str = if g.uptime == 0 { "—".to_string() } else {
                                            let d = g.uptime / 86400; let h = (g.uptime % 86400) / 3600;
                                            if d > 0 { format!("{}d {}h", d, h) } else { format!("{}h", h) }
                                        };
                                        let mem_pct = if g.maxmem > 0 { (g.mem as f64 / g.maxmem as f64 * 100.0) as u64 } else { 0 };
                                        let disk_pct = if g.maxdisk > 0 { (g.disk as f64 / g.maxdisk as f64 * 100.0) as u64 } else { 0 };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong><br><span class="meta">ID {}</span></td><td class="meta">{}</td><td><span class="badge info">{}</span></td><td><span class="badge {}">{}</span></td><td>{}</td><td>{} / {}<br><span class="meta">{}%</span></td><td>{} / {}<br><span class="meta">{}%</span></td><td>{}</td></tr>"#,
                                            g.name, g.vmid, label, type_label, state_class, g.status, g.cpus,
                                            fmt_bytes(g.mem), fmt_bytes(g.maxmem), mem_pct,
                                            fmt_bytes(g.disk), fmt_bytes(g.maxdisk), disk_pct,
                                            uptime_str,
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── Issues Table ───
                            if all_issues.is_empty() {
                                html.push_str(r#"<h2>Issues</h2><p style="color:#22c55e;text-align:center;padding:20px;">All systems healthy — no issues detected.</p>"#);
                            } else {
                                html.push_str(r#"<h2>Issues</h2>
                                <table><thead><tr><th>Severity</th><th>Node</th><th>Issue</th><th>Detail</th></tr></thead><tbody>"#);
                                for (cluster, host, issue) in &all_issues {
                                    let sev_class = match issue.severity.as_str() { "critical" => "critical", "warning" => "warning", _ => "info" };
                                    html.push_str(&format!(
                                        r#"<tr><td><span class="badge {}">{}</span></td><td><strong>{}</strong><br><span class="meta">{}</span></td><td>{}</td><td class="meta">{}</td></tr>"#,
                                        sev_class, issue.severity, host, cluster, issue.title, issue.detail,
                                    ));
                                }
                                html.push_str("</tbody></table>");
                            }

                            // ─── AI Recommendations ───
                            if !all_issues.is_empty() {
                                let issues_summary: String = all_issues.iter()
                                    .map(|(_, host, i)| format!("- [{}] {} on {}: {}", i.severity, i.title, host, i.detail))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let ai_recs = scan_ai.analyze_issue(
                                    &format!(
                                        "Here is today's WolfStack daily report with {} issue(s) across {} node(s). \
                                         Provide a brief prioritised summary of what the admin should address first, \
                                         with specific commands or steps for each issue. Servers may be running different \
                                         Linux distributions.\n\n{}",
                                        all_issues.len(), total_nodes, issues_summary
                                    )
                                ).await.unwrap_or_default();
                                if !ai_recs.is_empty() {
                                    // Escape HTML in AI output
                                    let escaped = ai_recs.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                                    html.push_str(&format!(
                                        r#"<h2 style="color:#eab308;">🤖 AI Recommendations</h2><div class="ai-box">{}</div>"#,
                                        escaped
                                    ));
                                }
                            }

                            // Footer
                            html.push_str(&format!(
                                r#"<p style="color:#555;font-size:11px;text-align:center;margin-top:24px;border-top:1px solid #2a2a3e;padding-top:12px;">WolfStack v{} &bull; Generated {}</p>"#,
                                env!("CARGO_PKG_VERSION"), chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                            ));
                            html.push_str("</div></body></html>");

                            if let Err(e) = ai::send_html_email(&config, &subject, &html) {
                                tracing::warn!("Failed to send daily report email: {}", e);
                            }
                        }
                    }
                }

                // Check every 60 seconds for schedule changes / time elapsed
                tokio::time::sleep(Duration::from_secs(60)).await;
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
                    // Collect local metrics (sync — release mutex before any .await)
                    let (hostname, cpu_pct, mem_used_gb, mem_total_gb, disk_used_gb, disk_total_gb,
                         docker_count, lxc_count, vm_count, uptime_secs) = {
                        let mut monitor = ai_state.monitor.lock().unwrap();
                        let m = monitor.collect();
                        let docker_count = containers::docker_count();
                        let lxc_count = containers::lxc_count();
                        let vm_count = ai_state.vms.lock().unwrap().list_vms().len() as u32;

                        let mem_used = m.memory_used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let mem_total = m.memory_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let root_disk = m.disks.iter().find(|d| d.mount_point == "/").or_else(|| m.disks.first());
                        let disk_used = root_disk.map(|d| d.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);
                        let disk_total = root_disk.map(|d| d.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);

                        (m.hostname.clone(), m.cpu_usage_percent, mem_used, mem_total,
                         disk_used, disk_total, docker_count, lxc_count, vm_count, m.uptime_secs)
                    };
                    // MutexGuard is now dropped — safe to .await below

                    // Collect per-guest CPU stats from Proxmox nodes in the cluster
                    let pve_nodes: Vec<_> = ai_state.cluster.get_all_nodes().into_iter()
                        .filter(|n| n.node_type == "proxmox" && n.online && n.pve_token.is_some())
                        .collect();

                    let mut guest_stats_owned: Vec<(String, String, u64, String, f32)> = Vec::new();
                    for pve_node in &pve_nodes {
                        let token = pve_node.pve_token.as_deref().unwrap_or("");
                        let pve_name = pve_node.pve_node_name.as_deref().unwrap_or(&pve_node.hostname);
                        let fp = pve_node.pve_fingerprint.as_deref();
                        if let Ok((_status, _lxc, _vm, _cluster, guests)) =
                            crate::proxmox::poll_pve_node(&pve_node.address, pve_node.port, token, fp, pve_name).await
                        {
                            for g in guests.iter().filter(|g| g.status == "running") {
                                guest_stats_owned.push((
                                    pve_name.to_string(),
                                    g.guest_type.clone(),
                                    g.vmid,
                                    g.name.clone(),
                                    g.cpu,
                                ));
                            }
                        }
                    }

                    let guest_stats_refs: Vec<(&str, &str, u64, &str, f32)> = guest_stats_owned.iter()
                        .map(|(node, gtype, vmid, name, cpu)| (node.as_str(), gtype.as_str(), *vmid, name.as_str(), *cpu))
                        .collect();

                    // Gather Kubernetes cluster health (blocking kubectl calls)
                    let k8s_health = tokio::task::spawn_blocking(|| {
                        crate::kubernetes::health_summary()
                    }).await.unwrap_or(None);

                    let summary = ai::build_metrics_summary(
                        &hostname,
                        cpu_pct,
                        mem_used_gb, mem_total_gb,
                        disk_used_gb, disk_total_gb,
                        docker_count, lxc_count, vm_count,
                        uptime_secs,
                        if guest_stats_refs.is_empty() { None } else { Some(&guest_stats_refs) },
                        k8s_health.as_deref(),
                    );
                    let _ = ai_agent_bg.health_check(&summary).await;
                }

                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Background: alerting threshold monitor (CPU, memory, disk) for ALL nodes
        let alert_cluster = cluster.clone();
        let alert_secret = cluster_secret.clone();
        let alert_ai = ai_agent.clone();
        let alert_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        tokio::spawn(async move {
            // Wait 90 seconds after startup before first check (let metrics stabilise)
            tokio::time::sleep(Duration::from_secs(90)).await;

            let mut cooldowns: std::collections::HashMap<String, std::time::Instant> = std::collections::HashMap::new();
            loop {
                let config = alerting::AlertConfig::load();


                if config.enabled && config.has_channels() {
                    let all_nodes = alert_cluster.get_all_nodes();

                    for node in &all_nodes {
                        if !node.online { continue; }
                        let metrics = match &node.metrics {
                            Some(m) => m,
                            None => continue,
                        };

                            let cpu_pct = metrics.cpu_usage_percent;
                            let mem_pct = metrics.memory_percent;
                            let disk_pct = metrics.disks.iter()
                                .filter(|d| {
                                    // Skip /boot/ and /etc/pve mounts unless >99% — managed by the OS/Proxmox
                                    if d.mount_point.starts_with("/boot") || d.mount_point == "/etc/pve" {
                                        d.usage_percent > 99.0
                                    } else {
                                        true
                                    }
                                })
                                .map(|d| d.usage_percent)
                                .fold(0.0_f32, f32::max);




                            let display_name = if node.hostname.is_empty() { &node.address } else { &node.hostname };

                            // Check thresholds
                            let triggered = alerting::check_thresholds(&config, cpu_pct, mem_pct, disk_pct);

                            for alert in &triggered {
                                if !alerting::is_in_cooldown(&cooldowns, &node.id, &alert.alert_type) {
                                    let type_label = match alert.alert_type.as_str() {
                                        "cpu" => "CPU",
                                        "memory" => "Memory",
                                        "disk" => "Disk",
                                        _ => &alert.alert_type,
                                    };

                                    // AI analysis of the issue
                                    let ai_suggestion = alert_ai.analyze_issue(
                                        &format!(
                                            "{} usage on '{}' is at {:.1}% (threshold: {:.0}%). \
                                             What are the most likely causes and how can the admin fix this?",
                                            type_label, display_name, alert.current, alert.threshold
                                        )
                                    ).await.unwrap_or_default();

                                    let title = format!(
                                        "[WolfStack ALERT] {} {} at {:.1}% on {}",
                                        type_label, "threshold exceeded", alert.current, display_name
                                    );
                                    let mut body = format!(
                                        "⚠️ {} Threshold Alert\n\n\
                                         Hostname: {}\n\
                                         Metric: {} usage\n\
                                         Current: {:.1}%\n\
                                         Threshold: {:.0}%\n\
                                         Time: {}\n\n\
                                         This alert will not repeat for 15 minutes.",
                                        type_label, display_name, type_label,
                                        alert.current, alert.threshold,
                                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                    );
                                    if !ai_suggestion.is_empty() {
                                        body.push_str(&format!(
                                            "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                        ));
                                    }

                                    let cfg = config.clone();
                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        alerting::send_alert(&cfg, &t, &b).await;
                                    });
                                    alerting::record_alert(&mut cooldowns, &node.id, &alert.alert_type);
                                }
                            }

                            // Recovery notifications: if previously alerted but now below threshold
                            let triggered_types: Vec<&str> = triggered.iter().map(|a| a.alert_type.as_str()).collect();
                            for check_type in &["cpu", "memory", "disk"] {
                                if !triggered_types.contains(check_type)
                                    && alerting::was_alerted(&cooldowns, &node.id, check_type)
                                {
                                    let type_label = match *check_type {
                                        "cpu" => "CPU",
                                        "memory" => "Memory",
                                        "disk" => "Disk",
                                        _ => check_type,
                                    };
                                    let current_val = match *check_type {
                                        "cpu" => cpu_pct,
                                        "memory" => mem_pct,
                                        "disk" => disk_pct,
                                        _ => 0.0,
                                    };
                                    let title = format!(
                                        "[WolfStack OK] {} recovered on {}",
                                        type_label, display_name
                                    );
                                    let body = format!(
                                        "✅ {} Recovered\n\n\
                                         Hostname: {}\n\
                                         Metric: {} usage\n\
                                         Current: {:.1}%\n\
                                         Time: {}\n\n\
                                         {} usage has dropped below the threshold.",
                                        type_label, display_name, type_label,
                                        current_val,
                                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                                        type_label,
                                    );

                                    let cfg = config.clone();
                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        alerting::send_alert(&cfg, &t, &b).await;
                                    });
                                    alerting::clear_cooldown(&mut cooldowns, &node.id, check_type);
                                }
                            }
                            // ── Reboot detection ──
                            // If uptime is under 10 minutes, the node recently rebooted
                            if metrics.uptime_secs < 600 {
                                let reboot_key = format!("{}:reboot", node.id);
                                if !cooldowns.contains_key(&reboot_key) {
                                    let uptime_mins = metrics.uptime_secs / 60;

                                    // Gather reboot reason diagnostics
                                    let diag = if node.is_self {
                                        gather_reboot_reason_local()
                                    } else {
                                        gather_reboot_reason_remote(
                                            &alert_http, &node.address, node.port, node.tls, &alert_secret
                                        ).await
                                    };

                                    // If AI is configured, analyze the diagnostics
                                    let ai_analysis = alert_ai.analyze_reboot(display_name, &diag).await
                                        .unwrap_or_default();

                                    let title = format!(
                                        "[WolfStack ALERT] {} rebooted — uptime {}m",
                                        display_name, uptime_mins
                                    );
                                    let mut body = format!(
                                        "🔄 Server Reboot Detected\n\n\
                                         Hostname: {}\n\
                                         Current Uptime: {} minutes\n\
                                         Time: {}\n\n\
                                         Reboot Diagnostics:\n{}",
                                        display_name, uptime_mins,
                                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                                        diag
                                    );
                                    if !ai_analysis.is_empty() {
                                        body.push_str(&format!(
                                            "\n\n🤖 AI Analysis & Recommendations:\n{}",
                                            ai_analysis
                                        ));
                                    }

                                    let cfg = config.clone();
                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        alerting::send_alert(&cfg, &t, &b).await;
                                    });
                                    // Use a long cooldown (1 hour) so we don't re-alert for the same reboot
                                    cooldowns.insert(reboot_key, std::time::Instant::now());
                                }
                            }
                    }

                    // ── Container memory monitoring (local node only) ──
                    if config.alert_containers {
                        let format_bytes = |b: u64| -> String {
                            if b >= 1073741824 { format!("{:.1} GB", b as f64 / 1073741824.0) }
                            else if b >= 1048576 { format!("{:.0} MB", b as f64 / 1048576.0) }
                            else { format!("{:.0} KB", b as f64 / 1024.0) }
                        };

                        let docker_stats = containers::docker_stats();
                        let lxc_stats = containers::lxc_stats();

                        let docker_alerts = alerting::check_container_thresholds(&config, &docker_stats, "docker");
                        let lxc_alerts = alerting::check_container_thresholds(&config, &lxc_stats, "lxc");

                        let all_container_alerts: Vec<_> = docker_alerts.into_iter().chain(lxc_alerts.into_iter()).collect();

                        for alert in &all_container_alerts {
                            let cooldown_key = format!("container:{}:memory", alert.container_name);
                            if !alerting::is_in_cooldown(&cooldowns, &cooldown_key, "memory") {
                                let runtime_label = if alert.runtime == "docker" { "Docker" } else { "LXC" };

                                let ai_suggestion = alert_ai.analyze_issue(
                                    &format!(
                                        "{} container '{}' memory usage is at {:.1}% ({} / {}). \
                                         What are the likely causes and how can the admin reduce memory usage or increase limits?",
                                        runtime_label, alert.container_name, alert.memory_percent,
                                        format_bytes(alert.memory_usage), format_bytes(alert.memory_limit)
                                    )
                                ).await.unwrap_or_default();

                                let title = format!(
                                    "[WolfStack ALERT] {} container '{}' memory at {:.1}%",
                                    runtime_label, alert.container_name, alert.memory_percent
                                );
                                let mut body = format!(
                                    "⚠️ Container Memory Alert\n\n\
                                     Container: {} ({})\n\
                                     Memory Used: {} / {}\n\
                                     Usage: {:.1}%\n\
                                     Threshold: {:.0}%\n\
                                     Time: {}\n\n\
                                     This alert will not repeat for 15 minutes.",
                                    alert.container_name, runtime_label,
                                    format_bytes(alert.memory_usage), format_bytes(alert.memory_limit),
                                    alert.memory_percent, alert.threshold,
                                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                );
                                if !ai_suggestion.is_empty() {
                                    body.push_str(&format!(
                                        "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                    ));
                                }

                                let cfg = config.clone();
                                let t = title.clone();
                                let b = body.clone();
                                tokio::spawn(async move {
                                    alerting::send_alert(&cfg, &t, &b).await;
                                });
                                alerting::record_alert(&mut cooldowns, &cooldown_key, "memory");
                            }
                        }

                        // Container recovery: clear cooldown when container drops below threshold
                        let running_names: Vec<String> = docker_stats.iter().chain(lxc_stats.iter())
                            .filter(|s| s.memory_limit > 0)
                            .map(|s| s.name.clone())
                            .collect();
                        let alerted_names: Vec<String> = all_container_alerts.iter()
                            .map(|a| a.container_name.clone())
                            .collect();
                        for name in &running_names {
                            if !alerted_names.contains(name) {
                                let cooldown_key = format!("container:{}:memory", name);
                                if alerting::was_alerted(&cooldowns, &cooldown_key, "memory") {
                                    // Find the stats for recovery message
                                    let stats = docker_stats.iter().chain(lxc_stats.iter())
                                        .find(|s| s.name == *name);
                                    if let Some(s) = stats {
                                        let runtime_label = if s.runtime == "docker" { "Docker" } else { "LXC" };
                                        let title = format!(
                                            "[WolfStack OK] {} container '{}' memory recovered",
                                            runtime_label, name
                                        );
                                        let body = format!(
                                            "✅ Container Memory Recovered\n\n\
                                             Container: {} ({})\n\
                                             Memory Used: {} / {}\n\
                                             Usage: {:.1}%\n\
                                             Time: {}\n\n\
                                             Container memory has dropped below the threshold.",
                                            name, runtime_label,
                                            format_bytes(s.memory_usage), format_bytes(s.memory_limit),
                                            s.memory_percent,
                                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                        );

                                        let cfg = config.clone();
                                        let t = title.clone();
                                        let b = body.clone();
                                        tokio::spawn(async move {
                                            alerting::send_alert(&cfg, &t, &b).await;
                                        });
                                    }
                                    alerting::clear_cooldown(&mut cooldowns, &cooldown_key, "memory");
                                }
                            }
                        }
                    }
                }

                // Use the configured interval (re-read each loop in case user changed it)
                let interval = config.check_interval_secs.max(30);
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Background: WolfRun reconciliation loop (every 15s)
        let wolfrun_cluster = cluster.clone();
        let wolfrun_secret = cluster_secret.clone();
        let wolfrun_bg = wolfrun_state.clone();
        tokio::spawn(async move {
            // Wait 30 seconds after startup before first reconciliation
            tokio::time::sleep(Duration::from_secs(30)).await;
            info!("WolfRun reconciliation loop started");
            loop {
                // Only the cluster leader runs reconciliation to prevent
                // duplicate container creation and IP address conflicts
                if wolfrun::is_leader(&wolfrun_cluster) {
                    wolfrun::reconcile(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                    // Broadcast updated instance status to cluster peers
                    wolfrun::broadcast_to_cluster(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });

        // Background: Status page health check runner (every 30s)
        let sp_state = statuspage_state.clone();
        tokio::spawn(async move {
            // Short delay after startup, then run first check immediately
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                statuspage::run_checks(&sp_state).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        // Background: periodically pull status page config from peers if we have none
        let sp_sync = statuspage_state.clone();
        let sp_sync_cluster = cluster.clone();
        let sp_sync_secret = cluster_secret.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                statuspage::pull_from_peers(&sp_sync, &sp_sync_cluster, &sp_sync_secret).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: WolfNet auto-restart watchdog (check every 60s, restart at most once/hour)
        let wolfnet_ai = ai_agent.clone();
        tokio::spawn(async move {
            // Wait for system to stabilise before first check
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut last_restart_attempt: Option<std::time::Instant> = None;
            let mut restart_failed = false;
            loop {
                let status = networking::get_wolfnet_status();
                // Only act if WolfNet is installed but not running
                if status.installed && !status.running {
                    let should_attempt = match last_restart_attempt {
                        None => true,
                        Some(t) => t.elapsed().as_secs() >= 3600, // once per hour
                    };

                    if should_attempt {
                        info!("WolfNet is down — attempting automatic restart");
                        match networking::wolfnet_service_action("restart") {
                            Ok(_) => {
                                // Verify it actually came up
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                let check = networking::get_wolfnet_status();
                                if check.running {
                                    info!("WolfNet auto-restart succeeded");
                                    restart_failed = false;
                                    // Send recovery alert if we previously reported failure
                                    let config = alerting::AlertConfig::load();
                                    if config.enabled && config.has_channels() {
                                        let title = "[WolfStack OK] WolfNet auto-recovered".to_string();
                                        let body = format!(
                                            "✅ WolfNet Auto-Recovery\n\n\
                                             WolfNet was detected as down and has been automatically restarted.\n\
                                             Time: {}",
                                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                        );
                                        tokio::spawn(async move {
                                            alerting::send_alert(&config, &title, &body).await;
                                        });
                                    }
                                } else {
                                    warn!("WolfNet auto-restart failed — service did not come up");
                                    if !restart_failed {
                                        restart_failed = true;
                                        let ai_suggestion = wolfnet_ai.analyze_issue(
                                            "WolfNet overlay network service is down and an automatic restart failed. \
                                             The service did not come up after 'systemctl restart wolfnet'. \
                                             What should the admin check and how can they fix this?"
                                        ).await.unwrap_or_default();
                                        let config = alerting::AlertConfig::load();
                                        if config.enabled && config.has_channels() {
                                            let title = "[WolfStack ALERT] WolfNet down — auto-restart failed".to_string();
                                            let mut body = format!(
                                                "⚠️ WolfNet Down\n\n\
                                                 WolfNet was detected as down and an automatic restart was attempted but failed.\n\
                                                 Manual intervention may be required.\n\
                                                 Time: {}\n\n\
                                                 Next restart attempt in 1 hour.",
                                                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                            );
                                            if !ai_suggestion.is_empty() {
                                                body.push_str(&format!(
                                                    "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                                ));
                                            }
                                            tokio::spawn(async move {
                                                alerting::send_alert(&config, &title, &body).await;
                                            });
                                        }
                                    }
                                }
                                last_restart_attempt = Some(std::time::Instant::now());
                            }
                            Err(e) => {
                                warn!("WolfNet auto-restart command failed: {}", e);
                                if !restart_failed {
                                    restart_failed = true;
                                    let ai_suggestion = wolfnet_ai.analyze_issue(
                                        &format!(
                                            "WolfNet overlay network service is down. The 'systemctl restart wolfnet' \
                                             command failed with error: {}. What should the admin check?", e
                                        )
                                    ).await.unwrap_or_default();
                                    let config = alerting::AlertConfig::load();
                                    if config.enabled && config.has_channels() {
                                        let title = "[WolfStack ALERT] WolfNet down — auto-restart failed".to_string();
                                        let mut body = format!(
                                            "⚠️ WolfNet Down\n\n\
                                             WolfNet was detected as down and an automatic restart was attempted but failed.\n\
                                             Error: {}\n\
                                             Manual intervention may be required.\n\
                                             Time: {}\n\n\
                                             Next restart attempt in 1 hour.",
                                            e, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                        );
                                        if !ai_suggestion.is_empty() {
                                            body.push_str(&format!(
                                                "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                            ));
                                        }
                                        tokio::spawn(async move {
                                            alerting::send_alert(&config, &title, &body).await;
                                        });
                                    }
                                }
                                last_restart_attempt = Some(std::time::Instant::now());
                            }
                        }
                    }
                } else if status.installed && status.running && restart_failed {
                    // WolfNet came back (maybe manually restarted)
                    restart_failed = false;
                    info!("WolfNet is running again");
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Determine web directory
        let web_dir = find_web_dir();
        info!("  Serving web UI from: {}", web_dir);
        info!("");

        // Resolve TLS certificate paths
        let tls_paths = if cli.no_tls {
            None
        } else if let (Some(cert), Some(key)) = (&cli.tls_cert, &cli.tls_key) {
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
            let (cert_path, key_path) = tls_paths.as_ref().unwrap();
            info!("  🔒 TLS enabled");
            info!("     Cert: {}", cert_path);
            info!("     Key:  {}", key_path);
            info!("     HTTPS: https://{}:{}", cli.bind, cli.port);
            info!("     HTTP (inter-node): http://{}:{}", cli.bind, cli.port + 1);
            info!("     Status pages: http://{}:8550", cli.bind);
            info!("");

            // Clone web_dir for second closure
            let web_dir2 = web_dir.clone();
            let app_state2 = app_state.clone();
            let app_state3 = app_state.clone();

            // Start HTTPS server on main port + HTTP server on port+1 for inter-node
            let https_bind = format!("{}:{}", cli.bind, cli.port);
            let https_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    .configure(api::configure)
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
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    .configure(api::configure)
                    .route("/", web::get().to(index_handler))
                    .service(actix_files::Files::new("/", &web_dir2).index_file("login.html"))
            })
            .bind(&http_bind)
            .map_err(|e| {
                tracing::error!("❌ Failed to bind HTTP on {}: {}", http_bind, e);
                e
            })?
            .run();

            // Dedicated status page listener — plain HTTP on port 8550
            let sp_bind = format!("{}:8550", cli.bind);
            let sp_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state3.clone())
                    .configure(api::configure_statuspage_only)
            })
            .bind(&sp_bind)
            .map_err(|e| {
                tracing::warn!("⚠️  Failed to bind status page listener on {}: {}", sp_bind, e);
                e
            });

            match sp_server {
                Ok(sp) => {
                    let (r1, r2, r3) = tokio::join!(https_server, http_server, sp.run());
                    r1?; r2?; r3?;
                }
                Err(_) => {
                    // Status page port unavailable — run without it
                    let (r1, r2) = tokio::join!(https_server, http_server);
                    r1?; r2?;
                }
            }
            Ok(())
        } else {
            if cli.no_tls {
                info!("  ⚡ HTTP mode (TLS disabled via --no-tls)");
            } else if tls_paths.is_some() {
                info!("  ⚠️  TLS certificates found but failed to load — running HTTP only");
            } else {
                info!("  ⚡ HTTP mode (no TLS certificates found)");
            }
            info!("     Dashboard: http://{}:{}", cli.bind, cli.port);
            info!("     Status pages: http://{}:8550", cli.bind);
            info!("     Tip: Use the Certificates page to request a Let's Encrypt certificate");
            info!("");

            let app_state2 = app_state.clone();

            // Start HTTP server (same as before — no breaking changes)
            let main_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    .configure(api::configure)
                    .route("/", web::get().to(index_handler))
                    .service(actix_files::Files::new("/", &web_dir).index_file("login.html"))
            })
            .bind(format!("{}:{}", cli.bind, cli.port))?
            .run();

            // Dedicated status page listener — plain HTTP on port 8550
            let sp_bind = format!("{}:8550", cli.bind);
            let sp_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state2.clone())
                    .configure(api::configure_statuspage_only)
            })
            .bind(&sp_bind)
            .map_err(|e| {
                tracing::warn!("⚠️  Failed to bind status page listener on {}: {}", sp_bind, e);
                e
            });

            match sp_server {
                Ok(sp) => {
                    let (r1, r2) = tokio::join!(main_server, sp.run());
                    r1?; r2?;
                }
                Err(_) => {
                    main_server.await?;
                }
            }
            Ok(())
        }
    }
}

/// Build the preferred inter-node HTTP URL for a given node and API path.
/// TLS nodes serve HTTPS on main port and plain HTTP on port+1 for inter-node calls.
fn node_api_url(node: &crate::agent::Node, path: &str) -> String {
    if node.tls {
        format!("http://{}:{}{}", node.address, node.port + 1, path)
    } else {
        format!("http://{}:{}{}", node.address, node.port, path)
    }
}

/// Gather reboot reason diagnostics from the local machine
fn gather_reboot_reason_local() -> String {
    let commands = [
        ("Last shutdown/reboot entries", "last -x reboot shutdown -n 5 2>/dev/null || last reboot -n 5 2>/dev/null"),
        ("Previous boot final logs", "journalctl -b -1 -n 30 --no-pager -p warning 2>/dev/null"),
        ("Kernel panic check", "journalctl -b -1 --no-pager -k 2>/dev/null | grep -i -E 'panic|oom|killed|segfault|error|watchdog' | tail -10"),
        ("Unattended upgrades", "tail -20 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null || echo '(no unattended-upgrades log)'"),
    ];

    let mut result = String::new();
    for (label, cmd) in &commands {
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(cmd)
            .output();
        let text = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let trimmed = stdout.trim().to_string();
                if trimmed.is_empty() { "(no output)".to_string() } else { trimmed }
            }
            Err(e) => format!("(failed: {})", e),
        };
        result.push_str(&format!("\n--- {} ---\n{}\n", label, text));
    }

    // Truncate if too long for notification
    if result.len() > 3000 {
        result.truncate(3000);
        result.push_str("\n[truncated]");
    }
    result
}

/// Gather reboot reason diagnostics from a remote node via /api/ai/exec
async fn gather_reboot_reason_remote(
    client: &reqwest::Client,
    address: &str,
    port: u16,
    tls: bool,
    secret: &str,
) -> String {
    let commands = [
        ("Last shutdown/reboot entries", "last -x reboot shutdown -n 5 2>/dev/null || last reboot -n 5 2>/dev/null"),
        ("Previous boot final logs", "journalctl -b -1 -n 30 --no-pager -p warning 2>/dev/null"),
        ("Kernel panic check", "journalctl -b -1 --no-pager -k 2>/dev/null | grep -i -E 'panic|oom|killed|segfault|error|watchdog' | tail -10"),
    ];

    // Build URL — try inter-node HTTP on port+1 first if TLS, else main port
    let urls: Vec<String> = if tls {
        vec![
            format!("http://{}:{}/api/ai/exec", address, port + 1),
            format!("https://{}:{}/api/ai/exec", address, port),
        ]
    } else {
        vec![format!("http://{}:{}/api/ai/exec", address, port)]
    };

    let mut result = String::new();
    for (label, cmd) in &commands {
        let mut output = format!("(could not reach node)");
        for url in &urls {
            let resp = client
                .post(url)
                .header("X-WolfStack-Secret", secret)
                .json(&serde_json::json!({ "command": *cmd }))
                .send()
                .await;
            match resp {
                Ok(r) => {
                    let text = r.text().await.unwrap_or_default();
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(err) = json["error"].as_str() {
                            output = format!("(error: {})", err);
                        } else {
                            output = json["output"].as_str().unwrap_or("(no output)").to_string();
                        }
                    } else {
                        output = "(invalid response)".to_string();
                    }
                    break;
                }
                Err(_) => continue,
            }
        }
        result.push_str(&format!("\n--- {} ---\n{}\n", label, output));
    }

    if result.len() > 3000 {
        result.truncate(3000);
        result.push_str("\n[truncated]");
    }
    result
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
