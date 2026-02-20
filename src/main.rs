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

    /// Print this server's join token and exit
    #[arg(long)]
    show_token: bool,
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

    // Ensure lxcbr0 bridge is up (needed for WolfNet container networking)
    containers::ensure_lxc_bridge();
    // Re-apply host routes for running containers (routes are lost on restart)
    containers::reapply_wolfnet_routes();

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
        let has_docker = containers::docker_status().installed;
        let has_lxc = containers::lxc_status().installed;
        let has_kvm = containers::kvm_installed();
        cluster.update_self(metrics, components, docker_count, lxc_count, vm_count, public_ip.clone(), has_docker, has_lxc, has_kvm);

        // Initialize AI agent
        let ai_agent = Arc::new(ai::AiAgent::new());

        let cached_status: Arc<std::sync::RwLock<Option<serde_json::Value>>> = Arc::new(std::sync::RwLock::new(None));

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
                let has_docker = containers::docker_status().installed;
                let has_lxc = containers::lxc_status().installed;
                let has_kvm = containers::kvm_installed();

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
                    wolfnet_ips: containers::wolfnet_used_ips(),
                    has_docker,
                    has_lxc,
                    has_kvm,
                };
                if let Ok(json) = serde_json::to_value(&msg) {
                    if let Ok(mut cache) = cached_status_bg.write() {
                        *cache = Some(json);
                    }
                }

                cluster_clone.update_self(metrics, components, docker_count, lxc_count, vm_count, public_ip.clone(), has_docker, has_lxc, has_kvm);
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
                // Sync container routes from WolfNet peers (works without cluster membership)
                containers::sync_wolfnet_peer_routes().await;
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
            let http_client = reqwest::Client::new();
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
                            let url = format!("http://{}:{}/api/issues/scan", node.address, node.port);
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
                            body.push_str(&format!("\nWolfStack v{}", env!("CARGO_PKG_VERSION")));
                            if let Err(e) = ai::send_alert_email(&config, &subject, &body) {
                                tracing::warn!("Failed to send critical issues email: {}", e);
                            } else {
                                tracing::info!("Sent critical issues alert email ({} issues)", critical_count);
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
                            let mut body = format!(
                                "📋 Daily Issues Report\nDate: {}\nWolfStack v{}\nNodes scanned: {}\n",
                                today, env!("CARGO_PKG_VERSION"), total_nodes
                            );
                            if all_issues.is_empty() {
                                body.push_str("\n✅ No issues detected — all systems healthy.\n");
                            } else {
                                body.push_str(&format_grouped(&all_issues, None));
                                body.push_str(&format!(
                                    "\n━━━ Summary ━━━\n{} critical, {} warning, {} info\n",
                                    critical_count, warning_count, info_count
                                ));
                            }
                            if let Err(e) = ai::send_alert_email(&config, &subject, &body) {
                                tracing::warn!("Failed to send daily issues email: {}", e);
                            } else {
                                tracing::info!("Sent daily issues summary email");
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
                        let docker_count = containers::docker_list_all().len() as u32;
                        let lxc_count = containers::lxc_list_all().len() as u32;
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

                    let summary = ai::build_metrics_summary(
                        &hostname,
                        cpu_pct,
                        mem_used_gb, mem_total_gb,
                        disk_used_gb, disk_total_gb,
                        docker_count, lxc_count, vm_count,
                        uptime_secs,
                        if guest_stats_refs.is_empty() { None } else { Some(&guest_stats_refs) },
                    );
                    let _ = ai_agent_bg.health_check(&summary).await;
                }

                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Background: alerting threshold monitor (CPU, memory, disk) for ALL nodes
        let alert_cluster = cluster.clone();
        tokio::spawn(async move {
            // Wait 90 seconds after startup before first check (let metrics stabilise)
            tokio::time::sleep(Duration::from_secs(90)).await;
            info!("Alerting monitor started (90s warmup complete)");
            let mut cooldowns: std::collections::HashMap<String, std::time::Instant> = std::collections::HashMap::new();
            let mut cycle_count: u64 = 0;
            loop {
                let config = alerting::AlertConfig::load();

                // Log status on first cycle and every 10 cycles
                if cycle_count % 10 == 0 {
                    tracing::info!(
                        "Alerting status: enabled={}, has_channels={}, thresholds=CPU:{:.0}%/Mem:{:.0}%/Disk:{:.0}%, interval={}s",
                        config.enabled, config.has_channels(),
                        config.cpu_threshold, config.memory_threshold, config.disk_threshold,
                        config.check_interval_secs,
                    );
                }
                cycle_count += 1;

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
                                .map(|d| d.usage_percent)
                                .fold(0.0_f32, f32::max);

                            tracing::debug!(
                                "Alert check: {} — CPU {:.1}%/{:.0}%, Mem {:.1}%/{:.0}%, Disk {:.1}%/{:.0}%",
                                node.hostname, cpu_pct, config.cpu_threshold,
                                mem_pct, config.memory_threshold,
                                disk_pct, config.disk_threshold,
                            );

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
                                    let title = format!(
                                        "[WolfStack ALERT] {} {} at {:.1}% on {}",
                                        type_label, "threshold exceeded", alert.current, display_name
                                    );
                                    let body = format!(
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
                                    tracing::info!("Threshold alert: {} {:.1}% >= {:.0}% on {}", alert.alert_type, alert.current, alert.threshold, display_name);
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
                                    tracing::info!("Recovery alert: {} {:.1}% on {} (was previously over threshold)", check_type, current_val, display_name);
                                    let cfg = config.clone();
                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        alerting::send_alert(&cfg, &t, &b).await;
                                    });
                                    alerting::clear_cooldown(&mut cooldowns, &node.id, check_type);
                                }
                            }
                    }
                }

                // Use the configured interval (re-read each loop in case user changed it)
                let interval = config.check_interval_secs.max(30);
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
