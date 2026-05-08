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
mod vr_terminal;
mod storage;
mod networking;
mod backup;
mod vms;
mod proxmox;
mod xo;
mod pools;
mod mysql_editor;
mod appstore;
mod alerting;
mod predictive;
mod wolfrun;
mod statuspage;
mod ceph;
mod gateway;
mod federation;
mod array;
mod configurator;
mod patreon;
mod kubernetes;
mod icons;
mod tui;
mod wolfflow;
mod wolfagents;
mod discord_bot;
mod telegram_bot;
mod whatsapp_bot;
mod mcp;
mod wolfnote;
mod wolfusb;
mod paths;
mod ports;
mod reverse_proxy;
mod control_panel;
mod github_backup;
mod deps;
mod systemcheck;
mod security;
mod services_discovery;
mod cluster_browser;
mod compat;
mod danger;
mod plugins;
mod sql_connections;
mod netguard;
mod certbot;
mod threat_intel;
#[allow(dead_code)]
mod integrations;

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
    /// Port to listen on (overrides ports.json `api`; defaults to 8553)
    #[arg(short, long)]
    port: Option<u16>,

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

    /// Run in agent-only mode — exposes the cluster API for a master node to
    /// proxy through, but does NOT serve the management SPA. Use this on
    /// every node except the one you want to log into. Persisted via the
    /// systemd ExecStart line written by setup.sh --agent.
    #[arg(long)]
    agent: bool,

    /// Print available WolfRouter recovery snapshots and exit. Use when
    /// the WolfRouter UI itself isn't reachable (or you want to confirm
    /// what's available before logging in). Lists each snapshot with
    /// its kind (backup / quarantine), age, size, and whether it
    /// parses cleanly with this binary.
    #[arg(long)]
    wolfrouter_recover: bool,

    /// Restore a specific WolfRouter recovery snapshot to the live
    /// config.json. Pass the absolute path printed by
    /// `--wolfrouter-recover`. The currently-live config (if any)
    /// is rotated to a new `.bak.<ts>` so the rollback itself is
    /// reversible. After running this, restart the wolfstack service
    /// (`systemctl restart wolfstack`) so the restored config takes
    /// effect in the running ruleset.
    #[arg(long, value_name = "PATH")]
    wolfrouter_restore: Option<String>,
}

/// Serve the login page for unauthenticated requests to /
/// Version string used as cache-buster for static assets.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Agent-mode root handler — returned for any path the SPA would normally
/// serve. The node is functional (cluster API still bound) but this user
/// hit the wrong door: they should manage it from the cluster's master
/// node UI, not by hitting this node directly.
async fn agent_index_handler() -> HttpResponse {
    let html = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WolfStack Agent Node</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 8vh auto; padding: 0 24px; color: #1a1a1a; line-height: 1.55; }
h1 { color: #dc2626; margin-bottom: 4px; }
.muted { color: #666; font-size: 14px; }
.box { background: #f5f5f5; border-left: 3px solid #dc2626; padding: 16px 20px; border-radius: 4px; margin: 24px 0; }
code { background: #ececec; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
ol { padding-left: 22px; }
ol li { margin-bottom: 8px; }
</style>
</head>
<body>
<h1>WolfStack Agent Node</h1>
<p class="muted">This server is running in agent-only mode &mdash; the cluster API is up but the management UI is intentionally not served from this node.</p>
<div class="box">
<strong>Manage this node from your master server&rsquo;s UI.</strong> Log into the management node you set up first, then add this server via <em>Add Node</em> using its hostname or IP and the join token below.
</div>
<ol>
<li>Find this node&rsquo;s join token: <code>sudo cat /etc/wolfstack/join-token</code></li>
<li>Open the management UI on your master server (port 8553).</li>
<li>Cluster &rarr; Add Node &rarr; paste the token, hostname, and IP.</li>
</ol>
<p class="muted"><strong>If you rotated the cluster secret</strong> on the master (Settings &rarr; Security), copy <code>/etc/wolfstack/custom-cluster-secret</code> from the master to this node before the first connection &mdash; otherwise inter-node calls will fail X-WolfStack-Secret authentication.</p>
<p class="muted">To convert this node into a full management server, edit the systemd unit at <code>/etc/systemd/system/wolfstack.service</code>, remove the <code>--agent</code> flag from <code>ExecStart=</code>, then run <code>sudo systemctl daemon-reload &amp;&amp; sudo systemctl restart wolfstack</code>.</p>
</body>
</html>"#;
    HttpResponse::Ok().content_type("text/html").body(html)
}

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
                // this has become a bit of a problem on chrome browsers. PC
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
        // we're logged out switch to login
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
                .add_directive("actix_http=off".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // --show-token: print join token and exit (for CLI access without web UI)
    if cli.show_token {
        let token = api::load_join_token();
        println!("{}", token);
        return Ok(());
    }

    // --wolfrouter-recover: print recovery snapshots and exit. Used
    // when the WolfRouter UI is unreachable (e.g. the wipe regression
    // happened and the user can't get to the rollback banner because
    // the running config is empty). Prints a copy-pasteable
    // `--wolfrouter-restore <path>` invocation per snapshot.
    if cli.wolfrouter_recover {
        let snapshots = networking::router::list_recovery_snapshots();
        if snapshots.is_empty() {
            println!("No WolfRouter recovery snapshots found in {}.",
                     networking::router::ROUTER_DIR);
            println!("Looked for: config.json.bak.<unix-ts>  (rolling backups)");
            println!("            config.json.broken-<unix-ts>  (quarantined parse failures)");
            println!();
            println!("If you upgraded from a pre-fix build the wipe happened");
            println!("BEFORE rolling backups existed, so there's nothing here.");
            println!("Try `wolfstack` then visit /api/router/recovery/reconstruct");
            println!("from the WolfRouter UI to rebuild from on-disk artefacts");
            println!("(dnsmasq.d snippets + /etc/ppp/peers files).");
            return Ok(());
        }
        println!("WolfRouter recovery snapshots (newest first):");
        println!();
        for s in &snapshots {
            let age = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(s.timestamp))
                .unwrap_or(0);
            let parses = if s.parses { "parses OK " } else { "DOES NOT PARSE" };
            println!("  [{}] {}  ({} bytes, {}s old, {})",
                     s.kind, s.path, s.size_bytes, age, parses);
        }
        println!();
        println!("Restore the newest one with:");
        println!("    sudo wolfstack --wolfrouter-restore {}",
                 snapshots[0].path);
        println!();
        println!("(Then `sudo systemctl restart wolfstack` to apply.)");
        return Ok(());
    }

    // --wolfrouter-restore <path>: atomic restore of a snapshot to the
    // live config.json, then exit. The next service start picks it up.
    if let Some(snapshot_path) = cli.wolfrouter_restore.as_deref() {
        match networking::router::restore_recovery_snapshot(snapshot_path) {
            Ok(()) => {
                println!("Restored {} to live WolfRouter config.", snapshot_path);
                println!("Run `sudo systemctl restart wolfstack` to apply the");
                println!("restored config in the running ruleset.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Restore failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Load persistent port config; CLI --port still overrides the API port
    // for one-off launches and pulls inter_node along with it (api+1) so the
    // pair stays coherent — matches the previous behaviour where inter_node
    // was always derived from --port.
    let port_cfg = ports::PortConfig::load();
    let api_port: u16 = cli.port.unwrap_or(port_cfg.api);
    let inter_node_port: u16 = match cli.port {
        Some(p) => p + 1,
        None => port_cfg.inter_node,
    };
    // Status-port auto-fallback: try the configured port, scan upward if taken.
    // Persists the chosen port back to ports.json so restarts are stable.
    let status_port: u16 = ports::reserve_status_port(&cli.bind, port_cfg.status, 8550..=8599);

    // Lock down /etc/wolfstack and known sensitive files. Pre-v18.7.27
    // installs left cluster-secret, nodes.json (containing PVE tokens),
    // join-token, license.key world-readable (0644). This is a no-op on
    // already-locked-down installs; on upgraded installs it migrates
    // the permissions in place. See paths::harden_existing for scope.
    paths::harden_existing();

    // Load or generate node ID
    let node_id_file = paths::get().node_id_file;
    let node_id = if let Ok(content) = std::fs::read_to_string(&node_id_file) {
        content.trim().to_string()
    } else {
        let id = format!("ws-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        if let Some(dir) = std::path::Path::new(&node_id_file).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(&node_id_file, &id) {
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
    info!("  Dashboard:  http://{}:{}", cli.bind, api_port);
    info!("  (C)Copyright Wolf Software Systems Ltd — https://wolf.uk.com");
    info!("  By Paul Clevett and my mate Claude - I have Autism");
    // Seed LXC storage paths from any mounted storage that has LXC containers
    if let Ok(entries) = std::fs::read_dir(&paths::get().storage_mount_base) {
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

    // Set kernel networking prerequisites for WolfNet container routing
    containers::wolfnet_init();
    // Ensure lxcbr0 bridge + reapply WolfNet routes in background (can be slow on Proxmox)
    std::thread::spawn(|| {
        containers::ensure_lxc_bridge();
        containers::reapply_wolfnet_routes();
    });

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
        if let Ok(client) = crate::api::ipv4_only_client_builder().timeout(Duration::from_secs(3)).build() {
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
        api_port,
    ));

    // Initialize VM manager
    let vms_manager = vms::manager::VmManager::new();
    vms_manager.autostart_vms();

    // Run potentially slow startup tasks in background so HTTP server can bind immediately
    std::thread::spawn(move || {
        storage::auto_mount_all();
        networking::apply_ip_mappings();
        containers::lxc_autostart_all();
        networking::apply_all_wireguard_bridges();
        kubernetes::apply_all_wolfnet_routes();
        plugins::start_all_backends();
    });

    // Check if TLS will be available (so the frontend knows the correct protocol for URLs)
    let tls_enabled = if cli.no_tls {
        false
    } else if cli.tls_cert.is_some() && cli.tls_key.is_some() {
        true
    } else {
        installer::find_tls_certificate(cli.tls_domain.as_deref()).is_some()
    };

    // Initial self-update — minimal blocking, polling loop fills in details within seconds
    {
        let mut mon = monitor;
        let metrics = mon.collect();
        // Run component/runtime checks with a hard timeout so nothing can block startup
        let (components, has_docker, has_lxc, has_kvm) = {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let comps = installer::get_all_status();
                let docker = containers::docker_status().installed;
                let lxc = containers::lxc_status().installed;
                let kvm = containers::kvm_installed();
                let _ = tx.send((comps, docker, lxc, kvm));
            });
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or_else(|_| {
                    tracing::warn!("Startup: component status check timed out (10s) — will retry in polling loop");
                    (vec![], false, false, false)
                })
        };
        cluster.update_self(metrics, components, 0, 0, 0, public_ip.clone(), has_docker, has_lxc, has_kvm, tls_enabled);

        // Initialize AI agent
        let ai_agent = Arc::new(ai::AiAgent::new());

        let cached_status: Arc<std::sync::RwLock<Option<serde_json::Value>>> = Arc::new(std::sync::RwLock::new(None));

        // Initialize WolfRun orchestration state
        let wolfrun_state = Arc::new(wolfrun::WolfRunState::new());
        let wolfflow_state = Arc::new(wolfflow::WolfFlowState::new());

        // Initialize Status Page monitoring state
        let statuspage_state = Arc::new(statuspage::StatusPageState::new());

        // Predictive ops — load proposals/acks/history from disk so a
        // restart doesn't blind the analyzer for 24 hours. Acks get
        // an immediate prune of any expired entries to keep the file
        // bounded over years of operator use.
        let predictive_proposals = Arc::new(std::sync::RwLock::new(
            predictive::ProposalStore::load(),
        ));
        let predictive_acks = Arc::new(std::sync::RwLock::new({
            let mut a = predictive::AckStore::load();
            a.prune_expired();
            a
        }));
        let predictive_metrics = Arc::new(std::sync::RwLock::new(
            predictive::MetricsHistory::load(),
        ));

        // Create app state
        let monitor_arc = Arc::new(Mutex::new(mon));
        let app_state = web::Data::new(api::AppState {
            monitor: monitor_arc.clone(),
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
            wolfflow: wolfflow_state.clone(),
            statuspage: statuspage_state.clone(),
            tls_enabled,
            login_limiter: Arc::new(auth::LoginRateLimiter::new()),
            wireguard_bridges: Arc::new(std::sync::RwLock::new(networking::load_wireguard_bridges())),
            patreon: Arc::new(patreon::PatreonState::new()),
            migration_tasks: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            alert_log: Arc::new(std::sync::RwLock::new(Vec::new())),
            password_reset_tokens: Arc::new(auth::PasswordResetTokens::new()),
            oidc_pending_flows: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            image_watcher_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            integrations: Arc::new(crate::integrations::IntegrationState::new(&cluster_secret)),
            router: Arc::new(crate::networking::router::RouterState::new()),
            predictive_proposals: predictive_proposals.clone(),
            predictive_acks: predictive_acks.clone(),
            predictive_metrics: predictive_metrics.clone(),
            predictive_cluster_cache: Arc::new(std::sync::Mutex::new(None)),
            node_id: node_id.clone(),
            gateways: Arc::new(std::sync::RwLock::new(gateway::GatewayStore::load())),
            federations: Arc::new(std::sync::RwLock::new(federation::FederationStore::load())),
            gateway_cluster_cache: Arc::new(std::sync::Mutex::new(None)),
            array_cluster_cache: Arc::new(std::sync::Mutex::new(None)),
            xo: Arc::new(std::sync::RwLock::new(xo::XoStore::load())),
        });

        // Storage-array health watcher — every 60s, scan /proc/mdstat
        // and per-disk SMART. Fire an alert_log entry on first
        // observation of a degraded array, faulty disk, or
        // SMART-FAILED drive. Suppression is per-condition so we
        // don't spam the operator every minute while the same disk is
        // still faulty — only on transitions.
        {
            let alert_log = app_state.alert_log.clone();
            let cluster = app_state.cluster.clone();
            let cluster_for_label = cluster.clone();
            tokio::spawn(async move {
                let mut last_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    // list_arrays() is fast (just /proc/mdstat) but
                    // doesn't populate per-disk SMART. We need SMART
                    // for the FAILED-disk alert path, so hydrate via
                    // array_detail() per array. spawn_blocking because
                    // smartctl is a sync subprocess call.
                    let arrays = tokio::task::spawn_blocking(|| {
                        crate::array::list_arrays().into_iter()
                            .filter_map(|a| crate::array::array_detail(&a.name))
                            .collect::<Vec<_>>()
                    }).await.unwrap_or_default();
                    let hostname = cluster.get_all_nodes().into_iter()
                        .find(|n| n.is_self).map(|n| n.hostname).unwrap_or_default();
                    let cluster_name = cluster_for_label.get_self_cluster_name();

                    let mut current = std::collections::HashSet::new();
                    let mut new_alerts: Vec<(String, String, String)> = Vec::new();
                    for arr in &arrays {
                        if arr.state == "degraded" {
                            let key = format!("array_degraded:{}", arr.name);
                            current.insert(key.clone());
                            if !last_seen.contains(&key) {
                                new_alerts.push((
                                    "critical".into(),
                                    format!("Array degraded: /dev/{}", arr.name),
                                    format!("level={} disks=[{}]", arr.level,
                                        arr.disks.iter().map(|d| format!("{}({})", d.device, d.state)).collect::<Vec<_>>().join(", ")),
                                ));
                            }
                        }
                        for d in &arr.disks {
                            if d.state == "faulty" || d.state == "missing" {
                                let key = format!("array_disk:{}:{}", arr.name, d.device);
                                current.insert(key.clone());
                                if !last_seen.contains(&key) {
                                    new_alerts.push((
                                        "critical".into(),
                                        format!("Disk {} on /dev/{} is {}", d.device, arr.name, d.state),
                                        format!("model={} role={}",
                                            d.model.clone().unwrap_or_default(), d.role),
                                    ));
                                }
                            }
                            if d.smart_status.eq_ignore_ascii_case("FAILED") {
                                let key = format!("array_smart:{}", d.device);
                                current.insert(key.clone());
                                if !last_seen.contains(&key) {
                                    new_alerts.push((
                                        "critical".into(),
                                        format!("SMART failure on {}", d.device),
                                        format!("array=/dev/{} model={}", arr.name,
                                            d.model.clone().unwrap_or_default()),
                                    ));
                                }
                            }
                        }
                    }
                    if !new_alerts.is_empty() {
                        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                        // 1. Write to the in-memory alert_log so the
                        //    dashboard's Tasks panel shows the event
                        //    immediately.
                        {
                            let mut log = alert_log.write().unwrap_or_else(|e| e.into_inner());
                            let mut next_id = log.last().map(|e| e.id + 1).unwrap_or(1);
                            for (sev, title, detail) in &new_alerts {
                                log.push(api::AlertLogEntry {
                                    id: next_id,
                                    timestamp: now.clone(),
                                    severity: sev.clone(),
                                    title: title.clone(),
                                    detail: detail.clone(),
                                    hostname: hostname.clone(),
                                    cluster: cluster_name.clone(),
                                });
                                next_id += 1;
                            }
                            while log.len() > 200 { log.remove(0); }
                        }
                        // 2. Fan out to the operator's configured
                        //    channels: Discord/Slack/Telegram via the
                        //    alerting module, email via the AI module
                        //    (uses the same SMTP creds the daily
                        //    report uses). Both are best-effort — a
                        //    failed dispatch logs a warning but never
                        //    blocks the watcher.
                        let alert_cfg = crate::alerting::AlertConfig::load();
                        let ai_cfg = crate::ai::AiConfig::load();
                        for (_sev, title, detail) in new_alerts {
                            let body = format!(
                                "Host: {}\nCluster: {}\n\n{}",
                                hostname, cluster_name, detail
                            );
                            crate::alerting::send_alert(&alert_cfg, &title, &body).await;
                            if ai_cfg.email_enabled && !ai_cfg.email_to.is_empty() {
                                let cfg = ai_cfg.clone();
                                let subj = title.clone();
                                let b = body.clone();
                                tokio::task::spawn_blocking(move || {
                                    if let Err(e) = crate::ai::send_alert_email(&cfg, &subj, &b) {
                                        tracing::warn!(
                                            target: "wolfstack::array",
                                            "email dispatch failed: {}", e
                                        );
                                    }
                                });
                            }
                        }
                    }
                    last_seen = current;
                }
            });
        }

        // Storage-array scheduler — runs every 60s, fires parity
        // checks when their cron expression matches the current
        // minute. Lightweight (one /etc/wolfstack/arrays.json read +
        // one cron-match per schedule per minute); doesn't run anything
        // until an actual schedule is configured.
        {
            tokio::spawn(async move {
                let mut last_minute = String::new();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                    let now = chrono::Local::now().naive_local();
                    let minute_key = now.format("%Y-%m-%dT%H:%M").to_string();
                    if minute_key == last_minute { continue; }
                    last_minute = minute_key;

                    let cfg = crate::array::ArrayConfig::load();
                    for sched in cfg.schedules {
                        if !sched.enabled { continue; }
                        if !crate::wolfflow::cron_matches(&sched.cron, &now) { continue; }
                        let array = sched.array.clone();
                        let action = sched.action.clone();
                        tokio::task::spawn_blocking(move || {
                            match crate::array::parity_check(&array, &action) {
                                Ok(_) => tracing::info!(target: "wolfstack::array",
                                    "scheduled parity {} started on /dev/{}", action, array),
                                Err(e) => tracing::warn!(target: "wolfstack::array",
                                    "scheduled parity on /dev/{} failed: {}", array, e),
                            }
                        });
                    }
                }
            });
        }

        // Reconcile orphan daemon configs (Samba snippets / NFS exports
        // / mount trees that aren't backed by a gateway in our store)
        // and re-apply every persisted gateway. Mounts and daemon
        // configs may have been wiped by a reboot; this brings them
        // back without operator action.
        //
        // KNOWN restart-window: this runs as an async task spawned
        // alongside the HTTP listener, so during the first few seconds
        // after start-up the API will report each gateway with a
        // "not running" runtime row before the apply loop completes.
        // The reconciler purges orphans before the loop runs so we
        // never serve stale state — just briefly report it as
        // not-yet-applied. Acceptable trade-off vs. blocking the API
        // listener on a potentially slow mount sequence (NFS sources
        // can stall for tens of seconds on a missing server).
        {
            let store = app_state.gateways.clone();
            let node_id_for_apply = node_id.clone();
            tokio::spawn(async move {
                {
                    let s = store.read().unwrap_or_else(|e| e.into_inner());
                    crate::gateway::reconcile_on_startup(&s, &node_id_for_apply);
                }
                let snapshot: Vec<crate::gateway::Gateway> = {
                    let s = store.read().unwrap_or_else(|e| e.into_inner());
                    s.gateways.values().cloned().collect()
                };
                let me = node_id_for_apply.clone();
                for g in snapshot {
                    // Only the owner node serves a gateway in v1.0.
                    // Peers hold the config (so the cluster panel can
                    // surface it) but don't write Samba snippets or
                    // mount sources locally — that would mean two
                    // hosts serving the same share name with diverged
                    // tdbsam state.
                    let owner = if g.origin_node_id.is_empty() {
                        // Pre-v22.9 configs that pre-dated the field
                        // get retroactively assigned to whichever node
                        // first re-applies them. This mirrors the
                        // "first node that boots is the owner" model
                        // and is fine because pre-v22.9 there was only
                        // one node anyway.
                        true
                    } else {
                        g.origin_node_id == me
                    };
                    if !owner {
                        tracing::debug!(
                            target: "wolfstack::gateway",
                            "skipping startup apply for '{}' — owned by '{}'",
                            g.name, g.origin_node_id
                        );
                        continue;
                    }
                    match crate::gateway::orchestrator::apply(&g) {
                        Ok(rt) => {
                            let mut s = store.write().unwrap_or_else(|e| e.into_inner());
                            s.runtime.insert(g.id.clone(), rt);
                            tracing::info!(target: "wolfstack::gateway", "gateway '{}' re-applied on startup", g.name);
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "wolfstack::gateway",
                                "gateway '{}' failed to re-apply on startup: {}",
                                g.name, e
                            );
                        }
                    }
                }
            });
        }

        // Predictive ops orchestrator — 5-min loop that samples
        // disks, records into history, runs analyzers, and upserts
        // proposals into the inbox. Ack/snooze/dismiss are honoured
        // before any proposal is materialised. Threshold + first-
        // appearance notification dispatch landed in convergence
        // A+B — orchestrator now reads SystemMetrics off the shared
        // monitor and fires alerting channels on Critical/High.
        {
            let p = predictive_proposals.clone();
            let a = predictive_acks.clone();
            let m = predictive_metrics.clone();
            let mon = monitor_arc.clone();
            let n = node_id.clone();
            tokio::spawn(predictive::orchestrator::run_loop(p, a, m, mon, n));
        }

        // WolfStack Pools orchestrator — drives in-flight pools
        // (`provisioning` → `leader_up` → `live`) by polling backend
        // VM IPs and joining followers to the leader's cluster.
        // 30 s tick. No state shared with the rest of the daemon —
        // it operates entirely off /etc/wolfstack/pools.json.
        tokio::spawn(crate::pools::orchestrator::run_loop());

        // Start the WolfRouter safe-mode watcher — auto-reverts firewall
        // changes if the user doesn't confirm within the safe-mode window.
        crate::networking::router::spawn_rollback_watcher(app_state.router.clone());

        // Security scanner background loop — runs posture + active-attack
        // checks on a timer and fires alerts via Discord/Slack/Telegram/
        // email when a critical-severity finding appears (SSH brute-force,
        // crypto miner, world-readable cluster_secret, etc). Cooldown keeps
        // the same finding from spamming channels.
        //
        // Interval is operator-configurable via Settings → Alerting
        // (`security_scan_interval_secs`, default 4 h). Each scan does
        // journalctl/lsof/port-probe work that costs CPU + (when AI
        // assistance is on) tokens — at 15 min that adds up across a
        // cluster. 4 h still catches attackers within the hour at worst
        // and operators can run on-demand scans via /api/system-check.
        // Clamped to a 60-second floor so misconfiguration can't turn
        // it into a busy-loop.
        tokio::spawn(async move {
            // Startup delay so the first scan happens after cluster discovery
            // settles — avoids noisy "scanner errored" at boot.
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut recent_alerts: std::collections::HashMap<String, std::time::Instant> =
                std::collections::HashMap::new();
            let cooldown = std::time::Duration::from_secs(60 * 60);
            loop {
                // Run the synchronous scan off the async executor.
                let findings = tokio::task::spawn_blocking(
                    crate::security::run_security_checks
                ).await.unwrap_or_default();

                // Load alert config fresh each iteration so toggle changes
                // take effect without a restart.
                let cfg = crate::alerting::AlertConfig::load();
                if cfg.enabled {
                    for f in &findings {
                        // Only `Missing` (which we use as "critical" severity)
                        // goes to alerts — warnings live in the System Check
                        // UI, don't page operators at 3am.
                        if !matches!(f.status, crate::systemcheck::DepStatus::Missing) {
                            continue;
                        }
                        // Dedup key: strip everything after an opening
                        // parenthesis so dynamic counts ("3 IPs, 47
                        // attempts") don't create a new key every
                        // iteration and defeat the cooldown. Stable
                        // prefix == same-attack dedup, while a NEW kind
                        // of finding gets its own bucket.
                        let key = f.name
                            .split('(')
                            .next().unwrap_or(&f.name)
                            .trim()
                            .to_string();
                        let now = std::time::Instant::now();
                        if let Some(prev) = recent_alerts.get(&key) {
                            if now.duration_since(*prev) < cooldown { continue; }
                        }
                        recent_alerts.insert(key, now);

                        let title = format!("🚨 WolfStack Security — {}", f.name);
                        let mut msg = f.detail.clone();
                        if let Some(fix) = &f.install_hint {
                            msg.push_str("\n\nSuggested fix:\n");
                            msg.push_str(fix);
                        }
                        crate::alerting::send_alert(&cfg, &title, &msg).await;
                    }
                }

                // Prune cooldown map entries older than 2× cooldown — stops
                // it growing unbounded over weeks of uptime.
                let prune_cutoff = std::time::Duration::from_secs(60 * 60 * 2);
                let now = std::time::Instant::now();
                recent_alerts.retain(|_, t| now.duration_since(*t) < prune_cutoff);

                // Re-read interval every iteration so a settings change
                // applies on the next sleep without needing a restart.
                // 60-second floor stops accidental zero/tiny values from
                // turning the scanner into a busy loop.
                let interval = crate::alerting::AlertConfig::load()
                    .security_scan_interval_secs
                    .max(60);
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        });

        // Re-apply the persisted router config (WAN, LAN DHCP/DNS,
        // firewall) on startup. Before this existed, every reboot of a
        // WolfStack-as-router host dropped its WAN link, LAN DHCP, and
        // firewall rules until a human clicked Apply in the UI — while
        // Docker and Proxmox happily auto-started their containers/VMs
        // into a network with no path to the internet. Spawn-blocking
        // so iptables/dnsmasq/pppd subprocess work doesn't hold up the
        // async runtime, with a small delay so sysinfo metrics and
        // cluster discovery initialize first.
        {
            let router_state = app_state.router.clone();
            let nid = node_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                tokio::task::spawn_blocking(move || {
                    // Restore threat-intel ipsets BEFORE the router applies its
                    // ruleset. Without this, a host reboot would leave the
                    // ipsets empty/missing and `iptables-restore --test` would
                    // reject the rule that references them, leaving the user
                    // un-protected until they re-enable from the UI.
                    crate::threat_intel::startup();
                    crate::networking::router::apply_on_startup(router_state, &nid);
                }).await.ok();
            });
        }

        // Background dnsmasq watchdog. Re-applies any LAN whose dnsmasq
        // crashed / was killed / never bound :53 to router_ip. Per-LAN
        // circuit breaker stops loops on permanently broken configs.
        // First tick is ~90s after spawn so the startup apply above has
        // settled.
        crate::networking::router::spawn_dnsmasq_watchdog(
            app_state.router.clone(),
            node_id.clone(),
        );

        // WolfAgents: one-shot migration for pre-v18.6.1 agents that
        // were created with an empty allowed_tools list. Runs before
        // the API starts serving so the first agent chat after upgrade
        // already has its tools available.
        wolfagents::migrate_empty_allowed_tools();

        // WolfUSB: init with cluster secret and restore assignments on startup
        wolfusb::init(&cluster_secret);
        {
            let nid = node_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                tokio::task::spawn_blocking(move || {
                    wolfusb::ensure_wolfusb_server();
                    wolfusb::restore_assignments(&nid);
                }).await.ok();
            });
        }

        // Background: periodic self-monitoring update
        let state_clone = app_state.clone();
        let cluster_clone = cluster.clone();
        // Clone public_ip for the background task
        // Deadman-switch tick — every second, check pending dangerous
        // ops and auto-rollback any whose TTL has expired. See
        // src/danger.rs for the design. Cheap (HashMap scan + Instant
        // elapsed check); runs unconditionally so every node enforces
        // its own rollback window even if the orchestrator's dead.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tokio::task::spawn_blocking(danger::tick).await.ok();
            }
        });

        // Threat-intel scheduler: every minute, refresh feeds when the
        // configured interval has elapsed. No-op when disabled (~1µs config
        // file read). Lives separate from the WolfRouter apply path —
        // refresh_all updates the cache + ipset, build_ruleset's hook
        // picks the result up on the next firewall apply.
        {
            let cluster_for_ti = cluster.clone();
            tokio::spawn(async move {
                threat_intel::scheduler_loop(cluster_for_ti).await;
            });
        }

        // Daily certbot renewal. Runs certbot's own `renew --quiet`
        // which is a no-op for any cert with >30 days left, so it's
        // cheap to fire every 24h. Skipped by config flag and when
        // certbot isn't installed — both checked inside renew_due.
        // First run after 60s so we don't race the service into a
        // fresh LE hit at every restart.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                tokio::task::spawn_blocking(|| {
                    let _ = certbot::renew_due();
                }).await.ok();
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        });

        let public_ip = public_ip.clone();
        let cached_status_bg = cached_status.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                // Run all blocking sysinfo/subprocess work off the async runtime
                let sc = state_clone.clone();
                let (metrics, components, docker_count, lxc_count, vm_count, has_docker, has_lxc, has_kvm) =
                    tokio::task::spawn_blocking(move || {
                        let mut monitor = sc.monitor.lock().unwrap();
                        let m = monitor.collect();
                        drop(monitor);  // release mutex before spawning subprocesses
                        let c = installer::get_all_status_cached();
                        let dc = containers::docker_count();
                        let lc = containers::lxc_count();
                        let vc = sc.vms.lock().unwrap().list_vms().len() as u32;
                        let hd = containers::has_docker_cached();
                        let hl = containers::has_lxc_cached();
                        let hk = containers::has_kvm_cached();
                        (m, c, dc, lc, vc, hd, hl, hk)
                    }).await.unwrap();
                // Record historical snapshot
                {
                    let mut history = state_clone.metrics_history.lock().unwrap();
                    history.push(&metrics);
                }

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
                    // Propagate license to cluster nodes
                    license_key: if crate::compat::platform_ready() {
                        std::fs::read_to_string(crate::compat::dm_path()).ok().map(|s| s.trim().to_string())
                    } else { None },
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

        // Background: clean up stale WolfNet kernel routes (every 60s)
        // Only runs if WolfNet is configured (cleanup fn returns early if not)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                tokio::task::spawn_blocking(|| {
                    containers::cleanup_stale_wolfnet_routes();
                }).await.ok();
            }
        });

        // Background: re-apply hardware VLAN offload disable on passthrough
        // NICs (every 30s). `ethtool -K` is session-local — when a NIC link
        // bounces (NM refresh, hostname-network restart, cable flap, driver
        // reload) the kernel resets offloads to driver defaults. Without
        // this, OPNsense + VLAN trunking gets a few good DHCP handshakes
        // then silently breaks once anything cycles the link.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                tokio::task::spawn_blocking(|| {
                    let m = vms::manager::VmManager::new();
                    m.reapply_passthrough_offloads();
                }).await.ok();
            }
        });

        // Discord bot supervisor — idle until the operator configures
        // a bot token in Settings → Alerting, then connects to the
        // Discord gateway and routes messages in agent-bound channels
        // to the right WolfAgent. Fails open: if the token is invalid
        // or Discord is unreachable, the supervisor retries every 30s
        // without affecting the rest of the server.
        // Clone the shared AppState into each surface-supervisor task
        // so Telegram / Discord-originated chats can run the full
        // tool-use loop — not just simple_chat. Without this, models
        // that follow the system-prompt tool directive (Gemini, some
        // Claude revisions) would get UNEXPECTED_TOOL_CALL errors
        // because the no-tools fallback couldn't honour the prompt.
        let discord_state = app_state.clone();
        tokio::spawn(async move {
            crate::discord_bot::supervise_forever(discord_state).await;
        });

        // Telegram receiver — same idea as Discord but simpler
        // (HTTP long-polling; no gateway, no heartbeat). Idle until
        // the operator turns on telegram_receiver_enabled AND a
        // telegram_bot_token is set.
        let telegram_state = app_state.clone();
        tokio::spawn(async move {
            crate::telegram_bot::supervise_forever(telegram_state).await;
        });

        // Background: session + login rate limiter + reset token cleanup.
        // Also sweeps expired OIDC pending-flow state tokens — pre-v18.7.30
        // that map grew without bound because the TTL was only checked
        // on successful callback lookup, so an attacker (or a buggy IdP)
        // that initiated flows without ever completing them could
        // exhaust memory.
        let sessions_cleanup = sessions.clone();
        let login_limiter_cleanup = app_state.login_limiter.clone();
        let reset_tokens_cleanup = app_state.password_reset_tokens.clone();
        let oidc_flows_cleanup = app_state.oidc_pending_flows.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                sessions_cleanup.cleanup();
                login_limiter_cleanup.cleanup();
                reset_tokens_cleanup.cleanup();
                // OIDC flows: 5 minute TTL. Walk the map and drop any
                // entry whose creation timestamp is older than that.
                {
                    let mut flows = oidc_flows_cleanup.write().unwrap();
                    let now = std::time::Instant::now();
                    flows.retain(|_state, flow| {
                        now.duration_since(flow.created_at).as_secs() < 300
                    });
                }
            }
        });

        // Background: backup schedule checker (every 60s)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                backup::check_schedules();
            }
        });

        // Cluster service discovery — runs on demand only (triggered
        // by the Cluster Browser page on load). Restore the previous
        // sweep's cache from disk so the first API hit returns
        // something instead of an empty list.
        services_discovery::restore_cache();

        // Background: cluster browser session reconciliation (every 60s)
        // — prunes ghost sessions whose container died.
        tokio::spawn(cluster_browser::run_reconcile_loop());

        // Background: WolfFlow scheduler (every 60s)
        {
            let wf_state = wolfflow_state.clone();
            let wf_cluster = cluster.clone();
            let wf_secret = cluster_secret.clone();
            let wf_ai = app_state.ai_agent.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    let due = wf_state.get_due_workflows();
                    for workflow in due {
                        let s = wf_state.clone();
                        let c = wf_cluster.clone();
                        let sec = wf_secret.clone();
                        let ai_cfg = wf_ai.config.lock().unwrap().clone();
                        tokio::spawn(async move {
                            wolfflow::execute_workflow(&s, &c, &sec, &workflow, "scheduled", Some(ai_cfg)).await;
                        });
                    }
                }
            });
        }

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

        // Background: Enterprise license heartbeat (once daily)
        // Reports server hostname, version, and cluster name to Wolf Software Systems
        // for license compliance. Fire-and-forget — never blocks the server.
        {
            let hb_cluster = cluster.clone();
            tokio::spawn(async move {
                // Initial delay — first heartbeat 5 minutes after boot
                tokio::time::sleep(Duration::from_secs(300)).await;
                loop {
                    if crate::compat::platform_ready() {
                        crate::compat::report_license_heartbeat(&hb_cluster).await;
                    }
                    tokio::time::sleep(Duration::from_secs(86400)).await; // once per day
                }
            });
        }

        // Background: image watcher — periodic check for container image updates
        {
            let iw_cache = app_state.image_watcher_cache.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(120)).await;
                loop {
                    let config = crate::containers::image_watcher::ImageWatcherConfig::load();
                    if config.enabled {
                        let results = crate::containers::image_watcher::check_all_containers(&config).await;
                        let mut cache = iw_cache.write().unwrap();
                        for r in results {
                            cache.insert(r.container_name.clone(), r);
                        }
                    }
                    let interval = config.check_interval_secs.max(300);
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                }
            });
        }

        // Background: integration health checks (every 60 seconds)
        {
            let int_state = app_state.integrations.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                loop {
                    int_state.check_all_health().await;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            });
        }

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
            let http_client = crate::api::ipv4_only_client_builder()
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
                        let ss = scan_state.clone();
                        let metrics = tokio::task::spawn_blocking(move || {
                            ss.monitor.lock().unwrap().collect()
                        }).await.unwrap();
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

                        // Write critical and warning issues to the alert log (surfaced in frontend Tasks window)
                        {
                            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                            let mut log = scan_state.alert_log.write().unwrap();
                            let mut next_id = log.last().map(|e| e.id + 1).unwrap_or(1);
                            for (cluster, host, issue) in &all_issues {
                                if issue.severity == "critical" || issue.severity == "warning" {
                                    log.push(api::AlertLogEntry {
                                        id: next_id,
                                        timestamp: now.clone(),
                                        severity: issue.severity.clone(),
                                        title: issue.title.clone(),
                                        detail: issue.detail.clone(),
                                        hostname: host.clone(),
                                        cluster: cluster.clone(),
                                    });
                                    next_id += 1;
                                }
                            }
                            // Keep only the last 200 entries
                            if log.len() > 200 {
                                let drain = log.len() - 200;
                                log.drain(..drain);
                            }
                        }

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
                            let wn_title = subject.clone();
                            let wn_body = body.clone();
                            tokio::spawn(async move {
                                wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
                            });
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
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8f9fa;color:#1a1a2e;margin:0;padding:20px;}
@media print{body{padding:0;background:#fff;}}
.container{max-width:900px;margin:0 auto;background:#ffffff;border-radius:12px;padding:24px;border:1px solid #e0e0e8;box-shadow:0 2px 8px rgba(0,0,0,0.06);}
h1{color:#1a1a2e;font-size:22px;margin-top:0;border-bottom:3px solid #dc2626;padding-bottom:8px;}
h2{color:#333;font-size:16px;margin:24px 0 12px;border-bottom:2px solid #e8e8ee;padding-bottom:8px;}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;}
th{background:#f0f1f5;color:#444;text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid #ddd;}
td{padding:8px 12px;border-bottom:1px solid #eee;color:#333;}
tr:nth-child(even) td{background:#fafbfc;}
.badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:11px;font-weight:600;}
.online{background:#dcfce7;color:#166534;}
.offline{background:#fee2e2;color:#991b1b;}
.running{background:#dcfce7;color:#166534;}
.stopped{background:#f3f4f6;color:#6b7280;}
.paused{background:#fef9c3;color:#854d0e;}
.frozen{background:#dbeafe;color:#1e40af;}
.critical{background:#fee2e2;color:#991b1b;}
.warning{background:#fef3c7;color:#92400e;}
.info{background:#dbeafe;color:#1e40af;}
.bar{height:8px;border-radius:4px;overflow:hidden;background:#e5e7eb;min-width:60px;}
.bar-fill{height:100%;border-radius:4px;}
.meta{color:#666;font-size:11px;}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}
.summary-card{background:#f8f9fa;border:1px solid #e0e0e8;border-radius:8px;padding:12px;text-align:center;}
.summary-value{font-size:24px;font-weight:700;color:#1a1a2e;}
.summary-label{font-size:11px;color:#666;text-transform:uppercase;margin-top:4px;}
a{color:#dc2626;text-decoration:none;}a:hover{text-decoration:underline;}
.ai-box{background:#fffbeb;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin-top:16px;white-space:pre-wrap;font-size:13px;line-height:1.6;color:#1a1a2e;}
.logo-bar{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #eee;}
.logo-bar img{height:28px;}
@media print{.container{box-shadow:none;border:none;} .bar-fill{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}
</style></head><body><div class="container">"#);

                            // Header
                            html.push_str(&format!(
                                r#"<h1>WolfStack Daily Report</h1>
                                <p style="color:#666;margin-top:-8px;font-size:13px;">Date: {} &bull; WolfStack v{} &bull; {} node(s) scanned</p>"#,
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
                                if critical_count > 0 { "#dc2626" } else { "#166534" }, critical_count,
                                if warning_count > 0 { "#92400e" } else { "#166534" }, warning_count,
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
                                    let cpu_color = if cpu > 80.0 { "#dc2626" } else if cpu > 50.0 { "#d97706" } else { "#16a34a" };
                                    let mem_color = if mem_pct > 90 { "#dc2626" } else if mem_pct > 70 { "#d97706" } else { "#16a34a" };
                                    (
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{:.0}%</span>"#, cpu.min(100.0), cpu_color, cpu),
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{} / {}</span>"#, mem_pct.min(100), mem_color, fmt_bytes(m.memory_used_bytes), fmt_bytes(m.memory_total_bytes)),
                                    )
                                } else {
                                    ("—".to_string(), "—".to_string())
                                };
                                let display_name = if n.hostname.is_empty() { &n.address } else { &n.hostname };
                                html.push_str(&format!(
                                    r#"<tr><td><strong>{}</strong><br><span class="meta">{} &bull; port {}</span></td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                                    display_name, n.address, n.port, status_class, status_text, cpu_str, mem_str,
                                    if n.has_docker { format!("{}", n.docker_count) } else { "—".to_string() },
                                    if n.has_lxc { format!("{}", n.lxc_count) } else { "—".to_string() },
                                    if n.has_kvm { format!("{}", n.vm_count) } else { "—".to_string() },
                                ));
                            }
                            // (Legacy Proxmox-API entries are no longer rendered — they're surfaced
                            // through the deprecation banner so the user can remove them.)
                            html.push_str("</tbody></table>");

                            // ─── Docker Containers Table ───
                            {
                                let local_docker = tokio::task::spawn_blocking(|| crate::containers::docker_list_all()).await.unwrap_or_default();
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
                                let local_lxc = tokio::task::spawn_blocking(|| crate::containers::lxc_list_all()).await.unwrap_or_default();
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
                                r#"<p style="color:#999;font-size:11px;text-align:center;margin-top:24px;border-top:1px solid #e0e0e8;padding-top:12px;">WolfStack v{} &bull; Generated {}</p>"#,
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
                    let ai_sc = ai_state.clone();
                    let (hostname, cpu_pct, mem_used_gb, mem_total_gb, disk_used_gb, disk_total_gb,
                         docker_count, lxc_count, vm_count, uptime_secs) =
                        tokio::task::spawn_blocking(move || {
                            let mut monitor = ai_sc.monitor.lock().unwrap();
                            let m = monitor.collect();
                            drop(monitor);
                            let docker_count = containers::docker_count();
                            let lxc_count = containers::lxc_count();
                            let vm_count = ai_sc.vms.lock().unwrap().list_vms().len() as u32;

                            let mem_used = m.memory_used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            let mem_total = m.memory_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            let root_disk = m.disks.iter().find(|d| d.mount_point == "/").or_else(|| m.disks.first());
                            let disk_used = root_disk.map(|d| d.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);
                            let disk_total = root_disk.map(|d| d.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);

                            (m.hostname.clone(), m.cpu_usage_percent, mem_used, mem_total,
                             disk_used, disk_total, docker_count, lxc_count, vm_count, m.uptime_secs)
                        }).await.unwrap();

                    // Legacy Proxmox-API guests no longer feed AI metrics — those entries are
                    // surfaced via the deprecation banner and not polled.
                    let guest_stats_refs: Vec<(&str, &str, u64, &str, f32)> = Vec::new();

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
                    let sample = ai::baseline::Sample {
                        ts: chrono::Utc::now().timestamp(),
                        cpu_pct,
                        mem_used_gb, mem_total_gb,
                        disk_used_gb, disk_total_gb,
                        docker_count, lxc_count, vm_count,
                    };
                    let outcome = ai_agent_bg.health_check(sample, &summary).await;
                    // AI output goes to private channels only (email +
                    // Discord/Telegram/Slack). It is NEVER posted to the
                    // public status page — host internals must not leak
                    // to anonymous viewers. On the alert→OK transition
                    // we fire a "cleared" notification so operators see
                    // the full cycle (self-gated — no-op if this host
                    // wasn't previously alerting, so every healthy ALL_OK
                    // stays silent).
                    if matches!(outcome, ai::HealthOutcome::Ok) {
                        ai_agent_bg.notify_resolved(&hostname).await;
                    }
                }

                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Background: alerting threshold monitor (CPU, memory, disk) for ALL nodes
        let alert_cluster = cluster.clone();
        let alert_secret = cluster_secret.clone();
        let alert_ai = ai_agent.clone();
        let alert_http = crate::api::ipv4_only_client_builder()
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

                            // Check thresholds.
                            //
                            // Convergence B (the predictive ops pipeline) now owns
                            // first-appearance threshold dispatch via
                            // `predictive::notify::find_first_appearance_alerts` +
                            // `dispatch_alerts`, fired from each tick of
                            // `predictive::orchestrator`. That layer:
                            //   • Has a unified Severity tier with snooze/dismiss/ack
                            //     semantics instead of the old cooldown HashMap
                            //   • Auto-resolves on `ConditionCleared` so the recovery
                            //     branch below isn't needed for thresholds it covers
                            //   • Surfaces in the Predictive Inbox alongside trend-based
                            //     findings (disk-fill ETA, container restart-loops, etc.)
                            //
                            // We keep this `triggered` binding *only* so the recovery-
                            // notification branch downstream still executes on legacy
                            // signals — it's harmless when `triggered` is empty. The
                            // primary alert-fire loop below sees zero entries and
                            // becomes a no-op.
                            //
                            // Per-node remote-peer dispatch: each cluster node runs its
                            // own predictive orchestrator; remote peers' findings are
                            // surfaced via `/api/proposals/cluster` aggregation in the
                            // Inbox UI.
                            let _ = (cpu_pct, mem_pct, disk_pct, &config);  // signal: kept for the recovery branch
                            let triggered: Vec<alerting::ThresholdAlert> = Vec::new();

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
                                    let wn_title = title.clone();
                                    let wn_body = body.clone();
                                    tokio::spawn(async move {
                                        wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
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
                                    let wn_title = title.clone();
                                    let wn_body = body.clone();
                                    tokio::spawn(async move {
                                        wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
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
                                    let wn_title = title.clone();
                                    let wn_body = body.clone();
                                    tokio::spawn(async move {
                                        wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
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

                        let docker_stats = tokio::task::spawn_blocking(|| containers::docker_stats()).await.unwrap_or_default();
                        let lxc_stats = tokio::task::spawn_blocking(|| containers::lxc_stats()).await.unwrap_or_default();

                        // Container memory threshold dispatch — RETIRED.
                        //
                        // Predictive item 5 (`predictive::container_memory`) is the
                        // canonical source for per-container memory findings. It uses
                        // the same `containers::*_stats_cached()` data this loop did,
                        // but routes through the unified Inbox with snooze/dismiss/ack
                        // semantics instead of the legacy cooldown HashMap. The
                        // first-appearance dispatch in `predictive::notify` fires the
                        // Discord/Slack/Telegram/email channels with stable severity
                        // and per-finding dedup.
                        //
                        // Keep these `_stats` bindings — they're consumed by the
                        // top-N renderer below, which is unrelated to thresholds.
                        let _ = (&docker_stats, &lxc_stats, &config);
                        let docker_alerts: Vec<alerting::ContainerAlert> = Vec::new();
                        let lxc_alerts: Vec<alerting::ContainerAlert> = Vec::new();

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
                                let wn_title = title.clone();
                                let wn_body = body.clone();
                                tokio::spawn(async move {
                                    wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
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
                                        let wn_title = title.clone();
                                        let wn_body = body.clone();
                                        tokio::spawn(async move {
                                            wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
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
                    // Check failover — promote standby containers for offline nodes
                    wolfrun::check_failover(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                    // Create standby containers for failover-enabled services
                    wolfrun::manage_standby(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
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
                // Only sync if status pages are configured
                if sp_sync.has_any_pages() {
                    statuspage::pull_from_peers(&sp_sync, &sp_sync_cluster, &sp_sync_secret).await;
                }
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
        let agent_mode = cli.agent;
        if agent_mode {
            info!("  ⚙ Agent-only mode — management SPA disabled, cluster API only");
            info!("    Manage this node from the master server's UI (Add Node).");
        } else {
            info!("  Serving web UI from: {}", web_dir);
        }
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
            info!("     HTTPS: https://{}:{}", cli.bind, api_port);
            info!("     HTTP (inter-node): http://{}:{}", cli.bind, inter_node_port);
            info!("     Status pages: http://{}:{}", cli.bind, status_port);
            info!("");

            // Clone web_dir for second closure
            let web_dir2 = web_dir.clone();
            let app_state2 = app_state.clone();
            let app_state3 = app_state.clone();

            // Start HTTPS server on main port + HTTP server on port+1 for inter-node
            let https_bind = format!("{}:{}", cli.bind, api_port);
            let https_server = HttpServer::new(move || {
                let app = App::new()
                    .app_data(app_state.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    .configure(api::configure);
                if agent_mode {
                    app.default_service(web::to(agent_index_handler))
                } else {
                    app
                        .route("/", web::get().to(index_handler))
                        .service(actix_files::Files::new("/", &web_dir).index_file("login.html"))
                }
            })
            // Tighten the lifecycle so peers churning connections (cluster
            // polling, wolfrun/statuspage broadcasts from older peers)
            // don't accumulate in CLOSE_WAIT on our side. Defaults are
            // 5s / 5s / 1s — halving them drops fd residence time ~80%
            // under peer-initiated-close workloads. Reported by Bel:
            // 26k CLOSE_WAIT on :8553 → fd exhaustion.
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            .bind_openssl(&https_bind, ssl_builder)
            .map_err(|e| {
                tracing::error!("❌ Failed to bind HTTPS on {}: {}", https_bind, e);
                e
            })?
            .run();

            let http_bind = format!("{}:{}", cli.bind, inter_node_port);
            let http_server = HttpServer::new(move || {
                let app = App::new()
                    .app_data(app_state2.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    .configure(api::configure);
                if agent_mode {
                    app.default_service(web::to(agent_index_handler))
                } else {
                    app
                        .route("/", web::get().to(index_handler))
                        .service(actix_files::Files::new("/", &web_dir2).index_file("login.html"))
                }
            })
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            .bind(&http_bind)
            .map_err(|e| {
                tracing::error!("❌ Failed to bind HTTP on {}: {}", http_bind, e);
                e
            })?
            .run();

            // Dedicated status page listener — plain HTTP on the configured status port
            let sp_bind = format!("{}:{}", cli.bind, status_port);
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
            info!("     Dashboard: http://{}:{}", cli.bind, api_port);
            info!("     Status pages: http://{}:{}", cli.bind, status_port);
            info!("     Tip: Use the Certificates page to request a Let's Encrypt certificate");
            info!("");

            let app_state2 = app_state.clone();

            // Start HTTP server (same as before — no breaking changes)
            let main_server = HttpServer::new(move || {
                let app = App::new()
                    .app_data(app_state.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    .configure(api::configure);
                if agent_mode {
                    app.default_service(web::to(agent_index_handler))
                } else {
                    app
                        .route("/", web::get().to(index_handler))
                        .service(actix_files::Files::new("/", &web_dir).index_file("login.html"))
                }
            })
            // See matching block above on the TLS path for why these
            // lifecycle knobs matter. Keep-alive / disconnect tuning
            // caps CLOSE_WAIT residence time to protect fd budget.
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            .bind(format!("{}:{}", cli.bind, api_port))?
            .run();

            // Dedicated status page listener — plain HTTP on the configured status port
            let sp_bind = format!("{}:{}", cli.bind, status_port);
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
