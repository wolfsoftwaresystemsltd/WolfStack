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
mod galera;
mod wolfscale;
mod vms;
mod proxmox;
mod xo;
mod truenas;
mod unraid;
mod pools;
mod mysql_editor;
mod appstore;
mod alerting;
mod predictive;
mod wolfrun;
mod statuspage;
mod ceph;
mod gluster;
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
mod dashboard_sync;
mod paths;
mod loghub;
mod ports;
mod reverse_proxy;
mod control_panel;
mod github_backup;
mod deps;
mod systemcheck;
mod security;
mod secret_audit;
mod secret_rotation;
mod at_rest_crypto;
mod services_discovery;
mod cluster_browser;
mod compat;
mod support;
mod danger;
mod plugins;
mod sql_connections;
mod netguard;
mod certbot;
mod dns_providers;
mod edge;
mod threat_intel;
mod security_audit;
mod scan_detector;
mod antivirus;
mod abuse_report;
mod diag;
mod netaddr;
mod local_ca;
#[allow(dead_code)]
mod integrations;
mod cluster_join;

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

    /// Bind address (IPv4 or IPv6 — e.g. 0.0.0.0, 192.168.1.5, ::, 2001:db8::1)
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

    /// Wipe this node's cluster membership state and exit. Deletes
    /// `self_cluster.json`, `nodes.json`, `deleted_nodes.json`, and
    /// `node_id` so that the daemon comes back up as a fresh
    /// single-node cluster on its next start. Use this when a node is
    /// stranded in a phantom old cluster (typically because the cluster
    /// name was changed on another node while this one was offline) and
    /// the management UI can't reach it cross-cluster to recover.
    /// Refuses to run while the `wolfstack` systemd unit is active —
    /// stop it first so file ops don't race the running daemon's saves.
    #[arg(long)]
    leave_cluster: bool,

    /// Modifier for `--leave-cluster`: also rotate the cluster-secret
    /// file (`/etc/wolfstack/custom-cluster-secret`) so old peers can
    /// no longer authenticate inter-node calls to this server. Has no
    /// effect without `--leave-cluster`.
    #[arg(long)]
    rotate_cluster_secret: bool,
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

    // --leave-cluster: wipe this node's cluster membership state and exit.
    // Refuses while the wolfstack service is active to avoid the running
    // daemon's `save_nodes()` racing the file deletions back into existence.
    if cli.leave_cluster {
        match agent::leave_is_service_active() {
            Some(true) => {
                eprintln!("Refusing to wipe cluster state while wolfstack.service is active.");
                eprintln!("Stop it first, then re-run this command:");
                eprintln!();
                eprintln!("    sudo systemctl stop wolfstack");
                eprintln!("    sudo wolfstack --leave-cluster{}",
                          if cli.rotate_cluster_secret { " --rotate-cluster-secret" } else { "" });
                eprintln!("    sudo systemctl start wolfstack");
                std::process::exit(1);
            }
            Some(false) => {}
            None => {
                eprintln!("warning: could not query systemctl — proceeding anyway. If the");
                eprintln!("         daemon is running it may re-create the files we delete.");
            }
        }

        let result = agent::leave_wipe_membership_files();
        println!("Cluster leave: wiping local membership state.");
        if let Some(prev) = &result.previous_cluster_name {
            println!("  Previous cluster name: {}", prev);
        }
        for f in &result.files {
            if f.cleared {
                println!("  removed  {}", f.path);
            } else if f.already_absent {
                println!("  (absent) {}", f.path);
            } else if let Some(err) = &f.error {
                eprintln!("  FAILED   {}  ({})", f.path, err);
            }
        }
        let any_failed = result.files.iter().any(|f| f.error.is_some());

        if cli.rotate_cluster_secret {
            // ORDERING: capture OLD on-disk secret before save so this
            // node's local at-rest stores (SQL / OIDC / integrations /
            // DNS / cloud / XO — none of them membership files) can be
            // re-keyed old→new. The node comes back up standalone; without
            // this its stored credentials would be undecryptable.
            let old_secret = auth::load_cluster_secret();
            let new_secret = auth::generate_cluster_secret();
            match auth::save_cluster_secret(&new_secret) {
                Ok(()) => {
                    println!("  rotated  {} (new secret written)",
                             paths::get().cluster_secret);
                    let report = secret_rotation::reencrypt_all_at_rest(&old_secret, &new_secret);
                    println!("  re-keyed {} at-rest secret(s){}",
                             report.total(),
                             if report.errors.is_empty() { String::new() }
                             else { format!(" ({} store error(s): {})",
                                            report.errors.len(), report.errors.join("; ")) });
                }
                Err(e) => {
                    eprintln!("  FAILED   rotate cluster secret: {}", e);
                    std::process::exit(2);
                }
            }
        }

        println!();
        if any_failed {
            eprintln!("Done with errors — see above. The daemon may still come up");
            eprintln!("partially cleared on next start; investigate the failed paths.");
            std::process::exit(2);
        }
        println!("Done. Start the daemon to bring this node up as a fresh");
        println!("single-node cluster:");
        println!();
        println!("    sudo systemctl start wolfstack");
        return Ok(());
    }

    if cli.rotate_cluster_secret {
        eprintln!("--rotate-cluster-secret has no effect without --leave-cluster.");
        eprintln!("To rotate the cluster secret on a running cluster, use the");
        eprintln!("management UI: Settings → Security → Generate New Cluster Secret.");
        std::process::exit(1);
    }

    // Load persistent port config; CLI --port still overrides the API port
    // for one-off launches and pulls inter_node along with it (api+1) so the
    // pair stays coherent — matches the previous behaviour where inter_node
    // was always derived from --port. inter_node here is just the *preferred*
    // value — the actual bind (only on self-signed installs in v23.12+) goes
    // through ports::reserve_inter_node_port and may shift if 8554 is taken
    // by Frigate/MediaMTX/etc.
    let port_cfg = ports::PortConfig::load();
    let api_port: u16 = cli.port.unwrap_or(port_cfg.api);
    let inter_node_pref: u16 = match cli.port {
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

    // Load or generate node ID. An empty / whitespace-only file is
    // treated the same as a missing file — pre-fix, an empty file
    // silently produced `node_id = ""`, which then leaked through
    // every StatusReport. Peers stored `self_id: null` for this node
    // forever (poll handler at agent/mod.rs preserves the previous
    // self_id when the incoming string is empty), and any subnet
    // route or other config pinned to this node's self_id became
    // unmatchable in the strict-cluster guard.
    let node_id_file = paths::get().node_id_file;
    let existing = std::fs::read_to_string(&node_id_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let node_id = match existing {
        Some(id) => id,
        None => {
            let id = format!("ws-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            if let Some(dir) = std::path::Path::new(&node_id_file).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(&node_id_file, &id) {
                tracing::error!("Failed to persist node ID: {}", e);
            }
            id
        }
    };
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    info!("");
    info!("  🐺 WolfStack v{}", env!("CARGO_PKG_VERSION"));
    info!("  ──────────────────────────────────");
    info!("  Node ID:    {}", node_id);
    info!("  Hostname:   {}", hostname);
    info!("  Dashboard:  http://{}", netaddr::host_port(&cli.bind, api_port));
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

    // Stage 2 of the cluster-secret migration: if this is a fresh
    // install (no on-disk custom secret + no peers in nodes.json),
    // generate a per-install secret right now so we never start up
    // using the built-in default that every WolfStack installation
    // shares. The helper refuses to act on anything that looks like
    // an existing install — see auth::auto_generate_for_fresh_install.
    let _ = auth::auto_generate_for_fresh_install();

    // Load per-installation cluster secret for inter-node authentication
    let cluster_secret = auth::load_cluster_secret();

    // Initialise the shared at-rest crypto module with the active
    // cluster secret. After this point, dns_providers / edge::store /
    // xo can use AES-256-GCM v2 encryption for new credential values;
    // legacy v1 XOR values still decrypt transparently via the
    // fallback path. Must run BEFORE any module that might encrypt.
    at_rest_crypto::init(&cluster_secret);

    // Stage 5 of the cluster-secret migration: log whether the
    // built-in default is currently accepted, so operators can see
    // their WOLFSTACK_REJECT_DEFAULT_SECRET env flag is being honoured.
    if !auth::default_secret_accepted() {
        info!("Cluster secret: built-in default REJECTED (WOLFSTACK_REJECT_DEFAULT_SECRET set). \
               Only the per-install secret will authenticate inter-node calls.");
    }
    if secret_audit::is_using_default_cluster_secret() {
        info!("Cluster secret: still using the built-in default — see \
               Settings → Security to rotate to a per-install value.");
    }

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
        // Heal LXC configs that carry an apparmor key this host's LXC can't
        // parse (Fedora/SELinux builds) BEFORE autostart, so broken containers
        // list and start again. No-op on AppArmor hosts / Proxmox.
        containers::lxc_migrate_apparmor_configs();
        containers::lxc_autostart_all();
        networking::apply_all_wireguard_bridges();
        kubernetes::apply_all_wolfnet_routes();
        plugins::start_all_backends();
    });

    // HTTPS-by-default: if the operator has NOT opted out (--no-tls),
    // has NOT supplied --tls-cert/--tls-key, and there's no existing
    // cert anywhere `find_tls_certificate()` would discover (operator
    // wolfstack/tls/, certbot CLI, /etc/letsencrypt/live, Proxmox VE),
    // auto-generate a self-signed cert at the standard
    // /etc/wolfstack/tls/{cert,key}.pem path. The existing TLS
    // discovery below picks it up via wolfstack_local_cert_paths()
    // with zero changes to the decision tree.
    //
    // Pre-v23.11 behaviour was to silently fall back to HTTP-only in
    // this case — which broke inter-node federation HTTPS calls and
    // surprised browsers expecting HTTPS on :8553. Self-signed is the
    // right default for the thousands of installs without a public
    // domain; operators who configure Let's Encrypt or supply their
    // own cert are unaffected (early-returns above keep their path).
    if !cli.no_tls && cli.tls_cert.is_none() && cli.tls_key.is_none() {
        if installer::find_tls_certificate(cli.tls_domain.as_deref()).is_none() {
            let detected_hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "wolfstack".into());
            let ips = installer::self_signed::detect_local_ips();
            if let Err(e) = installer::self_signed::ensure_self_signed_cert(
                &detected_hostname, &ips,
            ) {
                tracing::warn!(
                    "TLS: could not auto-generate self-signed cert ({}) — will fall back to HTTP-only. Run wolfstack with --tls-cert/--tls-key to provide one manually.",
                    e
                );
            }
        }
    }

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
            one_time_join_tokens: Arc::new(cluster_join::OneTimeTokens::new()),
            // Bootstrap grants are consumed seconds after minting (handshake →
            // immediate secret push), so a tight 120s TTL minimises the window.
            bootstrap_grants: Arc::new(cluster_join::OneTimeTokens::with_ttl(
                std::time::Duration::from_secs(120),
            )),
            pbs_restore_progress: Mutex::new(Default::default()),
            ai_agent: ai_agent.clone(),
            cached_status: cached_status.clone(),
            wolfrun: wolfrun_state.clone(),
            wolfflow: wolfflow_state.clone(),
            statuspage: statuspage_state.clone(),
            tls_enabled,
            login_limiter: Arc::new(auth::LoginRateLimiter::new()),
            scan_detector: Arc::new(scan_detector::ScanDetector::new()),
            diag_control: Arc::new(diag::Control::new()),
            wireguard_bridges: Arc::new(std::sync::RwLock::new(networking::load_wireguard_bridges())),
            patreon: Arc::new(patreon::PatreonState::new()),
            loghub: Arc::new(loghub::LogHubState::new(node_id.clone())),
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
            antivirus: Arc::new(antivirus::AntivirusState::load()),
        });

        // Let the networking module refresh the live bridge map when a
        // cluster rename re-keys a WireGuard bridge from outside an HTTP
        // handler (gossip self-adoption / agent push have no AppState).
        networking::register_shared_wireguard_bridges(app_state.wireguard_bridges.clone());

        // Strict cluster scoping self-heal (v24.38.4): NAS instances
        // registered before cluster tags existed are unassigned. They live
        // in THIS node's store, and this node belongs to exactly one
        // cluster — adopt them into it so every Storage page is strictly
        // one cluster's view. One-time per instance; no-op once tagged.
        {
            let label = agent::ClusterState::self_cluster_label();
            let tn = truenas::TrueNasStore::load().adopt_unassigned_into_cluster(&label);
            let ur = unraid::UnraidStore::load().adopt_unassigned_into_cluster(&label);
            if tn + ur > 0 {
                tracing::info!("storage scoping: adopted {} TrueNAS + {} Unraid unassigned instance(s) into cluster '{}'", tn, ur, label);
            }
        }

        // Wire fleet-wide lockout propagation hooks into the limiter.
        // The limiter calls these whenever a lock/unlock happens —
        // regardless of whether the source was the WolfStack web UI,
        // sshd, or pvedaemon. One pathway, three covered surfaces.
        //
        // **CRITICAL THREADING**: these hooks are called from BOTH
        // the async actix-web handlers (tokio context, fine) AND from
        // log_monitor's blocking std::thread (NOT in tokio context).
        // Using bare `tokio::spawn(..)` panics when called from a
        // non-tokio thread, which silently killed the log_monitor
        // thread and made SSH/PVE brute-force blocks never propagate.
        //
        // Fix: capture a `tokio::runtime::Handle` at hook install
        // time and use `handle.spawn(..)` from inside the closure.
        // Handle is the runtime-agnostic spawn API — callable from
        // any thread that knows the runtime exists.
        let rt_handle = tokio::runtime::Handle::current();
        {
            let cluster_block = app_state.cluster.clone();
            let cluster_unblock = app_state.cluster.clone();
            let self_id_block = app_state.cluster.self_id.clone();
            let self_id_fed = self_id_block.clone();
            let federations_block = app_state.federations.clone();
            // Use the LOADED cluster secret (the operator's custom value
            // if they have one set in /etc/wolfstack/cluster-secret),
            // NOT the hardcoded builtin default. Existing federation
            // calls all use this — and the receiving endpoints'
            // require_auth() accepts loaded + builtin + on-disk so the
            // sender always authenticates correctly.
            let secret_block = app_state.cluster_secret.clone();
            let secret_unblock = secret_block.clone();
            let rt_block = rt_handle.clone();
            let rt_unblock = rt_handle.clone();
            app_state.login_limiter.install_propagation_hooks(
                std::sync::Arc::new(move |ip, secs| {
                    let cluster = cluster_block.clone();
                    let secret = secret_block.clone();
                    let ip = ip.to_string();
                    let self_id = self_id_block.clone();
                    let federations = federations_block.clone();
                    let self_id_fed = self_id_fed.clone();
                    rt_block.spawn(async move {
                        // Local cluster fan-out — every WolfStack peer
                        // in THIS cluster gets the block via the
                        // existing X-WolfStack-Secret path.
                        api::propagate_kernel_block_to_peers(
                            cluster, secret, ip.clone(), secs, self_id).await;
                        // Federation fan-out — every cross-cluster
                        // federation we know about gets the block via
                        // its api_key. The federation's fleet endpoint
                        // applies + fans out within its own cluster.
                        // Loops are prevented by the federation
                        // endpoint NOT re-pushing to federations.
                        api::propagate_kernel_block_to_federations(
                            federations, ip, secs, self_id_fed).await;
                    });
                }),
                std::sync::Arc::new(move |ip| {
                    let cluster = cluster_unblock.clone();
                    let secret = secret_unblock.clone();
                    let ip = ip.to_string();
                    rt_unblock.spawn(async move {
                        api::propagate_kernel_unblock_to_peers(cluster, secret, ip).await;
                    });
                }),
            );
        }
        // Install the alert hooks on the limiter + scan detector so
        // every security event (lockout, scan detection) sends a
        // Discord / Slack / Telegram / email alert stamped with the
        // cluster name + hostname. Both modules call the same shape
        // of hook (title, body) — the hook decorates with node context
        // and dispatches via alerting::send_node_alert.
        //
        // Same threading caveat as the propagation hooks above —
        // scan_detector's run_loop is a std::thread, so use rt_handle.
        {
            let cluster_for_alert_lim = app_state.cluster.clone();
            let rt_alert_lim = rt_handle.clone();
            app_state.login_limiter.install_alert_hook(std::sync::Arc::new(move |title, body| {
                let cluster_name = cluster_for_alert_lim.get_self_cluster_name();
                let hostname = hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                rt_alert_lim.spawn(async move {
                    // Failed-login / IP-blocked events — BruteForce category.
                    // Public boxes get these constantly; Simple mode suppresses.
                    crate::alerting::send_node_alert(
                        &cluster_name, &hostname,
                        crate::alerting::AlertCategory::BruteForce,
                        &title, &body,
                    ).await;
                });
            }));
            let cluster_for_alert_scan = app_state.cluster.clone();
            let rt_alert_scan = rt_handle.clone();
            app_state.scan_detector.install_alert_hook(std::sync::Arc::new(move |title, body| {
                let cluster_name = cluster_for_alert_scan.get_self_cluster_name();
                let hostname = hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                rt_alert_scan.spawn(async move {
                    // Outbound scan from THIS host — compromise indicator.
                    // Always fires (Simple AND Verbose).
                    crate::alerting::send_node_alert(
                        &cluster_name, &hostname,
                        crate::alerting::AlertCategory::Compromise,
                        &title, &body,
                    ).await;
                });
            }));
        }
        // Populate the protected-address guards BEFORE re-applying persisted
        // kernel blocks. Without this, restore_persisted_lockouts() raced the
        // 10s protection task below: it ran while both guard sets were still
        // empty, so a persisted lockout for a container IP (or a peer node)
        // was re-applied with INPUT+FORWARD DROP on every restart — the
        // klasSponsor "wolfstack made iptables rules to drop traffic from
        // those containers" symptom returning after each upgrade (round 3,
        // 2026-06-10). Heals newly-protected node IPs immediately instead of
        // 10s later, then sweeps stale WolfStack-shaped DROP rules left in
        // the kernel by versions that predate the guard.
        crate::auth::set_protected_workload_subnets(
            networking::collect_workload_subnets(),
        );
        // Install `ipset` if missing BEFORE the first ipset_available() probe
        // below (it caches its result). Debian 13 / nftables-default hosts often
        // ship without it, so the O(1) blocklist match-set never engaged and
        // WolfStack walked one DROP rule per IP — on a router that per-packet
        // FORWARD walk saturates ksoftirqd (PapaSchlumpf, recurred 2026-06-22:
        // 546 per-IP rules, no ipset). migrate_legacy_block_rules() below then
        // folds those legacy rules into the set.
        crate::auth::ensure_ipset_installed();
        for ip in crate::auth::set_protected_node_ips(app_state.cluster.wolfstack_node_ips()) {
            crate::auth::kernel_unblock_ip(&ip);
        }
        crate::auth::sweep_protected_drop_rules();
        // Migrate any legacy per-IP kernel-block rules into the ipset so an
        // existing install with a large accumulated blocklist gets the O(1)
        // match-set behaviour immediately (fixes router ksoftirqd/throughput
        // collapse — PapaSchlumpf 2026-06-17), not just for newly-blocked IPs.
        crate::auth::migrate_legacy_block_rules();
        // Restore kernel iptables rules for any non-expired lockouts
        // from the previous WolfStack process. Kernel rules survive a
        // service restart; this keeps our in-memory state aligned.
        app_state.login_limiter.restore_persisted_lockouts();
        // Start the sshd/pvedaemon log monitor. Feeds the same limiter
        // so SSH and Proxmox brute-force attacks trigger the same
        // kernel-block + fleet propagation as WolfStack-UI attacks.
        crate::auth::log_monitor::start_monitor(app_state.login_limiter.clone());
        // Start the Fleet Logs shipper + janitor threads. Both idle cheaply
        // while the feature is disabled (off by default), so this is a no-op
        // on installs that never opt in. They re-read config each tick, so
        // enabling/configuring at runtime takes effect without a restart.
        crate::loghub::start(
            app_state.loghub.clone(),
            app_state.cluster.clone(),
            app_state.cluster_secret.clone(),
        );
        // Diagnostic listener — see src/diag.rs.
        crate::diag::start(
            app_state.login_limiter.clone(),
            app_state.cluster.clone(),
            app_state.diag_control.clone(),
        );
        // Start the outbound-scan detector. Periodically samples
        // /proc/net/tcp[6] for SYN_SENT-state sockets, counts distinct
        // destinations per process across the rolling window, and
        // kills + UID-blocks any process that crosses the threshold.
        // This is what would have caught the zmap incident at minute 1.
        app_state.scan_detector.clone().start();

        // Cluster-node block protection (klasSponsor 2026-06-08). Keep the auth
        // guard's protected-IP set in sync with cluster membership so WolfStack
        // nodes never kernel-block each other, heal any pre-existing bad ban
        // once per newly-seen node IP, and fire an alert when a peer-block is
        // refused (the red banner is driven by /api/security/protected-block-events).
        {
            let cluster = app_state.cluster.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                let mut last_alerted_id: u64 = 0;
                loop {
                    tick.tick().await;
                    // Also exempt this host's own container/workload bridges
                    // (docker0/br-*/lxcbr*/virbr*) so the auto-block never
                    // firewalls a local container (klasSponsor 2026-06-08).
                    let subnets_changed = crate::auth::set_protected_workload_subnets(
                        crate::networking::collect_workload_subnets(),
                    );
                    let newly = crate::auth::set_protected_node_ips(cluster.wolfstack_node_ips());
                    // Heal pre-existing bad bans (the ones klas hit before this
                    // shipped). One-shot per newly-protected IP, plus a sweep of
                    // stale WolfStack-shaped DROP rules whenever a workload
                    // bridge appears (Docker starting late, a new compose
                    // network). iptables is a sync subprocess, so off the
                    // executor.
                    if !newly.is_empty() || subnets_changed {
                        tokio::task::spawn_blocking(move || {
                            for ip in newly { crate::auth::kernel_unblock_ip(&ip); }
                            if subnets_changed {
                                crate::auth::sweep_protected_drop_rules();
                            }
                        }).await.ok();
                    }
                    // Alert once per new refused-block event.
                    let events = crate::auth::recent_protected_block_events();
                    let newest = events.last().map(|e| e.id).unwrap_or(0);
                    if newest > last_alerted_id {
                        let fresh = events.iter().filter(|e| e.id > last_alerted_id).count();
                        let latest_ip = events.last().map(|e| e.ip.clone()).unwrap_or_default();
                        last_alerted_id = newest;
                        let extra = if fresh > 1 {
                            format!(" (and {} other peer-block attempt(s))", fresh - 1)
                        } else { String::new() };
                        crate::alerting::send_local_alert(
                            crate::alerting::AlertCategory::Posture,
                            "Refused a block against a cluster node",
                            &format!(
                                "A security trigger tried to block WolfStack cluster node IP {}{} — it is \
                                 auto-whitelisted, so the block was refused. This usually means a node \
                                 tripped brute-force/scan detection against a peer; review the Security page.",
                                latest_ip, extra
                            ),
                        ).await;
                    }
                }
            });
        }

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
                        // Storage / SMART failures — Lifecycle category. The
                        // event itself is rare (state-change-gated, not per-tick)
                        // but operators told us Simple mode should stay minimal:
                        // dashboard surfaces these, switch to Verbose to push.
                        let cat = crate::alerting::AlertCategory::Lifecycle;
                        let category_allowed = crate::alerting::should_send(&alert_cfg, cat);
                        for (_sev, title, detail) in new_alerts {
                            // decorate_local prepends `[<cluster> / <host>]`
                            // and a Cluster:/Host:/When: header — same shape
                            // every other WolfStack alert uses. We pass the
                            // bare detail as the body since decorate_local
                            // already owns the host/cluster labelling; a
                            // manual prefix here would just duplicate it.
                            let (title, body) = crate::alerting::decorate_local(&title, &detail);
                            // Webhook (Discord/Slack/Telegram). send_alert
                            // re-checks `enabled + allows(category)`, so the
                            // category_allowed guard for the email path
                            // doesn't need to be repeated here.
                            crate::alerting::send_alert(&alert_cfg, cat, &title, &body).await;
                            if category_allowed && ai_cfg.email_enabled && !ai_cfg.email_to.is_empty() {
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

        // v23.2.2 safety migration: tear down any FireHOL Level 1
        // iptables/ipset state left over from v23.2.0/v23.2.1's
        // auto-enable behaviour. Idempotent; the second-run check
        // (sentinel file) short-circuits in under a millisecond.
        // Runs BEFORE the predictive orchestrator first ticks so the
        // analyzer never observes a stale "enabled" state and tries
        // to re-install rules. Synchronous (blocking iptables calls)
        // but cheap.
        let _ = crate::predictive::threat_intel::run_safety_migration_once();

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

        // HTTP-proxy edge reconciler — keeps DNS records (Cloudflare
        // and friends) in sync with peer-health observations. Runs
        // every 30s; only the elected leader actually pushes to
        // provider APIs (others compute their view of "should I be
        // leader" and short-circuit). See `edge::reconcile::run_pass`.
        let cluster_for_edge = app_state.cluster.clone();
        let router_for_edge = app_state.router.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            // Skip the first immediate fire — startup is busy enough
            // without hammering Cloudflare in the boot path.
            tick.tick().await;
            loop {
                tick.tick().await;
                let snapshot = crate::edge::reconcile::ClusterSnapshot::from_cluster_state(&cluster_for_edge);
                let am_leader = crate::edge::reconcile::am_i_leader(&snapshot);
                if !am_leader { continue; }
                let proxies = router_for_edge.config.read().unwrap().http_proxies.clone();
                if proxies.iter().all(|p| !p.edge.manages_dns()) { continue; }
                let providers = crate::edge::CloudProviderStore::load();
                let dns_providers = crate::dns_providers::DnsProviderStore::load();
                let reports = crate::edge::reconcile::run_pass(
                    &proxies, &snapshot, &providers, &dns_providers, true,
                ).await;
                for r in &reports {
                    if r.errors.is_empty() && (r.added > 0 || r.removed > 0) {
                        tracing::info!(
                            "edge reconcile: {} → {:?} (added {} removed {} kept {})",
                            r.proxy_id, r.after, r.added, r.removed, r.unchanged
                        );
                    }
                    for e in &r.errors {
                        tracing::warn!("edge reconcile {}: {}", r.proxy_id, e);
                    }
                }
            }
        });

        // Start the WolfRouter safe-mode watcher — auto-reverts firewall
        // changes if the user doesn't confirm within the safe-mode window.
        crate::networking::router::spawn_rollback_watcher(app_state.router.clone());

        // WolfNet route push — event-driven announcement of our local
        // container routes to every cluster peer. Wakes on the
        // `WOLFNET_ROUTES_CHANGED` Notify (signalled by
        // `flush_routes_to_disk` when the route map really changes),
        // plus a 5-minute heartbeat as a safety net for peers that
        // came online during a quiet period or missed an earlier push
        // due to transient network. No polling cost during steady-
        // state — if nothing changes and all peers heard the last
        // heartbeat, the next push is 5 minutes away.
        //
        // Symmetric to the pull-based `poll_remote_nodes` path: both
        // populate the same WOLFNET_ROUTES table on the receiver, and
        // either path failing on its own doesn't take down cross-node
        // container reachability.
        //
        // Why both: the pull path can silently fail in ways the
        // receiver can't recover from on its own (TLS-trust mismatch
        // on the peer's API, cluster state missing the peer entirely,
        // a peer's /api/agent/status returning non-StatusReport JSON).
        // dreamer 2026-05-26: routes.json on dreamer correctly
        // contained `10.10.10.100→10.10.10.171` but mouse's
        // routes.json had ZERO dreamer entries, so mouse couldn't
        // reply to container traffic from regions9 — the host-to-host
        // wolfnet tunnel was fine but mouse had no `find_route` hit
        // for the container's IP. Push closes the gap from the SOURCE
        // side, so the sender doesn't need the receiver's poll path
        // to be healthy.
        // Re-load the cluster secret from disk on every push instead of
        // capturing the boot-time value — see the equivalent comment on
        // the poll loop above. A cluster_secret rotation should take
        // effect without a wolfstack restart.

        // Seed WOLFNET_ROUTES with local container routes before the
        // first push fires (T+5). On a tmpfs system /var/run/wolfnet/
        // routes.json is lost on reboot, so WOLFNET_ROUTES starts empty.
        // Without this seed the T+5 push sends an empty announce, and
        // the receiver's wolfnet_routes_announce handler wipes all
        // existing routes for this host via cache.retain().  Seeding
        // here closes the window: the push at T+5 sends real local
        // routes instead of an empty set.
        //
        // Uses update_wolfnet_routes (merge) rather than replace so we
        // don't stomp any routes that were legitimately seeded from
        // an existing routes.json (non-tmpfs systems).
        {
            let local_ips = containers::wolfnet_used_ips_cached();
            if local_ips.len() > 1 {
                let host_ip = &local_ips[0];
                let mut local_routes = std::collections::HashMap::new();
                for ip in &local_ips[1..] {
                    if !ip.is_empty() && ip != host_ip {
                        local_routes.insert(ip.clone(), host_ip.clone());
                    }
                }
                if !local_routes.is_empty() {
                    containers::update_wolfnet_routes(&local_routes);
                    info!("WolfNet: seeded {} local container route(s) into cache before first push", local_routes.len());
                }
            }
        }

        let cluster_for_push = app_state.cluster.clone();
        tokio::spawn(async move {

            // Initial push so peers learn our routes on boot without
            // waiting for the heartbeat or for a route change.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            crate::api::announce_wolfnet_routes_to_peers(
                cluster_for_push.clone(),
                auth::load_cluster_secret(),
            ).await;
            loop {
                tokio::select! {
                    _ = crate::containers::WOLFNET_ROUTES_CHANGED.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                }
                crate::api::announce_wolfnet_routes_to_peers(
                    cluster_for_push.clone(),
                    auth::load_cluster_secret(),
                ).await;
            }
        });

        // WolfNet config.toml peer route sync — pull container routes
        // from peers listed in /etc/wolfnet/config.toml. This is the
        // ground-truth pull mechanism: config.toml defines exactly which
        // nodes share this WolfNet mesh, so it doesn't depend on the
        // cluster_name matching in poll_remote_nodes.
        tokio::spawn(async {
            // Wait for wolfnet to be up and initial push to fire
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            containers::sync_wolfnet_peer_routes().await;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            tick.tick().await; // skip immediate
            loop {
                tick.tick().await;
                containers::sync_wolfnet_peer_routes().await;
            }
        });

        // LXC bridge self-heal — re-affirm lxcbr0 + its iptables rules
        // every 60s. External events (Docker daemon restart, NetworkManager
        // reload, package upgrade, admin `iptables -F`, unattended-upgrades
        // restarting lxc-net) routinely wipe the bridge and our FORWARD /
        // MASQUERADE rules. Without this tick the next recovery is the
        // next `lxc-start` going through wolfstack — which may be hours
        // away while every container is unreachable. The function is
        // idempotent (early `ip addr show` skip when the bridge is
        // healthy) and shells out to `ip` / `iptables`, so it runs on
        // the blocking pool. Mirrors the router's subnet-route
        // reconciler at `networking::router::mod.rs:2281`.
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await; // skip the immediate fire — startup just did it
            loop {
                tick.tick().await;
                let _ = tokio::task::spawn_blocking(containers::ensure_lxc_bridge).await;
            }
        });

        // One-shot at startup: adopt any native `lxc-create` LXC containers
        // the pre-fix App Store installer left orphaned into PVE, so the
        // containers WolfStack tracks match what Proxmox shows. The function
        // self-guards (no-op off Proxmox / when there are none) and is
        // idempotent; it tars + re-creates rootfs, so it runs on the blocking
        // pool rather than the async runtime.
        let _ = tokio::task::spawn_blocking(crate::appstore::reconcile_orphaned_lxc);

        // Antivirus scheduler — every 5 minutes, check whether the
        // configured schedule_hours interval has elapsed since the
        // last completed scan; if so, fire a background scan thread.
        // Per-node (each host scans its own filesystem), so no
        // leader election required.
        let av_state = app_state.antivirus.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            // Skip the very first immediate fire — boot is busy enough.
            tick.tick().await;
            loop {
                tick.tick().await;
                crate::antivirus::maybe_run_scheduled_scan(av_state.clone());
            }
        });

        // Daily config auto-backup — snapshot all WolfStack config (cluster
        // nodes, AI/storage/PBS/IP-mapping settings, backup schedules) once a
        // day to /etc/wolfstack/config-backups so a wiped or garbled config can
        // always be restored from Settings → Config Backup. This is the hole
        // the v24.29.x control-plane incident fell into — no on-box snapshot to
        // roll back to. Hourly tick + a "today already done?" guard makes it
        // at-most-once-per-day and restart-safe; the first tick fires
        // immediately so a fresh node gets a snapshot at boot. PVE creds are
        // stripped from the snapshot (build_config_bundle).
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let _ = tokio::task::spawn_blocking(|| {
                    match crate::api::maybe_write_daily_config_backup() {
                        Ok(Some(name)) => tracing::info!("config: wrote daily backup {}", name),
                        Ok(None) => {}
                        Err(e) => tracing::warn!("config: daily backup failed: {}", e),
                    }
                }).await;
            }
        });

        // If on-access scanning was previously enabled, clamonacc keeps
        // running across a wolfstack restart (it's a systemd service)
        // but the log tailer thread doesn't (in-process). Re-attach
        // the tailer at startup so findings keep flowing to the UI.
        crate::antivirus::resume_on_access_tailer_if_enabled(app_state.antivirus.clone());

        // Self-heal: if /etc/logrotate.d/clamav-freshclam is installed but the
        // `clamav` user isn't, recreate the user so the daily logrotate run
        // stops failing, and clear any stale logrotate.service failed state.
        // v24.7.4 only healed post-apt-install; piranhaSponsor's nodes were
        // already in the broken state before upgrading WolfStack, so the
        // install-time hook never fired. Idempotent — no-op on healthy hosts.
        tokio::task::spawn_blocking(crate::antivirus::self_heal_clamav_logrotate);

        // ...and re-run it periodically. logrotate.timer fires daily and can
        // fail AFTER boot (e.g. a transient lock during freshclam's rotation
        // window); systemd then keeps logrotate.service red until its next
        // *successful* run, so the predictive inbox kept re-surfacing a stale
        // failure for operators whose clamav user was already fine (sponsor
        // report 2026-06-03, 4 nodes — "restarting logrotate fixes it but it
        // comes back"). The startup hook can't catch a failure that lands
        // between reboots, so re-run the idempotent heal every 30 min: it only
        // touches logrotate when the unit is actually in a failed state, and
        // clears it the moment a re-run succeeds — no operator action needed.
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1800));
            tick.tick().await; // consume the immediate tick — startup hook covers t0
            loop {
                tick.tick().await;
                let _ = tokio::task::spawn_blocking(crate::antivirus::self_heal_clamav_logrotate).await;
            }
        });

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
                        recent_alerts.insert(key.clone(), now);

                        let title = format!("🚨 WolfStack Security — {}", f.name);
                        let mut msg = f.detail.clone();
                        if let Some(fix) = &f.install_hint {
                            msg.push_str("\n\nSuggested fix:\n");
                            msg.push_str(fix);
                        }
                        // Map each finding to an AlertCategory by stable
                        // name prefix. Only Compromise fires under Simple
                        // mode; the rest are Verbose-only "you have a
                        // recommendation" or "we blocked a scanner" noise
                        // that floods operator inboxes on any public box.
                        let category = match key.as_str() {
                            // ── Compromise indicators — fire in Simple AND Verbose ──
                            // Crypto miner running on this host.
                            n if n.starts_with("Crypto-miner") => crate::alerting::AlertCategory::Compromise,
                            // Freshly-dropped executable in /tmp or /dev/shm.
                            // `scan_tmp_binaries` was promoted from warn → critical
                            // so this path is reachable.
                            n if n.starts_with("Suspicious binary")
                                || n.starts_with("Recent executable file") =>
                                crate::alerting::AlertCategory::Compromise,
                            // ── Brute-force noise — Verbose only ──
                            n if n.starts_with("SSH brute-force") =>
                                crate::alerting::AlertCategory::BruteForce,
                            // ── Everything else from the security scanner is
                            // posture/config (PermitRootLogin, world-readable
                            // secrets, duplicate IPs, fail2ban missing, etc.)
                            _ => crate::alerting::AlertCategory::Posture,
                        };
                        // send_local_alert prepends `[<cluster> / <host>]` and
                        // a Cluster/Host/When body header so operators on
                        // multi-cluster setups know which node fired the alert.
                        crate::alerting::send_local_alert(category, &title, &msg).await;
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

        // WolfUSB SOURCE-side restore (PapaSchlumpf/wabil 2026-06-17): when THIS
        // node is the USB *host* (the exporter with the device physically
        // plugged in) and it reboots, the device used to come back unexported
        // and the target couldn't reconnect until a manual remove + re-assign.
        // `restore_assignments` above only re-establishes the TARGET side — it
        // has no branch for assignments where this node is the SOURCE. Fill that
        // gap by re-driving each such assignment through the exact recovery the
        // manual "Re-attach" button runs (`POST /api/wolfusb/reattach/{busid}`):
        // for a remote target we poke the target node (it calls back here for
        // prepare-for-export, then re-installs its mount unit + re-passes the
        // device through); a same-node assignment recovers locally.
        {
            let nid = node_id.clone();
            let secret = cluster_secret.clone();
            let cluster_usb = cluster.clone();
            tokio::spawn(async move {
                // Run after the target-side restore (5s) so a whole-cluster
                // reboot doesn't have both ends fighting over the mount unit.
                tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                let config = wolfusb::WolfUsbConfig::load();
                if !config.enabled { return; }
                let mine: Vec<wolfusb::UsbAssignment> = config.assignments.iter()
                    .filter(|a| a.source_node_id == nid)
                    .cloned()
                    .collect();
                if mine.is_empty() || !wolfusb::is_wolfusb_available() { return; }
                info!("WolfUSB: re-driving {} source-side assignment(s) after startup", mine.len());
                for a in &mine {
                    if a.target_node_id == nid {
                        // Source and target are the same node — recover locally.
                        let busid = a.busid.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            wolfusb::reattach_local(&busid, None)
                        }).await;
                        continue;
                    }
                    // Remote target — trigger its full Re-attach recovery.
                    let Some(target) = cluster_usb.get_all_nodes().into_iter()
                        .find(|n| n.id == a.target_node_id) else {
                        warn!("WolfUSB: target node {} for {} not in cluster — skipping source-side restore",
                            a.target_node_id, a.busid);
                        continue;
                    };
                    let urls = api::build_node_urls(&target.address, target.port,
                        &format!("/api/wolfusb/reattach/{}", a.busid));
                    let client = &*api::API_HTTP_CLIENT;
                    let mut ok = false;
                    for url in &urls {
                        if let Ok(r) = client.post(url)
                            .timeout(std::time::Duration::from_secs(60))
                            .header("X-WolfStack-Secret", &secret)
                            .send().await
                            && r.status().is_success()
                        {
                            ok = true;
                            break;
                        }
                    }
                    if ok {
                        info!("WolfUSB: re-attach triggered on {} for {}", target.hostname, a.busid);
                    } else {
                        warn!("WolfUSB: could not trigger re-attach on {} for {} (target offline?) — \
                               its own mount unit will keep retrying", target.hostname, a.busid);
                    }
                }
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

        // Hook A for WolfNet endpoint self-healing — one-shot startup
        // pass 30s after launch. By then the first cluster gossip cycle
        // has run and we have public_ip for any peer that's online;
        // offline peers stay roaming-only until they come back and hit
        // Hook B (the gossip-arrival check in agent::mod).
        //
        // The pass is BATCHED in a single function call: one config
        // read, all changes applied in-memory, one config write, one
        // reload/restart. This is a critical behaviour change from
        // 22.14.8 — that version called the per-peer reconciler in a
        // loop, and each call independently restarted wolfnet via
        // systemctl, which on klasSponsor's cluster (3+ NAT'd peers)
        // immediately hit systemd's default `StartLimitBurst=5/10s`
        // and left wolfnet permanently dead. Batching collapses N
        // restarts to 1.
        //
        // The batched call also scans for ORPHAN peers — wolfnet
        // config entries that aren't wolfstack cluster members but
        // have loop-inducing endpoints (klasSponsor's unifios case,
        // a UniFi router with a stale `10.100.10.1:9634` endpoint).
        //
        // Runs 30s after launch (first gossip cycle done) and then every
        // 5 minutes, so it also self-heals drift that appears at runtime —
        // notably a stale/wrong peer `allowed_ip` in config.toml (klasSponsor
        // 2026-06-04: a VPS that showed peers as 10.10.20.x instead of
        // 10.100.10.x). The batch no-ops (one config read, no write, no
        // reload) when nothing has drifted, so the periodic cadence is cheap.
        {
            let cluster_for_wnfix = cluster.clone();
            tokio::spawn(async move {
                // Initial settle delay so the first cluster poll has
                // populated peer WolfNet IPs before we self-heal the config.
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    tick.tick().await; // first tick fires immediately
                    let self_addr = cluster_for_wnfix.self_address.clone();
                    // Cluster-scope the targets. The WolfNet IP self-heal writes
                    // to /etc/wolfnet/config.toml, so it must only ever trust
                    // peers in THIS cluster — feeding another cluster's nodes in
                    // (a hostname collision on a shared /24 would slip past the
                    // subnet guard) is exactly the cross-cluster poisoning class
                    // that bit klasSponsor before (v24.3.6). Same membership test
                    // the subnet-route path uses in agent::poll.
                    let self_cluster = cluster_for_wnfix.get_self_cluster_name();
                    let targets: Vec<crate::networking::ReconcileTarget> = cluster_for_wnfix
                        .get_all_nodes()
                        .into_iter()
                        .filter(|n| !n.is_self
                            && n.node_type == "wolfstack"
                            && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster)
                        .map(|n| {
                            // Authoritative WolfNet IP = the peer's own live
                            // wolfnet0 address, recorded from gossip. Borrow
                            // n.address before it's moved into lan_address.
                            let wolfnet_ip = crate::api::lookup_node_wolfnet_ip(&n.address);
                            crate::networking::ReconcileTarget {
                                hostname: n.hostname,
                                lan_address: Some(n.address),
                                public_ip: n.public_ip,
                                wolfnet_ip,
                            }
                        })
                        .collect();
                    tokio::task::spawn_blocking(move || {
                        match crate::networking::reconcile_wolfnet_peers_batch(&self_addr, &targets) {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(
                                "WolfNet reconcile: {} peer entr{} updated",
                                n, if n == 1 { "y" } else { "ies" }
                            ),
                            Err(e) => tracing::warn!("WolfNet reconcile failed: {}", e),
                        }
                    }).await.ok();
                }
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
                    workload_subnets: networking::collect_workload_subnets(),
                    // Self's declared site tag — gossiped to peers so
                    // their cluster-sync can choose LAN-dial vs public-dial.
                    site: cluster_clone.get_node(&cluster_clone.self_id).and_then(|n| n.site),
                    // Self's operator-set display name — gossiped so peers
                    // show the chosen name, not the OS hostname.
                    display_name: cluster_clone.get_node(&cluster_clone.self_id).and_then(|n| n.display_name),
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

        // Background: poll remote nodes.
        //
        // Re-load the cluster secret from disk on every iteration. The
        // pre-fix version held a boot-time `cluster_secret.clone()` for
        // the lifetime of the process, which meant a secret rotation
        // (Settings -> Security, or fleet rotation API) only took
        // effect on the SENDER side after a full wolfstack restart —
        // even though receivers already re-read disk on every auth call
        // (`validate_inter_node_secret`). That asymmetry quietly broke
        // route propagation across an entire fleet: the poll kept
        // sending the pre-rotation secret, every peer's receiver
        // returned 403, mouse never learned dreamer's container routes,
        // dreamer never learned mouse's. `sweep_push_cluster_names`
        // gets this right (line ~1588) — bringing the poll into line.
        let cluster_poll = cluster.clone();
        let ai_agent_poll = ai_agent.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let secret = auth::load_cluster_secret();
                agent::poll_remote_nodes(cluster_poll.clone(), secret, Some(ai_agent_poll.clone())).await;
            }
        });

        // Background: retroactive cluster-name sweep.
        // Heals existing fleets that were joined before C1-Fix-2: pushes
        // each peer's cluster_name (stored on this node's nodes.json
        // from the original add_node call) to the peer's
        // /api/agent/cluster-name. Receiver writes self_cluster.json,
        // per-node WolfRouter preflight goes green.
        //
        // Fundamentally one-shot: once a peer's self_cluster.json is
        // written, every subsequent sweep is a no-op (idempotent write).
        // 30-minute cadence is enough to catch the only case that needs
        // re-firing — a peer that was offline during the previous
        // sweep — without spam. First sweep at T+30s handles the
        // post-upgrade case immediately.
        //
        // Reads the cluster secret fresh from disk each iteration so a
        // Stage-3 rotation doesn't strand the sweep with a stale value.
        let cluster_sweep = cluster.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            loop {
                let secret = auth::load_cluster_secret();
                agent::sweep_push_cluster_names(cluster_sweep.clone(), secret).await;
                tokio::time::sleep(Duration::from_secs(1800)).await;
            }
        });

        // Background: identity-intent reconcile sweep. Re-pushes operator
        // renames (display_name) and moves (cluster_name) to each owning node
        // until its self-report confirms the value, then clears the intent.
        // This is what makes an edit to an offline/blipped node "apply on
        // reconnect" instead of silently reverting. 60s cadence; first run at
        // T+20s catches a node that was offline during the edit.
        let cluster_intents = cluster.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            loop {
                let secret = auth::load_cluster_secret();
                agent::sweep_identity_intents(cluster_intents.clone(), secret).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: control-plane replication sweep. Converges cluster
        // membership (so ANY node shows the whole fleet, not just the node the
        // cluster was built on) AND replicates WolfStack users + auth config
        // last-write-wins, so a user created on one node can log in on any
        // node. 30s cadence heals peers that were offline when a change's
        // immediate push fired. Secret re-read each tick (survives rotation).
        let cluster_repl = cluster.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            loop {
                let secret = auth::load_cluster_secret();
                agent::sweep_replicate_control_plane(cluster_repl.clone(), secret).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
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

        // Background: clean up duplicate IPs on `br-pt-*` slaves (every
        // 60s). Bridge-creation flushes the slave's IP, but NetworkManager
        // / systemd-networkd / dhclient on the slave often re-add it
        // afterwards — leaving the same IP on both the slave and the
        // bridge, plus duplicate routes. PapaSchlumpf's `ens1` /
        // `br-pt-ens1` both had 10.10.10.1/24 with two routes for
        // 10.10.10.0/24 from this exact race. The reconciliation only
        // removes IPs from the slave that ALSO exist on the bridge —
        // never the slave's only address.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                tokio::task::spawn_blocking(|| {
                    networking::cleanup_passthrough_slave_ips();
                }).await.ok();
            }
        });

        // Background: reconcile IP mappings (DNAT rules) until every
        // enabled mapping has its iptables rules in place. The
        // synchronous startup pass at boot fails silently when wolfnet0
        // isn't ready yet — typical right after a reboot, before
        // WireGuard establishes the mesh and assigns the wolfnet0
        // address. Without this loop, a node that boots with WolfStack
        // starting before WolfNet has no DNAT rules and the operator
        // only sees a `warn!` line in journalctl that nobody reads
        // (PapaSchlumpf's Frigate / Home Assistant
        // mapped-but-unreachable symptom). The retry tick is 5s while
        // any mapping is still failing, 30s once everything's settled.
        // `apply_ip_mappings` is idempotent — `apply_mapping_rules`
        // calls `purge_mapping_rules` first — so re-running over a
        // healthy state is a safe ~2 iptables ops per mapping.
        tokio::spawn(async move {
            let mut interval_secs = 30u64;
            loop {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                let failed = tokio::task::spawn_blocking(networking::apply_ip_mappings)
                    .await
                    .unwrap_or(0);
                interval_secs = if failed > 0 { 5 } else { 30 };
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

        // Background: backup schedule checker (every 60s).
        // check_schedules() is synchronous and ultimately runs
        // qemu-img convert / tar over multi-GB VM disks — call it via
        // spawn_blocking so a long backup can't starve the Tokio
        // worker threads (which would also block the actix workers
        // that share the same runtime).
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if let Err(e) = tokio::task::spawn_blocking(backup::check_schedules).await {
                    // A panic inside check_schedules would surface here
                    // as a JoinError. Log it so we don't silently lose
                    // the scheduler loop (the spawn itself keeps the
                    // loop alive because each iteration spawns afresh).
                    tracing::error!("backup::check_schedules panicked: {}", e);
                }
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

        // Background: image watcher — periodic check + auto-apply for
        // Docker container image updates. The check populates a cache
        // that the UI reads; the auto-apply step is gated by:
        //   - Per-container `AutoUpdate` policy
        //   - Cluster-wide maintenance window (cron + duration); when
        //     no window is configured, applies fire immediately on
        //     detection.
        //   - `max_parallel_updates` (default 1) bound via a Semaphore
        //     so a host with 20 containers doesn't get crushed by 20
        //     concurrent docker pulls.
        // Each applied update is recorded as an `ImageUpdateEvent` in
        // `config.update_history` (capped at the most-recent 200) so
        // the operator has a full audit trail.
        {
            let iw_cache = app_state.image_watcher_cache.clone();
            tokio::spawn(async move {
                use crate::containers::image_watcher as iw;
                tokio::time::sleep(Duration::from_secs(120)).await;
                loop {
                    let config = iw::ImageWatcherConfig::load();
                    if config.enabled {
                        // ── CHECK pass ──
                        let results = iw::check_all_containers(&config).await;
                        {
                            let mut cache = iw_cache.write().unwrap();
                            for r in &results {
                                cache.insert(r.container_name.clone(), r.clone());
                            }
                        }

                        // ── APPLY pass ──
                        // Only fires when a maintenance window is open
                        // (or no schedule is set). Returns the events
                        // produced so we can fold them into history.
                        let now = chrono::Utc::now().naive_utc();
                        if config.auto_apply_window_open(now) {
                            let pending: Vec<String> = results.iter()
                                .filter(|r| r.update_available && r.error.is_none())
                                .map(|r| r.container_name.clone())
                                .filter(|name| config.policy_for(name).is_auto_apply())
                                .collect();
                            if !pending.is_empty() {
                                let max_parallel = config.max_parallel_updates.max(1);
                                tracing::info!(
                                    "image_watcher: auto-applying {} update(s) (max_parallel={})",
                                    pending.len(), max_parallel,
                                );
                                let sem = std::sync::Arc::new(
                                    tokio::sync::Semaphore::new(max_parallel),
                                );
                                let mut handles = Vec::new();
                                for name in pending {
                                    let sem = sem.clone();
                                    let cfg = config.clone();
                                    // Keep an outer-scope copy of the
                                    // container name so a worker-join
                                    // failure can be attributed in the
                                    // audit trail. Without this the
                                    // fallback event records "<unknown>"
                                    // and the operator can't tell which
                                    // update misbehaved.
                                    let fallback_name = name.clone();
                                    handles.push(tokio::spawn(async move {
                                        let _permit = sem.acquire_owned().await
                                            .expect("semaphore closed");
                                        tokio::task::spawn_blocking(move || {
                                            iw::perform_update_blocking(&name, &cfg)
                                        }).await.unwrap_or_else(|join_err| {
                                            iw::ImageUpdateEvent {
                                                id: format!("evt-join-{}", chrono::Utc::now().timestamp()),
                                                container_name: fallback_name,
                                                image: String::new(),
                                                old_digest: String::new(),
                                                new_digest: String::new(),
                                                backup_id: None,
                                                status: iw::ImageUpdateStatus::Failed,
                                                timestamp: chrono::Utc::now().to_rfc3339(),
                                                error: Some(format!("worker join failed: {}", join_err)),
                                            }
                                        })
                                    }));
                                }
                                let mut events: Vec<iw::ImageUpdateEvent> = Vec::with_capacity(handles.len());
                                for h in handles {
                                    if let Ok(ev) = h.await {
                                        events.push(ev);
                                    }
                                }
                                // Persist the audit trail. Reload the
                                // config fresh because the apply pass
                                // can take minutes and the operator
                                // may have edited settings mid-flight.
                                if !events.is_empty() {
                                    let mut latest = iw::ImageWatcherConfig::load();
                                    latest.update_history.extend(events);
                                    let overflow = latest.update_history.len().saturating_sub(200);
                                    if overflow > 0 {
                                        latest.update_history.drain(0..overflow);
                                    }
                                    if let Err(e) = latest.save() {
                                        tracing::warn!(
                                            "image_watcher: failed to persist update history: {}", e,
                                        );
                                    }
                                }
                            }
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
                            // Aggregated daily-issues mail — Posture category
                            // (mixed bag of config/posture findings). Verbose
                            // only; Simple operators see the inbox.
                            let alert_config = crate::alerting::AlertConfig::load();
                            let posture_allowed = crate::alerting::should_send(
                                &alert_config,
                                crate::alerting::AlertCategory::Posture,
                            );
                            // Stamp the subject + body with `[<cluster> / <host>]`
                            // and the Cluster/Host/When header so the email AND
                            // the webhook recipients see the same originator
                            // metadata.
                            let (subject, body) = crate::alerting::decorate_local(&subject, &body);
                            if posture_allowed {
                                if let Err(e) = ai::send_alert_email(&config, &subject, &body) {
                                    tracing::warn!("Failed to send critical issues email: {}", e);
                                }
                            }

                            // Also send to webhook channels
                            if alert_config.enabled && alert_config.has_channels() {
                                let s = subject.clone();
                                let b = body.clone();
                                tokio::spawn(async move {
                                    crate::alerting::send_alert(
                                        &alert_config,
                                        crate::alerting::AlertCategory::Posture,
                                        &s, &b,
                                    ).await;
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
                // `check_interval_minutes == 0` is the operator's "Off"
                // setting for health checks (KO4BSR ask): the chat agent
                // stays usable but the periodic LLM probe is skipped so
                // a free/quota'd backend doesn't burn budget on idle hosts.
                // We still loop on a 5-minute cadence so re-enabling the
                // interval (or flipping agent_enabled back on) takes
                // effect within one cycle rather than at next process
                // restart.
                let (run_check, interval) = {
                    let config = ai_agent_bg.config.lock().unwrap();
                    let configured = config.is_configured();
                    let mins = config.check_interval_minutes;
                    let secs = if configured && mins > 0 {
                        mins as u64 * 60
                    } else {
                        300u64
                    };
                    (configured && mins > 0, secs)
                };

                if run_check {
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
                                if !alerting::is_in_cooldown_secs(&cooldowns, &node.id, &alert.alert_type, config.cooldown_secs) {
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

                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        // CPU/mem/disk threshold — visible on
                                        // dashboard, Simple suppresses push.
                                        // send_local_alert adds the cluster + host
                                        // labels so multi-cluster operators see
                                        // which node fired this in Discord/email.
                                        alerting::send_local_alert(
                                            alerting::AlertCategory::Threshold,
                                            &t, &b,
                                        ).await;
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

                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        // Threshold recovery — pair with the
                                        // matching breach, same category.
                                        alerting::send_local_alert(
                                            alerting::AlertCategory::Threshold,
                                            &t, &b,
                                        ).await;
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

                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        // Reboot detected — Lifecycle.
                                        alerting::send_local_alert(
                                            alerting::AlertCategory::Lifecycle,
                                            &t, &b,
                                        ).await;
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
                            if !alerting::is_in_cooldown_secs(&cooldowns, &cooldown_key, "memory", config.cooldown_secs) {
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

                                let t = title.clone();
                                let b = body.clone();
                                tokio::spawn(async move {
                                    // Container memory threshold — Threshold.
                                    alerting::send_local_alert(
                                        alerting::AlertCategory::Threshold,
                                        &t, &b,
                                    ).await;
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

                                        let t = title.clone();
                                        let b = body.clone();
                                        tokio::spawn(async move {
                                            // Container memory recovery — Threshold.
                                            alerting::send_local_alert(
                                                alerting::AlertCategory::Threshold,
                                                &t, &b,
                                            ).await;
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
                                            // WolfNet auto-recovered — Lifecycle.
                                            alerting::send_local_alert(
                                                alerting::AlertCategory::Lifecycle,
                                                &title, &body,
                                            ).await;
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
                                                // WolfNet restart failed — Lifecycle.
                                                alerting::send_local_alert(
                                                    alerting::AlertCategory::Lifecycle,
                                                    &title, &body,
                                                ).await;
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
                                            // WolfNet restart-command error — Lifecycle.
                                            alerting::send_local_alert(
                                                alerting::AlertCategory::Lifecycle,
                                                &title, &body,
                                            ).await;
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
            // v23.12: only bind the secondary plain-HTTP listener if the
            // loaded cert is self-signed. CA-signed-cert operators get
            // HTTPS-only and never collide with Frigate/MediaMTX/go2rtc/
            // GStreamer RTSP server etc. on 8554. The self-signed branch
            // also gets the auto-fallback scan (8554..=8599) so even
            // those operators can run alongside the same applications.
            // See src/installer/self_signed.rs:cert_appears_self_signed.
            let cert_is_self_signed = installer::self_signed::cert_appears_self_signed(cert_path);
            let inter_node_port: Option<u16> = if cert_is_self_signed {
                Some(ports::reserve_inter_node_port(
                    &cli.bind,
                    inter_node_pref,
                    8554..=8599,
                    &[api_port, status_port],
                ))
            } else {
                None
            };

            info!("  🔒 TLS enabled");
            info!("     Cert: {} ({})", cert_path,
                if cert_is_self_signed { "self-signed" } else { "CA-signed" });
            info!("     Key:  {}", key_path);
            info!("     HTTPS: https://{}", netaddr::host_port(&cli.bind, api_port));
            match inter_node_port {
                Some(p) => info!("     HTTP (inter-node legacy + cluster-home): http://{}", netaddr::host_port(&cli.bind, p)),
                None => info!("     HTTP (inter-node): not bound — CA-signed cert means peers use HTTPS"),
            }
            info!("     Status pages: http://{}", netaddr::host_port(&cli.bind, status_port));
            info!("");

            // Clone web_dir for status-page closure (always needed) + the
            // optional second listener closure (only constructed when bound).
            let web_dir2 = web_dir.clone();
            let app_state2 = app_state.clone();
            let app_state3 = app_state.clone();

            let https_bind = netaddr::host_port(&cli.bind, api_port);
            let https_server = HttpServer::new(move || {
                let app = App::new()
                    // Compress responses (gzip/brotli/zstd, negotiated via
                    // Accept-Encoding). web/js/app.js is ~3.9 MB uncompressed —
                    // without this every page load shipped the whole thing in
                    // the clear, which is what got reset (ERR_CONNECTION_RESET)
                    // on slow/proxied links and broke the entire UI
                    // ("toggleLayoutDropdown is not defined" = app.js never
                    // finished loading, so none of its functions existed).
                    // Compressed it's ~10x smaller and far less reset-prone.
                    .wrap(actix_web::middleware::Compress::default())
                    .app_data(app_state.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    // Cache-Control: no-cache on every response that doesn't set
                    // its own (DefaultHeaders never overwrites an explicit one).
                    // actix_files sends ETag/Last-Modified but NO Cache-Control,
                    // so browsers heuristically cached app.js/index.html for
                    // hours-days and operators ran a STALE UI after every
                    // upgrade (Gary KO4BSR 2026-06-10: phantom "connection
                    // lost" banner from a cached pre-fix heartbeat). no-cache
                    // means revalidate-always: unchanged files are still cheap
                    // 304s via ETag; changed files arrive immediately.
                    .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-cache")))
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

            // Secondary plain-HTTP listener — only on self-signed installs.
            // Construct the Option<server> upfront so the tokio::join!
            // arities stay static (join! macro can't accept a runtime
            // optional future cleanly).
            let http_server_opt = match inter_node_port {
                Some(p) => {
                    let http_bind = netaddr::host_port(&cli.bind, p);
                    let srv = HttpServer::new(move || {
                        let app = App::new()
                            // Compress responses — see the main server above
                            // (app.js is ~3.9 MB uncompressed otherwise).
                            .wrap(actix_web::middleware::Compress::default())
                            .app_data(app_state2.clone())
                            .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                            .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                            // Same stale-UI guard as the primary listeners — see
                            // the comment there (Gary KO4BSR 2026-06-10).
                            .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-cache")))
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
                    Some(srv)
                }
                None => None,
            };

            // Dedicated status page listener — plain HTTP on the configured status port
            let sp_bind = netaddr::host_port(&cli.bind, status_port);
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

            // Run the active set of listeners. Combinatorial: HTTPS is
            // always present; HTTP and SP each may or may not be. Four
            // branches; explicit so tokio::join!'s arity is fixed in
            // each.
            match (http_server_opt, sp_server) {
                (Some(http), Ok(sp)) => {
                    let (r1, r2, r3) = tokio::join!(https_server, http, sp.run());
                    r1?; r2?; r3?;
                }
                (Some(http), Err(_)) => {
                    let (r1, r2) = tokio::join!(https_server, http);
                    r1?; r2?;
                }
                (None, Ok(sp)) => {
                    let (r1, r2) = tokio::join!(https_server, sp.run());
                    r1?; r2?;
                }
                (None, Err(_)) => {
                    https_server.await?;
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
            info!("     Dashboard: http://{}", netaddr::host_port(&cli.bind, api_port));
            info!("     Status pages: http://{}", netaddr::host_port(&cli.bind, status_port));
            info!("     Tip: Use the Certificates page to request a Let's Encrypt certificate");
            info!("");

            let app_state2 = app_state.clone();

            // Start HTTP server (same as before — no breaking changes)
            let main_server = HttpServer::new(move || {
                let app = App::new()
                    // Compress responses (gzip/brotli/zstd, negotiated via
                    // Accept-Encoding). web/js/app.js is ~3.9 MB uncompressed —
                    // without this every page load shipped the whole thing in
                    // the clear, which is what got reset (ERR_CONNECTION_RESET)
                    // on slow/proxied links and broke the entire UI
                    // ("toggleLayoutDropdown is not defined" = app.js never
                    // finished loading, so none of its functions existed).
                    // Compressed it's ~10x smaller and far less reset-prone.
                    .wrap(actix_web::middleware::Compress::default())
                    .app_data(app_state.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    // Cache-Control: no-cache on every response that doesn't set
                    // its own (DefaultHeaders never overwrites an explicit one).
                    // actix_files sends ETag/Last-Modified but NO Cache-Control,
                    // so browsers heuristically cached app.js/index.html for
                    // hours-days and operators ran a STALE UI after every
                    // upgrade (Gary KO4BSR 2026-06-10: phantom "connection
                    // lost" banner from a cached pre-fix heartbeat). no-cache
                    // means revalidate-always: unchanged files are still cheap
                    // 304s via ETag; changed files arrive immediately.
                    .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-cache")))
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
            .bind(netaddr::host_port(&cli.bind, api_port))?
            .run();

            // Dedicated status page listener — plain HTTP on the configured status port
            let sp_bind = netaddr::host_port(&cli.bind, status_port);
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

/// Build the preferred inter-node URL for a given node and API path.
///
/// v23.12: returns HTTPS for TLS-enabled peers (with the surrounding HTTP
/// clients using `danger_accept_invalid_certs(true)` so self-signed certs
/// are accepted), plain HTTP for legacy `--no-tls` peers. The pre-v23.12
/// behaviour returned `http://addr:port+1` for TLS peers, which broke
/// against CA-signed-cert nodes that no longer bind the second listener.
fn node_api_url(node: &crate::agent::Node, path: &str) -> String {
    let host = netaddr::bracket_host(&node.address);
    if node.tls {
        format!("https://{}:{}{}", host, node.port, path)
    } else {
        format!("http://{}:{}{}", host, node.port, path)
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

    // HTTPS-first for TLS peers (client must accept self-signed); plain
    // HTTP on the main port for legacy `--no-tls` peers.
    let urls: Vec<String> = if tls {
        vec![format!("https://{}:{}/api/ai/exec", netaddr::bracket_host(address), port)]
    } else {
        vec![format!("http://{}:{}/api/ai/exec", netaddr::bracket_host(address), port)]
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
