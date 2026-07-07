use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Proxy a GET request to the local WolfStack API
pub async fn wolfstack_get(path: &str) -> Result<serde_json::Value, String> {
    wolfstack_api(path).await
}

const DEFAULT_SECRET: &str = "wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3";

/// Get all possible cluster secrets to try (WolfStack may use custom or default)
pub fn get_cluster_secrets() -> Vec<String> {
    let mut secrets = Vec::new();
    // Custom secret (highest priority — if admin generated one)
    if let Ok(s) = std::fs::read_to_string("/etc/wolfstack/custom-cluster-secret") {
        let s = s.trim().to_string();
        if !s.is_empty() { secrets.push(s); }
    }
    // Always include the default secret
    secrets.push(DEFAULT_SECRET.to_string());
    secrets
}

pub fn get_cluster_secret() -> String {
    get_cluster_secrets().into_iter().next().unwrap_or_else(|| DEFAULT_SECRET.to_string())
}

pub fn wolfstack_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}

/// Try HTTPS first (port 8553), then HTTP on same port, then HTTP on 8554
/// Try HTTPS on 8553 first, then HTTP on 8554 (port+1)
pub fn wolfstack_urls(path: &str) -> Vec<String> {
    vec![
        format!("https://127.0.0.1:8553{}", path),
        format!("http://127.0.0.1:8554{}", path),
    ]
}

async fn wolfstack_api(path: &str) -> Result<serde_json::Value, String> {
    let client = wolfstack_client();
    let secrets = get_cluster_secrets();
    for url in wolfstack_urls(path) {
        for secret in &secrets {
            match client.get(&url)
                .header("X-WolfStack-Secret", secret)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json::<serde_json::Value>().await
                        .map_err(|e| format!("Failed to parse WolfStack response: {}", e));
                }
                Ok(_) => continue, // wrong secret or other error, try next
                Err(_) => break, // connection failed, try next URL
            }
        }
    }
    Err(format!("WolfStack request failed: could not reach WolfStack API at {}", path))
}

async fn wolfstack_post(path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = wolfstack_client();
    let secrets = get_cluster_secrets();
    for url in wolfstack_urls(path) {
        for secret in &secrets {
            match client.post(&url)
                .header("X-WolfStack-Secret", secret)
                .header("Content-Type", "application/json")
                .json(body)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json::<serde_json::Value>().await
                        .map_err(|e| format!("Failed to parse WolfStack response: {}", e));
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
    Err(format!("WolfStack POST failed: could not reach WolfStack API at {}", path))
}

/// Public wrappers for portal modules to use
pub async fn wolfstack_post_pub(path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    wolfstack_post(path, body).await
}

/// Execute a command inside a container via WolfStack's exec API
async fn container_exec(container: &str, command: &str, node_id: &str, is_self: bool) -> Result<serde_json::Value, String> {
    let path = if is_self {
        format!("/api/containers/lxc/{}/exec", container)
    } else {
        format!("/api/nodes/{}/proxy/containers/lxc/{}/exec", node_id, container)
    };
    wolfstack_post(&path, &serde_json::json!({"command": command})).await
}

/// GET /servers/nodes — list all WolfStack cluster nodes
pub async fn list_nodes(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    match wolfstack_api("/api/nodes").await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /servers/nodes/{id}/containers — list LXC containers on a node
pub async fn node_containers(path: web::Path<String>) -> HttpResponse {
    let node_id = path.into_inner();

    // Get node info
    let nodes = match wolfstack_api("/api/nodes").await {
        Ok(data) => data,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let node = nodes["nodes"].as_array()
        .and_then(|arr| arr.iter().find(|n| n["id"].as_str() == Some(&node_id)));

    let node = match node {
        Some(n) => n,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Node not found"})),
    };

    // Route through the correct node
    let is_self = node["is_self"].as_bool() == Some(true);
    let api_path = if is_self {
        "/api/containers/lxc".to_string()
    } else {
        format!("/api/nodes/{}/proxy/containers/lxc", node_id)
    };
    match wolfstack_api(&api_path).await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /servers/nodes/{id}/stats — get LXC container stats on a node
pub async fn node_container_stats(path: web::Path<String>) -> HttpResponse {
    let _node_id = path.into_inner();
    match wolfstack_api("/api/containers/lxc/stats").await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /servers/templates — list available LXC templates
pub async fn list_templates() -> HttpResponse {
    match wolfstack_api("/api/containers/lxc/templates").await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /servers/node-ips — get all node external IP overrides
pub async fn get_node_ips(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let ips: HashMap<String, String> = state.store.load("node_ips");
    HttpResponse::Ok().json(ips)
}

#[derive(Debug, Deserialize)]
pub struct SetNodeIpRequest {
    pub node_id: String,
    pub external_ip: String,
}

/// PUT /servers/node-ips — set external IP for a node
pub async fn set_node_ip(state: web::Data<Arc<AppState>>, body: web::Json<SetNodeIpRequest>) -> HttpResponse {
    let req = body.into_inner();
    let mut ips: HashMap<String, String> = state.store.load("node_ips");

    if req.external_ip.is_empty() {
        ips.remove(&req.node_id);
    } else {
        ips.insert(req.node_id.clone(), req.external_ip.clone());
    }

    match state.store.save("node_ips", &ips) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "saved",
            "node_id": req.node_id,
            "external_ip": req.external_ip,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// Look up the external IP for a node — checks override first, then WolfStack data
fn resolve_node_ip(node: &serde_json::Value, overrides: &HashMap<String, String>) -> String {
    let node_id = node["id"].as_str().unwrap_or("");

    // Check override first
    if let Some(ip) = overrides.get(node_id) {
        if !ip.is_empty() {
            return ip.clone();
        }
    }

    // Fall back to WolfStack's public_ip
    let public_ip = node["public_ip"].as_str().unwrap_or("");
    if !public_ip.is_empty() && public_ip != "0.0.0.0" {
        return public_ip.to_string();
    }

    // Fall back to node address
    node["address"].as_str().unwrap_or("").to_string()
}

#[derive(Debug, Deserialize)]
pub struct ProvisionContainerRequest {
    pub service_id: String,
    #[serde(default)]
    pub node_id: Option<String>,
    pub distribution: Option<String>,
    pub release: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_cores: Option<String>,
}

/// Pick the best node in the cluster — lowest container count among online LXC-capable nodes
/// Works with both WolfStack native and Proxmox nodes
fn pick_best_node(nodes: &[serde_json::Value], _exclude_hint: Option<&str>) -> Option<serde_json::Value> {
    let mut candidates: Vec<&serde_json::Value> = nodes.iter()
        .filter(|n| n["online"].as_bool() == Some(true))
        // Both wolfstack and proxmox nodes can run LXC containers
        .filter(|n| {
            let node_type = n["node_type"].as_str().unwrap_or("wolfstack");
            // Proxmox always supports LXC; WolfStack needs has_lxc
            node_type == "proxmox" || n["has_lxc"].as_bool() != Some(false)
        })
        .collect();

    if candidates.is_empty() { return None; }

    // Sort by container count ascending (fewest first), then by memory usage
    candidates.sort_by(|a, b| {
        let a_count = a["lxc_count"].as_u64().unwrap_or(999);
        let b_count = b["lxc_count"].as_u64().unwrap_or(999);
        let a_mem_pct = a["metrics"]["memory_total"].as_f64()
            .map(|t| if t > 0.0 { a["metrics"]["memory_used"].as_f64().unwrap_or(0.0) / t } else { 0.0 })
            .unwrap_or(0.0);
        let b_mem_pct = b["metrics"]["memory_total"].as_f64()
            .map(|t| if t > 0.0 { b["metrics"]["memory_used"].as_f64().unwrap_or(0.0) / t } else { 0.0 })
            .unwrap_or(0.0);

        a_count.cmp(&b_count)
            .then(a_mem_pct.partial_cmp(&b_mem_pct).unwrap_or(std::cmp::Ordering::Equal))
    });

    Some(candidates[0].clone())
}

/// POST /servers/provision — create an LXC container for a customer service
pub async fn provision_container(state: web::Data<Arc<AppState>>, body: web::Json<ProvisionContainerRequest>) -> HttpResponse {
    let req = body.into_inner();

    // Get service and customer details
    let services = state.services.list().await;
    let service = match services.iter().find(|s| s.id == req.service_id) {
        Some(s) => s.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Service not found"})),
    };

    let customers = state.customers.list().await;
    let customer = match customers.iter().find(|c| c.id == service.customer_id) {
        Some(c) => c.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Customer not found"})),
    };

    let plans = state.plans.list().await;
    let plan = plans.iter().find(|p| p.id == service.plan_id);

    // Fetch cluster nodes
    let nodes_data = match wolfstack_api("/api/nodes").await {
        Ok(d) => d,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Cannot reach cluster: {}", e)})),
    };
    let nodes = nodes_data["nodes"].as_array().cloned().unwrap_or_default();

    // Select target node — explicit choice or auto-balance
    let target_node = if let Some(ref nid) = req.node_id {
        match nodes.iter().find(|n| n["id"].as_str() == Some(nid)) {
            Some(n) => n.clone(),
            None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Selected node not found"})),
        }
    } else {
        match pick_best_node(&nodes, None) {
            Some(n) => n,
            None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "No online LXC-capable nodes in cluster"})),
        }
    };

    let node_id = target_node["id"].as_str().unwrap_or("").to_string();
    let node_hostname = target_node["hostname"].as_str().unwrap_or("").to_string();
    let _node_address = target_node["address"].as_str().unwrap_or("").to_string();
    let node_type = target_node["node_type"].as_str().unwrap_or("wolfstack").to_string();
    let is_self_node = target_node["is_self"].as_bool() == Some(true);
    // Resolve external IP using admin overrides, then WolfStack public_ip, then address
    let node_ip_overrides: HashMap<String, String> = state.store.load("node_ips");
    let host_ip = resolve_node_ip(&target_node, &node_ip_overrides);

    log::info!("Target node: {} ({}) type={} is_self={}", node_hostname, host_ip, node_type, is_self_node);

    // Generate container name
    let container_name = format!("wh-{}-{}",
        customer.email.split('@').next().unwrap_or("user")
            .chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase(),
        &service.id[..8]
    );

    let domain = if service.domain.is_empty() { container_name.clone() } else { service.domain.clone() };

    // Determine resource limits from plan
    let memory = req.memory_limit.unwrap_or_else(|| {
        plan.map(|p| {
            if p.disk_mb >= 20480 { "2g".to_string() }
            else if p.disk_mb >= 10240 { "1g".to_string() }
            else { "512m".to_string() }
        }).unwrap_or_else(|| "512m".to_string())
    });
    let cpus = req.cpu_cores.unwrap_or_else(|| {
        plan.map(|p| {
            if p.disk_mb >= 20480 { "2".to_string() }
            else { "1".to_string() }
        }).unwrap_or_else(|| "1".to_string())
    });

    // FTP port offset based on service count
    // Assign FTP port based on service ID hash to avoid collisions on delete/recreate
    let used_ports: std::collections::HashSet<u16> = services.iter().map(|s| s.ftp_port).filter(|p| *p > 0).collect();
    let mut ftp_port: u16;
    // Hash the service ID to get a starting offset, then find first unused port
    let hash: u32 = service.id.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    ftp_port = 2100 + (hash as u16 % 900);
    while used_ports.contains(&ftp_port) { ftp_port += 1; if ftp_port > 2999 { ftp_port = 2100; } }

    // Create the container — route through the correct node
    let create_body = serde_json::json!({
        "name": container_name,
        "distribution": req.distribution.unwrap_or_else(|| "ubuntu".to_string()),
        "release": req.release.unwrap_or_else(|| "jammy".to_string()),
        "architecture": "amd64",
        "memory_limit": memory,
        "cpu_cores": cpus,
    });

    let create_path = if is_self_node {
        "/api/containers/lxc/create".to_string()
    } else {
        format!("/api/nodes/{}/proxy/containers/lxc/create", node_id)
    };

    let result = match wolfstack_post(&create_path, &create_body).await {
        Ok(data) => data,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Container creation failed: {}", e)})),
    };

    if let Some(err) = result.get("error") {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Container creation failed: {}", err)}));
    }

    // Start the container — route through the correct node
    let action_path = if is_self_node {
        format!("/api/containers/lxc/{}/action", container_name)
    } else {
        format!("/api/nodes/{}/proxy/containers/lxc/{}/action", node_id, container_name)
    };
    wolfstack_post(&action_path, &serde_json::json!({"action": "start"})).await.ok();

    // Update the service with container + host info immediately
    let cn = container_name.clone();
    let hi = host_ip.clone();
    let hh = node_hostname.clone();
    let nid = node_id.clone();
    let fp = ftp_port;
    let sid = service.id.clone();
    state.services.update_with(|items| {
        if let Some(s) = items.iter_mut().find(|s| s.id == sid) {
            s.server_node = nid;
            s.container_name = cn.clone();
            s.host_ip = hi;
            s.host_hostname = hh;
            s.ftp_port = fp;
            s.home_dir = format!("/var/lib/lxc/{}/rootfs/var/www/html", cn);
        }
    }).await.ok();

    // Create a provisioning log stream
    let task_id = format!("prov-{}", &container_name);
    let task_logger = state.provision_logger.create_stream(&task_id).await;

    // Spawn background task for web stack setup + port forwarding
    let bg_container = container_name.clone();
    let bg_domain = domain.clone();
    let bg_service_id = service.id.clone();
    let bg_state = state.clone();
    let bg_task_id = task_id.clone();
    let bg_node_hostname = node_hostname.clone();
    let bg_host_ip = host_ip.clone();
    let bg_node_type = node_type.clone();
    let bg_node_id = node_id.clone();
    let bg_is_self = is_self_node;

    tokio::spawn(async move {
        task_logger.info(format!("Container '{}' created on node {} ({})", bg_container, bg_node_hostname, bg_node_type)).await;
        task_logger.info(format!("Host IP: {}", bg_host_ip)).await;

        // Helper: exec a command inside the container via WolfStack API
        let exec = |cmd: String| {
            let c = bg_container.clone();
            let n = bg_node_id.clone();
            let s = bg_is_self;
            async move { container_exec(&c, &cmd, &n, s).await }
        };

        // Wait for container to boot
        task_logger.cmd("Waiting for container to boot...").await;
        let mut booted = false;
        for i in 0..20 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Ok(r) = exec("echo ok".to_string()).await {
                if r["ok"].as_bool() == Some(true) {
                    task_logger.ok(format!("Container ready after {}s", (i + 1) * 2)).await;
                    booted = true;
                    break;
                }
            }
        }
        if !booted {
            task_logger.err("Container did not start within 40s").await;
            task_logger.done("Provisioning failed.").await;
            bg_state.provision_logger.finish_stream(&bg_task_id).await;
            return;
        }

        // Detect distro and run setup step by step
        task_logger.cmd("Detecting OS...").await;
        let mut distro = "debian".to_string();
        if let Ok(r) = exec("cat /etc/os-release 2>/dev/null".to_string()).await {
            let out = r["stdout"].as_str().unwrap_or("").to_lowercase();
            if out.contains("alpine") { distro = "alpine".to_string(); }
            else if out.contains("alma") || out.contains("rocky") || out.contains("centos") || out.contains("rhel") || out.contains("fedora") { distro = "rhel".to_string(); }
            else if out.contains("arch") { distro = "arch".to_string(); }
        }
        task_logger.ok(format!("Detected: {}", distro)).await;

        let steps: Vec<(&str, String)> = match distro.as_str() {
            "alpine" => vec![
                ("Updating packages...", "apk update 2>&1".into()),
                ("Upgrading system...", "apk upgrade 2>&1".into()),
                ("Installing Apache2...", "apk add --no-cache apache2 apache2-ssl 2>&1".into()),
                ("Installing PHP...", "apk add --no-cache php82 php82-apache2 php82-mysqli php82-curl php82-gd php82-mbstring php82-xml php82-zip php82-session php82-json php82-openssl 2>&1".into()),
                ("Installing Certbot...", "apk add --no-cache certbot certbot-apache 2>&1".into()),
                ("Installing FTP server...", "apk add --no-cache vsftpd 2>&1".into()),
                ("Installing tools...", "apk add --no-cache curl wget unzip git mariadb-client bash 2>&1".into()),
                ("Starting services...", "rc-update add apache2 default 2>/dev/null; rc-service apache2 start 2>/dev/null; echo done".into()),
            ],
            "rhel" => vec![
                ("Updating packages...", "dnf makecache -q 2>&1 || yum makecache -q 2>&1".into()),
                ("Upgrading system...", "dnf upgrade -y -q 2>&1 || yum update -y -q 2>&1".into()),
                ("Installing Apache2...", "dnf install -y -q httpd mod_ssl 2>&1 || yum install -y -q httpd mod_ssl 2>&1".into()),
                ("Installing PHP...", "dnf install -y -q php php-mysqlnd php-curl php-gd php-mbstring php-xml php-zip 2>&1 || yum install -y -q php php-mysqlnd php-curl php-gd php-mbstring php-xml php-zip 2>&1".into()),
                ("Installing Certbot...", "dnf install -y -q certbot python3-certbot-apache 2>&1 || yum install -y -q certbot python3-certbot-apache 2>&1".into()),
                ("Installing FTP server...", "dnf install -y -q vsftpd 2>&1 || yum install -y -q vsftpd 2>&1".into()),
                ("Installing tools...", "dnf install -y -q curl wget unzip git mariadb 2>&1 || yum install -y -q curl wget unzip git mariadb 2>&1".into()),
                ("Starting services...", "systemctl enable httpd vsftpd 2>/dev/null; systemctl start httpd vsftpd 2>/dev/null; echo done".into()),
            ],
            "arch" => vec![
                ("Updating packages...", "pacman -Sy --noconfirm 2>&1".into()),
                ("Installing Apache2...", "pacman -S --noconfirm apache 2>&1".into()),
                ("Installing PHP...", "pacman -S --noconfirm php php-apache php-gd 2>&1".into()),
                ("Installing Certbot...", "pacman -S --noconfirm certbot certbot-apache 2>&1".into()),
                ("Installing FTP server...", "pacman -S --noconfirm vsftpd 2>&1".into()),
                ("Installing tools...", "pacman -S --noconfirm curl wget unzip git mariadb-clients 2>&1".into()),
                ("Starting services...", "systemctl enable httpd vsftpd 2>/dev/null; systemctl start httpd vsftpd 2>/dev/null; echo done".into()),
            ],
            _ => vec![ // debian/ubuntu
                ("Updating packages...", "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq 2>&1".into()),
                ("Upgrading system...", "export DEBIAN_FRONTEND=noninteractive && apt-get upgrade -y -qq 2>&1".into()),
                ("Installing Apache2...", "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq apache2 2>&1".into()),
                ("Installing PHP...", "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq libapache2-mod-php php php-mysql php-curl php-gd php-mbstring php-xml php-zip 2>&1".into()),
                ("Installing Certbot...", "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq certbot python3-certbot-apache 2>&1".into()),
                ("Installing FTP server...", "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq vsftpd 2>&1".into()),
                ("Installing tools...", "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq curl wget unzip git mariadb-client 2>&1".into()),
                ("Enabling Apache modules...", "a2enmod rewrite ssl headers expires 2>/dev/null; echo done".into()),
            ],
        };

        for (label, cmd) in &steps {
            task_logger.cmd((*label).to_string()).await;
            match exec(cmd.clone()).await {
                Ok(r) => {
                    if r["ok"].as_bool() == Some(true) {
                        task_logger.ok(format!("{} done", label.trim_end_matches("..."))).await;
                    } else {
                        let err = r["stderr"].as_str().unwrap_or("unknown error");
                        task_logger.err(format!("Warning: {}", err.lines().last().unwrap_or(err))).await;
                    }
                }
                Err(e) => task_logger.err(format!("Failed: {}", e)).await,
            }
        }

        // Configure Apache vhost
        task_logger.cmd("Configuring Apache vhost...").await;
        let vhost_cmd = format!(
            r#"VHOST='<VirtualHost *:80>
    ServerName {d}
    ServerAlias www.{d}
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>'
if [ -d /etc/apache2/sites-available ]; then
    echo "$VHOST" > /etc/apache2/sites-available/000-default.conf
    systemctl restart apache2 2>/dev/null
elif [ -d /etc/httpd/conf.d ]; then
    echo "$VHOST" > /etc/httpd/conf.d/wolfhost.conf
    systemctl restart httpd 2>/dev/null
fi
echo done"#, d = bg_domain);
        exec(vhost_cmd).await.ok();
        task_logger.ok("Apache vhost configured").await;

        // Create default website
        task_logger.cmd("Creating default website...").await;
        let html_cmd = format!(
            r#"cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{d}</title><style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:sans-serif;background:#0a0e1a;color:#e8ecf4;min-height:100vh;display:flex;align-items:center;justify-content:center}}.c{{background:#111827;border:1px solid #1e2a4a;border-radius:16px;padding:48px;text-align:center}}h1{{font-size:28px;background:linear-gradient(135deg,#dc2626,#f87171);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}p{{color:#8892a8}}</style></head><body><div class="c"><h1>Welcome to {d}</h1><p>Your website is ready!</p></div></body></html>
EOF
rm -f /var/www/html/index.nginx-debian.html 2>/dev/null
chown -R www-data:www-data /var/www/html"#, d = bg_domain);
        exec(html_cmd).await.ok();
        task_logger.ok("Default website created").await;

        // Configure FTP
        task_logger.cmd("Configuring FTP...").await;
        exec(r#"cat > /etc/vsftpd.conf << 'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30100
EOF
mkdir -p /var/run/vsftpd/empty
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable vsftpd 2>/dev/null; systemctl restart vsftpd 2>/dev/null
elif command -v rc-update >/dev/null 2>&1; then
    rc-update add vsftpd 2>/dev/null; rc-service vsftpd restart 2>/dev/null
fi"#.to_string()).await.ok();
        task_logger.ok("FTP configured").await;

        // Create webmaster user
        task_logger.cmd("Creating webmaster user...").await;
        exec("useradd -m -d /var/www/html -s /bin/bash -G www-data webmaster 2>/dev/null; chown -R webmaster:www-data /var/www/html".to_string()).await.ok();
        task_logger.ok("User 'webmaster' created").await;

        // Get container IP
        task_logger.cmd("Getting container IP...").await;
        let mut container_ip = String::new();
        if let Ok(r) = exec("hostname -I".to_string()).await {
            let ips = r["stdout"].as_str().unwrap_or("");
            for ip in ips.split_whitespace() {
                if !ip.starts_with("127.") && !ip.contains(':') {
                    container_ip = ip.to_string();
                    break;
                }
            }
        }

        if !container_ip.is_empty() {
            task_logger.ok(format!("Container IP: {}", container_ip)).await;
            let cip = container_ip.clone();
            let sid = bg_service_id.clone();
            bg_state.services.update_with(|items| {
                if let Some(s) = items.iter_mut().find(|s| s.id == sid) {
                    s.container_ip = cip;
                }
            }).await.ok();
        } else {
            task_logger.err("Could not determine container IP").await;
        }

        task_logger.done("Provisioning complete! Open the Terminal to access your container.").await;
        bg_state.provision_logger.finish_stream(&bg_task_id).await;
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "provisioning",
        "task_id": task_id,
        "container_name": container_name,
        "domain": domain,
        "node": node_hostname,
        "node_type": node_type,
        "host_ip": host_ip,
        "ftp_port": ftp_port,
        "message": "Container created. Web stack is being installed — watch the terminal for progress.",
    }))
}

/// GET /servers/provision/{task_id}/stream — SSE stream of provisioning logs
pub async fn provision_stream(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let task_id = path.into_inner();

    let (history, mut rx) = match state.provision_logger.subscribe(&task_id).await {
        Some(h) => h,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Task not found"})),
    };

    let (tx_body, rx_body) = tokio::sync::mpsc::channel::<Result<actix_web::web::Bytes, std::io::Error>>(64);

    tokio::spawn(async move {
        // Send history first
        for entry in history {
            let line = format!("data: {}\n\n", serde_json::json!({
                "time": entry.timestamp, "level": entry.level, "msg": entry.message,
            }));
            if tx_body.send(Ok(actix_web::web::Bytes::from(line))).await.is_err() { return; }
        }
        // Stream live events
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    let done = entry.level == "done";
                    let line = format!("data: {}\n\n", serde_json::json!({
                        "time": entry.timestamp, "level": entry.level, "msg": entry.message,
                    }));
                    if tx_body.send(Ok(actix_web::web::Bytes::from(line))).await.is_err() { return; }
                    if done { return; }
                }
                Err(_) => return,
            }
        }
    });

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .streaming(tokio_stream::wrappers::ReceiverStream::new(rx_body))
}

/// GET /servers/provision/{task_id}/logs — get all logs for a task (non-streaming)
pub async fn provision_logs(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> HttpResponse {
    let task_id = path.into_inner();
    match state.provision_logger.subscribe(&task_id).await {
        Some((history, _)) => {
            let logs: Vec<serde_json::Value> = history.iter().map(|e| {
                serde_json::json!({"time": e.timestamp, "level": e.level, "msg": e.message})
            }).collect();
            HttpResponse::Ok().json(logs)
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Task not found"})),
    }
}

/// POST /servers/containers/{name}/action — start/stop/restart a customer container
pub async fn container_action(path: web::Path<String>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let name = path.into_inner();
    match wolfstack_post(&format!("/api/containers/lxc/{}/action", name), &body.into_inner()).await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /servers/customer-containers — list all WolfHost-managed containers (wh- prefix)
pub async fn list_customer_containers(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    let containers = match wolfstack_api("/api/containers/lxc").await {
        Ok(data) => data,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let stats = wolfstack_api("/api/containers/lxc/stats").await.ok();

    // Filter to only WolfHost containers (wh- prefix)
    let arr = containers.as_array().unwrap_or(&Vec::new()).clone();
    let wh_containers: Vec<serde_json::Value> = arr.into_iter()
        .filter(|c| {
            c["name"].as_str().map(|n| n.starts_with("wh-")).unwrap_or(false)
        })
        .map(|mut c| {
            // Attach stats if available
            if let Some(ref stats_data) = stats {
                if let Some(stats_arr) = stats_data.as_array() {
                    let name = c["name"].as_str().unwrap_or("");
                    if let Some(st) = stats_arr.iter().find(|s| s["name"].as_str() == Some(name)) {
                        c["stats"] = st.clone();
                    }
                }
            }

            // Find the matching service/customer
            c
        })
        .collect();

    HttpResponse::Ok().json(wh_containers)
}
