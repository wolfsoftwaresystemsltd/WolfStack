use std::process::Command;

/// Create nginx reverse proxy on the HOST to forward domain traffic to container.
/// Includes a /.well-known/acme-challenge/ passthrough so certbot can verify domains.
pub fn setup_host_reverse_proxy(domain: &str, container_ip: &str) -> Result<(), String> {
    log::info!("Setting up reverse proxy: {} -> {}", domain, container_ip);

    // Create ACME webroot directory on the host
    let acme_root = "/var/www/acme";
    std::fs::create_dir_all(acme_root).ok();

    let nginx_conf = format!(r#"# WolfHost: {domain} -> container {container_ip}
# Managed by WolfHost — do not edit manually

server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};

    # ACME challenge for certbot (served from host)
    location /.well-known/acme-challenge/ {{
        root /var/www/acme;
        try_files $uri =404;
    }}

    # Proxy everything else to the container
    location / {{
        proxy_pass http://{container_ip}:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 256m;
    }}
}}
"#, domain = domain, container_ip = container_ip);

    let conf_path = format!("/etc/nginx/sites-available/wh-{}", domain);
    let link_path = format!("/etc/nginx/sites-enabled/wh-{}", domain);

    std::fs::write(&conf_path, &nginx_conf)
        .map_err(|e| format!("Failed to write nginx config: {}", e))?;

    if !std::path::Path::new(&link_path).exists() {
        std::os::unix::fs::symlink(&conf_path, &link_path)
            .map_err(|e| format!("Failed to create symlink: {}", e))?;
    }

    nginx_test_and_reload()?;
    log::info!("Nginx reverse proxy active for {}", domain);
    Ok(())
}

/// Request a Let's Encrypt SSL certificate for a domain using certbot on the HOST.
/// The nginx vhost must already exist (setup_host_reverse_proxy must be called first).
/// Certbot uses the webroot method with /var/www/acme as the webroot.
pub fn request_ssl_certificate(domain: &str, container_ip: &str, email: &str) -> Result<String, String> {
    log::info!("Requesting SSL certificate for {} (email: {})", domain, email);

    // Ensure ACME webroot exists
    std::fs::create_dir_all("/var/www/acme").ok();

    // Run certbot with webroot method
    let _email_arg = if email.is_empty() { "--register-unsafely-without-email".to_string() } else { format!("--email {}", email) };

    let output = Command::new("certbot")
        .args(&[
            "certonly",
            "--webroot",
            "-w", "/var/www/acme",
            "-d", domain,
            "-d", &format!("www.{}", domain),
            "--non-interactive",
            "--agree-tos",
        ])
        .arg(if email.is_empty() { "--register-unsafely-without-email" } else { "" })
        .args(if !email.is_empty() { vec!["--email", email] } else { vec![] })
        .output()
        .map_err(|e| format!("Failed to run certbot: {}", e))?;

    let _stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(format!("Certbot failed: {}", stderr));
    }

    // Now update nginx config with SSL
    let cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", domain);
    let key_path = format!("/etc/letsencrypt/live/{}/privkey.pem", domain);

    if !std::path::Path::new(&cert_path).exists() {
        return Err("Certificate files not found after certbot ran".to_string());
    }

    let nginx_ssl = format!(r#"# WolfHost: {domain} -> container {container_ip}
# Managed by WolfHost — SSL enabled via Let's Encrypt

# HTTP -> HTTPS redirect
server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};

    # ACME challenge for renewals
    location /.well-known/acme-challenge/ {{
        root /var/www/acme;
        try_files $uri =404;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# HTTPS
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain} www.{domain};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:WolfHost:10m;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {{
        proxy_pass http://{container_ip}:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 256m;
    }}
}}
"#, domain = domain, container_ip = container_ip, cert = cert_path, key = key_path);

    let conf_path = format!("/etc/nginx/sites-available/wh-{}", domain);
    std::fs::write(&conf_path, &nginx_ssl)
        .map_err(|e| format!("Failed to write SSL nginx config: {}", e))?;

    nginx_test_and_reload()?;
    log::info!("SSL enabled for {} — HTTPS active", domain);

    Ok(format!("SSL certificate issued for {}. HTTPS is now active with auto-redirect.", domain))
}

/// Renew all Let's Encrypt certificates
pub fn renew_certificates() -> Result<String, String> {
    let output = Command::new("certbot")
        .args(&["renew", "--quiet"])
        .output()
        .map_err(|e| format!("Certbot renew failed: {}", e))?;

    if output.status.success() {
        nginx_test_and_reload().ok();
        Ok("Certificates renewed".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Check if SSL is active for a domain
pub fn check_ssl_status(domain: &str) -> bool {
    let cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", domain);
    std::path::Path::new(&cert_path).exists()
}

/// Test nginx config and reload
fn nginx_test_and_reload() -> Result<(), String> {
    let test = Command::new("nginx").args(&["-t"]).output()
        .map_err(|e| format!("nginx -t failed: {}", e))?;
    if test.status.success() {
        Command::new("systemctl").args(&["reload", "nginx"]).output().ok();
        Ok(())
    } else {
        Err(format!("Nginx config test failed: {}", String::from_utf8_lossy(&test.stderr)))
    }
}

/// Remove nginx reverse proxy and FTP forwarding for a domain
pub fn teardown_proxy(domain: &str, _container_ip: &str) -> Result<(), String> {
    let link_path = format!("/etc/nginx/sites-enabled/wh-{}", domain);
    let conf_path = format!("/etc/nginx/sites-available/wh-{}", domain);
    std::fs::remove_file(&link_path).ok();
    std::fs::remove_file(&conf_path).ok();
    Command::new("systemctl").args(&["reload", "nginx"]).output().ok();

    // Revoke cert (best effort)
    Command::new("certbot")
        .args(&["delete", "--cert-name", domain, "--non-interactive"])
        .output().ok();

    Ok(())
}
