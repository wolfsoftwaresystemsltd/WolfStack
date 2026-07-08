// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! HTTP (L7) reverse-proxy entries.
//!
//! Sister to the L4 `router::proxy::ProxyEntry` iptables forwarder.
//! This module owns:
//!
//!   • The `HttpProxy` data model — multi-target, so one proxy can be
//!     replicated across N nodes for HA. Each target picks its own
//!     `TargetRuntime` (Host / Docker / LXC), letting the operator
//!     mix bare-host nginx with containerised nginx on different
//!     cluster nodes if they want.
//!
//!   • The render + apply pipeline. `apply_for_node` walks every
//!     proxy's targets, picks the ones bound to the local node,
//!     renders each via the configurator's `ExecTarget` abstraction
//!     (which already handles `docker exec` / `lxc-attach` /
//!     `pct exec`), then test-and-reloads the matching runtime via
//!     `proxy_runtime`.
//!
//! Public-ingress (DNS / LB / Cloudflare) lives one layer up in
//! `crate::edge` — render doesn't touch DNS, the reconcile loop does.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

use crate::edge::{EdgeStrategy, ProxyTarget, TargetRuntime};

/// nginx config dir read by both nginx and WolfProxy (the Rust product
/// reads /etc/nginx/conf.d as a drop-in nginx replacement). Same path
/// inside Host / Docker / LXC targets.
pub const CONFIG_DIR: &str = "/etc/nginx/conf.d";

/// Filename prefix so apply_for_node can identify configs it wrote
/// itself when pruning orphans, without scribbling over operator-
/// hand-written conf.d entries.
pub const FILE_PREFIX: &str = "wolfrouter-http-";

// ─── Data model ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxy {
    /// Stable identifier — ends up as the nginx config filename, so
    /// the charset is tight (see `validate_id`).
    pub id: String,

    /// Domains this proxy answers for. First is canonical.
    pub server_names: Vec<String>,

    /// Disabled = renders a 503 stub instead of forwarding upstream.
    /// Kept on disk so disabling doesn't lose TLS / SNI handshake.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Public listen ports. Empty = pick defaults (80 always, 443 if
    /// TLS).
    #[serde(default)]
    pub listen_ports: Vec<u16>,

    /// Where this proxy actually runs. One target = single-node, no
    /// resilience. Multiple = replicated; pair with a non-Local edge
    /// strategy to get failover.
    pub targets: Vec<ProxyTarget>,

    /// Public-ingress strategy. Set to `Local` for "operator manages
    /// DNS themselves"; otherwise the edge reconciler keeps DNS in
    /// sync with peer-health observations.
    #[serde(default)]
    pub edge: EdgeStrategy,

    // ─── Backends ──────────────────────────────────────────────────
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub lb_strategy: LoadBalance,

    // ─── TLS ────────────────────────────────────────────────────────
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub force_https: bool,
    #[serde(default)]
    pub hsts: bool,
    #[serde(default)]
    pub http2: bool,
    #[serde(default)]
    pub websocket: bool,

    // ─── Headers ───────────────────────────────────────────────────
    #[serde(default)]
    pub upstream_headers: Vec<HeaderPair>,
    #[serde(default)]
    pub response_headers: Vec<HeaderPair>,

    // ─── Timeouts (seconds; 0 = nginx default) ─────────────────────
    #[serde(default)]
    pub connect_timeout_s: u32,
    #[serde(default)]
    pub send_timeout_s: u32,
    #[serde(default)]
    pub read_timeout_s: u32,

    // ─── Custom error pages ────────────────────────────────────────
    #[serde(default)]
    pub error_pages: Vec<ErrorPage>,

    // ─── Access control ────────────────────────────────────────────
    #[serde(default)]
    pub access: AccessControl,

    // ─── Bookkeeping ───────────────────────────────────────────────
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub updated_at: String,

    /// Set when this proxy was auto-created by the Internet Exposure
    /// feature. Records the workload it fronts so the exposure reconcile
    /// can refresh the upstream IP when the workload restarts or migrates
    /// to another node. `None` for operator-created proxies (the whole
    /// existing surface), which the exposure reconcile never touches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposureSource>,
}

/// What an exposure proxy points at, so its upstream can be re-resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureSource {
    /// "docker" | "lxc" | "manual". `manual` upstreams (a fixed IP:port,
    /// e.g. a VM the operator addressed by hand) are never re-resolved.
    pub workload_kind: String,
    /// Container name for docker/lxc; empty for manual.
    #[serde(default)]
    pub workload_ref: String,
    /// The workload port the upstream targets.
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub url: String,
    #[serde(default = "default_one_u32")]
    pub weight: u32,
    #[serde(default)]
    pub max_conns: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalance {
    #[default]
    RoundRobin,
    LeastConn,
    IpHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    /// Name of the cert under `/etc/letsencrypt/live/` if it came
    /// from the DNS-providers flow. Empty for hand-pasted paths.
    /// Drives the cert-distribution reconciler in a later commit.
    #[serde(default)]
    pub cert_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPage {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessControl {
    #[serde(default)]
    pub rules: Vec<AclRule>,
    #[serde(default)]
    pub basic_auth_file: String,
    #[serde(default)]
    pub basic_auth_realm: String,
    #[serde(default)]
    pub rate_limit_rps: u32,
    #[serde(default)]
    pub rate_limit_burst: u32,
    #[serde(default)]
    pub conn_limit_per_ip: u32,
    #[serde(default)]
    pub block_threat_intel: bool,
    #[serde(default)]
    pub country_block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction { Allow, Deny }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub action: AclAction,
    pub cidr: String,
    #[serde(default)]
    pub comment: String,
}

fn default_true() -> bool { true }
fn default_one_u32() -> u32 { 1 }

// ─── Validation ────────────────────────────────────────────────────────

/// id ends up as a config filename — restrict to a tight charset so
/// no operator input can escape the conf.d directory or sneak shell
/// metachars into a `docker exec` arg.
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("id is required".into());
    }
    if id.len() > 64 {
        return Err("id must be ≤ 64 chars".into());
    }
    for c in id.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-') {
            return Err(format!(
                "id '{}' contains '{}' — only lowercase a-z, 0-9, '.', '_', '-' allowed",
                id, c
            ));
        }
    }
    Ok(())
}

/// Container names follow Docker/LXC's own restrictions (alnum + a
/// few separators). We don't enforce the full grammar; we just block
/// the obvious shell-injection chars so a malicious config file
/// can't `docker exec '; rm -rf /'`.
pub fn validate_container_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("container name is required".into());
    }
    if name.len() > 128 {
        return Err("container name too long".into());
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return Err(format!(
                "container name '{}' contains '{}' — only ASCII alnum and '.', '_', '-' allowed",
                name, c
            ));
        }
    }
    Ok(())
}

// ─── Render pipeline ───────────────────────────────────────────────────

/// Render every relevant target bound to this node, fan-out by
/// `TargetRuntime`. For each: write the conf to that runtime's
/// filesystem, prune orphans, then trigger a runtime-appropriate
/// reload.
///
/// Returns per-target warnings (empty Vec = clean apply). Failure on
/// one target doesn't abort the others — operators want the rest of
/// the cluster to stay in sync even if one node's docker daemon is
/// down.
pub fn apply_for_node(proxies: &[HttpProxy], self_node_id: &str) -> Vec<String> {
    use crate::configurator::ExecTarget;
    use std::collections::HashMap;

    let mut warnings = Vec::new();

    // Group the targets bound to *this* node by their runtime — one
    // pass per (Host / Docker:<name> / Lxc:<name>) bucket. Each
    // bucket gets its own prune-and-write-and-reload cycle because
    // the filesystem and reload command are different per bucket.
    type Bucket = (ExecTarget, &'static str); // (where, runtime-kind for reload routing)
    let mut buckets: HashMap<String, (Bucket, Vec<&HttpProxy>)> = HashMap::new();

    for p in proxies {
        for t in &p.targets {
            if t.node_id != self_node_id { continue; }
            let (key, bucket) = match &t.runtime {
                TargetRuntime::Host => {
                    ("host".to_string(), (ExecTarget::Host, "host"))
                }
                TargetRuntime::Docker { container } => {
                    if let Err(e) = validate_container_name(container) {
                        warnings.push(format!("{}: skipped docker target: {}", p.id, e));
                        continue;
                    }
                    (
                        format!("docker:{}", container),
                        (ExecTarget::Docker(container.clone()), "container"),
                    )
                }
                TargetRuntime::Lxc { container } => {
                    if let Err(e) = validate_container_name(container) {
                        warnings.push(format!("{}: skipped lxc target: {}", p.id, e));
                        continue;
                    }
                    (
                        format!("lxc:{}", container),
                        (ExecTarget::Lxc(container.clone()), "container"),
                    )
                }
            };
            buckets.entry(key).or_insert_with(|| (bucket, Vec::new())).1.push(p);
        }
    }

    for (label, ((target, runtime_kind), bucket_proxies)) in buckets {
        let bucket_warnings = apply_bucket(&target, runtime_kind, &bucket_proxies);
        for w in bucket_warnings {
            warnings.push(format!("[{}] {}", label, w));
        }
    }

    warnings
}

/// Apply one bucket's worth of proxies: prune orphans, write live
/// set, test, reload. `runtime_kind` is `"host"` (run reload on the
/// host's systemd / nginx) or `"container"` (the container has its
/// own nginx, reload inside).
fn apply_bucket(
    target: &crate::configurator::ExecTarget,
    runtime_kind: &str,
    proxies: &[&HttpProxy],
) -> Vec<String> {
    let mut warnings = Vec::new();

    // Build the keep-set so we know which conf files to drop on the
    // floor (orphans from previous renders).
    let keep: std::collections::HashSet<String> = proxies.iter().map(|p| p.id.clone()).collect();

    // Make sure conf.d exists. Cheap idempotent op via the target's
    // shell — works the same for host and container.
    let _ = target.exec(&format!("mkdir -p '{}'", CONFIG_DIR));

    // Prune orphans + per-proxy error-page bodies.
    let mut removed_any = false;
    if let Ok(names) = target.list_dir(CONFIG_DIR) {
        for name in names {
            if let Some(rest) = name.strip_prefix(FILE_PREFIX) {
                let id_opt = rest.strip_suffix(".conf")
                    .or_else(|| rest.rsplit_once("-error-").map(|(id, _)| id));
                if let Some(id) = id_opt {
                    if !keep.contains(id) {
                        let path = format!("{}/{}", CONFIG_DIR, name);
                        let q = path.replace('\'', "'\\''");
                        if target.exec(&format!("rm -f '{}'", q)).is_ok() {
                            removed_any = true;
                        }
                    }
                }
            }
        }
    }

    // Render each entry that belongs in this bucket.
    let mut any_emitted = false;
    for p in proxies {
        if let Err(e) = validate_id(&p.id) {
            warnings.push(format!("skipped '{}': {}", p.id, e));
            continue;
        }
        match render(p) {
            Ok(text) => {
                let path = format!("{}/{}{}.conf", CONFIG_DIR, FILE_PREFIX, p.id);
                if let Err(e) = target.write_file(&path, &text) {
                    warnings.push(format!("{}: write {}: {}", p.id, path, e));
                    continue;
                }
                for ep in &p.error_pages {
                    if ep.body.is_empty() { continue; }
                    let bp = format!("{}/{}{}-error-{}.html", CONFIG_DIR, FILE_PREFIX, p.id, ep.status);
                    let _ = target.write_file(&bp, &ep.body);
                }
                any_emitted = true;
            }
            Err(e) => {
                warnings.push(format!("{}: render: {}", p.id, e));
            }
        }
    }

    if !any_emitted && !removed_any {
        return warnings;
    }

    // Test + reload via the right runtime. Host uses the
    // proxy_runtime detection (nginx or wolfproxy); containers do
    // their own nginx -t / -s reload inside the namespace.
    test_and_reload(target, runtime_kind, &mut warnings);
    warnings
}

fn test_and_reload(
    target: &crate::configurator::ExecTarget,
    runtime_kind: &str,
    warnings: &mut Vec<String>,
) {
    // nginx -t works in both Host and container; it's a config
    // syntax check that doesn't bind ports.
    match target.exec("nginx -t 2>&1") {
        Ok(out) => {
            // Success — nginx -t emits "configuration file ... test is
            // successful" to stderr or stdout depending on version.
            // We only treat a non-zero exit as failure here; if the
            // exec ran clean, push on.
            let _ = out;
        }
        Err(e) => {
            warnings.push(format!("nginx -t failed: {}", e.trim()));
            return;
        }
    }

    if runtime_kind == "container" {
        // Containers have nginx-only. Reload via signal inside the
        // namespace; wolfproxy-in-container isn't a v23.2 scenario.
        if let Err(e) = target.exec("nginx -s reload") {
            warnings.push(format!("nginx -s reload (in container) failed: {}", e.trim()));
        }
        return;
    }

    // Host — pick the active reverse-proxy unit (nginx or wolfproxy).
    let status = crate::networking::router::proxy_runtime::detect_runtime();
    if !status.any_installed() {
        warnings.push("no_runtime: nginx/wolfproxy not installed on this node. Install one via Settings → HTTP Proxies, then re-apply.".into());
        return;
    }
    let unit = match status.active_runtime() {
        Some(u) => u,
        None => {
            warnings.push("config validated but no runtime active — start nginx or wolfproxy to pick up changes.".into());
            return;
        }
    };
    if let Err(e) = target.exec(&format!("systemctl reload {}", unit)) {
        warnings.push(format!(
            "systemctl reload {} failed: {}. Try `sudo systemctl restart {}` if reload isn't supported on your build.",
            unit, e.trim(), unit
        ));
    }
}

/// Pure: build the nginx config text for one proxy. No I/O. Same
/// shape that worked for both nginx and wolfproxy — they read the
/// same files.
pub fn render(p: &HttpProxy) -> Result<String, String> {
    if p.server_names.is_empty() {
        return Err("at least one server_name is required".into());
    }
    let mut out = String::new();
    writeln!(out, "# Generated by WolfRouter (HTTP proxy '{}').", p.id).ok();
    writeln!(out, "# Source of truth: /etc/wolfstack/router/config.json.").ok();
    writeln!(out, "# Edits here are clobbered on the next apply.").ok();
    writeln!(out).ok();

    let upstream_name = format!(
        "wolfrouter_http_{}",
        p.id.replace('.', "_").replace('-', "_")
    );
    let multi_backend = p.upstreams.len() > 1;

    if multi_backend {
        writeln!(out, "upstream {} {{", upstream_name).ok();
        match p.lb_strategy {
            LoadBalance::RoundRobin => {}
            LoadBalance::LeastConn => { writeln!(out, "    least_conn;").ok(); }
            LoadBalance::IpHash    => { writeln!(out, "    ip_hash;").ok(); }
        }
        for up in &p.upstreams {
            let target = strip_scheme(&up.url);
            let mut extras = String::new();
            if up.weight > 1 { extras.push_str(&format!(" weight={}", up.weight)); }
            if up.max_conns > 0 { extras.push_str(&format!(" max_conns={}", up.max_conns)); }
            writeln!(out, "    server {};{}", target, extras).ok();
        }
        writeln!(out, "}}").ok();
        writeln!(out).ok();
    }

    let mut http_ports: Vec<u16> = Vec::new();
    let mut https_ports: Vec<u16> = Vec::new();
    if p.listen_ports.is_empty() {
        http_ports.push(80);
        if p.tls.is_some() { https_ports.push(443); }
    } else {
        for port in &p.listen_ports {
            if p.tls.is_some() && (*port == 443 || *port == 8443) {
                https_ports.push(*port);
            } else {
                http_ports.push(*port);
            }
        }
    }
    let server_names = p.server_names.join(" ");

    if p.force_https && p.tls.is_some() && !http_ports.is_empty() {
        writeln!(out, "server {{").ok();
        for port in &http_ports {
            writeln!(out, "    listen {};", port).ok();
            writeln!(out, "    listen [::]:{};", port).ok();
        }
        writeln!(out, "    server_name {};", server_names).ok();
        writeln!(out, "    return 301 https://$host$request_uri;").ok();
        writeln!(out, "}}").ok();
        writeln!(out).ok();
    }

    writeln!(out, "server {{").ok();
    let serve_ports: Vec<u16> = if p.force_https && p.tls.is_some() {
        https_ports.clone()
    } else {
        let mut v = http_ports.clone();
        v.extend(&https_ports);
        v
    };
    for port in &serve_ports {
        let is_https = p.tls.is_some() && https_ports.contains(port);
        let h2 = if is_https && p.http2 { " http2" } else { "" };
        let ssl = if is_https { " ssl" } else { "" };
        writeln!(out, "    listen {}{}{};", port, ssl, h2).ok();
        writeln!(out, "    listen [::]:{}{}{};", port, ssl, h2).ok();
    }
    writeln!(out, "    server_name {};", server_names).ok();

    if let Some(tls) = &p.tls {
        writeln!(out, "    ssl_certificate     {};", tls.cert_path).ok();
        writeln!(out, "    ssl_certificate_key {};", tls.key_path).ok();
        writeln!(out, "    ssl_protocols TLSv1.2 TLSv1.3;").ok();
        writeln!(out, "    ssl_prefer_server_ciphers off;").ok();
    }

    if p.hsts && p.tls.is_some() {
        writeln!(out, "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;").ok();
    }
    for h in &p.response_headers {
        writeln!(out, "    add_header {} {} always;", quote_header(&h.name), quote_header(&h.value)).ok();
    }

    for rule in &p.access.rules {
        let kw = match rule.action { AclAction::Allow => "allow", AclAction::Deny => "deny" };
        writeln!(out, "    {} {};", kw, rule.cidr).ok();
    }
    if p.access.rules.iter().any(|r| matches!(r.action, AclAction::Allow))
        && !p.access.rules.iter().any(|r| matches!(r.action, AclAction::Deny) && r.cidr == "all")
    {
        writeln!(out, "    deny all;").ok();
    }

    if !p.access.basic_auth_file.is_empty() {
        let realm = if p.access.basic_auth_realm.is_empty() { "Restricted" } else { &p.access.basic_auth_realm };
        writeln!(out, "    auth_basic \"{}\";", realm.replace('"', "\\\"")).ok();
        writeln!(out, "    auth_basic_user_file {};", p.access.basic_auth_file).ok();
    }

    if p.connect_timeout_s > 0 { writeln!(out, "    proxy_connect_timeout {}s;", p.connect_timeout_s).ok(); }
    if p.send_timeout_s    > 0 { writeln!(out, "    proxy_send_timeout {}s;",    p.send_timeout_s).ok(); }
    if p.read_timeout_s    > 0 { writeln!(out, "    proxy_read_timeout {}s;",    p.read_timeout_s).ok(); }

    for ep in &p.error_pages {
        if ep.body.is_empty() { continue; }
        let body_path = format!("{}/{}{}-error-{}.html", CONFIG_DIR, FILE_PREFIX, p.id, ep.status);
        writeln!(out, "    error_page {} {};", ep.status, body_path).ok();
    }

    if !p.enabled {
        writeln!(out, "    location / {{").ok();
        writeln!(out, "        return 503;").ok();
        writeln!(out, "    }}").ok();
        writeln!(out, "}}").ok();
        return Ok(out);
    }

    writeln!(out, "    location / {{").ok();
    if p.upstreams.is_empty() {
        writeln!(out, "        return 502 \"WolfRouter: no upstream configured for '{}'\";", p.id).ok();
        writeln!(out, "    }}").ok();
        writeln!(out, "}}").ok();
        return Ok(out);
    }
    let pass_target = if multi_backend {
        // Follow the first backend's scheme for the upstream{} block —
        // mixed-scheme backends are unusual and unsupported, but
        // matching first-backend is predictable.
        let scheme = if p.upstreams[0].url.starts_with("https://") { "https" } else { "http" };
        format!("{}://{}", scheme, upstream_name)
    } else {
        p.upstreams[0].url.clone()
    };
    writeln!(out, "        proxy_pass {};", pass_target).ok();
    writeln!(out, "        proxy_http_version 1.1;").ok();
    writeln!(out, "        proxy_set_header Host $host;").ok();
    writeln!(out, "        proxy_set_header X-Real-IP $remote_addr;").ok();
    writeln!(out, "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;").ok();
    writeln!(out, "        proxy_set_header X-Forwarded-Proto $scheme;").ok();
    writeln!(out, "        proxy_set_header X-Forwarded-Host $host;").ok();
    writeln!(out, "        proxy_set_header X-Forwarded-Port $server_port;").ok();

    if p.websocket {
        writeln!(out, "        proxy_set_header Upgrade $http_upgrade;").ok();
        writeln!(out, "        proxy_set_header Connection \"upgrade\";").ok();
        writeln!(out, "        proxy_read_timeout 86400s;").ok();
    }

    for h in &p.upstream_headers {
        writeln!(out, "        proxy_set_header {} {};", quote_header(&h.name), quote_header(&h.value)).ok();
    }

    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
    Ok(out)
}

fn quote_header(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/') {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn strip_scheme(url: &str) -> String {
    url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url)
        .to_string()
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{ProxyTarget, TargetRuntime};

    fn simple(id: &str, node_id: &str) -> HttpProxy {
        HttpProxy {
            id: id.into(),
            server_names: vec![format!("{}.example.com", id)],
            enabled: true,
            listen_ports: vec![],
            targets: vec![ProxyTarget { node_id: node_id.into(), runtime: TargetRuntime::Host }],
            edge: EdgeStrategy::Local,
            upstreams: vec![Upstream { url: "http://10.0.0.5:8080".into(), weight: 1, max_conns: 0 }],
            lb_strategy: LoadBalance::default(),
            tls: None,
            force_https: false,
            hsts: false,
            http2: false,
            websocket: false,
            upstream_headers: vec![],
            response_headers: vec![],
            connect_timeout_s: 0,
            send_timeout_s: 0,
            read_timeout_s: 0,
            error_pages: vec![],
            access: AccessControl::default(),
            description: String::new(),
            updated_at: String::new(),
            exposure: None,
        }
    }

    #[test]
    fn validate_id_accepts_safe_chars() {
        assert!(validate_id("simple").is_ok());
        assert!(validate_id("with-dash").is_ok());
        assert!(validate_id("a.b_c-1").is_ok());
    }

    #[test]
    fn validate_id_rejects_unsafe_chars_and_uppercase() {
        assert!(validate_id("../etc/passwd").is_err());
        assert!(validate_id("Foo").is_err());
        assert!(validate_id("with space").is_err());
        assert!(validate_id("").is_err());
    }

    #[test]
    fn validate_container_name_rejects_shell_meta() {
        assert!(validate_container_name("my-container").is_ok());
        assert!(validate_container_name("nginx_v2").is_ok());
        assert!(validate_container_name("evil; rm -rf /").is_err());
        assert!(validate_container_name("$(whoami)").is_err());
        assert!(validate_container_name("").is_err());
    }

    #[test]
    fn render_plain_http() {
        let out = render(&simple("plain", "node-a")).unwrap();
        assert!(out.contains("listen 80;"));
        assert!(out.contains("server_name plain.example.com"));
        assert!(out.contains("proxy_pass http://10.0.0.5:8080"));
        assert!(out.contains("X-Real-IP"));
        assert!(!out.contains("ssl_certificate"));
    }

    #[test]
    fn render_multi_target_proxy_still_single_render() {
        // Multi-target proxies (HA) render the SAME nginx config on
        // every target — render() doesn't change based on target
        // count, only apply_for_node fans out across them.
        let mut p = simple("ha", "node-a");
        p.targets = vec![
            ProxyTarget { node_id: "node-a".into(), runtime: TargetRuntime::Host },
            ProxyTarget { node_id: "node-b".into(), runtime: TargetRuntime::Host },
            ProxyTarget { node_id: "node-c".into(), runtime: TargetRuntime::Host },
        ];
        let out = render(&p).unwrap();
        // Only one server block — render is per-config not per-target.
        assert_eq!(out.matches("server {").count(), 1);
    }

    #[test]
    fn render_https_force_redirect_emits_two_server_blocks() {
        let mut p = simple("secure", "node-a");
        p.tls = Some(TlsConfig {
            cert_path: "/etc/letsencrypt/live/secure.example.com/fullchain.pem".into(),
            key_path: "/etc/letsencrypt/live/secure.example.com/privkey.pem".into(),
            cert_name: "secure.example.com".into(),
        });
        p.force_https = true;
        p.hsts = true;
        p.http2 = true;
        let out = render(&p).unwrap();
        assert_eq!(out.matches("server {").count(), 2);
        assert!(out.contains("return 301 https://"));
        assert!(out.contains("listen 443 ssl http2"));
        assert!(out.contains("Strict-Transport-Security"));
    }

    #[test]
    fn render_multi_https_backends_uses_https_proxy_pass() {
        let mut p = simple("api", "node-a");
        p.upstreams = vec![
            Upstream { url: "https://10.0.0.5:8443".into(), weight: 1, max_conns: 0 },
            Upstream { url: "https://10.0.0.6:8443".into(), weight: 1, max_conns: 0 },
        ];
        let out = render(&p).unwrap();
        assert!(out.contains("proxy_pass https://wolfrouter_http_api"));
        assert!(out.contains("server 10.0.0.5:8443;"));
    }

    #[test]
    fn render_websocket_adds_upgrade_headers() {
        let mut p = simple("ws", "node-a");
        p.websocket = true;
        let out = render(&p).unwrap();
        assert!(out.contains("Upgrade $http_upgrade"));
        assert!(out.contains("proxy_read_timeout 86400s"));
    }

    #[test]
    fn render_disabled_returns_503() {
        let mut p = simple("off", "node-a");
        p.enabled = false;
        let out = render(&p).unwrap();
        assert!(out.contains("return 503"));
        assert!(!out.contains("proxy_pass"));
    }

    #[test]
    fn render_no_upstream_returns_502() {
        let mut p = simple("stub", "node-a");
        p.upstreams.clear();
        let out = render(&p).unwrap();
        assert!(out.contains("return 502"));
    }

    #[test]
    fn render_acl_allowlist_appends_implicit_deny() {
        let mut p = simple("acl", "node-a");
        p.access.rules = vec![
            AclRule { action: AclAction::Allow, cidr: "10.0.0.0/8".into(), comment: String::new() },
        ];
        let out = render(&p).unwrap();
        assert!(out.contains("allow 10.0.0.0/8"));
        assert!(out.contains("deny all"));
    }

    #[test]
    fn render_empty_server_names_errors() {
        let mut p = simple("bad", "node-a");
        p.server_names.clear();
        assert!(render(&p).is_err());
    }
}
