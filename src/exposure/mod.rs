// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Internet Exposure.
//!
//! One place to give a running workload (Docker/LXC container, or any
//! host/VM addressed by IP) its own public HTTPS URL on a wildcard
//! domain — without editing DNS per workload.
//!
//! How it fits together:
//!   * The operator sets a **wildcard zone** once (e.g. `apps.example.com`,
//!     with `*.apps.example.com` pointed at the ingress node and a wildcard
//!     TLS cert). That lives in [`ExposureConfig`].
//!   * Exposing a workload creates an ordinary WolfRouter [`HttpProxy`]
//!     entry (`expose-<subdomain>`) whose `server_name` is
//!     `<subdomain>.<zone>` and whose upstream is the workload's current
//!     `IP:port`. Because WolfRouter config is already cluster-replicated
//!     and rendered on the target node, the URL works cluster-wide and
//!     survives the workload restarting/moving — the reconcile just
//!     refreshes the upstream IP.
//!
//! Nothing is exposed until the operator explicitly turns it on for a
//! specific workload — everything else stays private.

use serde::{Deserialize, Serialize};

use crate::networking::router::http_proxy::{
    ExposureSource, HttpProxy, TlsConfig, Upstream,
};
use crate::edge::{EdgeStrategy, ProxyTarget, TargetRuntime};

/// Every exposure proxy id starts with this so operator-created proxies
/// (which never carry it) are never touched by the exposure reconcile.
pub const ID_PREFIX: &str = "expose-";

fn config_path() -> String {
    format!("{}/internet-exposure.json", crate::paths::get().config_dir)
}

/// Cluster-level exposure setup. Set once; drives the FQDN and TLS of
/// every exposed workload.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExposureConfig {
    /// Wildcard base zone, e.g. `apps.example.com`. Empty until set up.
    #[serde(default)]
    pub zone: String,
    /// Node that fronts the traffic (`*.zone` points here). The generated
    /// proxies render on this node.
    #[serde(default)]
    pub ingress_node_id: String,
    /// Wildcard TLS cert covering `*.zone`. Empty = serve plain HTTP only
    /// (the UI warns). Obtained via the Certificates page (DNS-01).
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
    /// Name under /etc/letsencrypt/live for the cert, if it came from the
    /// certbot flow — lets the cert-distribution reconciler ship it to the
    /// ingress node. Empty for hand-pasted paths.
    #[serde(default)]
    pub cert_name: String,
}

impl ExposureConfig {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&config_path(), json).map_err(|e| e.to_string())
    }

    pub fn is_ready(&self) -> bool {
        !self.zone.trim().is_empty() && !self.ingress_node_id.trim().is_empty()
    }
}

/// Validate + normalise a subdomain label (the part before the zone).
/// Lowercase DNS label rules — this becomes both an nginx `server_name`
/// segment and part of a config filename.
pub fn normalise_subdomain(s: &str) -> Result<String, String> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("Subdomain can't be empty.".into());
    }
    if s.len() > 63 {
        return Err("Subdomain is too long (max 63 characters).".into());
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Subdomain may only contain letters, numbers and hyphens.".into());
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err("Subdomain can't start or end with a hyphen.".into());
    }
    Ok(s)
}

/// Resolve a workload to an upstream URL for nginx (`http://ip:port`).
/// - docker/lxc: look up the container's current IP on this node.
/// - manual: `workload_ref` is already an IP/hostname (a VM, a bare host,
///   anything the operator addressed by hand).
pub fn resolve_upstream(kind: &str, workload_ref: &str, port: u16) -> Result<String, String> {
    if port == 0 {
        return Err("Pick the port the workload listens on.".into());
    }
    match kind {
        "manual" => {
            let host = workload_ref.trim();
            if host.is_empty() {
                return Err("Enter the workload's IP address or hostname.".into());
            }
            Ok(format!("http://{host}:{port}"))
        }
        "docker" | "lxc" => {
            let list = if kind == "docker" {
                crate::containers::docker_list_all_cached()
            } else {
                crate::containers::lxc_list_all_cached()
            };
            let c = list
                .iter()
                .find(|c| c.name == workload_ref)
                .ok_or_else(|| format!(
                    "{} container '{}' isn't running on this node. Expose it from the node that hosts it, or use a manual IP.",
                    kind, workload_ref
                ))?;
            if c.ip_address.trim().is_empty() {
                return Err(format!(
                    "Container '{}' has no IP address yet (is it started?).",
                    workload_ref
                ));
            }
            Ok(format!("http://{}:{}", c.ip_address.trim(), port))
        }
        other => Err(format!("Unknown workload type '{other}'.")),
    }
}

/// Build the WolfRouter proxy that fronts one exposed workload.
pub fn build_proxy(
    cfg: &ExposureConfig,
    subdomain: &str,
    kind: &str,
    workload_ref: &str,
    port: u16,
    upstream_url: &str,
) -> HttpProxy {
    let fqdn = format!("{}.{}", subdomain, cfg.zone.trim());
    let tls = if cfg.cert_path.trim().is_empty() {
        None
    } else {
        Some(TlsConfig {
            cert_path: cfg.cert_path.trim().to_string(),
            key_path: cfg.key_path.trim().to_string(),
            cert_name: cfg.cert_name.trim().to_string(),
        })
    };
    let has_tls = tls.is_some();
    HttpProxy {
        id: format!("{ID_PREFIX}{subdomain}"),
        server_names: vec![fqdn],
        enabled: true,
        listen_ports: Vec::new(), // 80 always, + 443 when TLS present
        targets: vec![ProxyTarget {
            node_id: cfg.ingress_node_id.clone(),
            runtime: TargetRuntime::Host,
        }],
        edge: EdgeStrategy::default(),
        upstreams: vec![Upstream {
            url: upstream_url.to_string(),
            weight: 1,
            max_conns: 0,
        }],
        lb_strategy: Default::default(),
        tls,
        force_https: has_tls,
        hsts: false,
        http2: has_tls,
        websocket: true,
        upstream_headers: Vec::new(),
        response_headers: Vec::new(),
        connect_timeout_s: 0,
        send_timeout_s: 0,
        read_timeout_s: 0,
        error_pages: Vec::new(),
        access: Default::default(),
        description: "Managed by Internet Exposure".to_string(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        exposure: Some(ExposureSource {
            workload_kind: kind.to_string(),
            workload_ref: workload_ref.to_string(),
            port,
        }),
    }
}

/// Re-resolve the upstream IP of every exposure proxy whose workload can
/// move (docker/lxc). Returns true if anything changed, so the caller
/// knows to save + re-apply. Manual upstreams are left alone.
pub fn reconcile_upstreams(proxies: &mut [HttpProxy]) -> bool {
    let mut changed = false;
    for p in proxies.iter_mut() {
        let Some(src) = p.exposure.clone() else { continue };
        if src.workload_kind == "manual" {
            continue;
        }
        // A workload that isn't resolvable right now (stopped, or moved to a
        // node this one can't see) leaves its last-known upstream in place
        // rather than blanking the route — it refreshes once reachable again.
        let Ok(url) = resolve_upstream(&src.workload_kind, &src.workload_ref, src.port) else {
            continue;
        };
        if p.upstreams.len() != 1 || p.upstreams[0].url != url {
            p.upstreams = vec![Upstream { url, weight: 1, max_conns: 0 }];
            changed = true;
        }
    }
    changed
}

/// Explicitly drop an exposure proxy's nginx conf on the local node and
/// reload the proxy runtime. `apply_for_node` only prunes + reloads when
/// the node still has at least one proxy (a live "bucket"); removing the
/// LAST exposure would otherwise leave a stale conf file that nginx keeps
/// serving until something reloads it. Best-effort: a no-op when there's
/// no running nginx/wolfproxy.
pub fn cleanup_local_conf(id: &str) {
    use crate::configurator::ExecTarget;
    let t = ExecTarget::Host;
    let path = format!(
        "{}/{}{}.conf",
        crate::networking::router::http_proxy::CONFIG_DIR,
        crate::networking::router::http_proxy::FILE_PREFIX,
        id
    );
    let _ = t.exec(&format!("rm -f '{}'", path.replace('\'', "'\\''")));
    let _ = t.exec(
        "nginx -t >/dev/null 2>&1 && \
         (nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || \
          systemctl reload wolfproxy 2>/dev/null) || true",
    );
}

/// The public URL an exposed proxy serves on.
pub fn public_url(cfg: &ExposureConfig, p: &HttpProxy) -> String {
    let scheme = if p.tls.is_some() { "https" } else { "http" };
    let host = p.server_names.first().cloned().unwrap_or_default();
    let _ = cfg;
    format!("{scheme}://{host}")
}
