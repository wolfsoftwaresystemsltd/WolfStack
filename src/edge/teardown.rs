// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Edge teardown — when an HTTP proxy is deleted, or its edge strategy
//! changes, we delete the cloud resources that the previous strategy
//! had provisioned. Without this orphan LBs keep billing and stale DNS
//! records keep pointing at offline nodes.
//!
//! Each provider's teardown is best-effort: errors are accumulated and
//! returned to the caller as a warnings vector, but they never abort
//! the local config save. That's deliberate — an operator who removes
//! a proxy because the cloud account is gone should still be able to
//! delete the local config; the warnings tell them what's left
//! dangling so they can clean up manually.
//!
//! Naming convention vs reconcile.rs: reconcile *converges* state
//! toward "what we want"; teardown *removes* state for a proxy that
//! no longer wants anything. They share provider clients but the
//! decision logic is one-shot here (no idempotent diffing).

use crate::edge::{
    cloudflare, cloudflare_tunnel, digitalocean_dns, digitalocean_lb,
    hetzner_dns, hetzner_lb,
    store::{CloudProviderKind, CloudProviderStore},
    EdgeStrategy,
};
use crate::networking::router::http_proxy::HttpProxy;

/// Tear down the cloud resources associated with `proxy.edge` for
/// every `proxy.server_names`. Loads provider stores itself so callers
/// don't have to plumb them through. Returns a warnings vector; an
/// empty vector means everything cleaned up cleanly.
pub async fn teardown_proxy(proxy: &HttpProxy) -> Vec<String> {
    teardown_edge(&proxy.edge, &proxy.server_names).await
}

/// Tear down a specific edge strategy across one or more server_names.
/// Used both by the proxy-delete path and the strategy-change path
/// (where the *old* strategy needs cleanup before the new one takes
/// over).
pub async fn teardown_edge(edge: &EdgeStrategy, server_names: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    let providers = CloudProviderStore::load();
    let dns_providers = crate::dns_providers::DnsProviderStore::load();

    match edge {
        EdgeStrategy::Local => {}

        EdgeStrategy::DnsRoundRobin { dns_provider_id, .. } |
        EdgeStrategy::CloudflareDns { dns_provider_id, .. } => {
            // Delete A records for every server_name. Plugin determines
            // which DNS client we route through.
            let provider = match dns_providers.get(dns_provider_id) {
                Some(p) => p,
                None => {
                    warnings.push(format!(
                        "teardown: DNS provider '{}' not found — A records for {:?} may remain",
                        dns_provider_id, server_names
                    ));
                    return warnings;
                }
            };
            for server_name in server_names {
                let res = match provider.plugin.as_str() {
                    "cloudflare" => teardown_cloudflare_dns(&dns_providers, dns_provider_id, server_name).await,
                    "hetzner"    => teardown_hetzner_dns(&dns_providers, dns_provider_id, server_name).await,
                    "digitalocean" => teardown_digitalocean_dns(&dns_providers, dns_provider_id, server_name).await,
                    other => Err(format!("plugin '{}' has no teardown", other)),
                };
                if let Err(e) = res {
                    warnings.push(format!("teardown {} via {}: {}", server_name, provider.plugin, e));
                }
            }
        }

        EdgeStrategy::HetznerLb { cloud_provider_id, lb_name, .. } => {
            if let Err(e) = teardown_hetzner_lb(&providers, cloud_provider_id, lb_name).await {
                warnings.push(format!("teardown Hetzner LB '{}': {}", lb_name, e));
            }
        }

        EdgeStrategy::DigitalOceanLb { cloud_provider_id, lb_name, .. } => {
            if let Err(e) = teardown_digitalocean_lb(&providers, cloud_provider_id, lb_name).await {
                warnings.push(format!("teardown DigitalOcean LB '{}': {}", lb_name, e));
            }
        }

        EdgeStrategy::CloudflareTunnel { cloud_provider_id, dns_provider_id, tunnel_name } => {
            if let Err(e) = teardown_cloudflare_tunnel(
                &providers, cloud_provider_id,
                &dns_providers, dns_provider_id,
                tunnel_name, server_names,
            ).await {
                warnings.push(format!("teardown Cloudflare Tunnel '{}': {}", tunnel_name, e));
            }
        }
    }
    warnings
}

// ─── Per-provider teardown helpers ─────────────────────────────────────

async fn teardown_cloudflare_dns(
    dns_providers: &crate::dns_providers::DnsProviderStore,
    dns_provider_id: &str,
    server_name: &str,
) -> Result<(), String> {
    let creds = super::reconcile::cloudflare_creds_from_dns_provider(dns_providers, dns_provider_id)?;
    let zone_name = super::reconcile::strip_to_zone(server_name);
    let zone_id = cloudflare::lookup_zone_id(&creds, &zone_name).await?
        .ok_or_else(|| format!("zone '{}' not found in token's scope", zone_name))?;
    let recs = cloudflare::list_a_records(&creds, &zone_id, server_name).await?;
    let mut errors = Vec::new();
    for r in &recs {
        if let Err(e) = cloudflare::delete_record(&creds, &zone_id, &r.id).await {
            errors.push(format!("delete {}: {}", r.id, e));
        }
    }
    // Also try to delete a CNAME for this server_name (would be
    // present if the proxy had been a CloudflareTunnel before swapping
    // to DNS — leftover CNAME would block the new A records).
    if let Ok(cnames) = cloudflare::list_records(&creds, &zone_id, server_name, "CNAME").await {
        for r in cnames {
            if let Err(e) = cloudflare::delete_record(&creds, &zone_id, &r.id).await {
                errors.push(format!("delete CNAME {}: {}", r.id, e));
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

async fn teardown_hetzner_dns(
    dns_providers: &crate::dns_providers::DnsProviderStore,
    dns_provider_id: &str,
    server_name: &str,
) -> Result<(), String> {
    let creds = super::reconcile::hetzner_dns_creds_from_dns_provider(dns_providers, dns_provider_id)?;
    let zone_name = super::reconcile::strip_to_zone(server_name);
    let zone_id = hetzner_dns::lookup_zone_id(&creds, &zone_name).await?
        .ok_or_else(|| format!("zone '{}' not found", zone_name))?;
    let recs = hetzner_dns::list_a_records_for_fqdn(&creds, &zone_id, &zone_name, server_name).await?;
    let mut errors = Vec::new();
    for r in &recs {
        if let Err(e) = hetzner_dns::delete_record(&creds, &r.id).await {
            errors.push(format!("delete {}: {}", r.id, e));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

async fn teardown_digitalocean_dns(
    dns_providers: &crate::dns_providers::DnsProviderStore,
    dns_provider_id: &str,
    server_name: &str,
) -> Result<(), String> {
    let creds = super::reconcile::digitalocean_creds_from_dns_provider(dns_providers, dns_provider_id)?;
    let zone = super::reconcile::strip_to_zone(server_name);
    let recs = digitalocean_dns::list_a_records_for_fqdn(&creds, &zone, server_name).await?;
    let mut errors = Vec::new();
    for r in &recs {
        if let Err(e) = digitalocean_dns::delete_record(&creds, &zone, r.id).await {
            errors.push(format!("delete {}: {}", r.id, e));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

async fn teardown_hetzner_lb(
    providers: &CloudProviderStore,
    cloud_provider_id: &str,
    lb_name: &str,
) -> Result<(), String> {
    let provider = providers.get(cloud_provider_id)
        .ok_or_else(|| format!("cloud provider '{}' not found", cloud_provider_id))?;
    if provider.kind != CloudProviderKind::Hetzner {
        return Err(format!("cloud provider '{}' is kind {} not hetzner", provider.name, provider.kind.label()));
    }
    let val = providers.credentials_json(cloud_provider_id)?;
    let creds = hetzner_lb::HetznerCloudCreds::from_value(&val)?;
    let lb = match hetzner_lb::find_by_name(&creds, lb_name).await? {
        Some(lb) => lb,
        None => return Ok(()),  // already gone — idempotent.
    };
    hetzner_lb::delete_lb(&creds, lb.id).await
}

async fn teardown_digitalocean_lb(
    providers: &CloudProviderStore,
    cloud_provider_id: &str,
    lb_name: &str,
) -> Result<(), String> {
    let provider = providers.get(cloud_provider_id)
        .ok_or_else(|| format!("cloud provider '{}' not found", cloud_provider_id))?;
    if provider.kind != CloudProviderKind::DigitalOcean {
        return Err(format!("cloud provider '{}' is kind {} not digitalocean", provider.name, provider.kind.label()));
    }
    let val = providers.credentials_json(cloud_provider_id)?;
    let creds = digitalocean_lb::DigitalOceanCreds::from_value(&val)?;
    let lb = match digitalocean_lb::find_by_name(&creds, lb_name).await? {
        Some(lb) => lb,
        None => return Ok(()),
    };
    digitalocean_lb::delete_lb(&creds, &lb.id).await
}

async fn teardown_cloudflare_tunnel(
    providers: &CloudProviderStore,
    cloud_provider_id: &str,
    dns_providers: &crate::dns_providers::DnsProviderStore,
    dns_provider_id: &str,
    tunnel_name: &str,
    server_names: &[String],
) -> Result<(), String> {
    let provider = providers.get(cloud_provider_id)
        .ok_or_else(|| format!("cloud provider '{}' not found", cloud_provider_id))?;
    if provider.kind != CloudProviderKind::Cloudflare {
        return Err(format!("cloud provider '{}' is kind {} not cloudflare", provider.name, provider.kind.label()));
    }
    let val = providers.credentials_json(cloud_provider_id)?;
    let tun_creds = cloudflare_tunnel::CloudflareTunnelCreds::from_value(&val)?;

    // Find the tunnel; if not present we're done. Same shape as the
    // reconcile path.
    let tunnel_id = match super::reconcile::find_tunnel_by_name(&tun_creds, tunnel_name).await? {
        Some(t) => t.id,
        None => return Ok(()),
    };

    let mut errors = Vec::new();

    // Delete the CNAMEs (must come before deleting the tunnel —
    // Cloudflare blocks tunnel deletion while DNS records still
    // reference it).
    if let Ok(dns_creds) = super::reconcile::cloudflare_creds_from_dns_provider(dns_providers, dns_provider_id) {
        for server_name in server_names {
            let zone_name = super::reconcile::strip_to_zone(server_name);
            match cloudflare::lookup_zone_id(&dns_creds, &zone_name).await {
                Ok(Some(zone_id)) => {
                    match cloudflare::list_records(&dns_creds, &zone_id, server_name, "CNAME").await {
                        Ok(recs) => {
                            for r in recs {
                                if let Err(e) = cloudflare::delete_record(&dns_creds, &zone_id, &r.id).await {
                                    errors.push(format!("delete CNAME {}: {}", r.id, e));
                                }
                            }
                        }
                        Err(e) => errors.push(format!("list CNAMEs for {}: {}", server_name, e)),
                    }
                }
                Ok(None) => errors.push(format!("zone for {} not visible in DNS token", server_name)),
                Err(e) => errors.push(format!("lookup zone for {}: {}", server_name, e)),
            }
        }
    } else {
        errors.push("dns provider for tunnel CNAME cleanup unavailable; CNAME records may remain".into());
    }

    // Then delete the tunnel.
    if let Err(e) = cloudflare_tunnel::delete_tunnel(&tun_creds, &tunnel_id).await {
        errors.push(format!("delete tunnel {}: {}", tunnel_id, e));
    }

    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{ProxyTarget, TargetRuntime};

    fn proxy_with_edge(edge: EdgeStrategy) -> HttpProxy {
        HttpProxy {
            id: "p".into(),
            server_names: vec!["a.example.com".into()],
            enabled: true,
            listen_ports: vec![],
            targets: vec![ProxyTarget { node_id: "a".into(), runtime: TargetRuntime::Host }],
            edge,
            upstreams: vec![],
            lb_strategy: Default::default(),
            tls: None,
            force_https: false, hsts: false, http2: false, websocket: false,
            upstream_headers: vec![],
            response_headers: vec![],
            connect_timeout_s: 0, send_timeout_s: 0, read_timeout_s: 0,
            error_pages: vec![],
            access: Default::default(),
            description: String::new(),
            updated_at: String::new(),
            exposure: None,
        }
    }

    #[tokio::test]
    async fn teardown_local_is_noop() {
        let p = proxy_with_edge(EdgeStrategy::Local);
        let warnings = teardown_proxy(&p).await;
        assert!(warnings.is_empty(), "Local teardown produced warnings: {:?}", warnings);
    }

    #[tokio::test]
    async fn teardown_missing_provider_returns_warning_not_panic() {
        // No matching cloud provider exists in the empty default
        // store — teardown should surface a warning, not panic.
        let p = proxy_with_edge(EdgeStrategy::HetznerLb {
            cloud_provider_id: "does-not-exist".into(),
            lb_name: "test-lb".into(),
            location: "fsn1".into(),
            https_passthrough: true,
        });
        let warnings = teardown_proxy(&p).await;
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("does-not-exist") || warnings[0].contains("not found"));
    }
}
