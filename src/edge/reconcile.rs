// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Reconcile loop — bring DNS / LB state in line with what
//! peer-health observations say is actually alive.
//!
//! Single-pass shape: take a snapshot of cluster nodes + their public
//! IPs + online state from `ClusterState`, walk every HTTP proxy with
//! a non-Local edge strategy, and for each one make the provider's
//! state (Cloudflare DNS records, etc.) match the live target set.
//!
//! Idempotent — running the pass twice in a row makes the second pass
//! a no-op (modulo concurrent operator edits). The caller (a tokio
//! background task in main.rs) wraps this in a 30s ticker.
//!
//! Leader election: when 2+ wolfstack nodes are healthy, only one
//! should drive DNS — otherwise two nodes racing to delete-and-re-add
//! the same records produces churn. We pick the leader
//! deterministically: the alive node with the alphabetically-smallest
//! `node_id`. Stable, cheap, no consensus protocol. If it goes down,
//! the next-smallest takes over on the following tick.

use crate::edge::{
    cloudflare, cloudflare_tunnel, digitalocean_dns, digitalocean_lb,
    hetzner_dns, hetzner_lb,
    store::{CloudProviderKind, CloudProviderStore},
    EdgeStrategy,
};
use crate::networking::router::http_proxy::HttpProxy;

/// Per-proxy reconcile outcome. Aggregated across the pass and
/// surfaced via /api/router/http-proxies/reconcile-status so the UI
/// can render "DNS updated for foo.example.com — 3 IPs now live".
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyReconcileReport {
    pub proxy_id: String,
    pub server_names: Vec<String>,
    /// IPs currently in DNS for the canonical server_name. Pre-reconcile
    /// state is `before`, post-reconcile is `after`.
    pub before: Vec<String>,
    pub after: Vec<String>,
    /// Net change — counts of records added / removed / unchanged.
    pub added: u32,
    pub removed: u32,
    pub unchanged: u32,
    /// Empty on success; populated when the provider call failed.
    /// The whole proxy's reconcile is best-effort: one failed
    /// server_name doesn't abort the others.
    pub errors: Vec<String>,
}

/// Snapshot input — cluster view at the start of the pass. Captured
/// once so the rest of the pass runs against a stable view (otherwise
/// the gossip-driven aliveness flapping mid-pass produces flapping
/// DNS records).
pub struct ClusterSnapshot {
    /// node_id → (public_ip, is_online). Only wolfstack-type nodes.
    pub nodes: std::collections::HashMap<String, (String, bool)>,
    /// Our own node_id, for leader-election self-check.
    pub self_node_id: String,
}

impl ClusterSnapshot {
    /// Build from the live `ClusterState`. Keys are the peer-known
    /// `self_id` (the `ws-...` ID, populated by the agent's gossip
    /// reply), not the locally-assigned `node-...` key — because
    /// `ProxyTarget.node_id` carries the self_id form (it's what the
    /// operator sees in the dropdown). For the management node itself
    /// we fall back to the local key when no self_id is present.
    pub fn from_cluster_state(cluster: &crate::agent::ClusterState) -> Self {
        use std::collections::HashMap;
        let mut nodes: HashMap<String, (String, bool)> = HashMap::new();
        let self_node_id = crate::agent::self_node_id();
        for n in cluster.get_all_nodes() {
            if n.node_type != "wolfstack" { continue; }
            let id = n.self_id.clone().unwrap_or_else(|| n.id.clone());
            let ip = n.public_ip.clone().unwrap_or_default();
            // get_all_nodes already computes online status; reuse it
            // rather than re-checking against last_seen here.
            nodes.insert(id, (ip, n.online));
        }
        // Self-node always considered online (it's running this code).
        if let Some(entry) = nodes.get_mut(&self_node_id) {
            entry.1 = true;
        }
        ClusterSnapshot { nodes, self_node_id }
    }
}

/// Run one reconcile pass. Returns the per-proxy reports for logging.
///
/// `should_drive` short-circuits when this node isn't the elected
/// leader for the current tick — see `am_i_leader`.
pub async fn run_pass(
    proxies: &[HttpProxy],
    snapshot: &ClusterSnapshot,
    providers: &CloudProviderStore,
    dns_providers: &crate::dns_providers::DnsProviderStore,
    should_drive: bool,
) -> Vec<ProxyReconcileReport> {
    let mut reports = Vec::new();
    if !should_drive {
        // Not the leader — bail. We still emit empty reports so the
        // logs make it obvious why no DNS calls happened ("am I
        // leader? no, X is").
        return reports;
    }

    for p in proxies {
        if !p.edge.manages_dns() { continue; }
        // Compute the live IP set for this proxy: target nodes that
        // are (a) wolfstack-type per snapshot, (b) online per gossip.
        let live_ips = live_ips_for(p, snapshot);
        for server_name in &p.server_names {
            match reconcile_one(p, server_name, &live_ips, providers, dns_providers).await {
                Ok(mut r) => {
                    r.proxy_id = p.id.clone();
                    r.server_names = vec![server_name.clone()];
                    reports.push(r);
                }
                Err(e) => {
                    reports.push(ProxyReconcileReport {
                        proxy_id: p.id.clone(),
                        server_names: vec![server_name.clone()],
                        before: Vec::new(),
                        after: Vec::new(),
                        added: 0,
                        removed: 0,
                        unchanged: 0,
                        errors: vec![e],
                    });
                }
            }
        }
    }
    reports
}

/// Build the live IP set for a proxy given the cluster snapshot.
/// Targets whose node is offline (or absent) are dropped. Order is
/// stable (sorted) so the snapshot diff downstream stays predictable.
fn live_ips_for(proxy: &HttpProxy, snapshot: &ClusterSnapshot) -> Vec<String> {
    let mut ips = Vec::new();
    for t in &proxy.targets {
        if let Some((ip, online)) = snapshot.nodes.get(&t.node_id) {
            if *online && !ip.is_empty() {
                ips.push(ip.clone());
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

async fn reconcile_one(
    proxy: &HttpProxy,
    server_name: &str,
    live_ips: &[String],
    providers: &CloudProviderStore,
    dns_providers: &crate::dns_providers::DnsProviderStore,
) -> Result<ProxyReconcileReport, String> {
    match &proxy.edge {
        EdgeStrategy::Local => unreachable!("filtered by manages_dns"),

        EdgeStrategy::DnsRoundRobin { dns_provider_id, ttl_seconds } => {
            // Route by the DNS provider's plugin so the same edge
            // strategy works for any provider we've implemented.
            let provider = dns_providers.get(dns_provider_id)
                .ok_or_else(|| format!("dns provider '{}' not found", dns_provider_id))?;
            match provider.plugin.as_str() {
                "cloudflare" => {
                    let creds = cloudflare_creds_from_dns_provider(dns_providers, dns_provider_id)?;
                    reconcile_cloudflare(&creds, server_name, live_ips, *ttl_seconds, /*proxied=*/false).await
                }
                "hetzner" => {
                    let creds = hetzner_dns_creds_from_dns_provider(dns_providers, dns_provider_id)?;
                    reconcile_hetzner_dns(&creds, server_name, live_ips, *ttl_seconds).await
                }
                "digitalocean" => {
                    let creds = digitalocean_creds_from_dns_provider(dns_providers, dns_provider_id)?;
                    reconcile_digitalocean_dns(&creds, server_name, live_ips, *ttl_seconds).await
                }
                other => Err(format!(
                    "DnsRoundRobin: DNS provider '{}' uses plugin '{}', which isn't supported yet. \
                     v23.2 supports cloudflare, hetzner, digitalocean — for others, switch the proxy's edge to Local.",
                    provider.name, other
                )),
            }
        }

        EdgeStrategy::CloudflareDns { dns_provider_id, ttl_seconds } => {
            // Cloudflare-orange-cloud is always Cloudflare; hard-
            // validate the provider plugin here.
            let provider = dns_providers.get(dns_provider_id)
                .ok_or_else(|| format!("dns provider '{}' not found", dns_provider_id))?;
            if provider.plugin != "cloudflare" {
                return Err(format!(
                    "CloudflareDns requires a cloudflare DNS provider — '{}' has plugin '{}'.",
                    provider.name, provider.plugin
                ));
            }
            let creds = cloudflare_creds_from_dns_provider(dns_providers, dns_provider_id)?;
            reconcile_cloudflare(&creds, server_name, live_ips, *ttl_seconds, /*proxied=*/true).await
        }

        EdgeStrategy::HetznerLb { cloud_provider_id, lb_name, location, https_passthrough } => {
            reconcile_hetzner_lb(providers, cloud_provider_id, lb_name, location, *https_passthrough, live_ips, server_name).await
        }

        EdgeStrategy::DigitalOceanLb { cloud_provider_id, lb_name, region, https_passthrough } => {
            reconcile_digitalocean_lb(providers, cloud_provider_id, lb_name, region, *https_passthrough, live_ips, server_name).await
        }

        EdgeStrategy::CloudflareTunnel { cloud_provider_id, dns_provider_id, tunnel_name } => {
            reconcile_cloudflare_tunnel(providers, cloud_provider_id, dns_providers, dns_provider_id, tunnel_name, server_name, proxy).await
        }
    }
}

/// Map an entry in the DnsProviderStore (which holds an INI for
/// certbot) to CloudflareCreds (which expects `api_token`). The
/// certbot INI format for the cloudflare plugin is:
///
///   dns_cloudflare_api_token = <token>
///
/// We grep the file for that line. If it's not there, return a
/// clear error.
pub(super) fn cloudflare_creds_from_dns_provider(
    dns_providers: &crate::dns_providers::DnsProviderStore,
    id: &str,
) -> Result<cloudflare::CloudflareCreds, String> {
    let creds_path_or_inline = dns_providers.materialize(id)
        .map_err(|e| format!("read dns provider '{}': {}", id, e))?;
    let raw = std::fs::read_to_string(&creds_path_or_inline.path)
        .map_err(|e| format!("read materialized creds {}: {}", creds_path_or_inline.path, e))?;
    let mut token = String::new();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("dns_cloudflare_api_token") {
            // formats: "dns_cloudflare_api_token = X" / "= X" / ":X"
            let val = rest.trim_start_matches(&[' ', '=', ':'][..]).trim();
            if !val.is_empty() { token = val.to_string(); break; }
        }
    }
    if token.is_empty() {
        return Err(format!(
            "dns provider '{}' has no dns_cloudflare_api_token line in its INI — \
             reconcile needs a Cloudflare API token. (The credentials file is automatically \
             unlinked when materialize_creds goes out of scope.)",
            id
        ));
    }
    Ok(cloudflare::CloudflareCreds { api_token: token })
}

async fn reconcile_cloudflare(
    creds: &cloudflare::CloudflareCreds,
    server_name: &str,
    desired_ips: &[String],
    ttl: u32,
    proxied: bool,
) -> Result<ProxyReconcileReport, String> {
    let zone_name = strip_to_zone(server_name);
    let zone_id = cloudflare::lookup_zone_id(creds, &zone_name).await?
        .ok_or_else(|| format!(
            "cloudflare token doesn't see zone '{}' — give the token Zone:Read + DNS:Edit on this zone",
            zone_name
        ))?;

    let existing = cloudflare::list_a_records(creds, &zone_id, server_name).await?;
    let before: Vec<String> = {
        let mut v: Vec<String> = existing.iter().map(|r| r.content.clone()).collect();
        v.sort();
        v
    };
    let desired: std::collections::HashSet<&str> = desired_ips.iter().map(|s| s.as_str()).collect();
    let existing_by_ip: std::collections::HashMap<&str, &cloudflare::DnsRecord> =
        existing.iter().map(|r| (r.content.as_str(), r)).collect();

    let mut added = 0u32;
    let mut removed = 0u32;
    let mut unchanged = 0u32;
    let mut errors = Vec::new();

    // Add records for desired IPs that aren't currently in DNS.
    for ip in desired_ips {
        if let Some(_existing) = existing_by_ip.get(ip.as_str()) {
            unchanged += 1;
        } else {
            match cloudflare::create_a_record(creds, &zone_id, server_name, ip, ttl, proxied).await {
                Ok(_) => added += 1,
                Err(e) => errors.push(format!("create A {} {} → {}: {}", server_name, ip, if proxied { "proxied" } else { "unproxied" }, e)),
            }
        }
    }
    // Remove records whose IPs are no longer in the desired set.
    for rec in &existing {
        if !desired.contains(rec.content.as_str()) {
            match cloudflare::delete_record(creds, &zone_id, &rec.id).await {
                Ok(_) => removed += 1,
                Err(e) => errors.push(format!("delete A {} {} (id={}): {}", server_name, rec.content, rec.id, e)),
            }
        }
    }

    let after: Vec<String> = {
        let mut v: Vec<String> = desired_ips.to_vec();
        v.sort();
        v
    };

    Ok(ProxyReconcileReport {
        proxy_id: String::new(),       // caller fills
        server_names: Vec::new(),      // caller fills
        before,
        after,
        added,
        removed,
        unchanged,
        errors,
    })
}

/// Walk back from "foo.bar.example.com" to "example.com" — that's the
/// zone we'll ask Cloudflare to look up. Just strips the host label.
/// For "*.example.com" the wildcard prefix isn't part of the zone, so
/// we drop it too. Doesn't handle public-suffix-list-aware splits —
/// Cloudflare's zone-lookup endpoint resolves whatever zone the
/// operator's token has access to.
pub(super) fn strip_to_zone(fqdn: &str) -> String {
    let fqdn = fqdn.trim().trim_end_matches('.');
    let parts: Vec<&str> = fqdn.split('.').collect();
    if parts.len() <= 2 {
        return fqdn.to_string();
    }
    // For one-host-deep names like "api.example.com", "example.com" is the zone.
    // For deeper names like "v2.api.example.com", Cloudflare's zone lookup needs
    // the actual configured zone — usually "example.com" still, but it could
    // also be "api.example.com" if the operator configured it as a separate
    // zone. We try the most-likely answer (last two labels); if Cloudflare's
    // zone-not-found is the failure, the operator's error message is clear
    // enough to fix it.
    let zone = parts[parts.len()-2..].join(".");
    zone
}

/// Deterministic leader election. Returns true if `self_node_id` is
/// the alphabetically-smallest alive wolfstack node in the snapshot
/// (or there's only one node, or no peers visible). Cheap to compute,
/// stable across the cluster (every node makes the same decision
/// given the same gossip view), and fails over the next tick when
/// the leader drops.
pub fn am_i_leader(snapshot: &ClusterSnapshot) -> bool {
    let mut alive_ids: Vec<&String> = snapshot.nodes.iter()
        .filter_map(|(id, (_ip, online))| if *online { Some(id) } else { None })
        .collect();
    alive_ids.sort();
    alive_ids.first().map(|id| **id == snapshot.self_node_id).unwrap_or(true)
}

// ─── Hetzner DNS reconcile ─────────────────────────────────────────────

/// Read the certbot-dns-hetzner INI line `dns_hetzner_api_token = …`
/// from a materialised DNS-provider creds file. lego + certbot-dns-
/// hetzner both standardise on that exact key.
pub(super) fn hetzner_dns_creds_from_dns_provider(
    dns_providers: &crate::dns_providers::DnsProviderStore,
    id: &str,
) -> Result<hetzner_dns::HetznerDnsCreds, String> {
    let materialised = dns_providers.materialize(id)
        .map_err(|e| format!("read dns provider '{}': {}", id, e))?;
    let raw = std::fs::read_to_string(&materialised.path)
        .map_err(|e| format!("read materialized creds {}: {}", materialised.path, e))?;
    let token = ini_value(&raw, "dns_hetzner_api_token");
    if token.is_empty() {
        return Err(format!(
            "dns provider '{}' has no dns_hetzner_api_token line in its INI", id
        ));
    }
    Ok(hetzner_dns::HetznerDnsCreds { api_token: token })
}

async fn reconcile_hetzner_dns(
    creds: &hetzner_dns::HetznerDnsCreds,
    server_name: &str,
    desired_ips: &[String],
    ttl: u32,
) -> Result<ProxyReconcileReport, String> {
    let zone_name = strip_to_zone(server_name);
    let zone_id = hetzner_dns::lookup_zone_id(creds, &zone_name).await?
        .ok_or_else(|| format!(
            "hetzner DNS token doesn't see zone '{}' — add it in the Hetzner DNS console or grant access on the token",
            zone_name
        ))?;

    let existing = hetzner_dns::list_a_records_for_fqdn(creds, &zone_id, &zone_name, server_name).await?;
    let before: Vec<String> = {
        let mut v: Vec<String> = existing.iter().map(|r| r.value.clone()).collect();
        v.sort();
        v
    };
    let desired: std::collections::HashSet<&str> = desired_ips.iter().map(|s| s.as_str()).collect();
    let existing_by_ip: std::collections::HashMap<&str, &hetzner_dns::DnsRecord> =
        existing.iter().map(|r| (r.value.as_str(), r)).collect();

    let mut added = 0u32;
    let mut removed = 0u32;
    let mut unchanged = 0u32;
    let mut errors = Vec::new();

    for ip in desired_ips {
        if existing_by_ip.contains_key(ip.as_str()) {
            unchanged += 1;
        } else {
            match hetzner_dns::create_a_record(creds, &zone_id, &zone_name, server_name, ip, ttl).await {
                Ok(_) => added += 1,
                Err(e) => errors.push(format!("hetzner create A {} {}: {}", server_name, ip, e)),
            }
        }
    }
    for rec in &existing {
        if !desired.contains(rec.value.as_str()) {
            match hetzner_dns::delete_record(creds, &rec.id).await {
                Ok(_) => removed += 1,
                Err(e) => errors.push(format!("hetzner delete A {} {} (id={}): {}", server_name, rec.value, rec.id, e)),
            }
        }
    }

    let after: Vec<String> = { let mut v = desired_ips.to_vec(); v.sort(); v };
    Ok(ProxyReconcileReport {
        proxy_id: String::new(), server_names: Vec::new(),
        before, after, added, removed, unchanged, errors,
    })
}

// ─── DigitalOcean DNS reconcile ────────────────────────────────────────

pub(super) fn digitalocean_creds_from_dns_provider(
    dns_providers: &crate::dns_providers::DnsProviderStore,
    id: &str,
) -> Result<digitalocean_dns::DigitalOceanCreds, String> {
    let materialised = dns_providers.materialize(id)
        .map_err(|e| format!("read dns provider '{}': {}", id, e))?;
    let raw = std::fs::read_to_string(&materialised.path)
        .map_err(|e| format!("read materialized creds {}: {}", materialised.path, e))?;
    let token = ini_value(&raw, "dns_digitalocean_token");
    if token.is_empty() {
        return Err(format!(
            "dns provider '{}' has no dns_digitalocean_token line in its INI", id
        ));
    }
    Ok(digitalocean_dns::DigitalOceanCreds { api_token: token })
}

async fn reconcile_digitalocean_dns(
    creds: &digitalocean_dns::DigitalOceanCreds,
    server_name: &str,
    desired_ips: &[String],
    ttl: u32,
) -> Result<ProxyReconcileReport, String> {
    let zone = strip_to_zone(server_name);
    if !digitalocean_dns::zone_exists(creds, &zone).await? {
        return Err(format!(
            "digitalocean account doesn't have domain '{}' — add it under Networking → Domains first",
            zone
        ));
    }

    let existing = digitalocean_dns::list_a_records_for_fqdn(creds, &zone, server_name).await?;
    let before: Vec<String> = {
        let mut v: Vec<String> = existing.iter().map(|r| r.data.clone()).collect();
        v.sort();
        v
    };
    let desired: std::collections::HashSet<&str> = desired_ips.iter().map(|s| s.as_str()).collect();
    let existing_by_ip: std::collections::HashMap<&str, &digitalocean_dns::DnsRecord> =
        existing.iter().map(|r| (r.data.as_str(), r)).collect();

    let mut added = 0u32;
    let mut removed = 0u32;
    let mut unchanged = 0u32;
    let mut errors = Vec::new();

    for ip in desired_ips {
        if existing_by_ip.contains_key(ip.as_str()) {
            unchanged += 1;
        } else {
            match digitalocean_dns::create_a_record(creds, &zone, server_name, ip, ttl).await {
                Ok(_) => added += 1,
                Err(e) => errors.push(format!("digitalocean create A {} {}: {}", server_name, ip, e)),
            }
        }
    }
    for rec in &existing {
        if !desired.contains(rec.data.as_str()) {
            match digitalocean_dns::delete_record(creds, &zone, rec.id).await {
                Ok(_) => removed += 1,
                Err(e) => errors.push(format!("digitalocean delete A {} {} (id={}): {}", server_name, rec.data, rec.id, e)),
            }
        }
    }

    let after: Vec<String> = { let mut v = desired_ips.to_vec(); v.sort(); v };
    Ok(ProxyReconcileReport {
        proxy_id: String::new(), server_names: Vec::new(),
        before, after, added, removed, unchanged, errors,
    })
}

// ─── Hetzner Cloud LB reconcile ────────────────────────────────────────

async fn reconcile_hetzner_lb(
    providers: &CloudProviderStore,
    cloud_provider_id: &str,
    lb_name: &str,
    location: &str,
    https_passthrough: bool,
    desired_ips: &[String],
    server_name: &str,
) -> Result<ProxyReconcileReport, String> {
    let provider = providers.get(cloud_provider_id)
        .ok_or_else(|| format!("cloud provider '{}' not found", cloud_provider_id))?;
    if provider.kind != CloudProviderKind::Hetzner {
        return Err(format!(
            "HetznerLb requires a hetzner cloud provider — '{}' is kind '{}'.",
            provider.name, provider.kind.label()
        ));
    }
    let val = providers.credentials_json(cloud_provider_id)?;
    let creds = hetzner_lb::HetznerCloudCreds::from_value(&val)?;

    let mut errors = Vec::new();
    let existing = hetzner_lb::find_by_name(&creds, lb_name).await?;
    let (lb_id, existing_ips): (i64, Vec<String>) = match existing {
        Some(lb) => {
            let ips: Vec<String> = lb.targets.iter()
                .filter_map(|t| t.ip.as_ref().map(|i| i.ip.clone()))
                .collect();
            (lb.id, ips)
        }
        None => {
            // Create with the full live set in one shot.
            let lb = hetzner_lb::create_lb(&creds, lb_name, location, desired_ips, https_passthrough).await?;
            let public_ip = lb.public_net.ipv4.as_ref().map(|i| i.ip.clone()).unwrap_or_default();
            return Ok(ProxyReconcileReport {
                proxy_id: String::new(), server_names: Vec::new(),
                before: Vec::new(),
                after: desired_ips.to_vec(),
                added: desired_ips.len() as u32,
                removed: 0, unchanged: 0,
                errors: vec![format!(
                    "Hetzner LB '{}' created (public IP {}). Point DNS for {} at this IP.",
                    lb_name, public_ip, server_name
                )],
            });
        }
    };

    let desired_set: std::collections::HashSet<&str> = desired_ips.iter().map(|s| s.as_str()).collect();
    let existing_set: std::collections::HashSet<&str> = existing_ips.iter().map(|s| s.as_str()).collect();

    let mut added = 0u32;
    let mut removed = 0u32;
    for ip in desired_ips {
        if existing_set.contains(ip.as_str()) { continue; }
        match hetzner_lb::add_target_ip(&creds, lb_id, ip).await {
            Ok(_) => added += 1,
            Err(e) => errors.push(format!("hetzner add target {}: {}", ip, e)),
        }
    }
    for ip in &existing_ips {
        if desired_set.contains(ip.as_str()) { continue; }
        match hetzner_lb::remove_target_ip(&creds, lb_id, ip).await {
            Ok(_) => removed += 1,
            Err(e) => errors.push(format!("hetzner remove target {}: {}", ip, e)),
        }
    }
    let unchanged: u32 = desired_ips.iter()
        .filter(|ip| existing_set.contains(ip.as_str())).count() as u32;
    let mut before = existing_ips.clone(); before.sort();
    let mut after = desired_ips.to_vec(); after.sort();
    Ok(ProxyReconcileReport {
        proxy_id: String::new(), server_names: Vec::new(),
        before, after, added, removed, unchanged, errors,
    })
}

// ─── DigitalOcean LB reconcile ─────────────────────────────────────────

async fn reconcile_digitalocean_lb(
    providers: &CloudProviderStore,
    cloud_provider_id: &str,
    lb_name: &str,
    region: &str,
    https_passthrough: bool,
    desired_ips: &[String],
    _server_name: &str,
) -> Result<ProxyReconcileReport, String> {
    let provider = providers.get(cloud_provider_id)
        .ok_or_else(|| format!("cloud provider '{}' not found", cloud_provider_id))?;
    if provider.kind != CloudProviderKind::DigitalOcean {
        return Err(format!(
            "DigitalOceanLb requires a digitalocean cloud provider — '{}' is kind '{}'.",
            provider.name, provider.kind.label()
        ));
    }
    let val = providers.credentials_json(cloud_provider_id)?;
    let creds = digitalocean_lb::DigitalOceanCreds::from_value(&val)?;

    // DigitalOcean LBs target *droplets*, not arbitrary IPs. Resolve
    // each desired IP to a droplet id. Anything we can't resolve gets
    // surfaced as an error — that node won't be served from this LB
    // until it has a droplet record in this DO account.
    let mut errors = Vec::new();
    let droplets = list_do_droplets(&creds).await?;
    let mut desired_droplet_ids: Vec<u64> = Vec::new();
    for ip in desired_ips {
        match droplets.iter().find(|d| d.has_ip(ip)) {
            Some(d) => desired_droplet_ids.push(d.id),
            None => errors.push(format!(
                "no DigitalOcean droplet in this account has IP {} — DO LBs can only target droplets",
                ip
            )),
        }
    }

    let existing = digitalocean_lb::find_by_name(&creds, lb_name).await?;
    let (lb_id, existing_ids) = match existing {
        Some(lb) => (lb.id.clone(), lb.droplet_ids.clone()),
        None => {
            let lb = digitalocean_lb::create_lb(&creds, lb_name, region, &desired_droplet_ids, https_passthrough).await?;
            errors.insert(0, format!(
                "DigitalOcean LB '{}' created (id {}, ip {}). Point DNS at the LB IP.",
                lb_name, lb.id, lb.ip
            ));
            return Ok(ProxyReconcileReport {
                proxy_id: String::new(), server_names: Vec::new(),
                before: Vec::new(),
                after: desired_ips.to_vec(),
                added: desired_droplet_ids.len() as u32,
                removed: 0, unchanged: 0,
                errors,
            });
        }
    };

    let desired_set: std::collections::HashSet<u64> = desired_droplet_ids.iter().copied().collect();
    let existing_set: std::collections::HashSet<u64> = existing_ids.iter().copied().collect();

    let to_add: Vec<u64> = desired_droplet_ids.iter().copied()
        .filter(|id| !existing_set.contains(id)).collect();
    let to_remove: Vec<u64> = existing_ids.iter().copied()
        .filter(|id| !desired_set.contains(id)).collect();

    let added = to_add.len() as u32;
    let removed = to_remove.len() as u32;
    let unchanged = (existing_set.len() as u32).saturating_sub(removed);
    if !to_add.is_empty() {
        if let Err(e) = digitalocean_lb::add_droplets(&creds, &lb_id, &to_add).await {
            errors.push(format!("digitalocean add droplets {:?}: {}", to_add, e));
        }
    }
    if !to_remove.is_empty() {
        if let Err(e) = digitalocean_lb::remove_droplets(&creds, &lb_id, &to_remove).await {
            errors.push(format!("digitalocean remove droplets {:?}: {}", to_remove, e));
        }
    }
    let mut before = desired_ips.to_vec(); before.sort();
    let mut after = desired_ips.to_vec(); after.sort();
    Ok(ProxyReconcileReport {
        proxy_id: String::new(), server_names: Vec::new(),
        before, after, added, removed, unchanged, errors,
    })
}

/// Minimal droplet view used for IP → id resolution. DO returns
/// nested public/private networks; we flatten to a list of v4 IPs
/// for matching.
#[derive(Debug, Clone)]
struct DoDroplet {
    id: u64,
    v4_ips: Vec<String>,
}
impl DoDroplet {
    fn has_ip(&self, ip: &str) -> bool {
        self.v4_ips.iter().any(|x| x == ip)
    }
}

async fn list_do_droplets(creds: &digitalocean_lb::DigitalOceanCreds) -> Result<Vec<DoDroplet>, String> {
    // Use the DO HTTP client through a one-shot reqwest call —
    // mirrors what the digitalocean_lb client does internally but the
    // droplet shape isn't worth exposing from that module.
    let url = "https://api.digitalocean.com/v2/droplets?per_page=200";
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("build reqwest: {}", e))?;
    let resp = client.get(url).bearer_auth(&creds.api_token).send().await
        .map_err(|e| format!("digitalocean GET /droplets: {}", e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("digitalocean GET /droplets: HTTP {}: {}",
            status, text.chars().take(200).collect::<String>()));
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("digitalocean droplets bad JSON: {}", e))?;
    let mut out = Vec::new();
    if let Some(arr) = v["droplets"].as_array() {
        for d in arr {
            let id = d["id"].as_u64().unwrap_or(0);
            if id == 0 { continue; }
            let mut v4_ips = Vec::new();
            if let Some(v4) = d["networks"]["v4"].as_array() {
                for n in v4 {
                    if let Some(ip) = n["ip_address"].as_str() {
                        v4_ips.push(ip.to_string());
                    }
                }
            }
            out.push(DoDroplet { id, v4_ips });
        }
    }
    Ok(out)
}

// ─── Cloudflare Tunnel reconcile ───────────────────────────────────────

async fn reconcile_cloudflare_tunnel(
    providers: &CloudProviderStore,
    cloud_provider_id: &str,
    dns_providers: &crate::dns_providers::DnsProviderStore,
    dns_provider_id: &str,
    tunnel_name: &str,
    server_name: &str,
    _proxy: &HttpProxy,
) -> Result<ProxyReconcileReport, String> {
    let provider = providers.get(cloud_provider_id)
        .ok_or_else(|| format!("cloud provider '{}' not found", cloud_provider_id))?;
    if provider.kind != CloudProviderKind::Cloudflare {
        return Err(format!(
            "CloudflareTunnel requires a cloudflare cloud provider — '{}' is kind '{}'.",
            provider.name, provider.kind.label()
        ));
    }
    let val = providers.credentials_json(cloud_provider_id)?;
    let tun_creds = cloudflare_tunnel::CloudflareTunnelCreds::from_value(&val)?;

    // Find existing tunnel by name, or create. The Cloudflare list-
    // tunnels endpoint accepts ?name= as a filter.
    let tunnel = match find_tunnel_by_name(&tun_creds, tunnel_name).await? {
        Some(t) => t,
        None => cloudflare_tunnel::create_tunnel(&tun_creds, tunnel_name).await?,
    };

    // Push ingress rules. WolfStack-local nginx listens on :80 inside
    // the node; cloudflared on the same node forwards to it. The
    // tunnel's ingress is therefore one rule per server_name routing
    // to http://localhost:80 plus the mandatory catch-all (the client
    // module adds it automatically).
    let ingress = vec![cloudflare_tunnel::IngressRule {
        hostname: Some(server_name.to_string()),
        service: "http://localhost:80".to_string(),
        path: None,
    }];
    cloudflare_tunnel::put_tunnel_configuration(&tun_creds, &tunnel.id, &ingress).await?;

    // Create the public CNAME pointing at <tunnel-id>.cfargotunnel.com.
    // Reuse the DNS-provider creds because the user already configured
    // a Cloudflare DNS provider for the zone — same token can write
    // DNS records (token must have DNS:Edit on the zone).
    let dns_creds = cloudflare_creds_from_dns_provider(dns_providers, dns_provider_id)?;
    let zone_name = strip_to_zone(server_name);
    let zone_id = cloudflare::lookup_zone_id(&dns_creds, &zone_name).await?
        .ok_or_else(|| format!(
            "cloudflare DNS token doesn't see zone '{}'",
            zone_name
        ))?;
    cloudflare_tunnel::create_tunnel_cname(&tun_creds, &zone_id, server_name, &tunnel.id).await?;

    Ok(ProxyReconcileReport {
        proxy_id: String::new(), server_names: Vec::new(),
        before: Vec::new(),
        after: vec![format!("{}.cfargotunnel.com", tunnel.id)],
        added: 1, removed: 0, unchanged: 0,
        errors: if tunnel.token.is_empty() {
            vec![format!(
                "Tunnel '{}' ready. Run cloudflared on each target node — fetch the connector token via /api/edge/cloudflare-tunnel/{}/token.",
                tunnel_name, tunnel.id
            )]
        } else {
            vec![format!(
                "Tunnel '{}' ready. Install cloudflared on each target node using the create-time token.",
                tunnel_name
            )]
        },
    })
}

pub async fn find_tunnel_by_name(
    creds: &cloudflare_tunnel::CloudflareTunnelCreds, name: &str,
) -> Result<Option<cloudflare_tunnel::Tunnel>, String> {
    // Cloudflare's list-tunnels endpoint returns paginated results;
    // we only need the first page since tunnel names are unique per
    // account in practice.
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel?name={}&is_deleted=false&per_page=50",
        urlencode_str(&creds.account_id), urlencode_str(name)
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("build reqwest: {}", e))?;
    let resp = client.get(&url).bearer_auth(&creds.api_token).send().await
        .map_err(|e| format!("cf-tunnel list: {}", e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("cf-tunnel list: HTTP {}: {}", status, text.chars().take(200).collect::<String>()));
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("cf-tunnel list: bad JSON: {}", e))?;
    if let Some(arr) = v["result"].as_array() {
        for entry in arr {
            if entry["name"].as_str() == Some(name) {
                let id = entry["id"].as_str().unwrap_or("").to_string();
                if !id.is_empty() {
                    return Ok(Some(cloudflare_tunnel::Tunnel {
                        id,
                        name: name.to_string(),
                        status: entry["status"].as_str().unwrap_or("").to_string(),
                        token: String::new(),
                    }));
                }
            }
        }
    }
    Ok(None)
}

// ─── INI parsing helper ────────────────────────────────────────────────

/// Extract the value of a single key from a certbot-style INI blob.
/// Returns empty string when the key is absent or has no value.
/// Accepts `key = value`, `key=value`, and `key: value` forms.
fn ini_value(raw: &str, key: &str) -> String {
    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            let val = rest.trim_start_matches(&[' ', '=', ':'][..]).trim();
            if !val.is_empty() { return val.to_string(); }
        }
    }
    String::new()
}

fn urlencode_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{ProxyTarget, TargetRuntime};
    use std::collections::HashMap;

    fn snap(self_id: &str, nodes: &[(&str, &str, bool)]) -> ClusterSnapshot {
        let mut m = HashMap::new();
        for (id, ip, online) in nodes {
            m.insert(id.to_string(), (ip.to_string(), *online));
        }
        ClusterSnapshot { nodes: m, self_node_id: self_id.into() }
    }

    #[test]
    fn live_ips_only_includes_online_targets() {
        let p = HttpProxy {
            id: "p".into(),
            server_names: vec!["a.example.com".into()],
            enabled: true,
            listen_ports: vec![],
            targets: vec![
                ProxyTarget { node_id: "a".into(), runtime: TargetRuntime::Host },
                ProxyTarget { node_id: "b".into(), runtime: TargetRuntime::Host },
                ProxyTarget { node_id: "c".into(), runtime: TargetRuntime::Host },
            ],
            edge: EdgeStrategy::Local,
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
        };
        let s = snap("a", &[
            ("a", "1.1.1.1", true),
            ("b", "2.2.2.2", false),  // offline — should be excluded
            ("c", "3.3.3.3", true),
            // "d" not present — also excluded
        ]);
        let ips = live_ips_for(&p, &s);
        assert_eq!(ips, vec!["1.1.1.1".to_string(), "3.3.3.3".to_string()]);
    }

    #[test]
    fn leader_election_picks_smallest_alive_id() {
        let s = snap("b", &[
            ("a", "ip", true),
            ("b", "ip", true),
            ("c", "ip", true),
        ]);
        // Self is "b", smallest alive is "a", so b is not leader.
        assert!(!am_i_leader(&s));

        let s = snap("a", &[
            ("a", "ip", true),
            ("b", "ip", true),
        ]);
        assert!(am_i_leader(&s));

        let s = snap("b", &[
            ("a", "ip", false),  // a is offline
            ("b", "ip", true),
        ]);
        // a is the smallest id but it's offline; b takes over.
        assert!(am_i_leader(&s));
    }

    #[test]
    fn leader_when_alone() {
        let s = snap("a", &[("a", "ip", true)]);
        assert!(am_i_leader(&s));
    }

    #[test]
    fn strip_to_zone_works_for_common_shapes() {
        assert_eq!(strip_to_zone("example.com"), "example.com");
        assert_eq!(strip_to_zone("api.example.com"), "example.com");
        assert_eq!(strip_to_zone("v2.api.example.com"), "example.com");
        assert_eq!(strip_to_zone("example.com."), "example.com");
    }
}
