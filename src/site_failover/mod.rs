// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Website failover across `Host`-role nodes.
//!
//! NoroNetwork 2026-07-09: "Multiple Host servers, that run all the clients
//! website. The data should be redundant (currently I use Ceph) so even if one
//! node goes down another will transfer and serve the website data."
//!
//! The data-redundancy half already exists — a client's docroot lives on shared
//! storage (Ceph / WolfDisk / Gluster), which WolfStack already manages, so any
//! [`Host`](crate::agent::NodeRole::Host) node can read it. What's missing is
//! the CONTROL half this module provides: track which Host node currently
//! *serves* each site, notice when that node goes offline, and re-assign its
//! sites to a surviving Host node so the ingress can re-point to it.
//!
//! Failover is a two-part motion, both already built elsewhere:
//!   1. A surviving Host node renders the vhost and serves the (shared) docroot.
//!   2. The ingress re-points that site's upstream to the new Host — exactly the
//!      re-point the [Internet Exposure](crate::exposure) reconciler already does
//!      when a workload moves.
//!
//! This module owns the *decision*: given the live Host-node set, which node
//! should serve each site. The planning is pure and unit-tested; executing a
//! reassignment updates the site's `active_host` and hands the re-point to the
//! router. Scope (v1): planning + model + status + reassignment. Automatic
//! docroot verification on the target (is the shared mount actually present?)
//! and full unattended failover are hardware-verification work, flagged in the
//! plan output.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const SITE_FAILOVER_CONFIG_PATH: &str = "/etc/wolfstack/site_failover.json";
static SF_IO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A website whose docroot is on shared storage and which any Host node can
/// serve. WolfStack tracks who currently serves it and who can take over.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostedSite {
    /// The site's domain (also its id).
    pub domain: String,
    /// Docroot path on the SHARED storage — identical on every Host node
    /// because the mount is shared (e.g. /mnt/ceph/sites/<domain>).
    pub docroot: String,
    /// WolfStack Host node id currently serving the site.
    pub active_host: String,
    /// WolfStack cluster this site belongs to (scopes the UI).
    #[serde(default)]
    pub cluster: String,
    /// Backend port the Host node serves the site on (for the ingress upstream).
    #[serde(default = "default_site_port")]
    pub port: u16,
}

fn default_site_port() -> u16 { 80 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteFailoverConfig {
    #[serde(default)]
    pub sites: Vec<HostedSite>,
}

// ── Persistence ──────────────────────────────────────────────────────

pub fn load_config() -> SiteFailoverConfig {
    match fs::read_to_string(SITE_FAILOVER_CONFIG_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => SiteFailoverConfig::default(),
    }
}

pub fn save_config(cfg: &SiteFailoverConfig) -> Result<(), String> {
    if let Some(parent) = Path::new(SITE_FAILOVER_CONFIG_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(SITE_FAILOVER_CONFIG_PATH, json).map_err(|e| format!("write {}: {}", SITE_FAILOVER_CONFIG_PATH, e))
}

/// Insert or replace a hosted-site definition under the IO lock.
pub fn upsert_site(site: HostedSite) -> Result<HostedSite, String> {
    let _g = SF_IO_LOCK.lock().map_err(|_| "site_failover lock poisoned".to_string())?;
    let mut cfg = load_config();
    if let Some(existing) = cfg.sites.iter_mut().find(|s| s.domain == site.domain) {
        *existing = site.clone();
    } else {
        cfg.sites.push(site.clone());
    }
    save_config(&cfg)?;
    Ok(site)
}

/// Re-tag sites when a WolfStack cluster is renamed (mirrors the other
/// cluster-scoped stores). Returns how many were re-tagged.
pub fn rename_wolfstack_cluster_tags(old_name: &str, new_name: &str) -> usize {
    let _g = match SF_IO_LOCK.lock() { Ok(g) => g, Err(_) => return 0 };
    let mut cfg = load_config();
    let mut n = 0;
    for s in &mut cfg.sites {
        if crate::agent::cluster_eq(Some(&s.cluster), Some(old_name)) {
            s.cluster = new_name.to_string();
            n += 1;
        }
    }
    if n > 0 { let _ = save_config(&cfg); }
    n
}

pub fn delete_site(domain: &str) -> Result<(), String> {
    let _g = SF_IO_LOCK.lock().map_err(|_| "site_failover lock poisoned".to_string())?;
    let mut cfg = load_config();
    let before = cfg.sites.len();
    cfg.sites.retain(|s| s.domain != domain);
    if cfg.sites.len() == before {
        return Err(format!("site '{}' not found", domain));
    }
    save_config(&cfg)
}

// ── Failover planning (pure) ─────────────────────────────────────────

/// One site's failover decision.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SitePlan {
    pub domain: String,
    /// The host currently recorded as serving it.
    pub current_host: String,
    /// The host that SHOULD serve it given who's online. Equal to
    /// `current_host` when no move is needed.
    pub target_host: String,
    /// True when the current host is offline and a move is required.
    pub needs_failover: bool,
    /// True when NO online Host node can take the site — it's stranded until a
    /// Host node returns (surfaced loudly, never silently dropped).
    pub stranded: bool,
}

/// Compute the failover plan for every tracked site.
///
/// `online_host_ids` are the Host-role node ids that are currently up, in a
/// deterministic (sorted) order — the caller derives them from
/// `nodes_with_role(Host)` filtered by `online`. A site whose `active_host` is
/// still online keeps it (no needless moves — churn is a failure mode). A site
/// whose host is offline is reassigned to the first online Host node
/// deterministically, so every WolfStack node computing the plan agrees on the
/// same target (no split decision).
pub fn plan_failover(sites: &[HostedSite], online_host_ids: &[String]) -> Vec<SitePlan> {
    sites.iter().map(|s| {
        let current_online = online_host_ids.iter().any(|id| id == &s.active_host);
        if current_online {
            SitePlan {
                domain: s.domain.clone(),
                current_host: s.active_host.clone(),
                target_host: s.active_host.clone(),
                needs_failover: false,
                stranded: false,
            }
        } else {
            // Deterministic pick: first online Host node (ids are pre-sorted).
            match online_host_ids.first() {
                Some(target) => SitePlan {
                    domain: s.domain.clone(),
                    current_host: s.active_host.clone(),
                    target_host: target.clone(),
                    needs_failover: true,
                    stranded: false,
                },
                None => SitePlan {
                    domain: s.domain.clone(),
                    current_host: s.active_host.clone(),
                    target_host: String::new(),
                    needs_failover: true,
                    stranded: true,
                },
            }
        }
    }).collect()
}

/// The online Host-role node ids, sorted — the deterministic input to
/// `plan_failover`.
pub fn online_host_ids(cluster: &crate::agent::ClusterState) -> Vec<String> {
    let mut ids: Vec<String> = cluster.nodes_with_role(crate::agent::NodeRole::Host)
        .into_iter()
        .filter(|n| n.online)
        .map(|n| n.id)
        .collect();
    ids.sort();
    ids
}

// ── Status ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct SiteFailoverStatus {
    pub site_count: usize,
    pub host_count: usize,
    /// Sites needing a move right now (their host is offline).
    pub failovers_pending: usize,
    /// Sites with no available host at all.
    pub stranded: usize,
    pub plans: Vec<SitePlan>,
}

pub fn status(cluster: &crate::agent::ClusterState) -> SiteFailoverStatus {
    let sites = load_config().sites;
    let hosts = online_host_ids(cluster);
    let plans = plan_failover(&sites, &hosts);
    SiteFailoverStatus {
        site_count: sites.len(),
        host_count: hosts.len(),
        failovers_pending: plans.iter().filter(|p| p.needs_failover && !p.stranded).count(),
        stranded: plans.iter().filter(|p| p.stranded).count(),
        plans,
    }
}

/// Execute a reassignment: record `target_host` as the site's active host.
/// Returns the updated site. The caller then hands the ingress re-point to the
/// router (the upstream becomes the target host's address). Idempotent — a
/// site already on `target_host` is a no-op success.
pub fn reassign_site(domain: &str, target_host: &str) -> Result<HostedSite, String> {
    let mut site = load_config().sites.into_iter().find(|s| s.domain == domain)
        .ok_or_else(|| format!("site '{}' not found", domain))?;
    site.active_host = target_host.to_string();
    upsert_site(site)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(domain: &str, host: &str) -> HostedSite {
        HostedSite {
            domain: domain.into(), docroot: format!("/mnt/ceph/sites/{}", domain),
            active_host: host.into(), cluster: String::new(), port: 80,
        }
    }

    #[test]
    fn healthy_site_is_not_moved() {
        let sites = vec![site("a.com", "node-1")];
        let plan = plan_failover(&sites, &["node-1".into(), "node-2".into()]);
        assert!(!plan[0].needs_failover);
        assert_eq!(plan[0].target_host, "node-1");
    }

    #[test]
    fn offline_host_triggers_deterministic_failover() {
        let sites = vec![site("a.com", "node-3")]; // node-3 not in online set
        let plan = plan_failover(&sites, &["node-1".into(), "node-2".into()]);
        assert!(plan[0].needs_failover);
        assert!(!plan[0].stranded);
        // Deterministic = first online host (sorted).
        assert_eq!(plan[0].target_host, "node-1");
    }

    #[test]
    fn no_hosts_leaves_site_stranded_not_dropped() {
        let sites = vec![site("a.com", "node-3")];
        let plan = plan_failover(&sites, &[]);
        assert!(plan[0].needs_failover);
        assert!(plan[0].stranded);
        assert_eq!(plan[0].target_host, "");
    }

    #[test]
    fn every_node_computes_the_same_target() {
        // Two nodes evaluating the same inputs must pick the same target —
        // that's what the sorted deterministic pick guarantees (no split).
        let sites = vec![site("a.com", "dead")];
        let hosts_a = vec!["node-2".to_string(), "node-1".to_string()];
        let mut hosts_b = hosts_a.clone();
        hosts_b.reverse();
        // Callers sort before calling; simulate that.
        let mut a = hosts_a.clone(); a.sort();
        let mut b = hosts_b.clone(); b.sort();
        assert_eq!(plan_failover(&sites, &a)[0].target_host, plan_failover(&sites, &b)[0].target_host);
    }

    #[test]
    fn config_backward_compatible_defaults() {
        let s: HostedSite = serde_json::from_str(
            "{\"domain\":\"d.com\",\"docroot\":\"/m\",\"active_host\":\"n\"}"
        ).unwrap();
        assert_eq!(s.port, 80);
        assert_eq!(s.cluster, "");
    }
}
