// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Edge — public-ingress strategy for HTTP proxies.
//!
//! This module owns the "how does traffic from the internet find a
//! WolfStack proxy node" question. It's the layer ABOVE the per-node
//! nginx/wolfproxy config (which lives in
//! `src/networking/router/http_proxy.rs`). Two strictly separate
//! concerns, because the choice is independent: an operator might run
//! identical nginx configs on 3 Hetzner servers and pick between
//! "Cloudflare in front" (DNS proxied), "WolfStack-managed DNS
//! round-robin" (TTL-bound failover), or "external LB" (Hetzner LB,
//! Cloudflare Tunnel, etc.) without changing a single line of the
//! nginx config.
//!
//! v23.2 ships three strategies: `Local`, `DnsRoundRobin`,
//! `CloudflareDns`. v23.3 adds `CloudflareTunnel` and `HetznerLb`. The
//! enum is structured so new variants land as additive changes — the
//! reconciler + UI both route on the `kind()` string.

pub mod store;
pub mod cloudflare;
pub mod hetzner_dns;
pub mod hetzner_lb;
pub mod digitalocean_dns;
pub mod digitalocean_lb;
pub mod cloudflare_tunnel;
pub mod reconcile;
pub mod teardown;

use serde::{Deserialize, Serialize};

/// How a proxy's public ingress is wired up. Picked per-proxy via the
/// "Resilience" dropdown in the UI. Local is the default when no
/// CloudProvider credentials are configured — it does nothing and
/// hands DNS management entirely to the operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
pub enum EdgeStrategy {
    /// No automation. Operator runs the proxy on N nodes and manages
    /// DNS themselves. This is what v23.1.x effectively did.
    #[default]
    Local,

    /// WolfStack reconciles A records via the named DNS provider,
    /// based on peer-health observations. Adds an IP per healthy
    /// target; removes IPs whose target is offline (per cluster
    /// gossip). Failover is TTL-bound. No third-party LB required.
    ///
    /// `dns_provider_id` references an entry in `DnsProviderStore`
    /// (the existing one shipped in v23.0.0). `ttl_seconds` is the
    /// A-record TTL — 60 is a reasonable default.
    DnsRoundRobin {
        dns_provider_id: String,
        #[serde(default = "default_ttl")]
        ttl_seconds: u32,
    },

    /// Same as DnsRoundRobin but with Cloudflare's `proxied=true`
    /// flag on the records — Cloudflare terminates TLS at its edge,
    /// does DDoS + WAF, caches static content. Origins talk plain HTTP
    /// among themselves on the WolfStack-managed network. Free tier.
    ///
    /// `dns_provider_id` MUST point at a Cloudflare-typed DNS provider
    /// — the reconciler validates this on save.
    CloudflareDns {
        dns_provider_id: String,
        #[serde(default = "default_ttl")]
        ttl_seconds: u32,
    },

    /// Hetzner Cloud Load Balancer. WolfStack provisions the LB via
    /// the Hetzner Cloud API, attaches each target's public IP as an
    /// "ip" target (works for non-Cloud origins too), and configures
    /// HTTP + HTTPS-passthrough services. Sub-10s failover. ~€5/mo.
    ///
    /// `cloud_provider_id` references an entry in CloudProviderStore
    /// with kind=hetzner.
    /// `lb_name` is the unique-per-project name WolfStack uses to
    /// look up / create the LB. `location` is the Hetzner DC
    /// (fsn1/nbg1/hel1/ash/hil).
    HetznerLb {
        cloud_provider_id: String,
        lb_name: String,
        #[serde(default = "default_location_fsn1")]
        location: String,
        /// Whether to enable an HTTPS-passthrough service on :443.
        #[serde(default = "default_true")]
        https_passthrough: bool,
    },

    /// DigitalOcean Load Balancer. Same shape as HetznerLb. Targets
    /// MUST be DigitalOcean droplets — non-DO origins can't be
    /// attached. The reconciler resolves WolfStack node public IPs
    /// to droplet IDs via the DO API at sync time.
    DigitalOceanLb {
        cloud_provider_id: String,
        lb_name: String,
        #[serde(default = "default_region_nyc3")]
        region: String,
        #[serde(default = "default_true")]
        https_passthrough: bool,
    },

    /// Cloudflare Tunnel — no inbound ports on the origin. WolfStack
    /// creates a Cloudflare-managed tunnel via API, installs
    /// `cloudflared` on each target node (must already be installed
    /// — we don't bundle it), pushes the connector token, and
    /// publishes a CNAME → `<tunnel-id>.cfargotunnel.com`. Free, no
    /// public IP needed on the origin (CGNAT-friendly).
    CloudflareTunnel {
        /// CloudProviderStore entry; credentials must contain
        /// account_id + api_token with Tunnel:Edit + DNS:Edit scopes.
        cloud_provider_id: String,
        /// DNS-provider entry for the zone we'll create the CNAME in
        /// — same Cloudflare API but different scope, so it's a
        /// separate entry in `dns_providers`.
        dns_provider_id: String,
        /// Friendly tunnel name (unique per CF account). Same name
        /// for all proxies in the same cluster is fine — they share
        /// a tunnel and route by ingress rule.
        tunnel_name: String,
    },
}


impl EdgeStrategy {
    /// String tag used in API responses and UI dropdowns. Stable
    /// across versions — adding a variant won't change existing
    /// tags. Frontend keys off this for which fields to render.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Local                 => "local",
            Self::DnsRoundRobin{..}     => "dns_round_robin",
            Self::CloudflareDns{..}     => "cloudflare_dns",
            Self::HetznerLb{..}         => "hetzner_lb",
            Self::DigitalOceanLb{..}    => "digitalocean_lb",
            Self::CloudflareTunnel{..}  => "cloudflare_tunnel",
        }
    }

    /// Whether this strategy needs the reconciler to do *anything*
    /// on each pass. Local does nothing; everything else does.
    pub fn manages_dns(&self) -> bool {
        !matches!(self, Self::Local)
    }
}

fn default_ttl() -> u32 { 60 }
fn default_location_fsn1() -> String { "fsn1".into() }   // Hetzner Falkenstein, EU
fn default_region_nyc3() -> String { "nyc3".into() }     // DO New York
fn default_true() -> bool { true }

/// One target where a proxy actually runs. Either the bare host or
/// inside a container we manage. v23.2 supports Host + Docker + LXC;
/// v23.4 adds KubernetesIngress (a different render path entirely —
/// emits an Ingress resource instead of an nginx config file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyTarget {
    /// Cluster node that hosts this target. Render fires only on the
    /// matching node.
    pub node_id: String,

    /// What runtime the proxy runs in on that node.
    pub runtime: TargetRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetRuntime {
    /// Bare-host nginx/wolfproxy. Config goes to
    /// `/etc/nginx/conf.d/wolfrouter-http-<id>.conf` on the node.
    Host,
    /// nginx inside a Docker container. Config goes to
    /// `/etc/nginx/conf.d/` *inside* the named container via
    /// `docker exec`. Uses the existing `configurator::ExecTarget::Docker`.
    Docker { container: String },
    /// Same but LXC, via `lxc-attach` / `pct exec`.
    Lxc { container: String },
    // v23.4+: KubernetesIngress { cluster, namespace, ingress_class }
}

// ─── Cloud-provider credentials store ──────────────────────────────────
//
// Sister to the existing DnsProviderStore (DNS API keys for ACME
// DNS-01). The cloud-provider store holds *infrastructure* tokens:
// Cloudflare account/tunnel API tokens, Hetzner Cloud project tokens,
// DigitalOcean tokens, etc. They're used by edge providers to
// provision LBs / tunnels and by future tranches for cluster-level
// automation (auto-scaling, etc.).
//
// Same XOR-obfuscation pattern as `dns_providers` — defence is
// filesystem permissions (mode 0600), the obfuscation just keeps the
// file from being trivially `cat`-able. Plugin whitelist gates which
// `kind` values are accepted; new providers land as one-line whitelist
// additions in this module.

pub use store::{CloudProviderStore, CloudProviderKind};
#[allow(unused_imports)]
pub use store::{CloudProvider, CloudProviderRedacted};
