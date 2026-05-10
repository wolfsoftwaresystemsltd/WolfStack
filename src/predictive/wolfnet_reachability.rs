// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! WolfNet peer-reachability health check.
//!
//! Symptom this catches: a node silently loses routing to other WolfNet
//! peers (WireGuard handshake stuck, peer config drift, kernel route
//! table eaten by some other tool, MTU issue, firewall rule injected
//! by an unrelated service). Cluster polling continues to "look" alive
//! at the API level because each node's local cluster state still
//! reports itself fine — but cross-node services (WolfNet-IP-addressed
//! VMs and containers on other peers) silently become unreachable and
//! nothing alerts.
//!
//! What this does: every predictive tick, ping every WolfNet peer
//! configured in `/etc/wolfnet/config.toml` from THIS node. Within a
//! single tick we attempt three pings with a 1s timeout each — a peer
//! is only flagged "unreachable" if all three fail, which gives us
//! useful hysteresis against a single dropped packet without needing
//! cross-tick state. Unreachable peers emit a `wolfnet_peer_unreachable`
//! finding into the Predictive Inbox; the finding auto-resolves on
//! the next tick where the peer answers.
//!
//! Scope is per-peer (resource_id keyed on the peer's WolfNet IP) so
//! a single node going down only produces one finding regardless of
//! how many ticks it's been down.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

/// Finding type for "this node can't ping a configured WolfNet peer".
pub const FINDING_TYPE: &str = "wolfnet_peer_unreachable";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerProbe {
    pub name: String,
    pub ip: String,
    pub reachable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WolfnetReachabilityFacts {
    pub probes: Vec<PeerProbe>,
    /// Set when we successfully read the WolfNet peer list. False when
    /// `/etc/wolfnet/config.toml` is missing or unreadable — in that
    /// case we have no opinion on reachability and the analyzer should
    /// skip emitting (and the resolver should skip auto-clearing).
    pub scanned: bool,
}

/// Sample reachability for every configured WolfNet peer. Runs on the
/// blocking pool because `ping` is a synchronous subprocess.
pub async fn sample_now_async(_timeout: Duration) -> WolfnetReachabilityFacts {
    tokio::task::spawn_blocking(|| {
        let peers = crate::networking::get_wolfnet_peers_list();
        if peers.is_empty() {
            // Could be: WolfNet not configured here at all (no
            // config.toml), or a single-node mesh with no peers.
            // Either way, nothing for this analyzer to do — and we
            // don't want to mark `scanned=true` and have the resolver
            // think we just looked at zero peers.
            return WolfnetReachabilityFacts { probes: Vec::new(), scanned: false };
        }
        let mut probes = Vec::with_capacity(peers.len());
        for peer in peers {
            if peer.ip.is_empty() { continue; }
            // Strip CIDR suffix if present (`get_wolfnet_peers_list`
            // returns "10.10.0.5/32" or similar from the config).
            let ip_only = peer.ip.split('/').next().unwrap_or(&peer.ip).to_string();

            // Three attempts, 1s timeout each. A peer is reachable if
            // any of the three succeeds — gives us a free hysteresis
            // pass over single-packet drops and brief MTU/queue blips.
            // Stops early on first success so the steady-state cost is
            // ~1 ping per reachable peer per tick.
            let mut reachable = false;
            for _ in 0..3 {
                let ok = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "1", &ip_only])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok { reachable = true; break; }
            }
            probes.push(PeerProbe {
                name: peer.name,
                ip: ip_only,
                reachable,
            });
        }
        WolfnetReachabilityFacts { probes, scanned: true }
    }).await.unwrap_or_default()
}

/// Emit one `wolfnet_peer_unreachable` proposal per peer that failed
/// all three ping attempts this tick. Idempotent across ticks via the
/// proposal store's dedup key + ack-store suppression.
pub fn analyze(
    ctx: &Context,
    facts: &WolfnetReachabilityFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    for p in &facts.probes {
        if p.reachable { continue; }
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", p.ip)),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_proposal(p, &scope));
    }
    out
}

/// Cover every peer we probed this tick — reachable AND unreachable —
/// so the resolver auto-clears findings the moment a peer comes back.
/// Without covering reachable peers, a previously-flagged peer that's
/// now answering would stay open forever.
pub fn covered_scopes(
    ctx: &Context,
    facts: &WolfnetReachabilityFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    facts.probes.iter().map(|p| (
        FINDING_TYPE.to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", p.ip)),
        },
    )).collect()
}

fn build_proposal(p: &PeerProbe, scope: &ProposalScope) -> Proposal {
    let title = format!(
        "WolfNet peer `{}` ({}) is unreachable from this node",
        p.name, p.ip,
    );
    let why = format!(
        "This node failed to ping `{}` ({}) three times in a row over the WolfNet \
         mesh. Cross-node services that route via this peer — VMs and containers \
         with WolfNet IPs on the other side, IP mappings whose target is on that \
         peer, anything talking to the peer's wolfnet0 IP — are silently broken \
         until reachability returns. Common causes: WireGuard handshake stuck \
         (peer rebooted, key rotation), kernel route for the WolfNet subnet \
         removed by another tool, firewall rule injected on either end blocking \
         UDP 51820 or the WolfNet subnet, MTU mismatch after a network change, \
         or the peer host is genuinely down.",
        p.name, p.ip,
    );
    let evidence = vec![
        Evidence {
            label: "Peer".into(),
            value: format!("{} ({})", p.name, p.ip),
            detail: Some("Configured in /etc/wolfnet/config.toml".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "Probe result".into(),
            value: "3 / 3 pings failed (1s timeout each)".into(),
            detail: Some("Re-probed every predictive tick; this finding clears the moment a ping succeeds.".into()),
            links: Vec::new(),
        },
    ];
    let commands = vec![
        format!("ping -c 5 {}", p.ip),
        format!("sudo wg show"),
        format!("ip -4 route get {}", p.ip),
        format!("sudo journalctl -u wolfnet --since '15 minutes ago' | tail -50"),
    ];
    Proposal::new(
        FINDING_TYPE,
        ProposalSource::Rule,
        Severity::High,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "Start with `wg show` on both ends and look for a recent \
                latest-handshake timestamp — if the peer's handshake is older than \
                a few minutes, the tunnel is dead. Common fixes: bounce the \
                wolfnet service on either end (`sudo systemctl restart wolfnet`), \
                check that UDP 51820 isn't being blocked by a recently-applied \
                firewall change, verify the peer's public endpoint hasn't changed \
                (CGNAT renumber, dynamic IP rotation), or confirm the kernel route \
                for the WolfNet subnet still points at wolfnet0. If the peer host \
                is itself down, the finding will auto-resolve when it returns.".into(),
            commands,
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanned_false_yields_no_proposals() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![PeerProbe {
                name: "test".into(),
                ip: "10.10.0.5".into(),
                reachable: false,
            }],
            scanned: false,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty(), "scanned=false must produce no proposals — we don't know whether the peers are reachable");
    }

    #[test]
    fn reachable_peers_yield_no_proposals_but_are_covered() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![PeerProbe {
                name: "alpha".into(),
                ip: "10.10.0.5".into(),
                reachable: true,
            }],
            scanned: true,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty(), "a reachable peer should not emit a finding");
        let covered = covered_scopes(&ctx, &facts);
        assert_eq!(covered.len(), 1, "reachable peers must still be in covered_scopes so the resolver can clear stale findings");
        assert_eq!(covered[0].0, FINDING_TYPE);
    }

    #[test]
    fn unreachable_peer_emits_high_severity_finding() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![PeerProbe {
                name: "bravo".into(),
                ip: "10.10.0.7".into(),
                reachable: false,
            }],
            scanned: true,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].finding_type, FINDING_TYPE);
        assert!(matches!(out[0].severity, Severity::High));
        assert!(out[0].title.contains("bravo"));
        assert!(out[0].title.contains("10.10.0.7"));
        let scope_id = out[0].scope.resource_id.as_deref().unwrap_or("");
        assert_eq!(scope_id, "wolfnet-peer:10.10.0.7", "scope keyed on peer IP for stable dedup");
    }

    #[test]
    fn mixed_set_only_flags_the_unreachable() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![
                PeerProbe { name: "ok-1".into(),  ip: "10.10.0.1".into(), reachable: true  },
                PeerProbe { name: "down".into(),  ip: "10.10.0.2".into(), reachable: false },
                PeerProbe { name: "ok-2".into(),  ip: "10.10.0.3".into(), reachable: true  },
            ],
            scanned: true,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1, "exactly one finding for the one unreachable peer");
        assert!(out[0].title.contains("down"));
        assert_eq!(covered_scopes(&ctx, &facts).len(), 3,
            "all three peers must be covered so the resolver clears findings as soon as 'down' answers again");
    }
}
