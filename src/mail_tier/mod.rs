// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! HA mail tier — MX topology + relay/replication config from node roles.
//!
//! NoroNetwork 2026-07-09: "Separate Email servers (2 preferably) … separate
//! server that handles the email data. (It would be perfect if DNS servers can
//! also run SMTP relay so you got redundant email targets)". This module turns
//! the [`Mail`](crate::agent::NodeRole::Mail) and
//! [`MailRelay`](crate::agent::NodeRole::MailRelay) roles into a concrete mail
//! topology:
//!
//!   * `Mail` nodes are the primary mailstore (the ≥2-server tier). They hold
//!     the mailboxes and are the low-priority (preferred) MX targets.
//!   * `MailRelay` nodes — typically the cheap `Dns` VPSs with good PTRs — are
//!     higher-priority-number (backup) MX targets that queue-and-forward to the
//!     mail tier when it is momentarily unreachable. Cheap PTR-clean relays in
//!     front of the real store is exactly the deliverability pattern Noro asked
//!     for.
//!
//! The keystone pays off twice here: placement comes from the roles, and the
//! generated MX/A records are published through the DNS tier's own fan-out
//! (stage 1) — one mechanism writes them to every nameserver.
//!
//! Scope (v1): topology derivation + MX/A record generation (published to the
//! DNS tier) + relay/replication CONFIG generation, all pure and unit-tested
//! and surfaced via the API for the operator to review and apply. Pushing the
//! generated postfix/dovecot config into containers and live-testing dovecot
//! cluster failover are hardware-verification steps for the sponsor, flagged in
//! the API responses — this module does NOT itself write into the containers.

use serde::Serialize;

/// Preferred (primary) MX priority — the mail-tier store.
const MX_PRIO_PRIMARY: u16 = 10;
/// Backup MX priority — the relay nodes. Higher number = lower preference, so
/// senders only fall back to a relay when the store is unreachable.
const MX_PRIO_BACKUP: u16 = 20;

/// One node in the mail topology, derived from a WolfStack node + its role.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MailTierNode {
    pub node_id: String,
    pub hostname: String,
    pub address: String,
    /// "mail" (store) or "relay".
    pub kind: String,
}

/// The mail tier as derived from cluster roles.
#[derive(Debug, Clone, Serialize)]
pub struct MailTier {
    pub store_nodes: Vec<MailTierNode>,
    pub relay_nodes: Vec<MailTierNode>,
}

impl MailTier {
    /// Derive the tier from the cluster's role assignments. Only online
    /// WolfStack nodes are included (an offline node can't serve mail).
    pub fn from_cluster(cluster: &crate::agent::ClusterState) -> MailTier {
        let map = |nodes: Vec<crate::agent::Node>, kind: &str| -> Vec<MailTierNode> {
            let mut v: Vec<MailTierNode> = nodes.into_iter()
                .filter(|n| n.online)
                .map(|n| MailTierNode {
                    node_id: n.id.clone(),
                    hostname: n.display_name.clone().unwrap_or(n.hostname),
                    address: n.address,
                    kind: kind.to_string(),
                })
                .collect();
            v.sort_by(|a, b| a.node_id.cmp(&b.node_id)); // deterministic ordering
            v
        };
        MailTier {
            store_nodes: map(cluster.nodes_with_role(crate::agent::NodeRole::Mail), "mail"),
            relay_nodes: map(cluster.nodes_with_role(crate::agent::NodeRole::MailRelay), "relay"),
        }
    }

    /// True when at least one store node exists — the minimum to serve mail.
    pub fn has_store(&self) -> bool {
        !self.store_nodes.is_empty()
    }
}

/// A DNS record to publish for a mail domain (fed to the DNS-tier fan-out).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MailDnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub content: String,
    pub ttl: u32,
}

/// Build the MX + host A records that publish this tier for `domain`.
///
/// Each store node gets a host name `mailN.<domain>` (A → its address) and an
/// MX at priority 10; each relay node gets `mxbackupN.<domain>` (A) and an MX
/// at priority 20. Deterministic ordering (nodes are sorted by id) so
/// re-publishing a domain produces a stable record set.
pub fn mx_records_for(domain: &str, tier: &MailTier) -> Vec<MailDnsRecord> {
    let mut out = Vec::new();
    for (i, n) in tier.store_nodes.iter().enumerate() {
        let host = format!("mail{}.{}", i + 1, domain);
        out.push(MailDnsRecord { name: host.clone(), rtype: "A".into(), content: n.address.clone(), ttl: 3600 });
        out.push(MailDnsRecord {
            name: domain.to_string(),
            rtype: "MX".into(),
            content: format!("{} {}.", MX_PRIO_PRIMARY, host),
            ttl: 3600,
        });
    }
    for (i, n) in tier.relay_nodes.iter().enumerate() {
        let host = format!("mxbackup{}.{}", i + 1, domain);
        out.push(MailDnsRecord { name: host.clone(), rtype: "A".into(), content: n.address.clone(), ttl: 3600 });
        out.push(MailDnsRecord {
            name: domain.to_string(),
            rtype: "MX".into(),
            content: format!("{} {}.", MX_PRIO_BACKUP, host),
            ttl: 3600,
        });
    }
    out
}

/// Generate the Postfix relay config lines for a `MailRelay` node: accept mail
/// for the hosted domains and forward it to the mail-tier store addresses.
/// `store_addrs` are the store nodes' addresses; `domains` the relayed domains.
/// Returned as (relay_domains value, transport_maps lines) — the caller writes
/// them into the container's postfix config.
pub fn relay_config(domains: &[String], store_addrs: &[String]) -> (String, Vec<String>) {
    let relay_domains = domains.join(" ");
    // Round-robin across the store nodes isn't expressible in a single
    // transport line, so we point at the FIRST store node and list the rest as
    // fallback via smtp_fallback_relay in the caller; the transport map keeps
    // it simple and correct: relay each domain to the primary store, MX-less.
    let primary = store_addrs.first().cloned().unwrap_or_default();
    let transport_maps: Vec<String> = domains.iter()
        .map(|d| format!("{}    smtp:[{}]", d, primary))
        .collect();
    (relay_domains, transport_maps)
}

/// Generate the dovecot replication (dsync over TCP) config for one store node,
/// given its PARTNER store nodes' addresses. Dovecot's replicator plugin keeps
/// mailboxes in sync between the tier's servers so a store node can take over
/// another's mailboxes. The caller writes this into the container.
pub fn dovecot_replication_config(partner_addrs: &[String]) -> String {
    // One mail_replica per partner. dsync runs over the doveadm TCP port 12345.
    let replicas: String = partner_addrs.iter()
        .map(|a| format!("  mail_replica = tcp:{}:12345\n", a))
        .collect();
    format!(
        "plugin {{\n{replicas}}}\n\
         service replicator {{\n  process_min_avail = 1\n}}\n\
         service aggregator {{\n  fifo_listener replication-notify-fifo {{\n    user = vmail\n  }}\n  \
         unix_listener replication-notify {{\n    user = vmail\n  }}\n}}\n\
         service doveadm {{\n  inet_listener {{\n    port = 12345\n  }}\n}}\n\
         doveadm_port = 12345\n",
        replicas = replicas,
    )
}

// ── Status ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct MailTierStatus {
    pub store_count: usize,
    pub relay_count: usize,
    /// True when the tier can serve mail with redundancy: ≥2 store nodes.
    pub redundant_store: bool,
    /// True when at least one backup relay exists.
    pub has_backup_relay: bool,
    pub store_nodes: Vec<MailTierNode>,
    pub relay_nodes: Vec<MailTierNode>,
}

pub fn status(cluster: &crate::agent::ClusterState) -> MailTierStatus {
    let tier = MailTier::from_cluster(cluster);
    MailTierStatus {
        store_count: tier.store_nodes.len(),
        relay_count: tier.relay_nodes.len(),
        redundant_store: tier.store_nodes.len() >= 2,
        has_backup_relay: !tier.relay_nodes.is_empty(),
        store_nodes: tier.store_nodes,
        relay_nodes: tier.relay_nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(stores: &[&str], relays: &[&str]) -> MailTier {
        let mk = |a: &str, k: &str| MailTierNode {
            node_id: format!("node-{}", a), hostname: format!("h-{}", a),
            address: a.to_string(), kind: k.to_string(),
        };
        MailTier {
            store_nodes: stores.iter().map(|a| mk(a, "mail")).collect(),
            relay_nodes: relays.iter().map(|a| mk(a, "relay")).collect(),
        }
    }

    #[test]
    fn mx_records_primary_and_backup_priorities() {
        let t = tier(&["10.0.0.1", "10.0.0.2"], &["203.0.113.1"]);
        let recs = mx_records_for("example.com", &t);
        // 2 stores → 2 A + 2 MX(pri10); 1 relay → 1 A + 1 MX(pri20).
        let mx: Vec<&MailDnsRecord> = recs.iter().filter(|r| r.rtype == "MX").collect();
        assert_eq!(mx.len(), 3);
        assert!(mx.iter().filter(|r| r.content.starts_with("10 ")).count() == 2, "two primary MX at pri 10");
        assert!(mx.iter().filter(|r| r.content.starts_with("20 ")).count() == 1, "one backup MX at pri 20");
        // Store host A records point at the store addresses.
        let a: Vec<&MailDnsRecord> = recs.iter().filter(|r| r.rtype == "A").collect();
        assert_eq!(a.len(), 3);
        assert!(a.iter().any(|r| r.name == "mail1.example.com" && r.content == "10.0.0.1"));
        assert!(a.iter().any(|r| r.name == "mxbackup1.example.com" && r.content == "203.0.113.1"));
        // MX content is FQDN-terminated (trailing dot).
        assert!(mx.iter().all(|r| r.content.ends_with('.')));
    }

    #[test]
    fn mx_records_are_deterministic() {
        let t = tier(&["10.0.0.1", "10.0.0.2"], &[]);
        assert_eq!(mx_records_for("d.com", &t), mx_records_for("d.com", &t));
    }

    #[test]
    fn relay_config_points_at_store() {
        let (rd, tm) = relay_config(
            &["a.com".to_string(), "b.com".to_string()],
            &["10.0.0.1".to_string(), "10.0.0.2".to_string()],
        );
        assert_eq!(rd, "a.com b.com");
        assert_eq!(tm.len(), 2);
        assert!(tm[0].contains("a.com") && tm[0].contains("[10.0.0.1]"));
    }

    #[test]
    fn dovecot_replication_lists_each_partner() {
        let cfg = dovecot_replication_config(&["10.0.0.2".to_string()]);
        assert!(cfg.contains("mail_replica = tcp:10.0.0.2:12345"));
        assert!(cfg.contains("service replicator"));
        assert!(cfg.contains("doveadm_port = 12345"));
    }

    #[test]
    fn empty_tier_has_no_store() {
        let t = tier(&[], &[]);
        assert!(!t.has_store());
        assert!(mx_records_for("x.com", &t).is_empty());
    }
}
