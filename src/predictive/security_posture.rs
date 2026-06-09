// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Security posture findings — Item 8 + partial Convergence C.
//!
//! First analyzer in the predictive pipeline whose severity depends
//! on `NetworkReachability` — this is the consumer that the
//! reachability classifier was built for. Same shape of finding
//! that `security.rs::scan_listening_services` and `scan_sshd_config`
//! produce, but routed through the unified Inbox so operators get:
//! - Snooze / dismiss / ack-as-intentional semantics
//! - Cluster-aware aggregation
//! - First-appearance notification dispatch on Critical/High
//!
//! ## Findings
//!
//! - `service_bound_publicly` — a well-known risky service is
//!   listening on an interface reachable from the public internet
//!   (per `NetworkReachability`). Severity by service-class +
//!   reachability matrix.
//! - `sshd_password_auth_enabled` — sshd has
//!   `PasswordAuthentication yes`. Severity higher when sshd is
//!   reachable from the public internet.
//! - `sshd_root_login_enabled` — sshd has `PermitRootLogin yes`.
//!   Severity higher when sshd is reachable from the public
//!   internet.
//!
//! ## Convergence note
//!
//! `security.rs` keeps its active-attack scans (SSH brute-force,
//! crypto miners, /tmp binaries, outbound suspicious) for now —
//! those are event-detection at a different cadence and the
//! convergence shape is non-trivial (they're "things happening
//! right now", not "posture that should be true"). Migrating them
//! is a follow-up; the duplication on these three POSTURE findings
//! is what this delta retires.

use std::time::Duration;

use crate::predictive::{
    Context, NetworkReachability, NetworkSnapshot, classify_bind,
    proposal::{
        Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_SERVICE_PUBLIC: &str = "service_bound_publicly";
pub const FINDING_SSHD_PASSWORD_AUTH: &str = "sshd_password_auth_enabled";
pub const FINDING_SSHD_ROOT_LOGIN: &str = "sshd_root_login_enabled";

/// Well-known services that should generally not be reachable from
/// outside loopback. The bool flags "extreme blast radius" — Docker
/// API plain on the public internet is *catastrophic*; an exposed
/// PostgreSQL is bad but not as instantly-game-over.
const RISKY_PORTS: &[(u16, &str, bool)] = &[
    (2375, "docker-api-plain", true),  // root via container escape, no auth
    (2376, "docker-api-tls",   false),
    (6379, "redis",            false),
    (27017,"mongodb",          false),
    (9200, "elasticsearch",    false),
    (3306, "mysql",            false),
    (5432, "postgres",         false),
    (11211,"memcached",        false),
    (5601, "kibana",           false),
];

/// Per-tick snapshot of sshd config state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshdConfig {
    pub password_auth: bool,
    pub root_login: bool,
}

/// Sample sshd config from the EFFECTIVE settings (`sshd -T`), so drop-in files
/// and Match blocks are honored — a `prohibit-password` drop-in reads as
/// not-root-login even when the main file still says `yes`.
pub fn sample_sshd_config_now() -> SshdConfig {
    SshdConfig {
        root_login: crate::security::sshd_effective("permitrootlogin").as_deref() == Some("yes"),
        password_auth: crate::security::sshd_effective("passwordauthentication").as_deref() == Some("yes"),
    }
}

pub async fn sample_sshd_config_now_async(timeout: Duration) -> SshdConfig {
    let fut = tokio::task::spawn_blocking(sample_sshd_config_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(c)) => c,
        _ => SshdConfig::default(),
    }
}

/// Run the analyzer. Consumes the network snapshot from `ctx` for
/// per-bind reachability classification.
pub fn analyze(
    ctx: &Context,
    sshd: &SshdConfig,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    out.extend(analyze_listening_services(ctx, &ctx.network, acks, proposals));
    out.extend(analyze_sshd(ctx, sshd, &ctx.network, acks, proposals));
    out
}

/// Covered scopes for auto-resolve. Includes one entry per
/// (finding_type, scope) the analyzer evaluated this tick.
pub fn covered_scopes(
    ctx: &Context,
    sshd: &SshdConfig,
) -> Vec<(String, ProposalScope)> {
    let mut out = Vec::new();
    let snap = &ctx.network;
    for sock in &snap.listening_sockets {
        if let Some((_, _, _)) = lookup_risky(sock.port) {
            out.push((
                FINDING_SERVICE_PUBLIC.to_string(),
                ProposalScope {
                    node_id: ctx.node_id.clone(),
                    resource_id: Some(format!("{}:{}", sock.bind, sock.port)),
                },
            ));
        }
    }
    // Always cover the sshd findings — the file either says yes
    // or no, so a clearance-from-yes-to-no should auto-resolve.
    let _ = sshd;
    let sshd_scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("sshd".into()),
    };
    out.push((FINDING_SSHD_PASSWORD_AUTH.to_string(), sshd_scope.clone()));
    out.push((FINDING_SSHD_ROOT_LOGIN.to_string(), sshd_scope));
    out
}

fn lookup_risky(port: u16) -> Option<(u16, &'static str, bool)> {
    RISKY_PORTS.iter().find(|(p, _, _)| *p == port).copied()
}

fn analyze_listening_services(
    ctx: &Context,
    snap: &NetworkSnapshot,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for sock in &snap.listening_sockets {
        let Some((_, service, is_critical_class)) = lookup_risky(sock.port) else { continue; };

        let reach = classify_bind(sock.bind, snap);
        if matches!(reach, NetworkReachability::LoopbackOnly) {
            continue;  // bound to lo only — that's the correct posture
        }

        // Severity matrix: reachability × service-class.
        let severity = match (&reach, is_critical_class) {
            (NetworkReachability::PublicInternet, true)  => Severity::Critical,
            (NetworkReachability::PublicInternet, false) => Severity::High,
            (NetworkReachability::LocalNetwork, true)    => Severity::High,
            (NetworkReachability::LocalNetwork, false)   => Severity::Warn,
            (NetworkReachability::OverlayOnly { .. }, _) => Severity::Info,
            (NetworkReachability::Unknown, true)         => Severity::High,
            (NetworkReachability::Unknown, false)        => Severity::Warn,
            (NetworkReachability::LoopbackOnly, _)       => continue,
        };

        let resource = format!("{}:{}", sock.bind, sock.port);
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource.clone()),
        };
        if acks.suppresses(FINDING_SERVICE_PUBLIC, &scope) { continue; }
        if proposals.is_suppressed(FINDING_SERVICE_PUBLIC, &scope) { continue; }

        out.push(build_listening_proposal(sock, service, &reach, severity, &scope));
    }
    out
}

fn build_listening_proposal(
    sock: &crate::predictive::ListeningSocket,
    service: &str,
    reach: &NetworkReachability,
    severity: Severity,
    scope: &ProposalScope,
) -> Proposal {
    let proto = match sock.protocol {
        crate::predictive::SocketProtocol::Tcp => "tcp",
        crate::predictive::SocketProtocol::Udp => "udp",
    };
    let reach_label = match reach {
        NetworkReachability::PublicInternet => "the public internet",
        NetworkReachability::LocalNetwork   => "the local network",
        NetworkReachability::OverlayOnly { network } => {
            return Proposal::new(
                FINDING_SERVICE_PUBLIC, ProposalSource::Rule, severity,
                format!("{} ({}/{}) on overlay {}", service, proto, sock.port, network),
                format!(
                    "{} is listening on overlay '{}'. Overlay-only \
                     bindings are usually intentional (the operator \
                     deliberately exposed this service to peers via \
                     the overlay), so this finding is informational. \
                     Acknowledge to silence it permanently if that's \
                     the case.",
                    service, network,
                ),
                vec![Evidence {
                    label: "Bind".into(),
                    value: format!("{}:{} ({})", sock.bind, sock.port, proto),
                    detail: sock.process.clone(),
                    links: Vec::new(),
                }],
                RemediationPlan::Manual {
                    instructions: format!("Bind '{}' is overlay-scoped — review whether the exposure is intentional.", service),
                    commands: vec![
                        format!("ss -tlnp | grep ':{}\\b'", sock.port),
                    ],
                },
                scope.clone(),
            );
        }
        NetworkReachability::Unknown => "an unclassified interface",
        NetworkReachability::LoopbackOnly => "loopback (this should not have fired)",
    };

    let title = format!(
        "{} ({}/{}) reachable from {}",
        service, proto, sock.port, reach_label,
    );

    let why = format!(
        "Service `{}` (port {}/{}) is bound to `{}`, which makes it \
         reachable from {}. The bind address resolves to that \
         reachability class via the unified `NetworkReachability` \
         classifier — see the resource_id `{}:{}` for filtering. \
         If the exposure is intentional (e.g. an opt-in public \
         endpoint with its own auth in front), acknowledge as \
         intentional to silence permanently.",
        service, sock.port, proto, sock.bind, reach_label,
        sock.bind, sock.port,
    );

    let evidence = vec![
        Evidence {
            label: "Service".into(),
            value: format!("{} ({}/{})", service, proto, sock.port),
            detail: sock.process.clone(),
            links: Vec::new(),
        },
        Evidence {
            label: "Bind".into(),
            value: format!("{}:{}", sock.bind, sock.port),
            detail: Some(format!("Reachability class: {:?}", reach)),
            links: Vec::new(),
        },
    ];

    let remediation = RemediationPlan::Manual {
        instructions: format!(
            "Bind {} to 127.0.0.1 in its config OR firewall the port \
             from external networks. If this is an intentional \
             exposure, the cleanest path is to ack the finding so \
             future scans don't re-flag it.",
            service,
        ),
        commands: vec![
            format!("ss -tlnp 'sport = :{}'", sock.port),
            format!("sudo iptables -A INPUT -p {} --dport {} ! -s 127.0.0.1 -j DROP", proto, sock.port),
        ],
    };

    Proposal::new(
        FINDING_SERVICE_PUBLIC, ProposalSource::Rule, severity,
        title, why, evidence, remediation, scope.clone(),
    )
}

fn analyze_sshd(
    ctx: &Context,
    sshd: &SshdConfig,
    snap: &NetworkSnapshot,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    let sshd_reach = sshd_reachability(snap);

    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("sshd".into()),
    };

    // Proxmox uses root SSH for cluster operations and re-asserts
    // PermitRootLogin on its own, so the finding is un-actionable there —
    // suppress it on Proxmox (in addition to the operator ack / proposal
    // suppression). A prohibit-password drop-in is the way to harden.
    if sshd.root_login
        && !crate::containers::is_proxmox()
        && !acks.suppresses(FINDING_SSHD_ROOT_LOGIN, &scope)
        && !proposals.is_suppressed(FINDING_SSHD_ROOT_LOGIN, &scope)
    {
        let severity = match sshd_reach {
            NetworkReachability::PublicInternet => Severity::Critical,
            NetworkReachability::LocalNetwork   => Severity::High,
            _                                   => Severity::Warn,
        };
        out.push(build_sshd_root_proposal(&sshd_reach, severity, &scope));
    }

    if sshd.password_auth
        && !acks.suppresses(FINDING_SSHD_PASSWORD_AUTH, &scope)
        && !proposals.is_suppressed(FINDING_SSHD_PASSWORD_AUTH, &scope)
    {
        let severity = match sshd_reach {
            NetworkReachability::PublicInternet => Severity::High,
            NetworkReachability::LocalNetwork   => Severity::Warn,
            _                                   => Severity::Info,
        };
        out.push(build_sshd_password_proposal(&sshd_reach, severity, &scope));
    }

    out
}

/// What reachability class does sshd's binding fall into? Walk the
/// listening sockets snapshot for port 22; classify each bind via
/// the existing classifier; pick the most-permissive (worst-case).
fn sshd_reachability(snap: &NetworkSnapshot) -> NetworkReachability {
    let mut worst = NetworkReachability::LoopbackOnly;
    for sock in &snap.listening_sockets {
        if sock.port != 22 { continue; }
        let r = classify_bind(sock.bind, snap);
        worst = pick_worst(worst, r);
    }
    worst
}

/// "Worst" = most exposed. PublicInternet beats LocalNetwork beats
/// OverlayOnly beats Unknown beats LoopbackOnly.
fn pick_worst(a: NetworkReachability, b: NetworkReachability) -> NetworkReachability {
    fn rank(r: &NetworkReachability) -> u8 {
        match r {
            NetworkReachability::PublicInternet => 4,
            NetworkReachability::LocalNetwork   => 3,
            NetworkReachability::OverlayOnly { .. } => 2,
            NetworkReachability::Unknown        => 1,
            NetworkReachability::LoopbackOnly   => 0,
        }
    }
    if rank(&a) >= rank(&b) { a } else { b }
}

fn build_sshd_root_proposal(
    reach: &NetworkReachability,
    severity: Severity,
    scope: &ProposalScope,
) -> Proposal {
    Proposal::new(
        FINDING_SSHD_ROOT_LOGIN, ProposalSource::Rule, severity,
        format!("sshd allows root login (sshd reachable from: {:?})", reach),
        format!(
            "/etc/ssh/sshd_config has `PermitRootLogin yes`. Severity \
             scales with sshd's actual exposure — currently classified \
             as {:?}. Direct root-over-SSH on a publicly-reachable \
             endpoint is a primary brute-force target; even on local \
             networks the audit trail loses meaning when everyone is \
             logging in as `root`.",
            reach,
        ),
        vec![Evidence {
            label: "sshd reachability".into(),
            value: format!("{:?}", reach),
            detail: Some("Computed via `NetworkReachability::classify_bind` on every listener for port 22.".into()),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Set `PermitRootLogin no` in /etc/ssh/sshd_config and reload sshd. Make sure you have a non-root user with sudo first.".into(),
            commands: vec![
                "grep -i 'PermitRootLogin' /etc/ssh/sshd_config".into(),
                "sudo sed -i 's/^[# ]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config".into(),
                "sudo sshd -t && sudo systemctl reload sshd".into(),
            ],
        },
        scope.clone(),
    )
}

fn build_sshd_password_proposal(
    reach: &NetworkReachability,
    severity: Severity,
    scope: &ProposalScope,
) -> Proposal {
    Proposal::new(
        FINDING_SSHD_PASSWORD_AUTH, ProposalSource::Rule, severity,
        format!("sshd accepts password auth (sshd reachable from: {:?})", reach),
        format!(
            "/etc/ssh/sshd_config has `PasswordAuthentication yes`. \
             Public SSH endpoints with password auth are the single \
             most-attacked surface on a Linux host; key-only auth + \
             fail2ban (or sshguard) cuts log noise dramatically and \
             makes credential-stuffing irrelevant. Reachability \
             class: {:?}.",
            reach,
        ),
        vec![Evidence {
            label: "sshd reachability".into(),
            value: format!("{:?}", reach),
            detail: None,
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Set `PasswordAuthentication no` in /etc/ssh/sshd_config — confirm your key works first by logging in via key in a separate session BEFORE you reload sshd.".into(),
            commands: vec![
                "grep -iE 'PasswordAuthentication|PubkeyAuthentication' /etc/ssh/sshd_config".into(),
                "# In a SECOND ssh session, confirm key-only auth works:".into(),
                "ssh -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o PasswordAuthentication=no <user>@<host>".into(),
                "sudo sed -i 's/^[# ]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config".into(),
                "sudo sshd -t && sudo systemctl reload sshd".into(),
            ],
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::{ListeningSocket, NetworkSnapshot, SocketProtocol};
    use crate::predictive::proposal::ProposalStore;
    use crate::networking::{InterfaceAddress, NetworkInterface};
    use std::net::IpAddr;

    fn iface(name: &str, addr: &str, family: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            mac: "00:00:00:00:00:00".into(),
            state: "up".into(), mtu: 1500,
            addresses: vec![InterfaceAddress {
                address: addr.into(),
                prefix: if family == "inet" { 24 } else { 64 },
                family: family.into(),
                scope: "global".into(),
            }],
            is_vlan: false, vlan_id: None, parent: None,
            speed: None, driver: None,
        }
    }

    fn sock(addr: &str, port: u16) -> ListeningSocket {
        ListeningSocket {
            bind: addr.parse::<IpAddr>().unwrap(),
            port,
            protocol: SocketProtocol::Tcp,
            process: Some(format!("svc-{}", port)),
        }
    }

    fn ctx_with(interfaces: Vec<NetworkInterface>, sockets: Vec<ListeningSocket>) -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(interfaces, sockets),
        }
    }

    // ── Listening services ──────────────────────────────────────

    #[test]
    fn mariadb_on_public_ip_is_high() {
        // The exact false-positive scenario from session memory:
        // the Inbox's binding-on-public finding scaled by reachability.
        // The doc-range 203.0.113.0/24 is treated as non-routable by
        // `is_publicly_routable_v4` (it's RFC 5737 documentation
        // space), so the fixture uses a real-world public IP.
        let socks = vec![sock("0.0.0.0", 3306)];
        let ifaces = vec![iface("eth0", "145.224.67.239", "inet")];
        let p = analyze_listening_services(
            &ctx_with(ifaces, socks),
            &NetworkSnapshot::from_parts(
                vec![iface("eth0", "145.224.67.239", "inet")],
                vec![sock("0.0.0.0", 3306)],
            ),
            &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
        assert!(p[0].title.contains("mysql"));
    }

    #[test]
    fn docker_api_plain_on_public_is_critical() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("0.0.0.0", 2375)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Critical,
            "docker-api-plain on public internet must be Critical");
    }

    #[test]
    fn mariadb_on_lan_only_is_warn() {
        // The MariaDB-on-private-LAN false-positive case the user
        // called out two sessions ago — must downgrade, not Critical.
        let ctx = ctx_with(
            vec![iface("eth0", "192.168.1.10", "inet")],
            vec![sock("0.0.0.0", 3306)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Warn,
            "MariaDB on RFC1918-only host must be Warn, never Critical");
    }

    #[test]
    fn loopback_only_silent() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty(),
            "lo-only bindings are correct posture; never fire");
    }

    #[test]
    fn ack_silences_specific_binding() {
        let ctx = ctx_with(
            vec![iface("eth0", "192.168.1.10", "inet")],
            vec![sock("0.0.0.0", 3306)],
        );
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_SERVICE_PUBLIC,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "0.0.0.0:3306".into(),
            },
            "Analytics LAN; intentional exposure to internal tools",
            "paul", None,
        ));
        let p = analyze_listening_services(
            &ctx, &ctx.network, &acks, &ProposalStore::default(),
        );
        assert!(p.is_empty());
    }

    // ── sshd config × reachability ──────────────────────────────

    #[test]
    fn sshd_root_on_public_is_critical() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("0.0.0.0", 22)],
        );
        let cfg = SshdConfig { root_login: true, password_auth: false };
        let p = analyze_sshd(
            &ctx, &cfg, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        let root = p.iter().find(|p| p.finding_type == FINDING_SSHD_ROOT_LOGIN).unwrap();
        assert_eq!(root.severity, Severity::Critical);
    }

    #[test]
    fn sshd_password_on_lan_is_warn() {
        let ctx = ctx_with(
            vec![iface("eth0", "192.168.1.10", "inet")],
            vec![sock("0.0.0.0", 22)],
        );
        let cfg = SshdConfig { root_login: false, password_auth: true };
        let p = analyze_sshd(
            &ctx, &cfg, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        let pa = p.iter().find(|p| p.finding_type == FINDING_SSHD_PASSWORD_AUTH).unwrap();
        assert_eq!(pa.severity, Severity::Warn);
    }

    #[test]
    fn analyzer_can_stay_quiet_on_clean_host() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306), sock("0.0.0.0", 22)],
        );
        let cfg = SshdConfig { root_login: false, password_auth: false };
        let p = analyze(
            &ctx, &cfg, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty(),
            "a clean host (services on lo, ssh keys-only) produces no posture findings");
    }

    /// Guards the discipline rule from the original predictive
    /// plan: every analyzer must produce at least one combination
    /// of inputs that yields no finding. Listening services on
    /// loopback and an SSH config with no password/root flags
    /// satisfies that.
    #[test]
    fn discipline_one_input_class_silent() {
        // LoopbackOnly + clean sshd → analyzer stays quiet.
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306)],
        );
        let cfg = SshdConfig::default();
        let p = analyze(&ctx, &cfg, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }
}
