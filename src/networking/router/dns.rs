// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! DNS helpers for WolfRouter. The heavy lifting is done by dnsmasq
//! via dhcp.rs (same process serves DHCP + DNS per LAN). This module
//! exposes a few query/lookup helpers the UI layer uses:
//!   • Reverse lookup: "what hostname does the router know for this IP?"
//!   • Upstream health check: can we reach the configured forwarders?

use super::*;
use std::process::Command;
use std::time::Duration;

/// Quick-and-dirty upstream check — `dig +short @<forwarder> example.com`
/// with a tight timeout. Returns the responding forwarder or None.
#[allow(dead_code)]
pub fn probe_forwarder(forwarder: &str) -> Option<Duration> {
    use std::time::Instant;
    let start = Instant::now();
    let out = Command::new("dig")
        .args(["+short", "+time=2", "+tries=1",
               &format!("@{}", forwarder), "cloudflare.com", "A"])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    // Any output means the forwarder answered. An empty stdout with
    // zero exit is "NXDOMAIN" — still proof the server is alive.
    Some(start.elapsed())
}

/// List every local DNS record across every LAN served by this node —
/// used by the UI to show "what hostnames can this cluster resolve?"
#[allow(dead_code)]
pub fn cluster_local_records(config: &RouterConfig) -> Vec<(String, LocalDnsRecord)> {
    let mut out = Vec::new();
    for lan in &config.lans {
        for rec in &lan.dns.local_records {
            out.push((lan.name.clone(), rec.clone()));
        }
    }
    out
}
