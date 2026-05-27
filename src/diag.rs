// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Diagnostic listener.
//!
//! Optional TCP listener used internally as a traffic-pattern probe.
//! Off by default — operator opts in via the UI toggle. When on,
//! inbound traffic from sources outside the expected envelope
//! (loopback, configured trusted CIDRs, WolfNet, cluster peers, and
//! by default the local LAN) is recorded through the auth limiter's
//! quiet auto-block path.
//!
//! The port is fixed at a high, uncommon number well outside the
//! typical scanner top-1000 / top-10000 range. The listener only
//! binds when enabled, so when off there is no port-conflict surface.
//! Toggle response latency is sub-second.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::agent::ClusterState;
use crate::auth::LoginRateLimiter;

/// Port to bind when enabled. Picked well above the typical scanner
/// top-N port lists so opportunistic sweeps don't hit it accidentally.
const PORT: u16 = 41910;
const STATE_PATH: &str = "/etc/wolfstack/diag.json";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const REBIND_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Serialize, Deserialize, Default, Clone)]
struct State {
    #[serde(default)]
    enabled: bool,
    /// When true, RFC1918 sources are NOT treated as expected. Off by
    /// default — most operators have internal monitoring on LAN.
    #[serde(default)]
    strict_lan: bool,
}

fn load_state() -> State {
    std::fs::read_to_string(STATE_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(s: &State) {
    let Ok(json) = serde_json::to_string_pretty(s) else { return };
    if let Some(parent) = Path::new(STATE_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(STATE_PATH, json);
}

/// Runtime control surface. Held in AppState so API handlers can flip
/// the toggle; the listener thread polls it.
pub struct Control {
    enabled: AtomicBool,
    strict_lan: AtomicBool,
}

impl Control {
    pub fn new() -> Self {
        let s = load_state();
        Self {
            enabled: AtomicBool::new(s.enabled),
            strict_lan: AtomicBool::new(s.strict_lan),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
        save_state(&State {
            enabled: on,
            strict_lan: self.strict_lan.load(Ordering::Relaxed),
        });
    }

    pub fn strict_lan(&self) -> bool {
        self.strict_lan.load(Ordering::Relaxed)
    }
}

impl Default for Control {
    fn default() -> Self { Self::new() }
}

#[derive(Clone)]
struct Allow {
    limiter: Arc<LoginRateLimiter>,
    cluster: Arc<ClusterState>,
    control: Arc<Control>,
}

impl Allow {
    fn is_allowed(&self, ip: &IpAddr) -> bool {
        if ip.is_loopback() { return true; }
        if self.limiter.config().is_trusted(&ip.to_string()) { return true; }
        if let IpAddr::V4(v4) = ip {
            if let Some((net, prefix)) = crate::networking::get_local_wolfnet_subnet() {
                if v4_in_cidr(*v4, net, prefix) { return true; }
            }
        }
        let needle = ip.to_string();
        let nodes = self.cluster.nodes.read().unwrap();
        for n in nodes.values() {
            if n.address == needle { return true; }
            if n.public_ip.as_deref() == Some(needle.as_str()) { return true; }
        }
        drop(nodes);
        if !self.control.strict_lan() && is_private(ip) { return true; }
        false
    }
}

fn v4_in_cidr(target: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    if prefix > 32 { return false; }
    let mask: u32 = (!0u32).checked_shl(32 - prefix as u32).unwrap_or(0);
    (u32::from(target) & mask) == (u32::from(net) & mask)
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => is_ula_or_local(v6),
    }
}

fn is_ula_or_local(v6: &Ipv6Addr) -> bool {
    let first = v6.segments()[0];
    if first & 0xfe00 == 0xfc00 { return true; }
    if first & 0xffc0 == 0xfe80 { return true; }
    v6.is_loopback()
}

/// Spawn the listener thread. The thread runs for the process
/// lifetime, polling `control.is_enabled()` to know whether to hold
/// the port open or release it.
pub fn start(
    limiter: Arc<LoginRateLimiter>,
    cluster: Arc<ClusterState>,
    control: Arc<Control>,
) {
    std::thread::Builder::new()
        .name("wolfstack-diag".into())
        .spawn(move || run(limiter, cluster, control))
        .ok();
}

fn run(
    limiter: Arc<LoginRateLimiter>,
    cluster: Arc<ClusterState>,
    control: Arc<Control>,
) {
    let allow = Allow { limiter, cluster, control: control.clone() };
    loop {
        // Idle wait while disabled — listener not bound, zero impact.
        while !control.is_enabled() {
            std::thread::sleep(POLL_INTERVAL);
        }
        // Bind. If the port is in use, back off and try again — the
        // operator may free it.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT);
        let listener = match TcpListener::bind(addr) {
            Ok(l) => {
                let _ = l.set_nonblocking(true);
                l
            }
            Err(e) => {
                tracing::debug!("diag: bind failed: {}", e);
                std::thread::sleep(REBIND_BACKOFF);
                continue;
            }
        };
        // Accept loop. set_nonblocking lets us periodically check the
        // disable flag without blocking forever in accept().
        loop {
            if !control.is_enabled() { break; }
            match listener.accept() {
                Ok((stream, peer)) => {
                    let allow = allow.clone();
                    std::thread::Builder::new()
                        .name("wolfstack-diag-c".into())
                        .spawn(move || handle(stream, peer, allow))
                        .ok();
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(_) => break,
            }
        }
        // Listener dropped here — port released.
    }
}

fn handle(mut stream: TcpStream, peer: SocketAddr, allow: Allow) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let ip = peer.ip();
    if allow.is_allowed(&ip) {
        return;
    }
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
    respond(head, &mut stream);
    let _ = allow.limiter.force_lockout(&ip.to_string(), "auto", "unsolicited connection");
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn respond(head: &str, stream: &mut TcpStream) {
    if head.starts_with("POST ") {
        let _ = stream.write_all(
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\nConnection: close\r\n\r\nbad password\n",
        );
        return;
    }
    if head.starts_with("GET ") || head.starts_with("HEAD ") {
        let body = LOGIN_HTML;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\nConnection: close\r\nServer: nginx\r\n\r\n{}",
            body.len(), body
        );
        let _ = stream.write_all(resp.as_bytes());
    }
}

const LOGIN_HTML: &str = "<!doctype html>
<html lang=\"en\"><head>
<meta charset=\"utf-8\">
<title>Sign in</title>
<style>body{font-family:sans-serif;max-width:340px;margin:60px auto;color:#222}
label{display:block;margin:8px 0 4px}input{width:100%;padding:6px}
button{margin-top:12px;padding:8px 16px}</style>
</head><body>
<h2>Sign in</h2>
<form method=\"post\" action=\"/login\">
<label>Username<input name=\"username\" autocomplete=\"username\"></label>
<label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\"></label>
<button type=\"submit\">Sign in</button>
</form>
</body></html>";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_cidr_match() {
        assert!(v4_in_cidr("10.5.5.5".parse().unwrap(), "10.0.0.0".parse().unwrap(), 8));
        assert!(!v4_in_cidr("11.5.5.5".parse().unwrap(), "10.0.0.0".parse().unwrap(), 8));
        assert!(v4_in_cidr("192.168.1.50".parse().unwrap(), "192.168.0.0".parse().unwrap(), 16));
    }

    #[test]
    fn private_detection() {
        assert!(is_private(&"10.0.0.5".parse().unwrap()));
        assert!(is_private(&"192.168.1.1".parse().unwrap()));
        assert!(is_private(&"172.16.0.1".parse().unwrap()));
        assert!(!is_private(&"8.8.8.8".parse().unwrap()));
        assert!(is_private(&"::1".parse().unwrap()));
        assert!(is_private(&"fe80::1".parse().unwrap()));
        assert!(is_private(&"fd00::1".parse().unwrap()));
        assert!(!is_private(&"2606:4700:4700::1111".parse().unwrap()));
    }

    // Note: no Control-toggle test here — set_enabled persists to
    // /etc/wolfstack/diag.json, which would clobber real state on the
    // dev machine. The in-memory atomic is trivially correct; the
    // persistence is exercised live.
}
