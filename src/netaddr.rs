// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Address formatting helpers for dual-stack (IPv4 + IPv6) support.
//!
//! Canonical form: node/peer addresses are STORED as bare strings
//! ("192.168.1.5", "2001:db8::1", "node7.lan") and brackets are added
//! only at the moment a URL, bind string, or connect target is built.
//! Every `http://{}:{}`-style format site must go through these helpers
//! — a bare IPv6 literal pasted into `host:port` is unparseable (the
//! port colon is ambiguous).

use std::borrow::Cow;

/// Wrap a bare IPv6 literal in `[brackets]` for use in URLs and
/// `host:port` strings. IPv4 addresses, hostnames, and already-bracketed
/// strings pass through unchanged, so every existing v4 callsite emits
/// byte-identical output.
///
/// Zone-scoped literals (`fe80::1%eth0`) do not parse as `Ipv6Addr` and
/// pass through unchanged — they are rejected upstream by
/// `agent::is_usable_addr` and never reach a URL builder.
pub fn bracket_host(host: &str) -> Cow<'_, str> {
    let h = host.trim();
    if h.parse::<std::net::Ipv6Addr>().is_ok() {
        Cow::Owned(format!("[{}]", h))
    } else {
        Cow::Borrowed(host)
    }
}

/// Join a host and port into a connectable / bindable `host:port`
/// string, bracketing bare IPv6 literals: `("::", 8553)` → `"[::]:8553"`,
/// `("0.0.0.0", 8553)` → `"0.0.0.0:8553"` (unchanged for v4).
pub fn host_port(host: &str, port: u16) -> String {
    format!("{}:{}", bracket_host(host), port)
}

/// Canonicalize an IP string: an IPv4-mapped IPv6 address
/// (`::ffff:1.2.3.4` — what a dual-stack `[::]` listener reports for
/// every IPv4 client) becomes the plain IPv4 form. Anything else passes
/// through unchanged. This MUST be applied wherever a peer IP string is
/// extracted for security decisions: a mapped string keys the wrong
/// lockout bucket, never matches a v4 trusted CIDR, and — worst —
/// routes `kernel_block_ip` to ip6tables, whose DROP never touches the
/// attacker's actual IPv4-wire traffic.
pub fn canonical_ip_str(s: &str) -> Cow<'_, str> {
    match s.trim().parse::<std::net::IpAddr>() {
        Ok(ip) => {
            let canon = ip.to_canonical();
            if canon == ip {
                Cow::Borrowed(s)
            } else {
                Cow::Owned(canon.to_string())
            }
        }
        Err(_) => Cow::Borrowed(s),
    }
}

/// Strip a trailing `:port` from an address, returning the bare host.
/// Handles every form that reaches us: `"[2001:db8::1]:8553"` → the
/// bare v6, `"10.0.0.1:8553"` / `"node7:8553"` → host, and — the trap
/// `rsplit(':')` falls into — a bare IPv6 literal (`"2001:db8::1"`)
/// is returned UNCHANGED because it parses as `Ipv6Addr` whole (its
/// last group would otherwise be eaten as a "port").
pub fn strip_port(addr: &str) -> &str {
    let a = addr.trim();
    // Bracketed v6 (with or without :port) — the bracket span is the host.
    if let Some(rest) = a.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &rest[..end];
    }
    // A bare IPv6 literal has no port by definition.
    if a.parse::<std::net::Ipv6Addr>().is_ok() {
        return a;
    }
    if let Some(idx) = a.rfind(':') {
        let port_part = &a[idx + 1..];
        if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
            return &a[..idx];
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_and_hostnames_pass_through_unchanged() {
        assert_eq!(bracket_host("192.168.1.5"), "192.168.1.5");
        assert_eq!(bracket_host("0.0.0.0"), "0.0.0.0");
        assert_eq!(bracket_host("rivendell.lan"), "rivendell.lan");
        assert_eq!(host_port("0.0.0.0", 8553), "0.0.0.0:8553");
        assert_eq!(host_port("node7", 8554), "node7:8554");
    }

    #[test]
    fn bare_v6_literals_get_brackets() {
        assert_eq!(bracket_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(bracket_host("::1"), "[::1]");
        assert_eq!(bracket_host("fd00:10:100::7"), "[fd00:10:100::7]");
        assert_eq!(host_port("::", 8553), "[::]:8553");
        assert_eq!(host_port("2001:db8::1", 8553), "[2001:db8::1]:8553");
    }

    #[test]
    fn already_bracketed_and_scoped_pass_through() {
        // Already bracketed — don't double-wrap.
        assert_eq!(bracket_host("[2001:db8::1]"), "[2001:db8::1]");
        // Zone-scoped link-local doesn't parse as Ipv6Addr — unchanged
        // (rejected upstream as an advertised address anyway).
        assert_eq!(bracket_host("fe80::1%eth0"), "fe80::1%eth0");
        // host:port strings are not valid Ipv6Addr — unchanged.
        assert_eq!(bracket_host("10.0.0.1:8553"), "10.0.0.1:8553");
    }

    #[test]
    fn mapped_v4_canonicalizes_everything_else_passes() {
        assert_eq!(canonical_ip_str("::ffff:192.168.1.5"), "192.168.1.5");
        assert_eq!(canonical_ip_str("::ffff:127.0.0.1"), "127.0.0.1");
        // Untouched: real v4, real v6, hostnames, garbage.
        assert_eq!(canonical_ip_str("192.168.1.5"), "192.168.1.5");
        assert_eq!(canonical_ip_str("2001:db8::1"), "2001:db8::1");
        assert_eq!(canonical_ip_str("::1"), "::1");
        assert_eq!(canonical_ip_str("bree.lan"), "bree.lan");
        assert_eq!(canonical_ip_str(""), "");
    }

    #[test]
    fn strip_port_handles_all_forms() {
        assert_eq!(strip_port("10.0.0.1:8553"), "10.0.0.1");
        assert_eq!(strip_port("10.0.0.1"), "10.0.0.1");
        assert_eq!(strip_port("bagend.lan:8553"), "bagend.lan");
        assert_eq!(strip_port("bagend.lan"), "bagend.lan");
        assert_eq!(strip_port("[2001:db8::1]:8553"), "2001:db8::1");
        assert_eq!(strip_port("[::1]"), "::1");
        // The rsplit(':') trap — bare v6 must NOT lose its last group.
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(strip_port("fd00::7"), "fd00::7");
    }

    #[test]
    fn bind_strings_parse_as_socket_addrs() {
        use std::net::SocketAddr;
        assert!(host_port("0.0.0.0", 8553).parse::<SocketAddr>().is_ok());
        assert!(host_port("::", 8553).parse::<SocketAddr>().is_ok());
        assert!(host_port("2001:db8::1", 80).parse::<SocketAddr>().is_ok());
        // The pre-fix failure mode: bare "::" + format! was ":::8553".
        assert!(":::8553".parse::<SocketAddr>().is_err());
    }
}
