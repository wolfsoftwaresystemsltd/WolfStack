// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Auto-generate a self-signed TLS certificate when the operator
//! hasn't supplied one and no Let's Encrypt cert is available.
//!
//! ## Why this exists
//!
//! Pre-v23.11, a fresh WolfStack install with no `--tls-cert`, no
//! `--tls-domain`, and no Let's Encrypt cert in standard locations
//! silently fell back to plain HTTP on the main port. Inter-node
//! federation calls (HTTPS first, HTTP fallback) couldn't always
//! reach those nodes — and any browser hitting `https://host:8553`
//! got a TLS handshake error. With thousands of installs in the
//! wild that often don't have a public domain, HTTPS-by-default is
//! the only sane posture.
//!
//! ## What this does
//!
//! - Writes a self-signed cert to `/etc/wolfstack/tls/cert.pem`
//!   and the matching key to `/etc/wolfstack/tls/key.pem`
//! - **Reuses** an existing cert if one is already present, valid,
//!   and not expiring within 30 days
//! - Regenerates if the cert is missing, corrupt, or expired
//! - Picks RSA-2048 (universal compat with browsers and openssl 0.10);
//!   key + cert valid for 10 years
//! - SAN includes the hostname, `*.<hostname>`, `localhost`,
//!   `127.0.0.1`, `::1`, and any IP supplied by the caller
//!
//! ## Why it lives under `installer/`
//!
//! Symmetrical with `find_tls_certificate()` and the operator-facing
//! cert helpers there. The existing `wolfstack_local_cert_paths()`
//! ALREADY checks `/etc/wolfstack/tls/cert.pem` + `/etc/wolfstack/tls/key.pem`,
//! so writing here means the existing TLS discovery path picks the
//! cert up with zero changes to the decision tree.
//!
//! ## What this does NOT do
//!
//! - Override an operator-supplied `--tls-cert` / `--tls-key`
//! - Override a Let's Encrypt cert found by `find_tls_certificate()`
//!   (caller is expected to call `ensure_self_signed_cert()` only
//!   when none of those took effect)
//! - Regenerate the cert when the host's IP set changes (operator
//!   may have intentionally configured the existing cert; deleting
//!   `/etc/wolfstack/tls/cert.pem` triggers regeneration on next
//!   startup if they want a refresh)

use std::net::IpAddr;
use std::path::Path;

pub const CERT_PATH: &str = "/etc/wolfstack/tls/cert.pem";
pub const KEY_PATH: &str = "/etc/wolfstack/tls/key.pem";

/// Validity window. 10 years means no renewal cron needed for the
/// lifetime of a typical WolfStack deployment.
const CERT_VALID_DAYS: u32 = 365 * 10;
/// Regenerate if the existing cert expires within this many days.
const REGEN_IF_EXPIRES_WITHIN_DAYS: i64 = 30;

/// Inspect a cert PEM file and return true iff it appears to be self-signed
/// (subject DN == issuer DN). v23.12 uses this to decide whether to bind the
/// secondary plain-HTTP listener on `inter_node_port`: operators with a real
/// CA-signed cert (Let's Encrypt, etc.) get HTTPS-only and never hit the
/// 8554/RTSP conflict with Frigate, MediaMTX, go2rtc, GStreamer RTSP, etc.
///
/// Returns `false` on any read/parse error — that's the conservative answer
/// because a false negative just keeps the legacy listener for one more
/// startup, while a false positive (treating a real cert as self-signed)
/// could leave the listener bound when it shouldn't be. Errors are logged
/// at debug, not warn — they're not actionable for the operator.
pub fn cert_appears_self_signed(cert_path: &str) -> bool {
    let bytes = match std::fs::read(cert_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!("cert_appears_self_signed: read {} failed: {}", cert_path, e);
            return false;
        }
    };
    let cert = match openssl::x509::X509::from_pem(&bytes) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("cert_appears_self_signed: parse {} failed: {}", cert_path, e);
            return false;
        }
    };
    // OpenSSL X509_NAME comparison: subject DN bytes vs issuer DN bytes.
    // `build_self_signed()` below calls `set_subject_name(&name)` and
    // `set_issuer_name(&name)` with the *same* X509Name (lines 225-226),
    // so our auto-generated certs always satisfy this. Externally-supplied
    // self-signed certs (mkcert, manually-issued internal CA root, etc.)
    // also satisfy it. CA-issued certs do not.
    let subject_bytes = match cert.subject_name().to_der() {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!("cert_appears_self_signed: subject DER {} failed: {}", cert_path, e);
            return false;
        }
    };
    let issuer_bytes = match cert.issuer_name().to_der() {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!("cert_appears_self_signed: issuer DER {} failed: {}", cert_path, e);
            return false;
        }
    };
    subject_bytes == issuer_bytes
}

/// Ensure a self-signed TLS cert exists at the standard WolfStack path.
///
/// Returns `(cert_path, key_path)` on success. The paths are constants
/// that already match the lookup list in `wolfstack_local_cert_paths()`,
/// so the existing `find_tls_certificate()` will discover them.
///
/// Reuses an existing cert when one is present, parses cleanly, and
/// isn't near expiry. Generates fresh otherwise.
///
/// Errors out (returning Err) when openssl fails or `/etc/wolfstack/tls`
/// is not writable. Caller should log the error and fall through to
/// HTTP-only — never crash startup over a missing cert.
pub fn ensure_self_signed_cert(
    hostname: &str,
    ips: &[IpAddr],
) -> Result<(String, String), String> {
    // 1) Reuse path — both files present, cert is parseable + valid.
    if both_files_present_and_valid()? {
        return Ok((CERT_PATH.to_string(), KEY_PATH.to_string()));
    }

    // 2) Generate fresh.
    let (cert_pem, key_pem) = build_self_signed(hostname, ips)?;

    // 3) Write atomically: write to <path>.tmp then rename. Renames
    //    are atomic on POSIX so partial writes can never produce a
    //    half-cert that openssl chokes on at next startup. We use the
    //    existing `paths::write_secure` helper which already does mode
    //    0600 + parent-dir creation; for the cert we'll relax to 0644
    //    AFTER write so browsers/operators can read it.
    crate::paths::write_secure(CERT_PATH, &cert_pem)
        .map_err(|e| format!("write {}: {}", CERT_PATH, e))?;
    crate::paths::write_secure(KEY_PATH, &key_pem)
        .map_err(|e| format!("write {}: {}", KEY_PATH, e))?;
    // Cert is public — relax to 0644 so non-root tooling (browsers
    // told to import it) can read it. Key stays 0600 (write_secure
    // already set it).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            CERT_PATH,
            std::fs::Permissions::from_mode(0o644),
        );
    }

    tracing::info!(
        "TLS: auto-generated self-signed cert at {} (valid {} days; SAN includes hostname + {} IP(s))",
        CERT_PATH, CERT_VALID_DAYS, ips.len()
    );

    Ok((CERT_PATH.to_string(), KEY_PATH.to_string()))
}

/// True iff both cert and key files exist, parse cleanly, and the
/// cert isn't within REGEN_IF_EXPIRES_WITHIN_DAYS of expiry.
///
/// Returns Err only on filesystem errors that would also prevent
/// writing a new cert — those propagate up so caller knows.
fn both_files_present_and_valid() -> Result<bool, String> {
    let cert_p = Path::new(CERT_PATH);
    let key_p = Path::new(KEY_PATH);
    if !cert_p.exists() || !key_p.exists() {
        return Ok(false);
    }
    // Empty files are treated as missing.
    let cert_meta = std::fs::metadata(cert_p)
        .map_err(|e| format!("stat {}: {}", CERT_PATH, e))?;
    let key_meta = std::fs::metadata(key_p)
        .map_err(|e| format!("stat {}: {}", KEY_PATH, e))?;
    if cert_meta.len() == 0 || key_meta.len() == 0 {
        return Ok(false);
    }
    // Parse the cert and check expiry. If parsing fails, treat as
    // corrupt and trigger regen.
    let cert_bytes = match std::fs::read(cert_p) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    let cert = match openssl::x509::X509::from_pem(&cert_bytes) {
        Ok(c) => c,
        Err(_) => {
            tracing::warn!(
                "TLS: existing self-signed cert at {} is unparseable — will regenerate",
                CERT_PATH
            );
            return Ok(false);
        }
    };
    // Check expiry. openssl::asn1::Asn1Time supports comparison with
    // another Asn1Time via diff(). If the cert expires within 30 days,
    // regenerate proactively.
    let cutoff = openssl::asn1::Asn1Time::days_from_now(REGEN_IF_EXPIRES_WITHIN_DAYS as u32)
        .map_err(|e| format!("asn1 cutoff time: {}", e))?;
    // not_after - cutoff: if positive, cert is still valid past cutoff
    let diff = match cert.not_after().diff(&cutoff) {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };
    // diff is (days, seconds) — if both <= 0 the cert.not_after is
    // BEFORE cutoff (i.e. expires within 30 days). Either day or
    // second negative means expires soon.
    if diff.days < 0 || (diff.days == 0 && diff.secs < 0) {
        tracing::warn!(
            "TLS: existing self-signed cert at {} expires within {} days — will regenerate",
            CERT_PATH, REGEN_IF_EXPIRES_WITHIN_DAYS
        );
        return Ok(false);
    }
    Ok(true)
}

/// Build the cert + key PEMs. Pure: no filesystem I/O. Caller writes
/// the output.
fn build_self_signed(
    hostname: &str,
    ips: &[IpAddr],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509, X509NameBuilder};

    // Hostname sanity — Asn1::set_subject_name rejects empty CN.
    let cn = if hostname.trim().is_empty() {
        "wolfstack"
    } else {
        hostname.trim()
    };

    let rsa = Rsa::generate(2048).map_err(|e| format!("rsa generate: {}", e))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| format!("pkey from rsa: {}", e))?;

    let mut name_b = X509NameBuilder::new()
        .map_err(|e| format!("x509 name builder: {}", e))?;
    name_b.append_entry_by_text("CN", cn)
        .map_err(|e| format!("set CN: {}", e))?;
    name_b.append_entry_by_text("O", "WolfStack")
        .map_err(|e| format!("set O: {}", e))?;
    let name = name_b.build();

    let mut builder = X509::builder().map_err(|e| format!("x509 builder: {}", e))?;
    builder.set_version(2).map_err(|e| format!("set version: {}", e))?; // v3
    // Random-ish serial. Single fixed value would still work but
    // changing this lets browsers distinguish regenerations.
    let mut serial_bytes = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut serial_bytes);
    }
    // Force positive: clear MSB.
    serial_bytes[0] &= 0x7F;
    let serial = BigNum::from_slice(&serial_bytes)
        .map_err(|e| format!("serial bignum: {}", e))?;
    let serial_asn = serial.to_asn1_integer()
        .map_err(|e| format!("serial to asn1: {}", e))?;
    builder.set_serial_number(&serial_asn)
        .map_err(|e| format!("set serial: {}", e))?;
    builder.set_subject_name(&name).map_err(|e| format!("set subject: {}", e))?;
    builder.set_issuer_name(&name).map_err(|e| format!("set issuer: {}", e))?;
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|e| format!("not_before: {}", e))?;
    let not_after = Asn1Time::days_from_now(CERT_VALID_DAYS)
        .map_err(|e| format!("not_after: {}", e))?;
    builder.set_not_before(&not_before).map_err(|e| format!("set not_before: {}", e))?;
    builder.set_not_after(&not_after).map_err(|e| format!("set not_after: {}", e))?;
    builder.set_pubkey(&pkey).map_err(|e| format!("set pubkey: {}", e))?;

    // Extensions.
    builder.append_extension(
        BasicConstraints::new().build()
            .map_err(|e| format!("BasicConstraints: {}", e))?
    ).map_err(|e| format!("append BC: {}", e))?;

    builder.append_extension(
        KeyUsage::new().digital_signature().key_encipherment().build()
            .map_err(|e| format!("KeyUsage: {}", e))?
    ).map_err(|e| format!("append KU: {}", e))?;

    builder.append_extension(
        ExtendedKeyUsage::new().server_auth().client_auth().build()
            .map_err(|e| format!("ExtendedKeyUsage: {}", e))?
    ).map_err(|e| format!("append EKU: {}", e))?;

    // SAN — must include EVERY name an operator might use to reach
    // this node. Include hostname + a wildcard for sub-hostnames,
    // localhost variants, and any IP the caller knows about.
    let mut san = SubjectAlternativeName::new();
    san.dns(cn);
    if !cn.contains('.') {
        // FQDN-style wildcard only useful when CN has a domain
    } else {
        san.dns(&format!("*.{}", cn));
    }
    san.dns("localhost");
    san.ip("127.0.0.1");
    san.ip("::1");
    let mut seen = std::collections::HashSet::new();
    seen.insert("127.0.0.1".to_string());
    seen.insert("::1".to_string());
    for ip in ips {
        let s = ip.to_string();
        if seen.insert(s.clone()) {
            san.ip(&s);
        }
    }
    let san_ext = san.build(&builder.x509v3_context(None, None))
        .map_err(|e| format!("SAN build: {}", e))?;
    builder.append_extension(san_ext)
        .map_err(|e| format!("append SAN: {}", e))?;

    builder.sign(&pkey, MessageDigest::sha256())
        .map_err(|e| format!("sign: {}", e))?;
    let cert = builder.build();

    let cert_pem = cert.to_pem().map_err(|e| format!("cert to_pem: {}", e))?;
    let key_pem = pkey.private_key_to_pem_pkcs8()
        .map_err(|e| format!("key to_pem: {}", e))?;
    Ok((cert_pem, key_pem))
}

/// Best-effort enumeration of non-loopback IPv4 + IPv6 addresses on
/// the host. Used by main.rs at startup to populate the SAN. Returns
/// empty Vec on failure — caller-side cert will still work for
/// hostname-based connections.
pub fn detect_local_ips() -> Vec<IpAddr> {
    // Shell out to `ip -j addr show` which returns JSON. Avoids a
    // libc binding dependency just for this. If `ip` isn't installed,
    // we return empty — cert just doesn't have IP SAN entries.
    let out = std::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output();
    let bytes = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let arr = match json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out: Vec<IpAddr> = Vec::new();
    for item in arr {
        // Skip lo and any loopback.
        let ifname = item.get("ifname").and_then(|v| v.as_str()).unwrap_or("");
        if ifname == "lo" { continue; }
        let addrs = match item.get("addr_info").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };
        for a in addrs {
            let scope = a.get("scope").and_then(|v| v.as_str()).unwrap_or("");
            // Skip link-local (fe80::) and host-scope — useless in a cert SAN.
            if scope == "link" || scope == "host" { continue; }
            let local = match a.get("local").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            if let Ok(ip) = local.parse::<IpAddr>() {
                if !ip.is_loopback() {
                    out.push(ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem_is_valid_cert(pem: &[u8]) -> bool {
        openssl::x509::X509::from_pem(pem).is_ok()
    }
    fn pem_is_valid_key(pem: &[u8]) -> bool {
        openssl::pkey::PKey::private_key_from_pem(pem).is_ok()
    }

    #[test]
    fn build_self_signed_produces_valid_pems() {
        let (cert, key) = build_self_signed(
            "test.example.com",
            &["10.0.0.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        ).expect("build must succeed");
        assert!(pem_is_valid_cert(&cert), "cert PEM must be valid");
        assert!(pem_is_valid_key(&key), "key PEM must be valid");
        // Cert text contains the expected fields
        let cert_obj = openssl::x509::X509::from_pem(&cert).unwrap();
        let subj = format!("{:?}", cert_obj.subject_name());
        assert!(subj.contains("test.example.com"), "CN not in subject: {}", subj);
    }

    #[test]
    fn build_self_signed_handles_empty_hostname() {
        // Falls back to "wolfstack" CN.
        let (cert, _) = build_self_signed("", &[]).expect("empty CN must default");
        let cert_obj = openssl::x509::X509::from_pem(&cert).unwrap();
        let subj = format!("{:?}", cert_obj.subject_name());
        assert!(subj.contains("wolfstack"), "fallback CN missing: {}", subj);
    }

    #[test]
    fn build_self_signed_handles_no_ips() {
        // Should still produce a valid cert with just hostname + loopback SAN.
        let (cert, key) = build_self_signed("solo.example.com", &[])
            .expect("must work without IPs");
        assert!(pem_is_valid_cert(&cert));
        assert!(pem_is_valid_key(&key));
    }

    #[test]
    fn build_self_signed_dedupes_loopback_ips() {
        // Caller passes 127.0.0.1 explicitly — the SAN should not have
        // duplicate IP entries (would still be valid but is ugly).
        // We can't easily inspect the SAN list from openssl rust bindings
        // without parsing the cert text, so just confirm it still produces
        // a parseable cert and doesn't panic.
        let (cert, _) = build_self_signed("dup.example.com", &[
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ]).expect("dedup must succeed");
        assert!(pem_is_valid_cert(&cert));
    }

    #[test]
    fn cert_validity_is_10_years() {
        let (cert, _) = build_self_signed("clock.example.com", &[]).unwrap();
        let cert_obj = openssl::x509::X509::from_pem(&cert).unwrap();
        // not_before is now-ish, not_after should be ~3650 days later.
        let now = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let one_year_later = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
        let nine_years_later = openssl::asn1::Asn1Time::days_from_now(365 * 9).unwrap();
        // not_before should be at or before "now"
        assert!(cert_obj.not_before() <= now.as_ref(),
            "not_before should be <= now");
        // not_after should be well past one year and beyond nine years
        // (i.e. approximately 10 years from now ±tolerance)
        assert!(cert_obj.not_after() > one_year_later.as_ref(),
            "not_after should be > 1 year from now");
        assert!(cert_obj.not_after() > nine_years_later.as_ref(),
            "not_after should be > 9 years from now (we generate 10y certs)");
    }

    // detect_local_ips() shells out to `ip` — can't unit test without
    // mocking. Its behaviour is best verified by running on a real
    // host. The function returns Vec::new() on any failure (no `ip`,
    // bad JSON), so it can't crash the cert-generation path.

    /// Helper: write a PEM to /tmp/wolfstack-test-<rand>.pem and return path.
    fn write_temp_pem(pem: &[u8]) -> String {
        let path = format!("/tmp/wolfstack-cert-test-{}.pem", std::process::id());
        std::fs::write(&path, pem).expect("temp write");
        path
    }

    #[test]
    fn cert_appears_self_signed_detects_our_own_cert() {
        let (cert_pem, _) = build_self_signed("self.example.com", &[]).unwrap();
        let path = write_temp_pem(&cert_pem);
        assert!(cert_appears_self_signed(&path), "auto-generated cert must be detected as self-signed");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cert_appears_self_signed_handles_missing_file() {
        // Non-existent path is conservatively "not self-signed" so we
        // don't accidentally suppress the second listener bind on a
        // botched install.
        assert!(!cert_appears_self_signed("/tmp/this-path-definitely-does-not-exist-xyz123.pem"));
    }

    #[test]
    fn cert_appears_self_signed_handles_unparseable_file() {
        let path = format!("/tmp/wolfstack-bogus-{}.pem", std::process::id());
        std::fs::write(&path, b"this is not a PEM").unwrap();
        assert!(!cert_appears_self_signed(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cert_appears_self_signed_rejects_ca_issued_cert() {
        // Build a tiny chain: a CA cert (self-signed) and a leaf cert
        // signed by it. The leaf's subject is "leaf.example.com" and
        // its issuer is "ca.example.com" — they MUST differ.
        use openssl::asn1::Asn1Time;
        use openssl::bn::{BigNum, MsbOption};
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509, X509Name, X509Builder};
        use openssl::nid::Nid;

        // CA key + cert
        let ca_rsa = Rsa::generate(2048).unwrap();
        let ca_key = PKey::from_rsa(ca_rsa).unwrap();
        let mut ca_name = X509Name::builder().unwrap();
        ca_name.append_entry_by_nid(Nid::COMMONNAME, "ca.example.com").unwrap();
        let ca_name = ca_name.build();
        let mut ca = X509Builder::new().unwrap();
        ca.set_version(2).unwrap();
        let mut sn = BigNum::new().unwrap();
        sn.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        ca.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
        ca.set_subject_name(&ca_name).unwrap();
        ca.set_issuer_name(&ca_name).unwrap();
        ca.set_pubkey(&ca_key).unwrap();
        ca.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        ca.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca_cert: X509 = ca.build();

        // Leaf cert signed by CA
        let leaf_rsa = Rsa::generate(2048).unwrap();
        let leaf_key = PKey::from_rsa(leaf_rsa).unwrap();
        let mut leaf_name = X509Name::builder().unwrap();
        leaf_name.append_entry_by_nid(Nid::COMMONNAME, "leaf.example.com").unwrap();
        let leaf_name = leaf_name.build();
        let mut leaf = X509Builder::new().unwrap();
        leaf.set_version(2).unwrap();
        let mut leaf_sn = BigNum::new().unwrap();
        leaf_sn.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        leaf.set_serial_number(&leaf_sn.to_asn1_integer().unwrap()).unwrap();
        leaf.set_subject_name(&leaf_name).unwrap();
        leaf.set_issuer_name(ca_cert.subject_name()).unwrap();  // issuer = CA subject
        leaf.set_pubkey(&leaf_key).unwrap();
        leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        leaf.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
        leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let leaf_cert: X509 = leaf.build();

        let leaf_pem = leaf_cert.to_pem().unwrap();
        let path = format!("/tmp/wolfstack-leaf-{}.pem", std::process::id());
        std::fs::write(&path, &leaf_pem).unwrap();

        assert!(
            !cert_appears_self_signed(&path),
            "CA-issued leaf cert (subject != issuer) must NOT be detected as self-signed"
        );

        let _ = std::fs::remove_file(&path);
    }
}

