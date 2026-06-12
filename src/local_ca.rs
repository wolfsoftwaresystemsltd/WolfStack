// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Local Certificate Authority for internal domains.
//!
//! Public ACME (Let's Encrypt) can't issue for an unregistered local
//! domain like `*.ai.home` — there's no public DNS to validate. The
//! answer is a local CA: generate one root, install it ONCE in each
//! device's trust store, then issue leaf certs signed by it. Every
//! internal cert is then trusted automatically — the home-lab / Traefik
//! replacement story (Phase 2 of the local-domain roadmap).
//!
//! Files (root-only, key mode 0600):
//!   /etc/wolfstack/local-ca/ca-cert.pem   the root CA cert (downloadable)
//!   /etc/wolfstack/local-ca/ca-key.pem    the root CA private key (never leaves the box)
//!
//! The CA key NEVER leaves the host and is never returned by any API.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

/// Serialises CA generation so two concurrent `init` calls can't both
/// build a root and leave a cert/key that don't match each other.
static CA_INIT_LOCK: Mutex<()> = Mutex::new(());

const CA_DIR: &str = "/etc/wolfstack/local-ca";
const CA_CERT_PATH: &str = "/etc/wolfstack/local-ca/ca-cert.pem";
const CA_KEY_PATH: &str = "/etc/wolfstack/local-ca/ca-key.pem";
/// Root CA lifetime — long, because reinstalling it on every device is
/// painful. 10 years.
const CA_VALID_DAYS: u32 = 365 * 10;
/// Leaf cert lifetime. 825 days is the longest many clients accept; for a
/// privately-trusted CA it's a safe, low-friction default.
const LEAF_VALID_DAYS: u32 = 825;

pub fn ca_dir() -> &'static str { CA_DIR }
pub fn ca_cert_path() -> &'static str { CA_CERT_PATH }

/// Both halves of the CA present on disk.
pub fn ca_exists() -> bool {
    Path::new(CA_CERT_PATH).exists() && Path::new(CA_KEY_PATH).exists()
}

/// Read the root CA certificate PEM (safe to hand out — it's the public
/// half operators install in their trust store).
pub fn ca_cert_pem() -> Result<Vec<u8>, String> {
    std::fs::read(CA_CERT_PATH).map_err(|e| format!("read CA cert: {}", e))
}

/// A random, positive 16-byte serial — lets clients distinguish certs.
/// Uses OpenSSL's CSPRNG (not a raw /dev/urandom read) so it can never
/// silently fall back to an all-zero serial, which RFC 5280 forbids and
/// some clients reject.
fn random_serial() -> Result<openssl::asn1::Asn1Integer, String> {
    use openssl::bn::BigNum;
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes).map_err(|e| format!("serial rand: {}", e))?;
    bytes[0] &= 0x7F; // force positive
    BigNum::from_slice(&bytes)
        .map_err(|e| format!("serial bignum: {}", e))?
        .to_asn1_integer()
        .map_err(|e| format!("serial to asn1: {}", e))
}

/// Write a secret file (private key) with 0600 from the start — no
/// umask race where it sits world-readable between create and chmod.
pub fn write_secret_file(path: &str, data: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(path).map_err(|e| format!("open {}: {}", path, e))?;
        f.write_all(data).map_err(|e| format!("write {}: {}", path, e))?;
        // Belt-and-braces in case the file pre-existed with wider perms.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    { std::fs::write(path, data).map_err(|e| format!("write {}: {}", path, e)) }
}

/// Generate the root CA cert + key PEMs. Pure (no I/O). `org_label` names
/// the CA (e.g. "WolfStack" → CN "WolfStack Local CA") so it's
/// identifiable in a browser's trust list.
fn build_ca(org_label: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
    use openssl::x509::{X509, X509NameBuilder};

    // Cap the label so an over-long / unicode-heavy value can't blow past
    // the 64-char X.509 CN limit some validators enforce.
    let label_owned: String = org_label.trim().chars().take(40).collect();
    let label = if label_owned.is_empty() { "WolfStack" } else { label_owned.as_str() };

    // 4096-bit for the root — it signs everything and lives 10 years.
    let rsa = Rsa::generate(4096).map_err(|e| format!("ca rsa generate: {}", e))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| format!("ca pkey: {}", e))?;

    let mut nb = X509NameBuilder::new().map_err(|e| format!("name builder: {}", e))?;
    nb.append_entry_by_text("CN", &format!("{} Local CA", label))
        .map_err(|e| format!("set CN: {}", e))?;
    nb.append_entry_by_text("O", label).map_err(|e| format!("set O: {}", e))?;
    let name = nb.build();

    let mut b = X509::builder().map_err(|e| format!("x509 builder: {}", e))?;
    b.set_version(2).map_err(|e| format!("set version: {}", e))?; // v3
    let serial = random_serial()?;
    b.set_serial_number(&serial).map_err(|e| format!("set serial: {}", e))?;
    b.set_subject_name(&name).map_err(|e| format!("set subject: {}", e))?;
    b.set_issuer_name(&name).map_err(|e| format!("set issuer: {}", e))?; // self-signed root
    let not_before = Asn1Time::days_from_now(0).map_err(|e| format!("nb: {}", e))?;
    let not_after = Asn1Time::days_from_now(CA_VALID_DAYS).map_err(|e| format!("na: {}", e))?;
    b.set_not_before(&not_before).map_err(|e| format!("set nb: {}", e))?;
    b.set_not_after(&not_after).map_err(|e| format!("set na: {}", e))?;
    b.set_pubkey(&pkey).map_err(|e| format!("set pubkey: {}", e))?;

    // CA:TRUE (critical) + key-cert-sign so it can issue leaves.
    b.append_extension(
        BasicConstraints::new().critical().ca().build()
            .map_err(|e| format!("BC: {}", e))?
    ).map_err(|e| format!("append BC: {}", e))?;
    b.append_extension(
        KeyUsage::new().critical().key_cert_sign().crl_sign().build()
            .map_err(|e| format!("KU: {}", e))?
    ).map_err(|e| format!("append KU: {}", e))?;
    // Subject Key Identifier — lets issued leaves reference us via AKI so
    // chain-building works in every client.
    let ski = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(None, None))
        .map_err(|e| format!("SKI: {}", e))?;
    b.append_extension(ski).map_err(|e| format!("append SKI: {}", e))?;

    b.sign(&pkey, MessageDigest::sha256()).map_err(|e| format!("ca sign: {}", e))?;
    let cert = b.build();
    let cert_pem = cert.to_pem().map_err(|e| format!("ca cert to_pem: {}", e))?;
    let key_pem = pkey.private_key_to_pem_pkcs8().map_err(|e| format!("ca key to_pem: {}", e))?;
    Ok((cert_pem, key_pem))
}

/// Create the root CA on disk if it doesn't exist yet. Idempotent: a
/// second call with the CA already present is a no-op and returns the
/// existing cert PEM. The key is written 0600 (root-only).
pub fn ensure_ca(org_label: &str) -> Result<Vec<u8>, String> {
    // Serialise: two concurrent inits must not both build + write a root.
    let _guard = CA_INIT_LOCK.lock().map_err(|_| "CA init lock poisoned".to_string())?;
    if ca_exists() {
        return ca_cert_pem();
    }
    let (cert_pem, key_pem) = build_ca(org_label)?;
    // Create the dir 0700 BEFORE writing the key into it, so the key is
    // never reachable through a world-listable directory even momentarily.
    std::fs::create_dir_all(CA_DIR).map_err(|e| format!("mkdir {}: {}", CA_DIR, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(CA_DIR, std::fs::Permissions::from_mode(0o700));
    }
    // Atomic 0600 key write (no umask race), then the public cert.
    write_secret_file(CA_KEY_PATH, &key_pem)?;
    std::fs::write(CA_CERT_PATH, &cert_pem).map_err(|e| format!("write ca cert: {}", e))?;
    tracing::info!("local CA: generated root CA at {}", CA_CERT_PATH);
    Ok(cert_pem)
}

/// Issue a leaf certificate for `domain`, signed by the local CA. SAN
/// covers `domain`, `*.domain` (so the whole subtree is covered — the
/// wildcard-DNS companion), plus any IPs. Returns (leaf_cert_pem,
/// key_pem). The CA must already exist (call `ensure_ca` first). The leaf
/// is returned alone — the issuing root is what clients trust, installed
/// once via the download endpoint.
pub fn issue_leaf(domain: &str, ips: &[IpAddr]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let ca_cert_pem = std::fs::read(CA_CERT_PATH).map_err(|e| format!("read ca cert: {}", e))?;
    let ca_key_pem = std::fs::read(CA_KEY_PATH).map_err(|e| format!("read ca key: {}", e))?;
    issue_leaf_signed(&ca_cert_pem, &ca_key_pem, domain, ips)
}

/// Pure core of `issue_leaf`: sign a leaf for `domain` with the given CA
/// cert + key PEMs. No I/O, so it's unit-testable (build_ca → this →
/// verify the chain).
pub fn issue_leaf_signed(ca_cert_pem: &[u8], ca_key_pem: &[u8], domain: &str, ips: &[IpAddr]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectAlternativeName, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509, X509NameBuilder};

    let domain = domain.trim().trim_start_matches("*.").trim_start_matches('.');
    if domain.is_empty() {
        return Err("issue_leaf: domain is empty".into());
    }

    let ca_cert = X509::from_pem(ca_cert_pem).map_err(|e| format!("parse ca cert: {}", e))?;
    let ca_key = PKey::private_key_from_pem(ca_key_pem).map_err(|e| format!("parse ca key: {}", e))?;

    let rsa = Rsa::generate(2048).map_err(|e| format!("leaf rsa: {}", e))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| format!("leaf pkey: {}", e))?;

    let mut nb = X509NameBuilder::new().map_err(|e| format!("name builder: {}", e))?;
    nb.append_entry_by_text("CN", domain).map_err(|e| format!("set CN: {}", e))?;
    let name = nb.build();

    let mut b = X509::builder().map_err(|e| format!("x509 builder: {}", e))?;
    b.set_version(2).map_err(|e| format!("set version: {}", e))?;
    let serial = random_serial()?;
    b.set_serial_number(&serial).map_err(|e| format!("set serial: {}", e))?;
    b.set_subject_name(&name).map_err(|e| format!("set subject: {}", e))?;
    b.set_issuer_name(ca_cert.subject_name()).map_err(|e| format!("set issuer: {}", e))?;
    let not_before = Asn1Time::days_from_now(0).map_err(|e| format!("nb: {}", e))?;
    let not_after = Asn1Time::days_from_now(LEAF_VALID_DAYS).map_err(|e| format!("na: {}", e))?;
    b.set_not_before(&not_before).map_err(|e| format!("set nb: {}", e))?;
    b.set_not_after(&not_after).map_err(|e| format!("set na: {}", e))?;
    b.set_pubkey(&pkey).map_err(|e| format!("set pubkey: {}", e))?;

    b.append_extension(
        BasicConstraints::new().build().map_err(|e| format!("BC: {}", e))?
    ).map_err(|e| format!("append BC: {}", e))?; // CA:FALSE
    b.append_extension(
        KeyUsage::new().digital_signature().key_encipherment().build()
            .map_err(|e| format!("KU: {}", e))?
    ).map_err(|e| format!("append KU: {}", e))?;
    b.append_extension(
        ExtendedKeyUsage::new().server_auth().client_auth().build()
            .map_err(|e| format!("EKU: {}", e))?
    ).map_err(|e| format!("append EKU: {}", e))?;

    let mut san = SubjectAlternativeName::new();
    san.dns(domain);
    if domain.contains('.') {
        san.dns(&format!("*.{}", domain));
    }
    for ip in ips {
        san.ip(&ip.to_string());
    }

    // SAN + AKI + SKI all need the v3 context (which borrows the builder
    // immutably) — build them in a scope, then append after the borrow ends.
    let (san_ext, aki, ski) = {
        let ctx = b.x509v3_context(Some(&ca_cert), None);
        let san_ext = san.build(&ctx).map_err(|e| format!("SAN: {}", e))?;
        // keyid(false) = best-effort: include the issuer key id when the CA
        // has an SKI (it does), but don't hard-fail issuance if it ever doesn't.
        let aki = AuthorityKeyIdentifier::new().keyid(false).build(&ctx)
            .map_err(|e| format!("AKI: {}", e))?;
        let ski = SubjectKeyIdentifier::new().build(&ctx)
            .map_err(|e| format!("SKI: {}", e))?;
        (san_ext, aki, ski)
    };
    b.append_extension(san_ext).map_err(|e| format!("append SAN: {}", e))?;
    b.append_extension(aki).map_err(|e| format!("append AKI: {}", e))?;
    b.append_extension(ski).map_err(|e| format!("append SKI: {}", e))?;

    // Signed by the CA key — that's what makes it chain to the trusted root.
    b.sign(&ca_key, MessageDigest::sha256()).map_err(|e| format!("leaf sign: {}", e))?;
    let leaf = b.build();
    let cert_pem = leaf.to_pem().map_err(|e| format!("leaf to_pem: {}", e))?;
    let key_pem = pkey.private_key_to_pem_pkcs8().map_err(|e| format!("leaf key to_pem: {}", e))?;
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generating + signing certs needs no filesystem, so the pure builders
    // are testable directly. Disk paths (/etc/wolfstack) aren't writable in
    // CI, so those are exercised live elsewhere.
    #[test]
    fn build_ca_is_a_valid_self_signed_ca() {
        let (cert_pem, key_pem) = build_ca("TestLab").unwrap();
        let cert = openssl::x509::X509::from_pem(&cert_pem).unwrap();
        // Self-signed: subject == issuer.
        let subj = format!("{:?}", cert.subject_name());
        let iss = format!("{:?}", cert.issuer_name());
        assert_eq!(subj, iss, "root CA must be self-signed");
        // The key parses and matches.
        assert!(openssl::pkey::PKey::private_key_from_pem(&key_pem).is_ok());
        // Verifies against its own key (self-signed signature checks out).
        let pubkey = cert.public_key().unwrap();
        assert!(cert.verify(&pubkey).unwrap(), "CA self-signature must verify");
    }

    #[test]
    fn root_carries_ca_true() {
        let (cert_pem, _) = build_ca("TestLab").unwrap();
        let cert = openssl::x509::X509::from_pem(&cert_pem).unwrap();
        let txt = String::from_utf8_lossy(&cert.to_text().unwrap()).to_string();
        assert!(txt.contains("CA:TRUE"), "root must carry BasicConstraints CA:TRUE");
    }

    #[test]
    fn issued_leaf_chains_to_the_ca() {
        use openssl::stack::Stack;
        use openssl::x509::store::X509StoreBuilder;
        use openssl::x509::{X509, X509StoreContext};

        let (ca_cert_pem, ca_key_pem) = build_ca("TestLab").unwrap();
        let (leaf_pem, leaf_key_pem) =
            issue_leaf_signed(&ca_cert_pem, &ca_key_pem, "ai.home", &[]).unwrap();

        let ca = X509::from_pem(&ca_cert_pem).unwrap();
        let leaf = X509::from_pem(&leaf_pem).unwrap();

        // The leaf's private key is valid.
        assert!(openssl::pkey::PKey::private_key_from_pem(&leaf_key_pem).is_ok());

        // SAN must cover the domain AND the wildcard subtree.
        let txt = String::from_utf8_lossy(&leaf.to_text().unwrap()).to_string();
        assert!(txt.contains("DNS:ai.home"), "leaf SAN must include ai.home:\n{txt}");
        assert!(txt.contains("DNS:*.ai.home"), "leaf SAN must include *.ai.home:\n{txt}");
        assert!(!txt.contains("CA:TRUE"), "leaf must NOT be a CA");

        // THE proof: the leaf verifies against a trust store containing only
        // the CA — i.e. it chains to the root. This is what `openssl verify`
        // does, and what a browser does once the CA is in its trust store.
        let mut store_b = X509StoreBuilder::new().unwrap();
        store_b.add_cert(ca).unwrap();
        let store = store_b.build();
        let chain = Stack::new().unwrap();
        let mut ctx = X509StoreContext::new().unwrap();
        let verified = ctx.init(&store, &leaf, &chain, |c| c.verify_cert()).unwrap();
        assert!(verified, "issued leaf must verify against the local CA (chain to root)");
    }

    #[test]
    fn openssl_cli_verifies_the_chain() {
        // Independent cross-check with the `openssl verify` CLI — exactly what
        // an admin would run. Skips cleanly if the CLI isn't installed.
        use std::process::Command;
        let have_cli = Command::new("openssl").arg("version").output()
            .map(|o| o.status.success()).unwrap_or(false);
        if !have_cli {
            eprintln!("openssl CLI absent — skipping cross-check (library verify already covers this)");
            return;
        }
        let (ca_pem, ca_key) = build_ca("TestLab").unwrap();
        let (leaf_pem, _) = issue_leaf_signed(&ca_pem, &ca_key, "ai.home", &[]).unwrap();
        let dir = std::env::temp_dir().join(format!("wolfca-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_p = dir.join("ca.pem");
        let leaf_p = dir.join("leaf.pem");
        std::fs::write(&ca_p, &ca_pem).unwrap();
        std::fs::write(&leaf_p, &leaf_pem).unwrap();
        let out = Command::new("openssl")
            .arg("verify").arg("-CAfile").arg(&ca_p).arg(&leaf_p)
            .output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.status.success() && stdout.contains("OK"),
            "`openssl verify` must pass for the issued leaf — stdout={stdout} stderr={stderr}");
    }
}
