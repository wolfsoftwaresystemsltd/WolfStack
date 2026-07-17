// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Mutual-TLS (client-certificate) gate for the admin HTTPS listener.
//!
//! OFF by default. When enabled with a client-CA, the main admin listener
//! (8553) requests and verifies a client certificate. A browser/human request
//! must present a certificate signed by the operator's CA or it is refused —
//! this is a cryptographic "it's really me" gate at the transport layer, before
//! any login or handler runs, so a public `https://host:8553` URL becomes
//! usable only by the operator's own devices, from any location (the cert
//! travels with the device, not an IP).
//!
//! ## Why it doesn't break the cluster
//! Inter-node calls authenticate with the shared cluster secret
//! (`X-WolfStack-Secret`), not a client cert. The TLS layer only *requests*
//! the cert (SSL_VERIFY_PEER, NOT fail-if-absent), so a cert-less inter-node
//! connection still completes; the app-layer gate then lets a secret-authed
//! request through without a cert and requires a cert only for everything else
//! (browser/session access). Agents polling the manager keep working.
//!
//! ## Fail-safe
//! If enabled but the CA file is missing/unreadable, the gate does NOT
//! activate (the server logs an error and runs without mTLS) — a config typo
//! must never brick admin access. And because activation only happens at
//! startup, a lock-out is always recoverable over SSH: delete/disable the
//! config and restart.

use std::sync::atomic::{AtomicBool, Ordering};

/// Set true at startup only when mTLS is actually active (enabled + CA loaded).
/// The enforcement middleware reads this so it is a zero-cost no-op otherwise.
pub static MTLS_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn is_active() -> bool {
    MTLS_ACTIVE.load(Ordering::Relaxed)
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct MtlsConfig {
    /// Master switch. Default false — existing installs are unaffected.
    #[serde(default)]
    pub enabled: bool,
    /// Path to a PEM file holding the CA certificate(s) that sign the
    /// operator's client certificates. Client certs are verified against this.
    #[serde(default)]
    pub client_ca_path: String,
}

impl MtlsConfig {
    fn config_path() -> String {
        format!("{}/mtls.json", crate::paths::get().config_dir)
    }

    /// Load the config. mTLS is configured by writing this JSON file directly
    /// (a deliberate, SSH-side action — there is no UI toggle yet, which also
    /// makes an accidental self-lockout harder). Example:
    ///   {"enabled": true, "client_ca_path": "/etc/wolfstack/mtls-client-ca.pem"}
    pub fn load() -> Self {
        std::fs::read_to_string(Self::config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Returns the CA path to enforce with, but ONLY if mTLS is enabled AND the
    /// CA file exists and is non-empty. Returns None (fail-safe: no gate) for a
    /// disabled or misconfigured setup, so a typo can never lock the operator
    /// out — the alternative (requiring certs against a broken CA) would reject
    /// every client, valid cert included.
    pub fn active_ca(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let ca = self.client_ca_path.trim();
        if ca.is_empty() {
            return None;
        }
        match std::fs::metadata(ca) {
            Ok(m) if m.len() > 0 => Some(ca.to_string()),
            _ => {
                tracing::error!(
                    "mTLS is enabled but the client CA '{}' is missing or empty — \
                     running WITHOUT the client-certificate gate so admin access is \
                     not bricked. Fix the CA path (Settings → Security) and restart.",
                    ca
                );
                None
            }
        }
    }
}

/// Per-connection marker inserted by the HttpServer `on_connect` hook: true when
/// the peer presented a client certificate. With SSL_VERIFY_PEER (and no
/// fail-if-absent), an *invalid* cert already aborts the handshake, so a present
/// certificate here means a valid, CA-verified one.
#[derive(Clone, Copy)]
pub struct ClientCertPresented(pub bool);

/// Configure an OpenSSL acceptor to request + verify client certs against
/// `ca_path`. Verification is PEER (not FAIL_IF_NO_PEER_CERT) so cert-less
/// inter-node connections still complete for the app-layer gate to judge.
/// Returns Err (and the caller then runs WITHOUT mTLS) on any load failure.
pub fn apply_client_ca(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    ca_path: &str,
) -> Result<(), String> {
    use openssl::ssl::{SslVerifyMode};
    builder
        .set_ca_file(ca_path)
        .map_err(|e| format!("load client CA '{}': {}", ca_path, e))?;
    // Request a client cert and verify it if presented; do NOT require one at
    // the TLS layer (inter-node peers have none — the app gate handles them).
    builder.set_verify(SslVerifyMode::PEER);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, ca: &str) -> MtlsConfig {
        MtlsConfig { enabled, client_ca_path: ca.to_string() }
    }

    #[test]
    fn disabled_never_activates() {
        assert!(cfg(false, "/does/not/matter").active_ca().is_none());
        assert!(cfg(false, "").active_ca().is_none());
    }

    #[test]
    fn enabled_with_empty_ca_is_inactive() {
        assert!(cfg(true, "").active_ca().is_none());
        assert!(cfg(true, "   ").active_ca().is_none());
    }

    #[test]
    fn enabled_with_missing_ca_fails_safe_to_inactive() {
        // The critical safety property: a config typo (CA path that doesn't
        // exist) must NOT activate the gate — otherwise the acceptor would
        // require certs it can't verify and lock every client out.
        assert!(cfg(true, "/nonexistent/wolfstack-ca.pem").active_ca().is_none());
    }

    #[test]
    fn enabled_with_real_ca_activates_and_loads() {
        // Generate a throwaway CA and confirm active_ca() returns it AND that
        // apply_client_ca actually loads it into an OpenSSL acceptor.
        let dir = std::env::temp_dir().join(format!("wsmtls-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let ca_path = dir.join("ca.pem");
        let ok = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", dir.join("ca.key").to_str().unwrap(),
                "-out", ca_path.to_str().unwrap(),
                "-days", "1", "-subj", "/CN=WolfStack Test CA",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("openssl unavailable — skipping CA-load assertion");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let c = cfg(true, ca_path.to_str().unwrap());
        assert_eq!(c.active_ca().as_deref(), Some(ca_path.to_str().unwrap()),
            "enabled + present non-empty CA must activate");

        // apply_client_ca must load the real CA without error, and reject junk.
        use openssl::ssl::{SslAcceptor, SslMethod};
        let mut b = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        assert!(apply_client_ca(&mut b, ca_path.to_str().unwrap()).is_ok(),
            "loading a valid CA must succeed");
        let mut b2 = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        assert!(apply_client_ca(&mut b2, "/nonexistent/ca.pem").is_err(),
            "loading a missing CA must return Err (caller then runs without the gate)");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
