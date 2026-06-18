// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! OIDC (OpenID Connect) Authentication — Authorization Code Flow with PKCE.
//!
//! Implements manual OIDC discovery and token exchange using `reqwest`,
//! avoiding the heavy `openidconnect` crate dependency tree.
//! Secrets (client_secret) are encrypted at rest using AES-256-GCM
//! with keys derived from the cluster secret via HKDF.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Shared HTTP client for every OIDC discovery + token-exchange call.
/// Per-request timeouts set at each call site. Previously each
/// discovery and each token exchange built its own Client.
static OIDC_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

fn oidc_config_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/oidc.json", cfg)
}

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

/// Top-level OIDC configuration, persisted to /etc/wolfstack/oidc.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Whether OIDC login is enabled globally
    #[serde(default)]
    pub enabled: bool,
    /// Configured identity providers (Entra ID, Google, Keycloak, etc.)
    #[serde(default)]
    pub providers: Vec<OidcProvider>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: Vec::new(),
        }
    }
}

impl OidcConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(&oidc_config_path()) {
            Ok(data) => match serde_json::from_str(&data) {
                Ok(cfg) => cfg,
                Err(e) => {
                    // Never silently drop a corrupt config — that would hide the
                    // loss of every provider + its encrypted secret. Surface it
                    // loudly so the operator can fix/restore the file.
                    tracing::error!(
                        "OIDC config at {} failed to parse ({}) — using an empty config; configured SSO providers are unavailable until the file is fixed",
                        oidc_config_path(), e
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = oidc_config_path();
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // 0600 — this file embeds the OIDC client_secret (encrypted,
        // but still the encrypted blob — and other provider metadata
        // operators may not want world-readable).
        crate::paths::write_secure(&path, json)
            .map_err(|e| format!("Failed to write OIDC config: {}", e))
    }
}

/// A single OIDC identity provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProvider {
    /// Unique identifier for this provider (e.g. "entra", "google", "keycloak")
    pub id: String,
    /// Display name shown on the login page
    pub name: String,
    /// Issuer URL (e.g. "https://login.microsoftonline.com/{tenant}/v2.0")
    pub issuer_url: String,
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 client secret — stored encrypted at rest
    #[serde(default)]
    pub client_secret: String,
    /// Scopes to request (default: "openid profile email")
    #[serde(default = "default_scopes")]
    pub scopes: String,
    /// Claim path for determining the user's role (e.g. "groups", "realm_access.roles")
    #[serde(default)]
    pub role_claim: String,
    /// Role mappings — map claim values to WolfStack roles
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
    /// Whether this provider is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_scopes() -> String {
    "openid profile email".to_string()
}

fn default_true() -> bool {
    true
}

/// Maps an OIDC claim value to a WolfStack role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMapping {
    /// Values that grant admin access
    #[serde(default)]
    pub admin_values: Vec<String>,
    /// Values that grant viewer (read-only) access
    #[serde(default)]
    pub viewer_values: Vec<String>,
    /// Default role if no match ("viewer" or "admin")
    #[serde(default = "default_role")]
    pub default_role: String,
}

fn default_role() -> String {
    "viewer".to_string()
}

// ═══════════════════════════════════════════════
// ─── Pending OIDC Flow ───
// ═══════════════════════════════════════════════

/// Tracks an in-progress OIDC authorization flow (stored in memory, keyed by state)
#[derive(Debug, Clone)]
pub struct OidcPendingFlow {
    /// CSRF state parameter — random UUID sent in the auth URL
    pub csrf_state: String,
    /// Nonce — included in the ID token to prevent replay attacks
    pub nonce: String,
    /// PKCE code verifier — the original random secret (sent in token exchange)
    pub pkce_verifier: String,
    /// Which provider this flow belongs to
    pub provider_id: String,
    /// When this flow was initiated
    pub created_at: std::time::Instant,
}

// ═══════════════════════════════════════════════
// ─── Secret Encryption (AES-256-GCM) ───
// ═══════════════════════════════════════════════

/// Derive a 256-bit encryption key from the cluster secret using HKDF-SHA256.
fn derive_key(cluster_secret: &str) -> ring::aead::LessSafeKey {
    use ring::hkdf;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"wolfstack-oidc-secret-encryption");
    let prk = salt.extract(cluster_secret.as_bytes());
    let okm = prk
        .expand(&[b"oidc-client-secret"], &ring::aead::AES_256_GCM)
        .expect("HKDF expand failed");
    let mut key_bytes = [0u8; 32];
    okm.fill(&mut key_bytes).expect("HKDF fill failed");
    let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key_bytes)
        .expect("AES-256-GCM key creation failed");
    ring::aead::LessSafeKey::new(unbound)
}

/// Encrypt a secret using AES-256-GCM. Returns `"encrypted:aes256:base64(nonce||ciphertext)"`.
/// If the input is empty, returns it as-is.
pub fn encrypt_secret(plaintext: &str, cluster_secret: &str) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    // Already encrypted? Return unchanged.
    if plaintext.starts_with("encrypted:") {
        return Ok(plaintext.to_string());
    }

    let key = derive_key(cluster_secret);

    // Generate a random 96-bit (12-byte) nonce
    let mut nonce_bytes = [0u8; 12];
    read_urandom(&mut nonce_bytes)?;
    let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt in place — ring appends the 16-byte auth tag
    let mut in_out = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut in_out)
        .map_err(|e| format!("AES-256-GCM seal failed: {}", e))?;

    // Concatenate nonce || ciphertext+tag and base64 encode
    let mut combined = Vec::with_capacity(12 + in_out.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&in_out);

    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&combined);
    Ok(format!("encrypted:aes256:{}", encoded))
}

/// Decrypt a secret encrypted by `encrypt_secret()`. If the input doesn't start
/// with "encrypted:", it's treated as plaintext and returned as-is (migration path).
pub fn decrypt_secret(ciphertext: &str, cluster_secret: &str) -> Result<String, String> {
    if ciphertext.is_empty() {
        return Ok(String::new());
    }
    if !ciphertext.starts_with("encrypted:aes256:") {
        // Plaintext fallback — not yet encrypted
        return Ok(ciphertext.to_string());
    }

    let encoded = &ciphertext["encrypted:aes256:".len()..];
    use base64::Engine;
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    if combined.len() < 12 + 16 {
        return Err("Ciphertext too short (need at least nonce + auth tag)".to_string());
    }

    let key = derive_key(cluster_secret);
    let nonce = ring::aead::Nonce::assume_unique_for_key(
        combined[..12].try_into().map_err(|_| "Invalid nonce length")?,
    );
    let mut in_out = combined[12..].to_vec();
    let plaintext_bytes = key
        .open_in_place(nonce, ring::aead::Aad::empty(), &mut in_out)
        .map_err(|_| "AES-256-GCM decryption failed (wrong key or corrupted data)".to_string())?;

    String::from_utf8(plaintext_bytes.to_vec())
        .map_err(|e| format!("Decrypted secret is not valid UTF-8: {}", e))
}

/// Read random bytes from /dev/urandom
fn read_urandom(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut f =
        std::fs::File::open("/dev/urandom").map_err(|e| format!("Cannot open /dev/urandom: {}", e))?;
    f.read_exact(buf)
        .map_err(|e| format!("Cannot read /dev/urandom: {}", e))
}

// ═══════════════════════════════════════════════
// ─── OIDC Discovery & Auth URL ───
// ═══════════════════════════════════════════════

/// OIDC Discovery document (subset of fields we need)
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    #[allow(dead_code)]
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

/// Fetch the OIDC discovery document from the provider's well-known endpoint.
async fn discover(issuer_url: &str) -> Result<DiscoveryDocument, String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let resp = OIDC_CLIENT
        .get(&discovery_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("OIDC discovery request failed: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        // Drain body so socket returns to the pool.
        let _ = resp.bytes().await;
        return Err(format!("OIDC discovery returned HTTP {}", status.as_u16()));
    }

    resp.json::<DiscoveryDocument>()
        .await
        .map_err(|e| format!("Failed to parse OIDC discovery document: {}", e))
}

/// Probe an issuer's OIDC discovery document — backs the Settings → SSO "Test"
/// button so an operator can confirm the issuer URL is reachable and speaks
/// OIDC before saving. Returns the discovered authorization + token endpoints.
pub async fn probe_discovery(issuer_url: &str) -> Result<(String, String), String> {
    let d = discover(issuer_url).await?;
    Ok((d.authorization_endpoint, d.token_endpoint))
}

/// Generate a PKCE code verifier (32 random bytes, base64url-encoded without padding).
fn generate_pkce_verifier() -> Result<String, String> {
    let mut buf = [0u8; 32];
    read_urandom(&mut buf)?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// Compute the PKCE code challenge (SHA-256 of the verifier, base64url-encoded).
fn pkce_code_challenge(verifier: &str) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, verifier.as_bytes());
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Build the authorization URL for an OIDC provider.
///
/// Returns the full URL to redirect the user to, along with the pending flow state
/// that must be kept in memory until the callback arrives.
pub async fn build_auth_url(
    provider: &OidcProvider,
    redirect_uri_base: &str,
) -> Result<(String, OidcPendingFlow), String> {
    let discovery = discover(&provider.issuer_url).await?;

    let state = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let code_verifier = generate_pkce_verifier()?;
    let code_challenge = pkce_code_challenge(&code_verifier);

    let redirect_uri = format!(
        "{}/api/auth/oidc/callback",
        redirect_uri_base.trim_end_matches('/')
    );

    // Build the authorization URL with query parameters
    let params = [
        ("client_id", provider.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", provider.scopes.as_str()),
        ("state", state.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];

    let query_string: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let auth_url = format!("{}?{}", discovery.authorization_endpoint, query_string);

    let pending = OidcPendingFlow {
        csrf_state: state,
        nonce,
        pkce_verifier: code_verifier,
        provider_id: provider.id.clone(),
        created_at: std::time::Instant::now(),
    };

    Ok((auth_url, pending))
}

// ═══════════════════════════════════════════════
// ─── Token Exchange ───
// ═══════════════════════════════════════════════

/// Exchange an authorization code for ID token claims.
///
/// Performs the token exchange at the provider's token_endpoint, then
/// decodes the ID token (JWT) payload to extract claims. The ID token
/// signature is NOT verified here — the code exchange itself authenticates
/// the response (confidential client + PKCE + TLS).
pub async fn exchange_code(
    provider: &OidcProvider,
    code: &str,
    pending: &OidcPendingFlow,
    redirect_uri_base: &str,
    cluster_secret: &str,
) -> Result<serde_json::Value, String> {
    let discovery = discover(&provider.issuer_url).await?;

    let redirect_uri = format!(
        "{}/api/auth/oidc/callback",
        redirect_uri_base.trim_end_matches('/')
    );

    // Decrypt the client secret if it's encrypted at rest
    let client_secret = decrypt_secret(&provider.client_secret, cluster_secret)?;

    let params: HashMap<&str, &str> = HashMap::from([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code_verifier", pending.pkce_verifier.as_str()),
    ]);

    let resp = OIDC_CLIENT
        .post(&discovery.token_endpoint)
        .timeout(std::time::Duration::from_secs(15))
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Token exchange request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Token endpoint returned HTTP {}: {}",
            status, body
        ));
    }

    let token_response: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    let id_token = token_response
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "No id_token in token response".to_string())?;

    // Decode the JWT payload (middle segment) — base64url without signature verification.
    // Security note: we trust the token because it came from a direct HTTPS POST
    // to the token_endpoint with our client_secret and PKCE verifier.
    let claims = decode_jwt_payload(id_token)?;

    // Validate nonce to prevent token replay/substitution attacks
    let token_nonce = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if token_nonce != pending.nonce {
        return Err(format!(
            "OIDC nonce mismatch: expected '{}', got '{}' — possible token replay attack",
            pending.nonce, token_nonce
        ));
    }

    Ok(claims)
}

/// Decode the payload (claims) segment of a JWT without verifying the signature.
fn decode_jwt_payload(jwt: &str) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT: expected 3 dot-separated segments".to_string());
    }

    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| {
            // Some IdPs pad with '=' — try standard base64url with padding
            base64::engine::general_purpose::URL_SAFE.decode(parts[1])
        })
        .map_err(|e| format!("Failed to base64-decode JWT payload: {}", e))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Failed to parse JWT payload JSON: {}", e))
}

// ═══════════════════════════════════════════════
// ─── Claim-to-Role Mapping ───
// ═══════════════════════════════════════════════

/// Resolve a dotted claim path from JWT claims.
///
/// For example, `"realm_access.roles"` on the JSON:
/// ```json
/// { "realm_access": { "roles": ["admin", "user"] } }
/// ```
/// returns the `["admin", "user"]` Value.
fn resolve_claim_path<'a>(claims: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = claims;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Map JWT claims to a WolfStack role using the provider's role mappings.
///
/// Resolves the `role_claim` path from the claims, then checks each value
/// against the admin_values and viewer_values lists. Returns `"admin"`,
/// `"viewer"`, or the mapping's default_role.
pub fn map_claims_to_role(claims: &serde_json::Value, provider: &OidcProvider) -> String {
    if provider.role_claim.is_empty() || provider.role_mappings.is_empty() {
        return "viewer".to_string();
    }

    let claim_value = match resolve_claim_path(claims, &provider.role_claim) {
        Some(v) => v,
        None => {
            // Claim path not found — return the first mapping's default role
            return provider
                .role_mappings
                .first()
                .map(|m| m.default_role.clone())
                .unwrap_or_else(|| "viewer".to_string());
        }
    };

    // Collect the claim values into a list of strings for matching
    let claim_strings: Vec<String> = match claim_value {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => vec![claim_value.to_string()],
    };

    for mapping in &provider.role_mappings {
        for val in &claim_strings {
            if mapping.admin_values.contains(val) {
                return "admin".to_string();
            }
        }
        for val in &claim_strings {
            if mapping.viewer_values.contains(val) {
                return "viewer".to_string();
            }
        }
    }

    // No match — return default role from first mapping
    provider
        .role_mappings
        .first()
        .map(|m| m.default_role.clone())
        .unwrap_or_else(|| "viewer".to_string())
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider(role_claim: &str, admin_values: Vec<&str>, viewer_values: Vec<&str>) -> OidcProvider {
        OidcProvider {
            id: "test".to_string(),
            name: "Test Provider".to_string(),
            issuer_url: "https://example.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: String::new(),
            scopes: "openid profile email".to_string(),
            role_claim: role_claim.to_string(),
            role_mappings: vec![RoleMapping {
                admin_values: admin_values.into_iter().map(|s| s.to_string()).collect(),
                viewer_values: viewer_values.into_iter().map(|s| s.to_string()).collect(),
                default_role: "viewer".to_string(),
            }],
            enabled: true,
        }
    }

    #[test]
    fn test_map_claims_groups_array_admin() {
        let claims = serde_json::json!({
            "sub": "user123",
            "groups": ["developers", "wolfstack-admins", "everyone"]
        });
        let provider = test_provider("groups", vec!["wolfstack-admins"], vec!["wolfstack-viewers"]);
        assert_eq!(map_claims_to_role(&claims, &provider), "admin");
    }

    #[test]
    fn test_map_claims_groups_array_viewer() {
        let claims = serde_json::json!({
            "sub": "user123",
            "groups": ["developers", "wolfstack-viewers", "everyone"]
        });
        let provider = test_provider("groups", vec!["wolfstack-admins"], vec!["wolfstack-viewers"]);
        assert_eq!(map_claims_to_role(&claims, &provider), "viewer");
    }

    #[test]
    fn test_map_claims_groups_array_no_match() {
        let claims = serde_json::json!({
            "sub": "user123",
            "groups": ["developers", "everyone"]
        });
        let provider = test_provider("groups", vec!["wolfstack-admins"], vec!["wolfstack-viewers"]);
        // No match — falls through to default_role
        assert_eq!(map_claims_to_role(&claims, &provider), "viewer");
    }

    #[test]
    fn test_map_claims_single_string() {
        let claims = serde_json::json!({
            "sub": "user123",
            "role": "admin"
        });
        let provider = test_provider("role", vec!["admin"], vec!["viewer"]);
        assert_eq!(map_claims_to_role(&claims, &provider), "admin");
    }

    #[test]
    fn test_map_claims_nested_path() {
        let claims = serde_json::json!({
            "sub": "user123",
            "realm_access": {
                "roles": ["offline_access", "uma_authorization", "wolfstack-admin"]
            }
        });
        let provider = test_provider(
            "realm_access.roles",
            vec!["wolfstack-admin"],
            vec!["wolfstack-viewer"],
        );
        assert_eq!(map_claims_to_role(&claims, &provider), "admin");
    }

    #[test]
    fn test_map_claims_missing_claim_path() {
        let claims = serde_json::json!({
            "sub": "user123"
        });
        let provider = test_provider("groups", vec!["admin"], vec!["viewer"]);
        // Claim not present — falls back to default_role
        assert_eq!(map_claims_to_role(&claims, &provider), "viewer");
    }

    #[test]
    fn test_map_claims_empty_role_claim() {
        let claims = serde_json::json!({
            "sub": "user123",
            "groups": ["admin"]
        });
        let provider = test_provider("", vec!["admin"], vec!["viewer"]);
        // Empty role_claim — returns viewer
        assert_eq!(map_claims_to_role(&claims, &provider), "viewer");
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let secret = "my-super-secret-client-password";
        let cluster_key = "wsk_test1234567890abcdef";

        let encrypted = encrypt_secret(secret, cluster_key).expect("encrypt should succeed");
        assert!(encrypted.starts_with("encrypted:aes256:"), "should have encrypted prefix");
        assert_ne!(encrypted, secret, "encrypted should differ from plaintext");

        let decrypted = decrypt_secret(&encrypted, cluster_key).expect("decrypt should succeed");
        assert_eq!(decrypted, secret, "round-trip should recover original secret");
    }

    #[test]
    fn test_encrypt_empty_string() {
        let result = encrypt_secret("", "key").expect("should succeed");
        assert_eq!(result, "", "empty input returns empty output");
    }

    #[test]
    fn test_decrypt_plaintext_fallback() {
        // Not encrypted — should return as-is
        let result = decrypt_secret("plain-secret", "key").expect("should succeed");
        assert_eq!(result, "plain-secret");
    }

    #[test]
    fn test_encrypt_already_encrypted() {
        // Already has the prefix — should return unchanged
        let already = "encrypted:aes256:AAAA";
        let result = encrypt_secret(already, "key").expect("should succeed");
        assert_eq!(result, already);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let encrypted =
            encrypt_secret("my-secret", "correct-key").expect("encrypt should succeed");
        let result = decrypt_secret(&encrypted, "wrong-key");
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn test_pkce_challenge_is_base64url_sha256() {
        // Known test vector: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // has SHA-256 = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM (RFC 7636 Appendix B)
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_code_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_decode_jwt_payload() {
        // Build a minimal JWT: header.payload.signature
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload_json = serde_json::json!({
            "sub": "user123",
            "email": "user@example.com",
            "nonce": "abc123"
        });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(payload_json.to_string().as_bytes());
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"fake-sig");

        let jwt = format!("{}.{}.{}", header, payload, signature);
        let claims = decode_jwt_payload(&jwt).expect("should decode");
        assert_eq!(claims["sub"], "user123");
        assert_eq!(claims["email"], "user@example.com");
    }
}
