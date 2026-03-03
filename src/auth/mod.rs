// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Authentication — Linux system user authentication via crypt()
//!
//! Authenticates against /etc/shadow using the system's crypt() function.
//! WolfStack must run as root to read /etc/shadow.
//!
//! Cluster-internal requests are authenticated via a shared secret. By default
//! all installations share a built-in secret. Users can generate a custom
//! per-cluster secret via the Settings → Security tab; the custom secret is
//! stored in /etc/wolfstack/cluster-secret and propagated to all nodes.
//! The built-in default is always accepted as a fallback so mixed clusters
//! (some upgraded, some not) continue to work.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::warn;

/// Session token lifetime (8 hours)
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Maximum failed login attempts per IP before lockout
const MAX_LOGIN_ATTEMPTS: u32 = 10;
/// Lockout window — failed attempts are counted within this period
const LOGIN_LOCKOUT_WINDOW: Duration = Duration::from_secs(300); // 5 minutes

/// Built-in cluster secret shared by all WolfStack installations.
const CLUSTER_SECRET: &str = "wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3";

/// Get the built-in default cluster secret (always accepted as fallback)
pub fn default_cluster_secret() -> &'static str {
    CLUSTER_SECRET
}

/// Path for user-generated custom cluster secrets (via Settings → Security).
/// Note: /etc/wolfstack/cluster-secret may contain leftover per-installation
/// secrets from v11.26.3 — we deliberately use a different path to avoid loading those.
const CUSTOM_SECRET_PATH: &str = "/etc/wolfstack/custom-cluster-secret";

/// Load the active cluster secret — custom from file if present, otherwise the built-in default
pub fn load_cluster_secret() -> String {
    let path = std::path::Path::new(CUSTOM_SECRET_PATH);
    if let Ok(secret) = std::fs::read_to_string(path) {
        let secret = secret.trim().to_string();
        if !secret.is_empty() {
            return secret;
        }
    }
    CLUSTER_SECRET.to_string()
}

/// Generate a new random cluster secret (wsk_ prefix + 64 hex chars)
pub fn generate_cluster_secret() -> String {
    use std::fmt::Write;
    let mut secret = String::from("wsk_");
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    for b in &buf {
        let _ = write!(secret, "{:02x}", b);
    }
    secret
}

/// Save a cluster secret to the custom secret file
pub fn save_cluster_secret(secret: &str) -> Result<(), String> {
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    std::fs::write(CUSTOM_SECRET_PATH, secret)
        .map_err(|e| format!("Cannot write custom-cluster-secret: {}", e))
}

/// Validate a cluster secret from a request header
pub fn validate_cluster_secret(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    // Constant-time comparison to prevent timing attacks
    provided.len() == expected.len()
        && provided.as_bytes().iter().zip(expected.as_bytes().iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

// Link against libcrypt for password verification
#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Active session
struct Session {
    username: String,
    created: Instant,
}

/// Session manager
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Session>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session for a user, returns the session token
    pub fn create_session(&self, username: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(token.clone(), Session {
            username: username.to_string(),
            created: Instant::now(),
        });

        token
    }

    /// Validate a session token, returns the username if valid
    pub fn validate(&self, token: &str) -> Option<String> {
        let sessions = self.sessions.read().unwrap();
        if let Some(session) = sessions.get(token) {
            if session.created.elapsed() < SESSION_LIFETIME {
                return Some(session.username.clone());
            }
        }
        None
    }

    /// Destroy a session
    pub fn destroy(&self, token: &str) {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(_session) = sessions.remove(token) {

        }
    }

    /// Clean up expired sessions
    pub fn cleanup(&self) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, s| s.created.elapsed() < SESSION_LIFETIME);
    }
}

/// Authenticate a user against the Linux system (/etc/shadow)
pub fn authenticate_user(username: &str, password: &str) -> bool {
    // Validate inputs
    if username.is_empty() || password.is_empty() {
        return false;
    }

    // Prevent path traversal and injection
    if username.contains(':') || username.contains('/') || username.contains('\0') {
        warn!("Invalid username characters in login attempt");
        return false;
    }

    // Read /etc/shadow (requires root)
    let shadow = match std::fs::read_to_string("/etc/shadow") {
        Ok(s) => s,
        Err(e) => {
            warn!("Cannot read /etc/shadow: {} — WolfStack must run as root", e);
            return false;
        }
    };

    for line in shadow.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 2 {
            continue;
        }

        if parts[0] != username {
            continue;
        }

        let stored_hash = parts[1];

        // Skip locked/disabled accounts
        if stored_hash.is_empty() || stored_hash == "!" || stored_hash == "*"
            || stored_hash == "!!" || stored_hash.starts_with('!')
        {
            warn!("Login attempt for locked account '{}'", username);
            return false;
        }

        // Use crypt() to verify password
        match verify_password(password, stored_hash) {
            true => {

                return true;
            }
            false => {
                warn!("Failed login attempt for user '{}'", username);
                return false;
            }
        }
    }

    warn!("Login attempt for unknown user '{}'", username);
    false
}

/// Verify a password against a stored hash using crypt()
fn verify_password(password: &str, stored_hash: &str) -> bool {
    let c_password = match std::ffi::CString::new(password) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let c_salt = match std::ffi::CString::new(stored_hash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe {
        let result = crypt(c_password.as_ptr(), c_salt.as_ptr());
        if result.is_null() {
            return false;
        }
        let result_str = std::ffi::CStr::from_ptr(result).to_string_lossy();
        result_str == stored_hash
    }
}

/// IP-based login rate limiter to prevent brute-force attacks
pub struct LoginRateLimiter {
    attempts: RwLock<HashMap<String, Vec<Instant>>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
        }
    }

    /// Record a failed login attempt for an IP. Returns true if the IP is now locked out.
    pub fn record_failure(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();
        let now = Instant::now();
        // Prune old entries outside the window
        entry.retain(|t| now.duration_since(*t) < LOGIN_LOCKOUT_WINDOW);
        entry.push(now);
        entry.len() >= MAX_LOGIN_ATTEMPTS as usize
    }

    /// Check if an IP is currently locked out (too many recent failures)
    pub fn is_locked_out(&self, ip: &str) -> bool {
        let attempts = self.attempts.read().unwrap();
        if let Some(entry) = attempts.get(ip) {
            let now = Instant::now();
            let recent = entry.iter().filter(|t| now.duration_since(**t) < LOGIN_LOCKOUT_WINDOW).count();
            recent >= MAX_LOGIN_ATTEMPTS as usize
        } else {
            false
        }
    }

    /// Clear failures for an IP (called on successful login)
    pub fn clear(&self, ip: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(ip);
    }

    /// Periodic cleanup of expired entries
    pub fn cleanup(&self) {
        let mut attempts = self.attempts.write().unwrap();
        let now = Instant::now();
        attempts.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < LOGIN_LOCKOUT_WINDOW);
            !entries.is_empty()
        });
    }
}

/// Validate a container/VM name — only allow safe characters (alphanumeric, dash, underscore, dot)
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}
