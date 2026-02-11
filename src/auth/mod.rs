//! Authentication — Linux system user authentication via crypt()
//!
//! Authenticates against /etc/shadow using the system's crypt() function.
//! WolfStack must run as root to read /etc/shadow.
//!
//! Cluster-internal requests are authenticated via a shared secret stored
//! in /etc/wolfstack/cluster.key (auto-generated on first run).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Session token lifetime (8 hours)
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Path to the cluster secret key
const CLUSTER_KEY_PATH: &str = "/etc/wolfstack/cluster.key";

/// Load or generate the cluster secret for inter-node authentication
pub fn load_cluster_secret() -> String {
    // Try to read existing key
    if let Ok(key) = std::fs::read_to_string(CLUSTER_KEY_PATH) {
        let key = key.trim().to_string();
        if key.len() >= 32 {
            return key;
        }
    }

    // Generate new key
    let key = uuid::Uuid::new_v4().to_string().replace('-', "")
        + &uuid::Uuid::new_v4().to_string().replace('-', "");

    // Ensure directory exists
    let _ = std::fs::create_dir_all("/etc/wolfstack");

    // Write key with restrictive permissions
    if let Err(e) = std::fs::write(CLUSTER_KEY_PATH, &key) {
        warn!("Failed to write cluster key: {} — inter-node auth will not persist across restarts", e);
        return key;
    }

    // chmod 600
    let _ = std::process::Command::new("chmod")
        .args(["600", CLUSTER_KEY_PATH])
        .output();

    info!("Generated new cluster secret at {}", CLUSTER_KEY_PATH);
    key
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
extern "C" {
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
        info!("Session created for user '{}'", username);
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
        if let Some(session) = sessions.remove(token) {
            info!("Session destroyed for user '{}'", session.username);
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
                info!("Successful login for user '{}'", username);
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
