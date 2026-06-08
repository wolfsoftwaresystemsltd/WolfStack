// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

// Authentication — Linux system user authentication via crypt(),
// with optional WolfStack user accounts and TOTP two-factor authentication.

pub mod users;
#[allow(dead_code)]
pub mod oidc;
#[allow(dead_code)]
pub mod webauthn;
pub mod log_monitor;

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::warn;

/// Session token lifetime (8 hours)
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);

// Old static MAX_LOGIN_ATTEMPTS / LOGIN_LOCKOUT_WINDOW constants were
// removed when the lockout system became operator-configurable.
// See `LoginLockoutConfig` for the per-policy fields.

/// Built-in cluster secret shared by all WolfStack installations.
const CLUSTER_SECRET: &str = "wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3";

/// Get the built-in default cluster secret (always accepted as fallback)
pub fn default_cluster_secret() -> &'static str {
    CLUSTER_SECRET
}

/// Path for user-generated custom cluster secrets (via Settings → Security).
/// Note: /etc/wolfstack/cluster-secret may contain leftover per-installation
/// secrets from v11.26.3 — we deliberately use a different path to avoid loading those.
fn custom_secret_path() -> String { crate::paths::get().cluster_secret }

/// Load the active cluster secret — custom from file if present, otherwise the built-in default
pub fn load_cluster_secret() -> String {
    let path_str = custom_secret_path();
    let path = std::path::Path::new(&path_str);
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

/// Save a cluster secret to the custom secret file. Written with mode
/// 0600 — the secret is the cluster's inter-node auth token, so any
/// non-root reader can impersonate a cluster member. Pre-v18.7.27 this
/// used `std::fs::write` which inherited the process umask (usually
/// 022 → 0644) and made the secret world-readable.
pub fn save_cluster_secret(secret: &str) -> Result<(), String> {
    let path = custom_secret_path();
    crate::paths::write_secure(&path, secret)
        .map_err(|e| format!("Cannot write custom-cluster-secret: {}", e))
}

/// Stage 2 of the cluster-secret migration: on a FRESH install (no
/// custom-secret file AND no peers configured), generate a fresh
/// per-install secret instead of inheriting the built-in default
/// shared by every WolfStack on Earth.
///
/// SAFETY — this MUST be called only when both conditions hold:
///   1. `custom_secret_path()` does not exist
///   2. No peers are recorded in nodes.json (single-node install)
///
/// Either condition false → existing install → do nothing, never
/// rotate behind the operator's back. Stage 3 (operator-triggered
/// coordinated rotation) is the supported path for existing clusters.
///
/// Returns `Some(new_secret)` on a fresh-install generation,
/// `None` if conditions aren't met or generation/save failed.
/// On generation, emits a loud INFO log so the operator can copy
/// the value to a password manager.
pub fn auto_generate_for_fresh_install() -> Option<String> {
    let path = custom_secret_path();
    if std::path::Path::new(&path).exists() { return None; }

    // Check for peers in nodes.json — if any exist, this is NOT a
    // fresh install (someone is rejoining, restoring from backup, or
    // running on a host whose old custom-secret was deleted but the
    // peer list survived). Refuse to auto-generate.
    //
    // W1 fix: if nodes.json exists but is unreadable, corrupted, or
    // contains anything we can't recognise as "empty", treat it as
    // "existing install" and refuse — the safe direction. Log a
    // warning so operators with a corrupted file see why the auto-gen
    // didn't fire (otherwise they'd silently keep running on the
    // default secret).
    let nodes_path = crate::paths::get().nodes_config;
    if std::path::Path::new(&nodes_path).exists() {
        match std::fs::read_to_string(&nodes_path) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if !trimmed.is_empty() && trimmed != "[]" && trimmed != "{}" {
                    return None;
                }
            }
            Err(e) => {
                tracing::warn!(target: "cluster_secret",
                    "fresh-install auto-gen skipped: cannot read {} ({}). \
                     If this is a fresh install, fix file perms and restart.",
                    nodes_path, e);
                return None;
            }
        }
    }

    let new_secret = generate_cluster_secret();
    if save_cluster_secret(&new_secret).is_err() {
        // Non-fatal: caller can still proceed with the built-in default.
        // We don't want a fresh-install failure here to break startup.
        return None;
    }
    // Keep /etc/wolfusb/wolfusb.env aligned. The install script writes
    // it with the hardcoded default BEFORE the daemon ever starts (so
    // it can't see our soon-to-be-generated per-install secret). If we
    // don't update it here, the external wolfusb daemon will run with
    // the default and our in-process wolfusb module will run with the
    // new per-install — they'll reject each other's auth headers.
    // Best-effort; failure here doesn't block startup.
    let _ = realign_wolfusb_env(&new_secret);
    // H1 fix: only log a fingerprint, never the secret bytes themselves.
    // journald is readable by anyone in the systemd-journal group on
    // most distros — a full secret in the log is an immediate exfil
    // path. Operators retrieve the full value from the 0600 file at
    // `path` or via Settings → Security in the UI.
    let masked = mask_secret_for_log(&new_secret);
    tracing::warn!(target: "cluster_secret",
        "Fresh-install cluster secret generated and saved to {} \
         (mode 0600). Fingerprint: {}. Retrieve the full value from \
         that file (sudo cat) before adding peer nodes — peers must \
         present the same secret to authenticate inter-node calls.",
        path, masked);
    Some(new_secret)
}

/// Print a short, log-safe fingerprint of a cluster secret: prefix +
/// first 6 chars after the `wsk_` + `…` + last 4. Enough for an
/// operator to confirm "is this the value I'm holding" without
/// committing the secret to journald.
fn mask_secret_for_log(s: &str) -> String {
    if s.len() < 14 { return "(too short to mask)".into(); }
    let head: String = s.chars().take(10).collect();   // "wsk_xxxxxx"
    let tail: String = s.chars().rev().take(4).collect::<Vec<_>>()
        .into_iter().rev().collect();
    format!("{}…{}", head, tail)
}

/// H5 — public wrapper used by Stage 3 coordinated rotation. After
/// any rotation that changes the on-disk cluster secret, the external
/// wolfusb daemon's WOLFUSB_KEY must be updated too — otherwise our
/// in-process wolfusb module (using the new cluster_secret) and the
/// external daemon (using the old env value) reject each other.
/// Best-effort; logs but does not fail on errors.
///
/// Also signals systemd to restart wolfusb.service so the daemon picks
/// up the new key without waiting for the next manual restart. Silent
/// no-op if systemctl / the service unit isn't present (e.g. fresh
/// install where setup.sh hasn't installed wolfusb yet).
pub fn realign_wolfusb_env_after_rotation(new_secret: &str) {
    if new_secret.is_empty() { return; }
    match realign_wolfusb_env(new_secret) {
        Ok(()) => {
            // C2 fix: dispatch the systemctl restart on a blocking
            // pool thread instead of synchronously on the caller —
            // this is called from actix request handlers and a
            // systemctl fork/exec under dbus pressure can block for
            // seconds. `--no-block` only stops systemd waiting on the
            // unit's startup; the spawn/exec itself is still
            // synchronous. tokio::spawn keeps the call off the actix
            // worker thread; the result is discarded (best-effort).
            // We also try to detect tokio runtime presence so the
            // helper stays callable from non-async contexts (init
            // paths, future CLI tools).
            let restart = || {
                let _ = std::process::Command::new("systemctl")
                    .args(["restart", "--no-block", "wolfusb.service"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            };
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => { handle.spawn_blocking(restart); }
                Err(_) => { std::thread::spawn(restart); }
            }
        }
        Err(e) => tracing::warn!(target: "cluster_secret",
            "failed to realign /etc/wolfusb/wolfusb.env after rotation ({}); \
             you may need to update WOLFUSB_KEY by hand and restart wolfusb.service",
            e),
    }
}

/// Update `/etc/wolfusb/wolfusb.env`'s `WOLFUSB_KEY=` line in place
/// without touching the rest of the file (preserves any operator
/// edits to bind / port). No-ops silently if the file isn't there.
fn realign_wolfusb_env(new_secret: &str) -> Result<(), std::io::Error> {
    let path = "/etc/wolfusb/wolfusb.env";
    if !std::path::Path::new(path).exists() { return Ok(()); }
    let body = std::fs::read_to_string(path)?;
    let mut out = String::with_capacity(body.len());
    let mut replaced = false;
    for line in body.lines() {
        if line.starts_with("WOLFUSB_KEY=") {
            out.push_str("WOLFUSB_KEY=");
            out.push_str(new_secret);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str("WOLFUSB_KEY=");
        out.push_str(new_secret);
        out.push('\n');
    }
    // Reuse the project's atomic 0600 writer so a partial write
    // can't leave the file truncated.
    crate::paths::write_secure(path, out)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

/// Stage 5 of the cluster-secret migration: is the built-in default
/// secret currently accepted as a valid inter-node auth value?
///
/// Default (in this release): **YES, accept**. Shipping the binary
/// must not break any existing install. Operators opt INTO rejection
/// by setting `WOLFSTACK_REJECT_DEFAULT_SECRET=1` in the environment.
///
/// A future release flips the default to "reject" with an opt-OUT
/// flag (`WOLFSTACK_ACCEPT_DEFAULT_SECRET=1`) for any install that
/// hasn't migrated by then. The escape hatch is permanent so ops
/// support can recover a broken upgrade by setting the variable
/// without an emergency hotfix release.
pub fn default_secret_accepted() -> bool {
    // Explicit reject takes priority — operators who set this WANT
    // the default rejected even if a future release flips the
    // overall default to "reject".
    if std::env::var("WOLFSTACK_REJECT_DEFAULT_SECRET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    // For now: accept by default. The opt-out env flag is here so
    // operators who've migrated their cluster can lock the door
    // behind them without waiting for a future release.
    true
}

/// Authenticate a presented `X-WolfStack-Secret` header value against
/// every acceptance path used by inter-node auth:
///   1. The in-memory secret from process start (`state.cluster_secret`)
///   2. The current on-disk secret (re-read every call so a Stage 3
///      .pending → active commit is picked up without restart)
///   3. The hardcoded built-in default — ONLY if Stage 5 still allows it
///      (operators can opt out via `WOLFSTACK_REJECT_DEFAULT_SECRET=1`)
///
/// Use this from every endpoint that authenticates by cluster secret —
/// the alternative is bespoke three-line checks at every call site, which
/// is how the Stage 5 review found 13+ endpoints accepting the default
/// unconditionally even when the operator had opted out.
///
/// Constant-time per-comparison via `validate_cluster_secret`. The
/// overall function short-circuits on success (`||` chain), which is
/// fine: an attacker learns nothing useful from "which of the three
/// values matched" because the three valid values are equally
/// authoritative.
pub fn validate_inter_node_secret(provided: &str, in_memory: &str) -> bool {
    if validate_cluster_secret(provided, in_memory) { return true; }
    if validate_cluster_secret(provided, &load_cluster_secret()) { return true; }
    if default_secret_accepted()
        && validate_cluster_secret(provided, default_cluster_secret())
    {
        return true;
    }
    false
}

/// Validate a cluster secret from a request header.
///
/// True constant-time comparison: the pre-v18.7.30 implementation had
/// an early-exit on length mismatch which leaked the secret's length
/// via timing. Now we fold the length difference into the accumulator
/// so the running time depends only on the longer of the two inputs.
pub fn validate_cluster_secret(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    // Mix the length difference into the accumulator by OR-ing every
    // byte of the XOR — this folds len-mismatch into the result
    // without a narrow u8 cast (which would alias 256-byte-apart
    // lengths to "equal"). Then walk both inputs in full by reading
    // zero for out-of-bounds indices.
    let len_diff_bytes = ((a.len() as u64) ^ (b.len() as u64)).to_le_bytes();
    let mut acc: u8 = len_diff_bytes.iter().fold(0u8, |x, b| x | *b);
    let max = a.len().max(b.len());
    for i in 0..max {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        acc |= x ^ y;
    }
    acc == 0
}

// Pure-Rust password hashing (replaces C libcrypt dependency)

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

    /// Destroy every active session. Used by the fleet-wide
    /// force-logout — operator wants to invalidate suspected stolen
    /// cookies. Every user has to re-authenticate after this.
    pub fn destroy_all(&self) {
        let mut sessions = self.sessions.write().unwrap();
        let n = sessions.len();
        sessions.clear();
        tracing::warn!("auth: destroyed {} active session(s) (force-logout)", n);
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

/// Verify a password against a stored hash.
/// Uses native C crypt() via dlopen when available, with pure-Rust fallback
/// for yescrypt ($y$), SHA-512 ($6$), and SHA-256 ($5$).
fn verify_password(password: &str, stored_hash: &str) -> bool {
    // Try native C crypt() first — handles all formats
    if let Some(result) = native_crypt(password, stored_hash) {
        use subtle::ConstantTimeEq;
        return result.as_bytes().ct_eq(stored_hash.as_bytes()).into();
    }
    // Fallback: pure Rust (needed for statically-linked / musl builds)
    if stored_hash.starts_with("$y$") {
        use yescrypt::Yescrypt;
        use yescrypt::password_hash::PasswordVerifier;
        return Yescrypt::default().verify_password(password.as_bytes(), stored_hash).is_ok();
    } else if stored_hash.starts_with("$6$") {
        sha_crypt::sha512_check(password, stored_hash).is_ok()
    } else if stored_hash.starts_with("$5$") {
        sha_crypt::sha256_check(password, stored_hash).is_ok()
    } else {
        false
    }
}

/// Try to call crypt() by dynamically loading libcrypt.so at runtime.
/// Returns None if libcrypt is not available (e.g. minimal Debian ISO).
fn native_crypt(password: &str, salt: &str) -> Option<String> {
    use std::ffi::{CStr, CString};
    let c_password = CString::new(password).ok()?;
    let c_salt = CString::new(salt).ok()?;
    unsafe {
        // Try libcrypt.so.2 (Arch/Fedora), then libcrypt.so.1 (Debian/Ubuntu)
        let lib = libc::dlopen(b"libcrypt.so.2\0".as_ptr() as *const _, libc::RTLD_NOW);
        let lib = if lib.is_null() {
            libc::dlopen(b"libcrypt.so.1\0".as_ptr() as *const _, libc::RTLD_NOW)
        } else {
            lib
        };
        if lib.is_null() {
            return None;
        }
        let sym = libc::dlsym(lib, b"crypt\0".as_ptr() as *const _);
        if sym.is_null() {
            libc::dlclose(lib);
            return None;
        }
        let crypt_fn: extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::c_char =
            std::mem::transmute(sym);
        let result = crypt_fn(c_password.as_ptr(), c_salt.as_ptr());
        let ret = if result.is_null() {
            None
        } else {
            Some(CStr::from_ptr(result).to_string_lossy().to_string())
        };
        libc::dlclose(lib);
        ret
    }
}

/// Operator-tunable lockout policy. Defaults are aggressive — designed
/// for fleets that are exposed to the public internet. An attacker who
/// learns one root password can try at most `max_failures` times in any
/// `window_seconds` rolling window before being hard-blocked for
/// `lockout_seconds`. 10 attempts and 48-hour blocks make typical
/// password-spray attacks economically impossible.
///
/// The operator can adjust any of these via the Security settings UI
/// or by editing `/etc/wolfstack/auth-lockout.json` directly. Trusted
/// IPs / CIDRs bypass the lockout entirely so the operator can never
/// lock themselves out from their own networks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginLockoutConfig {
    /// How many failures within the detection window trigger a hard lockout.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    /// Sliding window for counting failures (seconds).
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    /// Hard lockout duration once `max_failures` is hit (seconds).
    /// Default: 48 hours. The operator chose this — appropriate when
    /// the threat model is "real attacker with leaked credentials".
    #[serde(default = "default_lockout_seconds")]
    pub lockout_seconds: u64,
    /// IPs or CIDRs that bypass the lockout entirely. Examples:
    /// `192.168.1.5`, `192.168.0.0/24`, `2a01:4f8:151:7225::/64`.
    /// IPv4 and IPv6 supported.
    #[serde(default)]
    pub trusted_ips: Vec<String>,
    /// Master switch. If false, no lockout is applied at all (useful
    /// for debugging — NOT recommended for production).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

// 3 failures in 5 minutes from a single IP triggers a 48-hour kernel
// block. Aggressive default because in practice every brute-forcer
// hits one of:
//   - sshd:     Failed password / Invalid user
//   - pveproxy: authentication failure
//   - wolfstack: failed login on 8553
// and all three feed the same limiter (see log_monitor.rs). Three
// failures gives a legitimate fat-finger user one mistyped password
// + two retries before they're locked out; anything more rapid is
// automated scanning.
fn default_max_failures() -> u32 { 3 }
fn default_window_seconds() -> u64 { 300 }
fn default_lockout_seconds() -> u64 { 48 * 3600 }  // 48 hours
fn default_enabled() -> bool { true }

impl Default for LoginLockoutConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            window_seconds: default_window_seconds(),
            lockout_seconds: default_lockout_seconds(),
            trusted_ips: Vec::new(),
            enabled: default_enabled(),
        }
    }
}

impl LoginLockoutConfig {
    fn config_path() -> String {
        format!("{}/auth-lockout.json", crate::paths::get().config_dir)
    }
    pub fn load() -> Self {
        let mut cfg: Self = std::fs::read_to_string(Self::config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        // One-time migration: pre-v23.12.13 default was max_failures=10.
        // v23.12.13 tightened to 3. If the saved value is the old
        // default exactly, treat it as "operator never tuned this" and
        // bring it down to the new default. An operator who actually
        // wants 10 can re-save the policy from the UI; their explicit
        // value is preserved on every subsequent load.
        if cfg.max_failures == 10 {
            tracing::info!(
                "auth-lockout: migrating max_failures 10 -> 3 (post-v23.12.13 default). \
                 To restore the older threshold, save the policy form with the value you want."
            );
            cfg.max_failures = 3;
            let _ = cfg.save();
        }
        cfg
    }
    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("save lockout config: {}", e))
    }
    /// True if `ip` matches any trusted entry. Single-IP and CIDR forms
    /// supported; malformed entries are silently ignored (operator
    /// typos in the file shouldn't lock them out).
    pub fn is_trusted(&self, ip: &str) -> bool {
        let target: std::net::IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        for entry in &self.trusted_ips {
            // CIDR?
            if let Some((net_str, prefix_str)) = entry.split_once('/') {
                let net: std::net::IpAddr = match net_str.parse() { Ok(a) => a, Err(_) => continue };
                let prefix: u8 = match prefix_str.parse() { Ok(p) => p, Err(_) => continue };
                if ip_in_cidr(&target, &net, prefix) { return true; }
            } else if let Ok(parsed) = entry.parse::<std::net::IpAddr>() {
                if parsed == target { return true; }
            }
        }
        false
    }
}

fn ip_in_cidr(target: &std::net::IpAddr, net: &std::net::IpAddr, prefix: u8) -> bool {
    match (target, net) {
        (std::net::IpAddr::V4(t), std::net::IpAddr::V4(n)) => {
            if prefix > 32 { return false; }
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            (u32::from(*t) & mask) == (u32::from(*n) & mask)
        }
        (std::net::IpAddr::V6(t), std::net::IpAddr::V6(n)) => {
            if prefix > 128 { return false; }
            let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
            (u128::from(*t) & mask) == (u128::from(*n) & mask)
        }
        _ => false,
    }
}

/// Per-IP record. `failures` is the sliding-window count; `locked_until`
/// is the hard-block expiry (only set once the threshold is hit). The
/// two are independent: a slow trickle of failures never hits the
/// threshold and gradually expires; a fast burst hits the threshold
/// and triggers the hard block.
#[derive(Debug, Default)]
struct AttemptRecord {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
    /// Username last seen — surfaced in the audit log so the operator
    /// can tell if it's an attacker spraying "admin", "root", "test" or
    /// somebody fat-fingering their own login.
    last_username: String,
}

/// One row in the audit log. Bounded buffer (newest 500 entries) so we
/// don't grow unbounded over time.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthLogEntry {
    /// Unix epoch seconds.
    pub timestamp: u64,
    pub ip: String,
    pub username: String,
    pub success: bool,
    /// Plain-English reason: "ok", "bad password", "locked out", "trusted ip skipped lockout", etc.
    pub reason: String,
    /// True when the attempt was blocked because the IP was already locked.
    pub was_locked: bool,
}

const AUDIT_LOG_MAX: usize = 500;

/// IP-based login rate limiter with hard lockouts, trusted-IP allowlist,
/// and an in-memory audit log. The operator-facing API is unchanged
/// (is_locked_out / record_failure / clear) so existing callers keep
/// working; new methods expose the audit log and the config.
/// Hook callbacks installed by the API/runtime layer so the limiter
/// can trigger fleet propagation without owning ClusterState directly.
/// Set once at startup; called by the limiter whenever a lock/unlock
/// happens regardless of the source surface (WolfStack UI, sshd, PVE).
pub type PropagateBlockHook = std::sync::Arc<dyn Fn(&str, u64) + Send + Sync>;
pub type PropagateUnblockHook = std::sync::Arc<dyn Fn(&str) + Send + Sync>;
/// (title, body) callback fired when a lockout newly triggers. main.rs
/// wires this to alerting::send_node_alert so the operator gets a
/// Discord / Slack / Telegram / email with the cluster + hostname.
pub type SecurityAlertHook = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;

pub struct LoginRateLimiter {
    attempts: RwLock<HashMap<String, AttemptRecord>>,
    audit: RwLock<std::collections::VecDeque<AuthLogEntry>>,
    config: RwLock<LoginLockoutConfig>,
    propagate_block: RwLock<Option<PropagateBlockHook>>,
    propagate_unblock: RwLock<Option<PropagateUnblockHook>>,
    alert_hook: RwLock<Option<SecurityAlertHook>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
            audit: RwLock::new(std::collections::VecDeque::with_capacity(AUDIT_LOG_MAX)),
            config: RwLock::new(LoginLockoutConfig::load()),
            propagate_block: RwLock::new(None),
            propagate_unblock: RwLock::new(None),
            alert_hook: RwLock::new(None),
        }
    }

    pub fn install_alert_hook(&self, hook: SecurityAlertHook) {
        *self.alert_hook.write().unwrap() = Some(hook);
    }

    /// Install hooks the limiter will call whenever a lock/unlock
    /// happens. The hooks own (or clone) the cluster state and fan
    /// out via the existing inter-node API. Set ONCE at startup.
    pub fn install_propagation_hooks(&self,
        on_block: PropagateBlockHook,
        on_unblock: PropagateUnblockHook,
    ) {
        *self.propagate_block.write().unwrap() = Some(on_block);
        *self.propagate_unblock.write().unwrap() = Some(on_unblock);
    }

    fn fire_block_hook(&self, ip: &str, seconds: u64) {
        let hook = self.propagate_block.read().unwrap().clone();
        if let Some(h) = hook {
            h(ip, seconds);
        }
    }

    fn fire_unblock_hook(&self, ip: &str) {
        let hook = self.propagate_unblock.read().unwrap().clone();
        if let Some(h) = hook {
            h(ip);
        }
    }

    /// Snapshot the current config.
    pub fn config(&self) -> LoginLockoutConfig {
        self.config.read().unwrap().clone()
    }

    /// Replace the config (and persist to disk). Returns the saved
    /// shape so the caller can echo it back to the operator.
    pub fn set_config(&self, new: LoginLockoutConfig) -> Result<LoginLockoutConfig, String> {
        new.save()?;
        *self.config.write().unwrap() = new.clone();
        Ok(new)
    }

    /// Append an audit row. Bounded — oldest entry dropped when full.
    fn audit_push(&self, entry: AuthLogEntry) {
        let mut log = self.audit.write().unwrap();
        if log.len() >= AUDIT_LOG_MAX {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Read the audit log (newest first).
    pub fn audit_log(&self) -> Vec<AuthLogEntry> {
        let log = self.audit.read().unwrap();
        log.iter().rev().cloned().collect()
    }

    /// Currently-locked IPs (with remaining seconds). Useful for the UI.
    pub fn current_lockouts(&self) -> Vec<(String, u64, String)> {
        let attempts = self.attempts.read().unwrap();
        let now = Instant::now();
        attempts.iter()
            .filter_map(|(ip, rec)| {
                rec.locked_until.and_then(|until| {
                    if until > now {
                        Some((ip.clone(), until.duration_since(now).as_secs(), rec.last_username.clone()))
                    } else { None }
                })
            })
            .collect()
    }

    /// Manually clear a lockout for a specific IP. Operator escape hatch.
    pub fn unblock(&self, ip: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(ip);
        drop(attempts);
        // Drop the kernel rule too — operator unblocking expects full recovery.
        kernel_unblock_ip(ip);
        self.persist_lockouts();
        self.fire_unblock_hook(ip);
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: String::new(),
            success: false,
            reason: "manually unblocked by operator".into(),
            was_locked: false,
        });
    }

    /// Add a kernel block from a peer's propagation. Skips trusted IPs
    /// (each node has its own trusted list — the receiver always re-
    /// validates, so an attacker can't trick a peer into blocking your
    /// admin IP just because it's not trusted on their node). Records
    /// in the audit log so the operator sees fleet-wide propagation.
    pub fn add_propagated_lockout(&self, ip: &str, lockout_seconds: u64, source_node: &str) {
        let cfg = self.config.read().unwrap().clone();
        if cfg.is_trusted(ip) {
            tracing::info!(
                "auth: refused propagated lockout for {} (trusted on this node) — source: {}",
                ip, source_node
            );
            self.audit_push(AuthLogEntry {
                timestamp: now_secs(),
                ip: ip.to_string(),
                username: String::new(),
                success: false,
                reason: format!("propagated lockout from {} REFUSED — IP is trusted here", source_node),
                was_locked: false,
            });
            return;
        }
        let mut attempts = self.attempts.write().unwrap();
        let rec = attempts.entry(ip.to_string()).or_default();
        let new_until = Instant::now() + Duration::from_secs(lockout_seconds);
        // Extend if a longer lockout arrives, never shorten.
        rec.locked_until = Some(match rec.locked_until {
            Some(existing) if existing > new_until => existing,
            _ => new_until,
        });
        drop(attempts);
        kernel_block_ip(ip);
        self.persist_lockouts();
        tracing::warn!(
            "auth: kernel-blocked {} via fleet propagation from {} ({}s)",
            ip, source_node, lockout_seconds
        );
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: String::new(),
            success: false,
            reason: format!("kernel-blocked via fleet propagation from {}", source_node),
            was_locked: false,
        });
    }

    /// Record a failed login attempt. Returns true if the IP just hit
    /// the threshold (was not previously locked, now is).
    pub fn record_failure(&self, ip: &str) -> bool {
        self.record_failure_with(ip, "")
    }

    /// Variant that records the username and audit reason for the row.
    pub fn record_failure_with(&self, ip: &str, username: &str) -> bool {
        let cfg = self.config.read().unwrap().clone();
        // Trusted IPs never accumulate failures.
        if cfg.is_trusted(ip) {
            self.audit_push(AuthLogEntry {
                timestamp: now_secs(),
                ip: ip.to_string(),
                username: username.to_string(),
                success: false,
                reason: "bad password (trusted IP — no lockout)".into(),
                was_locked: false,
            });
            tracing::info!("auth: failed login for {} from trusted IP {} (no lockout)", username, ip);
            return false;
        }
        if !cfg.enabled {
            self.audit_push(AuthLogEntry {
                timestamp: now_secs(),
                ip: ip.to_string(),
                username: username.to_string(),
                success: false,
                reason: "bad password (lockout disabled in config)".into(),
                was_locked: false,
            });
            return false;
        }
        let window = Duration::from_secs(cfg.window_seconds);
        let lockout = Duration::from_secs(cfg.lockout_seconds);
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();
        let now = Instant::now();
        entry.failures.retain(|t| now.duration_since(*t) < window);
        entry.failures.push(now);
        entry.last_username = username.to_string();
        let just_locked = entry.failures.len() >= cfg.max_failures as usize && entry.locked_until.is_none();
        if just_locked {
            entry.locked_until = Some(now + lockout);
            tracing::warn!(
                "auth: IP {} hit {} failed logins in {}s — locked out for {}s",
                ip, cfg.max_failures, cfg.window_seconds, cfg.lockout_seconds
            );
        }
        drop(attempts);
        // Apply the kernel-level block AFTER releasing the write lock
        // (Command::new can take a few ms and we don't want to hold
        // the attempts lock across it).
        if just_locked {
            kernel_block_ip(ip);
            self.persist_lockouts();
            self.fire_block_hook(ip, cfg.lockout_seconds);
            // Alert operator out-of-band (Discord/Slack/Telegram/email).
            // Title includes the source IP; body has the username
            // attempted, threshold, and lockout duration. Cluster +
            // hostname are stamped in by the alert hook itself.
            let hook = self.alert_hook.read().unwrap().clone();
            if let Some(h) = hook {
                let title = format!("🚨 IP {} blocked after {} failed logins", ip, cfg.max_failures);
                let body = format!(
                    "Source IP {} crossed the brute-force threshold and is now kernel-blocked.\n\n\
                     User attempted: {}\n\
                     Threshold: {} failed logins within {} seconds\n\
                     Lockout: {} seconds ({} hours)\n\n\
                     The block is enforced via iptables DROP and is propagating to every other WolfStack-managed node in the cluster.",
                    ip, if username.is_empty() { "(unknown)".to_string() } else { username.to_string() },
                    cfg.max_failures, cfg.window_seconds,
                    cfg.lockout_seconds, cfg.lockout_seconds / 3600,
                );
                h(title, body);
            }
        }
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: username.to_string(),
            success: false,
            reason: if just_locked { "bad password — threshold hit, IP locked".into() } else { "bad password".into() },
            was_locked: false,
        });
        just_locked
    }

    /// Immediately lock out an IP without the threshold accumulation.
    /// Used for cases where a single hit is unambiguous evidence and
    /// the standard sliding-window count would just delay the same
    /// outcome. Returns `true` if newly locked (caller should
    /// propagate to the rest of the cluster); `false` if the IP was
    /// trusted, the limiter is disabled, or the IP was already locked.
    ///
    /// `source` and `detail` are caller-side context only — the
    /// operator-visible audit log uses a generic reason regardless.
    pub fn force_lockout(&self, ip: &str, source: &str, detail: &str) -> bool {
        let cfg = self.config.read().unwrap().clone();
        if cfg.is_trusted(ip) {
            tracing::info!("auth: force-lockout skipped for trusted IP {} ({})", ip, source);
            return false;
        }
        if !cfg.enabled {
            return false;
        }
        let lockout = Duration::from_secs(cfg.lockout_seconds);
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();
        let now = Instant::now();
        if let Some(until) = entry.locked_until {
            if until > now {
                return false; // already locked, don't re-fire
            }
        }
        entry.locked_until = Some(now + lockout);
        entry.last_username = source.to_string();
        drop(attempts);
        tracing::warn!("auth: auto-block {}", ip);
        kernel_block_ip(ip);
        self.persist_lockouts();
        self.fire_block_hook(ip, cfg.lockout_seconds);
        let hook = self.alert_hook.read().unwrap().clone();
        if let Some(h) = hook {
            let title = format!("🚨 IP {} auto-blocked", ip);
            let body = format!(
                "Source IP {} was blocked.\n\n\
                 Lockout: {} seconds ({} hours)\n\n\
                 The block is enforced via iptables DROP and is propagating to every other WolfStack-managed node in the cluster.",
                ip, cfg.lockout_seconds, cfg.lockout_seconds / 3600,
            );
            h(title, body);
        }
        // Audit reason is intentionally generic — callers pass their
        // own `detail` for context only at the limiter level; we don't
        // surface it in the operator-visible audit log.
        let _ = detail;
        let _ = source;
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: String::new(),
            success: false,
            reason: "auto-block".to_string(),
            was_locked: true,
        });
        true
    }

    /// Currently locked out?
    pub fn is_locked_out(&self, ip: &str) -> bool {
        let cfg = self.config.read().unwrap();
        if cfg.is_trusted(ip) || !cfg.enabled { return false; }
        drop(cfg);
        let attempts = self.attempts.read().unwrap();
        match attempts.get(ip) {
            Some(rec) => match rec.locked_until {
                Some(until) => until > Instant::now(),
                None => false,
            },
            None => false,
        }
    }

    /// Remaining lockout seconds (0 if not locked).
    pub fn lockout_remaining(&self, ip: &str) -> u64 {
        let attempts = self.attempts.read().unwrap();
        match attempts.get(ip).and_then(|r| r.locked_until) {
            Some(until) => {
                let now = Instant::now();
                if until > now { until.duration_since(now).as_secs() } else { 0 }
            }
            None => 0,
        }
    }

    /// Successful login — clear failures, audit the success.
    pub fn clear(&self, ip: &str) {
        self.clear_with(ip, "")
    }

    pub fn clear_with(&self, ip: &str, username: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(ip);
        drop(attempts);
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: username.to_string(),
            success: true,
            reason: "ok".into(),
            was_locked: false,
        });
        tracing::info!("auth: successful login for {} from {}", username, ip);
    }

    /// Audit-only: record a "blocked because already locked" attempt.
    pub fn audit_blocked(&self, ip: &str, username: &str) {
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: username.to_string(),
            success: false,
            reason: format!("rejected — IP locked for {}s more", self.lockout_remaining(ip)),
            was_locked: true,
        });
    }

    /// Periodic cleanup of expired entries (called from the background
    /// task). Removes kernel iptables rules for any lockouts that
    /// expired since the last tick — the rules persist across restarts,
    /// so without this they'd accumulate forever.
    pub fn cleanup(&self) {
        let cfg = self.config.read().unwrap().clone();
        let window = Duration::from_secs(cfg.window_seconds);
        let now = Instant::now();
        let mut to_unblock: Vec<String> = Vec::new();
        {
            let mut attempts = self.attempts.write().unwrap();
            attempts.retain(|ip, rec| {
                rec.failures.retain(|t| now.duration_since(*t) < window);
                let still_locked = matches!(rec.locked_until, Some(u) if u > now);
                let just_expired = matches!(rec.locked_until, Some(u) if u <= now);
                if just_expired {
                    to_unblock.push(ip.clone());
                }
                !rec.failures.is_empty() || still_locked
            });
        }
        for ip in to_unblock {
            kernel_unblock_ip(&ip);
            tracing::info!("auth: lockout for {} expired — kernel rule removed", ip);
        }
        if !to_unblock_was_empty(&self.attempts) {
            self.persist_lockouts();
        }
    }
}

fn to_unblock_was_empty(attempts: &RwLock<HashMap<String, AttemptRecord>>) -> bool {
    attempts.read().unwrap().is_empty()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════
// Kernel-level IP blocking — "act like the server isn't there"
// ════════════════════════════════════════════════════════════════════
//
// When the rate limiter decides an IP has crossed the threshold, we
// install an iptables DROP rule for that source. New TCP packets get
// silently discarded by the kernel — no SYN-ACK, no RST, no HTTP
// response. From the attacker's side the server appears offline.
//
// Existing TCP connections from a blocked IP keep working briefly
// (they're already established) but they'll timeout on the next ACK
// the kernel can't deliver. New connections fail at SYN.
//
// Trusted IPs are NEVER kernel-blocked — the operator can always reach
// the box from their declared admin networks.
//
// State is persisted to /etc/wolfstack/auth-active-lockouts.json so
// WolfStack can restore iptables rules on restart (kernel rules persist
// across WolfStack restarts; the file just lets us track what we own).

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedLockout {
    ip: String,
    locked_at: u64,         // unix secs
    lockout_seconds: u64,   // total duration
}

fn lockouts_file() -> String {
    format!("{}/auth-active-lockouts.json", crate::paths::get().config_dir)
}

// ─── Cluster-node block protection ──────────────────────────────────────────
// klasSponsor 2026-06-08: WolfStack nodes were kernel-blocking / fail2ban-
// banning each OTHER's IPs (inter-node polling, a propagated block, or SSH
// between nodes tripping the 3-strike / scan auto-block), silently breaking
// cluster connectivity — "one node had banned another's ip". Every kernel
// block funnels through `kernel_block_ip`, so a single guard there protects
// all paths (brute-force, scan, AND propagated blocks). The set is refreshed
// from cluster state every ~10s by a background task in main.rs; a refused
// block is recorded so the Security UI can raise a red banner and an alert can
// fire. (fail2ban bans independently — its ignoreip is handled separately.)
static PROTECTED_NODE_IPS: std::sync::OnceLock<RwLock<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();
static PROTECTED_BLOCK_EVENTS: std::sync::OnceLock<RwLock<std::collections::VecDeque<ProtectedBlockEvent>>> =
    std::sync::OnceLock::new();
const MAX_PROTECTED_EVENTS: usize = 50;

/// A refused attempt to kernel-block a cluster-node IP. Drives the red banner.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ProtectedBlockEvent {
    /// Monotonic id so the UI / alerter can tell what's new.
    pub id: u64,
    pub ip: String,
    /// Unix seconds.
    pub at: u64,
}

fn protected_ips() -> &'static RwLock<std::collections::HashSet<String>> {
    PROTECTED_NODE_IPS.get_or_init(|| RwLock::new(std::collections::HashSet::new()))
}
fn protected_events() -> &'static RwLock<std::collections::VecDeque<ProtectedBlockEvent>> {
    PROTECTED_BLOCK_EVENTS.get_or_init(|| RwLock::new(std::collections::VecDeque::new()))
}

/// Replace the set of cluster-node IPs that must never be kernel-blocked.
/// Returns the IPs that are NEWLY protected since the last call, so the caller
/// can heal any pre-existing bad ban (a one-shot unblock per IP) without
/// shelling out to iptables every cycle. Unspecified / unparseable addresses
/// (e.g. a node still reporting 0.0.0.0) are dropped — they'd match far too
/// much and must never be whitelisted.
pub fn set_protected_node_ips(ips: Vec<String>) -> Vec<String> {
    let set: std::collections::HashSet<String> = ips.into_iter()
        .filter(|s| {
            s.parse::<std::net::IpAddr>()
                .map(|ip| !ip.is_unspecified() && !ip.is_loopback())
                .unwrap_or(false)
        })
        .collect();
    let mut newly = Vec::new();
    if let Ok(mut g) = protected_ips().write() {
        for ip in &set {
            if !g.contains(ip) { newly.push(ip.clone()); }
        }
        *g = set;
    }
    newly
}

/// True if `ip` is a known cluster-node address that must never be blocked.
pub fn is_protected_node_ip(ip: &str) -> bool {
    protected_ips().read().map(|g| g.contains(ip)).unwrap_or(false)
}

/// Record that a block was refused for a protected cluster-node IP. Coalesces
/// a rapid repeat for the same IP so a tight propagation loop can't flood the
/// ring (or re-alert) — it bumps the existing entry's timestamp instead.
/// `pub` so other block paths that don't go through `kernel_block_ip` (e.g. the
/// compromise-remediation C2 block) can surface their own refusals too.
pub fn record_protected_block(ip: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut g) = protected_events().write() {
        if let Some(last) = g.back_mut()
            && last.ip == ip && now.saturating_sub(last.at) < 5
        {
            last.at = now;
            return;
        }
        let id = g.back().map(|e| e.id + 1).unwrap_or(1);
        g.push_back(ProtectedBlockEvent { id, ip: ip.to_string(), at: now });
        while g.len() > MAX_PROTECTED_EVENTS { g.pop_front(); }
    }
}

/// Recent refused blocks, oldest first. For the Security UI banner + alerter.
pub fn recent_protected_block_events() -> Vec<ProtectedBlockEvent> {
    protected_events().read().map(|g| g.iter().cloned().collect()).unwrap_or_default()
}

// ─── Local workload-subnet block protection ─────────────────────────────────
// klasSponsor 2026-06-08 (round 2): the same auto-block was also firewalling the
// host's OWN containers — a Docker/LXC service that hit an auth endpoint with bad
// creds tripped the 3-strike brute-force block, and kernel_block_ip's INPUT+FORWARD
// DROP on the container's IP killed its traffic ("wolfstack made iptables rules to
// drop traffic from those containers"). We exempt the locally-managed container
// bridges (docker0/br-*/lxcbr*/virbr*, from `collect_workload_subnets`) the same way
// cluster-node IPs are exempt. A genuinely-compromised container is stopped /
// quarantined, never blanket FORWARD-DROP'd (which is over-broad). CIDR-based
// because container IPs are dynamic; refreshed every ~10s in main.rs.
static PROTECTED_WORKLOAD_SUBNETS: std::sync::OnceLock<RwLock<Vec<(std::net::Ipv4Addr, u8)>>> =
    std::sync::OnceLock::new();

fn protected_workload_subnets() -> &'static RwLock<Vec<(std::net::Ipv4Addr, u8)>> {
    PROTECTED_WORKLOAD_SUBNETS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Parse an IPv4 CIDR "a.b.c.d/prefix" into (network, prefix). None on garbage,
/// a missing prefix, or a /0 — we must never whitelist the entire internet.
fn parse_workload_cidr(cidr: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let (ip_s, pfx_s) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip_s.trim().parse().ok()?;
    let prefix: u8 = pfx_s.trim().parse().ok()?;
    if prefix == 0 || prefix > 32 { return None; }
    Some((ip, prefix))
}

/// Replace the set of locally-managed container/workload subnets (Docker/LXC/
/// libvirt bridges) whose IPs must never be kernel-blocked. CIDR strings come
/// from `collect_workload_subnets()`.
pub fn set_protected_workload_subnets(cidrs: Vec<String>) {
    let parsed: Vec<(std::net::Ipv4Addr, u8)> =
        cidrs.iter().filter_map(|c| parse_workload_cidr(c)).collect();
    if let Ok(mut g) = protected_workload_subnets().write() {
        *g = parsed;
    }
}

/// True if `ip` falls inside a protected workload subnet.
pub fn is_protected_workload_ip(ip: std::net::Ipv4Addr) -> bool {
    let g = match protected_workload_subnets().read() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let ip_u = u32::from(ip);
    g.iter().any(|&(net, prefix)| {
        // prefix is 1..=32 (parse_workload_cidr rejects 0 and >32), shift is safe.
        let mask = u32::MAX << (32 - prefix as u32);
        (ip_u & mask) == (u32::from(net) & mask)
    })
}

/// Add a kernel DROP rule for `ip` (v4 or v6). Idempotent — uses
/// iptables -C to check before adding. Silent when iptables is missing
/// (the HTTP-level Forbidden fallback still applies).
pub fn kernel_block_ip(ip: &str) {
    let target: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("auth: cannot kernel-block invalid IP '{}'", ip);
            return;
        }
    };
    // Universal guard: never DROP a WolfStack-managed address. Every block path
    // (brute-force, scan, propagated) funnels through here, so this one check
    // covers them all — cluster-node IPs AND the host's own container/workload
    // bridges, so a container that trips auth detection can't get its own traffic
    // firewalled. Record the refusal so the Security UI shows a banner / alert.
    // (klasSponsor 2026-06-08.)
    let protected = is_protected_node_ip(ip)
        || matches!(target, std::net::IpAddr::V4(v4) if is_protected_workload_ip(v4));
    if protected {
        record_protected_block(ip);
        tracing::error!(
            "auth: REFUSED kernel-block of {} — it is a WolfStack-managed address \
             (a cluster node or a local container bridge), auto-whitelisted. A \
             security trigger tried to firewall your own infrastructure; check the \
             Security page (a compromised container should be stopped, not blocked).",
            ip
        );
        return;
    }
    let cmd = match target {
        std::net::IpAddr::V4(_) => "iptables",
        std::net::IpAddr::V6(_) => "ip6tables",
    };
    // Insert the DROP rule in BOTH the INPUT and FORWARD chains.
    //
    // - INPUT protects the host's own services (sshd, pveproxy on
    //   8006, wolfstack on 8553).
    // - FORWARD protects guests behind the host's Linux bridges /
    //   vSwitches — VM/LXC traffic that the host is forwarding, not
    //   consuming. Without this rule a brute-forcer who pivots from
    //   the host management plane to a guest service can keep
    //   attacking even after the host kicks them out.
    //
    // CAVEAT — FORWARD-chain rules only see bridged traffic when
    // `br_netfilter` is loaded and `net.bridge.bridge-nf-call-iptables=1`.
    // Proxmox enables this by default; on a vanilla Debian/Ubuntu box
    // it may need `modprobe br_netfilter`. If the kernel module isn't
    // present, the FORWARD rule is harmless (just inert).
    //
    // What this CANNOT block:
    //   - VMs using PCI/SR-IOV passthrough — packets reach the VM
    //     without ever touching the host kernel's netfilter
    //   - VMs reached via a separate physical NIC that bypasses
    //     the host's iptables (e.g. dedicated mgmt vs data NIC where
    //     only mgmt is firewalled here)
    // For those topologies, propagate the block to the upstream
    // router / switch ACL or to a per-VM firewall.
    insert_drop_rule(cmd, "INPUT", ip);
    insert_drop_rule(cmd, "FORWARD", ip);
}

/// Idempotently insert `-I <chain> 1 -s <ip> -j DROP` for the given
/// iptables variant. No-op if the rule already exists.
fn insert_drop_rule(cmd: &str, chain: &str, ip: &str) {
    let check = std::process::Command::new(cmd)
        .args(["-C", chain, "-s", ip, "-j", "DROP"])
        .output();
    if let Ok(out) = check {
        if out.status.success() { return; }  // rule already present
    }
    let r = std::process::Command::new(cmd)
        .args(["-I", chain, "1", "-s", ip, "-j", "DROP"])
        .output();
    match r {
        Ok(o) if o.status.success() => {
            tracing::warn!("auth: kernel-blocked {} in {}/{}", ip, cmd, chain);
        }
        Ok(o) => {
            tracing::error!(
                "auth: kernel-block failed for {} in {}/{}: {}",
                ip, cmd, chain, String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => {
            tracing::error!("auth: could not run {} to block {} in {}: {}", cmd, ip, chain, e);
        }
    }
}

/// Remove the kernel DROP rules for `ip` from both INPUT and FORWARD
/// chains. Loops per chain while the rule exists (handles duplicate
/// INSERTs that can accumulate across restarts).
pub fn kernel_unblock_ip(ip: &str) {
    let target: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    let cmd = match target {
        std::net::IpAddr::V4(_) => "iptables",
        std::net::IpAddr::V6(_) => "ip6tables",
    };
    remove_drop_rule(cmd, "INPUT", ip);
    remove_drop_rule(cmd, "FORWARD", ip);
    tracing::info!("auth: kernel-unblocked {} (INPUT + FORWARD)", ip);
}

fn remove_drop_rule(cmd: &str, chain: &str, ip: &str) {
    for _ in 0..10 {
        let r = std::process::Command::new(cmd)
            .args(["-D", chain, "-s", ip, "-j", "DROP"])
            .output();
        match r {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }
}

impl LoginRateLimiter {
    /// Snapshot of currently-locked entries → persistence file. Called
    /// on every state change so reloads are consistent.
    fn persist_lockouts(&self) {
        let now = Instant::now();
        let now_unix = now_secs();
        let attempts = self.attempts.read().unwrap();
        let mut snapshot: Vec<PersistedLockout> = Vec::new();
        let cfg = self.config.read().unwrap().clone();
        for (ip, rec) in attempts.iter() {
            if let Some(until) = rec.locked_until {
                if until > now {
                    let remaining = until.duration_since(now).as_secs();
                    // The lockout total isn't stored on the record (we
                    // only have an Instant); approximate from the config.
                    // This is good enough for cross-restart restoration.
                    let total = cfg.lockout_seconds;
                    snapshot.push(PersistedLockout {
                        ip: ip.clone(),
                        locked_at: now_unix.saturating_sub(total.saturating_sub(remaining)),
                        lockout_seconds: total,
                    });
                }
            }
        }
        if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
            let _ = crate::paths::write_secure(&lockouts_file(), &json);
        }
    }

    /// Restore kernel-block state from disk on startup. Call once after
    /// `LoginRateLimiter::new()`. For each non-expired entry: re-apply
    /// the iptables DROP rule and re-register the record in memory.
    /// Expired entries are dropped silently (caller-removed rules are
    /// fine — kernel_unblock is idempotent if they were never set).
    pub fn restore_persisted_lockouts(&self) {
        let json = match std::fs::read_to_string(lockouts_file()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let snapshot: Vec<PersistedLockout> = match serde_json::from_str(&json) {
            Ok(s) => s,
            Err(_) => return,
        };
        let now = now_secs();
        let cfg = self.config.read().unwrap().clone();
        for entry in snapshot {
            if cfg.is_trusted(&entry.ip) { continue; }
            let expires_at_unix = entry.locked_at.saturating_add(entry.lockout_seconds);
            if expires_at_unix <= now {
                // Already expired — nuke any leftover kernel rule.
                kernel_unblock_ip(&entry.ip);
                continue;
            }
            let remaining = expires_at_unix - now;
            kernel_block_ip(&entry.ip);
            let mut attempts = self.attempts.write().unwrap();
            let rec = attempts.entry(entry.ip.clone()).or_default();
            rec.locked_until = Some(Instant::now() + Duration::from_secs(remaining));
            tracing::warn!(
                "auth: restored kernel-block for {} ({}s remaining)",
                entry.ip, remaining
            );
        }
    }
}

// ─── Password Reset Tokens ───

/// In-memory storage for password reset tokens (30-minute expiry)
pub struct PasswordResetTokens {
    tokens: RwLock<HashMap<String, ResetToken>>,
}

struct ResetToken {
    username: String,
    created: Instant,
}

const RESET_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 60); // 30 minutes

impl PasswordResetTokens {
    pub fn new() -> Self {
        Self { tokens: RwLock::new(HashMap::new()) }
    }

    /// Create a reset token for a user. Returns the token string.
    pub fn create(&self, username: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().unwrap();
        // Remove any existing tokens for this user
        tokens.retain(|_, t| t.username != username);
        tokens.insert(token.clone(), ResetToken {
            username: username.to_string(),
            created: Instant::now(),
        });
        token
    }

    /// Validate and consume a reset token. Returns the username if valid.
    pub fn validate_and_consume(&self, token: &str) -> Option<String> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some(rt) = tokens.remove(token) {
            if rt.created.elapsed() < RESET_TOKEN_LIFETIME {
                return Some(rt.username);
            }
        }
        None
    }

    /// Clean up expired tokens
    pub fn cleanup(&self) {
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, t| t.created.elapsed() < RESET_TOKEN_LIFETIME);
    }
}

/// Validate a container/VM name — only allow safe characters (alphanumeric, dash, underscore, dot)
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn equal_content_equal_length_is_true() {
        assert!(validate_cluster_secret("wsk_abc123", "wsk_abc123"));
        assert!(validate_cluster_secret("x", "x"));
    }

    /// Stage 5 regression test: validate_inter_node_secret MUST accept
    /// the in-memory secret regardless of env-flag state. Pre-fix, the
    /// chain in `require_auth` was inlined at 7+ call sites; any future
    /// change must keep the in-memory path always-on. This test does
    /// NOT touch env vars (set_var is racy with parallel tests in
    /// edition 2024 — marked unsafe) — just exercises the trivial
    /// in-memory match.
    #[test]
    fn inter_node_accepts_in_memory_unconditionally() {
        assert!(validate_inter_node_secret("wsk_in_mem_value_for_test", "wsk_in_mem_value_for_test"));
    }

    /// Stage 5 regression test: the OR-chain in
    /// validate_inter_node_secret must reject an obviously-wrong value
    /// regardless of any env state. Sanity check that the helper isn't
    /// degenerate to "always true".
    #[test]
    fn inter_node_rejects_obviously_wrong_value() {
        assert!(!validate_inter_node_secret("not_a_real_secret_at_all_xyz",
                                            "wsk_in_mem_value_for_test"));
    }

    /// Stage 5 regression test: default_secret_accepted() must default
    /// to TRUE so shipping the binary doesn't break any existing install.
    /// If the env var is set in the test runner this assertion is
    /// skipped — we trust CI to not set WolfStack vars accidentally.
    #[test]
    fn default_secret_acceptance_defaults_to_true() {
        if std::env::var("WOLFSTACK_REJECT_DEFAULT_SECRET").is_ok() { return; }
        assert!(default_secret_accepted(),
                "default-secret acceptance must default to true — \
                 Stage 5 must not change behaviour for any install on upgrade");
    }

    #[test]
    fn equal_length_different_content_is_false() {
        assert!(!validate_cluster_secret("wsk_abc123", "wsk_xyz999"));
        assert!(!validate_cluster_secret("aaaaa", "aaaab"));  // one byte off
    }

    #[test]
    fn different_length_is_false() {
        // The bug this test prevents: pre-v18.7.30 the function did an
        // early return on length mismatch, leaking expected length via
        // timing. Now len-mismatch is folded into the accumulator
        // alongside content bytes — still returns false, still const
        // time relative to the longer input.
        assert!(!validate_cluster_secret("short", "muchlongersecret"));
        assert!(!validate_cluster_secret("longerthanexpected", "short"));
        assert!(!validate_cluster_secret("a", "ab"));
        assert!(!validate_cluster_secret("", ""));  // both empty — explicit early exit
    }

    #[test]
    fn empty_inputs_rejected() {
        assert!(!validate_cluster_secret("", "real_secret"));
        assert!(!validate_cluster_secret("real_secret", ""));
    }

    #[test]
    fn long_secret_equality() {
        let s = "wsk_".to_string() + &"a".repeat(64);
        assert!(validate_cluster_secret(&s, &s));
        let mut tampered = s.clone();
        tampered.pop();
        tampered.push('b');  // flip last byte
        assert!(!validate_cluster_secret(&s, &tampered));
    }
}

#[cfg(test)]
mod lockout_tests {
    use super::*;

    fn make_limiter(cfg: LoginLockoutConfig) -> LoginRateLimiter {
        let l = LoginRateLimiter::new();
        *l.config.write().unwrap() = cfg;
        l
    }

    #[test]
    fn default_threshold_is_three() {
        // v23.12.13 lowered the default to 3 so brute-force attempts
        // get blocked after a handful of tries instead of waiting for
        // 10 failures. Lock this in so a future config-edit doesn't
        // silently relax the default back.
        let cfg = LoginLockoutConfig::default();
        assert_eq!(cfg.max_failures, 3);
        assert_eq!(cfg.window_seconds, 300);
        assert_eq!(cfg.lockout_seconds, 48 * 3600);
        assert!(cfg.enabled);
    }

    #[test]
    fn lockout_triggers_after_threshold() {
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        assert!(!l.is_locked_out("1.2.3.4"));
        assert!(!l.record_failure_with("1.2.3.4", "u"));
        assert!(!l.record_failure_with("1.2.3.4", "u"));
        // Third failure is the threshold — should trigger.
        assert!(l.record_failure_with("1.2.3.4", "u"), "third failure must trigger lockout");
        assert!(l.is_locked_out("1.2.3.4"));
        // Subsequent failures don't re-trigger (already locked).
        assert!(!l.record_failure_with("1.2.3.4", "u"));
        assert!(l.is_locked_out("1.2.3.4"));
    }

    #[test]
    fn trusted_single_ip_never_locks_out() {
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["10.0.0.5".into()], enabled: true,
        };
        let l = make_limiter(cfg);
        for _ in 0..50 {
            assert!(!l.record_failure_with("10.0.0.5", "u"),
                "trusted IP must never trigger lockout");
        }
        assert!(!l.is_locked_out("10.0.0.5"));
    }

    #[test]
    fn trusted_cidr_v4_never_locks_out() {
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["10.0.0.0/8".into()], enabled: true,
        };
        let l = make_limiter(cfg);
        for ip in ["10.1.2.3", "10.255.255.255", "10.0.0.1"] {
            for _ in 0..10 { l.record_failure_with(ip, "u"); }
            assert!(!l.is_locked_out(ip), "IP {} in trusted CIDR must not lock", ip);
        }
        // An IP outside the CIDR DOES lock.
        for _ in 0..2 { l.record_failure_with("11.0.0.1", "u"); }
        assert!(l.is_locked_out("11.0.0.1"));
    }

    #[test]
    fn trusted_cidr_v6_never_locks_out() {
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["2a01:4f8:151:7225::/64".into()], enabled: true,
        };
        let l = make_limiter(cfg);
        for _ in 0..10 { l.record_failure_with("2a01:4f8:151:7225::5", "u"); }
        assert!(!l.is_locked_out("2a01:4f8:151:7225::5"));
        // Different /64 → not trusted → does lock.
        for _ in 0..2 { l.record_failure_with("2a01:4f8:151:7226::5", "u"); }
        assert!(l.is_locked_out("2a01:4f8:151:7226::5"));
    }

    #[test]
    fn disabled_config_skips_lockout_entirely() {
        let cfg = LoginLockoutConfig {
            max_failures: 1, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: false,
        };
        let l = make_limiter(cfg);
        for _ in 0..50 { l.record_failure_with("9.9.9.9", "u"); }
        assert!(!l.is_locked_out("9.9.9.9"), "disabled config must never lock");
    }

    #[test]
    fn unblock_clears_lockout() {
        let cfg = LoginLockoutConfig {
            max_failures: 1, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        l.record_failure_with("8.8.8.8", "u");
        assert!(l.is_locked_out("8.8.8.8"));
        l.unblock("8.8.8.8");
        assert!(!l.is_locked_out("8.8.8.8"));
    }

    #[test]
    fn audit_log_capped_at_500() {
        let cfg = LoginLockoutConfig::default();
        let l = make_limiter(cfg);
        // Force-feed 600 audit rows via clear_with (success path —
        // doesn't trigger lockout).
        for i in 0..600 {
            l.clear_with(&format!("1.2.3.{}", i % 250), "test");
        }
        let log = l.audit_log();
        assert!(log.len() <= 500, "audit log capped at 500, got {}", log.len());
    }

    #[test]
    fn block_hook_fires_on_threshold() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let calls_h = calls.clone();
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        l.install_propagation_hooks(
            std::sync::Arc::new(move |_ip, _secs| { calls_h.fetch_add(1, Ordering::SeqCst); }),
            std::sync::Arc::new(|_ip| {}),
        );
        l.record_failure_with("7.7.7.7", "u");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "hook must not fire before threshold");
        l.record_failure_with("7.7.7.7", "u");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook fires exactly once at threshold");
        l.record_failure_with("7.7.7.7", "u");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook does not re-fire on subsequent failures");
    }

    #[test]
    fn force_lockout_blocks_on_first_hit() {
        // No threshold accumulation — one hit is enough.
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        let locked = l.force_lockout("6.6.6.6", "auto", "ctx");
        assert!(locked, "force_lockout must return true on first hit");
        assert!(l.is_locked_out("6.6.6.6"));
    }

    #[test]
    fn force_lockout_respects_trusted_ips() {
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["10.0.0.0/8".into()],
            enabled: true,
        };
        let l = make_limiter(cfg);
        let locked = l.force_lockout("10.5.5.5", "auto", "ctx");
        assert!(!locked, "trusted IPs must not be force-locked");
        assert!(!l.is_locked_out("10.5.5.5"));
    }

    #[test]
    fn force_lockout_idempotent_when_already_locked() {
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        assert!(l.force_lockout("5.5.5.5", "auto", "first"));
        assert!(!l.force_lockout("5.5.5.5", "auto", "second"),
            "second force_lockout while still locked must return false");
    }
}

#[cfg(test)]
mod protected_node_tests {
    use super::*;

    // These touch process-global statics, but no other test exercises them, so
    // the sequences below are deterministic within the test binary.

    #[test]
    fn protected_ip_set_filters_and_diffs() {
        // Valid IPs are kept; loopback / unspecified / garbage are dropped —
        // protecting those would whitelist far too much.
        let newly = set_protected_node_ips(vec![
            "10.0.0.1".into(),
            "127.0.0.1".into(),   // loopback
            "0.0.0.0".into(),     // unspecified
            "not-an-ip".into(),   // garbage
            "192.168.1.5".into(),
        ]);
        assert!(is_protected_node_ip("10.0.0.1"));
        assert!(is_protected_node_ip("192.168.1.5"));
        assert!(!is_protected_node_ip("127.0.0.1"), "loopback must never be protected");
        assert!(!is_protected_node_ip("0.0.0.0"), "unspecified must never be protected");
        assert!(!is_protected_node_ip("8.8.8.8"));
        // First set → both valid IPs are newly protected (drives the one-shot heal).
        assert!(newly.contains(&"10.0.0.1".to_string()));
        assert!(newly.contains(&"192.168.1.5".to_string()));
        assert_eq!(newly.len(), 2);

        // Re-asserting the same set reports nothing new (no repeat heal churn).
        assert!(set_protected_node_ips(vec!["10.0.0.1".into(), "192.168.1.5".into()]).is_empty());

        // Dropping an IP from the set un-protects it.
        let _ = set_protected_node_ips(vec!["10.0.0.1".into()]);
        assert!(is_protected_node_ip("10.0.0.1"));
        assert!(!is_protected_node_ip("192.168.1.5"), "dropped IP must no longer be protected");
    }

    #[test]
    fn protected_block_events_record_and_coalesce() {
        record_protected_block("10.9.9.1");
        record_protected_block("10.9.9.2");
        let ev = recent_protected_block_events();
        assert!(ev.iter().any(|e| e.ip == "10.9.9.1"));
        assert!(ev.iter().any(|e| e.ip == "10.9.9.2"));
        // Event ids are monotonic.
        let ids: Vec<u64> = ev.iter().map(|e| e.id).collect();
        for w in ids.windows(2) { assert!(w[1] > w[0], "event ids must be monotonic"); }
        // A rapid repeat of the most-recent IP coalesces — no new ring entry.
        let before = recent_protected_block_events().len();
        record_protected_block("10.9.9.2");
        assert_eq!(before, recent_protected_block_events().len(),
            "a rapid repeat of the same IP must coalesce, not append");
    }

    #[test]
    fn workload_subnet_protection_matches_only_container_ranges() {
        // CIDRs exactly as collect_workload_subnets() returns them.
        set_protected_workload_subnets(vec![
            "172.17.0.0/16".into(), // docker0
            "10.0.3.0/24".into(),   // lxcbr0
            "garbage".into(),       // dropped (unparseable)
            "0.0.0.0/0".into(),     // dropped — must NEVER whitelist the whole internet
        ]);
        // Container IPs inside the bridges are protected.
        assert!(is_protected_workload_ip("172.17.0.5".parse().unwrap()));
        assert!(is_protected_workload_ip("172.17.255.254".parse().unwrap()));
        assert!(is_protected_workload_ip("10.0.3.42".parse().unwrap()));
        // Everything outside is NOT — including the adjacent /24, an unrelated
        // LAN, and any public IP (the /0 was dropped, so this must be false).
        assert!(!is_protected_workload_ip("10.0.4.1".parse().unwrap()));
        assert!(!is_protected_workload_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_protected_workload_ip("8.8.8.8".parse().unwrap()));
        // Clear it so we don't leak protection into other tests sharing the global.
        set_protected_workload_subnets(vec![]);
    }
}
