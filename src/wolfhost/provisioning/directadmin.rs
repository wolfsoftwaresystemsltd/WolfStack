//! DirectAdmin API client — speaks the DA REST API protocol.
//!
//! DA API uses POST with application/x-www-form-urlencoded bodies.
//! Adding ?json=yes to requests returns JSON responses.
//! Auth is HTTP Basic with admin credentials.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DA API client
pub struct DaClient {
    base_url: String,
    admin_user: String,
    admin_pass: String,
    client: reqwest::Client,
}

// ─── DA response types (internal, converted to WolfHost models externally) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaUserConfig {
    pub username: String,
    pub domain: String,
    pub email: String,
    pub bandwidth: u64,
    pub quota: u64,
    pub suspended: bool,
    pub package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaEmailAccount {
    pub user: String,
    pub domain: String,
    pub quota_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaDatabase {
    pub name: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaFtpAccount {
    pub user: String,
    pub directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaSslInfo {
    pub enabled: bool,
    pub expires: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaFileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub permission: String,
}

pub struct DaDnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

/// Resource limits + flags that make up a DirectAdmin user package.
/// `None` means "unlimited" — DA's wire format uses the literal
/// string `"unlimited"` for that case; we model it as Option<_> so
/// callers don't have to special-case sentinel values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaPackage {
    pub name: String,
    pub bandwidth_mb: Option<u64>,
    pub quota_mb: Option<u64>,
    pub domains: Option<u32>,
    pub subdomains: Option<u32>,
    pub email_accounts: Option<u32>,
    pub email_forwarders: Option<u32>,
    pub email_mailing_lists: Option<u32>,
    pub email_autoresponders: Option<u32>,
    pub ftp_accounts: Option<u32>,
    pub mysql_databases: Option<u32>,
    pub inodes: Option<u32>,
    pub dns_control: bool,
    pub cgi: bool,
    pub php: bool,
    pub spam: bool,
    pub ssl: bool,
    pub ssh: bool,
    pub suspend_at_limit: bool,
    pub language: String,
    pub ip: String,
    pub skin: String,
}

impl Default for DaPackage {
    fn default() -> Self {
        // Defaults match what DirectAdmin's "Add User Package" form
        // pre-fills: shared IP, evolution skin, English, no resource
        // caps. Callers override the limits to match the WolfHost
        // plan they're syncing.
        DaPackage {
            name: String::new(),
            bandwidth_mb: None,
            quota_mb: None,
            domains: None,
            subdomains: None,
            email_accounts: None,
            email_forwarders: None,
            email_mailing_lists: None,
            email_autoresponders: None,
            ftp_accounts: None,
            mysql_databases: None,
            inodes: None,
            dns_control: true,
            cgi: true,
            php: true,
            spam: true,
            ssl: true,
            ssh: false,           // default off; opt-in feature
            suspend_at_limit: true,
            language: "en".to_string(),
            ip: "shared".to_string(),
            skin: "evolution".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaUserUsage {
    pub bandwidth_mb: u64,
    pub bandwidth_quota_mb: Option<u64>,
    pub disk_mb: u64,
    pub disk_quota_mb: Option<u64>,
    pub domains: u32,
    pub email_accounts: u32,
    pub mysql_databases: u32,
    pub ftp_accounts: u32,
    pub subdomains: u32,
    pub inodes: u64,
    pub inodes_quota: Option<u64>,
    pub vdomains_quota: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaSiteBackup {
    pub filename: String,
    pub size_bytes: u64,
    pub created: String,
    pub user: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaEmailForwarder {
    pub user: String,
    pub destinations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaAutoresponder {
    pub user: String,
    pub subject: String,
    pub body: String,
    pub cc: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaVacation {
    pub user: String,
    pub message: String,
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaCatchAll {
    /// One of: `address` (forward to a single mailbox), `fail` (550),
    /// `blackhole` (silently discard), `ignore` (DA default routing).
    pub mode: String,
    pub destination: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaDbUser {
    pub user: String,
    pub databases: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaDomainPointer {
    pub from: String,
    pub to: String,
    pub alias: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaRedirect {
    pub path: String,
    pub destination: String,
    pub code: u16, // 301 / 302
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaCronJob {
    pub id: String,
    pub command: String,
    pub minute: String,
    pub hour: String,
    pub day_of_month: String,
    pub month: String,
    pub day_of_week: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaSshKey {
    pub key_id: String,
    pub label: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaMailingList {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaSpamSettings {
    pub enabled: bool,
    pub score_threshold: f32,
    pub action: String, // "tag", "subject", "deliver", "delete"
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaProtectedDir {
    pub path: String,
    pub realm: String,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaService {
    pub name: String,
    pub running: bool,
    pub auto_start: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaSystemInfo {
    pub kernel: String,
    pub uptime_seconds: u64,
    pub load_1m: f32,
    pub load_5m: f32,
    pub load_15m: f32,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub disk_used_pct: u32,
    pub directadmin_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaTwoFactorStatus {
    pub enabled: bool,
    pub method: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaEmailUsage {
    pub user: String,
    pub bytes: u64,
    pub quota_bytes: u64,
}

// ─── Password obfuscation (base64 XOR with a key) ───
//
// SECURITY NOTE: this is OBFUSCATION, not encryption. An attacker
// with the WolfHost binary and the data file can recover any
// stored DA admin password — XOR + base64 is reversible. The
// `OBFUSCATION_KEY` constant exists in source so this module can
// at least be one canonical place to swap in real AES-GCM later
// without touching ~26 callsites. Until that lands:
//   * Treat `admin_password_enc` as sensitive at-rest data.
//   * Restrict the data dir to mode 0700.
//   * Don't ship the binary with elevated trust assumptions.

const OBFUSCATION_KEY: &str = "wolfhost-da-key";

pub fn encode_password(plain: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    let encoded: Vec<u8> = plain.as_bytes().iter().enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&encoded)
}

pub fn decode_password(encoded: &str, key: &str) -> String {
    use base64::Engine;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return encoded.to_string(), // fallback: treat as plaintext
    };
    let key_bytes = key.as_bytes();
    let decoded: Vec<u8> = bytes.iter().enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(decoded).unwrap_or_else(|_| encoded.to_string())
}

/// Encode a plaintext password for at-rest storage in the
/// `admin_password_enc` field. Hides the obfuscation-key choice
/// from callers so they don't keep re-importing the constant.
pub fn obfuscate_password(plain: &str) -> String {
    encode_password(plain, OBFUSCATION_KEY)
}

/// Inverse of `obfuscate_password`. Falls back to the input verbatim
/// if it doesn't decode (e.g. legacy plaintext rows from before the
/// obfuscation was introduced).
pub fn deobfuscate_password(encoded: &str) -> String {
    decode_password(encoded, OBFUSCATION_KEY)
}

/// Build a ready-to-use `DaClient` from a stored instance. Replaces
/// the ~26 sites that each independently called
/// `decode_password(..., "wolfhost-da-key")` then
/// `DaClient::new(...)`. Centralises key rotation in one place.
pub fn client_for(instance: &crate::wolfhost::models::directadmin::DirectAdminInstance) -> DaClient {
    let pass = deobfuscate_password(&instance.admin_password_enc);
    DaClient::new(&instance.url, &instance.admin_user, &pass)
}

impl DaClient {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("HTTP client");
        DaClient {
            base_url: url.trim_end_matches('/').to_string(),
            admin_user: user.to_string(),
            admin_pass: pass.to_string(),
            client,
        }
    }

    /// GET request to DA API, returns parsed JSON
    async fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        let sep = if path.contains('?') { "&" } else { "?" };
        let url = format!("{}{}{}json=yes", self.base_url, path, sep);
        let resp = self.client.get(&url)
            .basic_auth(&self.admin_user, Some(&self.admin_pass))
            .send().await
            .map_err(|e| format!("DA request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("DA returned HTTP {}", resp.status()));
        }

        let body = resp.text().await.map_err(|e| format!("DA response read error: {}", e))?;
        serde_json::from_str(&body).map_err(|_| friendly_non_json_error(path, &body))
    }

    /// POST request to DA API with form-encoded body
    async fn post(&self, path: &str, params: &HashMap<&str, &str>) -> Result<serde_json::Value, String> {
        let sep = if path.contains('?') { "&" } else { "?" };
        let url = format!("{}{}{}json=yes", self.base_url, path, sep);
        let resp = self.client.post(&url)
            .basic_auth(&self.admin_user, Some(&self.admin_pass))
            .form(params)
            .send().await
            .map_err(|e| format!("DA request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // 405 Method Not Allowed almost always means DA's API
            // for this CMD has been disabled by the host (a common
            // hardening setting on managed DA boxes — `api_access`
            // restricts which endpoints accept POSTs). Translate
            // to something actionable rather than the raw status.
            if status.as_u16() == 405 {
                return Err(format!(
                    "DirectAdmin returned 405 Method Not Allowed for {}. \
                     This action is disabled at the host level — DA's `api_access` \
                     config blocks write operations on this endpoint. The host \
                     admin needs to enable it in directadmin.conf.",
                    path
                ));
            }
            // HTML body usually means the endpoint isn't supported
            // on this DA version (DA's web UI is served as a 404
            // catch-all).
            let body_lower = body.trim_start().to_ascii_lowercase();
            if body_lower.starts_with("<!doctype html") || body_lower.starts_with("<html") {
                return Err(format!(
                    "DirectAdmin's web UI was returned instead of an API response for {}. \
                     This DA version doesn't support that endpoint via the API.",
                    path
                ));
            }
            return Err(format!("DA returned HTTP {}: {}", status, body.chars().take(500).collect::<String>()));
        }

        let body = resp.text().await.map_err(|e| format!("DA response read error: {}", e))?;
        serde_json::from_str(&body).or_else(|_| Ok(serde_json::json!({"text": body})))
    }

    /// Check if DA is reachable and credentials work
    pub async fn test_connection(&self) -> Result<String, String> {
        let data = self.get("/CMD_API_SHOW_USERS").await?;
        // If we get a list back, we're authenticated
        let count = data.as_array().map(|a| a.len())
            .or_else(|| data.as_object().map(|o| o.len()))
            .unwrap_or(0);
        Ok(format!("Connected — {} users found", count))
    }

    // ─── Users ───

    pub async fn list_users(&self) -> Result<Vec<String>, String> {
        let data = self.get("/CMD_API_SHOW_USERS").await?;
        if let Some(arr) = data.as_array() {
            Ok(arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        } else if let Some(obj) = data.as_object() {
            // DA sometimes returns {"list": ["user1", "user2"]}
            if let Some(list) = obj.get("list").and_then(|v| v.as_array()) {
                Ok(list.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            } else {
                Ok(obj.keys().cloned().collect())
            }
        } else {
            Ok(vec![])
        }
    }

    pub async fn get_user_config(&self, user: &str) -> Result<DaUserConfig, String> {
        let data = self.get(&format!("/CMD_API_SHOW_USER_CONFIG?user={}", urlencoding::encode(user))).await?;
        Ok(DaUserConfig {
            username: user.to_string(),
            domain: data["domain"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().unwrap_or("").to_string(),
            bandwidth: data["bandwidth"].as_str().and_then(|s| s.parse().ok())
                .or_else(|| data["bandwidth"].as_u64()).unwrap_or(0),
            quota: data["quota"].as_str().and_then(|s| s.parse().ok())
                .or_else(|| data["quota"].as_u64()).unwrap_or(0),
            suspended: data["suspended"].as_str() == Some("yes")
                || data["suspended"].as_bool() == Some(true),
            package: data["package"].as_str().unwrap_or("default").to_string(),
        })
    }

    pub async fn create_user(&self, user: &str, email: &str, password: &str, domain: &str, package: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("add", "Submit");
        params.insert("username", user);
        params.insert("email", email);
        params.insert("passwd", password);
        params.insert("passwd2", password);
        params.insert("domain", domain);
        params.insert("package", package);
        let resp = self.post("/CMD_API_ACCOUNT_USER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn suspend_user(&self, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("suspend", "Suspend");
        params.insert("select0", user);
        let resp = self.post("/CMD_API_SELECT_USERS", &params).await?;
        check_da_error(&resp)
    }

    pub async fn unsuspend_user(&self, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("unsuspend", "Unsuspend");
        params.insert("select0", user);
        let resp = self.post("/CMD_API_SELECT_USERS", &params).await?;
        check_da_error(&resp)
    }

    // ─── Domains ───

    pub async fn list_domains(&self, user: &str) -> Result<Vec<String>, String> {
        let data = self.get(&format!("/CMD_API_SHOW_DOMAINS?user={}", urlencoding::encode(user))).await?;
        if let Some(arr) = data.as_array() {
            Ok(arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        } else if let Some(obj) = data.as_object() {
            if let Some(list) = obj.get("list").and_then(|v| v.as_array()) {
                Ok(list.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            } else {
                Ok(obj.keys().cloned().collect())
            }
        } else {
            Ok(vec![])
        }
    }

    pub async fn create_domain(&self, user: &str, domain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        let data = self.get(&format!("/CMD_API_DOMAIN?user={}&action=create&domain={}", urlencoding::encode(user), urlencoding::encode(domain))).await;
        // DA domain creation via GET with params
        match data {
            Ok(resp) => check_da_error(&resp),
            Err(_e) => {
                // Try POST as fallback
                let resp = self.post(&format!("/CMD_API_DOMAIN?user={}", urlencoding::encode(user)), &params).await?;
                check_da_error(&resp)
            }
        }
    }

    pub async fn delete_domain(&self, user: &str, domain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("confirmed", "Confirm");
        params.insert("delete", "yes");
        params.insert("select0", domain);
        let resp = self.post(&format!("/CMD_API_DOMAIN?user={}", urlencoding::encode(user)), &params).await?;
        check_da_error(&resp)
    }

    // ─── Email ───

    pub async fn list_email_accounts(&self, domain: &str) -> Result<Vec<DaEmailAccount>, String> {
        let data = self.get(&format!("/CMD_API_POP?domain={}&action=list", urlencoding::encode(domain))).await?;
        let mut accounts = Vec::new();
        if let Some(arr) = data.as_array() {
            // DA returns ["user1", "user2"] — plain username array
            for item in arr {
                if let Some(user) = item.as_str() {
                    accounts.push(DaEmailAccount {
                        user: user.to_string(),
                        domain: domain.to_string(),
                        quota_mb: 0,
                    });
                }
            }
        } else if let Some(obj) = data.as_object() {
            // DA sometimes returns {"user1": {"quota": 100}, ...}
            for (user, info) in obj {
                if user == "error" || user == "text" { continue; }
                let quota = info.get("quota").and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .or_else(|| info.get("quota").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                accounts.push(DaEmailAccount {
                    user: user.clone(),
                    domain: domain.to_string(),
                    quota_mb: quota,
                });
            }
        }
        Ok(accounts)
    }

    pub async fn create_email(&self, domain: &str, user: &str, password: &str, quota_mb: u64) -> Result<(), String> {
        let quota_str = quota_mb.to_string();
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        params.insert("user", user);
        params.insert("passwd", password);
        params.insert("passwd2", password);
        params.insert("quota", &quota_str);
        let resp = self.post("/CMD_API_POP", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_email(&self, domain: &str, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("user", user);
        let resp = self.post("/CMD_API_POP", &params).await?;
        check_da_error(&resp)
    }

    // ─── Databases ───

    pub async fn list_databases(&self, user: &str) -> Result<Vec<DaDatabase>, String> {
        let data = self.get(&format!("/CMD_API_DATABASES?user={}", urlencoding::encode(user))).await?;
        let mut dbs = Vec::new();
        if let Some(arr) = data.as_array() {
            for item in arr {
                if let Some(name) = item.as_str() {
                    dbs.push(DaDatabase {
                        name: name.to_string(),
                        user: format!("{}_{}", user, name.split('_').last().unwrap_or(name)),
                    });
                }
            }
        } else if let Some(obj) = data.as_object() {
            if let Some(list) = obj.get("list").and_then(|v| v.as_array()) {
                for item in list {
                    if let Some(name) = item.as_str() {
                        dbs.push(DaDatabase { name: name.to_string(), user: name.to_string() });
                    }
                }
            } else {
                for key in obj.keys() {
                    if key == "error" || key == "text" { continue; }
                    dbs.push(DaDatabase { name: key.clone(), user: key.clone() });
                }
            }
        }
        Ok(dbs)
    }

    pub async fn create_database(&self, user: &str, db_name: &str, db_user: &str, password: &str) -> Result<(), String> {
        // Pre-flight: probe whether the DA box actually has the
        // database API wired at all. If `list_databases` errors
        // (HTML response, 404, JSON-parse failure) before we even
        // try to write, surface a clear "MySQL/MariaDB isn't
        // enabled on this DA host" instead of a confusing post-
        // create verification failure. This covers three common
        // failure modes:
        //   * MariaDB / MySQL daemon not installed on the DA host
        //   * DA's MySQL plugin disabled in directadmin.conf
        //     (`mysql=0`)
        //   * API endpoint blocked by host's `api_access` config
        if let Err(e) = self.list_databases(user).await {
            let lower = e.to_ascii_lowercase();
            if lower.contains("web ui") || lower.contains("not json") {
                return Err(
                    "DirectAdmin's database API is unreachable on this host — \
                     MariaDB/MySQL is probably not installed or not enabled in DA's \
                     configuration. Run `cd /usr/local/directadmin/custombuild && \
                     ./build mariadb` on the DA host (or your distro's equivalent), \
                     then retry.".to_string()
                );
            }
            return Err(format!(
                "Couldn't talk to DirectAdmin's database API: {}. \
                 Verify MariaDB is installed and that the admin account can list databases.",
                e
            ));
        }

        // DirectAdmin enforces a `<account>_` prefix on every
        // database AND database-user name. Customers supplying just
        // `wordpress` would get rejected with a cryptic "Database
        // name must start with user_" — prepend the prefix here
        // (idempotent: skipped if the caller already qualified it).
        let prefix = format!("{}_", user);
        let qualified_name = if db_name.starts_with(&prefix) { db_name.to_string() } else { format!("{}{}", prefix, db_name) };
        let qualified_user = if db_user.starts_with(&prefix) { db_user.to_string() } else { format!("{}{}", prefix, db_user) };

        // The endpoint takes both URL `?user={da_user}` (which DA
        // account owns the DB) AND a `user=` form field (the DB
        // user being created). They're disambiguated by source on
        // the DA side. We also send `db_user` as a synonym because
        // a few DA builds parse the body that way instead.
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("name", qualified_name.as_str());
        params.insert("user", qualified_user.as_str());
        params.insert("db_user", qualified_user.as_str());
        params.insert("passwd", password);
        params.insert("passwd2", password);
        let resp = self.post(&format!("/CMD_API_DATABASES?user={}", urlencoding::encode(user)), &params).await?;
        // `check_da_error` only catches DA's structured error
        // (`error=1` + `text=...`). Some failure modes return
        // success-shaped responses with the actual error in the
        // `text` or `details` field (e.g. password-policy
        // rejections). Surface those too.
        check_da_error(&resp)?;
        if let Some(details) = resp.get("details").and_then(|v| v.as_str()) {
            let lower = details.to_ascii_lowercase();
            if lower.contains("error") || lower.contains("invalid") || lower.contains("must") {
                return Err(format!("DirectAdmin: {}", details));
            }
        }
        // Verify by reading back. If DA returned a success-shaped
        // JSON but the database isn't in the user's list, that's a
        // real failure — surface DA's response so the operator can
        // see what's going on (often a quota issue: the user's
        // package may have `mysql=0`).
        match self.list_databases(user).await {
            Ok(dbs) => {
                let exists = dbs.iter().any(|d| d.name == qualified_name);
                if !exists {
                    let body_snippet = serde_json::to_string(&resp).unwrap_or_default()
                        .chars().take(300).collect::<String>();
                    return Err(format!(
                        "DirectAdmin returned success but `{}` is not in the user's database list. \
                         Most likely the package's MySQL quota is `0` (DA Admin → Packages → set `mysql` > 0) \
                         or DA's database API rejected the request silently. Response body: {}",
                        qualified_name, body_snippet,
                    ));
                }
            }
            Err(_) => {
                // Pre-flight succeeded; if the post-create list
                // suddenly fails, treat it as a transient DA hiccup
                // and trust the success response.
            }
        }
        Ok(())
    }

    pub async fn delete_database(&self, user: &str, db_name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("select0", db_name);
        let resp = self.post(&format!("/CMD_API_DATABASES?user={}", urlencoding::encode(user)), &params).await?;
        check_da_error(&resp)
    }

    // ─── SSL ───

    pub async fn get_ssl_info(&self, domain: &str) -> Result<DaSslInfo, String> {
        let data = self.get(&format!("/CMD_API_SSL?domain={}", urlencoding::encode(domain))).await?;
        // DA's response shape varies wildly across versions and cert
        // sources (LE vs paste vs system). We treat the cert as
        // "enabled" if ANY positive evidence shows up:
        //   * an explicit `enabled=yes` flag (older DA),
        //   * a non-empty `cert` PEM block (DA returns the cert
        //     contents inline),
        //   * a populated `SSLCertificateFile` (paths-based config),
        //   * a non-empty expiry date (`not_after`, `not_after_str`,
        //     `valid_until`, `expires_in_days` > 0). DA only emits an
        //     expiry when there's actually a cert installed.
        let pop_str = |k: &str| data.get(k).and_then(|v| v.as_str())
            .map(|s| s.trim().to_string()).unwrap_or_default();
        let has_yes = pop_str("enabled") == "yes";
        let has_force_https = pop_str("force_ssl") == "yes" || pop_str("force_https") == "yes";
        let cert_pem = pop_str("cert");
        let cert_present = !cert_pem.is_empty()
            || data.get("SSLCertificateFile").is_some()
            || data.get("ssl_certificate_file").is_some();

        // Try DA's metadata fields first — they're cheap and what
        // some versions emit instead of the cert body.
        let mut expires = ["not_after", "not_after_str", "valid_until", "expires", "expiry"]
            .iter()
            .find_map(|k| {
                let v = pop_str(k);
                if v.is_empty() { None } else { Some(v) }
            })
            .unwrap_or_default();

        // Fallback: parse the actual cert PEM if DA gave it to us.
        // DA's `cert` field varies version to version, but when it's
        // there it's the authoritative source — the metadata fields
        // can be missing or stale, the X509's notAfter never lies.
        if expires.is_empty() && !cert_pem.is_empty() {
            if let Some(pem_block) = cert_pem.find("-----BEGIN CERTIFICATE-----")
                .map(|i| &cert_pem[i..]) {
                if let Ok(x509) = openssl::x509::X509::from_pem(pem_block.as_bytes()) {
                    // ASN1 time prints in DA's preferred format
                    // ("MMM DD HH:MM:SS YYYY GMT"). The portal
                    // formats with formatDate() so any parseable
                    // string works.
                    expires = x509.not_after().to_string();
                }
            }
        }

        // Last-resort: if DA only gives us "expires_in_days", roll
        // that forward from now so the operator at least sees a
        // ballpark date instead of "—".
        if expires.is_empty() {
            if let Some(days) = data.get("expires_in_days").and_then(|v| v.as_str())
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|d| *d > 0) {
                let when = chrono::Utc::now() + chrono::Duration::days(days);
                expires = when.to_rfc3339();
            }
        }

        let expiry_implies_cert = !expires.is_empty()
            || data.get("expires_in_days").and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok()).map(|d| d > 0).unwrap_or(false);
        Ok(DaSslInfo {
            enabled: has_yes || has_force_https || cert_present || expiry_implies_cert,
            expires,
        })
    }

    pub async fn request_letsencrypt(&self, domain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("domain", domain);
        params.insert("action", "save");
        params.insert("type", "create");
        params.insert("request", "letsencrypt");
        params.insert("le_select0", domain);
        params.insert("le_wc_select0", domain);
        let resp = self.post("/CMD_API_SSL", &params).await?;
        check_da_error(&resp)
    }

    // ─── File Manager ───

    pub async fn list_files(&self, path: &str) -> Result<Vec<DaFileEntry>, String> {
        let data = self.get(&format!("/CMD_API_FILE_MANAGER?action=list&path={}", urlencoding::encode(path))).await?;
        let mut entries = Vec::new();
        if let Some(obj) = data.as_object() {
            for (filepath, info) in obj {
                if filepath == "error" || filepath == "text" { continue; }
                // info is either a string (URL-encoded) or an object
                let (file_type, size, permission) = if let Some(s) = info.as_str() {
                    // URL-encoded string: parse key=value pairs
                    let params: std::collections::HashMap<String, String> = s.split('&')
                        .filter_map(|p| p.split_once('='))
                        .map(|(k, v)| (k.to_string(), urlencoding::decode(v).unwrap_or_default().to_string()))
                        .collect();
                    (
                        params.get("type").cloned().unwrap_or_default(),
                        params.get("size").and_then(|s| s.parse().ok()).unwrap_or(0u64),
                        params.get("permission").cloned().unwrap_or_default(),
                    )
                } else {
                    // JSON object
                    let t = info.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let s = info.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                    let p = info.get("permission").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    (t, s, p)
                };
                let name = filepath.rsplit('/').next().unwrap_or(filepath).to_string();
                entries.push(DaFileEntry {
                    name,
                    path: filepath.clone(),
                    is_dir: file_type == "dir",
                    size,
                    permission,
                });
            }
        }
        entries.sort_by(|a, b| {
            // Dirs first, then alphabetical
            b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name))
        });
        Ok(entries)
    }

    pub async fn read_file(&self, path: &str) -> Result<String, String> {
        let data = self.get(&format!("/CMD_API_FILE_MANAGER?action=edit&path={}", urlencoding::encode(path))).await?;
        // DA returns {"text": "file content"} or the content directly
        if let Some(text) = data.get("text").and_then(|v| v.as_str()) {
            Ok(text.to_string())
        } else if let Some(s) = data.as_str() {
            Ok(s.to_string())
        } else {
            Ok(data.to_string())
        }
    }

    pub async fn write_file(&self, path: &str, content: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("path", path);
        params.insert("text", content);
        let resp = self.post("/CMD_API_FILE_MANAGER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_file(&self, path: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("select0", path);
        let resp = self.post("/CMD_API_FILE_MANAGER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "folder");
        params.insert("path", path);
        let resp = self.post("/CMD_API_FILE_MANAGER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn rename_file(&self, from: &str, to: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "rename");
        params.insert("old", from);
        params.insert("new", to);
        let resp = self.post("/CMD_API_FILE_MANAGER", &params).await?;
        check_da_error(&resp)
    }

    // ─── DNS ───

    pub async fn list_dns_records(&self, domain: &str) -> Result<Vec<DaDnsRecord>, String> {
        let data = self.get(&format!("/CMD_API_DNS_CONTROL?domain={}", urlencoding::encode(domain))).await?;
        let mut records = Vec::new();
        if let Some(arr) = data.get("records").and_then(|v| v.as_array()) {
            for r in arr {
                records.push(DaDnsRecord {
                    record_type: r["type"].as_str().unwrap_or("").to_string(),
                    name: r["name"].as_str().unwrap_or("").to_string(),
                    value: r["value"].as_str().unwrap_or("").to_string(),
                    ttl: r["ttl"].as_str().and_then(|s| s.parse().ok())
                        .or_else(|| r["ttl"].as_u64().map(|v| v as u32))
                        .unwrap_or(3600),
                });
            }
        }
        Ok(records)
    }

    pub async fn add_dns_record(&self, domain: &str, record_type: &str, name: &str, value: &str, ttl: u32) -> Result<(), String> {
        let ttl_str = ttl.to_string();
        let mut params = HashMap::new();
        params.insert("domain", domain);
        params.insert("action", "add");
        params.insert("type", record_type);
        params.insert("name", name);
        params.insert("value", value);
        params.insert("ttl", &ttl_str);
        let resp = self.post("/CMD_API_DNS_CONTROL", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_dns_record(&self, domain: &str, record_type: &str, name: &str, value: &str) -> Result<(), String> {
        let rec_key = format!("{}_recs0", record_type.to_lowercase());
        let combined = format!("name={}&value={}", name, value);
        let mut params = HashMap::new();
        params.insert("domain", domain);
        params.insert("action", "select");
        params.insert("delete", "Delete Selected");
        params.insert(&rec_key, &combined);
        let resp = self.post("/CMD_API_DNS_CONTROL", &params).await?;
        check_da_error(&resp)
    }

    // ─── Subdomains ───

    pub async fn list_subdomains(&self, domain: &str) -> Result<Vec<String>, String> {
        let data = self.get(&format!("/CMD_API_SUBDOMAINS?domain={}", urlencoding::encode(domain))).await?;
        if let Some(arr) = data.as_array() {
            Ok(arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        } else {
            Ok(vec![])
        }
    }

    pub async fn create_subdomain(&self, domain: &str, subdomain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        params.insert("subdomain", subdomain);
        let resp = self.post("/CMD_API_SUBDOMAINS", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_subdomain(&self, domain: &str, subdomain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", subdomain);
        let resp = self.post("/CMD_API_SUBDOMAINS", &params).await?;
        check_da_error(&resp)
    }

    // ─── FTP ───

    pub async fn list_ftp_accounts(&self, user: &str) -> Result<Vec<DaFtpAccount>, String> {
        let data = self.get(&format!("/CMD_API_FTP?action=list&user={}", urlencoding::encode(user))).await?;
        let mut accounts = Vec::new();
        if let Some(obj) = data.as_object() {
            for (ftp_user, info) in obj {
                if ftp_user == "error" || ftp_user == "text" { continue; }
                let dir = info.get("path").and_then(|v| v.as_str())
                    .or_else(|| info.get("directory").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                accounts.push(DaFtpAccount {
                    user: ftp_user.clone(),
                    directory: dir,
                });
            }
        }
        Ok(accounts)
    }

    pub async fn create_ftp(&self, user: &str, ftp_user: &str, password: &str, domain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("user", ftp_user);
        params.insert("type", "custom");
        params.insert("passwd", password);
        params.insert("passwd2", password);
        params.insert("domain", domain);
        let resp = self.post(&format!("/CMD_API_FTP?user={}", urlencoding::encode(user)), &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_ftp(&self, user: &str, ftp_user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("select0", ftp_user);
        let resp = self.post(&format!("/CMD_API_FTP?user={}", urlencoding::encode(user)), &params).await?;
        check_da_error(&resp)
    }

    // ─── SSO login keys (CMD_API_LOGIN_KEYS) ───
    //
    // DirectAdmin lets us create a one-time login URL on behalf of a
    // user. The customer clicks a button in WolfHost's portal and lands
    // straight in the DA control panel without typing a password.
    //
    // The two flavours we expose:
    //   * `create_one_time_login_url` — single-use, expires in 60s,
    //     ideal for the "Open DirectAdmin" button.
    //   * `create_session_url` — short-lived URL good for ~10 min,
    //     useful for embedding the panel in an iframe.
    //
    // Both return a fully-formed URL the operator can redirect to.

    pub async fn create_one_time_login_url(&self, user: &str) -> Result<String, String> {
        let key_name = format!("wolfhost-otp-{}", chrono::Utc::now().timestamp_millis());
        // DA's CMD_API_LOGIN_KEYS wants the creator's password posted
        // as `passwd` / `passwd2` form fields, even when the request
        // is HTTP-basic-authed with the same credentials. Without
        // these the endpoint silently returns no `key` / no `url`
        // and we fall through to the "no login URL" error. Reference:
        // https://docs.directadmin.com/directadmin/customer-features/login-keys.html
        let params: HashMap<&str, &str> = [
            ("action", "create"),
            ("type", "one_time_url"),
            ("login_keyname", key_name.as_str()),
            ("passwd", self.admin_pass.as_str()),
            ("passwd2", self.admin_pass.as_str()),
            ("expiry", "60s"),
            ("max_uses", "1"),
            ("clear_key", "yes"),
            ("never_expires", "no"),
            ("login_id", user),
        ].into_iter().collect();
        let resp = self.post("/CMD_API_LOGIN_KEYS", &params).await?;
        check_da_error(&resp)?;
        // DA returns either {"key":"..."} or a `text=...` URL. Build a
        // canonical URL the caller can redirect to.
        if let Some(url) = resp.get("url").and_then(|v| v.as_str()) {
            if url.starts_with("http") { return Ok(url.to_string()); }
        }
        if let Some(key) = resp.get("key").and_then(|v| v.as_str()) {
            if !key.is_empty() {
                return Ok(format!(
                    "{}/CMD_LOGIN?username={}&key={}",
                    self.base_url, urlencoding::encode(user), urlencoding::encode(key),
                ));
            }
        }
        // Fallback: parse the URL out of a `text` field that some DA
        // builds emit with the URL embedded.
        if let Some(text) = resp.get("text").and_then(|v| v.as_str()) {
            if text.starts_with("http") { return Ok(text.to_string()); }
        }
        // Surface DA's actual response so the operator can debug.
        // Truncate to keep the error toast readable.
        Err(format!(
            "DirectAdmin returned no login key. Response keys: [{}]. Body: {}",
            resp.as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "<not an object>".to_string()),
            serde_json::to_string(&resp).unwrap_or_default().chars().take(300).collect::<String>(),
        ))
    }

    // ─── Packages / user resource plans (CMD_API_PACKAGES_USER) ───
    //
    // A "package" in DA is the set of resource limits (bandwidth,
    // disk quota, max domains, max email accounts, max databases,
    // …) that a user account inherits. WolfHost models its own
    // hosting plans locally; these methods let WolfHost sync those
    // plans onto DA so `create_user(..., package=…)` actually has
    // something to attach to.

    pub async fn list_packages(&self) -> Result<Vec<String>, String> {
        let data = self.get("/CMD_API_PACKAGES_USER").await?;
        if let Some(arr) = data.as_array() {
            Ok(arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        } else if let Some(obj) = data.as_object() {
            if let Some(list) = obj.get("list").and_then(|v| v.as_array()) {
                Ok(list.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            } else {
                Ok(obj.keys().filter(|k| *k != "error" && *k != "text").cloned().collect())
            }
        } else {
            Ok(vec![])
        }
    }

    pub async fn create_package(&self, pkg: &DaPackage) -> Result<(), String> {
        self.upsert_package(pkg, /*action=*/"create").await
    }

    pub async fn modify_package(&self, pkg: &DaPackage) -> Result<(), String> {
        self.upsert_package(pkg, /*action=*/"modify").await
    }

    async fn upsert_package(&self, pkg: &DaPackage, action: &str) -> Result<(), String> {
        // Owned strings — params is &str-keyed/-valued and HashMap
        // doesn't accept owned values directly inline.
        let bw = quota_to_da(pkg.bandwidth_mb);
        let q = quota_to_da(pkg.quota_mb);
        let domains = count_to_da(pkg.domains);
        let subdomains = count_to_da(pkg.subdomains);
        let emails = count_to_da(pkg.email_accounts);
        let fwd = count_to_da(pkg.email_forwarders);
        let mlists = count_to_da(pkg.email_mailing_lists);
        let auto = count_to_da(pkg.email_autoresponders);
        let ftp = count_to_da(pkg.ftp_accounts);
        let mysql = count_to_da(pkg.mysql_databases);
        let inodes = count_to_da(pkg.inodes);
        let on = "ON";
        let off = "OFF";
        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("action", action);
        params.insert("add", "Save");
        params.insert("package", &pkg.name);
        params.insert("bandwidth", &bw);
        params.insert("quota", &q);
        params.insert("vdomains", &domains);
        params.insert("nsubdomains", &subdomains);
        params.insert("nemails", &emails);
        params.insert("nemailf", &fwd);
        params.insert("nemailml", &mlists);
        params.insert("nemailr", &auto);
        params.insert("ftp", &ftp);
        params.insert("mysql", &mysql);
        params.insert("inode", &inodes);
        params.insert("dnscontrol", if pkg.dns_control { on } else { off });
        params.insert("cgi", if pkg.cgi { on } else { off });
        params.insert("php", if pkg.php { on } else { off });
        params.insert("spam", if pkg.spam { on } else { off });
        params.insert("ssl", if pkg.ssl { on } else { off });
        params.insert("ssh", if pkg.ssh { on } else { off });
        params.insert("suspend_at_limit", if pkg.suspend_at_limit { on } else { off });
        params.insert("language", &pkg.language);
        params.insert("ip", &pkg.ip);
        params.insert("skin", &pkg.skin);
        let resp = self.post("/CMD_API_PACKAGES_USER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_package(&self, name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("delete", "Confirm");
        params.insert("confirmed", "Confirm");
        params.insert("select0", name);
        let resp = self.post("/CMD_API_PACKAGES_USER", &params).await?;
        check_da_error(&resp)
    }
}


/// Same for count-type fields (domains, email accounts, etc).
fn parse_da_count(v: Option<&serde_json::Value>) -> Option<u32> {
    let s = v?.as_str()?;
    if s.eq_ignore_ascii_case("unlimited") || s.is_empty() { return None; }
    s.parse().ok()
}

/// Render a `Some(MB)` / `None` quota back into DA's string format —
/// "unlimited" or the integer.
fn quota_to_da(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "unlimited".to_string(),
    }
}

fn count_to_da(v: Option<u32>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "unlimited".to_string(),
    }
}

// ─── Resource usage / bandwidth ────────────────────────────────────
impl DaClient {
    /// Read accurate disk + bandwidth usage straight from DA. The
    /// portal previously fell back to local guesses; this is the
    /// authoritative source for billing-relevant numbers.
    pub async fn get_user_usage(&self, user: &str) -> Result<DaUserUsage, String> {
        let data = self.get(&format!(
            "/CMD_API_SHOW_USER_USAGE?user={}",
            urlencoding::encode(user),
        )).await?;
        // DA returns a flat object with string values. Some fields
        // include "Used/Limit" pairs in `bandwidth` (e.g. "1234.5/100000")
        // and we want them split.
        let split_used_limit = |raw: &str| -> (u64, Option<u64>) {
            if let Some((used, limit)) = raw.split_once('/') {
                let u = used.trim().parse::<f64>().unwrap_or(0.0) as u64;
                let lim_trim = limit.trim();
                let l = if lim_trim.eq_ignore_ascii_case("unlimited") { None }
                    else { lim_trim.parse::<f64>().ok().map(|v| v as u64) };
                return (u, l);
            }
            (raw.trim().parse::<f64>().unwrap_or(0.0) as u64, None)
        };

        let bw_raw = data.get("bandwidth").and_then(|v| v.as_str()).unwrap_or("0");
        let (bw_used, bw_limit) = split_used_limit(bw_raw);
        let q_raw = data.get("quota").and_then(|v| v.as_str()).unwrap_or("0");
        let (q_used, q_limit) = split_used_limit(q_raw);
        let inode_raw = data.get("inode").and_then(|v| v.as_str()).unwrap_or("0");
        let (inode_used, inode_limit) = split_used_limit(inode_raw);

        Ok(DaUserUsage {
            bandwidth_mb: bw_used,
            bandwidth_quota_mb: bw_limit,
            disk_mb: q_used,
            disk_quota_mb: q_limit,
            domains: parse_da_count(data.get("vdomains")).unwrap_or(0),
            email_accounts: parse_da_count(data.get("nemails")).unwrap_or(0),
            mysql_databases: parse_da_count(data.get("mysql")).unwrap_or(0),
            ftp_accounts: parse_da_count(data.get("ftp")).unwrap_or(0),
            subdomains: parse_da_count(data.get("nsubdomains")).unwrap_or(0),
            inodes: inode_used,
            inodes_quota: inode_limit,
            vdomains_quota: parse_da_count(data.get("vdomains_limit")),
        })
    }
}

// ─── User-level backups (CMD_API_SITE_BACKUP) ─────────────────────
//
// DA exposes two backup paths: admin-driven `CMD_API_USER_BACKUP`
// (one big snapshot of every account) and user-driven
// `CMD_API_SITE_BACKUP` (the customer can back up + restore their
// own data). WolfHost portal uses the latter so customers can
// self-serve; admin reseller flows can still call the former
// directly when needed.
impl DaClient {
    pub async fn list_user_backups(&self, user: &str) -> Result<Vec<DaSiteBackup>, String> {
        let data = self.get(&format!(
            "/CMD_API_SITE_BACKUP?user={}&action=list",
            urlencoding::encode(user),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (filename, info) in obj {
                if filename == "error" || filename == "text" { continue; }
                let size = info.get("size").and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .or_else(|| info.get("size").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                let created = info.get("date").and_then(|v| v.as_str())
                    .or_else(|| info.get("created").and_then(|v| v.as_str()))
                    .unwrap_or("").to_string();
                out.push(DaSiteBackup {
                    filename: filename.clone(),
                    size_bytes: size,
                    created,
                    user: user.to_string(),
                });
            }
        }
        out.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(out)
    }

    /// Trigger a backup of the user's data. `what` selects which
    /// areas to include — DA accepts a comma-separated list:
    /// `domain`, `subdomain`, `email`, `email_data`, `forwarder`,
    /// `vacation`, `autoresponder`, `list`, `ftp`, `ftpsettings`,
    /// `database`, `database_data`, `dns`. `"all"` is a WolfHost
    /// shorthand we expand to every flag.
    pub async fn create_user_backup(&self, user: &str, what: &str) -> Result<(), String> {
        let included = if what.eq_ignore_ascii_case("all") {
            "domain,subdomain,email,email_data,forwarder,vacation,autoresponder,list,ftp,ftpsettings,database,database_data,dns".to_string()
        } else {
            what.to_string()
        };
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("user", user);
        params.insert("what", included.as_str());
        let resp = self.post("/CMD_API_SITE_BACKUP", &params).await?;
        check_da_error(&resp)
    }

    pub async fn restore_user_backup(&self, user: &str, filename: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "restore");
        params.insert("user", user);
        params.insert("file", filename);
        let resp = self.post("/CMD_API_SITE_BACKUP", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_user_backup(&self, user: &str, filename: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("user", user);
        params.insert("select0", filename);
        let resp = self.post("/CMD_API_SITE_BACKUP", &params).await?;
        check_da_error(&resp)
    }

    /// Download a backup tarball from `/home/<user>/backups/<filename>`
    /// using DA's file-manager download endpoint. The file-manager
    /// download URL serves raw bytes when authenticated; we don't
    /// need the JSON wrapper. Increased timeout because backups are
    /// hundreds of MB on real accounts and we don't want a 30s
    /// timeout to kill a healthy long-running download.
    pub async fn download_user_backup(&self, user: &str, filename: &str) -> Result<Vec<u8>, String> {
        let path = format!("/home/{}/backups/{}", user, filename);
        let url = format!(
            "{}/CMD_FILE_MANAGER?action=download&path={}",
            self.base_url,
            urlencoding::encode(&path),
        );
        // Build a per-call client with a long timeout — the shared
        // `self.client` has a 30s timeout that's fine for JSON API
        // calls but kills any backup over ~50 MB on a slow link.
        let big_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(60 * 30))
            .build()
            .map_err(|e| format!("HTTP client build: {}", e))?;
        let resp = big_client.get(&url)
            .basic_auth(&self.admin_user, Some(&self.admin_pass))
            .send().await
            .map_err(|e| format!("Backup download request failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("DA returned HTTP {} for backup download", resp.status()));
        }
        let bytes = resp.bytes().await
            .map_err(|e| format!("Backup body read failed: {}", e))?;
        Ok(bytes.to_vec())
    }
}

// ─── Password changes ─────────────────────────────────────────────
impl DaClient {
    /// Change a user's main account password. Requires admin/reseller
    /// auth — the customer's own portal session can change their
    /// password via the WolfStack-side credential store, but rotating
    /// the DA-side password also requires hitting this endpoint.
    pub async fn change_user_password(&self, user: &str, new_password: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("username", user);
        params.insert("passwd", new_password);
        params.insert("passwd2", new_password);
        let resp = self.post("/CMD_API_USER_PASSWD", &params).await?;
        check_da_error(&resp)
    }

    pub async fn change_email_password(&self, domain: &str, user: &str, new_password: &str) -> Result<(), String> {
        // DA's CMD_API_POP supports action=modify with a new passwd.
        let mut params = HashMap::new();
        params.insert("action", "modify");
        params.insert("domain", domain);
        params.insert("user", user);
        params.insert("passwd", new_password);
        params.insert("passwd2", new_password);
        let resp = self.post("/CMD_API_POP", &params).await?;
        check_da_error(&resp)
    }

    pub async fn change_db_user_password(&self, user: &str, db_user: &str, new_password: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "PasswordChange");
        params.insert("name", db_user);
        params.insert("passwd", new_password);
        params.insert("passwd2", new_password);
        let resp = self.post(&format!(
            "/CMD_API_DATABASES?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }

    pub async fn change_ftp_password(&self, user: &str, ftp_user: &str, new_password: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "modify");
        params.insert("user", ftp_user);
        params.insert("passwd", new_password);
        params.insert("passwd2", new_password);
        let resp = self.post(&format!(
            "/CMD_API_FTP?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }

    /// Resize an FTP account's home directory quota. `quota_mb=None`
    /// means "no limit" (DA's `unlimited`).
    pub async fn set_ftp_quota(&self, user: &str, ftp_user: &str, quota_mb: Option<u64>) -> Result<(), String> {
        let q = quota_to_da(quota_mb);
        let mut params = HashMap::new();
        params.insert("action", "modify");
        params.insert("user", ftp_user);
        params.insert("quota", q.as_str());
        let resp = self.post(&format!(
            "/CMD_API_FTP?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }
}

// ─── Email forwarders (CMD_API_EMAIL_FORWARDERS) ──────────────────
impl DaClient {
    pub async fn list_email_forwarders(&self, domain: &str) -> Result<Vec<DaEmailForwarder>, String> {
        let data = self.get(&format!(
            "/CMD_API_EMAIL_FORWARDERS?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (user, dests) in obj {
                if user == "error" || user == "text" { continue; }
                // DA returns the destinations as a comma-separated
                // string (sometimes URL-encoded).
                let raw = dests.as_str().unwrap_or("");
                let decoded = urlencoding::decode(raw).unwrap_or_default().to_string();
                let destinations: Vec<String> = decoded.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                out.push(DaEmailForwarder { user: user.clone(), destinations });
            }
        }
        Ok(out)
    }

    pub async fn create_email_forwarder(&self, domain: &str, user: &str, destinations: &[String]) -> Result<(), String> {
        let dest_str = destinations.join(",");
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        params.insert("user", user);
        params.insert("email", dest_str.as_str());
        let resp = self.post("/CMD_API_EMAIL_FORWARDERS", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_email_forwarder(&self, domain: &str, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", user);
        let resp = self.post("/CMD_API_EMAIL_FORWARDERS", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Autoresponders (CMD_API_EMAIL_AUTORESPONDER) ─────────────────
impl DaClient {
    pub async fn list_autoresponders(&self, domain: &str) -> Result<Vec<DaAutoresponder>, String> {
        let data = self.get(&format!(
            "/CMD_API_EMAIL_AUTORESPONDER?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (user, info) in obj {
                if user == "error" || user == "text" { continue; }
                let subject = info.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let body = info.get("text").and_then(|v| v.as_str())
                    .or_else(|| info.get("body").and_then(|v| v.as_str()))
                    .unwrap_or("").to_string();
                let cc = info.get("cc").and_then(|v| v.as_str()).unwrap_or("").to_string();
                out.push(DaAutoresponder {
                    user: user.clone(),
                    subject,
                    body: urlencoding::decode(&body).unwrap_or_default().to_string(),
                    cc,
                });
            }
        }
        Ok(out)
    }

    pub async fn create_autoresponder(&self, domain: &str, user: &str, subject: &str, body: &str, cc: Option<&str>) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        params.insert("user", user);
        params.insert("subject", subject);
        params.insert("text", body);
        if let Some(cc) = cc {
            params.insert("cc", cc);
        }
        let resp = self.post("/CMD_API_EMAIL_AUTORESPONDER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_autoresponder(&self, domain: &str, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", user);
        let resp = self.post("/CMD_API_EMAIL_AUTORESPONDER", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Vacation messages (CMD_API_EMAIL_VACATION) ───────────────────
impl DaClient {
    pub async fn list_vacation_messages(&self, domain: &str) -> Result<Vec<DaVacation>, String> {
        let data = self.get(&format!(
            "/CMD_API_EMAIL_VACATION?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (user, info) in obj {
                if user == "error" || user == "text" { continue; }
                let message = info.get("text").and_then(|v| v.as_str())
                    .or_else(|| info.get("reply").and_then(|v| v.as_str()))
                    .unwrap_or("").to_string();
                let start = info.get("starttime").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let end = info.get("endtime").and_then(|v| v.as_str()).unwrap_or("").to_string();
                out.push(DaVacation {
                    user: user.clone(),
                    message: urlencoding::decode(&message).unwrap_or_default().to_string(),
                    start,
                    end,
                });
            }
        }
        Ok(out)
    }

    pub async fn create_vacation(&self, domain: &str, user: &str, message: &str, start: &str, end: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        params.insert("user", user);
        params.insert("text", message);
        params.insert("starttime", start);
        params.insert("endtime", end);
        let resp = self.post("/CMD_API_EMAIL_VACATION", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_vacation(&self, domain: &str, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", user);
        let resp = self.post("/CMD_API_EMAIL_VACATION", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Catch-all + local-mail toggle (CMD_API_EMAIL_CATCH_ALL/MX) ───
impl DaClient {
    pub async fn get_catch_all(&self, domain: &str) -> Result<DaCatchAll, String> {
        let data = self.get(&format!(
            "/CMD_API_EMAIL_CATCH_ALL?domain={}",
            urlencoding::encode(domain),
        )).await?;
        let mode = data.get("type").and_then(|v| v.as_str())
            .or_else(|| data.get("mode").and_then(|v| v.as_str()))
            .unwrap_or("ignore").to_string();
        let destination = data.get("address").and_then(|v| v.as_str())
            .or_else(|| data.get("destination").and_then(|v| v.as_str()))
            .unwrap_or("").to_string();
        Ok(DaCatchAll { mode, destination })
    }

    pub async fn set_catch_all(&self, domain: &str, mode: &str, destination: &str) -> Result<(), String> {
        // mode: address | fail | blackhole | ignore
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("domain", domain);
        params.insert("type", mode);
        if mode == "address" {
            params.insert("address", destination);
        }
        let resp = self.post("/CMD_API_EMAIL_CATCH_ALL", &params).await?;
        check_da_error(&resp)
    }

    pub async fn set_local_mail(&self, domain: &str, use_local: bool) -> Result<(), String> {
        // CMD_API_EMAIL_MX controls whether THIS server handles
        // mail for the domain (vs delegating to an external MX).
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("domain", domain);
        params.insert("internal", if use_local { "yes" } else { "no" });
        let resp = self.post("/CMD_API_EMAIL_MX", &params).await?;
        check_da_error(&resp)
    }

    /// Per-mailbox usage. Returns one entry per email account, each
    /// with current bytes used vs. the configured byte quota. Used
    /// by the customer portal's "Email" page so the operator can
    /// see the busiest mailboxes at a glance.
    pub async fn get_email_usage(&self, domain: &str) -> Result<Vec<DaEmailUsage>, String> {
        let data = self.get(&format!(
            "/CMD_API_EMAIL_USAGE?domain={}",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (user, info) in obj {
                if user == "error" || user == "text" { continue; }
                let bytes = info.get("bytes").and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .or_else(|| info.get("bytes").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                let quota = info.get("quota").and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .or_else(|| info.get("quota").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                out.push(DaEmailUsage {
                    user: user.clone(),
                    bytes,
                    quota_bytes: quota,
                });
            }
        }
        Ok(out)
    }
}

// ─── PHP version per domain (CMD_API_DOMAIN / CMD_API_PHP_SELECTOR) ─
impl DaClient {
    /// List PHP versions DA can switch this domain to. Returns the
    /// raw labels DA presents (e.g. `["8.1","8.2","8.3"]`), with
    /// the currently-selected version flagged separately via
    /// `get_domain_php_version`. The set is per-server, so callers
    /// should refresh it when the operator opens the "PHP version"
    /// page rather than caching.
    pub async fn list_php_versions(&self) -> Result<Vec<String>, String> {
        let data = self.get("/CMD_API_PHP_SELECTOR").await?;
        if let Some(arr) = data.get("versions").and_then(|v| v.as_array()) {
            return Ok(arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());
        }
        if let Some(obj) = data.as_object() {
            let mut out: Vec<String> = obj.keys()
                .filter(|k| *k != "error" && *k != "text" && k.chars().any(|c| c.is_ascii_digit()))
                .cloned().collect();
            out.sort();
            return Ok(out);
        }
        Ok(Vec::new())
    }

    pub async fn get_domain_php_version(&self, domain: &str) -> Result<String, String> {
        let data = self.get(&format!(
            "/CMD_API_DOMAIN?domain={}",
            urlencoding::encode(domain),
        )).await?;
        Ok(data.get("php_ver").and_then(|v| v.as_str())
            .or_else(|| data.get("php_version").and_then(|v| v.as_str()))
            .unwrap_or("").to_string())
    }

    pub async fn set_domain_php_version(&self, domain: &str, version: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "modify");
        params.insert("domain", domain);
        params.insert("php_ver", version);
        let resp = self.post("/CMD_API_DOMAIN", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Database users separate from databases (CMD_API_DATABASES) ───
impl DaClient {
    pub async fn list_db_users(&self, user: &str) -> Result<Vec<DaDbUser>, String> {
        let data = self.get(&format!(
            "/CMD_API_DATABASES?user={}&action=db_users",
            urlencoding::encode(user),
        )).await?;
        let mut out: Vec<DaDbUser> = Vec::new();
        if let Some(obj) = data.as_object() {
            for (db_user, dbs) in obj {
                if db_user == "error" || db_user == "text" { continue; }
                let raw = dbs.as_str().unwrap_or("");
                let databases: Vec<String> = raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                out.push(DaDbUser { user: db_user.clone(), databases });
            }
        }
        Ok(out)
    }

    pub async fn create_db_user(&self, user: &str, db_name: &str, db_user: &str, password: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create_user");
        params.insert("name", db_name);
        params.insert("user", db_user);
        params.insert("passwd", password);
        params.insert("passwd2", password);
        let resp = self.post(&format!(
            "/CMD_API_DATABASES?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_db_user(&self, user: &str, db_user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete_user");
        params.insert("select0", db_user);
        let resp = self.post(&format!(
            "/CMD_API_DATABASES?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }
}

// ─── Domain pointers / aliases (CMD_API_DOMAIN_POINTER) ───────────
impl DaClient {
    pub async fn list_pointers(&self, domain: &str) -> Result<Vec<DaDomainPointer>, String> {
        let data = self.get(&format!(
            "/CMD_API_DOMAIN_POINTER?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (from, info) in obj {
                if from == "error" || from == "text" { continue; }
                let alias_flag = info.as_str().map(|s| s == "alias")
                    .unwrap_or_else(|| info.get("type").and_then(|v| v.as_str()) == Some("alias"));
                out.push(DaDomainPointer {
                    from: from.clone(),
                    to: domain.to_string(),
                    alias: alias_flag,
                });
            }
        }
        Ok(out)
    }

    pub async fn create_pointer(&self, target_domain: &str, alias_from: &str, is_alias: bool) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "add");
        params.insert("domain", target_domain);
        params.insert("from", alias_from);
        if is_alias {
            params.insert("alias", "yes");
        }
        let resp = self.post("/CMD_API_DOMAIN_POINTER", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_pointer(&self, target_domain: &str, alias_from: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", target_domain);
        params.insert("select0", alias_from);
        let resp = self.post("/CMD_API_DOMAIN_POINTER", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Site redirects (CMD_API_REDIRECT) ────────────────────────────
impl DaClient {
    pub async fn list_redirects(&self, domain: &str) -> Result<Vec<DaRedirect>, String> {
        let data = self.get(&format!(
            "/CMD_API_REDIRECT?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (path, info) in obj {
                if path == "error" || path == "text" { continue; }
                let dest = info.get("destination").and_then(|v| v.as_str())
                    .or_else(|| info.as_str())
                    .unwrap_or("").to_string();
                let code = info.get("type").and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(301);
                out.push(DaRedirect {
                    path: path.clone(),
                    destination: dest,
                    code,
                });
            }
        }
        Ok(out)
    }

    pub async fn create_redirect(&self, domain: &str, path: &str, destination: &str, code: u16) -> Result<(), String> {
        let code_str = code.to_string();
        let mut params = HashMap::new();
        params.insert("action", "add");
        params.insert("domain", domain);
        params.insert("from", path);
        params.insert("redirect", destination);
        params.insert("type", code_str.as_str());
        let resp = self.post("/CMD_API_REDIRECT", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_redirect(&self, domain: &str, path: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", path);
        let resp = self.post("/CMD_API_REDIRECT", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Cron jobs (CMD_API_CRON_JOBS) ────────────────────────────────
impl DaClient {
    pub async fn list_cron_jobs(&self, user: &str) -> Result<Vec<DaCronJob>, String> {
        let data = self.get(&format!(
            "/CMD_API_CRON_JOBS?user={}&action=list",
            urlencoding::encode(user),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (id, info) in obj {
                if id == "error" || id == "text" { continue; }
                out.push(DaCronJob {
                    id: id.clone(),
                    command: info.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    minute: info.get("minute").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                    hour: info.get("hour").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                    day_of_month: info.get("dayofmonth").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                    month: info.get("month").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                    day_of_week: info.get("dayofweek").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                });
            }
        }
        Ok(out)
    }

    pub async fn create_cron_job(&self, user: &str, job: &DaCronJob) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("minute", job.minute.as_str());
        params.insert("hour", job.hour.as_str());
        params.insert("dayofmonth", job.day_of_month.as_str());
        params.insert("month", job.month.as_str());
        params.insert("dayofweek", job.day_of_week.as_str());
        params.insert("command", job.command.as_str());
        let resp = self.post(&format!(
            "/CMD_API_CRON_JOBS?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_cron_job(&self, user: &str, id: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("select0", id);
        let resp = self.post(&format!(
            "/CMD_API_CRON_JOBS?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }
}

// ─── SSH keys (CMD_API_SSH_KEYS) ──────────────────────────────────
impl DaClient {
    pub async fn list_ssh_keys(&self, user: &str) -> Result<Vec<DaSshKey>, String> {
        let data = self.get(&format!(
            "/CMD_API_SSH_KEYS?user={}&action=list",
            urlencoding::encode(user),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (key_id, info) in obj {
                if key_id == "error" || key_id == "text" { continue; }
                out.push(DaSshKey {
                    key_id: key_id.clone(),
                    label: info.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    fingerprint: info.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                });
            }
        }
        Ok(out)
    }

    pub async fn add_ssh_key(&self, user: &str, label: &str, public_key: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("name", label);
        params.insert("key", public_key);
        let resp = self.post(&format!(
            "/CMD_API_SSH_KEYS?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_ssh_key(&self, user: &str, key_id: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("select0", key_id);
        let resp = self.post(&format!(
            "/CMD_API_SSH_KEYS?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }
}

// ─── Mailing lists / Majordomo (CMD_API_MAILING_LIST) ─────────────
impl DaClient {
    pub async fn list_mailing_lists(&self, domain: &str) -> Result<Vec<DaMailingList>, String> {
        let data = self.get(&format!(
            "/CMD_API_MAILING_LIST?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(arr) = data.as_array() {
            for v in arr {
                if let Some(name) = v.as_str() {
                    out.push(DaMailingList {
                        name: name.to_string(),
                        address: format!("{}@{}", name, domain),
                    });
                }
            }
        } else if let Some(obj) = data.as_object() {
            for (name, _) in obj {
                if name == "error" || name == "text" { continue; }
                out.push(DaMailingList {
                    name: name.clone(),
                    address: format!("{}@{}", name, domain),
                });
            }
        }
        Ok(out)
    }

    pub async fn create_mailing_list(&self, domain: &str, name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "create");
        params.insert("domain", domain);
        params.insert("list", name);
        let resp = self.post("/CMD_API_MAILING_LIST", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_mailing_list(&self, domain: &str, name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", name);
        let resp = self.post("/CMD_API_MAILING_LIST", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Spam filter / SpamAssassin (CMD_API_FILTER) ──────────────────
impl DaClient {
    pub async fn get_spam_settings(&self, user: &str) -> Result<DaSpamSettings, String> {
        let data = self.get(&format!(
            "/CMD_API_FILTER?user={}&action=settings",
            urlencoding::encode(user),
        )).await?;
        Ok(DaSpamSettings {
            enabled: data.get("enabled").and_then(|v| v.as_str()) == Some("yes")
                || data.get("active").and_then(|v| v.as_str()) == Some("yes"),
            score_threshold: data.get("score").and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(5.0),
            action: data.get("action").and_then(|v| v.as_str()).unwrap_or("tag").to_string(),
        })
    }

    pub async fn set_spam_settings(&self, user: &str, settings: &DaSpamSettings) -> Result<(), String> {
        let score = settings.score_threshold.to_string();
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("active", if settings.enabled { "yes" } else { "no" });
        params.insert("score", score.as_str());
        params.insert("spam_action", settings.action.as_str());
        let resp = self.post(&format!(
            "/CMD_API_FILTER?user={}", urlencoding::encode(user),
        ), &params).await?;
        check_da_error(&resp)
    }
}

// ─── SSL toggles: force HTTPS, HSTS (CMD_API_SSL) ─────────────────
impl DaClient {
    pub async fn set_force_https(&self, domain: &str, force: bool) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("domain", domain);
        params.insert("force_redirect", if force { "yes" } else { "no" });
        let resp = self.post("/CMD_API_SSL", &params).await?;
        check_da_error(&resp)
    }

    pub async fn set_hsts(&self, domain: &str, enabled: bool) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("domain", domain);
        params.insert("hsts", if enabled { "yes" } else { "no" });
        let resp = self.post("/CMD_API_SSL", &params).await?;
        check_da_error(&resp)
    }

    /// Upload a PEM-encoded certificate + key (use this when the
    /// operator brings their own cert; `request_letsencrypt` is the
    /// usual path).
    pub async fn upload_certificate(&self, domain: &str, certificate_pem: &str, private_key_pem: &str, ca_bundle_pem: Option<&str>) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("domain", domain);
        params.insert("type", "paste");
        params.insert("certificate", certificate_pem);
        params.insert("key", private_key_pem);
        if let Some(ca) = ca_bundle_pem {
            params.insert("cacert", ca);
        }
        let resp = self.post("/CMD_API_SSL", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_certificate(&self, domain: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "save");
        params.insert("domain", domain);
        params.insert("type", "off");
        let resp = self.post("/CMD_API_SSL", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Directory protection / .htaccess (CMD_API_PROTECT_DIRS) ──────
impl DaClient {
    pub async fn list_protected_dirs(&self, domain: &str) -> Result<Vec<DaProtectedDir>, String> {
        let data = self.get(&format!(
            "/CMD_API_PROTECT_DIRS?domain={}&action=list",
            urlencoding::encode(domain),
        )).await?;
        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (path, info) in obj {
                if path == "error" || path == "text" { continue; }
                let realm = info.get("realm").and_then(|v| v.as_str())
                    .or_else(|| info.as_str())
                    .unwrap_or("").to_string();
                let users: Vec<String> = info.get("users").and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty()).collect())
                    .unwrap_or_default();
                out.push(DaProtectedDir {
                    path: path.clone(),
                    realm,
                    users,
                });
            }
        }
        Ok(out)
    }

    pub async fn add_protected_dir(&self, domain: &str, path: &str, realm: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "add");
        params.insert("domain", domain);
        params.insert("dir", path);
        params.insert("realm", realm);
        let resp = self.post("/CMD_API_PROTECT_DIRS", &params).await?;
        check_da_error(&resp)
    }

    pub async fn add_protected_user(&self, domain: &str, path: &str, username: &str, password: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "user");
        params.insert("domain", domain);
        params.insert("dir", path);
        params.insert("username", username);
        params.insert("passwd", password);
        params.insert("passwd2", password);
        let resp = self.post("/CMD_API_PROTECT_DIRS", &params).await?;
        check_da_error(&resp)
    }

    pub async fn delete_protected_dir(&self, domain: &str, path: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "delete");
        params.insert("domain", domain);
        params.insert("select0", path);
        let resp = self.post("/CMD_API_PROTECT_DIRS", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Service control (admin) (CMD_API_SERVICES) ───────────────────
//
// Restart Apache / Nginx / Exim / MySQL etc. Admin-only — the
// customer portal does not call these. WolfStack's host-side
// service-status panel surfaces them so an operator can recover a
// hung mailer without SSHing in.
impl DaClient {
    pub async fn list_services(&self) -> Result<Vec<DaService>, String> {
        // Newer DA versions disable `/CMD_API_SERVICES` (the dedicated
        // service-control endpoint) but still expose service status
        // as a `services` sub-object inside `CMD_API_SYSTEM_INFO`.
        // Try the dedicated endpoint first; if it returns HTML
        // (the friendly "Feature unavailable" path), fall back to
        // reading from system info — gives us a read-only list,
        // which is the most useful thing we can do anyway since
        // the start/stop/restart actions are also disabled when
        // CMD_API_SERVICES is.
        let try_dedicated = self.get("/CMD_API_SERVICES").await;
        let data = match try_dedicated {
            Ok(d) => d,
            Err(e) if e.to_ascii_lowercase().contains("web ui") || e.to_ascii_lowercase().contains("not json") => {
                let sys = self.get("/CMD_API_SYSTEM_INFO").await
                    .map_err(|e2| format!("Neither CMD_API_SERVICES nor CMD_API_SYSTEM_INFO returned usable data ({})", e2))?;
                sys.get("services").cloned().unwrap_or(serde_json::Value::Null)
            }
            Err(e) => return Err(e),
        };
        // Permissive "is this service running?" check — DA emits
        // wildly different shapes per version. We accept any of:
        //   "1", "yes", "y", "true", "on", "running", "up",
        //   "active", "OK", "started" — case-insensitive — and
        //   sub-objects with the same value under `running` /
        //   `status` / `state`.
        let is_running = |v: &serde_json::Value| -> bool {
            let to_bool = |s: &str| -> bool {
                let l = s.trim().to_ascii_lowercase();
                matches!(l.as_str(),
                    "1" | "yes" | "y" | "true" | "on" |
                    "running" | "up" | "active" | "ok" | "started"
                )
            };
            if let Some(s) = v.as_str()    { return to_bool(s); }
            if let Some(b) = v.as_bool()   { return b; }
            if let Some(n) = v.as_u64()    { return n > 0; }
            if let Some(o) = v.as_object() {
                for k in &["running", "status", "state"] {
                    if let Some(inner) = o.get(*k).and_then(|x| x.as_str()) {
                        if to_bool(inner) { return true; }
                    }
                    if let Some(b) = o.get(*k).and_then(|x| x.as_bool()) {
                        if b { return true; }
                    }
                }
            }
            false
        };

        let mut out = Vec::new();
        if let Some(obj) = data.as_object() {
            for (name, info) in obj {
                if name == "error" || name == "text" { continue; }
                let running = is_running(info);
                let auto_start = info.get("autostart").and_then(|v| v.as_str()) == Some("yes")
                    || info.get("on_boot").and_then(|v| v.as_str()) == Some("yes")
                    || info.get("enabled").and_then(|v| v.as_str()) == Some("yes");
                out.push(DaService { name: name.clone(), running, auto_start });
            }
        } else if let Some(arr) = data.as_array() {
            // Some DA builds return an array of `{name, status}`
            // objects instead of a name-keyed object.
            for entry in arr {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() { continue; }
                let running = is_running(entry);
                let auto_start = entry.get("autostart").and_then(|v| v.as_str()) == Some("yes")
                    || entry.get("on_boot").and_then(|v| v.as_str()) == Some("yes")
                    || entry.get("enabled").and_then(|v| v.as_str()) == Some("yes");
                out.push(DaService { name, running, auto_start });
            }
        }
        Ok(out)
    }

    pub async fn restart_service(&self, name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "restart");
        params.insert("service", name);
        let resp = self.post("/CMD_API_SERVICES", &params).await?;
        check_da_error(&resp)
    }

    pub async fn start_service(&self, name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "start");
        params.insert("service", name);
        let resp = self.post("/CMD_API_SERVICES", &params).await?;
        check_da_error(&resp)
    }

    pub async fn stop_service(&self, name: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "stop");
        params.insert("service", name);
        let resp = self.post("/CMD_API_SERVICES", &params).await?;
        check_da_error(&resp)
    }
}

// ─── System info (admin) (CMD_API_SYSTEM_INFO) ────────────────────
impl DaClient {
    pub async fn get_system_info(&self) -> Result<DaSystemInfo, String> {
        let data = self.get("/CMD_API_SYSTEM_INFO").await?;

        // Modern DA shape (confirmed in the wild on PapaSchlumpf's
        // server-159-69-169-100.da.direct): the response has nested
        // sub-objects keyed `cpus`, `load`, `mem_info`, `numcpus`,
        // `services`, `uptime_info`. Older DAs return a flat
        // object with `kernel`, `loadavg1/5/15`, `mem_total_mb`,
        // etc. We try sub-objects first and fall back to flat
        // top-level fields so both shapes work.

        // mem_info usually carries Linux /proc/meminfo entries:
        // "MemTotal", "MemFree", "MemAvailable" — values may be
        // strings like "8123456 kB" or plain numbers in KB.
        let mem_info = data.get("mem_info").cloned().unwrap_or(serde_json::Value::Null);
        let parse_mem_kb = |container: &serde_json::Value, keys: &[&str]| -> u64 {
            for k in keys {
                if let Some(s) = container.get(*k).and_then(|v| v.as_str()) {
                    // Strip "kB" / "KB" suffix and grab the first
                    // whitespace-separated number.
                    let first = s.split_whitespace().next().unwrap_or("");
                    if let Ok(n) = first.parse::<u64>() { return n; }
                }
                if let Some(n) = container.get(*k).and_then(|v| v.as_u64()) { return n; }
            }
            0
        };
        let mem_total_kb = parse_mem_kb(&mem_info, &["MemTotal", "memtotal", "total", "Total"]);
        let mem_free_kb  = parse_mem_kb(&mem_info, &["MemFree", "memfree", "free", "Free"]);
        let mem_avail_kb = parse_mem_kb(&mem_info, &["MemAvailable", "available", "Available"]);

        // load: usually a sub-object with "1"/"5"/"15" keys, or a
        // compound string "0.10 0.20 0.30". Newer DA also nests
        // load inside uptime_info, so we check there too.
        let load_v = data.get("load");
        let parse_f32 = |s: &str| s.trim().parse::<f32>().unwrap_or(0.0);
        let extract_load_triple = |v: &serde_json::Value| -> Option<(f32, f32, f32)> {
            if let Some(s) = v.as_str() {
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() >= 3 {
                    return Some((parse_f32(parts[0]), parse_f32(parts[1]), parse_f32(parts[2])));
                }
            }
            if let Some(obj) = v.as_object() {
                let f = |k1: &str, k2: &str| {
                    obj.get(k1).or_else(|| obj.get(k2))
                        .map(|v| v.as_f64().map(|f| f as f32)
                            .or_else(|| v.as_str().map(parse_f32))
                            .unwrap_or(0.0))
                        .unwrap_or(0.0)
                };
                return Some((f("1", "1m"), f("5", "5m"), f("15", "15m")));
            }
            None
        };
        let (load_1m, load_5m, load_15m) = load_v
            .and_then(extract_load_triple)
            .or_else(|| data.get("uptime_info")
                .and_then(|u| u.get("load_average").or_else(|| u.get("loadavg")))
                .and_then(extract_load_triple))
            .unwrap_or_else(|| {
                // Legacy flat shape: loadavg1 / loadavg5 / loadavg15
                let pop = |k: &str| data.get(k).and_then(|v| v.as_str())
                    .map(parse_f32).unwrap_or(0.0);
                (pop("loadavg1"), pop("loadavg5"), pop("loadavg15"))
            });

        // uptime_info is either a string (whole human-readable line)
        // or an object containing { uptime, uptime_seconds, ... }.
        // Use uptime_seconds when present, otherwise try to parse a
        // human string like "10 days, 4 hours, 32 mins" — at the
        // worst, leaving 0 means the dashboard shows "0 days" but
        // every other field still works.
        let uptime_seconds = {
            let u = data.get("uptime_info");
            if let Some(n) = u.and_then(|v| v.get("uptime_seconds").and_then(|x| x.as_u64())) {
                n
            } else if let Some(s) = u.and_then(|v| v.as_str()).or_else(|| u.and_then(|v| v.get("uptime").and_then(|x| x.as_str()))) {
                parse_uptime_human(s).unwrap_or(0)
            } else {
                data.get("uptime_seconds").and_then(|v| v.as_u64()).unwrap_or(0)
            }
        };

        // We accept a wide alias list and first-wins, falling back
        // to whatever's present.

        // Helper: numeric fields with multi-key alias support.
        let pop_u64 = |container: &serde_json::Value, keys: &[&str]| -> u64 {
            for k in keys {
                if let Some(v) = container.get(*k) {
                    if let Some(n) = v.as_u64() { return n; }
                    if let Some(s) = v.as_str() {
                        let first = s.split_whitespace().next().unwrap_or("");
                        if let Ok(n) = first.parse::<u64>() { return n; }
                        if let Ok(f) = first.parse::<f64>() { return f as u64; }
                    }
                }
            }
            0
        };
        let pop_str_in = |container: &serde_json::Value, keys: &[&str]| -> String {
            for k in keys {
                if let Some(v) = container.get(*k).and_then(|v| v.as_str()) {
                    let t = v.trim();
                    if !t.is_empty() { return t.to_string(); }
                }
            }
            String::new()
        };

        // Memory: prefer the meminfo path; fall back to flat fields.
        let mem_total_mb = if mem_total_kb > 0 {
            mem_total_kb / 1024
        } else {
            pop_u64(&data, &["memory_total", "mem_total", "memtotal", "mem_total_mb"])
        };
        let mem_used_mb = if mem_avail_kb > 0 {
            mem_total_kb.saturating_sub(mem_avail_kb) / 1024
        } else if mem_free_kb > 0 {
            mem_total_kb.saturating_sub(mem_free_kb) / 1024
        } else {
            let used = pop_u64(&data, &["memory_used", "mem_used", "memused", "mem_used_mb"]);
            let free = pop_u64(&data, &["memory_free", "mem_free", "memfree", "mem_free_mb"]);
            if used > 0 { used }
            else if mem_total_mb > 0 && free > 0 { mem_total_mb.saturating_sub(free) }
            else { 0 }
        };

        // Disk: prefer percentage if present, else compute from
        // used / total. Newer DA's CMD_API_SYSTEM_INFO doesn't
        // include disk; we'd need a separate call for that.
        let disk_used = pop_u64(&data, &["disk_used"]);
        let disk_total = pop_u64(&data, &["disk_total"]);
        let disk_used_pct = {
            let direct = pop_u64(&data, &["disk_used_pct", "disk_pct", "disk_usage_pct"]) as u32;
            if direct > 0 { direct }
            else if disk_total > 0 {
                ((disk_used as f64 / disk_total as f64) * 100.0) as u32
            } else { 0 }
        };

        // Kernel + version may live at the top level OR inside
        // uptime_info on newer DAs. Check both.
        let kernel = pop_str_in(&data, &["kernel_version", "kernel", "uname_r", "os_kernel"])
            .or_empty_then(|| pop_str_in(data.get("uptime_info").unwrap_or(&serde_json::Value::Null), &["kernel", "kernel_version"]));
        let version = pop_str_in(&data, &["directadmin_version", "version", "da_version", "directadmin", "version_string"])
            .or_empty_then(|| pop_str_in(data.get("uptime_info").unwrap_or(&serde_json::Value::Null), &["directadmin_version", "version"]));

        let info = DaSystemInfo {
            kernel,
            uptime_seconds,
            load_1m, load_5m, load_15m,
            mem_total_mb,
            mem_used_mb,
            disk_used_pct,
            directadmin_version: version,
        };

        // Honest empty-state: if literally every numeric field is
        // zero AND every string is empty, the endpoint returned a
        // shape we don't recognise. Surface that so the UI can
        // tell the operator instead of pretending it's a healthy
        // brand-new server with 0 MB of RAM.
        let all_blank = info.kernel.is_empty()
            && info.directadmin_version.is_empty()
            && info.uptime_seconds == 0
            && info.mem_total_mb == 0
            && info.disk_used_pct == 0
            && info.load_1m == 0.0;
        if all_blank {
            let keys = data.as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "<not an object>".to_string());
            return Err(format!(
                "DirectAdmin CMD_API_SYSTEM_INFO returned a shape this WolfHost build doesn't recognise. \
                 Response keys: [{}].",
                keys,
            ));
        }
        Ok(info)
    }
}

/// Parse DA's human-readable uptime string ("10 days, 4 hours, 32 mins")
/// into seconds. Best-effort — any unrecognised piece is skipped.
fn parse_uptime_human(s: &str) -> Option<u64> {
    let lower = s.to_ascii_lowercase();
    let mut total: u64 = 0;
    let mut found_anything = false;
    let parts = lower.split(|c: char| c == ',' || c == ';');
    for p in parts {
        let p = p.trim();
        let words: Vec<&str> = p.split_whitespace().collect();
        if words.len() < 2 { continue; }
        let n: u64 = match words[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let unit = words[1];
        let secs = if unit.starts_with("day") { n * 86400 }
            else if unit.starts_with("hour") || unit.starts_with("hr") { n * 3600 }
            else if unit.starts_with("min") { n * 60 }
            else if unit.starts_with("sec") { n }
            else if unit.starts_with("week") { n * 7 * 86400 }
            else { continue };
        total += secs;
        found_anything = true;
    }
    // Also handle the "HH:MM" form some uptime outputs use.
    if !found_anything {
        if let Some(hhmm) = s.split_whitespace().find(|w| w.contains(':')) {
            let parts: Vec<&str> = hhmm.split(':').collect();
            if parts.len() >= 2 {
                let h: u64 = parts[0].parse().ok()?;
                let m: u64 = parts[1].parse().ok()?;
                total = h * 3600 + m * 60;
                found_anything = true;
            }
        }
    }
    if found_anything { Some(total) } else { None }
}

trait OrEmptyThen {
    fn or_empty_then<F: FnOnce() -> String>(self, f: F) -> String;
}
impl OrEmptyThen for String {
    fn or_empty_then<F: FnOnce() -> String>(self, f: F) -> String {
        if self.is_empty() { f() } else { self }
    }
}

// ─── Two-factor auth (CMD_API_2FA) ────────────────────────────────
impl DaClient {
    pub async fn get_2fa_status(&self, user: &str) -> Result<DaTwoFactorStatus, String> {
        let data = self.get(&format!(
            "/CMD_API_2FA?user={}",
            urlencoding::encode(user),
        )).await?;
        Ok(DaTwoFactorStatus {
            enabled: data.get("enabled").and_then(|v| v.as_str()) == Some("yes")
                || data.get("active").and_then(|v| v.as_str()) == Some("yes"),
            method: data.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }

    /// Reset / disable 2FA on a user. Admin-side recovery — customer
    /// has lost their authenticator and can't log in. Returns Ok
    /// once 2FA is off; the customer must re-enrol next login.
    pub async fn disable_2fa(&self, user: &str) -> Result<(), String> {
        let mut params = HashMap::new();
        params.insert("action", "disable");
        params.insert("user", user);
        let resp = self.post("/CMD_API_2FA", &params).await?;
        check_da_error(&resp)
    }
}

// ─── Logs (CMD_API_LOGS / CMD_VIEW_LOG) ───────────────────────────
//
// DA exposes Apache / Nginx access + error logs and the per-user
// mail log via CMD_API_LOGS. Returns the raw log text — caller
// renders it. `lines` caps the returned tail.
impl DaClient {
    pub async fn get_log(&self, user: &str, log_type: DaLogType, lines: u32) -> Result<String, String> {
        let log_str = log_type.as_str();
        let lines_str = lines.to_string();
        let url = format!(
            "/CMD_API_LOGS?user={}&type={}&num={}",
            urlencoding::encode(user), log_str, lines_str,
        );
        let data = self.get(&url).await?;
        if let Some(text) = data.get("text").and_then(|v| v.as_str()) {
            return Ok(text.to_string());
        }
        if let Some(s) = data.as_str() {
            return Ok(s.to_string());
        }
        Ok(data.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaLogType {
    Access,
    Error,
    AccessSsl,
    ErrorSsl,
    Mail,
}

impl DaLogType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DaLogType::Access     => "access",
            DaLogType::Error      => "error",
            DaLogType::AccessSsl  => "access_ssl",
            DaLogType::ErrorSsl   => "error_ssl",
            DaLogType::Mail       => "mail",
        }
    }
}

/// Translate a non-JSON DA response body into something the operator
/// can act on. Two cases worth distinguishing:
///   * HTML page (newer DA versions serve their Vue admin UI when an
///     endpoint either doesn't exist or doesn't accept `json=yes`) —
///     surface "endpoint not available on this DA version" so the UI
///     can render a friendly empty state instead of a wall of HTML.
///   * Some DA endpoints return URL-encoded `key=value` instead of
///     JSON — pass through a short snippet so the cause is debuggable
///     without dumping a full HTML page into the toast.
fn friendly_non_json_error(path: &str, body: &str) -> String {
    let trimmed = body.trim_start();
    let looks_html = trimmed.starts_with('<')
        && (trimmed.to_ascii_lowercase().contains("<!doctype html")
            || trimmed.contains("<html"));
    if looks_html {
        format!(
            "DirectAdmin returned its web UI for `{}` instead of an API response. \
             This DA version probably doesn't support that endpoint via the API \
             (or it's been disabled by the host). Feature unavailable.",
            path
        )
    } else {
        format!(
            "DA response not JSON for `{}`: {}",
            path,
            body.chars().take(200).collect::<String>()
        )
    }
}

/// Check DA response for error field
fn check_da_error(resp: &serde_json::Value) -> Result<(), String> {
    if resp.get("error").and_then(|v| v.as_str()) == Some("1")
        || resp.get("error").and_then(|v| v.as_i64()) == Some(1)
    {
        let text = resp.get("text").and_then(|v| v.as_str()).unwrap_or("Unknown DA error");
        return Err(format!("DirectAdmin error: {}", text));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_encode_decode_roundtrip() {
        let key = "test-cluster-secret-123";
        let plain = "MyS3cretP@ss!";
        let encoded = encode_password(plain, key);
        assert_ne!(encoded, plain);
        let decoded = decode_password(&encoded, key);
        assert_eq!(decoded, plain);
    }

    #[test]
    fn password_decode_plaintext_fallback() {
        // If the encoded string isn't valid base64, it should return as-is
        let result = decode_password("not-base64!!!", "key");
        assert_eq!(result, "not-base64!!!");
    }

    #[test]
    fn check_da_error_success() {
        let resp = serde_json::json!({"text": "OK"});
        assert!(check_da_error(&resp).is_ok());
    }

    #[test]
    fn check_da_error_failure() {
        let resp = serde_json::json!({"error": "1", "text": "Something went wrong"});
        assert!(check_da_error(&resp).is_err());
    }
}
