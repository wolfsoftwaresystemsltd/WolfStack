// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Unifi Controller connector — manage devices, clients, and networks.
//!
//! UniFi has **two entirely separate HTTP APIs**, and which one you can use is
//! decided by *how you authenticate*. Getting this wrong is a guaranteed 401,
//! which is exactly what an earlier version of this connector did (it sent an
//! API key to the legacy cookie-only endpoints).
//!
//! 1. **API key → Integration API** (preferred; 2FA-safe). A local API key
//!    (Settings → Control Plane → Integrations on Network 9.3+) authenticates
//!    ONLY the official Integration API at
//!    `…/proxy/network/integration/v1/…` via the `X-API-KEY` header. The legacy
//!    `/api/s/{site}/…` endpoints reject the key outright. The Integration API
//!    exposes *reads* — sites, devices, clients — keyed by a site **UUID**
//!    (not the site name), so we resolve the configured site to its UUID first.
//!    It does **not** expose client block/kick or device restart, nor the
//!    network config list.
//!
//! 2. **Username/password → legacy cookie API** (fallback + the only path for
//!    the actions the Integration API lacks). POST the credentials, carry the
//!    returned session cookies, and — on UniFi OS consoles (UDM/UDR/UCG) — send
//!    every call under the `/proxy/network` prefix and attach an
//!    `X-CSRF-Token` to writes. Self-hosted controllers use the bare paths.
//!
//! So: an API-key-only connector can list devices/clients (what most operators
//! want) but must fall back to a configured username/password to block a client
//! or restart a device. When only an API key is present and one of those
//! actions is requested, we return a clear, actionable error rather than a
//! silent 401.

use crate::integrations::{
    AuthMethod, ConfigField, Connector, ConnectorCapability, ConnectorInfo,
    ConnectorOperation, HealthStatus, IntegrationInstance, ServiceStatus,
};
use base64::Engine as _;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Shared HTTP client for every Unifi API call. The old `base_client()`
/// built a fresh Client for every login + every request (api_get and
/// api_post each call login() which called base_client()) — one leaked
/// pool per request. Unifi sessions are identified by cookie headers
/// that we set per-request, so a single Client works for all sessions.
/// Policy::none() preserved — Unifi returns a 302 on login failure and
/// we want to see that instead of following it.
static UNIFI_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

pub struct UnifiConnector;

/// A resolved cookie session against the legacy API. `unifi_os` selects the
/// `/proxy/network` URL prefix; `csrf` is attached to writes on UniFi OS.
struct CookieSession {
    client: reqwest::Client,
    cookie: String,
    unifi_os: bool,
    csrf: Option<String>,
}

impl UnifiConnector {
    /// Return a cheap (Arc-refcounted) clone of the shared Client so
    /// the existing callers can keep using owned Client by value
    /// without re-plumbing references through the API.
    fn base_client() -> Result<reqwest::Client, String> {
        Ok(reqwest::Client::clone(&UNIFI_CLIENT))
    }

    /// The API key from credentials, if a non-empty one is configured.
    fn api_key(credentials: &serde_json::Value) -> Option<String> {
        credentials.get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    /// Whether a usable username+password pair is configured (needed for the
    /// legacy actions the Integration API can't perform).
    fn has_credentials(credentials: &serde_json::Value) -> bool {
        let nonempty = |k: &str| credentials.get(k)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        nonempty("username") && nonempty("password")
    }

    /// Resolve the site name from config, defaulting to "default".
    fn site(instance: &IntegrationInstance) -> String {
        instance.config.get("site")
            .cloned()
            .unwrap_or_else(|| "default".to_string())
    }

    // ── Legacy cookie API ────────────────────────────────────────────────────

    /// Log in and return a cookie session. Tries the UniFi OS endpoint
    /// (`/api/auth/login`) first, then the self-hosted one (`/api/login`),
    /// which also tells us which URL layout the rest of the calls must use.
    async fn cookie_login(
        base_url: &str,
        credentials: &serde_json::Value,
    ) -> Result<CookieSession, String> {
        let username = credentials.get("username")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'username' in credentials")?;
        let password = credentials.get("password")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'password' in credentials")?;

        let client = Self::base_client()?;
        let trimmed = base_url.trim_end_matches('/');
        let body = serde_json::json!({
            "username": username,
            "password": password,
            "remember": true,
        });

        let mut last_err = String::from("controller did not accept /api/auth/login or /api/login");
        // (path, is_unifi_os)
        for (path, unifi_os) in [("/api/auth/login", true), ("/api/login", false)] {
            let url = format!("{}{}", trimmed, path);
            let resp = match client.post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => { last_err = format!("{}: {}", url, e); continue; }
            };

            let status = resp.status();
            // A real credential rejection — stop; trying the other path won't help.
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                let _ = resp.bytes().await;
                return Err(format!(
                    "Unifi login failed: {} — check the username/password. \
                     If this account uses 2FA, use an API key instead.",
                    status
                ));
            }
            // Wrong path for this controller type (404/redirect/etc.) — try the next.
            if !status.is_success() {
                let _ = resp.bytes().await;
                last_err = format!("{} -> {}", url, status);
                continue;
            }

            // Success: pull cookies + CSRF token BEFORE consuming the body.
            let cookie_pairs: Vec<String> = resp.headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|v| v.split(';').next().unwrap_or(v).to_string())
                .collect();
            let csrf_header = resp.headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let _ = resp.bytes().await;

            if cookie_pairs.is_empty() {
                return Err("Unifi login returned no session cookie".to_string());
            }
            // UniFi OS carries the CSRF token in the TOKEN JWT when it isn't
            // echoed as a header — decode it so writes still work.
            let csrf = csrf_header.or_else(|| Self::csrf_from_cookies(&cookie_pairs));
            return Ok(CookieSession {
                client,
                cookie: cookie_pairs.join("; "),
                unifi_os,
                csrf,
            });
        }
        Err(format!("Unifi login failed: {}", last_err))
    }

    /// Extract the CSRF token from a UniFi OS `TOKEN` cookie (a JWT whose
    /// payload holds `csrfToken`). Returns None on any decode/parse failure —
    /// self-hosted controllers have no such cookie and don't need CSRF.
    fn csrf_from_cookies(cookie_pairs: &[String]) -> Option<String> {
        let token = cookie_pairs.iter().find_map(|c| c.strip_prefix("TOKEN="))?;
        let payload_b64 = token.split('.').nth(1)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .ok()?;
        let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        json.get("csrfToken").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    /// Build a legacy endpoint URL, adding the `/proxy/network` prefix on
    /// UniFi OS consoles.
    fn legacy_url(base_url: &str, unifi_os: bool, path: &str) -> String {
        let b = base_url.trim_end_matches('/');
        if unifi_os {
            format!("{}/proxy/network{}", b, path)
        } else {
            format!("{}{}", b, path)
        }
    }

    /// Authenticated GET on the legacy API.
    async fn legacy_get(sess: &CookieSession, url: &str) -> Result<serde_json::Value, String> {
        let resp = sess.client.get(url)
            .header("Accept", "application/json")
            .header("Cookie", &sess.cookie)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;
            return Err(format!("Unifi API error: {} {}", status, url));
        }
        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Authenticated POST on the legacy API, attaching the CSRF token on
    /// UniFi OS.
    async fn legacy_post(
        sess: &CookieSession,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut rb = sess.client.post(url)
            .header("Content-Type", "application/json")
            .header("Cookie", &sess.cookie);
        if let Some(csrf) = &sess.csrf {
            rb = rb.header("X-CSRF-Token", csrf);
        }
        let resp = rb.json(body).send().await
            .map_err(|e| format!("Request failed: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(format!("Unifi API error: {} {} — {}", status, url, body_text));
        }
        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Log in for a legacy action, or return a clear error when only an API key
    /// is configured (the Integration API can't perform these).
    async fn cookie_for_action(
        base_url: &str,
        credentials: &serde_json::Value,
        action: &str,
    ) -> Result<CookieSession, String> {
        if Self::has_credentials(credentials) {
            return Self::cookie_login(base_url, credentials).await;
        }
        Err(format!(
            "{} requires a controller username + password. UniFi's API-key \
             (Integration) API doesn't expose this action — add a username and \
             password to this connector to enable it.",
            action
        ))
    }

    // ── Integration API (API key) ────────────────────────────────────────────

    /// Authenticated GET on the Integration API.
    async fn integration_get(key: &str, url: &str) -> Result<serde_json::Value, String> {
        let client = Self::base_client()?;
        let resp = client.get(url)
            .header("Accept", "application/json")
            .header("X-API-KEY", key)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;
            return Err(format!("Unifi API error: {} {}", status, url));
        }
        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// The `id` (or Mongo-style `_id`) of a site object.
    fn site_id(s: &serde_json::Value) -> Option<&str> {
        s.get("id").and_then(|v| v.as_str())
            .or_else(|| s.get("_id").and_then(|v| v.as_str()))
    }

    /// Match the configured site (by UUID, name, internalReference or desc,
    /// case-insensitively) to its UUID. A single-site console is unambiguous,
    /// so we use its one site regardless of the configured label.
    fn pick_site_uuid(data: &serde_json::Value, want: &str) -> Option<String> {
        let arr = data.get("data").and_then(|v| v.as_array())?;
        let want_l = want.trim().to_lowercase();
        if !want_l.is_empty() {
            for s in arr {
                if let Some(id) = Self::site_id(s) {
                    let cands = [
                        id,
                        s.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        s.get("internalReference").and_then(|v| v.as_str()).unwrap_or(""),
                        s.get("desc").and_then(|v| v.as_str()).unwrap_or(""),
                    ];
                    if cands.iter().any(|c| !c.is_empty() && c.to_lowercase() == want_l) {
                        return Some(id.to_string());
                    }
                }
            }
        }
        if arr.len() == 1 {
            if let Some(id) = Self::site_id(&arr[0]) {
                return Some(id.to_string());
            }
        }
        None
    }

    /// Human-readable list of the sites the controller reported, for error text.
    fn site_labels(data: &serde_json::Value) -> String {
        data.get("data").and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|s| s.get("name").and_then(|v| v.as_str())
                    .or_else(|| Self::site_id(s)))
                .collect::<Vec<_>>()
                .join(", "))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "(none)".to_string())
    }

    /// Resolve the Integration API base prefix and the configured site's UUID.
    /// Probes the UniFi OS proxied path first, then the self-hosted path. A 401
    /// is a bad key (reported immediately); a 404 just means "wrong layout, try
    /// the other prefix". Returns `(prefix_base, site_uuid)`.
    async fn resolve_integration_site(
        base_url: &str,
        key: &str,
        site_name: &str,
    ) -> Result<(String, String), String> {
        let b = base_url.trim_end_matches('/');
        let mut last_err = String::from("no response");
        for prefix in ["/proxy/network/integration/v1", "/integration/v1"] {
            let sites_url = format!("{}{}/sites", b, prefix);
            let client = Self::base_client()?;
            let resp = match client.get(&sites_url)
                .header("Accept", "application/json")
                .header("X-API-KEY", key)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => { last_err = format!("{}: {}", sites_url, e); continue; }
            };
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                let _ = resp.bytes().await;
                return Err(format!(
                    "Unifi rejected the API key ({}). Create a Network API key \
                     under Settings → Control Plane → Integrations (Network 9.3+) \
                     and paste it into this connector.",
                    status
                ));
            }
            if !status.is_success() {
                let _ = resp.bytes().await;
                last_err = format!("{} -> {}", sites_url, status);
                continue;
            }
            let data: serde_json::Value = resp.json().await
                .map_err(|e| format!("JSON parse error: {}", e))?;
            let uuid = Self::pick_site_uuid(&data, site_name).ok_or_else(|| format!(
                "Site '{}' not found on the controller. Available sites: {}",
                site_name, Self::site_labels(&data)
            ))?;
            return Ok((format!("{}{}", b, prefix), uuid));
        }
        Err(format!(
            "Could not reach the Unifi Integration API (tried \
             /proxy/network/integration/v1 and /integration/v1). Needs UniFi \
             Network 9.3+ with API keys enabled. Last error: {}",
            last_err
        ))
    }
}

impl Connector for UnifiConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            id: "unifi".to_string(),
            name: "Unifi Controller".to_string(),
            icon: "fa-wifi".to_string(),
            description: "Manage Unifi network devices, clients, and networks. \
                An API key (Settings → Control Plane → Integrations, Network 9.3+) \
                lists devices and clients and is required if the controller has 2FA. \
                Add a username + password to also block/kick clients, restart devices, \
                and list networks. UniFi OS consoles (UDM/UDR/UCG) are supported."
                .to_string(),
            // API key first so the UI prefers it; username/password enables the
            // actions the Integration API can't perform.
            auth_methods: vec![AuthMethod::ApiKey, AuthMethod::Cookie],
            config_schema: vec![
                ConfigField {
                    name: "base_url".to_string(),
                    label: "Controller URL".to_string(),
                    field_type: "url".to_string(),
                    required: true,
                    default_value: None,
                    placeholder: Some("https://unifi.local:8443".to_string()),
                },
                ConfigField {
                    name: "site".to_string(),
                    label: "Site Name".to_string(),
                    field_type: "text".to_string(),
                    required: false,
                    default_value: Some("default".to_string()),
                    placeholder: Some("default".to_string()),
                },
            ],
        }
    }

    fn capabilities(&self) -> Vec<ConnectorCapability> {
        vec![
            ConnectorCapability {
                id: "devices".to_string(),
                label: "Devices".to_string(),
                icon: "fa-tower-broadcast".to_string(),
            },
            ConnectorCapability {
                id: "clients".to_string(),
                label: "Clients".to_string(),
                icon: "fa-laptop".to_string(),
            },
            ConnectorCapability {
                id: "networks".to_string(),
                label: "Networks".to_string(),
                icon: "fa-diagram-project".to_string(),
            },
        ]
    }

    fn operations(&self) -> Vec<ConnectorOperation> {
        // `execute` reads params["mac"] for all four; client ops take a client
        // MAC, restart_device a device MAC (unifi.rs execute arms). Verified.
        let mac_field = |label: &str| ConfigField {
            name: "mac".to_string(),
            label: label.to_string(),
            field_type: "text".to_string(),
            required: true,
            default_value: None,
            placeholder: Some("aa:bb:cc:dd:ee:ff".to_string()),
        };
        vec![
            ConnectorOperation { id: "block_client".to_string(), label: "Block client".to_string(),
                icon: "fa-ban".to_string(), params: vec![mac_field("Client MAC")], destructive: true },
            ConnectorOperation { id: "unblock_client".to_string(), label: "Unblock client".to_string(),
                icon: "fa-circle-check".to_string(), params: vec![mac_field("Client MAC")], destructive: false },
            ConnectorOperation { id: "reconnect_client".to_string(), label: "Reconnect client".to_string(),
                icon: "fa-rotate".to_string(), params: vec![mac_field("Client MAC")], destructive: false },
            ConnectorOperation { id: "restart_device".to_string(), label: "Restart device".to_string(),
                icon: "fa-power-off".to_string(), params: vec![mac_field("Device MAC")], destructive: true },
        ]
    }

    fn health_check<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + 'a>> {
        Box::pin(async move {
            let now = chrono::Utc::now().to_rfc3339();
            let start = std::time::Instant::now();
            let base = &instance.base_url;
            let site = Self::site(instance);

            let result: Result<Option<String>, String> = if let Some(key) = Self::api_key(credentials) {
                // API key: reaching the Integration API + resolving the site
                // proves connectivity. Grab the app version from /info if we can.
                match Self::resolve_integration_site(base, &key, &site).await {
                    Ok((prefix, _uuid)) => {
                        let version = Self::integration_get(&key, &format!("{}/info", prefix)).await.ok()
                            .and_then(|v| v.get("applicationVersion")
                                .or_else(|| v.get("version"))
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string()));
                        Ok(version)
                    }
                    Err(e) => Err(e),
                }
            } else {
                // Cookie: log in and read the sites list; version from `desc`.
                match Self::cookie_login(base, credentials).await {
                    Ok(sess) => {
                        let url = Self::legacy_url(base, sess.unifi_os, "/api/self/sites");
                        match Self::legacy_get(&sess, &url).await {
                            Ok(data) => Ok(data.get("data")
                                .and_then(|d| d.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|s| s.get("desc"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            };

            match result {
                Ok(version) => HealthStatus {
                    status: ServiceStatus::Online,
                    message: "Connected".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    last_checked: now,
                    version,
                },
                Err(e) => HealthStatus {
                    status: ServiceStatus::Offline,
                    message: e,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    last_checked: now,
                    version: None,
                },
            }
        })
    }

    fn execute<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
        operation: &'a str,
        params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let base = &instance.base_url;
            let site = Self::site(instance);
            let key = Self::api_key(credentials);

            // MAC helper for the action ops.
            let mac = |p: &serde_json::Value| p.get("mac")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| "Missing 'mac' parameter".to_string());

            match operation {
                // ── Reads: Integration API when a key is present, else legacy ──
                "list_devices" | "list_clients" => {
                    let leaf = if operation == "list_devices" { "devices" } else { "clients" };
                    if let Some(key) = &key {
                        let (prefix, uuid) = Self::resolve_integration_site(base, key, &site).await?;
                        let url = format!("{}/sites/{}/{}", prefix, uuid, leaf);
                        Self::integration_get(key, &url).await
                    } else {
                        let sess = Self::cookie_login(base, credentials).await?;
                        let legacy = if operation == "list_devices" { "stat/device" } else { "stat/sta" };
                        let url = Self::legacy_url(base, sess.unifi_os,
                            &format!("/api/s/{}/{}", site, legacy));
                        Self::legacy_get(&sess, &url).await
                    }
                }

                // ── Networks: legacy only (no Integration API endpoint) ──
                "list_networks" => {
                    let sess = Self::cookie_for_action(base, credentials, "Listing networks").await?;
                    let url = Self::legacy_url(base, sess.unifi_os,
                        &format!("/api/s/{}/rest/networkconf", site));
                    Self::legacy_get(&sess, &url).await
                }

                // ── Actions: legacy only (Integration API doesn't expose them) ──
                "block_client" => {
                    let mac = mac(params)?;
                    let sess = Self::cookie_for_action(base, credentials, "Blocking a client").await?;
                    let body = serde_json::json!({ "cmd": "block-sta", "mac": mac });
                    let url = Self::legacy_url(base, sess.unifi_os, &format!("/api/s/{}/cmd/stamgr", site));
                    Self::legacy_post(&sess, &url, &body).await
                }
                "unblock_client" => {
                    let mac = mac(params)?;
                    let sess = Self::cookie_for_action(base, credentials, "Unblocking a client").await?;
                    let body = serde_json::json!({ "cmd": "unblock-sta", "mac": mac });
                    let url = Self::legacy_url(base, sess.unifi_os, &format!("/api/s/{}/cmd/stamgr", site));
                    Self::legacy_post(&sess, &url, &body).await
                }
                "reconnect_client" => {
                    let mac = mac(params)?;
                    let sess = Self::cookie_for_action(base, credentials, "Reconnecting a client").await?;
                    let body = serde_json::json!({ "cmd": "kick-sta", "mac": mac });
                    let url = Self::legacy_url(base, sess.unifi_os, &format!("/api/s/{}/cmd/stamgr", site));
                    Self::legacy_post(&sess, &url, &body).await
                }
                "restart_device" => {
                    let mac = mac(params)?;
                    let sess = Self::cookie_for_action(base, credentials, "Restarting a device").await?;
                    let body = serde_json::json!({ "cmd": "restart", "mac": mac });
                    let url = Self::legacy_url(base, sess.unifi_os, &format!("/api/s/{}/cmd/devmgr", site));
                    Self::legacy_post(&sess, &url, &body).await
                }

                _ => Err(format!("Unknown operation: {}", operation)),
            }
        })
    }

    fn dashboard_data<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
        capability_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let empty = serde_json::json!({});
            match capability_id {
                "devices" => self.execute(instance, credentials, "list_devices", &empty).await,
                "clients" => self.execute(instance, credentials, "list_clients", &empty).await,
                "networks" => self.execute(instance, credentials, "list_networks", &empty).await,
                _ => Err(format!("Unknown capability: {}", capability_id)),
            }
        })
    }
}
