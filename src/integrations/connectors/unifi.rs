// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Unifi Controller connector — manage devices, clients, and networks.
//!
//! Two auth paths, tried in that order:
//!
//! 1. **API key** (preferred). If a `api_key` credential is present we send it
//!    as the `X-API-KEY` header and skip the login round-trip entirely. This is
//!    the only path that works when the controller/account has 2FA enabled,
//!    because the legacy `/api/login` username+password flow returns a 2FA
//!    challenge that a headless integration can't answer. UniFi OS 4.x / Network
//!    9.x let an admin mint a local API key under Settings → Admins → API Keys.
//! 2. **Cookie login** (fallback for older controllers without API keys). POST
//!    `/api/login` with `{username, password}`, then carry the returned session
//!    cookies on subsequent requests. Since reqwest's `cookies` feature is not
//!    enabled, we extract the `Set-Cookie` header manually and replay it.

use crate::integrations::{
    AuthMethod, ConfigField, Connector, ConnectorCapability, ConnectorInfo,
    ConnectorOperation, HealthStatus, IntegrationInstance, ServiceStatus,
};
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

/// Resolved auth for a single request. Kept separate from the request build so
/// `api_get`/`api_post` share one auth-resolution path.
enum UnifiAuth {
    /// Local API key — sent as `X-API-KEY`. No login round-trip, so it works
    /// even when the controller/account enforces 2FA.
    ApiKey(String),
    /// Session cookie string from a username/password `/api/login`.
    Cookie(String),
}

impl UnifiConnector {
    /// Return a cheap (Arc-refcounted) clone of the shared Client so
    /// the existing callers can keep using owned Client by value
    /// without re-plumbing references through the API.
    fn base_client() -> Result<reqwest::Client, String> {
        Ok(reqwest::Client::clone(&UNIFI_CLIENT))
    }

    /// Login to the Unifi controller and return the session cookie string.
    async fn login(
        base_url: &str,
        credentials: &serde_json::Value,
    ) -> Result<(reqwest::Client, String), String> {
        let username = credentials.get("username")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'username' in credentials")?;
        let password = credentials.get("password")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'password' in credentials")?;

        let client = Self::base_client()?;
        let url = format!("{}/api/login", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "username": username,
            "password": password,
        });

        let resp = client.post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Login request failed: {}", e))?;

        let status = resp.status();

        // Pull cookies out of the headers BEFORE consuming the body
        // — headers() is a &self reference so resp is still live.
        let cookies: Vec<String> = resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|v| {
                // Take only the cookie name=value part (before first ';')
                v.split(';').next().unwrap_or(v).to_string()
            })
            .collect();

        // Drain the body so the socket returns to the keep-alive
        // pool regardless of status. Every failed-login previously
        // orphaned a socket here.
        let _ = resp.bytes().await;

        if !status.is_success() {
            return Err(format!("Unifi login failed: {}", status));
        }

        if cookies.is_empty() {
            return Err("Unifi login returned no cookies".to_string());
        }

        let cookie_header = cookies.join("; ");
        Ok((client, cookie_header))
    }

    /// Resolve auth for a request: prefer an API key (no login, 2FA-safe),
    /// otherwise fall back to a username/password cookie login.
    async fn authenticate(
        base_url: &str,
        credentials: &serde_json::Value,
    ) -> Result<(reqwest::Client, UnifiAuth), String> {
        if let Some(key) = credentials.get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok((Self::base_client()?, UnifiAuth::ApiKey(key.to_string())));
        }
        let (client, cookie) = Self::login(base_url, credentials).await?;
        Ok((client, UnifiAuth::Cookie(cookie)))
    }

    /// Attach the resolved auth to a request builder.
    fn apply_auth(rb: reqwest::RequestBuilder, auth: &UnifiAuth) -> reqwest::RequestBuilder {
        match auth {
            UnifiAuth::ApiKey(key) => rb.header("X-API-KEY", key),
            UnifiAuth::Cookie(cookie) => rb.header("Cookie", cookie),
        }
    }

    /// GET request, authenticated by API key or session cookie.
    async fn api_get(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
    ) -> Result<serde_json::Value, String> {
        let (client, auth) = Self::authenticate(base_url, credentials).await?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);

        let resp = Self::apply_auth(
                client.get(&url).header("Accept", "application/json"),
                &auth,
            )
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            // Drain the error body so the socket returns to the pool.
            let _ = resp.bytes().await;
            return Err(format!("Unifi API error: {} {}", status, url));
        }

        // Success: `.json()` consumes the body internally, freeing
        // the connection back to the pool.
        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// POST request, authenticated by API key or session cookie.
    async fn api_post(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let (client, auth) = Self::authenticate(base_url, credentials).await?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);

        let resp = Self::apply_auth(
                client.post(&url).header("Content-Type", "application/json"),
                &auth,
            )
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(format!("Unifi API error: {} {} — {}", status, url, body_text));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Resolve the site name from config, defaulting to "default".
    fn site(instance: &IntegrationInstance) -> String {
        instance.config.get("site")
            .cloned()
            .unwrap_or_else(|| "default".to_string())
    }
}

impl Connector for UnifiConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            id: "unifi".to_string(),
            name: "Unifi Controller".to_string(),
            icon: "fa-wifi".to_string(),
            description: "Manage Unifi network devices, clients, and networks. Use an API key (Settings → Admins → API Keys) — required if the controller has 2FA; username/password is a fallback for older controllers.".to_string(),
            // API key first so the UI prefers it; cookie login stays as a
            // fallback for controllers without API-key support.
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

            match Self::api_get(&instance.base_url, credentials, "/api/self/sites").await {
                Ok(data) => {
                    // Try to extract controller version from site info
                    let version = data.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|site| site.get("desc"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    HealthStatus {
                        status: ServiceStatus::Online,
                        message: "Connected".to_string(),
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        last_checked: now,
                        version,
                    }
                }
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

            match operation {
                "list_clients" => {
                    Self::api_get(base, credentials, &format!("/api/s/{}/stat/sta", site)).await
                }

                "list_devices" => {
                    Self::api_get(base, credentials, &format!("/api/s/{}/stat/device", site)).await
                }

                "list_networks" => {
                    Self::api_get(base, credentials, &format!("/api/s/{}/rest/networkconf", site)).await
                }

                "block_client" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "block-sta",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/stamgr", site), &body).await
                }

                "unblock_client" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "unblock-sta",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/stamgr", site), &body).await
                }

                "reconnect_client" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "kick-sta",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/stamgr", site), &body).await
                }

                "restart_device" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "restart",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/devmgr", site), &body).await
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
