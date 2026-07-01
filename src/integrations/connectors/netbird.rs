// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! NetBird VPN connector — manage peers, groups, routes, and users via the
//! NetBird Management API.

use crate::integrations::{
    AuthMethod, ConfigField, Connector, ConnectorCapability, ConnectorInfo,
    ConnectorOperation, HealthStatus, IntegrationInstance, ServiceStatus,
};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Shared HTTP client for every NetBird API call. Auth token travels
/// per-request in the Authorization header (see `auth_header`), so
/// one shared pool works across all instances. Replaces the per-call
/// `crate::api::ipv4_only_client_builder()` that leaked a connection pool on
/// every api_get / api_post / api_put.
static NETBIRD_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

pub struct NetBirdConnector;

impl NetBirdConnector {
    /// Build the Authorization header value from the stored token.
    fn auth_header(credentials: &serde_json::Value) -> Result<String, String> {
        let token = credentials.get("token")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'token' in credentials")?;
        Ok(format!("Token {}", token))
    }

    async fn api_get(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
    ) -> Result<serde_json::Value, String> {
        let auth = Self::auth_header(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = NETBIRD_CLIENT.get(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            // Drain error body so the socket returns to the pool.
            let _ = resp.bytes().await;
            return Err(format!("NetBird API error: {} {}", status, url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    async fn api_post(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let auth = Self::auth_header(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = NETBIRD_CLIENT.post(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;
            return Err(format!("NetBird API error: {} {}", status, url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    async fn api_put(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let auth = Self::auth_header(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = NETBIRD_CLIENT.put(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let _ = resp.bytes().await;
            return Err(format!("NetBird API error: {} {}", status, url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }
}

impl Connector for NetBirdConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            id: "netbird".to_string(),
            name: "NetBird VPN".to_string(),
            icon: "fa-shield-halved".to_string(),
            description: "Manage NetBird VPN peers, groups, routes, and users".to_string(),
            auth_methods: vec![AuthMethod::Bearer],
            config_schema: vec![
                ConfigField {
                    name: "base_url".to_string(),
                    label: "Management URL".to_string(),
                    field_type: "url".to_string(),
                    required: true,
                    default_value: Some("https://api.netbird.io".to_string()),
                    placeholder: Some("https://api.netbird.io".to_string()),
                },
            ],
        }
    }

    fn capabilities(&self) -> Vec<ConnectorCapability> {
        vec![
            ConnectorCapability {
                id: "peers".to_string(),
                label: "Peers".to_string(),
                icon: "fa-network-wired".to_string(),
            },
            ConnectorCapability {
                id: "groups".to_string(),
                label: "Groups".to_string(),
                icon: "fa-layer-group".to_string(),
            },
            ConnectorCapability {
                id: "routes".to_string(),
                label: "Routes".to_string(),
                icon: "fa-route".to_string(),
            },
            ConnectorCapability {
                id: "users".to_string(),
                label: "Users".to_string(),
                icon: "fa-users".to_string(),
            },
        ]
    }

    fn operations(&self) -> Vec<ConnectorOperation> {
        // execute reads params["peer_id"] for enable/disable; create_group posts
        // params directly to /api/groups (NetBird group body: {name}). Verified.
        let peer_id = || ConfigField {
            name: "peer_id".to_string(),
            label: "Peer ID".to_string(),
            field_type: "text".to_string(),
            required: true,
            default_value: None,
            placeholder: None,
        };
        vec![
            ConnectorOperation { id: "disable_peer".to_string(), label: "Disable peer".to_string(),
                icon: "fa-plug-circle-xmark".to_string(), params: vec![peer_id()], destructive: true },
            ConnectorOperation { id: "enable_peer".to_string(), label: "Enable peer".to_string(),
                icon: "fa-plug-circle-check".to_string(), params: vec![peer_id()], destructive: false },
            ConnectorOperation { id: "create_group".to_string(), label: "Create group".to_string(),
                icon: "fa-layer-group".to_string(),
                params: vec![ConfigField {
                    name: "name".to_string(), label: "Group name".to_string(),
                    field_type: "text".to_string(), required: true,
                    default_value: None, placeholder: None,
                }],
                destructive: false },
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

            match Self::api_get(&instance.base_url, credentials, "/api/peers").await {
                Ok(_) => HealthStatus {
                    status: ServiceStatus::Online,
                    message: "Connected".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    last_checked: now,
                    version: None,
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
            match operation {
                "list_peers" => Self::api_get(base, credentials, "/api/peers").await,

                "get_peer" => {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or("Missing 'peer_id' parameter")?;
                    Self::api_get(base, credentials, &format!("/api/peers/{}", peer_id)).await
                }

                "disable_peer" => {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or("Missing 'peer_id' parameter")?;
                    let body = serde_json::json!({ "enabled": false });
                    Self::api_put(base, credentials, &format!("/api/peers/{}", peer_id), &body).await
                }

                "enable_peer" => {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or("Missing 'peer_id' parameter")?;
                    let body = serde_json::json!({ "enabled": true });
                    Self::api_put(base, credentials, &format!("/api/peers/{}", peer_id), &body).await
                }

                "list_groups" => Self::api_get(base, credentials, "/api/groups").await,

                "list_routes" => Self::api_get(base, credentials, "/api/routes").await,

                "list_users" => Self::api_get(base, credentials, "/api/users").await,

                "create_group" => {
                    Self::api_post(base, credentials, "/api/groups", params).await
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
                "peers" => self.execute(instance, credentials, "list_peers", &empty).await,
                "groups" => self.execute(instance, credentials, "list_groups", &empty).await,
                "routes" => self.execute(instance, credentials, "list_routes", &empty).await,
                "users" => self.execute(instance, credentials, "list_users", &empty).await,
                _ => Err(format!("Unknown capability: {}", capability_id)),
            }
        })
    }
}
