// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! TrueNAS connector — monitor pools, datasets, snapshots, shares, and
//! system info via the TrueNAS REST API (v2.0).

use crate::integrations::{
    AuthMethod, ConfigField, Connector, ConnectorCapability, ConnectorInfo,
    ConnectorOperation, HealthStatus, IntegrationInstance, ServiceStatus,
};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Shared HTTP client for every TrueNAS API call. Previously each
/// api_get / api_post built its own Client with a baked-in auth
/// header via default_headers — one leaked connection pool per call.
/// We now send the Authorization header per-request so the shared
/// pool works across every instance (different tokens = different
/// instances, same connection pool is safe since each request
/// carries its own header).
static TRUENAS_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

pub struct TrueNasConnector;

impl TrueNasConnector {
    /// Extract the bearer token from the credentials blob.
    fn auth_header(credentials: &serde_json::Value) -> Result<String, String> {
        let token = credentials.get("token")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'token' in credentials")?;
        Ok(format!("Bearer {}", token))
    }

    async fn api_get(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
    ) -> Result<serde_json::Value, String> {
        let auth = Self::auth_header(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = TRUENAS_CLIENT.get(&url)
            .header("Authorization", auth)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            // Drain error body → socket returns to the pool.
            let _ = resp.bytes().await;
            return Err(format!("TrueNAS API error: {} {}", status, url));
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
        let resp = TRUENAS_CLIENT.post(&url)
            .header("Authorization", auth)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(format!("TrueNAS API error: {} {} — {}", status, url, body_text));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }
}

impl Connector for TrueNasConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            id: "truenas".to_string(),
            name: "TrueNAS".to_string(),
            icon: "fa-database".to_string(),
            description: "Monitor and manage TrueNAS pools, datasets, snapshots, and shares".to_string(),
            auth_methods: vec![AuthMethod::Bearer],
            config_schema: vec![
                ConfigField {
                    name: "base_url".to_string(),
                    label: "TrueNAS URL".to_string(),
                    field_type: "url".to_string(),
                    required: true,
                    default_value: None,
                    placeholder: Some("https://truenas.local".to_string()),
                },
            ],
        }
    }

    fn capabilities(&self) -> Vec<ConnectorCapability> {
        vec![
            ConnectorCapability {
                id: "pools".to_string(),
                label: "Storage Pools".to_string(),
                icon: "fa-hard-drive".to_string(),
            },
            ConnectorCapability {
                id: "datasets".to_string(),
                label: "Datasets".to_string(),
                icon: "fa-folder-tree".to_string(),
            },
            ConnectorCapability {
                id: "snapshots".to_string(),
                label: "Snapshots".to_string(),
                icon: "fa-camera".to_string(),
            },
            ConnectorCapability {
                id: "shares".to_string(),
                label: "Shares".to_string(),
                icon: "fa-share-nodes".to_string(),
            },
            ConnectorCapability {
                id: "system".to_string(),
                label: "System Info".to_string(),
                icon: "fa-server".to_string(),
            },
        ]
    }

    fn operations(&self) -> Vec<ConnectorOperation> {
        // execute create_snapshot reads params["dataset"], params["name"] and
        // optional params["recursive"] (truenas.rs). Verified.
        vec![
            ConnectorOperation {
                id: "create_snapshot".to_string(),
                label: "Create snapshot".to_string(),
                icon: "fa-camera".to_string(),
                params: vec![
                    ConfigField {
                        name: "dataset".to_string(), label: "Dataset".to_string(),
                        field_type: "text".to_string(), required: true,
                        default_value: None, placeholder: Some("tank/data".to_string()),
                    },
                    ConfigField {
                        name: "name".to_string(), label: "Snapshot name".to_string(),
                        field_type: "text".to_string(), required: true,
                        default_value: None, placeholder: Some("manual-2026-07-01".to_string()),
                    },
                    ConfigField {
                        name: "recursive".to_string(), label: "Recursive".to_string(),
                        field_type: "checkbox".to_string(), required: false,
                        default_value: Some("false".to_string()), placeholder: None,
                    },
                ],
                destructive: false,
            },
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

            match Self::api_get(&instance.base_url, credentials, "/api/v2.0/system/info").await {
                Ok(info) => {
                    let version = info.get("version")
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
            match operation {
                "system_info" => {
                    Self::api_get(base, credentials, "/api/v2.0/system/info").await
                }

                "pool_status" => {
                    Self::api_get(base, credentials, "/api/v2.0/pool").await
                }

                "list_datasets" => {
                    Self::api_get(base, credentials, "/api/v2.0/pool/dataset").await
                }

                "list_snapshots" => {
                    Self::api_get(base, credentials, "/api/v2.0/zfs/snapshot").await
                }

                "create_snapshot" => {
                    let dataset = params.get("dataset").and_then(|v| v.as_str())
                        .ok_or("Missing 'dataset' parameter")?;
                    let name = params.get("name").and_then(|v| v.as_str())
                        .unwrap_or("wolfstack-manual");
                    let body = serde_json::json!({
                        "dataset": dataset,
                        "name": name,
                        // Accept a JSON boolean OR a "true"/"false" string, so
                        // both a checkbox (boolean) and a raw API caller work.
                        "recursive": params.get("recursive")
                            .and_then(|v| v.as_bool().or_else(|| v.as_str().and_then(|s| s.parse::<bool>().ok())))
                            .unwrap_or(false),
                    });
                    Self::api_post(base, credentials, "/api/v2.0/zfs/snapshot", &body).await
                }

                "list_smb_shares" => {
                    Self::api_get(base, credentials, "/api/v2.0/sharing/smb").await
                }

                "list_nfs_shares" => {
                    Self::api_get(base, credentials, "/api/v2.0/sharing/nfs").await
                }

                "list_alerts" => {
                    Self::api_get(base, credentials, "/api/v2.0/alert/list").await
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
                "pools" => self.execute(instance, credentials, "pool_status", &empty).await,
                "datasets" => self.execute(instance, credentials, "list_datasets", &empty).await,
                "snapshots" => self.execute(instance, credentials, "list_snapshots", &empty).await,
                "shares" => {
                    // Combine SMB + NFS shares into one response
                    let smb = self.execute(instance, credentials, "list_smb_shares", &empty).await.unwrap_or_default();
                    let nfs = self.execute(instance, credentials, "list_nfs_shares", &empty).await.unwrap_or_default();
                    Ok(serde_json::json!({ "smb": smb, "nfs": nfs }))
                }
                "system" => self.execute(instance, credentials, "system_info", &empty).await,
                _ => Err(format!("Unknown capability: {}", capability_id)),
            }
        })
    }
}
