// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Hetzner Cloud Load Balancer client. Endpoints + body shapes
//! verified against hcloud-go (the official Hetzner Cloud Go SDK):
//!   github.com/hetznercloud/hcloud-go/main/hcloud/load_balancer.go
//!   github.com/hetznercloud/hcloud-go/main/hcloud/schema/load_balancer.go
//!
//! API surface used by the reconciler:
//!
//!   Base: https://api.hetzner.cloud/v1
//!   Auth: Authorization: Bearer <token>
//!
//!   GET    /load_balancers                                  list (used to find an existing LB by name)
//!   POST   /load_balancers                                  create — body has name, load_balancer_type (id_or_name),
//!                                                            location, services[], targets[]
//!   GET    /load_balancers/{id}                             read current targets
//!   POST   /load_balancers/{id}/actions/add_target          {type:"ip", ip:{ip:"1.2.3.4"}}
//!   POST   /load_balancers/{id}/actions/remove_target       same body
//!   DELETE /load_balancers/{id}                             tear-down
//!
//! For WolfStack: targets are IP-type (operator's WolfStack nodes
//! may not be Hetzner-Cloud servers, and even when they are we can't
//! always resolve server-ID from a public IP). IP targets work for
//! any reachable IPv4/IPv6.

// This module is a complete API client. The reconcile loop today
// uses find_by_name / create_lb / add_target_ip / remove_target_ip /
// ping; delete_lb and read_lb are reachable via cleanup-on-strategy-
// change and the LB-status REST endpoint respectively, both of which
// route through this same client.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.hetzner.cloud/v1";

#[derive(Debug, Clone, Deserialize)]
pub struct HetznerCloudCreds {
    pub api_token: String,
}

impl HetznerCloudCreds {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(v.clone()).map_err(|e| {
            format!("hetzner-cloud credentials: expected {{\"api_token\":\"…\"}}: {}", e)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancer {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub public_net: PublicNet,
    #[serde(default)]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicNet {
    #[serde(default)]
    pub ipv4: Option<PublicIp>,
    #[serde(default)]
    pub ipv6: Option<PublicIp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIp {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub dns_ptr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    #[serde(rename = "type")]
    pub target_type: String,
    #[serde(default)]
    pub ip: Option<TargetIp>,
    #[serde(default)]
    pub server: Option<TargetServerRef>,
    #[serde(default)]
    pub health_status: Vec<HealthStatus>,
    #[serde(default)]
    pub use_private_ip: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetIp {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetServerRef {
    pub id: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthStatus {
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LbEnvelope { load_balancer: LoadBalancer }

#[derive(Debug, Clone, Deserialize)]
struct LbListEnvelope { #[serde(default)] load_balancers: Vec<LoadBalancer> }

#[derive(Debug, Clone, Deserialize)]
struct ActionEnvelope {
    /// Hetzner's action result is opaque to us; we just check the
    /// HTTP status code for success.
    #[serde(default)]
    action: serde_json::Value,
}

// ─── Public API ─────────────────────────────────────────────────────────

/// Find an LB by name. Hetzner Cloud LB names are unique per project,
/// so this is the natural lookup key once you've created one.
pub async fn find_by_name(creds: &HetznerCloudCreds, name: &str) -> Result<Option<LoadBalancer>, String> {
    let url = format!("{}/load_balancers?name={}", API_BASE, urlencode(name));
    let env: LbListEnvelope = http_get(creds, &url).await?;
    Ok(env.load_balancers.into_iter().find(|lb| lb.name == name))
}

/// Provision a new LB with a single HTTP service on :80 and an
/// optional HTTPS service on :443 forwarding to the same on the
/// targets. v23.2 keeps the service shape simple — the WolfStack
/// nodes themselves run nginx that handles all the L7 niceties; the
/// Hetzner LB is just L4-style forwarding (well, L7 HTTP per
/// Hetzner's terminology but no host-routing).
pub async fn create_lb(
    creds: &HetznerCloudCreds,
    name: &str,
    location: &str,                  // "fsn1" / "nbg1" / "hel1" / "ash" / "hil"
    target_ips: &[String],
    https_enabled: bool,
) -> Result<LoadBalancer, String> {
    let url = format!("{}/load_balancers", API_BASE);
    let mut services = vec![service_body("http", 80, 80)];
    if https_enabled {
        // tls-passthrough mode: LB forwards encrypted bytes to the
        // origin's :443 untouched. nginx/wolfproxy on the origin
        // terminates TLS using its own cert. This is the only way to
        // do HTTPS without uploading certs to Hetzner Cloud.
        services.push(serde_json::json!({
            "protocol": "tcp",
            "listen_port": 443,
            "destination_port": 443,
            "proxyprotocol": false,
            "health_check": health_check_body(),
        }));
    }
    let targets: Vec<serde_json::Value> = target_ips.iter().map(|ip| {
        serde_json::json!({
            "type": "ip",
            "ip": { "ip": ip },
            "use_private_ip": false,
        })
    }).collect();
    let body = serde_json::json!({
        "name": name,
        "load_balancer_type": { "name": "lb11" },  // smallest size — ~€5/mo
        "location": location,
        "algorithm": { "type": "round_robin" },
        "services": services,
        "targets": targets,
        "public_interface": true,
    });
    let env: LbEnvelope = http_post(creds, &url, &body).await?;
    Ok(env.load_balancer)
}

pub async fn add_target_ip(creds: &HetznerCloudCreds, lb_id: i64, ip: &str) -> Result<(), String> {
    let url = format!("{}/load_balancers/{}/actions/add_target", API_BASE, lb_id);
    let body = serde_json::json!({
        "type": "ip",
        "ip": { "ip": ip },
        "use_private_ip": false,
    });
    let _: ActionEnvelope = http_post(creds, &url, &body).await?;
    Ok(())
}

pub async fn remove_target_ip(creds: &HetznerCloudCreds, lb_id: i64, ip: &str) -> Result<(), String> {
    let url = format!("{}/load_balancers/{}/actions/remove_target", API_BASE, lb_id);
    let body = serde_json::json!({
        "type": "ip",
        "ip": { "ip": ip },
    });
    let _: ActionEnvelope = http_post(creds, &url, &body).await?;
    Ok(())
}

pub async fn read_lb(creds: &HetznerCloudCreds, lb_id: i64) -> Result<LoadBalancer, String> {
    let url = format!("{}/load_balancers/{}", API_BASE, lb_id);
    let env: LbEnvelope = http_get(creds, &url).await?;
    Ok(env.load_balancer)
}

pub async fn delete_lb(creds: &HetznerCloudCreds, lb_id: i64) -> Result<(), String> {
    let url = format!("{}/load_balancers/{}", API_BASE, lb_id);
    http_delete(creds, &url).await
}

/// Cheap proof-of-token via list-LBs. Empty list is fine — just
/// proves the token is accepted.
pub async fn ping(creds: &HetznerCloudCreds) -> Result<usize, String> {
    let url = format!("{}/load_balancers?per_page=1", API_BASE);
    let env: LbListEnvelope = http_get(creds, &url).await?;
    Ok(env.load_balancers.len())
}

fn service_body(protocol: &str, listen_port: u16, destination_port: u16) -> serde_json::Value {
    serde_json::json!({
        "protocol": protocol,
        "listen_port": listen_port,
        "destination_port": destination_port,
        "proxyprotocol": false,
        "health_check": health_check_body(),
    })
}

fn health_check_body() -> serde_json::Value {
    // Conservative defaults — 5s interval, 3 retries before unhealthy.
    serde_json::json!({
        "protocol": "tcp",
        "port": 80,
        "interval": 15,
        "timeout": 10,
        "retries": 3,
    })
}

// ─── Internals ──────────────────────────────────────────────────────────

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client builder")
}

async fn http_get<T: for<'de> Deserialize<'de>>(creds: &HetznerCloudCreds, url: &str) -> Result<T, String> {
    let resp = client().get(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .send().await
        .map_err(|e| format!("hetzner-lb GET {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("hetzner-lb GET {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("hetzner-lb GET {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_post<T: for<'de> Deserialize<'de>>(creds: &HetznerCloudCreds, url: &str, body: &serde_json::Value) -> Result<T, String> {
    let resp = client().post(url)
        .bearer_auth(&creds.api_token)
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| format!("hetzner-lb POST {}: {}", url, e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("hetzner-lb POST {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("hetzner-lb POST {}: bad JSON: {}: {}", url, e, truncate(&text, 200)))
}

async fn http_delete(creds: &HetznerCloudCreds, url: &str) -> Result<(), String> {
    let resp = client().delete(url)
        .bearer_auth(&creds.api_token)
        .send().await
        .map_err(|e| format!("hetzner-lb DELETE {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("hetzner-lb DELETE {}: HTTP {}: {}", url, status, truncate(&text, 200)));
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let cut: String = s.chars().take(max).collect();
    format!("{}…", cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creds_parse() {
        let v = serde_json::json!({"api_token": "tok"});
        assert_eq!(HetznerCloudCreds::from_value(&v).unwrap().api_token, "tok");
    }

    #[test]
    fn service_body_shape() {
        let b = service_body("http", 80, 80);
        assert_eq!(b["protocol"], "http");
        assert_eq!(b["listen_port"], 80);
        assert_eq!(b["destination_port"], 80);
        assert!(b["health_check"].is_object());
    }
}
