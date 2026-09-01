# Enterprise License Server Reporting — Implementation Plan

## Summary

When a WolfStack node has an Enterprise license, it should report back to IntelligentWolf which servers are using that license. This lets you verify the customer is paying for the right number of servers (£79/server/year) and gives you visibility into your Enterprise deployments.

## What Gets Reported

Each node with an active Enterprise license periodically sends a heartbeat to the Wolf licensing server containing:

- **License key** (the key they were issued)
- **Node ID** (unique per WolfStack install)
- **Hostname**
- **Cluster name**
- **Cluster node count** (how many nodes this server sees in its cluster)
- **Node list** (id + hostname for each node in the cluster — so you see all servers under one license)
- **WolfStack version**
- **OS** (e.g. "Debian 12", "Ubuntu 24.04", "Arch")
- **Architecture** (x86_64, aarch64)
- **Uptime**
- **First seen timestamp** (when this node first activated the license)

## What Does NOT Get Reported

- No user data, container names, VM names, or application data
- No IP addresses (privacy)
- No metrics (CPU/RAM/disk)
- No config files or secrets

## Implementation

### 1. Backend heartbeat (`src/compat/mod.rs`)

Add a function `report_license_usage()`:

```rust
pub async fn report_license_usage(cluster: &ClusterState, license_key: &str) {
    let nodes = cluster.get_all_nodes();
    let payload = serde_json::json!({
        "license_key": license_key,
        "reporter_node_id": self_node_id(),
        "reporter_hostname": hostname(),
        "cluster_name": cluster_name(),
        "wolfstack_version": env!("CARGO_PKG_VERSION"),
        "os": detect_os(),
        "arch": std::env::consts::ARCH,
        "node_count": nodes.len(),
        "nodes": nodes.iter().map(|n| serde_json::json!({
            "id": n.id,
            "hostname": n.hostname,
            "online": n.online,
        })).collect::<Vec<_>>(),
        "uptime_secs": system_uptime(),
        "reported_at": chrono::Utc::now().to_rfc3339(),
    });

    let _ = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default()
        .post("https://wolfscale.org/adminsys/heartbeat.php")
        .json(&payload)
        .send()
        .await;
    // Fire and forget — never block or fail the server if reporting fails
}
```

### 2. Background task (`src/main.rs`)

Add a `tokio::spawn` loop that runs every 24 hours:

```rust
if compat::platform_ready() {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(300)).await; // 5 min after boot
        loop {
            compat::report_license_usage(&cluster, &license_key).await;
            tokio::time::sleep(Duration::from_secs(86400)).await; // daily
        }
    });
}
```

### 3. Your licensing server (`license.wolf.uk.com`)

Build a simple API that:
- Receives heartbeats at `POST /api/v1/heartbeat`
- Validates the license key exists
- Stores the node list per license
- Dashboard shows: license key → customer → node count → list of hostnames → last seen
- Alerts you if a license is being used on more servers than they're paying for

### 4. WolfStack admin UI

In Settings → License, show:
- "This license is reporting usage to IntelligentWolf"
- "X servers detected on this license"
- List of server hostnames in the cluster
- Last report timestamp
- Link to privacy policy explaining what's reported

### 5. Privacy & transparency

- Add a note to the Enterprise docs: "Enterprise licenses report server count to IntelligentWolf for license compliance"
- The reporting is non-blocking — if the server can't reach license.wolf.uk.com, WolfStack continues working normally
- No kill switch — the license doesn't stop working if reporting fails
- Customers can see exactly what's reported in the UI

## Files to Modify

| File | Change |
|------|--------|
| `src/compat/mod.rs` | Add `report_license_usage()` function |
| `src/main.rs` | Add daily background heartbeat task |
| `web/js/app.js` | Show reporting status in Settings → License |

## Licensing Server

Already built at `wolfscale.org/adminsys/`:
- `heartbeat.php` — receives daily heartbeats, stores per-license
- `dashboard.php` — shows all licenses with active server counts, over-limit warnings, expandable server list per license
- `generate.php` — creates Ed25519-signed license keys with correct feature flags (api_keys, sso, plugins, wolfhost, wolfcustom)
