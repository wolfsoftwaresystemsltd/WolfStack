// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Docker image update watcher — checks whether container images have newer
//! versions available in their upstream registries and optionally auto-updates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{error, warn};

const CONFIG_FILE: &str = "/etc/wolfstack/image-watcher.json";

/// Shared HTTP client for registry auth + manifest fetches. Same
/// pattern as src/wolfrun/mod.rs (v19.8.1): one pool for the lifetime
/// of the process. Per-call `reqwest::Client::new()` was leaking
/// connection pools on every image check (one call to the token
/// endpoint + one HEAD to the registry per watched container, every
/// `check_interval_secs`).
static IMG_WATCH_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageWatcherConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
    #[serde(default)]
    pub default_policy: UpdatePolicy,
    #[serde(default)]
    pub container_policies: HashMap<String, ContainerUpdatePolicy>,
    #[serde(default)]
    pub update_history: Vec<ImageUpdateEvent>,
    /// Optional 5-field cron expression (`m h dom mon dow`) gating the
    /// AUTO-APPLY path. The CHECK loop still runs on its own interval
    /// regardless — operators want the dashboard to show pending
    /// updates 24/7. When `None`, auto-apply fires as soon as an
    /// update is detected for an `AutoUpdate` container. Common
    /// values: `"0 4 * * 0"` (Sundays 04:00 UTC), `"0 3 * * *"`
    /// (daily 03:00 UTC). Reuses `wolfflow::cron_matches` so the
    /// semantics match the rest of WolfFlow's cron handling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_cron: Option<String>,
    /// How long after a cron-match the auto-apply window stays open.
    /// At default 60 the loop applies for the first hour after each
    /// cron-fire. Anything outside this window holds back the apply
    /// until the next fire. Set higher if a single batch can take
    /// longer than an hour on slow links.
    #[serde(default = "default_window_minutes")]
    pub schedule_window_minutes: u64,
    /// Maximum number of containers to auto-update concurrently. Each
    /// apply involves a docker pull (network) + stop / start (kernel
    /// + I/O), so 1 by default avoids storming the host. Operators
    /// with fast networks and beefy hosts can raise this.
    #[serde(default = "default_max_parallel_updates")]
    pub max_parallel_updates: usize,
}

fn default_check_interval() -> u64 { 3600 }
fn default_window_minutes() -> u64 { 60 }
fn default_max_parallel_updates() -> usize { 1 }

impl Default for ImageWatcherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: default_check_interval(),
            default_policy: UpdatePolicy::default(),
            container_policies: HashMap::new(),
            update_history: Vec::new(),
            schedule_cron: None,
            schedule_window_minutes: default_window_minutes(),
            max_parallel_updates: default_max_parallel_updates(),
        }
    }
}

impl ImageWatcherConfig {
    /// Resolve the effective per-container policy: explicit entry in
    /// `container_policies` wins; falls back to a fresh policy whose
    /// `policy` field is `default_policy`. Single source of truth so
    /// check + apply paths can't disagree.
    pub fn policy_for(&self, container_name: &str) -> ContainerUpdatePolicy {
        if let Some(p) = self.container_policies.get(container_name) {
            return p.clone();
        }
        ContainerUpdatePolicy {
            policy: self.default_policy.clone(),
            ..ContainerUpdatePolicy::default()
        }
    }

    /// How often to check a specific container, in seconds: its own
    /// `check_interval_secs` override if set, else the global interval.
    /// The global keeps its historical 300s floor (so installs that never
    /// set an override behave exactly as before); an explicit per-container
    /// override may go as low as 60s (registry-protection floor) so an
    /// operator can watch a fast-moving image more closely.
    pub fn effective_interval_secs(&self, container_name: &str) -> u64 {
        match self.container_policies.get(container_name)
            .and_then(|p| p.check_interval_secs)
            .filter(|&s| s > 0)
        {
            Some(s) => s.max(60),
            None => self.check_interval_secs.max(300),
        }
    }

    /// The shortest effective interval across the global setting and every
    /// per-container override — i.e. how often the background loop must
    /// wake to honour the most-frequently-checked container. Passive
    /// (Ignore/Pinned) containers are skipped: they're never checked, so
    /// their override must not drag the whole loop's cadence down.
    pub fn min_effective_interval_secs(&self) -> u64 {
        let mut m = self.check_interval_secs.max(300);
        for p in self.container_policies.values() {
            if p.is_passive() { continue; }
            if let Some(s) = p.check_interval_secs {
                if s > 0 { m = m.min(s.max(60)); }
            }
        }
        m
    }

    /// Copy the CLUSTER-WIDE settings from `other` onto self, preserving this
    /// node's host-specific state. Applied when a config push arrives from a
    /// cluster peer: `enabled`, the check interval, the default policy, and the
    /// auto-apply schedule are cluster decisions and must match everywhere, but
    /// `container_policies` key on THIS host's container names and
    /// `update_history` is THIS host's audit trail — both stay local so a
    /// cluster-wide enable never wipes them. Single source of truth for what
    /// counts as "cluster-wide" so the API handler and any future caller agree.
    pub fn merge_cluster_settings_from(&mut self, other: &Self) {
        self.enabled = other.enabled;
        self.check_interval_secs = other.check_interval_secs;
        self.default_policy = other.default_policy.clone();
        self.schedule_cron = other.schedule_cron.clone();
        self.schedule_window_minutes = other.schedule_window_minutes;
        self.max_parallel_updates = other.max_parallel_updates;
    }

    /// True when the CLUSTER-WIDE settings (the ones `merge_cluster_settings_from`
    /// copies) are identical between the two configs. Lets the save handler skip
    /// a cluster fan-out when only host-local state changed — e.g. an operator
    /// pinning a single container — so a per-container edit never triggers (or
    /// blocks on) peer propagation.
    pub fn cluster_settings_eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.check_interval_secs == other.check_interval_secs
            && self.default_policy == other.default_policy
            && self.schedule_cron == other.schedule_cron
            && self.schedule_window_minutes == other.schedule_window_minutes
            && self.max_parallel_updates == other.max_parallel_updates
    }

    /// True when the auto-apply window is currently open. With no
    /// schedule configured, the window is always open (apply
    /// immediately on detection). With a cron set, the window opens
    /// at each cron-match and stays open for `schedule_window_minutes`
    /// minutes. Used by the background loop and the bulk-apply API
    /// to enforce maintenance hours.
    ///
    /// `now` is parameterised so tests can pin a clock; production
    /// callers pass `chrono::Utc::now().naive_utc()`.
    pub fn auto_apply_window_open(&self, now: chrono::NaiveDateTime) -> bool {
        let Some(cron) = self.schedule_cron.as_deref() else {
            return true; // no schedule == always open
        };
        let cron = cron.trim();
        if cron.is_empty() { return true; }
        let window = self.schedule_window_minutes.max(1);
        // Walk backwards minute-by-minute over the window. If any
        // minute in [now - window, now] matched the cron, the window
        // is open right now. Cheap: ≤ window iterations of a string
        // compare per call.
        for offset_min in 0..window {
            let when = now - chrono::Duration::minutes(offset_min as i64);
            if crate::wolfflow::cron_matches(cron, &when) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePolicy {
    /// Detect updates and surface them in the UI / Predictive Inbox,
    /// but never apply automatically. Operator clicks "Update now".
    NotifyOnly,
    /// Detect updates and apply automatically within the maintenance
    /// window. Backup + health-check + rollback semantics governed by
    /// the per-container flags.
    AutoUpdate,
    /// Don't even check this container. Useful for one-off / locally-
    /// built images where the registry roundtrip is wasteful.
    Ignore,
    /// Lock this container to a specific tag or digest. The check
    /// loop SKIPS the remote query (same as Ignore for the auto-apply
    /// path) so a pinned container never auto-updates. The pin target
    /// is stored in `ContainerUpdatePolicy.pinned_to` and surfaced in
    /// the UI so the operator can see WHAT it's pinned to without
    /// looking at the deploy config.
    Pinned,
}

impl Default for UpdatePolicy {
    fn default() -> Self { Self::NotifyOnly }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerUpdatePolicy {
    #[serde(default = "default_notify_only")]
    pub policy: UpdatePolicy,
    /// Tag (`1.2.3`, `stable`) or fully-qualified digest
    /// (`sha256:abc…`) the operator has pinned this container to.
    /// Only meaningful when `policy == UpdatePolicy::Pinned`. Stored
    /// as a free-form string — validation happens at the API layer
    /// (refuse Pinned policy without a non-empty target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_to: Option<String>,
    #[serde(default = "default_true")]
    pub backup_before_update: bool,
    #[serde(default = "default_true")]
    pub health_check: bool,
    #[serde(default = "default_health_check_timeout")]
    pub health_check_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub auto_rollback: bool,
    /// How often to check THIS container for an image update, in seconds.
    /// `None` (or 0) means "use the global `check_interval_secs`". Lets an
    /// operator watch a fast-moving image hourly while a stable one is
    /// checked once a day, per container/compose service. Floored to 60s
    /// when applied so a typo can't hammer registries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_interval_secs: Option<u64>,
}

fn default_notify_only() -> UpdatePolicy { UpdatePolicy::NotifyOnly }
fn default_true() -> bool { true }
fn default_health_check_timeout() -> u64 { 60 }

impl Default for ContainerUpdatePolicy {
    fn default() -> Self {
        Self {
            policy: UpdatePolicy::NotifyOnly,
            pinned_to: None,
            backup_before_update: true,
            health_check: true,
            health_check_timeout_secs: default_health_check_timeout(),
            auto_rollback: true,
            check_interval_secs: None,
        }
    }
}

impl ContainerUpdatePolicy {
    /// True when this policy means "do nothing automatically" — covers
    /// both `Ignore` (don't even check) and `Pinned` (check is also
    /// skipped because we'd just be measuring drift the operator
    /// already accepted). Use this everywhere the auto-apply loop or
    /// check loop needs to decide whether to touch a container.
    pub fn is_passive(&self) -> bool {
        matches!(self.policy, UpdatePolicy::Ignore | UpdatePolicy::Pinned)
    }

    /// True when this policy means "apply updates automatically when
    /// detected" — only `AutoUpdate` qualifies. NotifyOnly surfaces
    /// updates but doesn't apply; Pinned never applies; Ignore never
    /// even checks.
    pub fn is_auto_apply(&self) -> bool {
        matches!(self.policy, UpdatePolicy::AutoUpdate)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUpdateEvent {
    pub id: String,
    pub container_name: String,
    pub image: String,
    pub old_digest: String,
    pub new_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    #[serde(default)]
    pub status: ImageUpdateStatus,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImageUpdateStatus {
    UpdateAvailable,
    BackingUp,
    Pulling,
    Recreating,
    HealthChecking,
    Completed,
    RolledBack,
    Failed,
}

impl Default for ImageUpdateStatus {
    fn default() -> Self { Self::UpdateAvailable }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageCheckResult {
    pub container_name: String,
    pub image: String,
    pub local_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_digest: Option<String>,
    pub update_available: bool,
    pub last_checked: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════
// ─── Image Reference Parsing ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub struct ImageRef {
    pub registry: String,
    pub repo: String,
    pub tag: String,
}

impl ImageRef {
    /// Parse a Docker image reference into registry, repo, and tag components.
    ///
    /// Examples:
    /// - `nginx`            → registry-1.docker.io / library/nginx : latest
    /// - `user/repo:v2`     → registry-1.docker.io / user/repo    : v2
    /// - `ghcr.io/org/app:latest` → ghcr.io / org/app : latest
    /// - `docker.io/redis:6.2-alpine@sha256:905c…` → registry-1.docker.io /
    ///   library/redis : 6.2-alpine (digest pin stripped — the tag's CURRENT
    ///   remote digest is what an update check compares against)
    pub fn parse(image: &str) -> Self {
        // Digest-pinned references (`repo:tag@sha256:…`, as compose files
        // write after `docker compose pull`) broke the old parser: the last
        // colon sits INSIDE the digest, so repo became "redis:6.2-alpine@sha256"
        // and the token scope was garbage (pm1, 2026-07-03). Strip the pin —
        // digest comparison against the local RepoDigest works unchanged.
        let image = image.split_once('@').map(|(before, _)| before).unwrap_or(image);

        let (name, tag) = match image.rsplit_once(':') {
            // Guard against treating a port number as a tag, e.g. "host:5000/repo"
            Some((n, t)) if !t.contains('/') => (n, t.to_string()),
            _ => (image, "latest".to_string()),
        };

        // Determine if the first component is a registry hostname.
        // A hostname contains a dot or a colon (port), or is "localhost".
        let parts: Vec<&str> = name.splitn(2, '/').collect();

        if parts.len() == 1 {
            // Official image: "nginx"
            Self {
                registry: "registry-1.docker.io".into(),
                repo: format!("library/{}", parts[0]),
                tag,
            }
        } else {
            let first = parts[0];
            let rest = parts[1];

            if first == "docker.io" || first == "index.docker.io" {
                // Explicit Hub prefix (compose files write `docker.io/redis`).
                // The Hub's API host is registry-1.docker.io — treating
                // "docker.io" as a literal registry sent token requests to
                // https://docker.io/token, which doesn't exist (pm1,
                // 2026-07-03). Single-component repos need `library/`.
                Self {
                    registry: "registry-1.docker.io".into(),
                    repo: if rest.contains('/') { rest.into() } else { format!("library/{}", rest) },
                    tag,
                }
            } else if first.contains('.') || first.contains(':') || first == "localhost" {
                // Custom registry: "ghcr.io/org/app" or "localhost:5000/myimg"
                Self {
                    registry: first.into(),
                    repo: rest.into(),
                    tag,
                }
            } else {
                // Docker Hub user image: "user/repo"
                Self {
                    registry: "registry-1.docker.io".into(),
                    repo: name.into(),
                    tag,
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Config Persistence ───
// ═══════════════════════════════════════════════

impl ImageWatcherConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_FILE) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(dir) = std::path::Path::new(CONFIG_FILE).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_FILE, json).map_err(|e| e.to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── Local Digest ───
// ═══════════════════════════════════════════════

/// Get the image digest for a running container by inspecting Docker locally.
/// Returns the repo-digest string (e.g. `nginx@sha256:abc123...`).
/// Async: runs on the tokio runtime inside the watcher's check sweep — the
/// old sync `std::process::Command` here (and in the other check-path
/// functions) blocked a runtime worker for every docker exec; on a node with
/// dozens of containers and a busy dockerd, a sweep visibly stalled the whole
/// web UI including WebSocket terminals (wabil's pm1, 2026-07-03).
pub async fn get_local_digest(container_name: &str) -> Result<String, String> {
    // First, get the image name from the container
    let image_out = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{.Config.Image}}", container_name])
        .output()
        .await
        .map_err(|e| format!("Failed to run docker inspect: {}", e))?;

    if !image_out.status.success() {
        return Err(format!(
            "docker inspect failed for container '{}': {}",
            container_name,
            String::from_utf8_lossy(&image_out.stderr).trim()
        ));
    }

    let image = String::from_utf8_lossy(&image_out.stdout).trim().to_string();
    if image.is_empty() {
        return Err(format!("No image found for container '{}'", container_name));
    }

    // Get the repo digest for the image
    let digest_out = tokio::process::Command::new("docker")
        .args(["image", "inspect", "--format", "{{index .RepoDigests 0}}", &image])
        .output()
        .await
        .map_err(|e| format!("Failed to inspect image '{}': {}", image, e))?;

    if !digest_out.status.success() {
        return Err(format!(
            "docker image inspect failed for '{}': {}",
            image,
            String::from_utf8_lossy(&digest_out.stderr).trim()
        ));
    }

    let digest = String::from_utf8_lossy(&digest_out.stdout).trim().to_string();
    if digest.is_empty() {
        return Err(format!("No repo digest available for image '{}' (locally built?)", image));
    }

    Ok(digest)
}

// ═══════════════════════════════════════════════
// ─── Registry Authentication ───
// ═══════════════════════════════════════════════

/// Last digest-check error per image ref — lets the watcher WARN only on
/// change/recovery instead of every poll cycle. std::sync::Mutex is fine:
/// never held across an await (lock, compare, insert/remove, drop).
static DIGEST_CHECK_LAST_ERRORS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Token response from a registry's auth endpoint.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

/// Discover a registry's token endpoint from the `WWW-Authenticate` header of
/// an unauthenticated `/v2/` probe (the flow the OCI distribution spec
/// defines). Returns `realm` and `service`. Guessing `https://{host}/token`
/// worked for ghcr but 404'd on lscr.io and other Harbor/quay-style hosts
/// (pm1, 2026-07-03) — the header is the authoritative source.
async fn discover_token_endpoint(registry: &str) -> Result<(String, String), String> {
    let url = format!("https://{}/v2/", registry);
    let resp = IMG_WATCH_CLIENT
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Probe of {} failed: {}", url, e))?;
    let hdr = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let _ = resp.bytes().await; // drain — socket back to the pool
    let hdr = hdr.ok_or_else(|| format!("{} sent no WWW-Authenticate header", url))?;
    // Format: Bearer realm="https://…",service="…"[,…] — quoted-string values.
    let field = |name: &str| -> Option<String> {
        let pat = format!("{}=\"", name);
        let start = hdr.find(&pat)? + pat.len();
        let end = hdr[start..].find('"')? + start;
        Some(hdr[start..end].to_string())
    };
    let realm = field("realm").ok_or_else(|| format!("No realm in WWW-Authenticate: {}", hdr))?;
    // service is optional in the spec; default to the registry host.
    let service = field("service").unwrap_or_else(|| registry.to_string());
    Ok((realm, service))
}

/// Obtain a bearer token for pulling manifest metadata from a registry.
pub async fn get_registry_token(registry: &str, repo: &str) -> Result<String, String> {
    let url = match registry {
        "registry-1.docker.io" => format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
            repo
        ),
        "ghcr.io" => format!(
            "https://ghcr.io/token?service=ghcr.io&scope=repository:{}:pull",
            repo
        ),
        other => {
            // Every other registry: ask the registry itself where its token
            // endpoint lives instead of guessing a path.
            let (realm, service) = discover_token_endpoint(other).await?;
            format!(
                "{}?service={}&scope=repository:{}:pull",
                realm,
                urlencoding::encode(&service),
                repo
            )
        }
    };

    let resp = IMG_WATCH_CLIENT
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Token request to {} failed: {}", url, e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        // `.text()` consumes the body, returning the socket to the pool.
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token endpoint returned {}: {}", status, body));
    }

    let body: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    Ok(body.token)
}

// ═══════════════════════════════════════════════
// ─── Remote Digest ───
// ═══════════════════════════════════════════════

/// Fetch the digest of an image tag from its upstream registry via the V2 manifest API.
pub async fn get_remote_digest(image_ref: &ImageRef) -> Result<String, String> {
    let token = get_registry_token(&image_ref.registry, &image_ref.repo).await?;

    let url = format!(
        "https://{}/v2/{}/manifests/{}",
        image_ref.registry, image_ref.repo, image_ref.tag
    );

    let resp = IMG_WATCH_CLIENT
        .head(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json",
        )
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        // Multi-arch OCI images (immich, most modern ghcr images) publish an
        // OCI image INDEX; without this accept type ghcr answers 404
        // MANIFEST_UNKNOWN even though the tag exists (pm1, 2026-07-03).
        .header(
            "Accept",
            "application/vnd.oci.image.index.v1+json",
        )
        .send()
        .await
        .map_err(|e| format!("Manifest HEAD request to {} failed: {}", url, e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Registry returned {} for {}: {}", status, url, body));
    }

    // Extract the digest header, then drain any body bytes so the
    // socket returns to the pool. HEAD responses usually have no
    // body, but draining is cheap and explicit.
    let digest = resp.headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let _ = resp.bytes().await;
    digest.ok_or_else(|| format!("No Docker-Content-Digest header in response from {}", url))
}

// ═══════════════════════════════════════════════
// ─── Container Update Checking ───
// ═══════════════════════════════════════════════

/// Check a single container for available image updates.
pub async fn check_container_update(container_name: &str) -> Result<ImageCheckResult, String> {
    let now = chrono::Utc::now().to_rfc3339();

    // Get the image name from the container. Async docker exec — this runs
    // on the runtime inside the watcher sweep; see get_local_digest's doc.
    let image_out = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{.Config.Image}}", container_name])
        .output()
        .await
        .map_err(|e| format!("Failed to run docker inspect: {}", e))?;

    if !image_out.status.success() {
        return Err(format!(
            "docker inspect failed for container '{}': {}",
            container_name,
            String::from_utf8_lossy(&image_out.stderr).trim()
        ));
    }

    let image = String::from_utf8_lossy(&image_out.stdout).trim().to_string();
    if image.is_empty() {
        return Err(format!("No image found for container '{}'", container_name));
    }

    // Get local digest
    let local_digest = match get_local_digest(container_name).await {
        Ok(d) => d,
        Err(e) => {
            return Ok(ImageCheckResult {
                container_name: container_name.into(),
                image: image.clone(),
                local_digest: String::new(),
                remote_digest: None,
                update_available: false,
                last_checked: now,
                error: Some(format!("Could not get local digest: {}", e)),
            });
        }
    };

    // Parse the image reference and fetch the remote digest
    let image_ref = ImageRef::parse(&image);
    match get_remote_digest(&image_ref).await {
        Ok(remote) => {
            // A previously-failing image now checks cleanly — log the
            // recovery once and forget the failure so a relapse warns anew.
            {
                let mut last = DIGEST_CHECK_LAST_ERRORS.lock().unwrap_or_else(|p| p.into_inner());
                if last.remove(&image).is_some() {
                    tracing::info!("Remote digest check recovered for {}", image);
                }
            }
            // Extract just the digest portion from the local repo-digest (after '@')
            let local_hash = local_digest
                .rsplit_once('@')
                .map(|(_, h)| h)
                .unwrap_or(&local_digest);
            let update_available = local_hash != remote;

            Ok(ImageCheckResult {
                container_name: container_name.into(),
                image,
                local_digest,
                remote_digest: Some(remote),
                update_available,
                last_checked: now,
                error: None,
            })
        }
        Err(e) => {
            // WARN only when this image's failure is NEW or its message
            // changed — the watcher re-checks on a timer, and repeating the
            // identical warning every cycle buries real problems (pm1 journal,
            // 2026-07-03; log-state-changes-not-heartbeats rule). The full
            // error still lands in ImageCheckResult.error for the UI every
            // time. Recovery clears the entry (see the Ok arm) so a relapse
            // warns again.
            {
                let mut last = DIGEST_CHECK_LAST_ERRORS.lock().unwrap_or_else(|p| p.into_inner());
                if last.get(&image).map(|prev| prev != &e).unwrap_or(true) {
                    warn!("Failed to check remote digest for {}: {}", image, e);
                    last.insert(image.clone(), e.clone());
                }
            }
            Ok(ImageCheckResult {
                container_name: container_name.into(),
                image,
                local_digest,
                remote_digest: None,
                update_available: false,
                last_checked: now,
                error: Some(e),
            })
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Auto-apply Path ───
// ═══════════════════════════════════════════════

/// Perform an image update for one Docker container, honouring the
/// configured per-container policy (backup / health-check /
/// auto-rollback). Synchronous + blocking — call from
/// `tokio::task::spawn_blocking`.
///
/// Sequence:
///   1. Refuse on passive policies (Ignore + Pinned) — the auto-loop
///      shouldn't reach here for those, but defense-in-depth keeps a
///      misuse from mutating a frozen container.
///   2. `docker inspect` captures the current config (image, ports,
///      volumes, env, restart policy, etc.) and the old image ID for
///      rollback.
///   3. Optional pre-update backup via `backup::backup_docker`. Backup
///      failures ABORT the update — better to leave the container
///      running on the old image than apply without a rollback path.
///   4. `docker pull <image>`; we then snapshot the new image ID.
///   5. If the pull didn't change the local image (no-op), record
///      Completed without recreating.
///   6. `docker stop` + `docker rm` + recreate-from-inspect — the
///      tag's now pointing at the new image so recreate naturally
///      picks it up.
///   7. Health check (if enabled): poll docker inspect for HEALTHCHECK
///      status, OR fall back to "Running for ≥10 seconds" when no
///      HEALTHCHECK is declared (very common for community images).
///   8. On health failure: if `auto_rollback`, recreate with the OLD
///      image ID; otherwise mark Failed and leave the container in
///      its degraded state for the operator to inspect.
///
/// Always returns an `ImageUpdateEvent` — the caller appends it to
/// `config.update_history` regardless of outcome so the operator has
/// a full audit trail.
pub fn perform_update_blocking(container_name: &str, config: &ImageWatcherConfig) -> ImageUpdateEvent {
    let event = run_update_blocking(container_name, config);

    // WolfFunctions container_updated / container_update_failed triggers.
    // Two outcomes are deliberate non-events: a passive-policy refusal
    // (nothing was attempted) and the already-at-latest short circuit
    // (Completed + error set, no recreate happened). force_local: the
    // update runs on exactly this node.
    let passive_refusal = config.policy_for(container_name).is_passive();
    let noop = event.status == ImageUpdateStatus::Completed && event.error.is_some();
    if !passive_refusal && !noop {
        let trigger = match event.status {
            ImageUpdateStatus::Completed =>
                Some(crate::wolffunctions::TriggerEvent::ContainerUpdated),
            ImageUpdateStatus::Failed | ImageUpdateStatus::RolledBack =>
                Some(crate::wolffunctions::TriggerEvent::ContainerUpdateFailed),
            // In-flight statuses can't be returned — every exit path
            // sets Completed, RolledBack, or Failed — but a payload-only
            // match arm is cheaper than asserting that here.
            _ => None,
        };
        if let Some(trigger) = trigger {
            crate::wolffunctions::fire_event_global(
                trigger,
                serde_json::to_value(&event).unwrap_or_default(),
                true,
            );
        }
    }
    event
}

/// The actual update pipeline — see `perform_update_blocking` (the public
/// wrapper that also fires WolfFunctions trigger events) for the step list.
fn run_update_blocking(container_name: &str, config: &ImageWatcherConfig) -> ImageUpdateEvent {
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let started_at_rfc = chrono::Utc::now().to_rfc3339();
    let policy = config.policy_for(container_name);
    let mut event = ImageUpdateEvent {
        id: event_id,
        container_name: container_name.into(),
        image: String::new(),
        old_digest: String::new(),
        new_digest: String::new(),
        backup_id: None,
        status: ImageUpdateStatus::UpdateAvailable,
        timestamp: started_at_rfc,
        error: None,
    };

    if policy.is_passive() {
        event.status = ImageUpdateStatus::Failed;
        event.error = Some(format!(
            "policy is {:?} — auto-apply refused",
            policy.policy,
        ));
        return event;
    }

    // Step 2: inspect.
    let inspect = match crate::containers::docker_inspect(container_name) {
        Ok(v) => v,
        Err(e) => {
            event.status = ImageUpdateStatus::Failed;
            event.error = Some(format!("docker inspect failed: {}", e));
            return event;
        }
    };
    let image = inspect.pointer("/Config/Image")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let old_image_id = inspect.pointer("/Image")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    event.image = image.clone();
    event.old_digest = old_image_id.clone();
    if image.is_empty() {
        event.status = ImageUpdateStatus::Failed;
        event.error = Some("could not determine image from docker inspect".into());
        return event;
    }

    // Step 3: optional backup.
    if policy.backup_before_update {
        event.status = ImageUpdateStatus::BackingUp;
        // Pre-update safety backup captures everything — no mount exclusions,
        // and hot (false): the container is about to be recreated anyway, and
        // stopping it here would just add downtime before the update.
        match crate::backup::backup_docker(container_name, &[], false) {
            Ok((path, _size, _sha, _mounts)) => {
                event.backup_id = path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string());
            }
            Err(e) => {
                event.status = ImageUpdateStatus::Failed;
                event.error = Some(format!("pre-update backup failed: {}", e));
                return event;
            }
        }
    }

    // Step 4: pull.
    event.status = ImageUpdateStatus::Pulling;
    if let Err(e) = crate::containers::docker_pull(&image) {
        event.status = ImageUpdateStatus::Failed;
        event.error = Some(format!("docker pull failed: {}", e));
        return event;
    }
    let new_image_id = Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", &image])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    event.new_digest = new_image_id.clone();

    // Step 5: no-op short circuit.
    if !new_image_id.is_empty() && new_image_id == old_image_id {
        event.status = ImageUpdateStatus::Completed;
        event.error = Some("already at latest digest — no recreate needed".into());
        return event;
    }

    // Step 6: recreate. `docker_recreate_from_inspect` performs the whole safe
    // swap ITSELF on the LIVE container: it stops it, renames it to a
    // `<name>_wolfstack_old` backup, creates the replacement (which now
    // resolves the freshly-pulled image via its tag), starts it, and deletes
    // the backup only on success — rolling the backup back on any failure.
    // We must therefore NOT stop/remove the container first. The old flow did
    // `docker stop` + `docker rm` here, which deleted the container before the
    // recreate could rename it — the internal rename then failed with "No such
    // container" (surfacing to the operator as "name not found"), and because
    // the container was already gone there was nothing to roll back to, so it
    // vanished from the list (RutgerDiehard 2026-07-17). Hand the fn the full
    // lifecycle; on failure it has already restored the original container.
    event.status = ImageUpdateStatus::Recreating;
    if let Err(e) = crate::containers::docker_recreate_from_inspect(container_name, &inspect) {
        event.status = ImageUpdateStatus::Failed;
        event.error = Some(format!("docker recreate failed: {}", e));
        return event;
    }

    // Step 7+8: health check + optional rollback.
    if policy.health_check {
        event.status = ImageUpdateStatus::HealthChecking;
        let healthy = wait_for_healthy(container_name, policy.health_check_timeout_secs);
        if !healthy {
            if policy.auto_rollback {
                warn!(
                    "auto-update {} unhealthy after restart — rolling back to image {}",
                    container_name, old_image_id,
                );
                // recreate_with_image → docker_recreate_from_inspect does its
                // own stop + rename + create + rollback on the LIVE (new)
                // container; pre-removing it here would leave nothing to
                // rename — the same bug fixed in the main recreate above.
                match recreate_with_image(&inspect, container_name, &old_image_id) {
                    Ok(_) => {
                        event.status = ImageUpdateStatus::RolledBack;
                        event.error = Some("health check failed — rolled back to previous image".into());
                    }
                    Err(e) => {
                        event.status = ImageUpdateStatus::Failed;
                        event.error = Some(format!(
                            "health check failed AND rollback recreate failed: {}", e,
                        ));
                    }
                }
                return event;
            }
            event.status = ImageUpdateStatus::Failed;
            event.error = Some(format!(
                "health check failed after {}s — auto_rollback disabled, container left in degraded state",
                policy.health_check_timeout_secs,
            ));
            return event;
        }
    }

    event.status = ImageUpdateStatus::Completed;
    event
}

/// Clone `inspect`, override `Config.Image` to a specific image-ID
/// (typically the sha256 of the previous image for rollback) and
/// recreate. Keeps the recreate site in `perform_update_blocking`
/// readable without duplicating the inspect-mutation logic.
fn recreate_with_image(
    inspect: &serde_json::Value,
    container_name: &str,
    image_id: &str,
) -> Result<String, String> {
    let mut rollback_inspect = inspect.clone();
    if let Some(cfg) = rollback_inspect.pointer_mut("/Config") {
        cfg["Image"] = serde_json::Value::String(image_id.to_string());
    }
    crate::containers::docker_recreate_from_inspect(container_name, &rollback_inspect)
}

/// Poll `docker inspect` until the container reports healthy or the
/// deadline lapses. Two modes, selected automatically:
///
/// 1. **Image declares HEALTHCHECK** — wait for `.State.Health.Status`
///    to be `healthy`. Returns false on `unhealthy`, keeps polling on
///    `starting`.
/// 2. **No HEALTHCHECK declared** — wait for `.State.Status == "running"`
///    to hold for ≥10 contiguous seconds. The 10s gate filters out
///    images that crash-loop right after start (very common with
///    misconfigured env vars).
///
/// Returns true on success, false on timeout / explicit unhealthy.
fn wait_for_healthy(container_name: &str, timeout_secs: u64) -> bool {
    let timeout = std::time::Duration::from_secs(timeout_secs.max(5));
    let deadline = std::time::Instant::now() + timeout;
    let mut running_since: Option<std::time::Instant> = None;
    loop {
        if std::time::Instant::now() > deadline { return false; }
        let out = Command::new("docker")
            .args([
                "inspect", "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                container_name,
            ])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let raw = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let (status, health) = raw.split_once('|').unwrap_or((raw.as_str(), "none"));
                match health {
                    "healthy" => return true,
                    "unhealthy" => return false,
                    _ => {
                        // No HEALTHCHECK OR still "starting" — fall back
                        // to "running for 10s contiguous" as a stability
                        // signal. Reset if status drops off "running".
                        if status == "running" {
                            let now = std::time::Instant::now();
                            let r = *running_since.get_or_insert(now);
                            if now.duration_since(r) >= std::time::Duration::from_secs(10) {
                                return true;
                            }
                        } else {
                            running_since = None;
                        }
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Check all running Docker containers for available image updates.
/// Containers with an `Ignore` policy are skipped.
/// Check EVERY eligible container now, ignoring per-container frequency.
/// Used by manual / WolfFlow-triggered checks where "check now" means all.
pub async fn check_all_containers(config: &ImageWatcherConfig) -> Vec<ImageCheckResult> {
    check_containers_impl(config, &std::collections::HashMap::new()).await.0
}

/// Check only the containers whose per-container interval has elapsed since
/// their last result in `prev`; carry forward the cached result for the
/// rest. Used by the background loop so each container is polled on its own
/// cadence (its `check_interval_secs` override, or the global default).
///
/// Returns `(all results, set of names actually re-checked this pass)`. The
/// caller MUST gate the auto-apply pass on that set — a carried-forward
/// (stale) `update_available=true` must never re-trigger an apply, or a
/// failed auto-update would retry on every loop wake.
pub async fn check_due_containers(
    config: &ImageWatcherConfig,
    prev: &std::collections::HashMap<String, ImageCheckResult>,
) -> (Vec<ImageCheckResult>, std::collections::HashSet<String>) {
    check_containers_impl(config, prev).await
}

async fn check_containers_impl(
    config: &ImageWatcherConfig,
    prev: &std::collections::HashMap<String, ImageCheckResult>,
) -> (Vec<ImageCheckResult>, std::collections::HashSet<String>) {
    // List all running container names (async exec — see get_local_digest)
    let output = match tokio::process::Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            error!(
                "docker ps failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return (Vec::new(), std::collections::HashSet::new());
        }
        Err(e) => {
            error!("Failed to run docker ps: {}", e);
            return (Vec::new(), std::collections::HashSet::new());
        }
    };

    let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let now = chrono::Utc::now();
    let mut results = Vec::new();
    // Names re-queried this pass (not carried forward, not passive). Only
    // these may drive the auto-apply pass.
    let mut checked_now: std::collections::HashSet<String> = std::collections::HashSet::new();

    for name in &names {
        // Skip passive policies (Ignore + Pinned). Passive == the
        // operator has already decided not to follow remote-latest,
        // so the registry HEAD is wasted work AND surfaces noise as
        // "update available" on the dashboard for containers the
        // operator deliberately froze. `policy_for` is the single
        // source of truth for the per-container effective policy.
        let policy = config.policy_for(name);
        if policy.is_passive() {
            continue;
        }

        // Per-container check frequency: if `prev` holds a result that's
        // still within this container's interval, carry it forward rather
        // than hitting the registry again. `prev` is empty for a
        // check-all, so that path always re-checks.
        if let Some(cached) = prev.get(name) {
            let interval = config.effective_interval_secs(name);
            let still_fresh = chrono::DateTime::parse_from_rfc3339(&cached.last_checked)
                .ok()
                .map(|t| (now - t.with_timezone(&chrono::Utc)).num_seconds())
                .map(|elapsed| elapsed >= 0 && (elapsed as u64) < interval)
                .unwrap_or(false);
            if still_fresh {
                results.push(cached.clone());
                continue;
            }
        }

        // Re-querying the registry now → this is a fresh result, eligible to
        // drive an auto-apply.
        checked_now.insert(name.clone());
        match check_container_update(name).await {
            Ok(result) => results.push(result),
            Err(e) => {
                warn!("Failed to check container '{}': {}", name, e);
                results.push(ImageCheckResult {
                    container_name: name.clone(),
                    image: String::new(),
                    local_digest: String::new(),
                    remote_digest: None,
                    update_available: false,
                    last_checked: chrono::Utc::now().to_rfc3339(),
                    error: Some(e),
                });
            }
        }
    }

    (results, checked_now)
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_container_check_interval_overrides_global() {
        let mut cfg = ImageWatcherConfig::default();
        cfg.check_interval_secs = 3600; // global 1h

        // No override → global.
        assert_eq!(cfg.effective_interval_secs("nginx"), 3600);

        // Override for one container.
        let mut fast = ContainerUpdatePolicy::default();
        fast.check_interval_secs = Some(900); // 15 min
        cfg.container_policies.insert("nginx".into(), fast);
        assert_eq!(cfg.effective_interval_secs("nginx"), 900);
        assert_eq!(cfg.effective_interval_secs("other"), 3600); // still global

        // The loop must wake as often as the fastest container.
        assert_eq!(cfg.min_effective_interval_secs(), 900);

        // A silly-small value is floored to 60s (registry protection).
        let mut tiny = ContainerUpdatePolicy::default();
        tiny.check_interval_secs = Some(5);
        cfg.container_policies.insert("db".into(), tiny);
        assert_eq!(cfg.effective_interval_secs("db"), 60);
        assert_eq!(cfg.min_effective_interval_secs(), 60);

        // Explicit 0 (or None) means "use global", not "check constantly".
        let mut zero = ContainerUpdatePolicy::default();
        zero.check_interval_secs = Some(0);
        cfg.container_policies.insert("z".into(), zero);
        assert_eq!(cfg.effective_interval_secs("z"), 3600);

        // The global interval keeps its historical 300s floor for
        // no-override containers (no regression for a small global setting).
        let mut cfg2 = ImageWatcherConfig::default();
        cfg2.check_interval_secs = 120;
        assert_eq!(cfg2.effective_interval_secs("any"), 300);
        assert_eq!(cfg2.min_effective_interval_secs(), 300);

        // A passive (Pinned) container's fast override must NOT drag the
        // whole loop's cadence down — it's never checked anyway.
        let mut pinned = ContainerUpdatePolicy::default();
        pinned.policy = UpdatePolicy::Pinned;
        pinned.pinned_to = Some("1.2.3".into());
        pinned.check_interval_secs = Some(60);
        cfg2.container_policies.insert("frozen".into(), pinned);
        assert_eq!(cfg2.min_effective_interval_secs(), 300);

        // The override round-trips through JSON (the wire the PUT uses).
        let json = serde_json::to_string(&cfg2.container_policies["frozen"]).unwrap();
        assert!(json.contains("\"check_interval_secs\":60"));
        let back: ContainerUpdatePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.check_interval_secs, Some(60));
    }

    #[test]
    fn parse_official_image() {
        let r = ImageRef::parse("nginx");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_official_image_with_tag() {
        let r = ImageRef::parse("redis:7-alpine");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/redis");
        assert_eq!(r.tag, "7-alpine");
    }

    #[test]
    fn parse_user_image() {
        let r = ImageRef::parse("user/repo:v2");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "user/repo");
        assert_eq!(r.tag, "v2");
    }

    #[test]
    fn parse_user_image_no_tag() {
        let r = ImageRef::parse("myuser/myapp");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "myuser/myapp");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_custom_registry() {
        let r = ImageRef::parse("ghcr.io/org/app:latest");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repo, "org/app");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_custom_registry_with_port() {
        let r = ImageRef::parse("localhost:5000/myimage:dev");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repo, "myimage");
        assert_eq!(r.tag, "dev");
    }

    #[test]
    fn parse_custom_registry_nested_repo() {
        let r = ImageRef::parse("registry.example.com/team/project/app:1.0");
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.repo, "team/project/app");
        assert_eq!(r.tag, "1.0");
    }

    #[test]
    fn parse_digest_pinned_hub_image() {
        // Compose-style pin: the digest is stripped; tag survives; docker.io
        // maps to the real API host with library/ prefixing (pm1 2026-07-03).
        let r = ImageRef::parse("docker.io/redis:6.2-alpine@sha256:905c4ee67b8e0aa955331960d2aa745781e6bd89afc44a8584bfd13bc890f0ae");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/redis");
        assert_eq!(r.tag, "6.2-alpine");
    }

    #[test]
    fn parse_digest_pinned_user_image() {
        let r = ImageRef::parse("docker.io/tensorchord/pgvecto-rs:pg14-v0.2.0@sha256:90724186f0a3517cf6914295b5ab410db9ce23190a2d9d0b9dd6463e3fa298f0");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "tensorchord/pgvecto-rs");
        assert_eq!(r.tag, "pg14-v0.2.0");
    }

    #[test]
    fn parse_digest_only_pin_defaults_tag() {
        // Pin with no tag at all: `nginx@sha256:…` → tag falls back to latest.
        let r = ImageRef::parse("nginx@sha256:aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899aa");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_docker_io_prefix_without_digest() {
        let r = ImageRef::parse("docker.io/redis:7");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/redis");
        assert_eq!(r.tag, "7");
    }

    #[test]
    fn parse_index_docker_io_alias() {
        let r = ImageRef::parse("index.docker.io/library/nginx:stable");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/nginx");
        assert_eq!(r.tag, "stable");
    }

    #[test]
    fn config_serialization_roundtrip() {
        let mut config = ImageWatcherConfig::default();
        config.enabled = true;
        config.check_interval_secs = 1800;
        config.default_policy = UpdatePolicy::AutoUpdate;
        config.container_policies.insert(
            "my-app".into(),
            ContainerUpdatePolicy {
                policy: UpdatePolicy::AutoUpdate,
                pinned_to: None,
                backup_before_update: true,
                health_check: true,
                health_check_timeout_secs: 120,
                auto_rollback: false,
                check_interval_secs: None,
            },
        );
        config.update_history.push(ImageUpdateEvent {
            id: "evt-1".into(),
            container_name: "my-app".into(),
            image: "myuser/myapp:latest".into(),
            old_digest: "sha256:aaa".into(),
            new_digest: "sha256:bbb".into(),
            backup_id: Some("bk-123".into()),
            status: ImageUpdateStatus::Completed,
            timestamp: "2026-04-09T12:00:00Z".into(),
            error: None,
        });

        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let deserialized: ImageWatcherConfig =
            serde_json::from_str(&json).expect("deserialize");

        assert!(deserialized.enabled);
        assert_eq!(deserialized.check_interval_secs, 1800);
        assert_eq!(deserialized.default_policy, UpdatePolicy::AutoUpdate);
        assert_eq!(deserialized.container_policies.len(), 1);
        assert_eq!(deserialized.update_history.len(), 1);
        assert_eq!(deserialized.update_history[0].status, ImageUpdateStatus::Completed);
    }

    #[test]
    fn config_defaults_from_empty_json() {
        let config: ImageWatcherConfig = serde_json::from_str("{}").expect("deserialize");
        assert!(!config.enabled);
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.default_policy, UpdatePolicy::NotifyOnly);
        assert!(config.container_policies.is_empty());
        assert!(config.update_history.is_empty());
    }

    #[test]
    fn update_policy_serde_snake_case() {
        let json = serde_json::to_string(&UpdatePolicy::NotifyOnly).unwrap();
        assert_eq!(json, "\"notify_only\"");

        let json = serde_json::to_string(&UpdatePolicy::AutoUpdate).unwrap();
        assert_eq!(json, "\"auto_update\"");

        let json = serde_json::to_string(&UpdatePolicy::Ignore).unwrap();
        assert_eq!(json, "\"ignore\"");

        let json = serde_json::to_string(&UpdatePolicy::Pinned).unwrap();
        assert_eq!(json, "\"pinned\"");

        // Round-trip
        let parsed: UpdatePolicy = serde_json::from_str("\"auto_update\"").unwrap();
        assert_eq!(parsed, UpdatePolicy::AutoUpdate);
        let parsed: UpdatePolicy = serde_json::from_str("\"pinned\"").unwrap();
        assert_eq!(parsed, UpdatePolicy::Pinned);
    }

    /// Locks the passive/auto-apply classification. If either of these
    /// helpers ever flips for a variant, the auto-apply loop will
    /// either skip a container it should touch or touch one it
    /// shouldn't — both are P0 regressions.
    #[test]
    fn policy_passive_and_auto_apply_helpers() {
        let notify = ContainerUpdatePolicy { policy: UpdatePolicy::NotifyOnly, ..Default::default() };
        let auto   = ContainerUpdatePolicy { policy: UpdatePolicy::AutoUpdate, ..Default::default() };
        let ignore = ContainerUpdatePolicy { policy: UpdatePolicy::Ignore, ..Default::default() };
        let pinned = ContainerUpdatePolicy { policy: UpdatePolicy::Pinned, pinned_to: Some("1.2.3".into()), ..Default::default() };

        // is_passive — Ignore + Pinned only.
        assert!(!notify.is_passive());
        assert!(!auto.is_passive());
        assert!(ignore.is_passive());
        assert!(pinned.is_passive());

        // is_auto_apply — AutoUpdate only.
        assert!(!notify.is_auto_apply());
        assert!(auto.is_auto_apply());
        assert!(!ignore.is_auto_apply());
        assert!(!pinned.is_auto_apply());
    }

    /// `pinned_to` is serialised only when Some — keeps existing
    /// configs un-touched when the operator hasn't pinned anything,
    /// AND keeps the on-disk file diff-friendly.
    #[test]
    fn pinned_to_is_skipped_when_none() {
        let p = ContainerUpdatePolicy { policy: UpdatePolicy::NotifyOnly, ..Default::default() };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("pinned_to"), "expected no pinned_to field when None, got: {}", json);
    }

    #[test]
    fn pinned_to_serialises_when_some() {
        let p = ContainerUpdatePolicy {
            policy: UpdatePolicy::Pinned,
            pinned_to: Some("v1.4.3".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"pinned_to\":\"v1.4.3\""), "got: {}", json);
    }

    /// `policy_for` is the single source of truth for the effective
    /// per-container policy. Test the fallback to default_policy and
    /// the explicit-entry-wins behaviour.
    #[test]
    fn policy_for_uses_explicit_entry_then_default() {
        let mut cfg = ImageWatcherConfig::default();
        cfg.default_policy = UpdatePolicy::AutoUpdate;
        cfg.container_policies.insert("ngx".into(), ContainerUpdatePolicy {
            policy: UpdatePolicy::Ignore,
            ..Default::default()
        });

        // Explicit entry wins.
        assert_eq!(cfg.policy_for("ngx").policy, UpdatePolicy::Ignore);
        // No entry → default.
        assert_eq!(cfg.policy_for("untouched").policy, UpdatePolicy::AutoUpdate);
    }

    /// No schedule_cron → window is always open. Default install
    /// state — operators who haven't picked a maintenance window
    /// shouldn't have the apply loop silently held back.
    #[test]
    fn auto_apply_window_open_with_no_schedule() {
        let cfg = ImageWatcherConfig::default();
        assert!(cfg.schedule_cron.is_none());
        let now = chrono::NaiveDateTime::parse_from_str("2026-05-19 14:23:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert!(cfg.auto_apply_window_open(now));
    }

    /// Schedule "0 4 * * 0" = Sundays 04:00 UTC, with a 60-minute
    /// window. Sunday 04:00 = open; Sunday 04:30 = still open; Sunday
    /// 05:30 = CLOSED; Wednesday any time = CLOSED.
    #[test]
    fn auto_apply_window_respects_cron_and_duration() {
        let cfg = ImageWatcherConfig {
            schedule_cron: Some("0 4 * * 0".into()),
            schedule_window_minutes: 60,
            ..Default::default()
        };
        // 2026-05-17 is a Sunday.
        let sun_04_00 = chrono::NaiveDateTime::parse_from_str("2026-05-17 04:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let sun_04_30 = chrono::NaiveDateTime::parse_from_str("2026-05-17 04:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let sun_05_30 = chrono::NaiveDateTime::parse_from_str("2026-05-17 05:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let wed_04_00 = chrono::NaiveDateTime::parse_from_str("2026-05-20 04:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        assert!(cfg.auto_apply_window_open(sun_04_00), "Sunday 04:00 should open");
        assert!(cfg.auto_apply_window_open(sun_04_30), "Sunday 04:30 within 60min window");
        assert!(!cfg.auto_apply_window_open(sun_05_30), "Sunday 05:30 past 60min window");
        assert!(!cfg.auto_apply_window_open(wed_04_00), "Wednesday is not a Sunday cron-match");
    }

    /// Empty / whitespace-only cron string falls back to "always open"
    /// rather than silently blocking every apply forever. Defensive
    /// against an operator typo or a half-saved settings form.
    #[test]
    fn auto_apply_window_open_with_blank_cron() {
        let cfg = ImageWatcherConfig {
            schedule_cron: Some("   ".into()),
            ..Default::default()
        };
        let now = chrono::NaiveDateTime::parse_from_str("2026-05-19 14:23:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert!(cfg.auto_apply_window_open(now));
    }

    #[test]
    fn image_update_status_serde_snake_case() {
        let json = serde_json::to_string(&ImageUpdateStatus::UpdateAvailable).unwrap();
        assert_eq!(json, "\"update_available\"");

        let json = serde_json::to_string(&ImageUpdateStatus::HealthChecking).unwrap();
        assert_eq!(json, "\"health_checking\"");

        let json = serde_json::to_string(&ImageUpdateStatus::RolledBack).unwrap();
        assert_eq!(json, "\"rolled_back\"");

        let parsed: ImageUpdateStatus = serde_json::from_str("\"rolled_back\"").unwrap();
        assert_eq!(parsed, ImageUpdateStatus::RolledBack);
    }

    #[test]
    fn merge_cluster_settings_applies_globals_but_keeps_local_state() {
        // A peer that already has its own per-container policies + audit
        // history. A propagated cluster-wide enable must flip the globals
        // without touching either — that's the whole point of the merge
        // (RutgerDiehard 2026-07-20: enabling the watcher on one node must
        // reach the others, but must not clobber their local state).
        let mut local = ImageWatcherConfig::default(); // enabled = false
        local.container_policies.insert(
            "my-nginx".to_string(),
            ContainerUpdatePolicy { policy: UpdatePolicy::Pinned, ..Default::default() },
        );
        local.update_history.push(ImageUpdateEvent {
            id: "evt-1".to_string(),
            container_name: "my-nginx".to_string(),
            image: "nginx:1".to_string(),
            old_digest: String::new(),
            new_digest: String::new(),
            backup_id: None,
            status: ImageUpdateStatus::Completed,
            timestamp: "2026-07-20T00:00:00Z".to_string(),
            error: None,
        });

        let mut incoming = ImageWatcherConfig::default();
        incoming.enabled = true;
        incoming.check_interval_secs = 7200;
        incoming.default_policy = UpdatePolicy::AutoUpdate;
        incoming.schedule_cron = Some("0 4 * * 0".to_string());
        incoming.schedule_window_minutes = 120;
        incoming.max_parallel_updates = 3;
        // The pushing node's own policies/history must NOT leak into the peer.
        incoming.container_policies.insert(
            "other-host-container".to_string(),
            ContainerUpdatePolicy::default(),
        );

        local.merge_cluster_settings_from(&incoming);

        // Cluster-wide fields adopted.
        assert!(local.enabled);
        assert_eq!(local.check_interval_secs, 7200);
        assert_eq!(local.default_policy, UpdatePolicy::AutoUpdate);
        assert_eq!(local.schedule_cron.as_deref(), Some("0 4 * * 0"));
        assert_eq!(local.schedule_window_minutes, 120);
        assert_eq!(local.max_parallel_updates, 3);
        // Host-specific state preserved: our policy stays, the pusher's
        // container is not adopted, and our audit trail is intact.
        assert!(local.container_policies.contains_key("my-nginx"));
        assert!(!local.container_policies.contains_key("other-host-container"));
        assert_eq!(local.update_history.len(), 1);
        assert_eq!(local.update_history[0].id, "evt-1");

        // cluster_settings_eq: after the merge the cluster-wide fields match
        // the source; a difference in host-local state (a container policy)
        // must NOT read as a cluster-wide change, so a per-container edit
        // won't trigger propagation.
        assert!(local.cluster_settings_eq(&incoming));
        let mut only_policy_differs = local.clone();
        only_policy_differs.container_policies.insert(
            "yet-another".to_string(), ContainerUpdatePolicy::default());
        assert!(local.cluster_settings_eq(&only_policy_differs));
        // A genuine cluster-wide difference (disabled default vs enabled) reads
        // as changed.
        assert!(!ImageWatcherConfig::default().cluster_settings_eq(&incoming));
    }
}
