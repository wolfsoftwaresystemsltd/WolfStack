// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! GitHub Backup — version-control WolfStack configuration in a GitHub repo.
//!
//! Pushes every JSON config file in /etc/wolfstack/ (excluding the
//! github-backup.json itself, to avoid leaking the token) plus every
//! docker-compose.yml under /etc/wolfstack/compose/ as a single
//! atomic commit on the configured branch. Uses the GitHub Git Data
//! API so each push produces exactly one commit even when many files
//! changed, which keeps the repo history readable as an audit log of
//! WolfStack state.
//!
//! Restore pulls the most recent tree from the configured branch and
//! writes each tracked file back to disk. Non-tracked local files are
//! left alone — restore is additive/overwriting, not destructive.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "/etc/wolfstack/github-backup.json";
const WOLFSTACK_ETC: &str = "/etc/wolfstack";
const COMPOSE_SUBDIR: &str = "compose";
const CONFIG_PREFIX: &str = "config/";
const COMPOSE_PREFIX: &str = "compose/";
const API_BASE: &str = "https://api.github.com";
const USER_AGENT: &str = "WolfStack/19 GitHub-Backup";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct GithubBackupConfig {
    #[serde(default)]
    pub enabled: bool,
    /// GitHub personal access token (classic with `repo` scope, or
    /// fine-grained with `Contents: read and write`). Stored plaintext
    /// in a 0600-mode file — consistent with how other WolfStack
    /// secrets (AI keys, PBS tokens, SMB passwords) are kept.
    #[serde(default)]
    pub token: String,
    /// Repo owner (user or org).
    #[serde(default)]
    pub owner: String,
    /// Repo name.
    #[serde(default)]
    pub repo: String,
    /// Branch to push to. Defaults to `main` and the branch must
    /// already exist on the remote — we don't auto-init empty repos.
    #[serde(default = "default_branch")]
    pub branch: String,
    /// Commit author name.
    #[serde(default = "default_author_name")]
    pub commit_name: String,
    /// Commit author email.
    #[serde(default = "default_author_email")]
    pub commit_email: String,
    /// Last successful push metadata — surfaced in the UI so admins
    /// can see when the backup last ran.
    #[serde(default)]
    pub last_push_at: Option<String>,
    #[serde(default)]
    pub last_push_sha: Option<String>,
    #[serde(default)]
    pub last_push_error: Option<String>,
}

fn default_branch() -> String { "main".to_string() }
fn default_author_name() -> String { "WolfStack Backup".to_string() }
fn default_author_email() -> String { "backup@wolfstack.local".to_string() }

impl GithubBackupConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_FILE) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| e.to_string())?;
        crate::paths::write_secure(CONFIG_FILE, json).map_err(|e| e.to_string())
    }

    /// UI-facing copy — token replaced by a recognisable sentinel so
    /// the real token never reaches the browser. PUT /config treats
    /// an empty or sentinel token as "leave current value unchanged"
    /// so editing other fields doesn't require re-entering the token.
    pub fn masked(&self) -> Self {
        let mut c = self.clone();
        if !c.token.is_empty() {
            let last4 = if c.token.len() > 4 { &c.token[c.token.len() - 4..] } else { "" };
            c.token = format!("••••••••{}", last4);
        }
        c
    }

    /// Brief human-readable description of the push target — used in
    /// error messages and UI.
    pub fn target_label(&self) -> String {
        format!("{}/{}@{}", self.owner, self.repo, self.branch)
    }
}

/// Is the config complete enough to attempt a push?
fn is_configured(cfg: &GithubBackupConfig) -> Result<(), String> {
    if cfg.token.trim().is_empty() { return Err("No GitHub token configured".to_string()); }
    if cfg.owner.trim().is_empty() { return Err("Repo owner is required".to_string()); }
    if cfg.repo.trim().is_empty() { return Err("Repo name is required".to_string()); }
    if cfg.branch.trim().is_empty() { return Err("Branch is required".to_string()); }
    Ok(())
}

// ─── File discovery ────────────────────────────────────────────────────

/// The set of files this backup tracks, as (repo_path, local_path)
/// tuples. Repo paths are prefixed with `config/` or `compose/` so
/// the layout in the remote repo is self-documenting.
fn discover_files() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();

    // Every .json file in /etc/wolfstack/ except github-backup.json
    // itself (never push the token to GitHub).
    if let Ok(read) = std::fs::read_dir(WOLFSTACK_ETC) {
        for entry in read.flatten() {
            let path = entry.path();
            if !path.is_file() { continue; }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if name == "github-backup.json" { continue; }
            if !name.ends_with(".json") { continue; }
            out.push((format!("{}{}", CONFIG_PREFIX, name), path));
        }
    }

    // Every docker-compose.yml under /etc/wolfstack/compose/{stack}/
    // (includes both user stacks and appstore-* stacks).
    let compose_root = Path::new(WOLFSTACK_ETC).join(COMPOSE_SUBDIR);
    if let Ok(read) = std::fs::read_dir(&compose_root) {
        for entry in read.flatten() {
            let stack_dir = entry.path();
            if !stack_dir.is_dir() { continue; }
            let stack_name = match stack_dir.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let compose_file = stack_dir.join("docker-compose.yml");
            if compose_file.is_file() {
                out.push((format!("{}{}/docker-compose.yml", COMPOSE_PREFIX, stack_name), compose_file));
            }
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ─── Push (Git Data API) ───────────────────────────────────────────────

/// Push every tracked file to the configured repo as one commit.
/// Returns the new commit sha on success.
pub async fn push_all() -> Result<String, String> {
    let mut cfg = GithubBackupConfig::load();
    is_configured(&cfg)?;
    let client = client()?;
    let target = cfg.target_label();

    // Resolve the current tip of the branch.
    let ref_url = format!("{}/repos/{}/{}/git/refs/heads/{}",
        API_BASE, cfg.owner, cfg.repo, cfg.branch);
    let parent_commit_sha = get_json(&client, &cfg.token, &ref_url).await
        .map_err(|e| format!("resolve branch {}: {}", target, e))?
        .pointer("/object/sha").and_then(|v| v.as_str()).map(str::to_string)
        .ok_or_else(|| format!("branch {} not found on remote (create an initial commit there first)", target))?;

    // Walk the files we want to push.
    let files = discover_files();
    if files.is_empty() {
        return Err("No files found to back up — /etc/wolfstack/ is empty".to_string());
    }

    // Create a blob for each file, base64-encoded.
    let mut tree_entries: Vec<serde_json::Value> = Vec::with_capacity(files.len());
    for (repo_path, local_path) in &files {
        let bytes = std::fs::read(local_path)
            .map_err(|e| format!("read {}: {}", local_path.display(), e))?;
        let content_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let blob_url = format!("{}/repos/{}/{}/git/blobs", API_BASE, cfg.owner, cfg.repo);
        let blob = post_json(&client, &cfg.token, &blob_url, &serde_json::json!({
            "content": content_b64,
            "encoding": "base64",
        })).await.map_err(|e| format!("blob {}: {}", repo_path, e))?;
        let sha = blob.get("sha").and_then(|v| v.as_str())
            .ok_or_else(|| format!("blob response missing sha for {}", repo_path))?
            .to_string();
        tree_entries.push(serde_json::json!({
            "path": repo_path,
            "mode": "100644",
            "type": "blob",
            "sha": sha,
        }));
    }

    // Create a tree. We DON'T base it on the previous tree — this
    // means deletions are reflected in history: if an appstore stack
    // is uninstalled, the next push no longer includes its YAML and
    // the new tree won't carry it over.
    let tree_url = format!("{}/repos/{}/{}/git/trees", API_BASE, cfg.owner, cfg.repo);
    let tree = post_json(&client, &cfg.token, &tree_url, &serde_json::json!({
        "tree": tree_entries,
    })).await.map_err(|e| format!("create tree: {}", e))?;
    let tree_sha = tree.get("sha").and_then(|v| v.as_str())
        .ok_or("create tree: missing sha")?.to_string();

    // Create the commit.
    let now = chrono::Utc::now().to_rfc3339();
    let commit_url = format!("{}/repos/{}/{}/git/commits", API_BASE, cfg.owner, cfg.repo);
    let commit_body = serde_json::json!({
        "message": format!("wolfstack-backup: {} files at {}", files.len(), now),
        "tree": tree_sha,
        "parents": [parent_commit_sha],
        "author": {
            "name": cfg.commit_name,
            "email": cfg.commit_email,
            "date": now,
        },
        "committer": {
            "name": cfg.commit_name,
            "email": cfg.commit_email,
            "date": now,
        },
    });
    let commit = post_json(&client, &cfg.token, &commit_url, &commit_body).await
        .map_err(|e| format!("create commit: {}", e))?;
    let new_sha = commit.get("sha").and_then(|v| v.as_str())
        .ok_or("create commit: missing sha")?.to_string();

    // Fast-forward the branch ref.
    patch_json(&client, &cfg.token, &ref_url, &serde_json::json!({
        "sha": new_sha,
        "force": false,
    })).await.map_err(|e| format!("update ref {}: {}", target, e))?;

    cfg.last_push_at = Some(now);
    cfg.last_push_sha = Some(new_sha.clone());
    cfg.last_push_error = None;
    cfg.save()?;
    Ok(new_sha)
}

// ─── Restore ───────────────────────────────────────────────────────────

/// Pull every tracked file from the latest tree on the configured
/// branch back into /etc/wolfstack/. Overwrites in place; local
/// files not present in the remote tree are left alone.
pub async fn restore_all() -> Result<usize, String> {
    let cfg = GithubBackupConfig::load();
    is_configured(&cfg)?;
    let client = client()?;
    let target = cfg.target_label();

    // Resolve branch tip → commit → tree.
    let ref_url = format!("{}/repos/{}/{}/git/refs/heads/{}",
        API_BASE, cfg.owner, cfg.repo, cfg.branch);
    let refv = get_json(&client, &cfg.token, &ref_url).await
        .map_err(|e| format!("resolve branch {}: {}", target, e))?;
    let commit_sha = refv.pointer("/object/sha").and_then(|v| v.as_str())
        .ok_or_else(|| format!("branch {} not found", target))?.to_string();
    let commit_url = format!("{}/repos/{}/{}/git/commits/{}", API_BASE, cfg.owner, cfg.repo, commit_sha);
    let commit = get_json(&client, &cfg.token, &commit_url).await
        .map_err(|e| format!("fetch commit: {}", e))?;
    let tree_sha = commit.pointer("/tree/sha").and_then(|v| v.as_str())
        .ok_or("commit response missing tree.sha")?.to_string();

    // Fetch the full tree recursively so we see every file in one call.
    let tree_url = format!("{}/repos/{}/{}/git/trees/{}?recursive=1",
        API_BASE, cfg.owner, cfg.repo, tree_sha);
    let tree = get_json(&client, &cfg.token, &tree_url).await
        .map_err(|e| format!("fetch tree: {}", e))?;
    let empty: Vec<serde_json::Value> = Vec::new();
    let entries = tree.get("tree").and_then(|v| v.as_array()).unwrap_or(&empty);

    let mut restored = 0usize;
    for entry in entries {
        let t = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if t != "blob" { continue; }
        let repo_path = match entry.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => continue,
        };
        let local = match repo_path_to_local(repo_path) {
            Some(p) => p,
            None => continue,
        };
        let blob_sha = match entry.get("sha").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let blob_url = format!("{}/repos/{}/{}/git/blobs/{}",
            API_BASE, cfg.owner, cfg.repo, blob_sha);
        let blob = get_json(&client, &cfg.token, &blob_url).await
            .map_err(|e| format!("fetch blob {}: {}", repo_path, e))?;
        let content_b64 = blob.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let cleaned: String = content_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes())
            .map_err(|e| format!("decode blob {}: {}", repo_path, e))?;

        if let Some(parent) = local.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Secrets (AI config etc.) are always in /etc/wolfstack/ — use
        // the same secure write helper the original code does.
        if local.starts_with(WOLFSTACK_ETC) {
            let path_str = local.to_string_lossy().to_string();
            crate::paths::write_secure(&path_str, &bytes).map_err(|e| e.to_string())?;
        } else {
            std::fs::write(&local, &bytes).map_err(|e| e.to_string())?;
        }
        restored += 1;
    }
    Ok(restored)
}

/// Map a repo-relative path back to a local filesystem path.
/// Silently ignores paths outside the known prefixes so someone
/// checking unrelated files into the repo doesn't cause WolfStack
/// to write them somewhere unexpected.
fn repo_path_to_local(repo_path: &str) -> Option<PathBuf> {
    if let Some(rest) = repo_path.strip_prefix(CONFIG_PREFIX) {
        // Flat filename inside /etc/wolfstack/.
        if rest.is_empty() || rest.contains('/') || rest == "github-backup.json" {
            return None;
        }
        return Some(Path::new(WOLFSTACK_ETC).join(rest));
    }
    if let Some(rest) = repo_path.strip_prefix(COMPOSE_PREFIX) {
        // Must be `{stack}/docker-compose.yml` — no deeper nesting.
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() != 2 || parts[1] != "docker-compose.yml" { return None; }
        if parts[0].is_empty() || parts[0].contains("..") { return None; }
        return Some(Path::new(WOLFSTACK_ETC).join(COMPOSE_SUBDIR).join(parts[0]).join(parts[1]));
    }
    None
}

// ─── Credential check ──────────────────────────────────────────────────

/// Hit GET /user and GET /repos/{owner}/{repo} to verify the token
/// works and the repo is reachable. Returns the authenticated user's
/// login on success so the UI can confirm which account it's using.
pub async fn test_credentials() -> Result<serde_json::Value, String> {
    let cfg = GithubBackupConfig::load();
    is_configured(&cfg)?;
    let client = client()?;

    let user = get_json(&client, &cfg.token, &format!("{}/user", API_BASE))
        .await.map_err(|e| format!("GET /user: {}", e))?;
    let login = user.get("login").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let repo_url = format!("{}/repos/{}/{}", API_BASE, cfg.owner, cfg.repo);
    let repo = get_json(&client, &cfg.token, &repo_url).await
        .map_err(|e| format!("GET /repos/{}/{}: {}", cfg.owner, cfg.repo, e))?;
    let default_branch = repo.get("default_branch").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Verify the configured branch actually exists.
    let ref_url = format!("{}/repos/{}/{}/git/refs/heads/{}", API_BASE, cfg.owner, cfg.repo, cfg.branch);
    let branch_exists = get_json(&client, &cfg.token, &ref_url).await.is_ok();

    Ok(serde_json::json!({
        "authenticated_as": login,
        "default_branch": default_branch,
        "configured_branch": cfg.branch,
        "configured_branch_exists": branch_exists,
        "target": cfg.target_label(),
    }))
}

// ─── HTTP helpers ──────────────────────────────────────────────────────

/// Shared HTTP client for all GitHub REST API calls. Previously
/// `client()` built a fresh Client per backup run; one pool per run
/// × many requests per run leaked connection pools through
/// process lifetime. User-Agent and timeout are baked in here.
static GITHUB_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

fn client() -> Result<reqwest::Client, String> {
    // Cheap Arc clone of the shared pool. Return Result to keep the
    // existing call-site shape (`client()?`) stable.
    Ok(reqwest::Client::clone(&GITHUB_CLIENT))
}

async fn get_json(client: &reqwest::Client, token: &str, url: &str) -> Result<serde_json::Value, String> {
    let resp = client.get(url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send().await.map_err(|e| e.to_string())?;
    handle(resp).await
}

async fn post_json(client: &reqwest::Client, token: &str, url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let resp = client.post(url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(body)
        .send().await.map_err(|e| e.to_string())?;
    handle(resp).await
}

async fn patch_json(client: &reqwest::Client, token: &str, url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let resp = client.patch(url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(body)
        .send().await.map_err(|e| e.to_string())?;
    handle(resp).await
}

async fn handle(resp: reqwest::Response) -> Result<serde_json::Value, String> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // Try to pull a "message" out of GitHub's JSON error body.
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
            .unwrap_or_else(|| text.clone());
        return Err(format!("HTTP {} — {}", status, msg));
    }
    if text.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(&text).map_err(|e| format!("parse response: {}", e))
}
