// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Reverse-proxy configuration.
//!
//! When WolfStack sits behind a reverse proxy (Cloudflare Tunnel, nginx,
//! Traefik, Caddy, …) public-facing URLs — status page links, shareable
//! cluster-browser URLs — need to use the admin-facing domain, not the
//! node's internal IP. Same-cluster status links default to the page's
//! current origin, which handles the common case automatically.
//!
//! This config lets an admin pin an explicit public base URL for cases
//! the auto-detection can't cover — typically subpath proxying (e.g.
//! `https://example.com/wolfstack/` → `:8553/`) or when the admin UI is
//! reached via a different host than the public status pages.

use serde::{Deserialize, Serialize};
use std::path::Path;

const CONFIG_PATH: &str = "/etc/wolfstack/reverse-proxy.json";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReverseProxyConfig {
    /// Absolute URL (no trailing slash) to prepend when building public
    /// links — e.g. `https://status.example.com` or
    /// `https://example.com/wolfstack`. Empty string = not configured,
    /// fall back to the browser's current origin.
    #[serde(default)]
    pub public_base_url: String,
}

impl ReverseProxyConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = Path::new(CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_PATH, json).map_err(|e| e.to_string())
    }

    /// Normalise trailing slashes off so callers can always `format!("{base}/status/{slug}")`.
    pub fn normalised(&self) -> Self {
        Self {
            public_base_url: self.public_base_url.trim().trim_end_matches('/').to_string(),
        }
    }
}
