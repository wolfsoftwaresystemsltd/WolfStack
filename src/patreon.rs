// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Patreon OAuth integration — links a WolfStack installation to a Patreon account
//! to determine the user's support tier and gate access to beta update channels.
//!
//! Architecture: The client secret NEVER touches WolfStack. All token operations
//! (exchange and refresh) are proxied through wolfscale.org which holds the secret.
//! WolfStack only stores the resulting access/refresh tokens locally.

use serde::{Deserialize, Serialize};
use std::sync::RwLock;

const CONFIG_PATH: &str = "/etc/wolfstack/patreon.json";

/// Public client ID — safe to embed (visible in OAuth URLs anyway).
const PATREON_CLIENT_ID: &str = "NawRwaiiX2WMqOuin7Tp0t8KTsarYTbi4g4e-C2Ab75QrdXjbN_6nx5JN73i6JVN";

const PATREON_AUTH_URL: &str = "https://www.patreon.com/oauth2/authorize";
const PATREON_IDENTITY_URL: &str = "https://www.patreon.com/api/oauth2/v2/identity";

/// The wolfscale.org proxy handles OAuth callbacks and token operations.
/// The client secret lives ONLY on wolfscale.org, never in the binary or config.
const OAUTH_PROXY_BASE: &str = "https://wolfscale.org/patreon-proxy.php";
const REDIRECT_URI: &str = "https://wolfscale.org/patreon-proxy.php";

/// Support tier levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatreonTier {
    None,
    Free,
    Basic,
    Advanced,
    Platinum,
    Enterprise,
}

impl Default for PatreonTier {
    fn default() -> Self {
        PatreonTier::None
    }
}

impl PatreonTier {
    /// Whether this tier grants access to the beta update channel.
    pub fn has_beta_access(&self) -> bool {
        matches!(self, PatreonTier::Advanced | PatreonTier::Platinum | PatreonTier::Enterprise)
    }

    /// Determine tier from pledge amount in cents.
    pub fn from_cents(cents: i64) -> Self {
        if cents >= 9500 {
            PatreonTier::Platinum
        } else if cents >= 2500 {
            PatreonTier::Advanced
        } else if cents >= 300 {
            PatreonTier::Basic
        } else if cents > 0 {
            PatreonTier::Free
        } else {
            PatreonTier::None
        }
    }
}

/// Persisted Patreon config — stored at /etc/wolfstack/patreon.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatreonConfig {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub patreon_user_id: Option<String>,
    #[serde(default)]
    pub patreon_user_name: Option<String>,
    #[serde(default)]
    pub patreon_email: Option<String>,
    #[serde(default)]
    pub tier: PatreonTier,
    #[serde(default)]
    pub pledge_amount_cents: i64,
    #[serde(default)]
    pub last_checked: Option<String>,
    #[serde(default)]
    pub linked: bool,
}

impl Default for PatreonConfig {
    fn default() -> Self {
        Self {
            access_token: None,
            refresh_token: None,
            patreon_user_id: None,
            patreon_user_name: None,
            patreon_email: None,
            tier: PatreonTier::None,
            pledge_amount_cents: 0,
            last_checked: None,
            linked: false,
        }
    }
}

impl PatreonConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = std::path::Path::new(CONFIG_PATH).parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_PATH, json).map_err(|e| e.to_string())
    }
}

/// Runtime state held in AppState.
pub struct PatreonState {
    pub config: RwLock<PatreonConfig>,
}

impl PatreonState {
    pub fn new() -> Self {
        let config = PatreonConfig::load();
        Self {
            config: RwLock::new(config),
        }
    }

    /// Build the OAuth authorization URL. The state parameter encodes the
    /// WolfStack server's callback URL so the proxy knows where to redirect.
    pub fn authorize_url(&self, wolfstack_callback_url: &str) -> String {
        let state = base64_encode(wolfstack_callback_url);
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=identity%20identity%5Bemail%5D%20identity.memberships&state={}",
            PATREON_AUTH_URL, PATREON_CLIENT_ID, urlencoding::encode(REDIRECT_URI), urlencoding::encode(&state)
        )
    }

    /// Refresh the access token via the wolfscale.org proxy (which holds the client secret).
    pub async fn refresh_access_token(refresh_token: &str) -> Result<(String, String), String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;

        let url = format!("{}?action=refresh", OAUTH_PROXY_BASE);

        let resp = client
            .post(&url)
            .form(&[("refresh_token", refresh_token)])
            .send()
            .await
            .map_err(|e| format!("Token refresh failed: {}", e))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

        if let Some(error) = body["error"].as_str() {
            return Err(format!("Refresh error: {}", error));
        }

        let access_token = body["access_token"]
            .as_str()
            .ok_or("No access_token in refresh response")?
            .to_string();
        let new_refresh = body["refresh_token"]
            .as_str()
            .unwrap_or(refresh_token)
            .to_string();

        Ok((access_token, new_refresh))
    }

    /// Fetch the user's identity and membership info from Patreon API v2 directly.
    pub async fn fetch_identity(access_token: &str) -> Result<PatreonIdentity, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;

        let url = format!(
            "{}?include=memberships.currently_entitled_tiers&fields%5Buser%5D=full_name,email&fields%5Bmember%5D=currently_entitled_amount_cents,patron_status&fields%5Btier%5D=title,amount_cents",
            PATREON_IDENTITY_URL
        );

        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| format!("Identity fetch failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Patreon API error {}: {}", status, text));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse identity: {}", e))?;

        let user_data = &body["data"];
        let user_id = user_data["id"].as_str().unwrap_or("").to_string();
        let attrs = &user_data["attributes"];
        let full_name = attrs["full_name"].as_str().unwrap_or("").to_string();
        let email = attrs["email"].as_str().unwrap_or("").to_string();

        // Find the highest active pledge across memberships
        let mut pledge_cents: i64 = 0;
        if let Some(included) = body["included"].as_array() {
            for item in included {
                if item["type"].as_str() == Some("member") {
                    let member_attrs = &item["attributes"];
                    let status = member_attrs["patron_status"].as_str().unwrap_or("");
                    let cents = member_attrs["currently_entitled_amount_cents"].as_i64().unwrap_or(0);
                    if status == "active_patron" && cents > pledge_cents {
                        pledge_cents = cents;
                    }
                }
            }
        }

        Ok(PatreonIdentity {
            user_id,
            full_name,
            email,
            pledge_amount_cents: pledge_cents,
            tier: PatreonTier::from_cents(pledge_cents),
        })
    }

    /// Full sync: fetch identity, update config, persist.
    pub async fn sync_membership(&self) -> Result<PatreonTier, String> {
        let (access_token, refresh_token) = {
            let config = self.config.read().map_err(|e| e.to_string())?;
            match (&config.access_token, &config.refresh_token) {
                (Some(at), Some(rt)) => (at.clone(), rt.clone()),
                _ => return Err("Not linked to Patreon".to_string()),
            }
        };

        // Try fetching with current token, refresh if expired
        let identity = match Self::fetch_identity(&access_token).await {
            Ok(id) => id,
            Err(e) if e.contains("401") || e.contains("403") => {
                // Token expired, try refresh via wolfscale.org proxy
                tracing::info!("Patreon token expired, refreshing via proxy...");
                let (new_access, new_refresh) = Self::refresh_access_token(&refresh_token).await?;

                // Save new tokens immediately
                {
                    let mut config = self.config.write().map_err(|e| e.to_string())?;
                    config.access_token = Some(new_access.clone());
                    config.refresh_token = Some(new_refresh);
                    let _ = config.save();
                }

                Self::fetch_identity(&new_access).await?
            }
            Err(e) => return Err(e),
        };

        let tier = identity.tier.clone();

        // Update config
        {
            let mut config = self.config.write().map_err(|e| e.to_string())?;
            config.patreon_user_id = Some(identity.user_id);
            config.patreon_user_name = Some(identity.full_name);
            config.patreon_email = Some(identity.email);
            config.tier = identity.tier;
            config.pledge_amount_cents = identity.pledge_amount_cents;
            config.last_checked = Some(chrono::Utc::now().to_rfc3339());
            let _ = config.save();
        }

        Ok(tier)
    }
}

/// Parsed identity from Patreon API.
pub struct PatreonIdentity {
    pub user_id: String,
    pub full_name: String,
    pub email: String,
    pub pledge_amount_cents: i64,
    pub tier: PatreonTier,
}

/// Simple base64 encode for the state parameter.
fn base64_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_from_cents() {
        assert_eq!(PatreonTier::from_cents(0), PatreonTier::None);
        assert_eq!(PatreonTier::from_cents(100), PatreonTier::Free);
        assert_eq!(PatreonTier::from_cents(300), PatreonTier::Basic);
        assert_eq!(PatreonTier::from_cents(2500), PatreonTier::Advanced);
        assert_eq!(PatreonTier::from_cents(9500), PatreonTier::Platinum);
        assert_eq!(PatreonTier::from_cents(20000), PatreonTier::Platinum);
    }

    #[test]
    fn test_beta_access() {
        assert!(!PatreonTier::None.has_beta_access());
        assert!(!PatreonTier::Free.has_beta_access());
        assert!(!PatreonTier::Basic.has_beta_access());
        assert!(PatreonTier::Advanced.has_beta_access());
        assert!(PatreonTier::Platinum.has_beta_access());
        assert!(PatreonTier::Enterprise.has_beta_access());
    }
}
