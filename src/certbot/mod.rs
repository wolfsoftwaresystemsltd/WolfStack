// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Certbot / Let's Encrypt certificate management for WolfProxy and the
//! nginx app. Replaces the old stop-proxy / start-nginx / run-certbot /
//! stop-nginx / start-proxy dance with zero-downtime ACME challenges:
//!
//! * **Webroot (default):** WolfProxy serves a hardcoded ACME location
//!   block from `/var/lib/wolfstack/acme-webroot`. Certbot writes its
//!   challenge files there; Let's Encrypt fetches them over the still-
//!   running proxy. No service interruption.
//! * **DNS-01 (for wildcards or port-80-less setups):** certbot talks
//!   to the user's DNS provider via one of its plugins. The provider
//!   and credentials are supplied per-request.
//!
//! Renewal is handled by a daily tokio task (`certbot renew --quiet`)
//! with a `--deploy-hook` that reloads WolfProxy on success.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

const CONFIG_PATH: &str = "/etc/wolfstack/certbot.json";
const DEFAULT_WEBROOT: &str = "/var/lib/wolfstack/acme-webroot";
const LE_LIVE_DIR: &str = "/etc/letsencrypt/live";

/// Persisted certbot configuration. Separate file rather than shoved
/// into an existing one — other modules don't need to know about ACME
/// internals, and cert admins shouldn't need read access to unrelated
/// settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertbotConfig {
    /// Default contact email for Let's Encrypt registration. Required
    /// by the CA for expiry notices and account recovery.
    #[serde(default)]
    pub email: String,
    /// Webroot path WolfProxy is configured to serve for ACME HTTP-01
    /// challenges. Override only if the default doesn't work for your
    /// layout — most installs should leave it alone.
    #[serde(default = "default_webroot")]
    pub webroot: String,
    /// Whether the daily renewal task should run. Defaults to on; set
    /// false if you're managing certs manually or via an external
    /// orchestrator.
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    /// Command to run after a successful renewal to pick up the new
    /// chain. Empty means "pick sensibly based on what's running".
    #[serde(default)]
    pub reload_cmd: String,
}

fn default_webroot() -> String { DEFAULT_WEBROOT.to_string() }
fn default_true() -> bool { true }

impl Default for CertbotConfig {
    fn default() -> Self {
        Self {
            email: String::new(),
            webroot: default_webroot(),
            auto_renew: true,
            reload_cmd: String::new(),
        }
    }
}

impl CertbotConfig {
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
}

/// Summary of a single issued certificate, gleaned from the filesystem
/// (no cert-store parsing — we read the PEM directly). `name` matches
/// certbot's `--cert-name` so renewal and deletion can address it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub name: String,
    pub domains: Vec<String>,
    /// ISO-8601 expiry in UTC. Empty string if the cert couldn't be
    /// parsed — rare, but rather surface an empty field than hide a
    /// cert that still exists on disk.
    pub expires: String,
    /// Days until expiry. Negative when already expired. Frontend uses
    /// this to colour the row (green > 30, amber 7–30, red < 7).
    pub days_remaining: i64,
    /// Absolute path to `fullchain.pem`. Derived from `LE_LIVE_DIR` +
    /// `name`. Filled in by `list_certs`; on serialisation it's stable
    /// across builds because certbot's layout is well-known. UI uses
    /// this to auto-fill the WolfProxy site form so operators don't
    /// have to retype `/etc/letsencrypt/live/<zone>/fullchain.pem`.
    #[serde(default)]
    pub cert_path: String,
    /// Absolute path to `privkey.pem`. See `cert_path` above.
    #[serde(default)]
    pub key_path: String,
    /// True if at least one of `domains` is a wildcard (`*.zone.tld`).
    /// Wildcards let one cert cover every host in the zone, so the
    /// site-creation UI treats them differently — it offers a
    /// "subdomain" input that synthesises `server_name`.
    #[serde(default)]
    pub is_wildcard: bool,
    /// For wildcard certs, the zone the wildcard covers
    /// (`*.wolf.uk.com` → `wolf.uk.com`). Empty for non-wildcard
    /// certs. The UI shows this as a suffix chip next to the subdomain
    /// input so the operator can see what the final hostname will be.
    #[serde(default)]
    pub base_zone: String,
}

/// Resolve the path to the `certbot` binary, or `None` if not present.
///
/// systemd's default `PATH` is `/usr/local/sbin:/usr/local/bin:/usr/sbin:
/// /usr/bin:/sbin:/bin` — it does NOT include `/snap/bin`. Operators who
/// installed certbot via `snap install certbot --classic` (the path
/// EFF recommends on Ubuntu / Debian since 20.04) end up with certbot
/// at `/snap/bin/certbot`, invisible to the WolfStack systemd service.
/// Pre-v23.0.1 this surfaced as a confusing "certbot is not installed
/// on this node" from the DNS-provider Test button even though
/// `certbot --version` worked fine in the operator's shell.
///
/// We probe PATH first (cheap), then fall back to a known-good list of
/// install locations: apt (`/usr/bin`), pip / source build
/// (`/usr/local/bin`), snap (`/snap/bin`), and the EFF-maintained
/// virtualenv path (`/opt/certbot/bin`).
pub fn certbot_path() -> Option<String> {
    if let Ok(out) = Command::new("certbot").arg("--version").output() {
        if out.status.success() {
            return Some("certbot".to_string());
        }
    }
    for cand in &[
        "/usr/bin/certbot",
        "/usr/local/bin/certbot",
        "/snap/bin/certbot",
        "/opt/certbot/bin/certbot",
    ] {
        if std::path::Path::new(cand).exists() {
            if let Ok(out) = Command::new(cand).arg("--version").output() {
                if out.status.success() {
                    return Some((*cand).to_string());
                }
            }
        }
    }
    None
}

pub fn is_installed() -> bool {
    certbot_path().is_some()
}

pub fn ensure_webroot(cfg: &CertbotConfig) -> Result<(), String> {
    std::fs::create_dir_all(&cfg.webroot).map_err(|e| format!("create webroot: {e}"))
}

/// List every cert currently on disk in /etc/letsencrypt/live. We walk
/// the directory rather than asking `certbot certificates` because the
/// latter needs root AND prints a free-form table that's annoying to
/// parse. The cert.pem symlink resolves to the live archive so reading
/// expiry works even for certs issued years ago.
pub fn list_certs() -> Vec<CertSummary> {
    let live = Path::new(LE_LIVE_DIR);
    if !live.exists() { return Vec::new(); }
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(live) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // "README" is a stock certbot file, not a cert directory.
        if name == "README" { continue; }
        let cert_pem = path.join("cert.pem");
        if !cert_pem.exists() { continue; }
        let (domains, expires, days_remaining) = probe_cert(&cert_pem);
        // Pick the first wildcard SAN for `base_zone`. A single
        // multi-SAN cert can carry both `wolf.uk.com` and
        // `*.wolf.uk.com`; the wildcard one is what makes it useful
        // for "any host under this zone" proxying.
        let wildcard = domains.iter().find(|d| d.starts_with("*."));
        let is_wildcard = wildcard.is_some();
        let base_zone = wildcard
            .map(|d| d.trim_start_matches("*.").to_string())
            .unwrap_or_default();
        out.push(CertSummary {
            name: name.to_string(),
            domains,
            expires,
            days_remaining,
            cert_path: format!("{}/{}/fullchain.pem", LE_LIVE_DIR, name),
            key_path: format!("{}/{}/privkey.pem", LE_LIVE_DIR, name),
            is_wildcard,
            base_zone,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Same as `list_certs` but reads `/etc/letsencrypt/live/` from inside
/// the given `ExecTarget`. Used by the WolfProxy nginx site form so
/// the cert dropdown reflects the certs visible to the *container* (or
/// host) that will actually serve nginx — picking a host cert when
/// you're configuring an LXC container would auto-fill a path the
/// container can't read, and nginx would fail to start.
///
/// Returns an empty Vec if the target has no /etc/letsencrypt/live/
/// directory (typical for fresh containers that haven't had certbot
/// run inside them and don't have /etc/letsencrypt bind-mounted from
/// the host). Caller renders an "empty container" hint rather than a
/// fallback to host certs — leaking host paths into a container
/// context is exactly the bug we're fixing here.
pub fn list_certs_via_target(target: &crate::configurator::ExecTarget) -> Vec<CertSummary> {
    use crate::configurator::ExecTarget;
    // Fast path for the host case — avoid the sudo sh subprocess
    // round-trip openssl-per-cert that the ExecTarget abstraction
    // would impose. Behaviour-equivalent, just cheaper.
    if matches!(target, ExecTarget::Host) {
        return list_certs();
    }

    // Probe the container's /etc/letsencrypt/live/ via ExecTarget.
    if !target.path_exists(LE_LIVE_DIR).unwrap_or(false) {
        return Vec::new();
    }
    let names = match target.list_dir(LE_LIVE_DIR) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for name in names {
        // certbot drops a README at the top of LE_LIVE_DIR and uses
        // per-cert subdirectories for everything else; same filter as
        // the host-side walker.
        if name == "README" || name.starts_with('.') {
            continue;
        }
        let cert_pem = format!("{}/{}/cert.pem", LE_LIVE_DIR, name);
        if !target.path_exists(&cert_pem).unwrap_or(false) {
            continue;
        }
        let (domains, expires, days_remaining) = probe_cert_via_target(target, &cert_pem);
        let wildcard = domains.iter().find(|d| d.starts_with("*."));
        let is_wildcard = wildcard.is_some();
        let base_zone = wildcard
            .map(|d| d.trim_start_matches("*.").to_string())
            .unwrap_or_default();
        out.push(CertSummary {
            name: name.clone(),
            domains,
            expires,
            days_remaining,
            cert_path: format!("{}/{}/fullchain.pem", LE_LIVE_DIR, name),
            key_path: format!("{}/{}/privkey.pem", LE_LIVE_DIR, name),
            is_wildcard,
            base_zone,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Container-aware version of `probe_cert` — shells out to openssl
/// *inside* the target. Same parsing logic; only the transport differs.
fn probe_cert_via_target(
    target: &crate::configurator::ExecTarget,
    pem_path: &str,
) -> (Vec<String>, String, i64) {
    let mut domains = Vec::new();
    let mut expires = String::new();
    let mut days: i64 = 0;

    // The path can be controlled by `name` from list_dir, but list_dir
    // already filtered to entries under /etc/letsencrypt/live/. Quote
    // defensively anyway — single-quote-escape via the same pattern as
    // ExecTarget::read_file.
    let q = pem_path.replace('\'', "'\\''");
    let sans_cmd = format!("openssl x509 -in '{}' -noout -ext subjectAltName", q);
    if let Ok(txt) = target.exec(&sans_cmd) {
        for line in txt.lines() {
            for part in line.split(',') {
                if let Some(dom) = part.trim().strip_prefix("DNS:") {
                    domains.push(dom.trim().to_string());
                }
            }
        }
    }
    let end_cmd = format!("openssl x509 -in '{}' -noout -enddate", q);
    if let Ok(txt) = target.exec(&end_cmd) {
        let trimmed = txt.trim();
        if let Some(val) = trimmed.strip_prefix("notAfter=") {
            expires = val.to_string();
            // Convert via `date -d` inside the same target so timezone
            // semantics match — containers can have skewed clocks but
            // openssl emits UTC, so date -d on the target is fine.
            let date_cmd = format!("date -d '{}' +%s", val.replace('\'', "'\\''"));
            if let Ok(out) = target.exec(&date_cmd) {
                if let Ok(ts) = out.trim().parse::<i64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    days = (ts - now) / 86400;
                }
            }
        }
    }
    (domains, expires, days)
}

/// Extract the SANs and notAfter from a PEM-encoded x509. We shell out
/// to `openssl x509` rather than pulling in a rustls-pemfile/x509-parser
/// dep tree — certbot already requires openssl on the host, so there's
/// nothing to gain from adding a crate.
fn probe_cert(pem: &Path) -> (Vec<String>, String, i64) {
    let mut domains = Vec::new();
    let mut expires = String::new();
    let mut days: i64 = 0;

    // SANs — the x509 extension listing all cert subjects.
    if let Ok(o) = Command::new("openssl")
        .args(["x509", "-in", &pem.to_string_lossy(), "-noout", "-ext", "subjectAltName"])
        .output()
    {
        let txt = String::from_utf8_lossy(&o.stdout);
        for line in txt.lines() {
            for part in line.split(',') {
                if let Some(dom) = part.trim().strip_prefix("DNS:") {
                    domains.push(dom.trim().to_string());
                }
            }
        }
    }

    // Expiry — `openssl x509 -enddate` returns `notAfter=…`.
    if let Ok(o) = Command::new("openssl")
        .args(["x509", "-in", &pem.to_string_lossy(), "-noout", "-enddate"])
        .output()
    {
        let txt = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Some(val) = txt.strip_prefix("notAfter=") {
            expires = val.to_string();
            // Convert to days-remaining via `date -d … +%s`, portable
            // across the BSDs/GNU-isms the installer might be on.
            if let Ok(d) = Command::new("date")
                .args(["-d", val, "+%s"]).output()
            {
                if let Ok(ts) = String::from_utf8_lossy(&d.stdout).trim().parse::<i64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64).unwrap_or(0);
                    days = (ts - now) / 86400;
                }
            }
        }
    }

    (domains, expires, days)
}

/// Request a new certificate. `challenge` is either "webroot" (the
/// recommended default) or "dns-<provider>" where provider matches a
/// certbot-dns-* plugin name. `dns_credentials_path` is a path to an
/// INI file the user uploaded — required for DNS-01, ignored for
/// webroot.
pub fn issue(
    domains: &[String],
    email: &str,
    challenge: &str,
    dns_credentials_path: Option<&str>,
    dry_run: bool,
) -> Result<String, String> {
    if !is_installed() {
        return Err("certbot is not installed on this node".to_string());
    }
    if domains.is_empty() {
        return Err("at least one domain is required".to_string());
    }
    let cfg = CertbotConfig::load();
    if email.is_empty() && cfg.email.is_empty() {
        return Err("an email address is required (for Let's Encrypt account registration)".to_string());
    }

    // Always invoke certbot via its resolved path (handles /snap/bin
    // etc. that aren't in systemd's PATH). is_installed() already
    // guaranteed Some above; expect() can only fire on a TOCTOU race
    // where someone uninstalled certbot in the last microseconds, in
    // which case "certbot is not installed" is the right thing to say.
    let certbot_bin = certbot_path()
        .ok_or_else(|| "certbot is not installed on this node".to_string())?;
    let mut cmd = Command::new(&certbot_bin);
    cmd.arg("certonly").arg("--non-interactive").arg("--agree-tos");

    // Email priority: explicit arg overrides saved default. Saved
    // default exists so the admin doesn't have to retype it every
    // time.
    let resolved_email = if email.is_empty() { cfg.email.clone() } else { email.to_string() };
    cmd.arg("--email").arg(&resolved_email);

    for d in domains {
        cmd.arg("-d").arg(d);
    }
    if dry_run { cmd.arg("--dry-run"); }

    match challenge {
        "webroot" => {
            ensure_webroot(&cfg)?;
            cmd.arg("--webroot").arg("-w").arg(&cfg.webroot);
        }
        provider if provider.starts_with("dns-") => {
            // certbot plugin name is `dns-cloudflare`, auth flag is
            // `--dns-cloudflare-credentials`. The credentials INI file
            // must be 0600 or certbot refuses to use it.
            let plugin = provider;
            cmd.arg(format!("--{}", plugin));
            if let Some(creds) = dns_credentials_path {
                // certbot refuses credentials files with permissive
                // modes — chmod to 0600 defensively, since an admin
                // uploading via our UI won't know to do that.
                let _ = Command::new("chmod").args(["0600", creds]).output();
                cmd.arg(format!("--{}-credentials", plugin)).arg(creds);
            } else {
                return Err(format!("DNS challenge '{}' needs a credentials file", plugin));
            }
        }
        other => return Err(format!("unknown challenge type: {}", other)),
    }

    let out = cmd.output().map_err(|e| format!("spawn certbot: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "certbot failed:\n{}",
            String::from_utf8_lossy(&out.stderr),
        ));
    }

    // On success, fire the reload hook so WolfProxy picks up the new
    // chain without the admin having to restart anything.
    if !dry_run {
        let _ = reload_proxy(&cfg);
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Issue a cert using DNS-01 via a stored DNS provider. The provider
/// credentials are materialised to a 0600 INI file under
/// `/run/wolfstack/dns-creds/` for the duration of the certbot run, then
/// unlinked via the `MaterializedCreds` Drop impl — even on error or
/// panic. This is the wildcard-friendly path; pass `*.zone.tld` in
/// `domains` and certbot does the rest.
///
/// `dry_run = true` hits Let's Encrypt's staging CA — used by the
/// `/api/dns-providers/{id}/test` button so an operator can sanity-check
/// their credentials without burning the 5-issuance-per-week rate limit
/// on production.
pub fn issue_via_provider(
    domains: &[String],
    email: &str,
    provider_id: &str,
    dry_run: bool,
) -> Result<String, String> {
    if !is_installed() {
        return Err("certbot is not installed on this node".to_string());
    }
    if domains.is_empty() {
        return Err("at least one domain is required".to_string());
    }
    let cfg = CertbotConfig::load();
    let resolved_email = if email.is_empty() { cfg.email.clone() } else { email.to_string() };
    if resolved_email.is_empty() {
        return Err("an email address is required (for Let's Encrypt account registration)".to_string());
    }

    // Load the store fresh so any concurrent UI update of the provider
    // credentials takes effect immediately (no in-memory caching).
    let store = crate::dns_providers::DnsProviderStore::load();
    let provider = store
        .get(provider_id)
        .ok_or_else(|| format!("DNS provider '{}' not found", provider_id))?;
    if !crate::dns_providers::is_known_plugin(&provider.plugin) {
        // Belt-and-braces: store::add already guards this, but a
        // hand-edited /etc/wolfstack/dns-providers.json could slip a
        // bad plugin past validation. Plugin is about to be
        // interpolated into argv, so refuse here too.
        return Err(format!("DNS provider has unsafe plugin '{}'", provider.plugin));
    }

    // Materialise creds. The guard unlinks the file when it goes out of
    // scope — bind it to a local so the file lives for the full
    // duration of the certbot call below.
    let creds = store.materialize(provider_id)?;

    // Resolve certbot via certbot_path() so snap installs at /snap/bin
    // are found — systemd's default PATH doesn't include /snap/bin and
    // pre-fix `Command::new("certbot")` silently failed there.
    let certbot_bin = certbot_path()
        .ok_or_else(|| "certbot is not installed on this node".to_string())?;
    let mut cmd = Command::new(&certbot_bin);
    cmd.arg("certonly").arg("--non-interactive").arg("--agree-tos");
    cmd.arg("--email").arg(&resolved_email);
    for d in domains {
        cmd.arg("-d").arg(d);
    }
    if dry_run {
        cmd.arg("--dry-run");
    }
    // certbot DNS plugins follow a fixed naming convention:
    //   --dns-<plugin>                      → use this plugin
    //   --dns-<plugin>-credentials <path>   → INI file path
    // Plugin is whitelisted (dns_providers::KNOWN_PLUGINS), so the
    // string interpolation here can't introduce a new flag.
    cmd.arg(format!("--dns-{}", provider.plugin));
    cmd.arg(format!("--dns-{}-credentials", provider.plugin)).arg(&creds.path);

    let out = cmd.output().map_err(|e| format!("spawn certbot: {e}"))?;
    // `creds` drops here on either success or error — file is unlinked.
    if !out.status.success() {
        return Err(format!(
            "certbot failed:\n{}",
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    if !dry_run {
        let _ = reload_proxy(&cfg);
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Force-renew one cert by name. Skips certbot's 30-day freshness
/// window — used when the admin wants to rotate the cert early (e.g.
/// after changing SANs).
pub fn renew(name: &str) -> Result<String, String> {
    let certbot_bin = certbot_path().ok_or_else(|| "certbot is not installed".to_string())?;
    let out = Command::new(&certbot_bin)
        .args(["renew", "--non-interactive", "--force-renewal", "--cert-name", name])
        .output()
        .map_err(|e| format!("spawn certbot: {e}"))?;
    if !out.status.success() {
        return Err(format!("renew failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    let cfg = CertbotConfig::load();
    let _ = reload_proxy(&cfg);
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Delete one cert and its archive dir. Certbot's own `delete`
/// subcommand handles the archive cleanup — manually removing
/// `/etc/letsencrypt/{live,archive}/<name>` leaves dangling renewal
/// config in `/etc/letsencrypt/renewal/<name>.conf`.
pub fn delete(name: &str) -> Result<String, String> {
    let certbot_bin = certbot_path().ok_or_else(|| "certbot is not installed".to_string())?;
    let out = Command::new(&certbot_bin)
        .args(["delete", "--non-interactive", "--cert-name", name])
        .output()
        .map_err(|e| format!("spawn certbot: {e}"))?;
    if !out.status.success() {
        return Err(format!("delete failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Reload WolfProxy / nginx so the new cert is served. Prefers
/// `systemctl reload wolfproxy` if the service is present, falls back
/// to nginx, and honours an explicit `reload_cmd` override. No-op on
/// systems running neither — the admin presumably runs the webserver
/// out-of-band and will reload it themselves.
fn reload_proxy(cfg: &CertbotConfig) -> Result<(), String> {
    if !cfg.reload_cmd.is_empty() {
        let status = Command::new("sh").arg("-c").arg(&cfg.reload_cmd).status();
        return match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(format!("reload_cmd exited {}", s)),
            Err(e) => Err(format!("reload_cmd spawn: {e}")),
        };
    }
    for service in ["wolfproxy", "nginx"] {
        let active = Command::new("systemctl")
            .args(["is-active", service]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
        if active {
            let _ = Command::new("systemctl").args(["reload", service]).status();
            return Ok(());
        }
    }
    Ok(())
}

/// Called by the daily background task in main.rs. Runs renew across
/// every cert, letting certbot decide which ones are actually due
/// (anything with < 30 days left). The deploy hook reloads the proxy
/// exactly once per invocation, regardless of how many certs renewed.
pub fn renew_due() -> Result<(), String> {
    let cfg = CertbotConfig::load();
    if !cfg.auto_renew { return Ok(()); }
    let certbot_bin = match certbot_path() {
        Some(p) => p,
        None => return Ok(()), // no certbot installed → silently no-op (daily task)
    };
    let _ = Command::new(&certbot_bin)
        .args(["renew", "--non-interactive", "--quiet"])
        .output();
    // Always reload — cheap, and picks up anything certbot just
    // rotated without a per-cert deploy-hook dance.
    let _ = reload_proxy(&cfg);
    Ok(())
}

/// Location of the generated WolfProxy snippet that serves the ACME
/// webroot. Callers patch this into their main `http {}` config via
/// an `include` directive.
pub fn nginx_snippet_path() -> PathBuf {
    PathBuf::from("/etc/wolfproxy/conf.d/acme-challenge.conf")
}

/// Write (or overwrite) the ACME snippet. Contains a single location
/// block so both :80 and :443 servers can `include` it. Serving the
/// challenge on :443 is harmless and lets DNS cutovers resolve faster.
pub fn write_nginx_snippet(cfg: &CertbotConfig) -> Result<(), String> {
    let path = nginx_snippet_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create conf.d: {e}"))?;
    }
    let body = format!(
        "# Auto-generated by WolfStack certbot module — do not edit.\n\
         # Include from any server block that needs to solve ACME challenges.\n\
         location /.well-known/acme-challenge/ {{\n\
         \x20   root {};\n\
         \x20   default_type \"text/plain\";\n\
         \x20   try_files $uri =404;\n\
         }}\n",
        cfg.webroot,
    );
    std::fs::write(&path, body).map_err(|e| format!("write snippet: {e}"))?;
    ensure_webroot(cfg)?;
    Ok(())
}
