// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Container-scoped certificate management — certbot + Apache/WolfServe
//! inside LXC (and Docker) containers.
//!
//! The host Cert Manager (`certbot::{issue, renew, delete}`) runs certbot
//! on the node itself for WolfProxy. Containers running their own web
//! server (Apache2 or WolfServe — which share the same
//! `/etc/apache2/sites-available` config layout) need the same lifecycle
//! *inside* the container: the cert files must live where the container's
//! web server can read them, and the renewal config must sit next to the
//! certbot that will renew it. Everything here executes through
//! `ExecTarget`, the same transport the configurator uses (`lxc-attach`,
//! `pct exec`, or `docker exec`).
//!
//! Issuance is webroot (HTTP-01) only: the site's DocumentRoot serves the
//! challenge through the already-running web server, so there is no
//! downtime and no port conflict. Wildcards need DNS-01 and are refused
//! with a pointer to the host Cert Manager.

use serde::Serialize;

use super::{list_certs_via_target, CertSummary, CertbotConfig, LE_LIVE_DIR};
use crate::certbot::replication::is_safe_cert_name;
use crate::configurator::{apache, validate_name, ExecTarget};

/// Single-quote-escape for embedding a value in a `sh -c '...'` command
/// string — same idiom as `ExecTarget::read_file`.
fn shq(s: &str) -> String {
    s.replace('\'', "'\\''")
}

// ─── web server detection ───

/// A web server found inside the container. `id` is stable for the
/// frontend ("apache2" | "httpd" | "wolfserve"); `service` is the
/// systemd unit used for reloads.
#[derive(Debug, Clone, Serialize)]
pub struct WebServerInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub service: &'static str,
    pub running: bool,
}

/// Probe for `cmd` on the target's PATH.
fn has_command(target: &ExecTarget, cmd: &str) -> bool {
    target
        .exec_full(&format!("command -v '{}' >/dev/null 2>&1", shq(cmd)))
        .map(|(_, _, ok)| ok)
        .unwrap_or(false)
}

/// Is the web server actually running? `systemctl is-active` first,
/// with a process-table fallback (`pidof`/`pgrep`) for containers that
/// don't run systemd — Docker images and minimal LXC templates run the
/// server as PID 1 and systemctl would wrongly report it stopped.
fn service_active(target: &ExecTarget, service: &str) -> bool {
    let s = shq(service);
    target
        .exec_full(&format!(
            "systemctl is-active '{}' 2>/dev/null | grep -qx active \
             || pidof '{}' >/dev/null 2>&1 \
             || pgrep -x '{}' >/dev/null 2>&1",
            s, s, s
        ))
        .map(|(_, _, ok)| ok)
        .unwrap_or(false)
}

/// Detect which web server this container runs. WolfServe and Apache
/// share the same config layout, so either one makes the Certificates
/// page applicable. When more than one is installed, prefer whichever
/// service is actually running; otherwise the first installed in
/// wolfserve → apache2 → httpd order.
pub fn detect_web_server(target: &ExecTarget) -> Option<WebServerInfo> {
    // (id, label, service, install-probe commands)
    let candidates: [(&'static str, &'static str, &'static str, &[&str]); 3] = [
        ("wolfserve", "WolfServe", "wolfserve", &["wolfserve"]),
        ("apache2", "Apache 2", "apache2", &["apache2ctl", "apache2"]),
        ("httpd", "Apache (httpd)", "httpd", &["httpd", "apachectl"]),
    ];
    let mut installed: Vec<WebServerInfo> = Vec::new();
    for (id, label, service, probes) in candidates {
        if probes.iter().any(|p| has_command(target, p)) {
            installed.push(WebServerInfo {
                id,
                label,
                service,
                running: service_active(target, service),
            });
        }
    }
    if let Some(pos) = installed.iter().position(|w| w.running) {
        return Some(installed.swap_remove(pos));
    }
    installed.into_iter().next()
}

// ─── certbot inside the container ───

/// Resolve certbot's path inside the target. `command -v` first (covers
/// normal package installs), then the fixed locations the host-side
/// probe also knows about (snap, pipx/venv installs).
pub fn certbot_bin_in(target: &ExecTarget) -> Option<String> {
    if let Ok((out, _, ok)) = target.exec_full("command -v certbot 2>/dev/null") {
        let path = out.trim();
        if ok && !path.is_empty() {
            return Some(path.to_string());
        }
    }
    for path in [
        "/usr/bin/certbot",
        "/usr/local/bin/certbot",
        "/snap/bin/certbot",
        "/opt/certbot/bin/certbot",
    ] {
        if let Ok((_, _, ok)) = target.exec_full(&format!("test -x '{}'", path))
            && ok
        {
            return Some(path.to_string());
        }
    }
    None
}

/// Install certbot inside the container via its own package manager.
/// Same manager-probe order as the container update checker
/// (`detect_container_pkg_manager` in api/mod.rs).
pub fn install_certbot(target: &ExecTarget) -> Result<String, String> {
    if certbot_bin_in(target).is_some() {
        return Ok("certbot is already installed in this container".to_string());
    }
    let install_cmd = if has_command(target, "apt-get") {
        "apt-get update -qq 2>/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y certbot 2>&1"
    } else if has_command(target, "dnf") {
        "dnf install -y certbot 2>&1"
    } else if has_command(target, "yum") {
        "yum install -y certbot 2>&1"
    } else if has_command(target, "pacman") {
        "pacman -Sy --noconfirm certbot 2>&1"
    } else if has_command(target, "apk") {
        "apk add certbot 2>&1"
    } else {
        return Err(
            "No supported package manager (apt, dnf, yum, pacman, apk) found in this container — \
             install certbot manually via the container console"
                .to_string(),
        );
    };
    let (out, err, ok) = target.exec_full(install_cmd)?;
    if !ok {
        let detail = if err.trim().is_empty() { out } else { err };
        return Err(format!("certbot install failed:\n{}", detail.trim()));
    }
    // Verify — a "successful" package run that still leaves no binary
    // (broken repo, masked package) must not report success.
    match certbot_bin_in(target) {
        Some(path) => Ok(format!("certbot installed at {}", path)),
        None => Err(
            "Package manager reported success but no certbot binary was found afterwards — \
             check the container's package sources"
                .to_string(),
        ),
    }
}

/// Reload the container's web server so it picks up new/renewed certs.
/// Mirrors the fallback chain in `configurator::apache::reload`; used
/// both directly after renew and as the certbot `--deploy-hook` so
/// unattended renewals inside the container reload too. Trailing
/// `|| true` keeps a missing service from failing the certbot run —
/// the cert is already on disk at that point.
const RELOAD_CHAIN: &str = "systemctl reload apache2 2>/dev/null \
    || systemctl reload httpd 2>/dev/null \
    || apache2ctl -k graceful 2>/dev/null \
    || systemctl reload wolfserve 2>/dev/null \
    || systemctl restart wolfserve 2>/dev/null \
    || true";

fn reload_web_server(target: &ExecTarget) {
    let _ = target.exec_full(RELOAD_CHAIN);
}

/// Domain allowlist for `-d` args. Wildcards are deliberately excluded:
/// webroot (HTTP-01) cannot validate them — that flow lives in the host
/// Cert Manager's DNS-01 path.
fn validate_domain(d: &str) -> Result<(), String> {
    if d.is_empty() || d.len() > 253 {
        return Err(format!("invalid domain '{}'", d));
    }
    if d.contains('*') {
        return Err(format!(
            "wildcard domain '{}' needs a DNS-01 challenge, which requires DNS provider \
             credentials — use the host Certificates page (DNS providers) for wildcards",
            d
        ));
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
    {
        return Err(format!(
            "domain '{}' may only contain letters, digits, hyphens and dots",
            d
        ));
    }
    if d.starts_with('.') || d.contains("..") {
        return Err(format!("invalid domain '{}'", d));
    }
    Ok(())
}

fn validate_email(e: &str) -> Result<(), String> {
    if e.is_empty() {
        return Err("an email address is required (for Let's Encrypt account registration)".to_string());
    }
    if !e.contains('@')
        || !e
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+'))
    {
        return Err(format!("'{}' does not look like a valid email address", e));
    }
    Ok(())
}

/// Issue a certificate inside the container via webroot HTTP-01. The
/// webroot is the target site's DocumentRoot — the running web server
/// serves `/.well-known/acme-challenge/` from there, so issuance needs
/// no downtime. Requires port 80 for the domain to reach this
/// container from the internet.
pub fn issue_in_container(
    target: &ExecTarget,
    domains: &[String],
    email: &str,
    webroot: &str,
) -> Result<String, String> {
    if domains.is_empty() {
        return Err("at least one domain is required".to_string());
    }
    for d in domains {
        validate_domain(d)?;
    }
    validate_email(email)?;
    if !webroot.starts_with('/') {
        return Err(format!(
            "webroot '{}' must be an absolute path (the site's DocumentRoot)",
            webroot
        ));
    }
    if webroot.contains('\'') {
        return Err("webroot path may not contain quotes".to_string());
    }
    let certbot = certbot_bin_in(target).ok_or_else(|| {
        "certbot is not installed in this container — use the Install certbot button first"
            .to_string()
    })?;

    // The DocumentRoot is read from the vhost config; it normally exists,
    // but a freshly created site may not have it yet and certbot fails
    // confusingly when -w points at nothing.
    let _ = target.exec_full(&format!("mkdir -p '{}'", shq(webroot)));

    let mut cmd = format!(
        "'{}' certonly --non-interactive --agree-tos --email '{}' --webroot -w '{}' \
         --deploy-hook '{}'",
        shq(&certbot),
        shq(email),
        shq(webroot),
        RELOAD_CHAIN, // contains no single quotes — safe inside '…'
    );
    for d in domains {
        cmd.push_str(&format!(" -d '{}'", shq(d)));
    }
    let (out, err, ok) = target.exec_full(&cmd)?;
    if !ok {
        let detail = if err.trim().is_empty() { out } else { err };
        return Err(format!("certbot failed:\n{}", detail.trim()));
    }
    Ok(out)
}

/// Find the lineage name certbot gave a just-issued cert. certbot names
/// the lineage after the first `-d` domain (with `*.` stripped —
/// irrelevant here since wildcards are refused), suffixing `-0001` etc.
/// on collision, so match by name first and fall back to SAN coverage.
pub fn find_cert_for_domain(target: &ExecTarget, first_domain: &str) -> Option<CertSummary> {
    let certs = list_certs_via_target(target);
    if let Some(c) = certs.iter().find(|c| c.name == first_domain) {
        return Some(c.clone());
    }
    certs
        .into_iter()
        .find(|c| c.domains.iter().any(|d| d == first_domain))
}

/// `certbot renew --force-renewal --cert-name <name>` inside the
/// container, then reload the web server. Force, matching the host-side
/// `renew` — this is the explicit per-cert button, not the scheduled
/// sweep, so the operator wants a fresh cert now.
pub fn renew_in_container(target: &ExecTarget, name: &str) -> Result<String, String> {
    if !is_safe_cert_name(name) {
        return Err(format!("unsafe certificate name '{}'", name));
    }
    let certbot = certbot_bin_in(target)
        .ok_or_else(|| "certbot is not installed in this container".to_string())?;
    let (out, err, ok) = target.exec_full(&format!(
        "'{}' renew --non-interactive --force-renewal --cert-name '{}'",
        shq(&certbot),
        shq(name)
    ))?;
    if !ok {
        let detail = if err.trim().is_empty() { out } else { err };
        return Err(format!("renew failed:\n{}", detail.trim()));
    }
    reload_web_server(target);
    Ok(out)
}

/// `certbot delete --cert-name <name>` inside the container — certbot
/// cleans up live/, archive/ AND the renewal config (removing the dirs
/// by hand leaves a dangling renewal conf, same reasoning as the host
/// `delete`).
pub fn delete_in_container(target: &ExecTarget, name: &str) -> Result<String, String> {
    if !is_safe_cert_name(name) {
        return Err(format!("unsafe certificate name '{}'", name));
    }
    let certbot = certbot_bin_in(target)
        .ok_or_else(|| "certbot is not installed in this container".to_string())?;
    let (out, err, ok) = target.exec_full(&format!(
        "'{}' delete --non-interactive --cert-name '{}'",
        shq(&certbot),
        shq(name)
    ))?;
    if !ok {
        let detail = if err.trim().is_empty() { out } else { err };
        return Err(format!("delete failed:\n{}", detail.trim()));
    }
    Ok(out)
}

// ─── site inspection ───

/// One site config file with the certificate-relevant directives parsed
/// out. A file can hold several `<VirtualHost>` blocks (typically :80 +
/// :443 for the same site) — this aggregates across them, which is the
/// granularity the attach flow works at.
#[derive(Debug, Clone, Serialize)]
pub struct SiteCertInfo {
    pub name: String,
    pub enabled: bool,
    pub server_name: String,
    pub aliases: Vec<String>,
    pub doc_root: String,
    pub ports: Vec<u16>,
    pub has_ssl: bool,
    /// Path currently in SSLCertificateFile, if any.
    pub ssl_cert_path: String,
    /// Lineage name when ssl_cert_path points under /etc/letsencrypt/live/.
    pub cert_name: String,
}

/// Strip surrounding double quotes Apache permits on directive values.
fn unquote(v: &str) -> &str {
    v.trim().trim_matches('"')
}

/// Parse the certificate-relevant directives out of one vhost file.
fn parse_site(name: &str, enabled: bool, content: &str) -> SiteCertInfo {
    let mut info = SiteCertInfo {
        name: name.to_string(),
        enabled,
        server_name: String::new(),
        aliases: Vec::new(),
        doc_root: String::new(),
        ports: Vec::new(),
        has_ssl: false,
        ssl_cert_path: String::new(),
        cert_name: String::new(),
    };
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("<virtualhost") {
            // `<VirtualHost *:80>` / `<VirtualHost 10.0.0.5:443 [::]:443>`
            for token in line.trim_start_matches('<').trim_end_matches('>').split_whitespace().skip(1) {
                if let Some(port_s) = token.rsplit(':').next()
                    && let Ok(p) = port_s.parse::<u16>()
                    && !info.ports.contains(&p)
                {
                    info.ports.push(p);
                }
            }
        } else if let Some(v) = strip_directive(line, &lower, "servername") {
            if info.server_name.is_empty() {
                info.server_name = unquote(v).to_string();
            }
        } else if let Some(v) = strip_directive(line, &lower, "serveralias") {
            for a in v.split_whitespace() {
                let a = unquote(a).to_string();
                if !a.is_empty() && !info.aliases.contains(&a) {
                    info.aliases.push(a);
                }
            }
        } else if let Some(v) = strip_directive(line, &lower, "documentroot") {
            if info.doc_root.is_empty() {
                info.doc_root = unquote(v).to_string();
            }
        } else if let Some(v) = strip_directive(line, &lower, "sslcertificatefile") {
            info.has_ssl = true;
            if info.ssl_cert_path.is_empty() {
                info.ssl_cert_path = unquote(v).to_string();
            }
        } else if lower.starts_with("sslengine") && lower.contains("on") {
            info.has_ssl = true;
        }
    }
    // Derive the lineage name from a Let's Encrypt live path:
    // /etc/letsencrypt/live/<name>/fullchain.pem
    if let Some(rest) = info.ssl_cert_path.strip_prefix(&format!("{}/", LE_LIVE_DIR))
        && let Some(lineage) = rest.split('/').next()
    {
        info.cert_name = lineage.to_string();
    }
    info
}

/// If `line` starts with the directive (case-insensitive, whole word),
/// return the argument part of the original-case line.
fn strip_directive<'a>(line: &'a str, lower: &str, directive: &str) -> Option<&'a str> {
    if lower.starts_with(directive) {
        let rest = &line[directive.len()..];
        if rest.starts_with(' ') || rest.starts_with('\t') {
            return Some(rest);
        }
    }
    None
}

/// All site files with their parsed certificate state.
pub fn list_sites_with_ssl(target: &ExecTarget) -> Result<Vec<SiteCertInfo>, String> {
    let sites = apache::list_sites(target)?;
    let mut out = Vec::new();
    for s in sites {
        let content = apache::read_site(target, &s.name).unwrap_or_default();
        out.push(parse_site(&s.name, s.enabled, &content));
    }
    Ok(out)
}

// ─── attach a cert to a site ───

/// Point a site at a certificate. Two cases:
///
/// * The config already has SSL directives → rewrite the
///   `SSLCertificateFile` / `SSLCertificateKeyFile` values in place
///   (indentation preserved).
/// * No SSL yet → clone the first `<VirtualHost>` block into a `:443`
///   copy with `SSLEngine on` + the cert paths, appended to the same
///   file. The `:80` block keeps serving HTTP (and the ACME webroot
///   renewals need).
///
/// The rewritten config is tested (`apachectl configtest` /
/// `wolfserve --test`) and **reverted** if the test fails, so a bad
/// attach can never leave a broken config that blocks the next reload.
pub fn attach_cert_to_site(
    target: &ExecTarget,
    site_name: &str,
    cert_name: &str,
) -> Result<String, String> {
    validate_name(site_name)?;
    if !is_safe_cert_name(cert_name) {
        return Err(format!("unsafe certificate name '{}'", cert_name));
    }
    let fullchain = format!("{}/{}/fullchain.pem", LE_LIVE_DIR, cert_name);
    let privkey = format!("{}/{}/privkey.pem", LE_LIVE_DIR, cert_name);
    if !target.path_exists(&fullchain).unwrap_or(false) {
        return Err(format!(
            "certificate '{}' not found in this container ({} does not exist)",
            cert_name, fullchain
        ));
    }

    let original = apache::read_site(target, site_name)?;
    let updated = if original.to_ascii_lowercase().contains("sslcertificatefile") {
        rewrite_ssl_paths(&original, &fullchain, &privkey)
    } else {
        append_ssl_vhost(&original, &fullchain, &privkey)?
    };

    apache::save_site(target, site_name, &updated)?;

    // Apache needs mod_ssl for SSLEngine. a2enmod exists only on
    // Debian-layout Apache installs; it is idempotent, and on a
    // WolfServe-only container the command is simply absent — skip.
    if has_command(target, "a2enmod") {
        let _ = target.exec_full("a2enmod ssl 2>&1");
    }

    let test = apache::test_config(target);
    if !test.success {
        // Roll back — never leave a config the web server refuses.
        let restore = apache::save_site(target, site_name, &original);
        let mut msg = format!(
            "config test failed after attaching the certificate — the change was rolled back.\n{}",
            test.output
        );
        if test.output.contains("SSLEngine") || test.output.contains("SSLCertificateFile") {
            msg.push_str(
                "\n\nThe SSL module appears to be missing: run `a2enmod ssl` (Debian/Ubuntu) \
                 or install mod_ssl (`dnf install mod_ssl` on RHEL-family) inside the container.",
            );
        }
        if let Err(e) = restore {
            msg.push_str(&format!("\n\nWARNING: rollback also failed: {}", e));
        }
        return Err(msg);
    }

    // Only a reload makes the running server pick it up; reload() tests
    // again internally, which is cheap and keeps one code path.
    apache::reload(target)?;
    Ok(format!(
        "certificate '{}' attached to {} and the web server reloaded",
        cert_name, site_name
    ))
}

/// Case (a): existing SSL directives — swap just the file paths.
fn rewrite_ssl_paths(content: &str, fullchain: &str, privkey: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        let lower = trimmed.to_ascii_lowercase();
        if strip_directive(trimmed, &lower, "sslcertificatefile").is_some() {
            out.push_str(&format!("{}SSLCertificateFile {}\n", indent, fullchain));
        } else if strip_directive(trimmed, &lower, "sslcertificatekeyfile").is_some() {
            out.push_str(&format!("{}SSLCertificateKeyFile {}\n", indent, privkey));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Case (b): no SSL yet — clone the first `<VirtualHost>` block as a
/// `:443` vhost with the SSL directives added before its closing tag.
fn append_ssl_vhost(content: &str, fullchain: &str, privkey: &str) -> Result<String, String> {
    let lower = content.to_ascii_lowercase();
    let open = lower
        .find("<virtualhost")
        .ok_or_else(|| "no <VirtualHost> block found in this site config".to_string())?;
    let close_rel = lower[open..]
        .find("</virtualhost>")
        .ok_or_else(|| "unterminated <VirtualHost> block in this site config".to_string())?;
    let close_end = open + close_rel + "</virtualhost>".len();
    let block = &content[open..close_end];

    // Rewrite the opening tag's address:port tokens to :443.
    let tag_end_rel = block
        .find('>')
        .ok_or_else(|| "malformed <VirtualHost> opening tag".to_string())?;
    let open_tag = &block[..tag_end_rel]; // "<VirtualHost *:80 [::]:80"
    let rest = &block[tag_end_rel..]; // ">…</VirtualHost>"
    let mut addrs: Vec<String> = Vec::new();
    for token in open_tag.trim_start_matches('<').split_whitespace().skip(1) {
        let addr = match token.rfind(':') {
            // ":80" → keep the host part, force :443. rfind handles
            // bracketed IPv6 like "[::]:80".
            Some(pos) if token[pos + 1..].chars().all(|c| c.is_ascii_digit()) => {
                format!("{}:443", &token[..pos])
            }
            _ => format!("{}:443", token),
        };
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        addrs.push("*:443".to_string());
    }

    let mut ssl_block = format!("<VirtualHost {}", addrs.join(" "));
    // Insert the SSL directives just before the closing tag, preserving
    // everything else (ServerName, DocumentRoot, proxy rules, logs…).
    let rest_lower = rest.to_ascii_lowercase();
    let close_in_rest = rest_lower
        .rfind("</virtualhost>")
        .ok_or_else(|| "unterminated <VirtualHost> block in this site config".to_string())?;
    ssl_block.push_str(&rest[..close_in_rest]);
    if !ssl_block.ends_with('\n') {
        ssl_block.push('\n');
    }
    ssl_block.push_str(&format!(
        "\n    SSLEngine on\n    SSLCertificateFile {}\n    SSLCertificateKeyFile {}\n",
        fullchain, privkey
    ));
    ssl_block.push_str("</VirtualHost>");

    let mut out = content.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("\n# HTTPS vhost added by WolfStack Certificates\n");
    out.push_str(&ssl_block);
    out.push('\n');
    Ok(out)
}

// ─── overview ───

/// Everything the container Certificates page needs in one round trip.
#[derive(Debug, Serialize)]
pub struct ContainerCertOverview {
    pub web_server: Option<WebServerInfo>,
    pub certbot_installed: bool,
    pub certs: Vec<CertSummary>,
    pub sites: Vec<SiteCertInfo>,
    /// Host Cert Manager's saved contact email, as a prefill convenience
    /// — the account inside the container is separate.
    pub default_email: String,
}

pub fn overview(target: &ExecTarget) -> ContainerCertOverview {
    let web_server = detect_web_server(target);
    if web_server.is_none() {
        // No web server → the page renders its "Nothing is installed"
        // state; skip the per-site and per-cert probing entirely.
        return ContainerCertOverview {
            web_server: None,
            certbot_installed: certbot_bin_in(target).is_some(),
            certs: Vec::new(),
            sites: Vec::new(),
            default_email: CertbotConfig::load().email,
        };
    }
    ContainerCertOverview {
        web_server,
        certbot_installed: certbot_bin_in(target).is_some(),
        certs: list_certs_via_target(target),
        sites: list_sites_with_ssl(target).unwrap_or_default(),
        default_email: CertbotConfig::load().email,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_VHOST: &str = "<VirtualHost *:80>\n    ServerName example.com\n    ServerAlias www.example.com api.example.com\n    DocumentRoot /var/www/example\n\n    ErrorLog ${APACHE_LOG_DIR}/example_com-error.log\n</VirtualHost>\n";

    #[test]
    fn parse_plain_site() {
        let info = parse_site("example.conf", true, PLAIN_VHOST);
        assert_eq!(info.server_name, "example.com");
        assert_eq!(info.aliases, vec!["www.example.com", "api.example.com"]);
        assert_eq!(info.doc_root, "/var/www/example");
        assert_eq!(info.ports, vec![80]);
        assert!(!info.has_ssl);
        assert!(info.cert_name.is_empty());
    }

    #[test]
    fn parse_ssl_site_derives_cert_name() {
        let content = "<VirtualHost *:443>\n    ServerName example.com\n    SSLEngine on\n    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\n    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem\n</VirtualHost>\n";
        let info = parse_site("example.conf", true, content);
        assert!(info.has_ssl);
        assert_eq!(info.cert_name, "example.com");
        assert_eq!(info.ports, vec![443]);
    }

    #[test]
    fn parse_ignores_comments_and_quotes() {
        let content = "# ServerName commented.example\n<VirtualHost *:80>\n    ServerName \"quoted.example.com\"\n    DocumentRoot \"/var/www/q\"\n</VirtualHost>\n";
        let info = parse_site("q.conf", false, content);
        assert_eq!(info.server_name, "quoted.example.com");
        assert_eq!(info.doc_root, "/var/www/q");
        assert!(!info.enabled);
    }

    #[test]
    fn append_ssl_vhost_clones_first_block() {
        let out = append_ssl_vhost(
            PLAIN_VHOST,
            "/etc/letsencrypt/live/example.com/fullchain.pem",
            "/etc/letsencrypt/live/example.com/privkey.pem",
        )
        .unwrap();
        // Original :80 block untouched, new :443 block appended.
        assert!(out.contains("<VirtualHost *:80>"));
        assert!(out.contains("<VirtualHost *:443>"));
        assert!(out.contains("SSLEngine on"));
        assert!(out.contains("SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem"));
        assert!(out.contains("SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem"));
        // The clone keeps the site identity directives.
        let ssl_part = &out[out.find("*:443").unwrap()..];
        assert!(ssl_part.contains("ServerName example.com"));
        assert!(ssl_part.contains("DocumentRoot /var/www/example"));
        // Parses back as an SSL-enabled site with both ports.
        let info = parse_site("example.conf", true, &out);
        assert!(info.has_ssl);
        assert_eq!(info.cert_name, "example.com");
        assert_eq!(info.ports, vec![80, 443]);
    }

    #[test]
    fn append_ssl_vhost_handles_multiple_addrs() {
        let content = "<VirtualHost 10.0.0.5:80 [::]:80>\n    ServerName v6.example.com\n</VirtualHost>\n";
        let out = append_ssl_vhost(content, "/c/full.pem", "/c/priv.pem").unwrap();
        assert!(out.contains("<VirtualHost 10.0.0.5:443 [::]:443>"));
    }

    #[test]
    fn append_ssl_vhost_requires_vhost_block() {
        assert!(append_ssl_vhost("DocumentRoot /var/www\n", "/c/f", "/c/p").is_err());
    }

    #[test]
    fn rewrite_ssl_paths_preserves_indentation() {
        let content = "<VirtualHost *:443>\n\tSSLEngine on\n\tSSLCertificateFile /old/cert.pem\n\tSSLCertificateKeyFile /old/key.pem\n</VirtualHost>\n";
        let out = rewrite_ssl_paths(content, "/new/fullchain.pem", "/new/privkey.pem");
        assert!(out.contains("\tSSLCertificateFile /new/fullchain.pem"));
        assert!(out.contains("\tSSLCertificateKeyFile /new/privkey.pem"));
        assert!(!out.contains("/old/"));
        assert!(out.contains("SSLEngine on"));
    }

    #[test]
    fn domain_validation() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub-1.example.co.uk").is_ok());
        assert!(validate_domain("*.example.com").is_err()); // wildcard → DNS-01 only
        assert!(validate_domain("bad domain").is_err());
        assert!(validate_domain("in'ject").is_err());
        assert!(validate_domain("").is_err());
        assert!(validate_domain(".leading.dot").is_err());
    }

    #[test]
    fn email_validation() {
        assert!(validate_email("ops@example.com").is_ok());
        assert!(validate_email("").is_err());
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("a'b@example.com").is_err());
    }
}
