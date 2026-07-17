//! Native-backend implementations of the "Hosting Tools" feature set.
//!
//! Every function here operates on a service's LXC container through
//! the WolfStack exec API (node-aware: local first, then the node
//! proxy — same routing as `portal::databases::container_exec`).
//! Responses reuse the `Da*` structs from `provisioning::directadmin`
//! so the portal frontend receives identical JSON regardless of
//! which backend served it.
//!
//! The container layout these functions manage is the one the deploy
//! path actually provisions (see `api::servers` deploy steps and
//! `provisioning::container::setup_web_stack`):
//!   * Apache vhost `/etc/apache2/sites-available/000-default.conf`
//!     with `DocumentRoot /var/www/html` and `AllowOverride All`
//!   * FTP via vsftpd with local system users (`webmaster`)
//!   * Mail (optional) via Postfix virtual mailboxes
//!     (`/etc/postfix/vmailbox`) + Dovecot passwd-file
//!     (`/etc/dovecot/users`), maildirs under `/var/mail/vhosts/%d/%n`
//!     — see `provisioning::mail::setup_mail_server`.
//!
//! Non-Debian-family containers (the deploy path can also install a
//! bare Apache on Alpine/RHEL/Arch but never writes a vhost there)
//! get a clear "requires the standard web stack" error instead of a
//! silent failure.

use serde::{Deserialize, Serialize};

use crate::wolfhost::models::service::HostingService;
use crate::wolfhost::provisioning::directadmin::{
    DaCronJob, DaProtectedDir, DaRedirect, DaSshKey,
};

/// Source: portal/databases.rs:18-32 container_exec() — try the local
/// WolfStack API first, then fall back to the node proxy.
pub async fn exec(service: &HostingService, command: &str) -> Result<ExecResult, String> {
    let container = &service.container_name;
    if container.is_empty() {
        return Err("No container provisioned for this service".to_string());
    }
    let local = format!("/api/containers/lxc/{}/exec", container);
    let body = serde_json::json!({ "command": command });
    let mut last_err;
    match crate::wolfhost::api::servers::wolfstack_post_pub(&local, &body).await {
        Ok(r) if r["ok"].as_bool() == Some(true) || r.get("exit_code").is_some() => {
            return Ok(ExecResult::from_json(&r));
        }
        Ok(r) => last_err = r["error"].as_str().unwrap_or("exec failed").to_string(),
        Err(e) => last_err = e,
    }
    if !service.server_node.is_empty() {
        let remote = format!(
            "/api/nodes/{}/proxy/containers/lxc/{}/exec",
            service.server_node, container
        );
        let r = crate::wolfhost::api::servers::wolfstack_post_pub(&remote, &body).await?;
        if r["ok"].as_bool() == Some(true) || r.get("exit_code").is_some() {
            return Ok(ExecResult::from_json(&r));
        }
        last_err = r["error"].as_str().unwrap_or("exec failed").to_string();
    }
    Err(format!("Container not reachable: {}", last_err))
}

pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i64,
}

impl ExecResult {
    fn from_json(r: &serde_json::Value) -> Self {
        Self {
            stdout: r["stdout"].as_str().unwrap_or("").to_string(),
            stderr: r["stderr"].as_str().unwrap_or("").to_string(),
            exit_code: r["exit_code"].as_i64().unwrap_or(0),
        }
    }
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

/// Single-quote a string for safe interpolation into `sh -c`.
pub fn squote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Write a file inside the container from arbitrary (possibly
/// multi-line, attacker-controlled) content WITHOUT a heredoc.
///
/// Heredocs terminate on a line equal to the delimiter, so any
/// content a customer fully controls (a sieve vacation body, a
/// pasted PEM with trailing junk lines) could break out of the
/// heredoc and inject shell. base64-encoding the content in Rust
/// and decoding in the container removes that entire class of bug:
/// the only thing interpolated is `[A-Za-z0-9+/=]`, further wrapped
/// in single quotes. `base64` exists in coreutils and busybox.
pub async fn write_file(
    service: &HostingService,
    path: &str,
    content: &str,
) -> Result<(), String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
    let cmd = format!(
        "printf %s {b64} | base64 -d > {path} && echo WROTE_7f3a",
        b64 = squote(&b64),
        path = squote(path)
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("WROTE_7f3a") {
        return Err(format!("Failed to write {}: {}", path, r.stderr));
    }
    Ok(())
}

/// Document root the deploy path provisions.
/// Source: provisioning/container.rs:69 + api/servers.rs deploy vhost — `DocumentRoot /var/www/html`.
pub const DOCROOT: &str = "/var/www/html";

/// Vhost file the deploy path writes.
/// Source: provisioning/container.rs:83 — `/etc/apache2/sites-available/000-default.conf`.
pub const VHOST_FILE: &str = "/etc/apache2/sites-available/000-default.conf";

/// Reload Apache, tolerating both systemd and OpenRC layouts.
const APACHE_RELOAD: &str =
    "systemctl reload apache2 2>/dev/null || systemctl restart apache2 2>/dev/null || rc-service apache2 reload 2>/dev/null";

/// Guard: these tools manage the Debian/Ubuntu Apache layout that the
/// provisioner writes. Errors clearly on containers without it.
async fn require_web_stack(service: &HostingService) -> Result<(), String> {
    let r = exec(service, "test -d /etc/apache2 && echo APACHE_DEB").await?;
    if !r.stdout.contains("APACHE_DEB") {
        return Err(
            "This tool requires the standard Ubuntu/Debian web stack (Apache) that WolfHost provisions. \
             This container does not have /etc/apache2 — contact support."
                .to_string(),
        );
    }
    Ok(())
}

/// Guard for mail tools: Postfix must have been set up via the
/// Email → "Set Up Mail Server" flow (provisioning::mail).
async fn require_mail_stack(service: &HostingService) -> Result<(), String> {
    let r = exec(service, "test -f /etc/postfix/main.cf && echo HAVE_POSTFIX").await?;
    if !r.stdout.contains("HAVE_POSTFIX") {
        return Err(
            "The mail server is not set up on this service yet. \
             Open Email and use \"Set Up Mail Server\" first."
                .to_string(),
        );
    }
    Ok(())
}

/// Replace (or create) a marker-delimited block in a file inside the
/// container. Passing an empty `content` removes the block.
async fn set_marker_block(
    service: &HostingService,
    file: &str,
    marker: &str,
    content: &str,
) -> Result<(), String> {
    // Strip any existing block, then append the new one.
    let strip = format!(
        "touch {f} && awk 'index($0, \"# BEGIN {m}\"){{skip=1}} !skip{{print}} index($0, \"# END {m}\"){{skip=0}}' {f} > {f}.whtmp && mv {f}.whtmp {f}",
        f = file,
        m = marker
    );
    let r = exec(service, &strip).await?;
    if !r.ok() {
        return Err(format!("Failed to update {}: {}", file, r.stderr));
    }
    if !content.is_empty() {
        let append = format!(
            "cat >> {f} << 'WH_EOF_7f3a'\n# BEGIN {m}\n{c}\n# END {m}\nWH_EOF_7f3a",
            f = file,
            m = marker,
            c = content
        );
        let r = exec(service, &append).await?;
        if !r.ok() {
            return Err(format!("Failed to write {}: {}", file, r.stderr));
        }
    }
    Ok(())
}

/// Read a marker-delimited block's inner lines from a file.
async fn get_marker_block(
    service: &HostingService,
    file: &str,
    marker: &str,
) -> Result<Vec<String>, String> {
    let cmd = format!(
        "awk 'index($0, \"# END {m}\"){{on=0}} on{{print}} index($0, \"# BEGIN {m}\"){{on=1}}' {f} 2>/dev/null",
        f = file,
        m = marker
    );
    let r = exec(service, &cmd).await?;
    Ok(r.stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Validate a URL path fragment the customer supplies (redirect
/// source, protected-dir path). Must start with `/`, no whitespace,
/// no `..` traversal, no quotes that could break out of directives.
fn valid_url_path(p: &str) -> bool {
    p.starts_with('/')
        && !p.contains("..")
        && !p.contains(char::is_whitespace)
        && !p.contains('"')
        && !p.contains('\'')
        && !p.contains('`')
        && !p.contains('\\')
}

/// Validate a redirect destination — absolute URL or absolute path.
fn valid_destination(d: &str) -> bool {
    (d.starts_with('/') || d.starts_with("http://") || d.starts_with("https://"))
        && !d.contains(char::is_whitespace)
        && !d.contains('"')
        && !d.contains('\'')
        && !d.contains('`')
}

/// Validate a hostname/domain label string (RFC 952-ish, enough to
/// keep it safe inside Apache directives and shell single-quotes).
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() < 254
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !d.starts_with('-')
        && !d.starts_with('.')
}

// ─────────────────────────────────────────────────────────────────
// HTTP redirects — mod_alias `Redirect` lines in the docroot
// .htaccess (AllowOverride All is set by the provisioner vhost).
// Response shape: DaRedirect { path, destination, code }.
// ─────────────────────────────────────────────────────────────────

const REDIRECT_MARKER: &str = "wolfhost-redirects";

fn htaccess_path() -> String {
    format!("{}/.htaccess", DOCROOT)
}

pub async fn list_redirects(service: &HostingService) -> Result<Vec<DaRedirect>, String> {
    require_web_stack(service).await?;
    let lines = get_marker_block(service, &htaccess_path(), REDIRECT_MARKER).await?;
    let mut out = Vec::new();
    for line in lines {
        // Format written by create_redirect: `Redirect <code> <path> <dest>`
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 4 && parts[0] == "Redirect" {
            out.push(DaRedirect {
                path: parts[2].to_string(),
                destination: parts[3].to_string(),
                code: parts[1].parse().unwrap_or(301),
            });
        }
    }
    Ok(out)
}

pub async fn create_redirect(
    service: &HostingService,
    path: &str,
    destination: &str,
    code: u16,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_url_path(path) {
        return Err("Redirect path must start with / and contain no spaces or quotes".to_string());
    }
    if !valid_destination(destination) {
        return Err("Destination must be an absolute path or http(s) URL".to_string());
    }
    let mut redirects = list_redirects(service).await?;
    redirects.retain(|r| r.path != path);
    redirects.push(DaRedirect {
        path: path.to_string(),
        destination: destination.to_string(),
        code,
    });
    write_redirects(service, &redirects).await
}

pub async fn delete_redirect(service: &HostingService, path: &str) -> Result<(), String> {
    require_web_stack(service).await?;
    let mut redirects = list_redirects(service).await?;
    let before = redirects.len();
    redirects.retain(|r| r.path != path);
    if redirects.len() == before {
        return Err(format!("No redirect found for path {}", path));
    }
    write_redirects(service, &redirects).await
}

async fn write_redirects(service: &HostingService, redirects: &[DaRedirect]) -> Result<(), String> {
    let content = redirects
        .iter()
        .map(|r| format!("Redirect {} {} {}", r.code, r.path, r.destination))
        .collect::<Vec<_>>()
        .join("\n");
    set_marker_block(service, &htaccess_path(), REDIRECT_MARKER, &content).await
}

// ─────────────────────────────────────────────────────────────────
// Security toggles — force-HTTPS rewrite + HSTS header, both as
// marker blocks in the docroot .htaccess. mod_rewrite and
// mod_headers are enabled by the provisioner (`a2enmod rewrite ssl
// headers expires` — api/servers.rs deploy + container.rs:60).
// ─────────────────────────────────────────────────────────────────

const FORCE_HTTPS_MARKER: &str = "wolfhost-force-https";
const HSTS_MARKER: &str = "wolfhost-hsts";

pub async fn set_force_https(service: &HostingService, force: bool) -> Result<(), String> {
    require_web_stack(service).await?;
    let content = if force {
        "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
    } else {
        ""
    };
    set_marker_block(service, &htaccess_path(), FORCE_HTTPS_MARKER, content).await
}

pub async fn set_hsts(service: &HostingService, enabled: bool) -> Result<(), String> {
    require_web_stack(service).await?;
    let content = if enabled {
        "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
    } else {
        ""
    };
    set_marker_block(service, &htaccess_path(), HSTS_MARKER, content).await
}

// ─────────────────────────────────────────────────────────────────
// Protected directories — .htaccess basic auth + htpasswd files kept
// outside the docroot in /etc/wolfhost-htpasswd/. Passwords are
// hashed by the `htpasswd` tool itself (bcrypt) so we never guess at
// hash formats; the tool is installed on demand.
// Response shape: DaProtectedDir { path, realm, users }.
// ─────────────────────────────────────────────────────────────────

const HTPASSWD_DIR: &str = "/etc/wolfhost-htpasswd";

fn protected_token(path: &str) -> String {
    // Stable filesystem-safe token for a protected path.
    let t: String = path
        .trim_matches('/')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if t.is_empty() { "root".to_string() } else { t }
}

pub async fn list_protected_dirs(service: &HostingService) -> Result<Vec<DaProtectedDir>, String> {
    require_web_stack(service).await?;
    // Find every .htaccess under the docroot that carries our auth
    // block, then read realm + user list for each.
    let cmd = format!(
        "grep -rls --include=.htaccess 'BEGIN wolfhost-protect' {} 2>/dev/null",
        DOCROOT
    );
    let r = exec(service, &cmd).await?;
    let mut out = Vec::new();
    for file in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        let dir = file.trim_end_matches("/.htaccess");
        let rel = dir.strip_prefix(DOCROOT).unwrap_or("");
        let rel = if rel.is_empty() { "/".to_string() } else { rel.to_string() };
        let block = get_marker_block(service, file, "wolfhost-protect").await?;
        let mut realm = String::new();
        let mut userfile = String::new();
        for line in &block {
            if let Some(v) = line.strip_prefix("AuthName ") {
                realm = v.trim_matches('"').to_string();
            }
            if let Some(v) = line.strip_prefix("AuthUserFile ") {
                userfile = v.trim().to_string();
            }
        }
        let mut users = Vec::new();
        if !userfile.is_empty() {
            let r = exec(service, &format!("cut -d: -f1 {} 2>/dev/null", squote(&userfile))).await?;
            users = r
                .stdout
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
        }
        out.push(DaProtectedDir { path: rel, realm, users });
    }
    Ok(out)
}

pub async fn add_protected_dir(
    service: &HostingService,
    path: &str,
    realm: &str,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_url_path(path) {
        return Err("Path must start with / and contain no spaces, quotes or ..".to_string());
    }
    if realm.contains('"') || realm.contains('\n') || realm.contains('\\') || realm.contains('`') || realm.contains('$') {
        return Err("Realm must not contain quotes or special characters".to_string());
    }
    let token = protected_token(path);
    let userfile = format!("{}/{}", HTPASSWD_DIR, token);
    let dir = format!("{}{}", DOCROOT, path);
    let mkdir = format!(
        "mkdir -p {d} {hp} && touch {uf} && chmod 640 {uf} && chown root:www-data {uf} 2>/dev/null; echo READY",
        d = squote(&dir),
        hp = HTPASSWD_DIR,
        uf = squote(&userfile)
    );
    let r = exec(service, &mkdir).await?;
    if !r.stdout.contains("READY") {
        return Err(format!("Failed to prepare directory: {}", r.stderr));
    }
    let content = format!(
        "AuthType Basic\nAuthName \"{}\"\nAuthUserFile {}\nRequire valid-user",
        realm, userfile
    );
    set_marker_block(service, &format!("{}/.htaccess", dir), "wolfhost-protect", &content).await
}

pub async fn add_protected_user(
    service: &HostingService,
    path: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_url_path(path) {
        return Err("Invalid path".to_string());
    }
    if username.is_empty() || !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err("Username may only contain letters, digits, . _ -".to_string());
    }
    let token = protected_token(path);
    let userfile = format!("{}/{}", HTPASSWD_DIR, token);
    // htpasswd does the hashing (bcrypt); install apache2-utils on
    // demand — same install-on-demand chain style as the DB path
    // (portal/databases.rs install_cmd).
    let cmd = format!(
        "test -f {uf} || exit 40; \
         command -v htpasswd >/dev/null 2>&1 || {{ export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq apache2-utils 2>&1 || dnf install -y -q httpd-tools 2>&1 || apk add --no-cache apache2-utils 2>&1; }}; \
         htpasswd -bB {uf} {u} {p} 2>&1 && echo USERADDED",
        uf = squote(&userfile),
        u = squote(username),
        p = squote(password)
    );
    let r = exec(service, &cmd).await?;
    if r.exit_code == 40 {
        return Err("That path is not protected yet — protect it first".to_string());
    }
    if !r.stdout.contains("USERADDED") {
        return Err(format!("htpasswd failed: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

pub async fn delete_protected_dir(service: &HostingService, path: &str) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_url_path(path) {
        return Err("Invalid path".to_string());
    }
    let token = protected_token(path);
    let dir = format!("{}{}", DOCROOT, path);
    set_marker_block(service, &format!("{}/.htaccess", dir), "wolfhost-protect", "").await?;
    let cleanup = format!(
        "rm -f {}/{} ; [ -s {}/.htaccess ] || rm -f {}/.htaccess; echo CLEANED",
        HTPASSWD_DIR,
        token,
        squote(&dir),
        squote(&dir)
    );
    exec(service, &cleanup).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Domain pointers / aliases.
//   * alias  → `ServerAlias` inside a marker block in the primary
//     vhost (000-default.conf), so the extra name serves the same
//     site.
//   * pointer (redirect) → dedicated vhost file
//     `wolfhost-ptr-<from>.conf` that 301s everything to the target.
// If PowerDNS is running (provisioning::dns), a zone is created for
// the new name so it resolves through the platform's nameservers.
// Response shape: DaDomainPointer { from, to, alias }.
// ─────────────────────────────────────────────────────────────────

const POINTER_MARKER: &str = "wolfhost-aliases";

pub async fn list_pointers(
    service: &HostingService,
    target_domain: &str,
) -> Result<Vec<crate::wolfhost::provisioning::directadmin::DaDomainPointer>, String> {
    use crate::wolfhost::provisioning::directadmin::DaDomainPointer;
    require_web_stack(service).await?;
    let mut out = Vec::new();
    // Aliases: ServerAlias lines inside our marker block.
    for line in get_marker_block(service, VHOST_FILE, POINTER_MARKER).await? {
        if let Some(alias) = line.strip_prefix("ServerAlias ") {
            out.push(DaDomainPointer {
                from: alias.trim().to_string(),
                to: target_domain.to_string(),
                alias: true,
            });
        }
    }
    // Redirect pointers: one vhost file per name.
    let r = exec(
        service,
        "ls /etc/apache2/sites-available/ 2>/dev/null | grep '^wolfhost-ptr-' || true",
    )
    .await?;
    for f in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        let from = f
            .trim()
            .trim_start_matches("wolfhost-ptr-")
            .trim_end_matches(".conf")
            .to_string();
        out.push(DaDomainPointer {
            from,
            to: target_domain.to_string(),
            alias: false,
        });
    }
    Ok(out)
}

pub async fn create_pointer(
    service: &HostingService,
    target_domain: &str,
    from: &str,
    is_alias: bool,
    branding_ns: (&str, &str),
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_domain(from) {
        return Err("Alias must be a valid domain name".to_string());
    }
    if is_alias {
        let mut aliases: Vec<String> = get_marker_block(service, VHOST_FILE, POINTER_MARKER)
            .await?
            .into_iter()
            .filter_map(|l| l.strip_prefix("ServerAlias ").map(|a| a.trim().to_string()))
            .collect();
        if !aliases.iter().any(|a| a.eq_ignore_ascii_case(from)) {
            aliases.push(from.to_string());
        }
        let content = aliases
            .iter()
            .map(|a| format!("ServerAlias {}", a))
            .collect::<Vec<_>>()
            .join("\n");
        // The marker block sits inside the <VirtualHost> element:
        // insert before the closing tag rather than appending to EOF.
        set_vhost_alias_block(service, &content).await?;
    } else {
        let vhost = format!(
            "<VirtualHost *:80>\n    ServerName {from}\n    Redirect permanent / http://{to}/\n</VirtualHost>",
            from = from,
            to = target_domain
        );
        let cmd = format!(
            "cat > /etc/apache2/sites-available/wolfhost-ptr-{from}.conf << 'WH_EOF_7f3a'\n{v}\nWH_EOF_7f3a\na2ensite wolfhost-ptr-{from} >/dev/null 2>&1; {reload}; echo PTRDONE",
            from = from,
            v = vhost,
            reload = APACHE_RELOAD
        );
        let r = exec(service, &cmd).await?;
        if !r.stdout.contains("PTRDONE") {
            return Err(format!("Failed to create pointer vhost: {}", r.stderr));
        }
    }
    // Best-effort DNS zone so the alias resolves via the platform's
    // nameservers; skipped silently when PowerDNS isn't installed.
    // pdns calls shell out to curl (dns.rs pdns_request), so keep
    // them off the async runtime.
    if !service.host_ip.is_empty() {
        let (ns1, ns2) = branding_ns;
        if !ns1.is_empty() {
            let from = from.to_string();
            let host_ip = service.host_ip.clone();
            let ns1 = ns1.to_string();
            let ns2 = ns2.to_string();
            tokio::task::spawn_blocking(move || {
                if crate::wolfhost::provisioning::dns::is_pdns_running() {
                    crate::wolfhost::provisioning::dns::create_zone(&from, &host_ip, &ns1, &ns2).ok();
                }
            })
            .await
            .ok();
        }
    }
    apache_reload(service).await
}

pub async fn delete_pointer(
    service: &HostingService,
    from: &str,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_domain(from) {
        return Err("Invalid alias name".to_string());
    }
    // Remove from the alias block if present.
    let aliases: Vec<String> = get_marker_block(service, VHOST_FILE, POINTER_MARKER)
        .await?
        .into_iter()
        .filter_map(|l| l.strip_prefix("ServerAlias ").map(|a| a.trim().to_string()))
        .filter(|a| !a.eq_ignore_ascii_case(from))
        .collect();
    let content = aliases
        .iter()
        .map(|a| format!("ServerAlias {}", a))
        .collect::<Vec<_>>()
        .join("\n");
    set_vhost_alias_block(service, &content).await?;
    // Remove a redirect-pointer vhost if present.
    let cmd = format!(
        "a2dissite wolfhost-ptr-{from} >/dev/null 2>&1; rm -f /etc/apache2/sites-available/wolfhost-ptr-{from}.conf; echo PTRGONE",
        from = from
    );
    exec(service, &cmd).await?;
    {
        let from = from.to_string();
        tokio::task::spawn_blocking(move || {
            if crate::wolfhost::provisioning::dns::is_pdns_running() {
                crate::wolfhost::provisioning::dns::delete_zone(&from).ok();
            }
        })
        .await
        .ok();
    }
    apache_reload(service).await
}

/// Write the alias marker block INSIDE the primary <VirtualHost>,
/// just before its closing tag. Strips any previous block first.
async fn set_vhost_alias_block(service: &HostingService, content: &str) -> Result<(), String> {
    let strip = format!(
        "awk 'index($0, \"# BEGIN {m}\"){{skip=1}} !skip{{print}} index($0, \"# END {m}\"){{skip=0}}' {f} > {f}.whtmp && mv {f}.whtmp {f}",
        m = POINTER_MARKER,
        f = VHOST_FILE
    );
    let r = exec(service, &strip).await?;
    if !r.ok() {
        return Err(format!("Failed to update vhost: {}", r.stderr));
    }
    if !content.is_empty() {
        // Insert the block before </VirtualHost> using awk.
        let block = format!("# BEGIN {m}\n{c}\n# END {m}", m = POINTER_MARKER, c = content);
        let cmd = format!(
            "awk -v block={b} 'index($0, \"</VirtualHost>\") && !done {{print block; done=1}} {{print}}' {f} > {f}.whtmp && mv {f}.whtmp {f}",
            b = squote(&block),
            f = VHOST_FILE
        );
        let r = exec(service, &cmd).await?;
        if !r.ok() {
            return Err(format!("Failed to write vhost aliases: {}", r.stderr));
        }
    }
    Ok(())
}

async fn apache_reload(service: &HostingService) -> Result<(), String> {
    let r = exec(service, &format!("{}; echo RELOADOK", APACHE_RELOAD)).await?;
    if !r.stdout.contains("RELOADOK") {
        return Err(format!("Apache reload failed: {}", r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// PHP version. Native containers run mod_php from the distro (the
// provisioner installs `libapache2-mod-php php` — api/servers.rs
// deploy steps). Listing shows what's installed under /etc/php;
// switching re-points mod_php and the php CLI alternative. Asking
// for a version that isn't installed produces a clear error instead
// of pretending.
// ─────────────────────────────────────────────────────────────────

pub async fn list_php_versions(service: &HostingService) -> Result<Vec<String>, String> {
    require_web_stack(service).await?;
    let r = exec(service, "ls /etc/php 2>/dev/null").await?;
    let mut versions: Vec<String> = r
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && l.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .collect();
    versions.sort();
    if versions.is_empty() {
        // PHP not installed at all — report the CLI version if any.
        let r = exec(service, "php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null").await?;
        if !r.stdout.trim().is_empty() {
            versions.push(r.stdout.trim().to_string());
        }
    }
    Ok(versions)
}

pub async fn get_php_version(service: &HostingService) -> Result<String, String> {
    require_web_stack(service).await?;
    let r = exec(service, "php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null").await?;
    let v = r.stdout.trim().to_string();
    if v.is_empty() {
        return Err("PHP is not installed on this service".to_string());
    }
    Ok(v)
}

pub async fn set_php_version(service: &HostingService, version: &str) -> Result<(), String> {
    require_web_stack(service).await?;
    if !version.chars().all(|c| c.is_ascii_digit() || c == '.') || version.is_empty() {
        return Err("Version must look like 8.2".to_string());
    }
    let installed = list_php_versions(service).await?;
    if !installed.iter().any(|v| v == version) {
        // Try to install it; on stock Debian/Ubuntu only the distro
        // version exists, so surface the honest failure.
        let cmd = format!(
            "export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq php{v} libapache2-mod-php{v} 2>&1 && echo PHPINSTALLED",
            v = version
        );
        let r = exec(service, &cmd).await?;
        if !r.stdout.contains("PHPINSTALLED") {
            return Err(format!(
                "PHP {} is not installed and could not be installed from the distribution repositories. Installed versions: {}",
                version,
                installed.join(", ")
            ));
        }
    }
    // Switch mod_php and the CLI alternative to the requested version.
    let cmd = format!(
        "for m in /etc/apache2/mods-enabled/php*.load; do [ -e \"$m\" ] && a2dismod $(basename \"$m\" .load) >/dev/null 2>&1; done; \
         a2enmod php{v} >/dev/null 2>&1 && update-alternatives --set php /usr/bin/php{v} >/dev/null 2>&1; {reload}; \
         php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'",
        v = version,
        reload = APACHE_RELOAD
    );
    let r = exec(service, &cmd).await?;
    if r.stdout.trim() != version {
        return Err(format!(
            "Switch did not take effect (php reports {}). Check that php{} and libapache2-mod-php{} are installed.",
            r.stdout.trim(),
            version,
            version
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Cron jobs — managed in the `webmaster` user's crontab (the FTP /
// site user the provisioner creates: container.rs "useradd -m -d
// /var/www/html -s /bin/bash -G www-data webmaster"). Each job is
// written as a pair of lines so it carries a stable id:
//   # wolfhost-id=<uuid>
//   <min> <hr> <dom> <mon> <dow> <command>
// Response shape: DaCronJob.
// ─────────────────────────────────────────────────────────────────

const CRON_USER: &str = "webmaster";

/// cron isn't guaranteed inside a fresh LXC image — install/enable on
/// demand, same fallback-chain style as the DB installer
/// (portal/databases.rs install_cmd).
const ENSURE_CRON: &str =
    "command -v crontab >/dev/null 2>&1 || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq cron 2>&1 || dnf install -y -q cronie 2>&1 || apk add --no-cache busybox-suid 2>&1; }; \
     systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || rc-service crond start 2>/dev/null; true";

pub async fn list_cron_jobs(service: &HostingService) -> Result<Vec<DaCronJob>, String> {
    let r = exec(
        service,
        &format!("crontab -u {} -l 2>/dev/null || true", CRON_USER),
    )
    .await?;
    Ok(parse_cron_lines(&r.stdout))
}

fn parse_cron_lines(text: &str) -> Vec<DaCronJob> {
    let mut out = Vec::new();
    let mut pending_id: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(id) = line.strip_prefix("# wolfhost-id=") {
            pending_id = Some(id.trim().to_string());
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            pending_id = None;
            continue;
        }
        let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if parts.len() == 6 {
            out.push(DaCronJob {
                id: pending_id.take().unwrap_or_default(),
                minute: parts[0].to_string(),
                hour: parts[1].to_string(),
                day_of_month: parts[2].to_string(),
                month: parts[3].to_string(),
                day_of_week: parts[4].to_string(),
                command: parts[5].to_string(),
            });
        }
        pending_id = None;
    }
    out
}

fn valid_cron_field(f: &str) -> bool {
    !f.is_empty()
        && f.len() <= 64
        && f.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '*' | '/' | ',' | '-'))
}

pub async fn create_cron_job(service: &HostingService, job: &DaCronJob) -> Result<String, String> {
    for f in [&job.minute, &job.hour, &job.day_of_month, &job.month, &job.day_of_week] {
        if !valid_cron_field(f) {
            return Err("Schedule fields may only contain * , - / digits and names".to_string());
        }
    }
    if job.command.contains('\n') || job.command.contains('\r') {
        return Err("Command must be a single line".to_string());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let entry = format!(
        "# wolfhost-id={id}\n{m} {h} {dom} {mon} {dow} {cmd}",
        id = id,
        m = job.minute,
        h = job.hour,
        dom = job.day_of_month,
        mon = job.month,
        dow = job.day_of_week,
        cmd = job.command
    );
    let cmd = format!(
        "{ensure}; ( crontab -u {u} -l 2>/dev/null; cat << 'WH_EOF_7f3a'\n{e}\nWH_EOF_7f3a\n) | crontab -u {u} - && echo CRONADDED",
        ensure = ENSURE_CRON,
        u = CRON_USER,
        e = entry
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("CRONADDED") {
        return Err(format!("Failed to install cron job: {} {}", r.stdout, r.stderr));
    }
    Ok(id)
}

pub async fn delete_cron_job(service: &HostingService, id: &str) -> Result<(), String> {
    // An empty id would make `.chars().all()` vacuously true and the
    // awk marker `# wolfhost-id=` (no suffix) match EVERY job — wiping
    // the whole crontab. Reject it explicitly.
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Invalid job id".to_string());
    }
    // Drop the id comment line and the single job line that follows it.
    let cmd = format!(
        "crontab -u {u} -l 2>/dev/null | awk 'del {{del=0; next}} index($0, \"# wolfhost-id={id}\") {{del=1; next}} {{print}}' | crontab -u {u} - && echo CRONREMOVED",
        u = CRON_USER,
        id = id
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("CRONREMOVED") {
        return Err(format!("Failed to remove cron job: {}", r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// SSH keys — the customer's container root account
// (/root/.ssh/authorized_keys). The webmaster user's home is the
// docroot, so keys must NOT live there (they would be web-servable).
// key_id/fingerprint are derived from the key blob via sha256sum,
// which exists in every container (coreutils/busybox).
// Response shape: DaSshKey { key_id, label, fingerprint }.
// ─────────────────────────────────────────────────────────────────

const AUTH_KEYS: &str = "/root/.ssh/authorized_keys";

pub async fn list_ssh_keys(service: &HostingService) -> Result<Vec<DaSshKey>, String> {
    let r = exec(service, &format!("cat {} 2>/dev/null || true", AUTH_KEYS)).await?;
    let mut out = Vec::new();
    for line in r.stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // authorized_keys line: <type> <base64-blob> [comment]
        let mut parts = line.split_whitespace();
        let ktype = parts.next().unwrap_or("");
        let blob = parts.next().unwrap_or("");
        let label: String = parts.collect::<Vec<_>>().join(" ");
        if blob.is_empty() {
            continue;
        }
        let fp = key_fingerprint(service, blob).await;
        out.push(DaSshKey {
            key_id: fp.chars().take(12).collect(),
            label: if label.is_empty() { ktype.to_string() } else { label },
            fingerprint: fp,
        });
    }
    Ok(out)
}

async fn key_fingerprint(service: &HostingService, blob: &str) -> String {
    let cmd = format!(
        "printf %s {} | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1",
        squote(blob)
    );
    match exec(service, &cmd).await {
        Ok(r) => r.stdout.trim().to_string(),
        Err(_) => String::new(),
    }
}

pub async fn add_ssh_key(
    service: &HostingService,
    label: &str,
    public_key: &str,
) -> Result<(), String> {
    // Caller (portal/ssh_keys.rs) already validated the key prefix.
    if public_key.contains('\n') {
        return Err("Public key must be a single line".to_string());
    }
    let safe_label: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
        .collect();
    // Key line stores the label as the trailing comment. Strip any
    // comment the pasted key carried so ours is authoritative.
    let mut parts = public_key.split_whitespace();
    let ktype = parts.next().unwrap_or("");
    let blob = parts.next().unwrap_or("");
    if blob.is_empty() {
        return Err("Malformed public key".to_string());
    }
    let line = if safe_label.is_empty() {
        format!("{} {}", ktype, blob)
    } else {
        format!("{} {} {}", ktype, blob, safe_label)
    };
    let cmd = format!(
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh && touch {ak} && chmod 600 {ak} && \
         grep -qF {blob} {ak} && echo DUPLICATE || {{ echo {line} >> {ak} && echo KEYADDED; }}",
        ak = AUTH_KEYS,
        blob = squote(blob),
        line = squote(&line)
    );
    let r = exec(service, &cmd).await?;
    if r.stdout.contains("DUPLICATE") {
        return Err("That key is already authorised".to_string());
    }
    if !r.stdout.contains("KEYADDED") {
        return Err(format!("Failed to add key: {}", r.stderr));
    }
    // Make sure an SSH daemon actually runs so the key is usable —
    // honour-the-option-end-to-end. Best effort with visible logging.
    let ensure = "command -v sshd >/dev/null 2>&1 || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq openssh-server 2>&1 || dnf install -y -q openssh-server 2>&1 || apk add --no-cache openssh 2>&1; }; \
                  systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || rc-service sshd start 2>/dev/null; true";
    exec(service, ensure).await.ok();
    Ok(())
}

pub async fn delete_ssh_key(service: &HostingService, key_id: &str) -> Result<(), String> {
    if key_id.is_empty() || !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid key id".to_string());
    }
    // Re-list to find the blob whose fingerprint starts with key_id,
    // then filter that line out of authorized_keys.
    let r = exec(service, &format!("cat {} 2>/dev/null || true", AUTH_KEYS)).await?;
    let mut kept: Vec<String> = Vec::new();
    let mut removed = false;
    for line in r.stdout.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            kept.push(line.to_string());
            continue;
        }
        let blob = t.split_whitespace().nth(1).unwrap_or("");
        let fp = key_fingerprint(service, blob).await;
        if fp.starts_with(key_id) {
            removed = true;
        } else {
            kept.push(line.to_string());
        }
    }
    if !removed {
        return Err("Key not found".to_string());
    }
    let content = kept.join("\n");
    let cmd = format!(
        "cat > {ak} << 'WH_EOF_7f3a'\n{c}\nWH_EOF_7f3a\nchmod 600 {ak} && echo KEYSSAVED",
        ak = AUTH_KEYS,
        c = content
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("KEYSSAVED") {
        return Err(format!("Failed to rewrite authorized_keys: {}", r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Log tails. Native containers log Apache to /var/log/apache2/* (the
// provisioner vhost: "ErrorLog ${APACHE_LOG_DIR}/error.log" /
// "CustomLog ${APACHE_LOG_DIR}/access.log" — container.rs:74-75) and
// mail to /var/log/mail.log with a journalctl fallback for images
// without rsyslog. The ssl kinds map to the same files — the native
// vhost logs both plain and TLS traffic there.
// ─────────────────────────────────────────────────────────────────

pub async fn tail_log(service: &HostingService, kind: &str, lines: u32) -> Result<String, String> {
    let lines = lines.min(5000);
    let cmd = match kind {
        "access" | "access_ssl" => format!("tail -n {} /var/log/apache2/access.log 2>/dev/null || true", lines),
        "error" | "error_ssl" => format!("tail -n {} /var/log/apache2/error.log 2>/dev/null || true", lines),
        "mail" => format!(
            "tail -n {n} /var/log/mail.log 2>/dev/null || journalctl -u postfix -n {n} --no-pager 2>/dev/null || true",
            n = lines
        ),
        _ => return Err("kind must be one of: access, error, access_ssl, error_ssl, mail".to_string()),
    };
    let r = exec(service, &cmd).await?;
    Ok(r.stdout)
}

// ─────────────────────────────────────────────────────────────────
// Email forwarders + catch-all — Postfix virtual alias map.
// setup_mail_server (provisioning/mail.rs) configures virtual
// MAILBOX maps only; the alias map is added here on first use:
//   virtual_alias_maps = hash:/etc/postfix/virtual
// Lines: `user@domain dest1,dest2` / catch-all: `@domain dest`.
// Source: mail.rs:38-81 (main.cf template — no virtual_alias_maps
// present) + Postfix virtual(5) table format.
// ─────────────────────────────────────────────────────────────────

const VIRTUAL_MAP: &str = "/etc/postfix/virtual";

async fn ensure_virtual_alias_map(service: &HostingService) -> Result<(), String> {
    require_mail_stack(service).await?;
    let cmd = format!(
        "postconf -e 'virtual_alias_maps = hash:{vm}' && touch {vm} && postmap {vm} && systemctl reload postfix 2>/dev/null; echo VAMOK",
        vm = VIRTUAL_MAP
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("VAMOK") {
        return Err(format!("Failed to enable the alias map: {}", r.stderr));
    }
    Ok(())
}

fn valid_mail_local_part(u: &str) -> bool {
    !u.is_empty()
        && u.len() < 64
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

pub fn valid_email(a: &str) -> bool {
    let mut parts = a.splitn(2, '@');
    match (parts.next(), parts.next()) {
        (Some(u), Some(d)) => valid_mail_local_part(u) && valid_domain(d),
        _ => false,
    }
}

async fn read_virtual_map(service: &HostingService) -> Result<Vec<(String, String)>, String> {
    let r = exec(service, &format!("cat {} 2>/dev/null || true", VIRTUAL_MAP)).await?;
    let mut out = Vec::new();
    for line in r.stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, dest)) = line.split_once(char::is_whitespace) {
            out.push((key.to_string(), dest.trim().to_string()));
        }
    }
    Ok(out)
}

async fn write_virtual_map(
    service: &HostingService,
    entries: &[(String, String)],
) -> Result<(), String> {
    let content = entries
        .iter()
        .map(|(k, v)| format!("{} {}", k, v))
        .collect::<Vec<_>>()
        .join("\n");
    // Written via base64 (never a heredoc) — entries include the
    // customer's domain, so this closes the delimiter-breakout class
    // even if a caller ever forgets to validate.
    write_file(service, VIRTUAL_MAP, &content).await?;
    let r = exec(
        service,
        &format!("postmap {vm} && systemctl reload postfix 2>/dev/null; echo VMAPSAVED", vm = VIRTUAL_MAP),
    )
    .await?;
    if !r.stdout.contains("VMAPSAVED") {
        return Err(format!("Failed to save alias map: {}", r.stderr));
    }
    Ok(())
}

pub async fn list_forwarders(
    service: &HostingService,
    domain: &str,
) -> Result<Vec<crate::wolfhost::provisioning::directadmin::DaEmailForwarder>, String> {
    use crate::wolfhost::provisioning::directadmin::DaEmailForwarder;
    require_mail_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    let suffix = format!("@{}", domain);
    Ok(read_virtual_map(service)
        .await?
        .into_iter()
        .filter(|(k, _)| k.ends_with(&suffix) && !k.starts_with('@'))
        .map(|(k, v)| DaEmailForwarder {
            user: k.trim_end_matches(&suffix).to_string(),
            destinations: v.split(',').map(|d| d.trim().to_string()).collect(),
        })
        .collect())
}

pub async fn create_forwarder(
    service: &HostingService,
    domain: &str,
    user: &str,
    destinations: &[String],
) -> Result<(), String> {
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    if !valid_mail_local_part(user) {
        return Err("Forwarder name may only contain letters, digits, . _ - +".to_string());
    }
    for d in destinations {
        if !valid_email(d) {
            return Err(format!("`{}` is not a valid destination address", d));
        }
    }
    ensure_virtual_alias_map(service).await?;
    let key = format!("{}@{}", user, domain);
    let mut entries = read_virtual_map(service).await?;
    entries.retain(|(k, _)| k != &key);
    entries.push((key, destinations.join(",")));
    write_virtual_map(service, &entries).await
}

pub async fn delete_forwarder(
    service: &HostingService,
    domain: &str,
    user: &str,
) -> Result<(), String> {
    require_mail_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    let key = format!("{}@{}", user, domain);
    let mut entries = read_virtual_map(service).await?;
    let before = entries.len();
    entries.retain(|(k, _)| k != &key);
    if entries.len() == before {
        return Err("Forwarder not found".to_string());
    }
    write_virtual_map(service, &entries).await
}

/// Catch-all. Modes match DaCatchAll: `address`, `fail`, `blackhole`,
/// `ignore`. With no `@domain` entry, Postfix already 550-rejects
/// unknown virtual recipients (virtual_mailbox_maps lookup failure),
/// so `fail`/`ignore` simply remove the entry. `blackhole` routes to
/// a local `devnull` alias piped to /dev/null.
pub async fn get_catch_all(
    service: &HostingService,
    domain: &str,
) -> Result<crate::wolfhost::provisioning::directadmin::DaCatchAll, String> {
    use crate::wolfhost::provisioning::directadmin::DaCatchAll;
    require_mail_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    let key = format!("@{}", domain);
    for (k, v) in read_virtual_map(service).await? {
        if k == key {
            if v == "devnull" {
                return Ok(DaCatchAll { mode: "blackhole".to_string(), destination: String::new() });
            }
            return Ok(DaCatchAll { mode: "address".to_string(), destination: v });
        }
    }
    Ok(DaCatchAll { mode: "fail".to_string(), destination: String::new() })
}

pub async fn set_catch_all(
    service: &HostingService,
    domain: &str,
    mode: &str,
    destination: &str,
) -> Result<(), String> {
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    ensure_virtual_alias_map(service).await?;
    let key = format!("@{}", domain);
    let mut entries = read_virtual_map(service).await?;
    entries.retain(|(k, _)| k != &key);
    match mode {
        "address" => {
            if !valid_email(destination) {
                return Err("Destination must be a valid email address".to_string());
            }
            entries.push((key, destination.to_string()));
        }
        "blackhole" => {
            // Local alias devnull → /dev/null; delivery via the alias
            // map requires the local domain (mydestination includes
            // localhost — mail.rs:56).
            let r = exec(
                service,
                "grep -q '^devnull:' /etc/aliases 2>/dev/null || echo 'devnull: /dev/null' >> /etc/aliases; newaliases && echo ALIASOK",
            )
            .await?;
            if !r.stdout.contains("ALIASOK") {
                return Err(format!("Failed to configure blackhole alias: {}", r.stderr));
            }
            entries.push((key, "devnull".to_string()));
        }
        "fail" | "ignore" => {}
        _ => return Err("mode must be address, fail, blackhole or ignore".to_string()),
    }
    write_virtual_map(service, &entries).await
}

// ─────────────────────────────────────────────────────────────────
// Autoresponders + vacation — Dovecot Pigeonhole sieve.
// Config verified against doc.dovecot.org (Sieve configuration):
//   protocol lmtp { mail_plugins = $mail_plugins sieve }
//   plugin { sieve = file:~/sieve;active=~/.dovecot.sieve }
// Global before-script (spam delete) pre-compiled with sievec per
// the same docs. Mailbox home dirs are /var/mail/vhosts/<d>/<u>
// (mail.rs dovecot userdb `home=/var/mail/vhosts/%d/%n`).
// ─────────────────────────────────────────────────────────────────

const SPAM_DISCARD_SIEVE: &str = "/etc/dovecot/wolfhost-spam-discard.sieve";
const DOVECOT_CONF: &str = "/etc/dovecot/dovecot.conf";

/// A native autoresponder / vacation record persisted by the portal
/// layer in the plugin's JSON store (collections `autoresponders` /
/// `vacations`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeResponder {
    pub customer_id: String,
    pub service_id: String,
    pub domain: String,
    pub user: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub cc: String,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub end: String,
    /// "autoresponder" or "vacation"
    pub kind: String,
}

pub async fn ensure_sieve(service: &HostingService) -> Result<(), String> {
    require_mail_stack(service).await?;
    // Install pigeonhole (package verified: dovecot-sieve in
    // Debian/Ubuntu) and make sure the neutral no-op before-script
    // exists so the plugin block below always points at something.
    let install = format!(
        "command -v sievec >/dev/null 2>&1 || {{ export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq dovecot-sieve 2>&1; }}; \
         command -v sievec >/dev/null 2>&1 || exit 41; \
         [ -f {sd} ] || printf '# wolfhost spam action: deliver\\n' > {sd}; \
         sievec {sd} 2>&1 && echo SIEVEREADY",
        sd = SPAM_DISCARD_SIEVE
    );
    let r = exec(service, &install).await?;
    if r.exit_code == 41 {
        return Err("Could not install the Dovecot Sieve plugin (dovecot-sieve)".to_string());
    }
    if !r.stdout.contains("SIEVEREADY") {
        return Err(format!("Sieve setup failed: {} {}", r.stdout, r.stderr));
    }
    // Enable the plugin for LMTP delivery. Written as a marker block
    // appended to dovecot.conf — later sections override earlier ones
    // in dovecot config, and setup_mail_server rewrites the file
    // wholesale, so this block is re-added here if it went missing.
    let block = format!(
        "protocol lmtp {{\n  mail_plugins = $mail_plugins sieve\n}}\nplugin {{\n  sieve = file:~/sieve;active=~/.dovecot.sieve\n  sieve_before = file:{sd}\n}}",
        sd = SPAM_DISCARD_SIEVE
    );
    let existing = get_marker_block(service, DOVECOT_CONF, "wolfhost-sieve").await?;
    if existing.is_empty() {
        set_marker_block(service, DOVECOT_CONF, "wolfhost-sieve", &block).await?;
        let r = exec(service, "systemctl restart dovecot 2>/dev/null && echo DOVEOK").await?;
        if !r.stdout.contains("DOVEOK") {
            return Err(format!("Dovecot restart failed: {}", r.stderr));
        }
    }
    Ok(())
}

fn sieve_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build and install the sieve script for one mailbox from its
/// stored responder records. Compile-checked with sievec so syntax
/// errors surface immediately instead of silently breaking delivery.
pub async fn apply_mailbox_sieve(
    service: &HostingService,
    domain: &str,
    user: &str,
    responders: &[NativeResponder],
) -> Result<(), String> {
    ensure_sieve(service).await?;
    if !valid_mail_local_part(user) || !valid_domain(domain) {
        return Err("Invalid mailbox".to_string());
    }
    // `subject` goes inside a quoted Sieve string; a newline would
    // break out of the quotes and inject Sieve statements. sieve_quote
    // escapes `\` and `"` but not newlines, so reject them here. (The
    // body is written into a `text:` block terminated only by `\n.\n`
    // and is dot-stuffed, so it can't break out.)
    for r in responders {
        if r.subject.contains('\n') || r.subject.contains('\r') {
            return Err("Auto-reply subject must be a single line".to_string());
        }
    }
    let mut requires: Vec<&str> = Vec::new();
    let mut rules: Vec<String> = Vec::new();
    for r in responders {
        let subject = if r.subject.is_empty() {
            "Automatic reply".to_string()
        } else {
            r.subject.clone()
        };
        // Multi-line body via RFC 5228 `text:` with dot-stuffing.
        let body_text = r
            .body
            .lines()
            .map(|l| if l.starts_with('.') { format!(".{}", l) } else { l.to_string() })
            .collect::<Vec<_>>()
            .join("\n");
        if !requires.contains(&"\"vacation\"") {
            requires.push("\"vacation\"");
        }
        let vacation = format!(
            "vacation :days 1 :subject \"{}\" text:\n{}\n.\n;",
            sieve_quote(&subject),
            body_text
        );
        if r.kind == "vacation" && !r.start.is_empty() && !r.end.is_empty() {
            for req in ["\"date\"", "\"relational\""] {
                if !requires.contains(&req) {
                    requires.push(req);
                }
            }
            rules.push(format!(
                "if allof (currentdate :value \"ge\" \"date\" \"{}\", currentdate :value \"le\" \"date\" \"{}\") {{\n{}\n}}",
                sieve_quote(&r.start),
                sieve_quote(&r.end),
                vacation
            ));
        } else {
            rules.push(vacation);
        }
        // Note: DA's autoresponder `cc` sends a copy of the
        // AUTO-REPLY to another address. Sieve's vacation action has
        // no such option, so native creation rejects cc up front
        // (portal/autoresponders.rs) rather than silently doing
        // something different.
    }
    let home = format!("/var/mail/vhosts/{}/{}", domain, user);
    let sieve_file = format!("{}/.dovecot.sieve", home);
    if rules.is_empty() {
        let cmd = format!(
            "rm -f {sf} {sf}.svbin {h}/.dovecot.svbin 2>/dev/null; echo SIEVEGONE",
            sf = squote(&sieve_file),
            h = squote(&home)
        );
        exec(service, &cmd).await?;
        return Ok(());
    }
    let script = format!("require [{}];\n{}\n", requires.join(", "), rules.join("\n"));
    // Body is fully customer-controlled — write via base64, never a
    // heredoc (see write_file).
    exec(service, &format!("mkdir -p {}", squote(&home))).await?;
    write_file(service, &sieve_file, &script).await?;
    let cmd = format!(
        "sievec {sf} 2>&1 && chown -R vmail:vmail {h} && echo SIEVEOK",
        h = squote(&home),
        sf = squote(&sieve_file)
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("SIEVEOK") {
        // Compile failure would leave a broken script in place and
        // break delivery for this mailbox — remove it.
        exec(service, &format!("rm -f {} {}.svbin", squote(&sieve_file), squote(&sieve_file))).await.ok();
        return Err(format!("Sieve script rejected: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Spam filtering — SpamAssassin as a Postfix content_filter.
// master.cf shape verified against the Apache SpamAssassin wiki
// (IntegratedSpamdInPostfix): smtp/inet gets
// `-o content_filter=spamassassin`; a `spamassassin` pipe service
// re-injects through sendmail. Edits use `postconf -M` / `-P`
// (postconf(1), Postfix ≥2.11). Threshold lives in
// /etc/spamassassin/local.cf (`required_score`); the `subject`
// action adds `rewrite_header Subject`; `delete` discards flagged
// mail via the global sieve_before script.
// ─────────────────────────────────────────────────────────────────

pub async fn get_spam_settings(
    service: &HostingService,
) -> Result<crate::wolfhost::provisioning::directadmin::DaSpamSettings, String> {
    use crate::wolfhost::provisioning::directadmin::DaSpamSettings;
    require_mail_stack(service).await?;
    let r = exec(
        service,
        "postconf -P smtp/inet/content_filter 2>/dev/null | grep -q spamassassin && echo SPAM_ON; \
         grep -E '^required_score' /etc/spamassassin/local.cf 2>/dev/null | tail -1; \
         grep -qE '^rewrite_header Subject' /etc/spamassassin/local.cf 2>/dev/null && echo SUBJ_ON; \
         grep -q 'discard' /etc/dovecot/wolfhost-spam-discard.sieve 2>/dev/null && echo DELETE_ON",
    )
    .await?;
    let enabled = r.stdout.contains("SPAM_ON");
    let mut score = 5.0f32;
    for line in r.stdout.lines() {
        if let Some(v) = line.trim().strip_prefix("required_score")
            && let Ok(s) = v.trim().parse::<f32>()
        {
            score = s;
        }
    }
    let action = if r.stdout.contains("DELETE_ON") {
        "delete"
    } else if r.stdout.contains("SUBJ_ON") {
        "subject"
    } else {
        "tag"
    };
    Ok(DaSpamSettings { enabled, score_threshold: score, action: action.to_string() })
}

pub async fn set_spam_settings(
    service: &HostingService,
    settings: &crate::wolfhost::provisioning::directadmin::DaSpamSettings,
) -> Result<(), String> {
    require_mail_stack(service).await?;
    if !settings.enabled {
        let cmd = "postconf -PX smtp/inet/content_filter 2>/dev/null; systemctl reload postfix 2>/dev/null; echo SPAMOFF";
        let r = exec(service, cmd).await?;
        if !r.stdout.contains("SPAMOFF") {
            return Err(format!("Failed to disable the spam filter: {}", r.stderr));
        }
        return Ok(());
    }
    if !(0.1..=100.0).contains(&settings.score_threshold) {
        return Err("Score threshold must be between 0.1 and 100".to_string());
    }
    // 1. Install + enable spamd.
    let install = "command -v spamc >/dev/null 2>&1 || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq spamassassin spamc 2>&1; }; \
                   command -v spamc >/dev/null 2>&1 || exit 42; \
                   systemctl enable --now spamd 2>/dev/null || systemctl enable --now spamassassin 2>/dev/null; echo SAINSTALLED";
    let r = exec(service, install).await?;
    if r.exit_code == 42 {
        return Err("Could not install SpamAssassin".to_string());
    }
    // 2. local.cf: threshold + optional subject rewrite.
    let mut local_cf = format!("required_score {:.1}\nreport_safe 0", settings.score_threshold);
    if settings.action == "subject" {
        local_cf.push_str("\nrewrite_header Subject *****SPAM*****");
    }
    set_marker_block(service, "/etc/spamassassin/local.cf", "wolfhost-spam", &local_cf).await?;
    // 3. Postfix content_filter + pipe service (SpamAssassin wiki
    //    shape; re-injection via sendmail, run as nobody).
    let master = "postconf -M 'spamassassin/unix=spamassassin unix - n n - - pipe flags=Rq user=nobody argv=/usr/bin/spamc -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}' && \
                  postconf -P 'smtp/inet/content_filter=spamassassin' && \
                  systemctl restart spamd 2>/dev/null || systemctl restart spamassassin 2>/dev/null; \
                  systemctl reload postfix 2>/dev/null; echo SPAMWIRED";
    let r = exec(service, master).await?;
    if !r.stdout.contains("SPAMWIRED") {
        return Err(format!("Failed to wire SpamAssassin into Postfix: {} {}", r.stdout, r.stderr));
    }
    // 4. Delete action → global sieve discard of flagged mail
    //    (X-Spam-Flag: YES is set once the score passes
    //    required_score). Any other action → neutral script.
    ensure_sieve(service).await?;
    let discard = if settings.action == "delete" {
        "if header :contains \"X-Spam-Flag\" \"YES\" {\n  discard;\n  stop;\n}"
    } else {
        "# wolfhost spam action: deliver"
    };
    let cmd = format!(
        "cat > {sd} << 'WH_EOF_7f3a'\n{c}\nWH_EOF_7f3a\nsievec {sd} 2>&1 && echo DISCARDSET",
        sd = SPAM_DISCARD_SIEVE,
        c = discard
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("DISCARDSET") {
        return Err(format!("Failed to set spam action: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Email password change — upsert into the Dovecot passwd-file
// exactly the way accounts are created. Source: mail.rs:224-267
// add_email_account() — /etc/dovecot/users line format
// `addr:hash:::::/var/mail/vhosts/<domain>/<user>` with SHA512-CRYPT
// via doveadm (openssl passwd -6 fallback).
// ─────────────────────────────────────────────────────────────────

pub async fn change_email_password(
    service: &HostingService,
    address: &str,
    new_password: &str,
) -> Result<(), String> {
    require_mail_stack(service).await?;
    if !valid_email(address) {
        return Err("Invalid email address".to_string());
    }
    let (user, domain) = address.split_once('@').unwrap();
    // Match the mailbox by EXACT first field (awk -F:), never a regex
    // — email local parts contain `.` / `+`, which as a grep pattern
    // would match (and delete) unrelated mailboxes.
    // `addr_q` (single-quoted) for the awk -v assignments; `addr`
    // raw for the new line written via printf — valid_email already
    // restricts it to alnum . _ - + @, so it carries no shell
    // metacharacters inside the double-quoted printf argument.
    let cmd = format!(
        "awk -F: -v a={addr_q} '$1==a{{f=1}} END{{exit !f}}' /etc/dovecot/users || exit 43; \
         HASH=$(doveadm pw -s SHA512-CRYPT -p {pw} 2>/dev/null || openssl passwd -6 {pw}); \
         awk -F: -v a={addr_q} '$1!=a' /etc/dovecot/users > /tmp/wh_du_tmp 2>/dev/null; \
         printf '%s\\n' \"{addr}:$HASH:::::/var/mail/vhosts/{domain}/{user}\" >> /tmp/wh_du_tmp; \
         mv /tmp/wh_du_tmp /etc/dovecot/users; \
         chown vmail:dovecot /etc/dovecot/users; chmod 640 /etc/dovecot/users; echo PWCHANGED",
        addr_q = squote(address),
        addr = address,
        pw = squote(new_password),
        domain = domain,
        user = user
    );
    let r = exec(service, &cmd).await?;
    if r.exit_code == 43 {
        return Err("That mailbox does not exist on the mail server".to_string());
    }
    if !r.stdout.contains("PWCHANGED") {
        return Err(format!("Password change failed: {}", r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// FTP system users — native FTP is vsftpd with local users
// (container.rs vsftpd_conf: local_enable=YES, chroot_local_user).
// The store-only records the portal used to keep never created the
// user, so native FTP accounts silently didn't work; these calls
// make create/delete/password real.
// ─────────────────────────────────────────────────────────────────

pub fn valid_system_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && u.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
        && u.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

/// Translate the host-side home_dir the service record stores
/// (`/var/lib/lxc/<cn>/rootfs/var/www/html` — api/servers.rs deploy)
/// into the path inside the container.
pub fn container_home_dir(service: &HostingService, home_dir: &str) -> String {
    let prefix = format!("/var/lib/lxc/{}/rootfs", service.container_name);
    match home_dir.strip_prefix(&prefix) {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ if home_dir.is_empty() => DOCROOT.to_string(),
        _ => home_dir.to_string(),
    }
}

pub async fn create_ftp_user(
    service: &HostingService,
    username: &str,
    password: &str,
    home_dir: &str,
) -> Result<(), String> {
    if !valid_system_user(username) {
        return Err("FTP username must be lowercase letters, digits, _ or -".to_string());
    }
    let home = container_home_dir(service, home_dir);
    if !home.starts_with('/') || home.contains("..") {
        return Err("Invalid home directory".to_string());
    }
    let cmd = format!(
        "id {u} >/dev/null 2>&1 && exit 44; \
         mkdir -p {h} && useradd -d {h} -s /usr/sbin/nologin -G www-data {u} 2>&1 && \
         printf '%s:%s' {u} {p} | chpasswd && echo FTPCREATED",
        u = squote(username),
        h = squote(&home),
        p = squote(password)
    );
    let r = exec(service, &cmd).await?;
    if r.exit_code == 44 {
        return Err(format!("System user `{}` already exists", username));
    }
    if !r.stdout.contains("FTPCREATED") {
        return Err(format!("Failed to create FTP user: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

pub async fn delete_ftp_user(service: &HostingService, username: &str) -> Result<(), String> {
    if !valid_system_user(username) {
        return Err("Invalid FTP username".to_string());
    }
    if username == "webmaster" || username == "root" {
        return Err("The built-in account cannot be deleted".to_string());
    }
    let cmd = format!("userdel {u} 2>&1; echo FTPGONE", u = squote(username));
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("FTPGONE") {
        return Err(format!("Failed to remove FTP user: {}", r.stderr));
    }
    Ok(())
}

pub async fn change_ftp_password(
    service: &HostingService,
    username: &str,
    new_password: &str,
) -> Result<(), String> {
    if !valid_system_user(username) {
        return Err("Invalid FTP username".to_string());
    }
    let cmd = format!(
        "id {u} >/dev/null 2>&1 || exit 45; printf '%s:%s' {u} {p} | chpasswd && echo FTPPWOK",
        u = squote(username),
        p = squote(new_password)
    );
    let r = exec(service, &cmd).await?;
    if r.exit_code == 45 {
        return Err(format!("FTP user `{}` does not exist on the server", username));
    }
    if !r.stdout.contains("FTPPWOK") {
        return Err(format!("Password change failed: {}", r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Usage — disk from `du` inside the container, bandwidth from the
// container's network counters (WolfStack /api/containers/lxc/stats,
// same endpoint the dashboard's container_stats proxy uses).
// ─────────────────────────────────────────────────────────────────

pub async fn disk_usage_mb(service: &HostingService) -> Result<u64, String> {
    let r = exec(
        service,
        "du -sm /var/www/html /var/mail/vhosts /var/lib/mysql 2>/dev/null | awk '{s+=$1} END {print s+0}'",
    )
    .await?;
    r.stdout.trim().parse::<u64>().map_err(|_| "du failed".to_string())
}

/// Per-mailbox maildir sizes for a domain.
/// Response shape: DaEmailUsage { user, bytes, quota_bytes }.
pub async fn email_usage(
    service: &HostingService,
    domain: &str,
) -> Result<Vec<crate::wolfhost::provisioning::directadmin::DaEmailUsage>, String> {
    use crate::wolfhost::provisioning::directadmin::DaEmailUsage;
    require_mail_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    let cmd = format!(
        "for d in /var/mail/vhosts/{}/*/; do [ -d \"$d\" ] && du -sb \"$d\" 2>/dev/null; done",
        domain
    );
    let r = exec(service, &cmd).await?;
    let mut out = Vec::new();
    for line in r.stdout.lines() {
        let mut parts = line.split_whitespace();
        let bytes: u64 = parts.next().and_then(|b| b.parse().ok()).unwrap_or(0);
        if let Some(path) = parts.next() {
            let user = path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
            if !user.is_empty() {
                out.push(DaEmailUsage { user, bytes, quota_bytes: 0 });
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────
// Database users — same in-container mysql invocation style as the
// database create/drop path (portal/databases.rs create_cmd /
// drop_cmd), including its sanitisation of names and passwords.
// Response shape: DaDbUser { user, databases }.
// ─────────────────────────────────────────────────────────────────

pub fn sanitize_db_ident(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect()
}

pub fn escape_db_password(s: &str) -> String {
    // Source: portal/databases.rs:208 — same escaping for the value
    // interpolated inside the double-quoted mysql -e string.
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
}

pub async fn create_db_user(
    service: &HostingService,
    db_name: &str,
    db_user: &str,
    password: &str,
) -> Result<(), String> {
    let name = sanitize_db_ident(db_name);
    let user = sanitize_db_ident(db_user);
    if name.is_empty() || user.is_empty() {
        return Err("Database and username may only contain letters, digits and _".to_string());
    }
    let pass = escape_db_password(password);
    let cmd = format!(
        "mysql -e \"CREATE USER IF NOT EXISTS '{u}'@'localhost' IDENTIFIED BY '{p}'; GRANT ALL PRIVILEGES ON \\`{n}\\`.* TO '{u}'@'localhost'; FLUSH PRIVILEGES;\" 2>&1 && echo DBUSEROK",
        u = user,
        p = pass,
        n = name
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("DBUSEROK") {
        return Err(format!("MySQL: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

pub async fn change_db_user_password(
    service: &HostingService,
    db_user: &str,
    new_password: &str,
) -> Result<(), String> {
    let user = sanitize_db_ident(db_user);
    if user.is_empty() {
        return Err("Invalid database username".to_string());
    }
    let pass = escape_db_password(new_password);
    let cmd = format!(
        "mysql -e \"ALTER USER '{u}'@'localhost' IDENTIFIED BY '{p}'; FLUSH PRIVILEGES;\" 2>&1 && echo DBPWOK",
        u = user,
        p = pass
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("DBPWOK") {
        return Err(format!("MySQL: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

pub async fn delete_db_user(service: &HostingService, db_user: &str) -> Result<(), String> {
    let user = sanitize_db_ident(db_user);
    if user.is_empty() {
        return Err("Invalid database username".to_string());
    }
    let cmd = format!(
        "mysql -e \"DROP USER IF EXISTS '{u}'@'localhost'; FLUSH PRIVILEGES;\" 2>&1 && echo DBUSERGONE",
        u = user
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("DBUSERGONE") {
        return Err(format!("MySQL: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Subdomains — vhost `wolfhost-sub-<label>.<domain>.conf` with
// docroot `<DOCROOT>/<label>` (visible in the file manager), plus a
// PowerDNS A record when the platform serves the zone. Deleting
// removes vhost + DNS but keeps the files (same data-preservation
// stance as deprovision_service — provisioning/mod.rs:63).
// ─────────────────────────────────────────────────────────────────

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !l.starts_with('-')
}

pub async fn list_subdomains(service: &HostingService, domain: &str) -> Result<Vec<String>, String> {
    require_web_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    let cmd = format!(
        "ls /etc/apache2/sites-available/ 2>/dev/null | grep '^wolfhost-sub-.*\\.{}\\.conf$' || true",
        domain.replace('.', "\\.")
    );
    let r = exec(service, &cmd).await?;
    let suffix = format!(".{}.conf", domain);
    Ok(r.stdout
        .lines()
        .filter_map(|f| {
            f.trim()
                .strip_prefix("wolfhost-sub-")
                .and_then(|rest| rest.strip_suffix(&suffix))
                .map(|s| s.to_string())
        })
        .collect())
}

pub async fn create_subdomain(
    service: &HostingService,
    domain: &str,
    label: &str,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_domain(domain) || !valid_label(label) {
        return Err("Subdomain must be a single DNS label (letters, digits, -)".to_string());
    }
    let fqdn = format!("{}.{}", label, domain);
    let docroot = format!("{}/{}", DOCROOT, label);
    let vhost = format!(
        "<VirtualHost *:80>\n    ServerName {fqdn}\n    DocumentRoot {dr}\n    <Directory {dr}>\n        Options -Indexes +FollowSymLinks\n        AllowOverride All\n        Require all granted\n    </Directory>\n    ErrorLog ${{APACHE_LOG_DIR}}/error.log\n    CustomLog ${{APACHE_LOG_DIR}}/access.log combined\n</VirtualHost>",
        fqdn = fqdn,
        dr = docroot
    );
    let cmd = format!(
        "mkdir -p {dr} && chown webmaster:www-data {dr} 2>/dev/null; \
         cat > /etc/apache2/sites-available/wolfhost-sub-{fqdn}.conf << 'WH_EOF_7f3a'\n{v}\nWH_EOF_7f3a\na2ensite wolfhost-sub-{fqdn} >/dev/null 2>&1 && {reload}; echo SUBOK",
        dr = squote(&docroot),
        fqdn = fqdn,
        v = vhost,
        reload = APACHE_RELOAD
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("SUBOK") {
        return Err(format!("Failed to create subdomain: {} {}", r.stdout, r.stderr));
    }
    if !service.host_ip.is_empty() {
        let domain = domain.to_string();
        let name = format!("{}.{}.", label, domain);
        let host_ip = service.host_ip.clone();
        tokio::task::spawn_blocking(move || {
            if crate::wolfhost::provisioning::dns::is_pdns_running() {
                crate::wolfhost::provisioning::dns::set_record(&domain, &name, "A", &host_ip, 3600).ok();
            }
        })
        .await
        .ok();
    }
    Ok(())
}

pub async fn delete_subdomain(
    service: &HostingService,
    domain: &str,
    label: &str,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_domain(domain) || !valid_label(label) {
        return Err("Invalid subdomain".to_string());
    }
    let fqdn = format!("{}.{}", label, domain);
    let cmd = format!(
        "a2dissite wolfhost-sub-{fqdn} >/dev/null 2>&1; rm -f /etc/apache2/sites-available/wolfhost-sub-{fqdn}.conf; {reload}; echo SUBGONE",
        fqdn = fqdn,
        reload = APACHE_RELOAD
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("SUBGONE") {
        return Err(format!("Failed to remove subdomain: {}", r.stderr));
    }
    {
        let domain = domain.to_string();
        let name = format!("{}.{}.", label, domain);
        tokio::task::spawn_blocking(move || {
            if crate::wolfhost::provisioning::dns::is_pdns_running() {
                crate::wolfhost::provisioning::dns::delete_record(&domain, &name, "A").ok();
            }
        })
        .await
        .ok();
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Custom SSL upload — PEM material is validated in the handler
// (openssl crate), stored under /etc/wolfhost-ssl/ inside the
// container, and served by a dedicated :443 vhost. mod_ssl is
// enabled by the provisioner (`a2enmod rewrite ssl headers expires`).
// ─────────────────────────────────────────────────────────────────

const SSL_DIR: &str = "/etc/wolfhost-ssl";

pub async fn install_custom_cert(
    service: &HostingService,
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
    chain_pem: &str,
) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    let chain_directive = if chain_pem.trim().is_empty() {
        String::new()
    } else {
        format!("\n    SSLCertificateChainFile {}/{}.chain.pem", SSL_DIR, domain)
    };
    let vhost = format!(
        "<VirtualHost *:443>\n    ServerName {d}\n    ServerAlias www.{d}\n    DocumentRoot {dr}\n    SSLEngine on\n    SSLCertificateFile {sd}/{d}.crt.pem\n    SSLCertificateKeyFile {sd}/{d}.key.pem{chain}\n    <Directory {dr}>\n        Options -Indexes +FollowSymLinks\n        AllowOverride All\n        Require all granted\n    </Directory>\n</VirtualHost>",
        d = domain,
        dr = DOCROOT,
        sd = SSL_DIR,
        chain = chain_directive
    );
    // PEM text is customer-supplied and only loosely validated by
    // the handler's openssl parse (which tolerates trailing junk
    // lines) — write every PEM file via base64, never a heredoc.
    exec(service, &format!("mkdir -p {sd} && chmod 700 {sd}", sd = SSL_DIR)).await?;
    write_file(service, &format!("{}/{}.crt.pem", SSL_DIR, domain), cert_pem.trim()).await?;
    write_file(service, &format!("{}/{}.key.pem", SSL_DIR, domain), key_pem.trim()).await?;
    exec(service, &format!("chmod 600 {sd}/{d}.key.pem", sd = SSL_DIR, d = domain)).await?;
    if !chain_pem.trim().is_empty() {
        write_file(service, &format!("{}/{}.chain.pem", SSL_DIR, domain), chain_pem.trim()).await?;
    }
    // The vhost is built only from the validated domain + constants,
    // so a heredoc here is safe.
    let files = format!(
        "cat > /etc/apache2/sites-available/wolfhost-ssl-{d}.conf << 'WH_EOF_7f3a'\n{v}\nWH_EOF_7f3a\n\
         a2enmod ssl >/dev/null 2>&1; a2ensite wolfhost-ssl-{d} >/dev/null 2>&1 && \
         apache2ctl configtest 2>&1 && {reload} && echo SSLOK",
        d = domain,
        v = vhost,
        reload = APACHE_RELOAD
    );
    let r = exec(service, &files).await?;
    if !r.stdout.contains("SSLOK") {
        // Roll the site back out so a bad cert never wedges Apache.
        let undo = format!(
            "a2dissite wolfhost-ssl-{d} >/dev/null 2>&1; rm -f /etc/apache2/sites-available/wolfhost-ssl-{d}.conf; {reload}",
            d = domain,
            reload = APACHE_RELOAD
        );
        exec(service, &undo).await.ok();
        return Err(format!("Apache rejected the certificate config: {} {}", r.stdout, r.stderr));
    }
    Ok(())
}

pub async fn remove_custom_cert(service: &HostingService, domain: &str) -> Result<(), String> {
    require_web_stack(service).await?;
    if !valid_domain(domain) {
        return Err("Invalid domain".to_string());
    }
    // Covers both cert flavours a native service can carry: the
    // custom-upload vhost from install_custom_cert, and a certbot
    // (Let's Encrypt) cert from the create() flow. For certbot the
    // vhosts referencing the cert must be disabled BEFORE
    // `certbot delete`, or Apache fails its reload on missing files.
    let cmd = format!(
        "a2dissite wolfhost-ssl-{d} >/dev/null 2>&1; \
         rm -f /etc/apache2/sites-available/wolfhost-ssl-{d}.conf {sd}/{d}.crt.pem {sd}/{d}.key.pem {sd}/{d}.chain.pem; \
         if [ -d /etc/letsencrypt/live/{d} ]; then \
           grep -l 'letsencrypt/live/{d}/' /etc/apache2/sites-enabled/*.conf 2>/dev/null | while read f; do a2dissite $(basename \"$f\" .conf) >/dev/null 2>&1; done; \
           certbot delete --cert-name {d} --non-interactive 2>&1; \
         fi; \
         {reload}; echo SSLGONE",
        d = domain,
        sd = SSL_DIR,
        reload = APACHE_RELOAD
    );
    let r = exec(service, &cmd).await?;
    if !r.stdout.contains("SSLGONE") {
        return Err(format!("Failed to remove certificate: {}", r.stderr));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_parse_roundtrip() {
        let text = "# wolfhost-id=abc-123\n*/5 * * * * php /var/www/html/cron.php\n# a stray comment\n0 3 * * 1 /usr/bin/backup --weekly\n";
        let jobs = parse_cron_lines(text);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].id, "abc-123");
        assert_eq!(jobs[0].minute, "*/5");
        assert_eq!(jobs[0].command, "php /var/www/html/cron.php");
        // The second job has no id comment — parsed, id empty.
        assert_eq!(jobs[1].id, "");
        assert_eq!(jobs[1].day_of_week, "1");
        assert_eq!(jobs[1].command, "/usr/bin/backup --weekly");
    }

    #[test]
    fn cron_field_validation() {
        assert!(valid_cron_field("*/5"));
        assert!(valid_cron_field("1,15-20"));
        assert!(!valid_cron_field("5; rm -rf /"));
        assert!(!valid_cron_field(""));
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(squote("plain"), "'plain'");
        assert_eq!(squote("it's"), "'it'\\''s'");
    }

    #[test]
    fn url_path_validation() {
        assert!(valid_url_path("/admin"));
        assert!(valid_url_path("/a/b-c_d"));
        assert!(!valid_url_path("admin"));
        assert!(!valid_url_path("/a/../etc"));
        assert!(!valid_url_path("/a b"));
        assert!(!valid_url_path("/a\"b"));
    }

    #[test]
    fn domain_validation() {
        assert!(valid_domain("example.com"));
        assert!(valid_domain("sub-1.example.co.uk"));
        assert!(!valid_domain("-bad.com"));
        assert!(!valid_domain("bad domain.com"));
        assert!(!valid_domain(""));
        assert!(!valid_domain("evil.com'; rm -rf /"));
    }

    #[test]
    fn email_validation() {
        assert!(valid_email("user@example.com"));
        assert!(valid_email("first.last+tag@example.com"));
        assert!(!valid_email("no-at-sign"));
        assert!(!valid_email("bad user@example.com"));
        assert!(!valid_email("user@bad domain"));
    }

    #[test]
    fn protected_token_stability() {
        assert_eq!(protected_token("/admin"), "admin");
        assert_eq!(protected_token("/a/b"), "a_b");
        // Docroot itself must still yield a usable file name.
        assert_eq!(protected_token("/"), "root");
    }

    #[test]
    fn sieve_string_escaping() {
        assert_eq!(sieve_quote("plain"), "plain");
        assert_eq!(sieve_quote("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(sieve_quote("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn home_dir_translation() {
        let mut svc = HostingService {
            id: "s1".into(), customer_id: "c1".into(), plan_id: "p1".into(),
            domain: "example.com".into(),
            status: crate::wolfhost::models::service::ServiceStatus::Active,
            billing_cycle: crate::wolfhost::models::service::BillingCycle::Monthly,
            next_billing: String::new(), server_node: String::new(),
            home_dir: String::new(), container_name: "wh-user-abc".into(),
            container_ip: String::new(), host_ip: String::new(),
            host_hostname: String::new(), ftp_port: 0,
            usage: Default::default(),
            backend: crate::wolfhost::models::service::ServiceBackend::Native,
            da_instance_id: String::new(), da_username: String::new(),
            created_at: String::new(), expires_at: String::new(),
        };
        // Host-side path (api/servers.rs deploy writes this shape)
        // must translate to the in-container path.
        assert_eq!(
            container_home_dir(&svc, "/var/lib/lxc/wh-user-abc/rootfs/var/www/html"),
            "/var/www/html"
        );
        // Already-container paths pass through.
        assert_eq!(container_home_dir(&svc, "/srv/ftp"), "/srv/ftp");
        // Empty falls back to the docroot.
        assert_eq!(container_home_dir(&svc, ""), DOCROOT);
        svc.container_name = "other".into();
        assert_eq!(
            container_home_dir(&svc, "/var/lib/lxc/wh-user-abc/rootfs/var/www/html"),
            "/var/lib/lxc/wh-user-abc/rootfs/var/www/html"
        );
    }
}
