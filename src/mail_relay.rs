// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Host mail relay.
//!
//! Many host-side services (cron `MAILTO`, PHP `mail()`, monitoring
//! scripts, app-store apps) send email by invoking a local
//! `/usr/sbin/sendmail` binary. On a minimal server there is no MTA, so
//! those sends silently fail. WolfStack itself never needs this — its own
//! alert/AI email goes straight out over SMTP via the `lettre` crate — but
//! the services it manages often do.
//!
//! This module wires up [`msmtp`](https://marlam.de/msmtp/) as a
//! sendmail-compatible relay: a tiny SMTP client with no listening daemon
//! and no open ports. It reuses the SMTP relay the operator has already
//! configured for alert email (`AiConfig`), writes `/etc/msmtprc`, and
//! symlinks `msmtp` in as `/usr/sbin/sendmail`.
//!
//! Safety:
//! - We refuse to replace an EXISTING MTA (postfix/exim/…) unless the
//!   operator explicitly forces it — honouring "never break existing
//!   installs". An existing `sendmail` that isn't ours is left untouched.
//! - `/etc/msmtprc` is written world-readable (0644) so services running
//!   as any user (e.g. `www-data`) can send. That means the relay
//!   password is readable by local users, so the status surfaces a clear
//!   warning to use a dedicated relay credential — never a primary account.

use serde::Serialize;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const MSMTPRC: &str = "/etc/msmtprc";
const SENDMAIL: &str = "/usr/sbin/sendmail";
/// Where the previous `/usr/sbin/sendmail` is moved if the operator forces
/// a replacement, so the change is reversible.
const SENDMAIL_BAK: &str = "/usr/sbin/sendmail.wolfstack-bak";

/// Locate a binary without shelling out to `which` — minimal hosts and
/// containers often don't ship the `which` command at all. Public
/// because other host-integration modules (ups) probe binaries the
/// same way.
pub fn which(bin: &str) -> Option<String> {
    // Common absolute locations first (fast, and covers empty $PATH).
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"] {
        let p = format!("{dir}/{bin}");
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    // Then anything else on $PATH.
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let p = format!("{dir}/{bin}");
            if Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Classify the current `/usr/sbin/sendmail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendmailKind {
    /// No sendmail binary at all.
    None,
    /// A symlink chain that resolves to msmtp — i.e. ours.
    Ours,
    /// A real MTA (postfix/exim/sendmail) or anything not msmtp.
    Other,
}

fn classify_sendmail() -> (SendmailKind, Option<String>) {
    let p = Path::new(SENDMAIL);
    if !p.exists() {
        // exists() follows symlinks; a dangling symlink means "gone".
        // symlink_metadata catches the dangling case so we don't report a
        // broken link as "None" and then refuse to overwrite it.
        if std::fs::symlink_metadata(p).is_err() {
            return (SendmailKind::None, None);
        }
    }
    // Resolve the full chain (handles /etc/alternatives indirection).
    let target = std::fs::canonicalize(p)
        .ok()
        .map(|t| t.to_string_lossy().to_string());
    let is_msmtp = target
        .as_deref()
        .map(|t| Path::new(t).file_name().and_then(|f| f.to_str()) == Some("msmtp"))
        .unwrap_or(false);
    if is_msmtp {
        (SendmailKind::Ours, target)
    } else {
        (SendmailKind::Other, target)
    }
}

#[derive(Serialize)]
pub struct MailRelayStatus {
    pub msmtp_installed: bool,
    pub msmtp_path: Option<String>,
    /// SMTP relay is configured (a host is set) so we have something to
    /// point msmtp at.
    pub smtp_configured: bool,
    pub smtp_host: String,
    /// "none" | "ours" | "other" — what currently owns /usr/sbin/sendmail.
    pub sendmail: String,
    pub sendmail_target: Option<String>,
    /// True when our msmtprc is present AND sendmail resolves to msmtp.
    pub relay_active: bool,
    /// Present when relay_active — reminds the operator the relay password
    /// is host-readable.
    pub warning: Option<String>,
    pub is_root: bool,
    pub distro: String,
    pub pkg_mgr: crate::deps::PkgMgr,
}

pub fn status() -> MailRelayStatus {
    let cfg = crate::ai::AiConfig::load();
    let msmtp_path = which("msmtp");
    let (kind, target) = classify_sendmail();
    let relay_active = kind == SendmailKind::Ours && Path::new(MSMTPRC).exists();
    let (distro, pkg_mgr) = crate::deps::detect_for_status();

    MailRelayStatus {
        msmtp_installed: msmtp_path.is_some(),
        msmtp_path,
        smtp_configured: !cfg.smtp_host.trim().is_empty(),
        smtp_host: cfg.smtp_host.clone(),
        sendmail: match kind {
            SendmailKind::None => "none",
            SendmailKind::Ours => "ours",
            SendmailKind::Other => "other",
        }
        .to_string(),
        sendmail_target: target,
        relay_active,
        warning: if relay_active {
            Some("The relay password is stored in a host-readable file (/etc/msmtprc) so any local service can send mail. Use a dedicated SMTP/relay credential, not a primary account.".to_string())
        } else {
            None
        },
        is_root: crate::deps::is_root(),
        distro,
        pkg_mgr,
    }
}

/// Build the `/etc/msmtprc` contents from the configured SMTP relay.
fn build_msmtprc(cfg: &crate::ai::AiConfig) -> String {
    let auth = !cfg.smtp_user.trim().is_empty();
    // Sender: prefer smtp_from, fall back to smtp_user (matches the
    // alert-email path in ai::send_alert_email).
    let from = if !cfg.smtp_from.trim().is_empty() {
        cfg.smtp_from.trim()
    } else {
        cfg.smtp_user.trim()
    };
    // TLS: "tls" = implicit (465), "none" = plaintext, anything else = STARTTLS.
    let (tls_on, starttls) = match cfg.smtp_tls.as_str() {
        "tls" => (true, false),
        "none" => (false, false),
        _ => (true, true),
    };

    let mut s = String::new();
    s.push_str("# Managed by WolfStack — host mail relay (msmtp).\n");
    s.push_str("# Regenerated each time you enable the relay from Settings.\n");
    s.push_str("# Host services send via /usr/sbin/sendmail, which points here.\n\n");
    s.push_str("defaults\n");
    s.push_str(if auth { "auth on\n" } else { "auth off\n" });
    if tls_on {
        s.push_str("tls on\n");
        s.push_str(if starttls { "tls_starttls on\n" } else { "tls_starttls off\n" });
        // Use a system CA bundle when we can find one; otherwise fall back
        // to msmtp's built-in system trust store (default when unset).
        for bundle in [
            "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Arch
            "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
            "/etc/ssl/ca-bundle.pem",             // openSUSE
        ] {
            if Path::new(bundle).exists() {
                s.push_str(&format!("tls_trust_file {bundle}\n"));
                break;
            }
        }
    } else {
        s.push_str("tls off\n");
    }
    // Log to syslog rather than a file so a service running as www-data
    // isn't blocked by a root-owned logfile it can't write.
    s.push_str("syslog on\n\n");

    s.push_str("account wolfstack\n");
    s.push_str(&format!("host {}\n", cfg.smtp_host.trim()));
    s.push_str(&format!("port {}\n", cfg.smtp_port));
    if !from.is_empty() {
        s.push_str(&format!("from {from}\n"));
    }
    if auth {
        s.push_str(&format!("user {}\n", cfg.smtp_user.trim()));
        s.push_str(&format!("password {}\n", cfg.smtp_pass));
    }
    s.push_str("\naccount default : wolfstack\n");
    s
}

#[derive(Serialize)]
pub struct EnableResult {
    pub ok: bool,
    pub message: String,
    /// Package-manager output when we had to install msmtp (else empty).
    pub install_output: String,
    pub status: MailRelayStatus,
}

/// Install + configure the msmtp relay on this node. `force` allows
/// replacing an existing non-msmtp `/usr/sbin/sendmail` (backed up first).
pub fn enable(force: bool) -> Result<EnableResult, String> {
    if !crate::deps::is_root() {
        return Err("Enabling the host mail relay needs root.".into());
    }
    let cfg = crate::ai::AiConfig::load();
    if cfg.smtp_host.trim().is_empty() {
        return Err(
            "No SMTP relay is configured. Set up your SMTP server under Settings → AI \
             (the same settings used for alert email) first."
                .into(),
        );
    }

    // Don't clobber an existing MTA unless explicitly forced.
    let (kind, target) = classify_sendmail();
    if kind == SendmailKind::Other && !force {
        return Err(format!(
            "This host already has a mail transfer agent providing {} ({}). \
             Refusing to replace it. Re-run with 'force' only if you're sure you \
             want WolfStack to take over sending.",
            SENDMAIL,
            target.as_deref().unwrap_or("unknown"),
        ));
    }

    // Install msmtp if the binary isn't already present.
    let mut install_output = String::new();
    if which("msmtp").is_none() {
        let res = crate::deps::install("mail")?;
        install_output = res.output.clone();
        if res.ran && res.exit_code != 0 {
            return Err(format!(
                "Failed to install msmtp (exit {}). Output:\n{}",
                res.exit_code, res.output
            ));
        }
    }
    let msmtp_path = which("msmtp")
        .ok_or_else(|| "msmtp is still not on PATH after installation.".to_string())?;

    // Write /etc/msmtprc (0644 so any local service can read it and send).
    let contents = build_msmtprc(&cfg);
    std::fs::write(MSMTPRC, &contents).map_err(|e| format!("write {MSMTPRC}: {e}"))?;
    std::fs::set_permissions(MSMTPRC, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("chmod {MSMTPRC}: {e}"))?;

    // Point /usr/sbin/sendmail at msmtp. Back up a forced-over real MTA
    // binary so the operator can restore it.
    if kind == SendmailKind::Other {
        // Only move a real file; a symlink we just remove.
        let meta = std::fs::symlink_metadata(SENDMAIL).ok();
        if let Some(m) = meta {
            if m.file_type().is_symlink() {
                let _ = std::fs::remove_file(SENDMAIL);
            } else {
                std::fs::rename(SENDMAIL, SENDMAIL_BAK)
                    .map_err(|e| format!("back up existing sendmail: {e}"))?;
            }
        }
    } else if kind == SendmailKind::Ours {
        // Refresh the link in case msmtp moved.
        let _ = std::fs::remove_file(SENDMAIL);
    }
    if let Some(dir) = Path::new(SENDMAIL).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if !Path::new(SENDMAIL).exists() {
        std::os::unix::fs::symlink(&msmtp_path, SENDMAIL)
            .map_err(|e| format!("symlink {SENDMAIL} -> {msmtp_path}: {e}"))?;
    }

    Ok(EnableResult {
        ok: true,
        message: format!(
            "Host mail relay enabled. Services can now send email via {} through {}.",
            SENDMAIL,
            cfg.smtp_host.trim()
        ),
        install_output,
        status: status(),
    })
}

/// Remove our sendmail symlink and msmtprc, restoring any backed-up MTA.
pub fn disable() -> Result<MailRelayStatus, String> {
    if !crate::deps::is_root() {
        return Err("Disabling the host mail relay needs root.".into());
    }
    let (kind, _) = classify_sendmail();
    if kind == SendmailKind::Ours {
        let _ = std::fs::remove_file(SENDMAIL);
        // Restore a backed-up real MTA if we replaced one earlier.
        if Path::new(SENDMAIL_BAK).exists() {
            let _ = std::fs::rename(SENDMAIL_BAK, SENDMAIL);
        }
    }
    let _ = std::fs::remove_file(MSMTPRC);
    Ok(status())
}

/// Send a test message through the sendmail path to prove it works
/// end-to-end. Returns msmtp's own output on failure so the operator can
/// see the SMTP-level error.
pub fn test_send(to: &str) -> Result<String, String> {
    let to = to.trim();
    if to.is_empty() {
        return Err("Enter a recipient address to send the test to.".into());
    }
    // Basic guard — this address goes into a shell-free argv, but reject
    // obvious junk early with a clear message.
    if !to.contains('@') || to.contains(char::is_whitespace) {
        return Err(format!("'{to}' doesn't look like an email address."));
    }
    if classify_sendmail().0 != SendmailKind::Ours {
        return Err("The WolfStack mail relay isn't active on this host — enable it first.".into());
    }
    let cfg = crate::ai::AiConfig::load();
    let from = if !cfg.smtp_from.trim().is_empty() {
        cfg.smtp_from.trim()
    } else {
        cfg.smtp_user.trim()
    };
    let body = format!(
        "From: {}\r\nTo: {}\r\nSubject: WolfStack host mail relay test\r\n\r\n\
         This is a test message sent through /usr/sbin/sendmail (msmtp) from {}.\r\n\
         If you received it, host services on this node can now send email.\r\n",
        from,
        to,
        hostname()
    );
    // Invoke sendmail with the recipient as an explicit argv entry (no
    // shell) and feed the message on stdin.
    use std::io::Write;
    let mut child = Command::new(SENDMAIL)
        .arg("-i")
        .arg(to)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {SENDMAIL}: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(body.as_bytes())
            .map_err(|e| format!("write to sendmail: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait for sendmail: {e}"))?;
    if out.status.success() {
        Ok(format!("Test message queued to {to}."))
    } else {
        let mut msg = String::from_utf8_lossy(&out.stdout).to_string();
        msg.push_str(&String::from_utf8_lossy(&out.stderr));
        Err(format!(
            "sendmail exited {}: {}",
            out.status.code().unwrap_or(-1),
            msg.trim()
        ))
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "this host".to_string())
}
