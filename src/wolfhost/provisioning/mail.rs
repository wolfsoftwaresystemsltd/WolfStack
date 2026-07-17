use std::process::Command;

fn is_proxmox() -> bool {
    Command::new("which").arg("pct").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn lxc_exec(container: &str, cmd: &str) -> Result<String, String> {
    let output = if is_proxmox() {
        Command::new("pct")
            .args(&["exec", container, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("pct exec failed: {}", e))?
    } else {
        Command::new("lxc-attach")
            .args(&["-n", container, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("lxc-attach failed: {}", e))?
    };
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Install and configure Postfix + Dovecot mail server inside a container
pub fn setup_mail_server(container: &str, domain: &str, hostname: &str) -> Result<(), String> {
    log::info!("[{}] Installing mail server for {}", container, domain);

    // Install Postfix and Dovecot
    lxc_exec(container,
        "export DEBIAN_FRONTEND=noninteractive && \
         debconf-set-selections <<< 'postfix postfix/mailname string localhost' && \
         debconf-set-selections <<< 'postfix postfix/main_mailer_type string Internet Site' && \
         apt-get install -y -qq postfix dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
         opendkim opendkim-tools 2>/dev/null"
    )?;

    // Configure Postfix main.cf
    let postfix_main = format!(r#"
smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may
smtp_tls_security_level=may

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = {hostname}
mydomain = {domain}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = $myhostname, {domain}, localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Virtual mailbox settings
virtual_mailbox_domains = {domain}
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_minimum_uid = 100
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_transport = lmtp:unix:private/dovecot-lmtp

# SASL Authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname

# Submission port
submission_relay_restrictions = permit_sasl_authenticated,reject
"#, domain = domain, hostname = hostname);

    lxc_exec(container, &format!("cat > /etc/postfix/main.cf << 'POSTCF'\n{}\nPOSTCF", postfix_main))?;

    // Enable submission port in master.cf
    lxc_exec(container, r#"
        grep -q '^submission' /etc/postfix/master.cf || \
        echo 'submission inet n - y - - smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING' >> /etc/postfix/master.cf
    "#)?;

    // Create vmail user and directories
    lxc_exec(container, &format!(
        "groupadd -g 5000 vmail 2>/dev/null; \
         useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -s /usr/sbin/nologin 2>/dev/null; \
         mkdir -p /var/mail/vhosts/{domain}; \
         chown -R vmail:vmail /var/mail/vhosts",
        domain = domain
    ))?;

    // Create empty vmailbox file
    lxc_exec(container, "touch /etc/postfix/vmailbox && postmap /etc/postfix/vmailbox")?;

    // Configure Dovecot
    let dovecot_conf = format!(r#"
protocols = imap pop3 lmtp
listen = *, ::

mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = vmail

namespace inbox {{
  inbox = yes
}}

# Authentication
auth_mechanisms = plain login
passdb {{
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
}}
userdb {{
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}}

# SSL
ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key

# LMTP for Postfix delivery
service lmtp {{
  unix_listener /var/spool/postfix/private/dovecot-lmtp {{
    mode = 0600
    user = postfix
    group = postfix
  }}
}}

# SASL for Postfix auth
service auth {{
  unix_listener /var/spool/postfix/private/auth {{
    mode = 0660
    user = postfix
    group = postfix
  }}
  unix_listener auth-userdb {{
    mode = 0600
    user = vmail
  }}
}}

service auth-worker {{
  user = vmail
}}
"#);

    lxc_exec(container, &format!("cat > /etc/dovecot/dovecot.conf << 'DOVECF'\n{}\nDOVECF", dovecot_conf))?;

    // Create empty users file
    lxc_exec(container, "touch /etc/dovecot/users && chown vmail:dovecot /etc/dovecot/users && chmod 640 /etc/dovecot/users")?;

    // Set up DKIM
    lxc_exec(container, &format!(
        "mkdir -p /etc/opendkim/keys/{domain} && \
         opendkim-genkey -b 2048 -d {domain} -D /etc/opendkim/keys/{domain} -s mail -v 2>/dev/null && \
         chown -R opendkim:opendkim /etc/opendkim",
        domain = domain
    ))?;

    // Configure OpenDKIM
    let dkim_conf = format!(r#"
AutoRestart             Yes
AutoRestartRate         10/1h
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
OversignHeaders         From
KeyTable                /etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
InternalHosts           /etc/opendkim/trusted.hosts
Socket                  local:/var/spool/postfix/opendkim/opendkim.sock
PidFile                 /run/opendkim/opendkim.pid
UMask                   007
UserID                  opendkim
"#);

    lxc_exec(container, &format!("cat > /etc/opendkim.conf << 'DKIMCF'\n{}\nDKIMCF", dkim_conf))?;
    lxc_exec(container, &format!("echo 'mail._domainkey.{d} {d}:mail:/etc/opendkim/keys/{d}/mail.private' > /etc/opendkim/key.table", d = domain))?;
    lxc_exec(container, &format!("echo '*@{d} mail._domainkey.{d}' > /etc/opendkim/signing.table", d = domain))?;
    lxc_exec(container, &format!("echo '127.0.0.1\nlocalhost\n{d}' > /etc/opendkim/trusted.hosts", d = domain))?;
    lxc_exec(container, "mkdir -p /var/spool/postfix/opendkim && chown opendkim:postfix /var/spool/postfix/opendkim")?;

    // Add DKIM milter to Postfix
    lxc_exec(container, r#"
        postconf -e 'milter_protocol = 6'
        postconf -e 'milter_default_action = accept'
        postconf -e 'smtpd_milters = local:opendkim/opendkim.sock'
        postconf -e 'non_smtpd_milters = $smtpd_milters'
    "#)?;

    // Set mailname
    lxc_exec(container, &format!("echo '{}' > /etc/mailname", domain))?;

    // Start services
    lxc_exec(container, "systemctl enable postfix dovecot opendkim 2>/dev/null")?;
    lxc_exec(container, "systemctl restart postfix dovecot opendkim 2>/dev/null")?;

    log::info!("[{}] Mail server configured for {}", container, domain);
    Ok(())
}

/// Add an email account inside the container
pub fn add_email_account(container: &str, address: &str, password: &str) -> Result<(), String> {
    // The address (and the user/domain split from it) is interpolated into
    // shell strings run inside the container below. `valid_email` restricts
    // it to [A-Za-z0-9._+-]@[A-Za-z0-9.-] — no quote, semicolon, backtick,
    // `$` or whitespace can survive — so it cannot break out of the shell
    // command. Reject at the boundary; a legitimate mailbox address always
    // passes. (password is separately single-quote-escaped below.)
    if !super::native_tools::valid_email(address) {
        return Err("Invalid email address".to_string());
    }
    let parts: Vec<&str> = address.split('@').collect();
    if parts.len() != 2 { return Err("Invalid email address".to_string()); }
    let user = parts[0];
    let domain = parts[1];

    // Generate password hash
    let hash_output = lxc_exec(container, &format!(
        "doveadm pw -s SHA512-CRYPT -p '{}' 2>/dev/null || openssl passwd -6 '{}'",
        password.replace('\'', "'\\''"),
        password.replace('\'', "'\\''"),
    ))?;
    let hash = hash_output.trim().to_string();

    // Add to Dovecot users file
    lxc_exec(container, &format!(
        "grep -v '^{addr}:' /etc/dovecot/users > /tmp/dovecot_users_tmp 2>/dev/null; \
         echo '{addr}:{hash}:::::/var/mail/vhosts/{domain}/{user}' >> /tmp/dovecot_users_tmp; \
         mv /tmp/dovecot_users_tmp /etc/dovecot/users; \
         chown vmail:dovecot /etc/dovecot/users; chmod 640 /etc/dovecot/users",
        addr = address, hash = hash, domain = domain, user = user,
    ))?;

    // Add to Postfix virtual mailbox map
    lxc_exec(container, &format!(
        "grep -v '^{addr} ' /etc/postfix/vmailbox > /tmp/vmailbox_tmp 2>/dev/null; \
         echo '{addr} {domain}/{user}/' >> /tmp/vmailbox_tmp; \
         mv /tmp/vmailbox_tmp /etc/postfix/vmailbox; \
         postmap /etc/postfix/vmailbox",
        addr = address, domain = domain, user = user,
    ))?;

    // Create maildir
    lxc_exec(container, &format!(
        "mkdir -p /var/mail/vhosts/{domain}/{user} && chown -R vmail:vmail /var/mail/vhosts/{domain}/{user}",
        domain = domain, user = user,
    ))?;

    // Reload
    lxc_exec(container, "systemctl reload postfix 2>/dev/null")?;

    log::info!("[{}] Email account added: {}", container, address);
    Ok(())
}

/// Remove an email account from the container
pub fn remove_email_account(container: &str, address: &str) -> Result<(), String> {
    // Same shell-safety guard as add_email_account — address is interpolated
    // into container shell commands below.
    if !super::native_tools::valid_email(address) {
        return Err("Invalid email address".to_string());
    }
    // Remove from Dovecot users
    lxc_exec(container, &format!(
        "grep -v '^{}:' /etc/dovecot/users > /tmp/du_tmp 2>/dev/null; mv /tmp/du_tmp /etc/dovecot/users; \
         chown vmail:dovecot /etc/dovecot/users; chmod 640 /etc/dovecot/users",
        address
    ))?;

    // Remove from Postfix vmailbox
    lxc_exec(container, &format!(
        "grep -v '^{} ' /etc/postfix/vmailbox > /tmp/vm_tmp 2>/dev/null; mv /tmp/vm_tmp /etc/postfix/vmailbox; \
         postmap /etc/postfix/vmailbox",
        address
    ))?;

    lxc_exec(container, "systemctl reload postfix 2>/dev/null")?;
    log::info!("[{}] Email account removed: {}", container, address);
    Ok(())
}

/// Get DKIM public key from the container (for DNS TXT record)
pub fn get_dkim_record(container: &str, domain: &str) -> Result<String, String> {
    let key_file = format!("/etc/opendkim/keys/{}/mail.txt", domain);
    let output = lxc_exec(container, &format!("cat {} 2>/dev/null", key_file))?;
    if output.trim().is_empty() {
        return Err("DKIM key not found".to_string());
    }
    Ok(output.trim().to_string())
}

/// Set up mail port forwarding from host to container
/// Ports: 25 (SMTP), 587 (Submission), 993 (IMAPS), 995 (POP3S), 110 (POP3), 143 (IMAP)
pub fn setup_mail_forwarding(container_ip: &str) -> Result<(), String> {
    log::info!("Setting up mail port forwarding to {}", container_ip);

    let ports = [25, 587, 993, 995, 143, 110];
    for port in &ports {
        let cmd = format!(
            "iptables -t nat -C PREROUTING -p tcp --dport {} -j DNAT --to-destination {}:{} 2>/dev/null || \
             iptables -t nat -A PREROUTING -p tcp --dport {} -j DNAT --to-destination {}:{}",
            port, container_ip, port, port, container_ip, port
        );
        Command::new("sh").args(&["-c", &cmd]).output().ok();

        let masq = format!(
            "iptables -t nat -C POSTROUTING -p tcp -d {} --dport {} -j MASQUERADE 2>/dev/null || \
             iptables -t nat -A POSTROUTING -p tcp -d {} --dport {} -j MASQUERADE",
            container_ip, port, container_ip, port
        );
        Command::new("sh").args(&["-c", &masq]).output().ok();
    }

    Command::new("sh").args(&["-c", "sysctl -w net.ipv4.ip_forward=1 2>/dev/null"]).output().ok();
    log::info!("Mail ports forwarded: 25, 587, 993, 995, 143, 110 -> {}", container_ip);
    Ok(())
}
