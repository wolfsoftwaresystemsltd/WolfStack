use std::process::Command;

/// Install PowerDNS authoritative server on the host
pub fn install_powerdns() -> Result<(), String> {
    log::info!("Installing PowerDNS...");

    let output = Command::new("sh")
        .args(&["-c", "export DEBIAN_FRONTEND=noninteractive && \
            apt-get install -y -qq pdns-server pdns-backend-sqlite3 sqlite3 2>/dev/null"])
        .output()
        .map_err(|e| format!("Failed to install PowerDNS: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    // Create SQLite database
    Command::new("sh").args(&["-c", "mkdir -p /var/lib/powerdns"]).output().ok();

    let schema = r#"
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY,
  name VARCHAR(255) NOT NULL COLLATE NOCASE,
  master VARCHAR(128) DEFAULT NULL,
  last_check INTEGER DEFAULT NULL,
  type VARCHAR(10) NOT NULL DEFAULT 'NATIVE',
  notified_serial INTEGER DEFAULT NULL,
  account VARCHAR(40) DEFAULT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS name_index ON domains(name);

CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY,
  domain_id INTEGER DEFAULT NULL,
  name VARCHAR(255) DEFAULT NULL,
  type VARCHAR(10) DEFAULT NULL,
  content VARCHAR(65535) DEFAULT NULL,
  ttl INTEGER DEFAULT NULL,
  prio INTEGER DEFAULT NULL,
  disabled BOOLEAN DEFAULT 0,
  ordername VARCHAR(255),
  auth BOOLEAN DEFAULT 1,
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS rec_name_index ON records(name);
CREATE INDEX IF NOT EXISTS nametype_index ON records(name,type);
CREATE INDEX IF NOT EXISTS domain_id ON records(domain_id);

CREATE TABLE IF NOT EXISTS supermasters (
  ip VARCHAR(64) NOT NULL,
  nameserver VARCHAR(255) NOT NULL COLLATE NOCASE,
  account VARCHAR(40) NOT NULL
);
"#;

    Command::new("sh")
        .args(&["-c", &format!("sqlite3 /var/lib/powerdns/pdns.sqlite3 '{}'", schema.replace('\'', "'\\''"))])
        .output()
        .map_err(|e| format!("Failed to create DB: {}", e))?;

    Command::new("sh")
        .args(&["-c", "chown -R pdns:pdns /var/lib/powerdns"])
        .output().ok();

    // Configure PowerDNS
    let pdns_conf = r#"
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/pdns.sqlite3
local-address=0.0.0.0
local-port=53
api=yes
api-key=wolfhost-dns-key
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
webserver-allow-from=127.0.0.1
default-soa-content=ns1.@ hostmaster.@ 0 10800 3600 604800 3600
"#;

    std::fs::write("/etc/powerdns/pdns.conf", pdns_conf.trim())
        .map_err(|e| format!("Failed to write pdns.conf: {}", e))?;

    // Disable systemd-resolved on port 53 if it's running
    Command::new("sh").args(&["-c",
        "if systemctl is-active systemd-resolved >/dev/null 2>&1; then \
            mkdir -p /etc/systemd/resolved.conf.d && \
            echo '[Resolve]\nDNSStubListener=no' > /etc/systemd/resolved.conf.d/no-stub.conf && \
            systemctl restart systemd-resolved 2>/dev/null; \
         fi"
    ]).output().ok();

    Command::new("systemctl").args(&["enable", "pdns"]).output().ok();
    Command::new("systemctl").args(&["restart", "pdns"]).output().ok();

    log::info!("PowerDNS installed and running");
    Ok(())
}

/// Check if PowerDNS is running
pub fn is_pdns_running() -> bool {
    Command::new("systemctl")
        .args(&["is-active", "pdns"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

const PDNS_API: &str = "http://127.0.0.1:8081/api/v1/servers/localhost";
const PDNS_KEY: &str = "wolfhost-dns-key";

fn pdns_get(path: &str) -> Result<serde_json::Value, String> {
    let output = Command::new("curl")
        .args(&["-s", "-H", &format!("X-API-Key: {}", PDNS_KEY),
                &format!("{}{}", PDNS_API, path)])
        .output()
        .map_err(|e| format!("PDNS API request failed: {}", e))?;
    let body = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&body).map_err(|e| format!("PDNS parse error: {} — body: {}", e, body))
}

fn pdns_request(method: &str, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let body_str = serde_json::to_string(body).unwrap_or_default();
    let output = Command::new("curl")
        .args(&["-s", "-X", method,
                "-H", &format!("X-API-Key: {}", PDNS_KEY),
                "-H", "Content-Type: application/json",
                "-d", &body_str,
                &format!("{}{}", PDNS_API, path)])
        .output()
        .map_err(|e| format!("PDNS API request failed: {}", e))?;

    let body = String::from_utf8_lossy(&output.stdout);
    if body.trim().is_empty() {
        Ok(serde_json::json!({"status": "ok"}))
    } else {
        serde_json::from_str(&body).map_err(|_| body.to_string())
    }
}

/// Create a DNS zone for a domain with default records
pub fn create_zone(domain: &str, host_ip: &str, ns1: &str, ns2: &str) -> Result<(), String> {
    log::info!("Creating DNS zone for {} (IP: {}, NS: {}, {})", domain, host_ip, ns1, ns2);

    let zone = serde_json::json!({
        "name": format!("{}.", domain),
        "kind": "Native",
        "nameservers": [format!("{}.", ns1), format!("{}.", ns2)],
        "rrsets": [
            {
                "name": format!("{}.", domain),
                "type": "A",
                "ttl": 3600,
                "changetype": "REPLACE",
                "records": [{"content": host_ip, "disabled": false}]
            },
            {
                "name": format!("www.{}.", domain),
                "type": "CNAME",
                "ttl": 3600,
                "changetype": "REPLACE",
                "records": [{"content": format!("{}.", domain), "disabled": false}]
            },
            {
                "name": format!("mail.{}.", domain),
                "type": "A",
                "ttl": 3600,
                "changetype": "REPLACE",
                "records": [{"content": host_ip, "disabled": false}]
            },
            {
                "name": format!("{}.", domain),
                "type": "MX",
                "ttl": 3600,
                "changetype": "REPLACE",
                "records": [{"content": format!("10 mail.{}.", domain), "disabled": false}]
            },
            {
                "name": format!("{}.", domain),
                "type": "TXT",
                "ttl": 3600,
                "changetype": "REPLACE",
                "records": [{"content": format!("\"v=spf1 ip4:{} ~all\"", host_ip), "disabled": false}]
            },
        ]
    });

    pdns_request("POST", "/zones", &zone)?;
    log::info!("DNS zone created for {}", domain);
    Ok(())
}

/// Delete a DNS zone
pub fn delete_zone(domain: &str) -> Result<(), String> {
    pdns_request("DELETE", &format!("/zones/{}.", domain), &serde_json::json!({}))?;
    Ok(())
}

/// List all zones
pub fn list_zones() -> Result<Vec<serde_json::Value>, String> {
    let data = pdns_get("/zones")?;
    Ok(data.as_array().cloned().unwrap_or_default())
}

/// Get all records for a zone
pub fn get_zone_records(domain: &str) -> Result<serde_json::Value, String> {
    pdns_get(&format!("/zones/{}.", domain))
}

/// Add or update a DNS record
pub fn set_record(domain: &str, name: &str, rtype: &str, content: &str, ttl: u32) -> Result<(), String> {
    // Ensure name is fully qualified
    let fqdn = if name == "@" || name.is_empty() {
        format!("{}.", domain)
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.{}.", name, domain)
    };

    let patch = serde_json::json!({
        "rrsets": [{
            "name": fqdn,
            "type": rtype,
            "ttl": ttl,
            "changetype": "REPLACE",
            "records": [{"content": content, "disabled": false}]
        }]
    });

    pdns_request("PATCH", &format!("/zones/{}.", domain), &patch)?;
    Ok(())
}

/// Delete a DNS record
pub fn delete_record(domain: &str, name: &str, rtype: &str) -> Result<(), String> {
    let fqdn = if name == "@" || name.is_empty() {
        format!("{}.", domain)
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.{}.", name, domain)
    };

    let patch = serde_json::json!({
        "rrsets": [{
            "name": fqdn,
            "type": rtype,
            "changetype": "DELETE",
        }]
    });

    pdns_request("PATCH", &format!("/zones/{}.", domain), &patch)?;
    Ok(())
}
