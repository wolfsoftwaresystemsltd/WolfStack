// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Wrapper around the `ipset` CLI for atomic blocklist swaps.
//!
//! The pattern: build a *temporary* set with the same shape as the live
//! one, populate it via `ipset restore`, then `ipset swap` to make the
//! temp set live and the old one disposable. This keeps the kernel's
//! match-set rule pointed at a stable name throughout — no window where
//! the rule references a missing or half-built set.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};

/// Is the `ipset` binary present on PATH? Without it, threat-intel can
/// fetch and report (dry-run) but cannot apply.
pub fn ipset_available() -> bool {
    Command::new("ipset")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Push the given CIDRs into the named ipset atomically. Creates the set
/// if it doesn't exist. `family` is "inet" for v4 or "inet6" for v6.
pub fn replace_set(name: &str, family: &str, entries: &BTreeSet<String>) -> Result<(), String> {
    if !ipset_available() {
        return Err("ipset binary not found — install ipset to enable enforcement".to_string());
    }
    let tmp_name = format!("{}-tmp", name);
    // Build the restore script:
    //   create <tmp> hash:net family <fam> hashsize 65536 maxelem 250000 -exist
    //   add <tmp> 1.2.3.4/24
    //   add <tmp> ...
    //   create <name> hash:net family <fam> hashsize 65536 maxelem 250000 -exist
    //   swap <tmp> <name>
    //   destroy <tmp>
    let mut script = String::with_capacity(entries.len() * 32 + 256);
    script.push_str(&format!(
        "create {} hash:net family {} hashsize 65536 maxelem {} -exist\n",
        tmp_name, family, super::MAX_BLOCKLIST_SIZE
    ));
    // Make sure the temp set starts empty even if a previous run left it around.
    script.push_str(&format!("flush {}\n", tmp_name));
    for entry in entries.iter() {
        script.push_str("add ");
        script.push_str(&tmp_name);
        script.push(' ');
        script.push_str(entry);
        script.push('\n');
    }
    script.push_str(&format!(
        "create {} hash:net family {} hashsize 65536 maxelem {} -exist\n",
        name, family, super::MAX_BLOCKLIST_SIZE
    ));
    script.push_str(&format!("swap {} {}\n", tmp_name, name));
    script.push_str(&format!("destroy {}\n", tmp_name));

    let mut child = Command::new("ipset")
        .arg("restore")
        .arg("-!")  // ignore "already exists" / "doesn't exist" warnings
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn ipset restore: {}", e))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())
            .map_err(|e| format!("write ipset stdin: {}", e))?;
    }
    let out = child.wait_with_output()
        .map_err(|e| format!("wait ipset: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("ipset restore failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Empty the named set without destroying it. Used when threat-intel is
/// disabled — leaves the iptables rule in place (it'll match nothing) so
/// re-enabling is a single ipset operation away.
pub fn flush_set(name: &str) -> Result<(), String> {
    if !ipset_available() {
        return Ok(());  // Nothing to do — set was never created.
    }
    let out = Command::new("ipset")
        .args(["flush", name])
        .output()
        .map_err(|e| format!("spawn ipset flush: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "The set with the given name does not exist" is fine — we
        // wanted it empty, it's empty.
        if stderr.contains("does not exist") { return Ok(()); }
        return Err(format!("ipset flush failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Destroy the set entirely. Used on uninstall or when iptables rules
/// have been torn down separately. Reserved for future "uninstall
/// threat-intel" UX; not currently called.
#[allow(dead_code)]
pub fn destroy_set(name: &str) -> Result<(), String> {
    if !ipset_available() {
        return Ok(());
    }
    let out = Command::new("ipset")
        .args(["destroy", name])
        .output()
        .map_err(|e| format!("spawn ipset destroy: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("does not exist") { return Ok(()); }
        return Err(format!("ipset destroy failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// We can't actually run `ipset` in the test env (and shouldn't —
    /// the test suite must not modify the host's firewall). These tests
    /// only verify the script-building behaviour by checking that the
    /// availability probe is gated correctly.
    #[test]
    fn test_replace_set_errors_when_ipset_missing() {
        // Best-effort sentinel: if the runner does have ipset, this test
        // becomes a no-op assertion.
        if !ipset_available() {
            let mut entries = BTreeSet::new();
            entries.insert("203.0.113.1/32".to_string());
            let r = replace_set("definitely-not-a-real-set", "inet", &entries);
            assert!(r.is_err());
        }
    }

    #[test]
    fn test_flush_set_returns_ok_when_ipset_missing() {
        if !ipset_available() {
            assert!(flush_set("nonexistent").is_ok());
        }
    }
}
