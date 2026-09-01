// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Local Unraid user-share discovery — for WolfStack agents running
//! natively ON an Unraid host (klas, 2026-08-11: "seeing all the shares
//! on unraid and being able to publish them to the cluster (the ones
//! with smb enabled)").
//!
//! Unlike the GraphQL integration in the parent module (which needs a
//! registered instance + API key), this reads emhttp's own runtime
//! state files directly — zero configuration on an agent node:
//!
//!   * `/var/local/emhttp/shares.ini` — one section per user share
//!     (name, comment, cache mode…). Source: unraid/webgui
//!     `include/ShareList.php` (`parse_ini_file('state/shares.ini')`;
//!     the webgui's `state/` resolves to /var/local/emhttp — same dir
//!     as var.ini per `include/Wireless.php`).
//!   * `/var/local/emhttp/sec.ini` — SMB security per share; the
//!     `export` key is the SMB toggle. Values from the webgui's
//!     SecuritySMB.page selector: `-` No, `e` Yes, `eh` Yes (hidden),
//!     `et` Yes/Time Machine, `eth` Yes/Time Machine (hidden) — so
//!     "SMB-enabled" == value starts with `e`, "hidden" == contains
//!     `h`.
//!
//! User shares are always exposed at `/mnt/user/<name>`, which is what
//! the SMB export serves — so the mountable UNC for a peer is
//! `//<host>/<name>`.

use serde::Serialize;
use std::collections::HashMap;

const SHARES_INI: &str = "/var/local/emhttp/shares.ini";
const SEC_INI: &str = "/var/local/emhttp/sec.ini";

#[derive(Debug, Clone, Serialize)]
pub struct LocalShare {
    pub name: String,
    /// Host path the share serves (always /mnt/user/<name>).
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Raw emhttp export value ("-", "e", "eh", "et", "eth").
    pub smb_export: String,
    /// SMB-enabled (export value starts with 'e').
    pub smb_enabled: bool,
    /// Hidden from network browse (export value contains 'h').
    pub smb_hidden: bool,
}

/// List this host's Unraid user shares. `None` when this is not an
/// Unraid host or emhttp state isn't readable (the caller reports
/// "unsupported" rather than an empty share list — the distinction
/// matters to the UI).
pub fn list_local_shares() -> Option<Vec<LocalShare>> {
    if !crate::installer::unraid_tools::is_unraid() {
        return None;
    }
    let shares_raw = std::fs::read_to_string(SHARES_INI).ok()?;
    // sec.ini can legitimately be absent moments after boot; treat as
    // "nothing exported" rather than unsupported.
    let sec_raw = std::fs::read_to_string(SEC_INI).unwrap_or_default();

    let sec = parse_emhttp_ini(&sec_raw);
    let mut out = Vec::new();
    for (name, fields) in parse_emhttp_ini(&shares_raw) {
        let export = sec.iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, f)| f.get("export"))
            .cloned()
            .unwrap_or_else(|| "-".into());
        out.push(LocalShare {
            path: format!("/mnt/user/{}", name),
            comment: fields.get("comment").cloned().unwrap_or_default(),
            smb_enabled: export.starts_with('e'),
            smb_hidden: export.contains('h'),
            smb_export: export,
            name,
        });
    }
    Some(out)
}

/// Parse emhttp's ini dialect: `["section"]` headers (quotes optional)
/// and `key="value"` pairs (quotes optional). Preserves section order —
/// the UI shows shares in emhttp's own order. PHP's parse_ini_file is
/// the reference consumer (webgui ShareList.php), which accepts both
/// quoted and bare forms.
pub fn parse_emhttp_ini(content: &str) -> Vec<(String, HashMap<String, String>)> {
    let mut out: Vec<(String, HashMap<String, String>)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim_matches('"').to_string();
            out.push((name, HashMap::new()));
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        // Keys before the first [section] are dropped on purpose —
        // same as PHP's parse_ini_file(…, true), the reference
        // consumer; emhttp's shares.ini/sec.ini always open with a
        // section. Mind this if reusing the parser for var.ini, which
        // is sectionless and would parse to nothing here.
        if let Some((_, fields)) = out.last_mut() {
            fields.insert(
                k.trim().to_string(),
                v.trim().trim_matches('"').to_string(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shapes mirror the webgui's parse_ini_file consumers: quoted
    // section names + quoted values (emhttp's writer), with the
    // export values from SecuritySMB.page's selector.
    const SHARES_FIXTURE: &str = r#"
["appdata"]
nameOrig="appdata"
comment="application data"
useCache="only"
["media"]
nameOrig="media"
comment=""
["secret"]
nameOrig="secret"
comment="not for browsing"
"#;

    const SEC_FIXTURE: &str = r#"
["appdata"]
export="-"
security="public"
["media"]
export="e"
security="public"
["secret"]
export="eh"
security="private"
"#;

    #[test]
    fn ini_parser_handles_quoted_sections_and_values() {
        let parsed = parse_emhttp_ini(SHARES_FIXTURE);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, "appdata");
        assert_eq!(parsed[0].1.get("comment").unwrap(), "application data");
        assert_eq!(parsed[1].1.get("comment").unwrap(), "");
    }

    #[test]
    fn export_flags_map_to_enabled_and_hidden() {
        let sec = parse_emhttp_ini(SEC_FIXTURE);
        let get = |n: &str| sec.iter().find(|(name, _)| name == n).unwrap().1.get("export").unwrap().clone();
        assert_eq!(get("appdata"), "-");
        // "e" = exported, visible; "eh" = exported, hidden;
        // "et"/"eth" (Time Machine) still start with 'e'.
        for (val, enabled, hidden) in [("-", false, false), ("e", true, false), ("eh", true, true), ("et", true, false), ("eth", true, true)] {
            assert_eq!(val.starts_with('e'), enabled, "export {:?}", val);
            assert_eq!(val.starts_with('e') && val.contains('h'), hidden, "export {:?}", val);
        }
    }

    #[test]
    fn non_unraid_host_reports_unsupported() {
        if !crate::installer::unraid_tools::is_unraid() {
            assert!(list_local_shares().is_none());
        }
    }
}
