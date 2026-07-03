// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Unraid tool bootstrapper — Unraid is a RAM-based Slackware with no
//! package manager: /usr/local/bin is recreated on every boot, so anything
//! we install there evaporates. This module gives Unraid agent nodes the
//! tools WolfStack features need (PBS backups, SMART monitoring) by
//! downloading static builds from the rolling `unraid-tools-v1` GitHub
//! release (built/verified by .github/workflows/unraid-tools.yml),
//! persisting them on the array at /mnt/user/appdata/wolfstack/tools, and
//! re-linking them into /usr/local/bin on every startup (klasSponsor,
//! 2026-07-03: "wolfstack could just reinstall what's needed when it's run
//! at startup").
//!
//! Runs from the post-bind background startup thread — per the masterpier
//! lesson (2026-07-03) nothing here may gate the dashboard bind, and every
//! external command is timeout-bounded.

use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Tools we ensure: (binary name, release asset name). Unraid is x86_64-only
/// as a product, so amd64 assets are sufficient.
const TOOLS: &[(&str, &str)] = &[
    // Official Proxmox static client (extracted from their signed deb by CI).
    // Needed for PBS backup destinations; pxar for file-level archives.
    ("proxmox-backup-client", "proxmox-backup-client-x86_64"),
    ("pxar", "pxar-x86_64"),
    // Static musl smartctl — Unraid ships its own smartctl, so this only
    // downloads on stripped-down or future variants where it's absent
    // (the on-PATH check below skips natively-present tools entirely).
    ("smartctl", "smartctl-x86_64"),
];

const RELEASE_BASE: &str =
    "https://github.com/wolfsoftwaresystemsltd/WolfStack/releases/download/unraid-tools-v1";

/// Same array-backed appdata dir setup.sh installs the agent into — /etc and
/// /usr/local/bin are RAM, this survives reboots.
const TOOLS_DIR: &str = "/mnt/user/appdata/wolfstack/tools";
const LINK_DIR: &str = "/usr/local/bin";

pub fn is_unraid() -> bool {
    Path::new("/etc/unraid-version").exists()
}

/// Ensure every manifest tool is usable on this Unraid node. No-op on
/// non-Unraid systems and on tools already on PATH. Logs state changes only:
/// silent when everything is already in place.
pub fn ensure_unraid_tools() {
    if !is_unraid() {
        return;
    }
    if std::env::consts::ARCH != "x86_64" {
        // Unraid is x86_64-only; anything else has no assets to fetch.
        return;
    }
    for (bin, asset) in TOOLS {
        ensure_tool(bin, asset);
    }
}

fn ensure_tool(bin: &str, asset: &str) {
    // Already runnable (native Unraid tool, or our link from a prior pass)?
    // `which` is present on Unraid (busybox/coreutils both ship it).
    let on_path = Command::new("which").arg(bin).output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if on_path {
        return;
    }

    let persisted = format!("{}/{}", TOOLS_DIR, bin);
    if !Path::new(&persisted).exists() {
        if let Err(e) = download_tool(asset, &persisted) {
            warn!("unraid tools: could not fetch {}: {} — the feature needing it will report it missing", bin, e);
            return;
        }
        info!("unraid tools: downloaded {} → {}", bin, persisted);
    }

    // Re-link into RAM-backed /usr/local/bin (fresh every boot).
    let link = format!("{}/{}", LINK_DIR, bin);
    let _ = std::fs::remove_file(&link); // stale symlink from a previous boot image
    match std::os::unix::fs::symlink(&persisted, &link) {
        Ok(()) => info!("unraid tools: {} linked → {}", bin, link),
        Err(e) => warn!("unraid tools: could not link {} into {}: {}", bin, LINK_DIR, e),
    }
}

/// Download one asset to `dest` via curl (present on every Unraid — setup.sh
/// itself arrives through it). Temp-file + rename so a cut connection never
/// leaves a half-written binary where a feature might exec it. Bounded:
/// 15s connect, 10min total (assets are up to ~20MB, lines can be slow).
fn download_tool(asset: &str, dest: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(dest).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {}", dir.display(), e))?;
    }
    let url = format!("{}/{}", RELEASE_BASE, asset);
    let tmp = format!("{}.download", dest);
    let out = Command::new("curl")
        .args(["-fSL", "--connect-timeout", "15", "--max-time", "600", "-o", &tmp, &url])
        .output()
        .map_err(|e| format!("failed to run curl: {}", e))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "download of {} failed: {}",
            url,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // Executable before the rename so the file is never visible non-runnable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {}", tmp, e))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| format!("rename into place: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_assets_are_x86_64_suffixed() {
        // The release only carries x86_64 assets (Unraid is x86_64-only);
        // a manifest entry without the suffix would 404 on every node.
        for (bin, asset) in TOOLS {
            assert!(asset.ends_with("-x86_64"), "{} asset {} lacks arch suffix", bin, asset);
            assert!(!bin.contains('/'), "{} must be a bare binary name", bin);
        }
    }

    #[test]
    fn non_unraid_is_a_noop() {
        // On any dev/CI box without /etc/unraid-version this must return
        // without touching the filesystem — guard the guard.
        if !is_unraid() {
            ensure_unraid_tools(); // must not panic, download, or link anything
        }
    }
}
