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

/// WolfNet ships its own prebuilt static binaries on the WolfNet repo's
/// latest release — the same assets setup.sh downloads on every other
/// distro (setup.sh: `PREBUILT_URL=".../releases/latest/download"`,
/// assets `wolfnet-x86_64` / `wolfnetctl-x86_64`). Unraid can't run
/// setup.sh (Slackware — no apt/dnf/pacman, and its /etc is RAM), so
/// the agent bundles WolfNet the same way it bundles the other tools
/// (klas, 2026-08-11: "wolfnet could be bundled into the agent").
const WOLFNET_RELEASE_BASE: &str =
    "https://github.com/wolfsoftwaresystemsltd/WolfNet/releases/latest/download";
const WOLFNET_TOOLS: &[(&str, &str)] = &[
    ("wolfnet", "wolfnet-x86_64"),
    ("wolfnetctl", "wolfnetctl-x86_64"),
];

/// Same array-backed appdata dir setup.sh installs the agent into — /etc and
/// /usr/local/bin are RAM, this survives reboots.
const TOOLS_DIR: &str = "/mnt/user/appdata/wolfstack/tools";
const LINK_DIR: &str = "/usr/local/bin";

/// WolfNet state that must survive reboots: config.toml + private.key.
/// `/etc/wolfnet` (the path every wolfnet default and every WolfStack
/// networking feature uses) becomes a symlink to this dir.
const WOLFNET_ETC: &str = "/etc/wolfnet";
const WOLFNET_APPDATA: &str = "/mnt/user/appdata/wolfstack/wolfnet";

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
        ensure_tool(bin, asset, RELEASE_BASE);
    }
    ensure_unraid_wolfnet();
    // Supervision tick: Unraid has no systemd, so the agent keeps the
    // wolfnet daemon alive. 60s matches how fast a mesh outage becomes
    // operator-visible without burning cycles — each pass is a `which`
    // + symlink stat + pgrep unless something actually needs doing.
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        ensure_unraid_wolfnet();
    });
}

/// Bundle WolfNet on Unraid: binaries persisted + linked like every
/// other tool, `/etc/wolfnet` symlinked onto the array so the identity
/// key survives reboots, and the daemon started when a config exists.
/// Also called from the supervision tick (see `supervise_forever`) so
/// a crashed daemon comes back within a minute.
pub fn ensure_unraid_wolfnet() {
    if !is_unraid() || std::env::consts::ARCH != "x86_64" {
        return;
    }
    for (bin, asset) in WOLFNET_TOOLS {
        ensure_tool(bin, asset, WOLFNET_RELEASE_BASE);
    }
    persist_wolfnet_etc();
    start_wolfnet_if_configured();
}

/// Make `/etc/wolfnet` a symlink to the array-backed appdata dir.
/// A real directory left by a manual install is migrated (copied) into
/// appdata first so an existing identity key is never lost — the
/// private key IS the node's mesh identity; losing it would orphan the
/// node from every peer.
fn persist_wolfnet_etc() {
    let etc = Path::new(WOLFNET_ETC);
    if let Err(e) = std::fs::create_dir_all(WOLFNET_APPDATA) {
        warn!("unraid wolfnet: cannot create {}: {}", WOLFNET_APPDATA, e);
        return;
    }
    // Already the symlink we want? (symlink_metadata: never follow.)
    if let Ok(meta) = std::fs::symlink_metadata(etc) {
        if meta.file_type().is_symlink() {
            return;
        }
        // Real dir from a manual install this boot — migrate contents
        // that appdata doesn't already have (never overwrite: appdata
        // is the durable copy, RAM /etc is the transient one). The dir
        // is only replaced when EVERY entry migrated cleanly — a
        // failed or skipped copy followed by remove_dir_all would
        // destroy the one copy of the node's mesh identity key.
        if meta.is_dir() {
            let mut migration_clean = true;
            match std::fs::read_dir(etc) {
                Ok(entries) => {
                    for ent in entries.flatten() {
                        let src = ent.path();
                        if src.is_dir() {
                            // wolfnet keeps a flat config dir; anything
                            // deeper is operator-made — don't guess,
                            // don't delete.
                            warn!("unraid wolfnet: {} contains a subdirectory ({:?}) — leaving /etc/wolfnet as-is; move it into {} manually", WOLFNET_ETC, ent.file_name(), WOLFNET_APPDATA);
                            migration_clean = false;
                            continue;
                        }
                        let dest = Path::new(WOLFNET_APPDATA).join(ent.file_name());
                        if !dest.exists() {
                            if let Err(e) = std::fs::copy(&src, &dest) {
                                warn!("unraid wolfnet: migrating {:?}: {}", ent.file_name(), e);
                                migration_clean = false;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("unraid wolfnet: cannot read {}: {}", WOLFNET_ETC, e);
                    migration_clean = false;
                }
            }
            if !migration_clean {
                return; // retry next supervision tick; never delete unmigrated state
            }
            if let Err(e) = std::fs::remove_dir_all(etc) {
                warn!("unraid wolfnet: cannot replace {} with symlink: {}", WOLFNET_ETC, e);
                return;
            }
        } else if std::fs::remove_file(etc).is_err() {
            return;
        }
    }
    match std::os::unix::fs::symlink(WOLFNET_APPDATA, etc) {
        Ok(()) => info!("unraid wolfnet: {} → {}", WOLFNET_ETC, WOLFNET_APPDATA),
        Err(e) => warn!("unraid wolfnet: symlink {}: {}", WOLFNET_ETC, e),
    }
}

/// Start the wolfnet daemon when a config exists and it isn't already
/// running. Unraid has no systemd — the agent is the supervisor. The
/// invocation matches setup.sh's systemd unit verbatim
/// (`ExecStart=/usr/local/bin/wolfnet --config /etc/wolfnet/config.toml`);
/// pgrep is the same liveness check src/networking uses for reloads.
fn start_wolfnet_if_configured() {
    if !Path::new(WOLFNET_APPDATA).join("config.toml").exists() {
        return; // not configured — nothing to run
    }
    let running = Command::new("pgrep").args(["-x", "wolfnet"]).output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if running {
        return;
    }
    let log = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(format!("{}/wolfnet.log", WOLFNET_APPDATA));
    let Ok(log) = log else {
        warn!("unraid wolfnet: cannot open wolfnet.log — not starting");
        return;
    };
    let err = match log.try_clone() {
        Ok(c) => c,
        Err(_) => { warn!("unraid wolfnet: cannot clone log handle — not starting"); return; }
    };
    match Command::new(format!("{}/wolfnet", LINK_DIR))
        .args(["--config", "/etc/wolfnet/config.toml"])
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(err)
        .spawn()
    {
        Ok(mut child) => {
            info!("unraid wolfnet: daemon started (pid {})", child.id());
            // Reap on exit — a dropped Child is never waited on, so a
            // crashed daemon would otherwise sit as a zombie until the
            // agent restarts. The supervision tick restarts it.
            std::thread::spawn(move || { let _ = child.wait(); });
        }
        Err(e) => warn!("unraid wolfnet: failed to start daemon: {}", e),
    }
}

fn ensure_tool(bin: &str, asset: &str, base: &str) {
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
        if let Err(e) = download_tool(base, asset, &persisted) {
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
fn download_tool(base: &str, asset: &str, dest: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(dest).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {}", dir.display(), e))?;
    }
    let url = format!("{}/{}", base, asset);
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
        for (bin, asset) in TOOLS.iter().chain(WOLFNET_TOOLS) {
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
