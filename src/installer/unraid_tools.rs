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
use std::sync::atomic::Ordering;
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
    // 1. A daemon WE started and that is still alive is authoritative —
    //    no probe involved. This is the check that makes a spawn storm
    //    impossible.
    {
        let mut owned = wolfnet_child();
        if let Some(child) = owned.as_mut() {
            match child.try_wait() {
                Ok(None) => return,               // still running
                Ok(Some(status)) => {             // exited; try_wait reaped it
                    warn!("unraid wolfnet: daemon exited ({}) — restarting after backoff", status);
                    *owned = None;
                }
                // Can't tell whether our own child is alive — never spawn
                // on uncertainty.
                Err(e) => {
                    warn!("unraid wolfnet: cannot check daemon state: {} — not starting another", e);
                    return;
                }
            }
        }
    }

    // 2. Backoff: a daemon that dies immediately must not be respawned
    //    every single tick. Doubles to a 1h ceiling and resets once one
    //    survives a tick.
    let now = now_secs();
    if now < WOLFNET_RETRY_AFTER.load(Ordering::Relaxed) {
        return;
    }

    // 3. Someone else's wolfnet (manual install, or ours from before an
    //    agent restart)? Read procfs directly: `pgrep -x` was the old
    //    check and its exit status is ambiguous on busybox, where an
    //    unsupported flag looks exactly like "no match" — which meant a
    //    new VPN daemon every 60 seconds, forever (klas, Unraid,
    //    2026-08-12). Unknown => do NOT spawn.
    match wolfnet_running_externally() {
        Some(true) => return,
        None => {
            warn!("unraid wolfnet: could not determine whether a daemon is already running — not starting another");
            return;
        }
        Some(false) => {}
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
        Ok(child) => {
            info!("unraid wolfnet: daemon started (pid {})", child.id());
            // Keep the Child: the next tick calls try_wait() on it, which
            // both answers "is it alive?" authoritatively and reaps it
            // when it isn't. (The old code moved the Child into a waiter
            // thread, leaving the supervisor with nothing to check but a
            // pgrep probe.)
            *wolfnet_child() = Some(child);
            // Next failure waits at least the base interval; a daemon that
            // survives resets this below.
            WOLFNET_RETRY_AFTER.store(now_secs() + WOLFNET_RETRY_BASE_SECS, Ordering::Relaxed);
            WOLFNET_RETRY_BACKOFF.store(WOLFNET_RETRY_BASE_SECS, Ordering::Relaxed);
        }
        Err(e) => {
            // Exponential backoff, capped at an hour: a host that can
            // never start wolfnet (missing /dev/net/tun, bad config)
            // must not pay for a spawn attempt every minute forever.
            let next = (WOLFNET_RETRY_BACKOFF.load(Ordering::Relaxed) * 2)
                .clamp(WOLFNET_RETRY_BASE_SECS, WOLFNET_RETRY_MAX_SECS);
            WOLFNET_RETRY_BACKOFF.store(next, Ordering::Relaxed);
            WOLFNET_RETRY_AFTER.store(now_secs() + next, Ordering::Relaxed);
            warn!("unraid wolfnet: failed to start daemon: {} — next attempt in {}s", e, next);
        }
    }
}

/// The wolfnet daemon this process started, if any. Owning the `Child`
/// is what makes liveness authoritative instead of probe-dependent.
fn wolfnet_child() -> std::sync::MutexGuard<'static, Option<std::process::Child>> {
    static CHILD: std::sync::LazyLock<std::sync::Mutex<Option<std::process::Child>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
    match CHILD.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

const WOLFNET_RETRY_BASE_SECS: u64 = 60;
const WOLFNET_RETRY_MAX_SECS: u64 = 3600;
static WOLFNET_RETRY_AFTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WOLFNET_RETRY_BACKOFF: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(WOLFNET_RETRY_BASE_SECS);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Is a wolfnet daemon running that we don't own? Reads `/proc/<pid>/comm`
/// rather than shelling out, so the answer doesn't depend on which
/// `pgrep` the distro ships. `None` means "couldn't tell" — callers must
/// treat that as "do not spawn", never as "not running".
///
/// Runs once per supervision tick (60s), so this is not a hot scan —
/// see tests/resource_safety.rs for the scans that must stay cached.
fn wolfnet_running_externally() -> Option<bool> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        // A process can exit mid-scan; a missing comm is not an error.
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
            if comm.trim() == "wolfnet" {
                return Some(true);
            }
        }
    }
    Some(false)
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

#[cfg(test)]
mod wolfnet_supervision_tests {
    use super::*;

    #[test]
    fn liveness_probe_never_reports_false_on_uncertainty() {
        // The supervisor must only spawn on a DEFINITE "not running".
        // `pgrep -x` was the old probe and its exit status is ambiguous
        // on busybox — an unsupported flag looks identical to "no
        // match", which spawned a new VPN daemon every 60s forever
        // (klas, Unraid, 2026-08-12). The procfs reader answers
        // Some(true)/Some(false) only when it actually knows.
        let answer = wolfnet_running_externally();
        // Deliberately NOT asserting true or false: the answer depends
        // on whether the host happens to run wolfnet (the dev box does,
        // which is how this probe was confirmed against a live process).
        // The invariant under test is that with /proc readable the probe
        // commits to a DEFINITE answer, and that "couldn't tell" is
        // None — never Some(false), which is the value that would let
        // the supervisor spawn.
        if std::path::Path::new("/proc/self/comm").exists() {
            assert!(answer.is_some(), "with /proc readable the probe must give a definite answer");
        }
        // Whatever it says, it must agree with itself — a probe that
        // flickered would spawn on the tick that happened to say false.
        assert_eq!(answer, wolfnet_running_externally(), "probe must be stable across calls");
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        // Mirrors the failure path's arithmetic: doubling, floored at
        // the base interval and capped at an hour, so a host that can
        // never start wolfnet stops paying a spawn per minute.
        let mut backoff = WOLFNET_RETRY_BASE_SECS;
        let mut seen = Vec::new();
        for _ in 0..10 {
            backoff = (backoff * 2).clamp(WOLFNET_RETRY_BASE_SECS, WOLFNET_RETRY_MAX_SECS);
            seen.push(backoff);
        }
        assert!(seen[0] > WOLFNET_RETRY_BASE_SECS, "backoff must grow after a failure");
        assert!(seen.iter().all(|s| *s <= WOLFNET_RETRY_MAX_SECS), "backoff must be capped");
        assert_eq!(*seen.last().unwrap(), WOLFNET_RETRY_MAX_SECS, "repeated failure settles at the cap");
    }

    #[test]
    fn supervision_is_a_no_op_off_unraid() {
        // Every path is guarded by is_unraid(); on a non-Unraid host
        // this must not spawn, scan, or touch the filesystem.
        if !is_unraid() {
            ensure_unraid_wolfnet();
            assert!(wolfnet_child().is_none(), "no daemon may be owned on a non-Unraid host");
        }
    }
}
