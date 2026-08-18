// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Self-hosted S3 servers (Garage, MinIO) and the rclone engine as
//! storage providers: detection (native binary/systemd AND Docker
//! containers deployed from the App Store), native install for Garage
//! and rclone, and App Store hand-off for MinIO.
//!
//! Why MinIO has no native installer: MinIO stopped maintaining
//! pre-compiled community server binaries (dl.min.io builds are frozen;
//! upstream recommends source builds or containers — verified
//! 2026-08-18). Shipping an installer that pulls a stale unmaintained
//! binary would be a disservice, so MinIO's install path is the App
//! Store Docker manifest (`appstore/mod.rs` id "minio"), which tracks
//! `minio/minio:latest`.

use std::process::Command;
use tracing::{info, warn};

/// Garage release pinned for native installs. Deliberately a constant,
/// not "latest from the API": the binary is fetched over the network as
/// root, so pinning keeps the supply chain reviewable — bumping it is a
/// one-line change that goes through review like any other. URL pattern
/// verified 2026-08-18 (HTTP 200 for both targets); v2.3.0 is live-proven
/// on asset-mirror-1 since 2026-08-14.
const GARAGE_VERSION: &str = "v2.3.0";
const GARAGE_DOWNLOAD_BASE: &str = "https://garagehq.deuxfleurs.fr/_releases";

const GARAGE_BIN: &str = "/usr/local/bin/garage";
const GARAGE_CONFIG_DIR: &str = "/etc/garage";
const GARAGE_CONFIG: &str = "/etc/garage/garage.toml";
const GARAGE_UNIT_PATH: &str = "/etc/systemd/system/garage.service";
const GARAGE_DATA_DIR: &str = "/var/lib/garage";

// ─── Detection ───

pub fn has_rclone() -> bool {
    Command::new("rclone").arg("version").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn has_garage_binary() -> bool {
    Command::new("garage").arg("--version").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn has_minio_binary() -> bool {
    Command::new("minio").arg("--version").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// First line of `<bin> --version` / `<bin> version`, for the provider
/// card. e.g. "garage v2.3.0 [features: …]" → "garage v2.3.0".
pub fn binary_version(bin: &str, arg: &str) -> Option<String> {
    let out = Command::new(bin).arg(arg).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let first = String::from_utf8_lossy(&out.stdout);
    let first = first.lines().next()?.trim();
    if first.is_empty() {
        return None;
    }
    // Strip garage's long feature list — the card wants "garage v2.3.0",
    // not three lines of build flags.
    Some(first.split('[').next().unwrap_or(first).trim().to_string())
}

/// Name of a RUNNING Docker container whose image matches any needle
/// (e.g. "dxflrs/garage", "minio/minio"). Detects App Store deployments
/// and hand-rolled containers alike. Docker absent/stopped = None.
pub fn docker_instance(image_needles: &[&str]) -> Option<String> {
    let out = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Image}}", "--no-trunc"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut parts = line.split('\t');
        let name = parts.next().unwrap_or("");
        let image = parts.next().unwrap_or("");
        if !name.is_empty() && image_needles.iter().any(|n| image.contains(n)) {
            return Some(name.to_string());
        }
    }
    None
}

// ─── Install: rclone ───

/// Distro-package install, reusing the per-distro table the mount-helper
/// installer already maintains (storage::package_for_helper — "rclone" on
/// every family; EPEL on RHEL clones, same dance as s3fs). Distro builds
/// lag upstream, which is fine here: the sync engine uses long-stable
/// flags (copy/sync/--max-age/--transfers), not new features.
pub fn install_rclone() -> Result<String, String> {
    let (pkg_mgr, pkg_name) = super::package_for_helper("rclone")
        .ok_or_else(|| "No rclone package mapping for this distro".to_string())?;
    if pkg_mgr == "dnf" {
        let _ = Command::new("dnf").args(["install", "-y", "epel-release"]).output();
    }
    let mut args: Vec<&str> = match pkg_mgr {
        "pacman" => vec!["-S", "--noconfirm"],
        "apk" => vec!["add", "--no-cache"],
        _ => vec!["install", "-y"],
    };
    args.push(pkg_name);
    let output = Command::new(pkg_mgr)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", pkg_mgr, e))?;
    if output.status.success() {
        Ok("rclone installed successfully".to_string())
    } else {
        Err(format!("Installation failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── Install: Garage (native single-node) ───

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    use std::fmt::Write;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut s = String::with_capacity(bytes * 2);
    for b in &buf {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// The musl target for this machine, or an error for architectures
/// garage doesn't publish (URL pattern verified for both 2026-08-18).
fn garage_target() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        other => Err(format!(
            "No garage release build for architecture '{}' — deploy the Docker image from the App Store instead",
            other
        )),
    }
}

/// Run the garage CLI against the installed config, capturing combined
/// output for error reporting.
fn garage_cli(args: &[&str]) -> Result<String, String> {
    let output = Command::new(GARAGE_BIN)
        .arg("-c")
        .arg(GARAGE_CONFIG)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run garage: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "garage {} failed: {}{}",
            args.first().unwrap_or(&""),
            stdout.trim(),
            stderr.trim()
        ))
    }
}

/// Full single-node Garage install: pinned binary → config with fresh
/// secrets → systemd unit → single-node layout → a bucket-creating API
/// key saved as a WolfStack S3 remote, so buckets/mounts/sync work on
/// the new server with zero manual credential copying.
///
/// Config shape and CLI sequence follow the official quick-start plus
/// the live asset-mirror-1 install (garage v2.3.0): `[s3_web]` is
/// optional and omitted; sqlite metadata engine; region "garage".
/// Idempotent-ish: an existing config/unit is kept (we never overwrite
/// an operator's garage.toml), so re-running after a partial failure
/// resumes rather than resetting secrets.
pub fn install_garage() -> Result<String, String> {
    let target = garage_target()?;

    // 1. Binary (skip if the exact pinned version responds).
    let have = binary_version(GARAGE_BIN, "--version");
    if have.as_deref().map(|v| v.contains(GARAGE_VERSION)) != Some(true) {
        let url = format!("{}/{}/{}/garage", GARAGE_DOWNLOAD_BASE, GARAGE_VERSION, target);
        info!("Downloading garage {} from {}", GARAGE_VERSION, url);
        let tmp = format!("{}.download", GARAGE_BIN);
        let output = Command::new("curl")
            .args(["-fsSL", "--max-time", "300", "-o", &tmp, &url])
            .output()
            .map_err(|e| format!("Failed to run curl: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "Download of {} failed: {}",
                url,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        std::fs::rename(&tmp, GARAGE_BIN)
            .map_err(|e| format!("Failed to move garage binary into place: {}", e))?;
        let _ = Command::new("chmod").args(["755", GARAGE_BIN]).output();
        // The binary must actually run on this machine before we build
        // config and services around it.
        if binary_version(GARAGE_BIN, "--version").is_none() {
            return Err("Downloaded garage binary does not execute on this system".to_string());
        }
    }

    // 2. Config — only written if absent; secrets are generated fresh
    // and stay in the 0600 file (admin token is NOT stored anywhere
    // else; WolfStack talks S3, not the admin API, in this phase).
    if !std::path::Path::new(GARAGE_CONFIG).exists() {
        std::fs::create_dir_all(GARAGE_CONFIG_DIR)
            .map_err(|e| format!("Failed to create {}: {}", GARAGE_CONFIG_DIR, e))?;
        std::fs::create_dir_all(format!("{}/meta", GARAGE_DATA_DIR))
            .and_then(|_| std::fs::create_dir_all(format!("{}/data", GARAGE_DATA_DIR)))
            .map_err(|e| format!("Failed to create {}: {}", GARAGE_DATA_DIR, e))?;
        let config = format!(
            "# Generated by WolfStack — single-node Garage.\n\
             # Shape follows the official quick-start; [s3_web] is optional and omitted.\n\
             metadata_dir = \"{data}/meta\"\n\
             data_dir = \"{data}/data\"\n\
             db_engine = \"sqlite\"\n\
             \n\
             replication_factor = 1\n\
             \n\
             rpc_bind_addr = \"127.0.0.1:3901\"\n\
             rpc_public_addr = \"127.0.0.1:3901\"\n\
             rpc_secret = \"{rpc_secret}\"\n\
             \n\
             [s3_api]\n\
             s3_region = \"garage\"\n\
             api_bind_addr = \"[::]:3900\"\n\
             root_domain = \".s3.garage.localhost\"\n\
             \n\
             [admin]\n\
             api_bind_addr = \"127.0.0.1:3903\"\n\
             admin_token = \"{admin_token}\"\n\
             metrics_token = \"{metrics_token}\"\n",
            data = GARAGE_DATA_DIR,
            rpc_secret = random_hex(32),
            admin_token = random_hex(32),
            metrics_token = random_hex(32),
        );
        crate::paths::write_secure(GARAGE_CONFIG, config)
            .map_err(|e| format!("Failed to write {}: {}", GARAGE_CONFIG, e))?;
    }

    // 3. systemd unit (shape mirrors the live-proven asset-mirror-1 unit).
    if !std::path::Path::new(GARAGE_UNIT_PATH).exists() {
        let unit = format!(
            "[Unit]\n\
             Description=Garage S3 object store (installed by WolfStack)\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             ExecStart={} -c {} server\n\
             Restart=always\n\
             RestartSec=5\n\
             LimitNOFILE=131072\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            GARAGE_BIN, GARAGE_CONFIG
        );
        std::fs::write(GARAGE_UNIT_PATH, unit)
            .map_err(|e| format!("Failed to write {}: {}", GARAGE_UNIT_PATH, e))?;
        let _ = Command::new("systemctl").arg("daemon-reload").output();
    }
    let output = Command::new("systemctl")
        .args(["enable", "--now", "garage.service"])
        .output()
        .map_err(|e| format!("Failed to run systemctl: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "garage.service failed to start: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // 4. Wait for the RPC socket, then lay out the single node. `node id -q`
    // prints `<hex-id>@<addr>`; layout assign takes the id (a prefix works).
    let mut node_id = String::new();
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(out) = garage_cli(&["node", "id", "-q"])
            && let Some(id) = out.trim().split('@').next()
            && !id.is_empty()
        {
            node_id = id.to_string();
            break;
        }
    }
    if node_id.is_empty() {
        return Err("garage started but its RPC socket never answered `node id`".to_string());
    }

    // Only assign a layout when the cluster has none — `layout show` on a
    // laid-out node lists the assigned role; re-running install must not
    // stack a second pending layout version.
    let layout = garage_cli(&["layout", "show"]).unwrap_or_default();
    if !layout.contains(&node_id[..node_id.len().min(16)]) {
        // Capacity = free space on the data dir's filesystem, rounded down
        // to GiB, floor 1 GiB. Garage wants an explicit capacity; the free
        // space now is the honest number, and `garage layout assign -c`
        // can resize later.
        let capacity_gb = fs_free_gb(GARAGE_DATA_DIR).max(1);
        garage_cli(&[
            "layout", "assign",
            "-z", "wolfstack",
            "-c", &format!("{}G", capacity_gb),
            &node_id,
        ])?;
        garage_cli(&["layout", "apply", "--version", "1"])?;
    }

    // 5. An S3 key WolfStack can use, saved as a remote. Key output is
    // parsed defensively (labels verified against garage v2.3.0 live
    // output 2026-08-18); if the shape ever changes we fail loudly
    // rather than store junk. Right after `layout apply` the cluster
    // can briefly answer "Layout not ready" (observed live on the same
    // version) — retry for up to ~15s before giving up.
    let key_name = "wolfstack";
    let mut created = String::new();
    let mut last_err = String::new();
    for _ in 0..15 {
        match garage_cli(&["key", "create", key_name]) {
            Ok(out) => {
                created = out;
                break;
            }
            Err(e) if e.contains("Layout not ready") => {
                last_err = e;
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(e) => return Err(e),
        }
    }
    if created.is_empty() {
        return Err(last_err);
    }
    let access_key = extract_labeled(&created, &["Key ID:"]);
    let secret_key = extract_labeled(&created, &["Secret key:"]);
    let (access_key, secret_key) = match (access_key, secret_key) {
        (Some(a), Some(s)) => (a, s),
        _ => {
            return Err(format!(
                "garage key create succeeded but its output shape was unexpected — create a key manually with `garage key create` and save it under Storage → S3 Remotes. Output was:\n{}",
                created.trim()
            ))
        }
    };
    garage_cli(&["key", "allow", "--create-bucket", key_name])?;

    let remote = super::S3Remote {
        id: String::new(),
        name: "garage-local".to_string(),
        provider: "Garage".to_string(),
        endpoint: "http://127.0.0.1:3900".to_string(),
        region: "garage".to_string(),
        access_key_id: access_key,
        secret_access_key: secret_key,
        origin: String::new(),
    };
    if let Err(e) = super::save_s3_remote(remote) {
        // The server is up and the key exists — losing only the remote
        // registration is recoverable, so report rather than fail.
        warn!("garage installed but saving the S3 remote failed: {}", e);
        return Ok(format!(
            "Garage {} installed and running on :3900, but saving its credentials as an S3 remote failed ({}). Create the remote manually under Storage → S3 Remotes.",
            GARAGE_VERSION, e
        ));
    }

    Ok(format!(
        "Garage {} installed: S3 API on :3900 (region \"garage\"), single-node layout applied, credentials saved as S3 remote “garage-local”",
        GARAGE_VERSION
    ))
}

/// Free space of the filesystem holding `path`, in whole GiB.
fn fs_free_gb(path: &str) -> u64 {
    // `df -B1 --output=avail <path>` prints a header line then the byte
    // count — no parsing of human units.
    let out = Command::new("df")
        .args(["-B1", "--output=avail", path])
        .output();
    if let Ok(o) = out
        && o.status.success()
    {
        let text = String::from_utf8_lossy(&o.stdout);
        if let Some(line) = text.lines().nth(1)
            && let Ok(bytes) = line.trim().parse::<u64>()
        {
            return bytes / (1024 * 1024 * 1024);
        }
    }
    0
}

/// Value after any of the given labels on its line, e.g.
/// extract_labeled("Key ID: GK123…", &["Key ID:"]) → "GK123…".
fn extract_labeled(text: &str, labels: &[&str]) -> Option<String> {
    for line in text.lines() {
        for label in labels {
            if let Some(rest) = line.trim().strip_prefix(label) {
                let v = rest.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_labeled_parses_garage_key_output() {
        // VERBATIM `garage key create` output from garage v2.3.0
        // (captured live 2026-08-18) — column-padded labels included.
        let out = "\
==== ACCESS KEY INFORMATION ====\n\
Key ID:              GKe4c6011b3cdefc7c9ba30359\n\
Key name:            wolfstack\n\
Secret key:          0572fc7e6df7cb2a8ebc558d7508984a1b2dd8d5a6ef04d4a481d6e0a63e903c\n\
Created:             2026-08-18 06:38:54.710 +00:00\n\
Validity:            valid\n\
Expiration:          never\n\
\n\
Can create buckets:  false\n";
        assert_eq!(
            extract_labeled(out, &["Key ID:"]).as_deref(),
            Some("GKe4c6011b3cdefc7c9ba30359")
        );
        assert_eq!(
            extract_labeled(out, &["Secret key:"]).as_deref(),
            Some("0572fc7e6df7cb2a8ebc558d7508984a1b2dd8d5a6ef04d4a481d6e0a63e903c")
        );
        assert!(extract_labeled(out, &["Nope:"]).is_none());
        assert!(extract_labeled("Key ID:   \n", &["Key ID:"]).is_none());
    }

    #[test]
    fn version_line_is_trimmed_of_feature_lists() {
        // binary_version strips from '[' — mirror of the live output
        // "garage v2.3.0 [features: bundled-libs, …]".
        let line = "garage v2.3.0 [features: bundled-libs, sqlite]";
        assert_eq!(line.split('[').next().unwrap().trim(), "garage v2.3.0");
    }
}
