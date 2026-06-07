// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Detection + install hooks for the reverse-proxy software on the
//! local node — nginx or WolfProxy. Both read the same nginx-format
//! config files, so the runtime question is operational (which
//! systemd unit is in front of port 80) rather than configurational.
//!
//! Separated from `http_proxy` because it's useful before the proxy
//! data model exists — the "no reverse proxy installed" banner needs
//! to render even when there are zero proxies configured.

use serde::Serialize;
use std::process::Command;

/// Snapshot of what reverse-proxy software is available on the local
/// node. Drives the UI status panel ("Active: wolfproxy" badge,
/// install CTA when neither is present) and any future apply pipeline
/// that needs to pick a reload command.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyRuntimeStatus {
    /// `nginx -v` succeeds.
    pub nginx_installed: bool,
    /// `systemctl is-active --quiet nginx` exits 0.
    pub nginx_active: bool,
    /// wolfproxy binary present in PATH or a known install location.
    pub wolfproxy_installed: bool,
    /// `systemctl is-active --quiet wolfproxy` exits 0.
    pub wolfproxy_active: bool,
}

impl ProxyRuntimeStatus {
    pub fn any_installed(&self) -> bool {
        self.nginx_installed || self.wolfproxy_installed
    }

    /// Which runtime is currently serving traffic on this node. Both
    /// active → wolfproxy wins (it's Wolf's own product; mid-migration
    /// from nginx to wolfproxy is the realistic both-active scenario).
    pub fn active_runtime(&self) -> Option<&'static str> {
        if self.wolfproxy_active { return Some("wolfproxy"); }
        if self.nginx_active { return Some("nginx"); }
        None
    }
}

pub fn detect_runtime() -> ProxyRuntimeStatus {
    let nginx_installed = Command::new("nginx").arg("-v")
        .output().map(|o| o.status.success()).unwrap_or(false);
    let nginx_active = systemctl_active("nginx");
    let wolfproxy_installed = wolfproxy_binary_path().is_some();
    let wolfproxy_active = systemctl_active("wolfproxy");
    ProxyRuntimeStatus { nginx_installed, nginx_active, wolfproxy_installed, wolfproxy_active }
}

fn systemctl_active(unit: &str) -> bool {
    Command::new("systemctl").args(["is-active", "--quiet", unit])
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Probe stable install locations for wolfproxy. Pre-v0.4.4 it lived
/// under /opt/wolfproxy/target/release/wolfproxy; the precompiled
/// installer (v0.4.4+) drops it at /usr/local/bin/wolfproxy and
/// symlinks the old path. Either way one of these resolves it.
fn wolfproxy_binary_path() -> Option<String> {
    for cand in &[
        "/usr/local/bin/wolfproxy",
        "/opt/wolfproxy/target/release/wolfproxy",
        "/opt/wolfproxy/wolfproxy",
        "/usr/bin/wolfproxy",
    ] {
        if std::path::Path::new(cand).exists() && wolfproxy_version_ok(cand) {
            return Some((*cand).to_string());
        }
    }
    if wolfproxy_version_ok("wolfproxy") {
        return Some("wolfproxy".into());
    }
    None
}

/// Probe `<bin> --version` under a hard timeout. A correct wolfproxy (v0.4.7+)
/// prints its version and exits instantly; a pre-v0.4.7 binary ignored argv and
/// started a full server on `--version`, so an unbounded probe could bind a
/// port (orphan) or hang this detection — which runs on every status poll —
/// forever. `timeout` caps the probe and TERMs any stray it spawned.
fn wolfproxy_version_ok(bin: &str) -> bool {
    Command::new("timeout")
        .args(["5", bin, "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
