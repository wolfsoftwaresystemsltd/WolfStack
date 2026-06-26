// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Persistent port configuration.
//!
//! WolfStack listens on up to three ports:
//! - `api` — main HTTP(S) API and dashboard (default 8553) — always bound
//! - `inter_node` — plain HTTP for legacy inter-node fallback + cluster-home
//!   browser flow (default api+1) — **only bound when the loaded TLS cert is
//!   self-signed**. Operators with a real CA-signed cert never bind this
//!   listener, eliminating the 8554/RTSP conflict with Frigate/MediaMTX/etc.
//!   See v23.12 release notes for the rationale.
//! - `status` — public status pages (default 8550) — always bound
//!
//! Per-node config lives in `/etc/wolfstack/ports.json` and is the persistent
//! source of truth — the **Node Ports** settings panel writes it. A CLI
//! `--port` flag overrides the API port for genuine one-off **manual** launches
//! (`wolfstack --port N` from a shell). When WolfStack runs as its systemd
//! service, a `--port` baked into the unit by an old `setup.sh` is reconciled
//! into `ports.json` once (see [`reconcile_baked_port`]) and then ignored, so
//! `ports.json` (and the UI) stay authoritative — a baked `--port` no longer
//! silently overrides the configured ports or pins `inter_node` to `api + 1`.
//! Both `inter_node` and `status` have auto-fallbacks (`reserve_inter_node_port`,
//! `reserve_status_port`) so a colliding service (e.g. WolfDisk on 8550, Frigate
//! on 8554) doesn't stop the daemon from starting.

use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use tracing::warn;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PortConfig {
    #[serde(default = "default_api")]
    pub api: u16,
    #[serde(default = "default_inter_node")]
    pub inter_node: u16,
    #[serde(default = "default_status")]
    pub status: u16,
}

fn default_api() -> u16 { 8553 }
fn default_inter_node() -> u16 { 8554 }
fn default_status() -> u16 { 8550 }

/// Reconcile a systemd-unit-baked `--port N` into a loaded [`PortConfig`].
///
/// Background: `setup.sh` historically wrote `--port $WS_PORT` into the
/// `ExecStart` line of `wolfstack.service`. The CLI flag overrode `ports.json`
/// for BOTH the api port and the inter-node port (the latter was forced to
/// `port + 1`), which made the **Node Ports** settings panel a silent no-op
/// for everyone on a default install — the UI wrote `ports.json`, but the
/// running daemon ignored it. See [RutgerDiehard]'s 8554/go2rtc clash.
///
/// To make `ports.json` (and the UI) authoritative WITHOUT changing the port
/// an existing install currently runs on, we reconcile the baked port once:
/// for each field, if `ports.json` still holds the compiled-in default, seed
/// it from the baked value — this preserves a custom `--port` that never had a
/// matching `ports.json`. If the operator already set a non-default value
/// (e.g. via the UI), keep it: that is the deliberate choice the baked `--port`
/// was wrongly overriding. Returns the (possibly updated) config plus whether
/// anything changed (so the caller only re-persists on a real change).
pub fn reconcile_baked_port(mut cfg: PortConfig, baked_port: u16) -> (PortConfig, bool) {
    let mut changed = false;
    // api: only seed when ports.json is still the default AND the unit forced
    // a different port (so the running api port is preserved, not reset).
    if cfg.api == default_api() && baked_port != default_api() {
        cfg.api = baked_port;
        changed = true;
    }
    // inter_node historically derived as api+1 from the baked --port. Mirror
    // that only when ports.json hasn't been given an explicit inter_node.
    let baked_inter = baked_port.saturating_add(1);
    if cfg.inter_node == default_inter_node() && baked_inter != default_inter_node() {
        cfg.inter_node = baked_inter;
        changed = true;
    }
    (cfg, changed)
}

/// The api + inter-node ports resolved for a launch, plus an optional config to
/// persist when a systemd-baked `--port` had to be reconciled into `ports.json`.
pub struct ResolvedApiPorts {
    pub api: u16,
    /// *Preferred* inter-node port; the actual bind may shift via
    /// [`reserve_inter_node_port`] on a collision (and only binds at all on
    /// self-signed-cert installs).
    pub inter_node_pref: u16,
    /// `Some(cfg)` when `ports.json` should be re-written (a baked `--port` was
    /// reconciled in); `None` when nothing changed.
    pub persist: Option<PortConfig>,
}

/// Decide the api + inter-node ports for this launch.
///
/// - **Manual shell launch** (`running_as_service == false`): a `--port` is a
///   genuine one-off override and pulls `inter_node = port + 1` with it, the
///   historical behaviour. `ports.json` fills in when no flag is given.
/// - **systemd service** (`running_as_service == true`, i.e. `INVOCATION_ID`
///   is set): `ports.json` is authoritative. A `--port` baked into the unit by
///   an old `setup.sh` is reconciled into `ports.json` once (see
///   [`reconcile_baked_port`]) and otherwise ignored — so the Node Ports panel
///   actually takes effect and `inter_node` is no longer pinned to `api + 1`.
pub fn resolve_api_ports(
    cli_port: Option<u16>,
    running_as_service: bool,
    cfg: PortConfig,
) -> ResolvedApiPorts {
    if !running_as_service {
        return match cli_port {
            Some(p) => ResolvedApiPorts {
                api: p,
                inter_node_pref: p.saturating_add(1),
                persist: None,
            },
            None => ResolvedApiPorts {
                api: cfg.api,
                inter_node_pref: cfg.inter_node,
                persist: None,
            },
        };
    }
    match cli_port {
        Some(baked) => {
            let (reconciled, changed) = reconcile_baked_port(cfg, baked);
            ResolvedApiPorts {
                api: reconciled.api,
                inter_node_pref: reconciled.inter_node,
                persist: if changed { Some(reconciled) } else { None },
            }
        }
        None => ResolvedApiPorts {
            api: cfg.api,
            inter_node_pref: cfg.inter_node,
            persist: None,
        },
    }
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            api: default_api(),
            inter_node: default_inter_node(),
            status: default_status(),
        }
    }
}

impl PortConfig {
    pub fn load() -> Self {
        let path = crate::paths::get().ports_config.clone();
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                warn!("ports.json parse error ({}), using defaults", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = crate::paths::get().ports_config.clone();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }
}

/// Try to reserve the preferred status port. If it's taken, scan upward through
/// the range and pick the first free one — persists the choice back to ports.json
/// so subsequent restarts use the same port. Returns the chosen port, or the
/// preferred port unchanged if nothing else is free (caller will then surface
/// the bind error like before).
pub fn reserve_status_port(bind: &str, preferred: u16, range: std::ops::RangeInclusive<u16>) -> u16 {
    if port_is_free(bind, preferred) {
        return preferred;
    }
    for p in range {
        if p == preferred { continue; }
        if port_is_free(bind, p) {
            warn!("status port {} taken, falling back to {}", preferred, p);
            let mut cfg = PortConfig::load();
            if cfg.status != p {
                cfg.status = p;
                if let Err(e) = cfg.save() {
                    warn!("failed to persist new status port to ports.json: {}", e);
                }
            }
            return p;
        }
    }
    warn!("no free status port found in scan range, leaving as {}", preferred);
    preferred
}

/// Same as `reserve_status_port`, but for the inter-node HTTP port. Only
/// called from the self-signed-cert branch in `main.rs` (real-cert nodes
/// don't bind a second listener at all in v23.12+). Skips any port already
/// claimed by the api/status listeners — `avoid` carries those.
pub fn reserve_inter_node_port(
    bind: &str,
    preferred: u16,
    range: std::ops::RangeInclusive<u16>,
    avoid: &[u16],
) -> u16 {
    if !avoid.contains(&preferred) && port_is_free(bind, preferred) {
        return preferred;
    }
    for p in range {
        if p == preferred { continue; }
        if avoid.contains(&p) { continue; }
        if port_is_free(bind, p) {
            warn!("inter-node port {} taken, falling back to {}", preferred, p);
            let mut cfg = PortConfig::load();
            if cfg.inter_node != p {
                cfg.inter_node = p;
                if let Err(e) = cfg.save() {
                    warn!("failed to persist new inter-node port to ports.json: {}", e);
                }
            }
            return p;
        }
    }
    warn!("no free inter-node port found in scan range, leaving as {}", preferred);
    preferred
}

fn port_is_free(bind: &str, port: u16) -> bool {
    TcpListener::bind((bind, port)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(api: u16, inter: u16, status: u16) -> PortConfig {
        PortConfig { api, inter_node: inter, status }
    }

    #[test]
    fn default_install_baked_default_port_is_noop() {
        // Unit has --port 8553, ports.json is defaults → nothing changes, and
        // we must NOT write a file (changed = false).
        let (out, changed) = reconcile_baked_port(PortConfig::default(), 8553);
        assert!(!changed);
        assert_eq!(out.api, 8553);
        assert_eq!(out.inter_node, 8554);
    }

    #[test]
    fn ui_set_ports_win_over_baked_default_port() {
        // RutgerDiehard: unit baked --port 8553, operator set api=8556 /
        // inter_node=8557 via the UI. The UI values must survive, freeing 8554.
        let (out, changed) = reconcile_baked_port(cfg(8556, 8557, 8550), 8553);
        assert!(!changed);
        assert_eq!(out.api, 8556);
        assert_eq!(out.inter_node, 8557);
    }

    #[test]
    fn custom_baked_port_without_ports_json_is_preserved() {
        // Unit baked --port 9000, no prior ports.json (defaults loaded) →
        // seed both fields so the node keeps running on 9000/9001.
        let (out, changed) = reconcile_baked_port(PortConfig::default(), 9000);
        assert!(changed);
        assert_eq!(out.api, 9000);
        assert_eq!(out.inter_node, 9001);
    }

    #[test]
    fn second_boot_after_reconcile_does_not_rewrite() {
        // Once ports.json holds the seeded custom port, a subsequent boot with
        // the same baked --port must be a no-op (no churn-writing every start).
        let (out, changed) = reconcile_baked_port(cfg(9000, 9001, 8550), 9000);
        assert!(!changed);
        assert_eq!(out.api, 9000);
        assert_eq!(out.inter_node, 9001);
    }

    #[test]
    fn custom_baked_port_does_not_clobber_explicit_inter_node() {
        // Operator baked --port 9000 but also set inter_node=9500 in the UI:
        // keep the explicit inter_node, only seed the still-default api.
        let (out, changed) = reconcile_baked_port(cfg(8553, 9500, 8550), 9000);
        assert!(changed);
        assert_eq!(out.api, 9000);
        assert_eq!(out.inter_node, 9500);
    }

    #[test]
    fn manual_launch_port_flag_overrides_and_pulls_inter_node() {
        // `wolfstack --port 9000` from a shell (not systemd): one-off override,
        // inter_node = port+1, nothing persisted.
        let r = resolve_api_ports(Some(9000), false, cfg(8556, 8557, 8550));
        assert_eq!(r.api, 9000);
        assert_eq!(r.inter_node_pref, 9001);
        assert!(r.persist.is_none());
    }

    #[test]
    fn manual_launch_no_flag_uses_ports_json() {
        let r = resolve_api_ports(None, false, cfg(8556, 8557, 8550));
        assert_eq!(r.api, 8556);
        assert_eq!(r.inter_node_pref, 8557);
        assert!(r.persist.is_none());
    }

    #[test]
    fn service_ignores_baked_default_port_and_honours_ui_ports() {
        // The RutgerDiehard fix end-to-end: systemd unit baked --port 8553 but
        // the operator set 8556/8557 via the UI → those win, 8554 is freed,
        // and nothing needs re-persisting.
        let r = resolve_api_ports(Some(8553), true, cfg(8556, 8557, 8550));
        assert_eq!(r.api, 8556);
        assert_eq!(r.inter_node_pref, 8557);
        assert!(r.persist.is_none());
    }

    #[test]
    fn service_default_install_stays_on_defaults_without_writing() {
        let r = resolve_api_ports(Some(8553), true, PortConfig::default());
        assert_eq!(r.api, 8553);
        assert_eq!(r.inter_node_pref, 8554);
        assert!(r.persist.is_none(), "a default install must not spuriously write ports.json");
    }

    #[test]
    fn service_custom_baked_port_is_preserved_and_persisted() {
        // Custom --port 9000 with no prior ports.json: keep running on 9000/9001
        // AND persist so the value survives once the unit drops --port.
        let r = resolve_api_ports(Some(9000), true, PortConfig::default());
        assert_eq!(r.api, 9000);
        assert_eq!(r.inter_node_pref, 9001);
        let persisted = r.persist.expect("custom baked port must be persisted");
        assert_eq!(persisted.api, 9000);
        assert_eq!(persisted.inter_node, 9001);
    }
}
