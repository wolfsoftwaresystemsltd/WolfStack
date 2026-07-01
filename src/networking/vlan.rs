// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Provider-agnostic 802.1Q VLAN attachments and routed public IPs.
//!
//! ## Why this module exists
//!
//! Operators with dedicated servers from Hetzner / OVH / Equinix /
//! self-hosted VLAN trunks regularly need:
//! 1. A tagged VLAN sub-interface on the physical NIC, plus a bridge
//!    on top so containers/VMs can attach.
//! 2. Routed extra public IPs delivered to specific containers without
//!    bridging the public NIC (the proxy-ARP + DNAT pattern).
//!
//! Doing both by hand involves editing distro-specific network config
//! files and getting the MTU / routing / persistence right. This module
//! puts both behind a structured profile + JSON store + apply step.
//!
//! ## Provider presets
//!
//! Each provider has fixed MTU and VLAN-ID rules baked in. The user
//! picks a preset; we set the right defaults. "Custom" lets the
//! operator supply any values for non-listed providers.
//!
//! - Hetzner vSwitch: VLAN 4000-4091, MTU 1400 (mandatory).
//! - OVH vRack: any VLAN, MTU 1500 default.
//! - Equinix Metal: any VLAN, MTU 1500.
//! - Custom: anything goes.
//!
//! ## Distro coverage
//!
//! Persistent config writers exist for the four mainstream Linux
//! network managers — `apply()` detects which is live and dispatches:
//!
//! - **ifupdown** (Debian/Devuan/Alpine without netplan): writes
//!   `/etc/network/interfaces.d/wolfstack-vlan.conf`.
//! - **netplan** (Ubuntu Server 18+, cloud images): writes
//!   `/etc/netplan/99-wolfstack-vlan.yaml` and runs `netplan apply`.
//! - **NetworkManager** (RHEL/Fedora/Rocky/Alma): creates connections
//!   via `nmcli` (one bridge connection per VLAN, one slave VLAN
//!   connection per parent NIC).
//! - **systemd-networkd** (Arch, minimal Debian, container hosts):
//!   writes `.netdev` and `.network` files into
//!   `/etc/systemd/network/` and runs `networkctl reload`.
//!
//! For the few remaining managers (wicked on openSUSE, anything
//! exotic) we still generate the ifupdown snippet to
//! `/var/lib/wolfstack/suggested-vlan-config.txt` and surface a
//! warning — better than silently doing nothing.
//!
//! ## On-disk layout
//!
//! - State: `/etc/wolfstack/vlan-attachments.json` (the structured
//!   profile list — what the operator configured via the UI).
//! - System config write targets per manager — see `apply()`.
//! - Operator-edited primary config files (`/etc/network/interfaces`,
//!   existing `*.network` units) are never modified by us; we only
//!   add WolfStack-prefixed files alongside them.

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Provider-specific defaults. Picking a preset auto-fills MTU and
/// gives the UI a hint about VLAN-ID range. Custom skips all hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VlanProvider {
    /// Hetzner Robot vSwitch — VLAN 4000-4091, MTU 1400 mandatory.
    Hetzner,
    /// OVH vRack — any VLAN, MTU 1500 default (1496 with PPPoE).
    Ovh,
    /// Equinix Metal Layer-2 — any VLAN, MTU 1500.
    Equinix,
    /// Generic 802.1Q VLAN — any provider, no preset rules.
    Custom,
}

impl VlanProvider {
    /// Provider preset MTU. Currently consumed by the frontend's
    /// equivalent JS map (which can't introspect Rust enums); kept
    /// here as the source of truth so a future native client / API
    /// integration test has the right value to assert against.
    #[allow(dead_code)]
    pub fn default_mtu(&self) -> u32 {
        match self {
            VlanProvider::Hetzner => 1400,
            VlanProvider::Ovh => 1500,
            VlanProvider::Equinix => 1500,
            VlanProvider::Custom => 1500,
        }
    }
    /// Bounds-check a VLAN ID for the chosen provider. Returns Err
    /// with a human-readable message; UI surfaces it inline.
    pub fn validate_vlan_id(&self, id: u32) -> Result<(), String> {
        // 802.1Q reserves 0 (priority-tag) and 4095 (reserved). 1-4094
        // are usable across the spec; providers narrow further.
        if !(1..=4094).contains(&id) {
            return Err(format!(
                "VLAN ID {} is outside the 802.1Q valid range (1-4094)", id
            ));
        }
        match self {
            VlanProvider::Hetzner => {
                if !(4000..=4091).contains(&id) {
                    return Err(format!(
                        "Hetzner vSwitch requires VLAN ID 4000-4091; {} is outside that range",
                        id
                    ));
                }
            }
            VlanProvider::Ovh | VlanProvider::Equinix | VlanProvider::Custom => {}
        }
        Ok(())
    }
}

/// One VLAN attachment — a tagged sub-interface on a physical NIC plus
/// a bridge on top of it. Containers/VMs attach to the bridge.
///
/// The persistence target is a single config file under
/// `/etc/network/interfaces.d/` (or the distro equivalent) regenerated
/// from the profile list on every save. This means the operator can
/// safely edit the JSON state file directly if needed; we never round-
/// trip through a parser of the live config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanAttachment {
    /// Stable, unique identifier (UUID) — used as the on-disk and API key.
    /// We don't use vlan_id alone because nothing stops the same VLAN
    /// being attached on two different parent NICs (multi-NIC servers).
    pub id: String,
    /// Operator-facing label, e.g. "production-vswitch". Used as the
    /// config-file comment so manual `cat /etc/network/interfaces.d/*`
    /// shows what's what.
    pub name: String,
    pub provider: VlanProvider,
    /// Physical NIC the VLAN tags ride on top of, e.g. `eno1`.
    pub parent_iface: String,
    /// VLAN ID 1-4094 (provider-validated separately).
    pub vlan_id: u32,
    /// MTU for both the VLAN sub-interface and the bridge above it.
    /// Hetzner mandates 1400; others typically 1500.
    pub mtu: u32,
    /// Bridge name to expose to containers/VMs. Default `vmbr<vlan_id>`
    /// so it sorts naturally alongside Proxmox-style names.
    pub bridge_name: String,
    /// IPv4 subnet on the VLAN (e.g. `10.0.1.0/24`). The host's own
    /// address on the bridge is `self_ip` within this subnet.
    pub subnet: String,
    pub self_ip: String,
    /// Optional gateway for routes accessible via this VLAN. Common
    /// case: Hetzner vSwitch members reach Cloud-Network-side IPs via
    /// `10.0.0.0/16 via 10.0.1.1` — the cloud network's Layer-3
    /// gateway. Empty list = vlan stays local-only.
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    /// IPs WolfStack has allocated to local guests (containers / VMs)
    /// on this VLAN. Used as the source of truth for next-available-IP
    /// picking and to render the "members" list. Cluster peers each
    /// have their own allocations; the cluster-wide picker unions all.
    #[serde(default)]
    pub allocations: Vec<IpAllocation>,
    /// IPs / ranges held by machines NOT managed by this WolfStack
    /// install — other people's servers, manually-configured boxes,
    /// the cloud-network gateway IP, etc. The auto-picker treats
    /// these as "in use" so we don't double-allocate.
    #[serde(default)]
    pub external_reservations: Vec<ExternalReservation>,
    /// Free-form notes the operator can attach. Survives apply cycles.
    #[serde(default)]
    pub notes: String,
}

/// One container/VM that we've attached to this VLAN. We persist these
/// (rather than reading them back from the live container config) so
/// we can answer "is 10.0.1.10 in use" without per-container queries
/// every time, and so an offline-but-existing container's IP isn't
/// accidentally reassigned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAllocation {
    pub ip: String,
    pub target_kind: TargetKind,
    /// Backend-specific identifier: container name (LXC native),
    /// VMID stringified (Proxmox), container name (Docker), or
    /// VM name (native/libvirt).
    pub target_id: String,
    /// Operator label so the UI can show something nicer than the id.
    #[serde(default)]
    pub label: String,
    /// When the allocation was created — for audit / sort.
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Container managed by raw `lxc` tools (this WolfStack node's host).
    LxcNative,
    /// Container managed by Proxmox VE (this node IS a Proxmox host).
    LxcProxmox,
    /// Docker container (this node runs Docker).
    Docker,
    /// VM managed by Proxmox VE.
    VmProxmox,
    /// VM managed by libvirt / native QEMU on this host.
    VmNative,
    /// Operator-claimed allocation with no backend write — useful when
    /// the IP is held by something WolfStack doesn't manage (a static
    /// service, a kubernetes node, etc.) but the operator wants the
    /// auto-picker to treat it as taken.
    Manual,
}

impl TargetKind {
    /// Human-readable label for UI rendering. Currently mirrored in
    /// the JS frontend; kept in Rust as the source of truth so future
    /// API consumers can render the same labels without duplicating.
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            TargetKind::LxcNative => "LXC (native)",
            TargetKind::LxcProxmox => "LXC (Proxmox)",
            TargetKind::Docker => "Docker",
            TargetKind::VmProxmox => "VM (Proxmox)",
            TargetKind::VmNative => "VM (libvirt/native)",
            TargetKind::Manual => "Manual reservation",
        }
    }
}

/// Range or single-IP held by something outside WolfStack's
/// management. Use for "the standalone server next door uses
/// 10.0.1.20 to 10.0.1.30" or "the cloud-network gateway is 10.0.1.1".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReservation {
    /// Single IP `10.0.1.5` OR inclusive range `10.0.1.20-10.0.1.30`.
    pub spec: String,
    /// Why is this reserved? Shown in the UI so the operator
    /// remembers "oh, that's the OpenSim grid load balancer".
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    /// CIDR being routed, e.g. `10.0.0.0/16`.
    pub destination: String,
    /// Next-hop IP, must be on the same subnet as the VLAN.
    pub via: String,
}

/// One routed public IP delivered to a single container via host-side
/// proxy-ARP + iptables DNAT/SNAT (no bridging of the public NIC).
///
/// This is the pattern that worked for the regions80 case after we
/// untangled it manually — it keeps the host's existing public IP
/// untouched on `eno1` while delivering an additional IP to a guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIpAttachment {
    pub id: String,
    /// Operator label e.g. "regions80-public".
    pub name: String,
    pub provider: VlanProvider,
    /// The additional IP, e.g. `159.69.169.116`.
    pub ip: String,
    /// Internal IP on a known WolfStack-managed bridge (e.g. the
    /// container's lxcbr0 address `10.0.3.100`). DNAT redirects
    /// inbound traffic to this address; SNAT rewrites outbound from
    /// this address back to the public IP.
    pub container_internal_ip: String,
    /// Physical NIC that proxy-ARPs for the IP. Usually the host's
    /// main public NIC (e.g. `eno1`).
    pub egress_iface: String,
}

// ────────────────────────────────────────────────────────────────────
// Persistence
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
// Discovery — detect VLAN topologies that already exist on the host
// ────────────────────────────────────────────────────────────────────
//
// Operators with existing servers (especially Proxmox boxes already
// configured for a vSwitch) typically already have VLANs in place.
// Re-creating them through WolfStack's UI would either duplicate
// (kernel allows two interfaces with the same VID on the same parent
// — confusing) or fail outright. This discovery pass reads the kernel
// state and surfaces what's there so the operator can either import,
// skip, or migrate.
//
// Two main topologies in the wild:
//
// 1. **WolfStack-shaped**: separate VLAN sub-interface (e.g.
//    `eno1.4000`) on the parent NIC, plain bridge on top
//    (e.g. `vmbr4000`) with the sub-iface as a member. This is what
//    the WolfStack apply path generates — directly importable.
//
// 2. **VLAN-aware bridge** (Proxmox default for vSwitch setups):
//    a single bridge with `vlan_filtering=1` and the parent NIC as a
//    port, plus a `vlanN` interface using the bridge as raw device
//    for IP termination on a specific VID. This is a different
//    topology — WolfStack can't reproduce it without a different
//    apply path, so we surface it as "not importable" with a clear
//    explanation.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredVlan {
    /// What kind of topology we detected.
    pub kind: DiscoveredKind,
    /// Parent interface (eno1, vmbr0, etc.).
    pub parent_iface: String,
    /// VLAN ID on the wire.
    pub vlan_id: u32,
    /// Bridge name if we found one for this VID, otherwise None.
    pub bridge_name: Option<String>,
    /// Self IP on the bridge or VLAN interface, if any.
    pub self_ip: Option<String>,
    /// Subnet derived from the address prefix, if any.
    pub subnet: Option<String>,
    /// MTU we observed on the VLAN sub-interface or vlan-aware bridge port.
    pub mtu: Option<u32>,
    /// True if this VLAN is already in WolfStack's store.
    pub already_managed: bool,
    /// Human-readable explanation of what we found and what to do.
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveredKind {
    /// Separate VLAN sub-interface + plain bridge — directly importable.
    Importable,
    /// VLAN-aware bridge pattern (Proxmox-style) — can't import, would
    /// conflict if the operator added a WolfStack-shaped VLAN for the
    /// same VID on the same physical NIC.
    VlanAwareBridge,
    /// VLAN sub-interface with no bridge — operator's using it directly.
    /// Importable as a manual reservation but no bridge to attach guests.
    SubInterfaceOnly,
}

/// Walk the kernel state and report VLAN topologies. Read-only — no
/// modifications to the host.
pub fn discover(store: &VlanStore) -> Vec<DiscoveredVlan> {
    let mut out = Vec::new();
    let already: std::collections::HashSet<(String, u32)> = store.vlans.iter()
        .map(|v| (v.parent_iface.clone(), v.vlan_id))
        .collect();

    let links = list_link_details();

    // 1. Find every VLAN sub-interface (kind=vlan).
    for l in &links {
        if !l.is_vlan { continue; }
        let parent = l.vlan_parent.clone().unwrap_or_default();
        let vid = l.vlan_id.unwrap_or(0);
        if vid == 0 { continue; }

        // Is this sub-interface a member of some bridge?
        let bridge_member = l.master.clone();

        let (self_ip, subnet) = primary_ipv4(&l.name)
            .or_else(|| bridge_member.as_ref().and_then(|b| primary_ipv4(b)))
            .map(|(ip, prefix)| (Some(ip.clone()), Some(format!("{}/{}", network_addr(&ip, prefix), prefix))))
            .unwrap_or((None, None));

        let kind = if bridge_member.is_some() {
            DiscoveredKind::Importable
        } else {
            DiscoveredKind::SubInterfaceOnly
        };
        let already_managed = already.contains(&(parent.clone(), vid));
        let note = match (kind, already_managed) {
            (_, true) => "Already managed by WolfStack — skip.".to_string(),
            (DiscoveredKind::Importable, false) => format!(
                "Sub-interface {} attached to bridge {}. Click Import to take over management.",
                l.name, bridge_member.as_deref().unwrap_or("?"),
            ),
            (DiscoveredKind::SubInterfaceOnly, false) => format!(
                "Sub-interface {} has no bridge — guests can't attach to a bridge that isn't there. \
                 Importing would create the bridge from this point forward.",
                l.name,
            ),
            (DiscoveredKind::VlanAwareBridge, false) => unreachable!(),
        };

        out.push(DiscoveredVlan {
            kind,
            parent_iface: parent,
            vlan_id: vid,
            bridge_name: bridge_member,
            self_ip,
            subnet,
            mtu: Some(l.mtu),
            already_managed,
            note,
        });
    }

    // 2. Find vlan-aware bridges and the VIDs they handle. These are
    //    bridges with kind=bridge AND vlan_filtering=1. The actual
    //    IP-bearing interfaces are typically `vlanN` ifupdown stanzas
    //    that use the bridge as their raw device — those don't show
    //    up as kind=vlan in `ip link` (they're managed by ifupdown's
    //    vconfig wrapper). Read /etc/network/interfaces for the VID
    //    list as a best-effort detection.
    for l in &links {
        if !l.is_vlan_aware_bridge { continue; }
        // Read /etc/network/interfaces for `bridge-vids` and `vlan-raw-device <this bridge>`.
        let interfaces_path = "/etc/network/interfaces";
        let interfaces_content = std::fs::read_to_string(interfaces_path).unwrap_or_default();
        let mut found_vids: Vec<u32> = Vec::new();
        // Look for `iface vlanNNN inet ...` blocks that have
        // `vlan-raw-device <l.name>` somewhere inside.
        let mut current_iface: Option<String> = None;
        let mut current_uses_this_bridge = false;
        for line in interfaces_content.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("iface ") {
                // Flush previous block.
                if let Some(name) = current_iface.take() {
                    if current_uses_this_bridge {
                        if let Some(vid) = name.strip_prefix("vlan").and_then(|s| s.parse::<u32>().ok()) {
                            found_vids.push(vid);
                        }
                    }
                }
                current_iface = rest.split_whitespace().next().map(|s| s.to_string());
                current_uses_this_bridge = false;
            } else if t.starts_with("vlan-raw-device") || t.starts_with("vlan_raw_device") {
                if let Some(dev) = t.split_whitespace().nth(1) {
                    if dev == l.name { current_uses_this_bridge = true; }
                }
            }
        }
        // Flush trailing block.
        if let Some(name) = current_iface.take() {
            if current_uses_this_bridge {
                if let Some(vid) = name.strip_prefix("vlan").and_then(|s| s.parse::<u32>().ok()) {
                    found_vids.push(vid);
                }
            }
        }

        // Find what physical NIC is bridged through here (the parent
        // for VID purposes — the underlying L2 carrier).
        let bridge_ports: Vec<String> = links.iter()
            .filter(|p| p.master.as_deref() == Some(&l.name))
            .filter(|p| !p.is_vlan)  // skip VLAN sub-interfaces in case any
            .map(|p| p.name.clone())
            .collect();
        let phys_parent = bridge_ports.first().cloned().unwrap_or_else(|| "?".to_string());

        for vid in found_vids {
            let already_managed = already.contains(&(phys_parent.clone(), vid));
            // For a vlan-aware bridge with `vlanNNN inet static address ...`,
            // the IP lives on the vlanNNN interface. Look it up.
            let vlan_iface_name = format!("vlan{}", vid);
            let (self_ip, subnet) = primary_ipv4(&vlan_iface_name)
                .map(|(ip, prefix)| (Some(ip.clone()), Some(format!("{}/{}", network_addr(&ip, prefix), prefix))))
                .unwrap_or((None, None));

            out.push(DiscoveredVlan {
                kind: DiscoveredKind::VlanAwareBridge,
                parent_iface: phys_parent.clone(),
                vlan_id: vid,
                bridge_name: Some(l.name.clone()),
                self_ip,
                subnet,
                mtu: Some(l.mtu),
                already_managed,
                note: format!(
                    "Detected on VLAN-aware bridge '{}' (Proxmox-style topology). \
                     WolfStack manages plain bridges with a separate VLAN sub-interface — a different \
                     topology. DO NOT add a WolfStack VLAN for ID {} on this NIC: you'd end up with two \
                     interfaces both carrying VID {} traffic on the same physical port. Either keep your \
                     existing config (no WolfStack action needed) or migrate manually: remove the \
                     `vlan{}` stanza and the `bridge-vlan-aware`/`bridge-vids` lines from `{}`, then add \
                     the VLAN through WolfStack.",
                    l.name, vid, vid, vid, l.name,
                ),
            });
        }
    }

    out
}

/// Minimal info we need per-link from `ip -d -j link show`. We parse
/// the JSON manually so we don't pull in serde_json codegen for every
/// link's full schema (it's verbose and we only need a few fields).
#[derive(Debug, Clone, Default)]
struct LinkInfo {
    name: String,
    mtu: u32,
    is_vlan: bool,
    /// Set when the link is a kind=vlan device.
    vlan_id: Option<u32>,
    vlan_parent: Option<String>,
    /// Set when the link is a bridge with vlan_filtering=1.
    is_vlan_aware_bridge: bool,
    /// Master link name when this link is a slave (bridge port).
    master: Option<String>,
}

fn list_link_details() -> Vec<LinkInfo> {
    let out = Command::new("ip").args(["-d", "-j", "link", "show"]).output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_slice(&stdout) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let arr = match json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for item in arr {
        let name = item.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { continue; }
        let mtu = item.get("mtu").and_then(|v| v.as_u64()).unwrap_or(1500) as u32;
        let master = item.get("master").and_then(|v| v.as_str()).map(|s| s.to_string());

        let mut info = LinkInfo { name: name.clone(), mtu, master, ..Default::default() };

        // linkinfo.info_kind tells us "vlan" or "bridge"; linkinfo.info_data
        // has the kind-specific details (vlan_id, parent, vlan_filtering).
        if let Some(linkinfo) = item.get("linkinfo") {
            let kind = linkinfo.get("info_kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind == "vlan" {
                info.is_vlan = true;
                info.vlan_id = linkinfo.get("info_data")
                    .and_then(|d| d.get("id"))
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                info.vlan_parent = item.get("link").and_then(|v| v.as_str()).map(|s| s.to_string());
            } else if kind == "bridge" {
                let vf = linkinfo.get("info_data")
                    .and_then(|d| d.get("vlan_filtering"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                info.is_vlan_aware_bridge = vf == 1;
            }
        }
        out.push(info);
    }
    out
}

/// Read the primary global IPv4 address on an interface (address +
/// prefix), or None. Skips secondary/scope-link addresses.
fn primary_ipv4(iface: &str) -> Option<(String, u8)> {
    let out = Command::new("ip").args(["-o", "-4", "addr", "show", "dev", iface]).output().ok()?;
    if !out.status.success() { return None; }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: "N: iface inet 1.2.3.4/24 scope global ..."
        if let Some(addr) = parts.get(3) {
            if let Some((ip, prefix)) = addr.split_once('/') {
                if let Ok(p) = prefix.parse::<u8>() {
                    return Some((ip.to_string(), p));
                }
            }
        }
    }
    None
}

/// Compute the network address of `ip/prefix`. Best-effort IPv4 only;
/// returns the input unchanged on parse failure.
fn network_addr(ip: &str, prefix: u8) -> String {
    let parsed: Result<std::net::Ipv4Addr, _> = ip.parse();
    match parsed {
        Ok(addr) => {
            let n = u32::from(addr);
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            std::net::Ipv4Addr::from(n & mask).to_string()
        }
        Err(_) => ip.to_string(),
    }
}

// ────────────────────────────────────────────────────────────────────
// Parse ifupdown config from elsewhere (another server) — used to
// import a working VLAN definition as a template for THIS server.
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedVlan {
    /// Source topology — affects what we recommend the operator do.
    pub source_topology: SourceTopology,
    pub vlan_id: u32,
    /// Whatever was on the right-hand side of `vlan-raw-device` in the
    /// pasted config — could be a physical NIC (eno1) for the
    /// WolfStack-shaped topology, or a bridge name (vmbr0) for the
    /// vlan-aware-bridge topology. The recommendation explains.
    pub raw_device: String,
    pub mtu: Option<u32>,
    pub self_ip: Option<String>,
    pub subnet: Option<String>,
    pub routes: Vec<RouteEntry>,
    /// Plain-English summary of what we found and how the operator
    /// should use it on this server.
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTopology {
    /// `vlan-raw-device` pointed at a physical NIC — same shape WolfStack
    /// generates. Direct template.
    PhysicalParent,
    /// `vlan-raw-device` pointed at a bridge (Proxmox-style vlan-aware
    /// bridge). Different topology — operator needs to swap to physical
    /// NIC for the WolfStack version.
    VlanAwareBridge,
}

/// Parse Debian/Ubuntu `/etc/network/interfaces` text and pull out
/// every `iface ... inet static/manual` block that's a VLAN. Tolerant
/// of indentation, blank lines, comments, out-of-order directives,
/// CRLF line endings, IPv6 blocks (skipped), and arbitrary unrelated
/// stanzas (lo, eno1, vmbr0, bonds, ovs bridges, wireguard configs,
/// etc.) — anything that doesn't look like a VLAN is dropped silently.
///
/// Designed for "operator pasted their entire /etc/network/interfaces
/// from another server" — we extract just the VLAN bits and ignore
/// the rest. Duplicate (raw_device, vlan_id) pairs (e.g. when two
/// `iface X` blocks exist for the same interface) collapse to one.
pub fn parse_ifupdown_text(text: &str) -> Vec<ParsedVlan> {
    let mut blocks: Vec<IfaceBlock> = Vec::new();
    let mut current: Option<IfaceBlock> = None;
    let mut continuation: Option<String> = None;
    for raw_line in text.lines() {
        // Handle line-continuation backslashes — `up something \` followed
        // by an indented next line means treat both as one logical line.
        // Rare in real configs but legal per ifupdown grammar.
        let raw_owned;
        let raw = if let Some(prev) = continuation.take() {
            raw_owned = format!("{} {}", prev, raw_line);
            raw_owned.as_str()
        } else {
            raw_line
        };
        // Trim trailing CR (CRLF line endings from a Windows paste).
        let trimmed_eol = raw.trim_end_matches(['\r', '\n']);
        // If this line ends with `\`, it continues on the next line.
        if let Some(rest) = trimmed_eol.strip_suffix('\\') {
            continuation = Some(rest.trim_end().to_string());
            continue;
        }
        // Strip inline comments. We split on `#` regardless of position;
        // ifupdown values don't contain literal `#` characters in
        // practice (operators put `#` only in comments).
        let no_comment = trimmed_eol.split('#').next().unwrap_or(trimmed_eol);
        let t = no_comment.trim();
        if t.is_empty() { continue; }

        if let Some(rest) = t.strip_prefix("iface ") {
            // New iface block — flush the previous one.
            if let Some(b) = current.take() { blocks.push(b); }
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or("").to_string();
            // Detect address family. `iface X inet ...` is v4;
            // `iface X inet6 ...` is v6. WolfStack is v4-only today —
            // skip v6 blocks rather than emit invalid candidates.
            let family = parts.next().unwrap_or("");
            let is_inet6 = family == "inet6";
            current = Some(IfaceBlock { name, is_inet6, ..Default::default() });
        } else if t.starts_with("auto ") || t.starts_with("allow-")
            || t.starts_with("source ") || t.starts_with("source-directory ")
            || t.starts_with("mapping ")
        {
            // Top-level directives that aren't iface blocks. Skip
            // explicitly so we don't accidentally classify them as
            // a directive in the previous block.
            // Also: an `auto`/`allow-`/etc terminates the previous
            // block's "current" status — but only conceptually. Real
            // ifupdown uses a blank line or another `iface` to end a
            // block; we already handle both. Just skip.
        } else if let Some(b) = current.as_mut() {
            // Directive inside the current block.
            let mut parts = t.split_whitespace();
            let key = parts.next().unwrap_or("");
            let value = parts.collect::<Vec<_>>().join(" ");
            match key {
                "address" => b.address = Some(value),
                "netmask" => b.netmask = Some(value),
                "gateway" => b.gateway = Some(value),
                "mtu" => b.mtu = value.parse().ok(),
                "vlan-raw-device" | "vlan_raw_device" => b.vlan_raw_device = Some(value),
                "vlan-id" => b.vlan_id_directive = value.parse().ok(),
                // Accept all the common "run a command on bring-up"
                // hooks since operators put route adds in any of them.
                // We deliberately do NOT collect `down`/`pre-down`/
                // `post-down` — those are teardown actions, not state.
                "up" | "pre-up" | "post-up" => b.up_lines.push(value),
                _ => {}
            }
        }
    }
    if let Some(b) = current.take() { blocks.push(b); }

    // Filter for VLAN blocks. A block is a VLAN if any of:
    // - it has `vlan-raw-device`
    // - its name matches `vlanNNN` or `DEV.NNN`
    // IPv6 blocks are skipped — WolfStack is v4-only.
    let mut out: Vec<ParsedVlan> = Vec::new();
    let mut seen: std::collections::HashSet<(String, u32)> = Default::default();
    for b in blocks {
        if b.is_inet6 { continue; }
        let (vid, raw_device) = match (vlan_id_from_block(&b), b.vlan_raw_device.clone()) {
            (Some(vid), Some(dev)) => (vid, dev),
            (Some(vid), None) => {
                // Name-derived: DEV.NNN — split.
                if let Some((dev, _)) = b.name.rsplit_once('.') {
                    (vid, dev.to_string())
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        // Bounds-check the VID against 802.1Q. Garbage names like
        // `iface vlan99999` or `iface eth0.0` would otherwise produce
        // nonsense candidates.
        if !(1..=4094).contains(&vid) { continue; }
        // Dedupe: a single (parent, VID) pair should appear once even
        // if the operator pasted multiple iface blocks for it.
        if !seen.insert((raw_device.clone(), vid)) { continue; }
        // Determine source topology heuristically: if the raw_device
        // name starts with `vmbr`/`br`, it's almost certainly a bridge
        // (vlan-aware topology). Anything else is treated as physical.
        let source_topology = if raw_device.starts_with("vmbr")
            || raw_device.starts_with("br-")
            || raw_device.starts_with("br0")
            || raw_device == "br0"
        {
            SourceTopology::VlanAwareBridge
        } else {
            SourceTopology::PhysicalParent
        };
        let (self_ip, subnet) = parse_address_subnet(&b);
        let routes = parse_routes_from_up(&b.up_lines);
        let recommendation = match source_topology {
            SourceTopology::PhysicalParent => format!(
                "Source uses the WolfStack-shape topology (separate VLAN sub-interface on a physical NIC). \
                 Pre-fill values: VID {}, MTU {}, subnet {}. \
                 Pick a DIFFERENT self IP on this server — the source's IP {} is in use on the other machine.",
                vid,
                b.mtu.map(|m| m.to_string()).unwrap_or_else(|| "(default)".into()),
                subnet.clone().unwrap_or_else(|| "(unknown)".into()),
                self_ip.clone().unwrap_or_else(|| "(unknown)".into()),
            ),
            SourceTopology::VlanAwareBridge => format!(
                "Source uses a vlan-aware bridge (Proxmox-style — `{}` is a bridge with `bridge-vlan-aware yes`). \
                 WolfStack manages a different topology (separate VLAN sub-interface + plain bridge), but the \
                 over-the-wire VLAN traffic is identical, so a WolfStack-managed server can co-exist on the same \
                 vSwitch as the source. \
                 Pre-fill values: VID {}, MTU {}, subnet {}. \
                 PARENT NIC: pick the underlying physical NIC of the source's `{}` (e.g. eno1 — what the source has as `bridge-ports`). \
                 Pick a DIFFERENT self IP — the source's IP {} is taken.",
                raw_device,
                vid,
                b.mtu.map(|m| m.to_string()).unwrap_or_else(|| "(default)".into()),
                subnet.clone().unwrap_or_else(|| "(unknown)".into()),
                raw_device,
                self_ip.clone().unwrap_or_else(|| "(unknown)".into()),
            ),
        };
        out.push(ParsedVlan {
            source_topology,
            vlan_id: vid,
            raw_device,
            mtu: b.mtu,
            self_ip,
            subnet,
            routes,
            recommendation,
        });
    }
    out
}

#[derive(Debug, Default, Clone)]
struct IfaceBlock {
    name: String,
    /// True if the iface line was `iface X inet6 ...` rather than
    /// `iface X inet ...`. We skip v6 blocks at output time —
    /// WolfStack itself is v4-only and a v6 candidate would just
    /// confuse the operator.
    is_inet6: bool,
    address: Option<String>,
    netmask: Option<String>,
    #[allow(dead_code)]
    gateway: Option<String>,
    mtu: Option<u32>,
    vlan_raw_device: Option<String>,
    vlan_id_directive: Option<u32>,
    up_lines: Vec<String>,
}

fn vlan_id_from_block(b: &IfaceBlock) -> Option<u32> {
    // Explicit `vlan-id` wins.
    if let Some(v) = b.vlan_id_directive { return Some(v); }
    // DEV.NNN pattern.
    if let Some((_, vid)) = b.name.rsplit_once('.') {
        if let Ok(n) = vid.parse::<u32>() { return Some(n); }
    }
    // vlanNNN pattern.
    if let Some(rest) = b.name.strip_prefix("vlan") {
        if let Ok(n) = rest.parse::<u32>() { return Some(n); }
    }
    None
}

fn parse_address_subnet(b: &IfaceBlock) -> (Option<String>, Option<String>) {
    let addr = match b.address.clone() {
        Some(a) => a,
        None => return (None, None),
    };
    // Two forms in the wild:
    //   address 10.0.1.5/24    (CIDR — modern)
    //   address 10.0.1.5
    //   netmask 255.255.255.0  (split — old-style)
    if let Some((ip, prefix_str)) = addr.split_once('/') {
        if let Ok(prefix) = prefix_str.parse::<u8>() {
            let net = network_addr(ip, prefix);
            return (Some(ip.to_string()), Some(format!("{}/{}", net, prefix)));
        }
    }
    // Old-style with netmask.
    if let Some(mask) = b.netmask.as_ref() {
        if let Some(prefix) = netmask_to_prefix(mask) {
            let net = network_addr(&addr, prefix);
            return (Some(addr), Some(format!("{}/{}", net, prefix)));
        }
    }
    (Some(addr), None)
}

fn netmask_to_prefix(mask: &str) -> Option<u8> {
    let parsed: Result<std::net::Ipv4Addr, _> = mask.parse();
    let bits = u32::from(parsed.ok()?);
    Some(bits.count_ones() as u8)
}

/// Parse routes from `up ip route add X via Y dev Z` style up-hooks.
/// Tolerates `ip route add` and `ip -4 route add` variants. dev clause
/// is optional and ignored (we re-derive on apply).
fn parse_routes_from_up(lines: &[String]) -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    for line in lines {
        let toks: Vec<&str> = line.split_whitespace().collect();
        // Look for "ip ... route add DEST via VIA"
        if !toks.iter().any(|t| *t == "route") { continue; }
        if !toks.iter().any(|t| *t == "add") { continue; }
        let mut dest: Option<&str> = None;
        let mut via: Option<&str> = None;
        let mut i = 0;
        while i < toks.len() {
            if toks[i] == "add" && i + 1 < toks.len() {
                dest = Some(toks[i + 1]);
            }
            if toks[i] == "via" && i + 1 < toks.len() {
                via = Some(toks[i + 1]);
            }
            i += 1;
        }
        if let (Some(d), Some(v)) = (dest, via) {
            routes.push(RouteEntry { destination: d.to_string(), via: v.to_string() });
        }
    }
    routes
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VlanStore {
    #[serde(default)]
    pub vlans: Vec<VlanAttachment>,
    #[serde(default)]
    pub public_ips: Vec<PublicIpAttachment>,
}

fn store_path() -> String {
    format!("{}/vlan-attachments.json", crate::paths::get().config_dir)
}

impl VlanStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(store_path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = store_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Mode 0600 — contains topology that's not secret per se but
        // also nobody's business by default.
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("save vlan store: {}", e))
    }

    pub fn get_vlan(&self, id: &str) -> Option<&VlanAttachment> {
        self.vlans.iter().find(|v| v.id == id)
    }

    pub fn get_public_ip(&self, id: &str) -> Option<&PublicIpAttachment> {
        self.public_ips.iter().find(|p| p.id == id)
    }

    pub fn upsert_vlan(&mut self, mut v: VlanAttachment) -> Result<String, String> {
        validate_vlan_attachment(&v)?;
        if v.id.is_empty() {
            v.id = format!("vlan-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        }
        if let Some(existing) = self.vlans.iter_mut().find(|x| x.id == v.id) {
            *existing = v.clone();
        } else {
            // Reject duplicate (parent, vlan_id) combinations — the kernel
            // also rejects them but a clear error is better than failure
            // at apply time.
            if self.vlans.iter().any(|x| x.parent_iface == v.parent_iface && x.vlan_id == v.vlan_id) {
                return Err(format!(
                    "VLAN {} on parent {} already exists",
                    v.vlan_id, v.parent_iface
                ));
            }
            self.vlans.push(v.clone());
        }
        Ok(v.id)
    }

    pub fn remove_vlan(&mut self, id: &str) -> bool {
        let before = self.vlans.len();
        self.vlans.retain(|v| v.id != id);
        before != self.vlans.len()
    }

    pub fn upsert_public_ip(&mut self, mut p: PublicIpAttachment) -> Result<String, String> {
        validate_public_ip_attachment(&p)?;
        if p.id.is_empty() {
            p.id = format!("pip-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        }
        if let Some(existing) = self.public_ips.iter_mut().find(|x| x.id == p.id) {
            *existing = p.clone();
        } else {
            // One IP can only forward to one container — reject duplicates.
            if self.public_ips.iter().any(|x| x.ip == p.ip) {
                return Err(format!(
                    "Public IP {} is already attached to a container",
                    p.ip
                ));
            }
            self.public_ips.push(p.clone());
        }
        Ok(p.id)
    }

    pub fn remove_public_ip(&mut self, id: &str) -> bool {
        let before = self.public_ips.len();
        self.public_ips.retain(|p| p.id != id);
        before != self.public_ips.len()
    }

    /// Record an IP allocation against a VLAN. Returns Err if the IP
    /// is outside the VLAN's subnet, already taken locally, or the
    /// VLAN id doesn't exist.
    pub fn allocate_ip(
        &mut self,
        vlan_id: &str,
        ip: &str,
        target_kind: TargetKind,
        target_id: &str,
        label: &str,
    ) -> Result<(), String> {
        let v = self.vlans.iter_mut().find(|v| v.id == vlan_id)
            .ok_or_else(|| format!("vlan attachment '{}' not found", vlan_id))?;
        if !ip_in_cidr(ip, &v.subnet)? {
            return Err(format!("IP {} is not inside the VLAN subnet {}", ip, v.subnet));
        }
        if v.allocations.iter().any(|a| a.ip == ip) {
            return Err(format!("IP {} is already allocated on VLAN {}", ip, v.name));
        }
        v.allocations.push(IpAllocation {
            ip: ip.to_string(),
            target_kind,
            target_id: target_id.to_string(),
            label: label.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        Ok(())
    }

    /// Remove an IP allocation by VLAN id + IP. Returns true if it
    /// was there. Idempotent — caller can detach a target with no
    /// recorded allocation safely (returns false).
    pub fn deallocate_ip(&mut self, vlan_id: &str, ip: &str) -> bool {
        let v = match self.vlans.iter_mut().find(|v| v.id == vlan_id) {
            Some(v) => v,
            None => return false,
        };
        let before = v.allocations.len();
        v.allocations.retain(|a| a.ip != ip);
        before != v.allocations.len()
    }

    /// Remove every allocation for the given target (used when the
    /// container/VM is deleted and we need to release its IP across
    /// every VLAN it was on). Wired into the permanent-delete paths via
    /// `release_target_allocations`.
    pub fn deallocate_target(&mut self, target_kind: TargetKind, target_id: &str) -> usize {
        let mut count = 0;
        for v in &mut self.vlans {
            let before = v.allocations.len();
            v.allocations.retain(|a| !(a.target_kind == target_kind && a.target_id == target_id));
            count += before - v.allocations.len();
        }
        count
    }
}

/// Release every vSwitch/VLAN IP allocation held by a target that is being
/// permanently deleted, so a deleted container/VM doesn't leak its reserved
/// IP(s) (which would otherwise sit in the store forever and be skipped by the
/// auto-picker). Loads the store, drops matching allocations, and persists only
/// if something actually changed. Idempotent and safe to call for a target that
/// never had an allocation (returns 0, writes nothing).
///
/// `target_id` must be the SAME identifier used at attach time: native LXC and
/// Docker use the container name, Proxmox guests use the VMID, libvirt VMs use
/// the domain name. Only wire this into PERMANENT-delete boundaries — never the
/// Docker image-update recreate path, which removes and re-creates the same
/// container under the same name and must keep its allocation.
///
/// The load-modify-save is intentionally lock-free, matching how the
/// `vlan_attach`/`vlan_detach` handlers already mutate the store; a concurrent
/// attach racing a release is a pre-existing store-wide limitation, not specific
/// to this path.
pub fn release_target_allocations(target_kind: TargetKind, target_id: &str) -> usize {
    let mut store = VlanStore::load();
    let n = store.deallocate_target(target_kind, target_id);
    if n > 0 {
        match store.save() {
            Ok(()) => tracing::info!(
                "released {} vSwitch IP allocation(s) for deleted target {}", n, target_id),
            Err(e) => tracing::warn!(
                "failed to persist vSwitch IP release for {}: {}", target_id, e),
        }
    }
    n
}

// ────────────────────────────────────────────────────────────────────
// Validation
// ────────────────────────────────────────────────────────────────────

fn validate_vlan_attachment(v: &VlanAttachment) -> Result<(), String> {
    if v.name.trim().is_empty() {
        return Err("name is required".into());
    }
    v.provider.validate_vlan_id(v.vlan_id)?;
    if !(576..=9216).contains(&v.mtu) {
        return Err(format!(
            "MTU {} is outside the sane range (576-9216). Hetzner requires 1400; most providers default to 1500.",
            v.mtu
        ));
    }
    if v.parent_iface.is_empty() || !v.parent_iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') {
        return Err(format!("parent interface name '{}' is invalid", v.parent_iface));
    }
    if v.bridge_name.is_empty() || !v.bridge_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') {
        return Err(format!("bridge name '{}' is invalid", v.bridge_name));
    }
    // Bridge name must fit in IFNAMSIZ - 1 (Linux limit is 15 chars).
    if v.bridge_name.len() > 15 {
        return Err(format!(
            "bridge name '{}' is {} chars; Linux IFNAMSIZ limit is 15",
            v.bridge_name, v.bridge_name.len()
        ));
    }
    // L2-only attachment: empty subnet AND empty self_ip = a pure
    // bridge with no host address (e.g. a vSwitch whose IPs live only
    // on the guests attached to it — the container-driven auto-wire
    // path uses this). Skip the L3 checks for that case; routes need a
    // subnet, so they're disallowed without one.
    let subnet_empty = v.subnet.is_empty();
    let self_ip_empty = v.self_ip.is_empty();
    if subnet_empty != self_ip_empty {
        return Err("subnet and self_ip must both be set or both be empty \
            (both empty = an L2-only bridge with no host IP)".into());
    }
    if subnet_empty {
        if !v.routes.is_empty() {
            return Err("an L2-only VLAN attachment (no subnet/self_ip) cannot \
                carry routes — routes require a subnet".into());
        }
        return Ok(());
    }
    parse_cidr(&v.subnet).map_err(|e| format!("subnet: {}", e))?;
    parse_ip(&v.self_ip).map_err(|e| format!("self_ip: {}", e))?;
    if !ip_in_cidr(&v.self_ip, &v.subnet)? {
        return Err(format!(
            "self_ip {} is not inside subnet {}",
            v.self_ip, v.subnet
        ));
    }
    for r in &v.routes {
        parse_cidr(&r.destination).map_err(|e| format!("route destination: {}", e))?;
        parse_ip(&r.via).map_err(|e| format!("route via: {}", e))?;
        if !ip_in_cidr(&r.via, &v.subnet)? {
            return Err(format!(
                "route gateway {} is not inside the VLAN subnet {} — kernel can't reach it",
                r.via, v.subnet
            ));
        }
    }
    Ok(())
}

fn validate_public_ip_attachment(p: &PublicIpAttachment) -> Result<(), String> {
    if p.name.trim().is_empty() {
        return Err("name is required".into());
    }
    parse_ip(&p.ip).map_err(|e| format!("public ip: {}", e))?;
    parse_ip(&p.container_internal_ip).map_err(|e| format!("container internal ip: {}", e))?;
    if p.egress_iface.is_empty() {
        return Err("egress interface is required".into());
    }
    Ok(())
}

fn parse_ip(s: &str) -> Result<std::net::IpAddr, String> {
    s.parse::<std::net::IpAddr>().map_err(|_| format!("'{}' is not a valid IP address", s))
}

fn parse_cidr(s: &str) -> Result<(std::net::IpAddr, u8), String> {
    let (ip_part, prefix_part) = s.rsplit_once('/').ok_or_else(|| {
        format!("'{}' is not a CIDR (expected ADDRESS/PREFIX, e.g. 10.0.0.0/24)", s)
    })?;
    let ip = parse_ip(ip_part)?;
    let prefix: u8 = prefix_part.parse().map_err(|_| {
        format!("'{}' has an invalid prefix length", s)
    })?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix /{} exceeds max /{} for the address family", prefix, max));
    }
    Ok((ip, prefix))
}

/// Expand an `ExternalReservation` spec into individual IPv4 addresses.
/// Accepts a single IP (`10.0.1.5`) or an inclusive range
/// (`10.0.1.20-10.0.1.30`). IPv6 ranges aren't supported here — yet.
fn expand_reservation(spec: &str) -> Result<Vec<std::net::Ipv4Addr>, String> {
    let s = spec.trim();
    if let Some((lo, hi)) = s.split_once('-') {
        let lo: std::net::Ipv4Addr = lo.trim().parse()
            .map_err(|_| format!("range start '{}' is not an IPv4 address", lo.trim()))?;
        let hi: std::net::Ipv4Addr = hi.trim().parse()
            .map_err(|_| format!("range end '{}' is not an IPv4 address", hi.trim()))?;
        let lo_n = u32::from(lo);
        let hi_n = u32::from(hi);
        if hi_n < lo_n {
            return Err(format!("range '{}' is reversed (end < start)", spec));
        }
        if hi_n - lo_n > 65535 {
            return Err(format!("range '{}' covers more than /16; refusing", spec));
        }
        Ok((lo_n..=hi_n).map(std::net::Ipv4Addr::from).collect())
    } else {
        let ip: std::net::Ipv4Addr = s.parse()
            .map_err(|_| format!("'{}' is not an IPv4 address", s))?;
        Ok(vec![ip])
    }
}

/// Pick the next-available IPv4 address in the VLAN's subnet that
/// isn't held by any local allocation, external reservation, or any
/// of the additional `cluster_used` addresses (typically aggregated
/// from peer nodes via the cluster-allocations API). Skips:
/// - the network address (.0 in /24)
/// - the broadcast address (.255 in /24)
/// - the bridge's own `self_ip`
/// - first-IP gateway convention (.1 in /24) UNLESS self_ip IS .1,
///   in which case the operator has clearly chosen a different layout
///
/// Returns `None` if the subnet has no free IPs left.
pub fn next_available_ip(v: &VlanAttachment, cluster_used: &[String]) -> Option<String> {
    let (net, prefix) = match parse_cidr(&v.subnet).ok()? {
        (std::net::IpAddr::V4(n), p) => (n, p),
        _ => return None,  // IPv6 next-available picker is its own design
    };
    let net_n = u32::from(net);
    let host_bits = 32u8.saturating_sub(prefix);
    if host_bits < 2 { return None; }  // /31 and /32 have no usable hosts
    let mask = if prefix == 0 { 0u32 } else { !0u32 << host_bits };
    let net_addr = net_n & mask;
    let bcast_addr = net_addr | !mask;
    let self_ip: std::net::Ipv4Addr = v.self_ip.parse().ok()?;
    let self_n = u32::from(self_ip);
    // Build the "used" set from local + external + cluster-supplied.
    let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
    used.insert(net_addr);
    used.insert(bcast_addr);
    used.insert(self_n);
    // Conventional gateway = first usable IP. Treat as used UNLESS
    // self is the gateway (operator chose the .1 slot deliberately).
    let conventional_gw = net_addr.wrapping_add(1);
    if self_n != conventional_gw {
        used.insert(conventional_gw);
    }
    for a in &v.allocations {
        if let Ok(ip) = a.ip.parse::<std::net::Ipv4Addr>() {
            used.insert(u32::from(ip));
        }
    }
    for r in &v.external_reservations {
        if let Ok(ips) = expand_reservation(&r.spec) {
            for ip in ips { used.insert(u32::from(ip)); }
        }
    }
    for s in cluster_used {
        if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
            used.insert(u32::from(ip));
        }
    }
    // Iterate hosts in the subnet (skip network + broadcast). For /24
    // this is 254 candidates; cheap to scan. For /16 it's ~65k —
    // still well under a millisecond.
    let first = net_addr.wrapping_add(1);
    let last = bcast_addr.wrapping_sub(1);
    for n in first..=last {
        if !used.contains(&n) {
            return Some(std::net::Ipv4Addr::from(n).to_string());
        }
    }
    None
}

fn ip_in_cidr(ip: &str, cidr: &str) -> Result<bool, String> {
    let parsed = parse_ip(ip)?;
    let (net, prefix) = parse_cidr(cidr)?;
    match (parsed, net) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            let a = u32::from(a);
            let n = u32::from(n);
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            Ok((a & mask) == (n & mask))
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            let a = u128::from(a);
            let n = u128::from(n);
            let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
            Ok((a & mask) == (n & mask))
        }
        _ => Err("IP and subnet are different address families".into()),
    }
}

// ────────────────────────────────────────────────────────────────────
// Distro detection — what's managing networking on this host?
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetManager {
    /// Debian (no netplan), Alpine, Devuan — `/etc/network/interfaces`.
    Ifupdown,
    /// Modern Ubuntu Server / Cloud — `/etc/netplan/*.yaml`.
    Netplan,
    /// RHEL / Fedora / Rocky / Alma — `nmcli` connections.
    NetworkManager,
    /// Arch / minimal Debian configs — `/etc/systemd/network/*.network`.
    SystemdNetworkd,
    /// openSUSE — `/etc/sysconfig/network/ifcfg-*`.
    Wicked,
    /// Couldn't tell — emit a snippet and ask the operator.
    Unknown,
}

impl NetManager {
    pub fn label(&self) -> &'static str {
        match self {
            NetManager::Ifupdown => "ifupdown (/etc/network/interfaces)",
            NetManager::Netplan => "netplan",
            NetManager::NetworkManager => "NetworkManager",
            NetManager::SystemdNetworkd => "systemd-networkd",
            NetManager::Wicked => "wicked (openSUSE)",
            NetManager::Unknown => "unknown",
        }
    }
    /// True when WolfStack will write a managed config file directly
    /// for this manager and reload the live network stack. Other
    /// managers (Wicked, Unknown) get a generated snippet only.
    pub fn auto_persist_supported(&self) -> bool {
        matches!(
            self,
            NetManager::Ifupdown
                | NetManager::Netplan
                | NetManager::NetworkManager
                | NetManager::SystemdNetworkd
        )
    }
}

/// Detect the live network manager. Order matters: NetworkManager is
/// checked before systemd-networkd because hosts often have both
/// installed but only one active. Netplan checked before ifupdown
/// because Ubuntu can have both files but netplan wins.
pub fn detect_net_manager() -> NetManager {
    // Active service detection first — actually-running service is
    // more authoritative than presence of config files.
    let active = |unit: &str| -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if active("NetworkManager") { return NetManager::NetworkManager; }
    if active("wicked") { return NetManager::Wicked; }
    // Netplan generates output for either networkd or NM, so this
    // check fires when /etc/netplan has files AND `netplan` exists.
    if std::path::Path::new("/etc/netplan").exists() {
        if let Ok(read) = std::fs::read_dir("/etc/netplan") {
            let any_yaml = read.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().ends_with(".yaml"));
            if any_yaml {
                return NetManager::Netplan;
            }
        }
    }
    if active("systemd-networkd") { return NetManager::SystemdNetworkd; }
    // ifupdown is the fallback for Debian-derived systems with the
    // /etc/network/interfaces file present.
    if std::path::Path::new("/etc/network/interfaces").exists() {
        return NetManager::Ifupdown;
    }
    NetManager::Unknown
}

// ────────────────────────────────────────────────────────────────────
// Config generation
// ────────────────────────────────────────────────────────────────────

/// Path to the WolfStack-managed ifupdown config snippet. Lives under
/// `/etc/network/interfaces.d/` because Debian-derived systems source
/// the entire directory from `/etc/network/interfaces`. Operator-edited
/// `/etc/network/interfaces` is never touched by us.
const IFUPDOWN_SNIPPET: &str = "/etc/network/interfaces.d/wolfstack-vlan.conf";

/// Generate the ifupdown snippet for all VLANs + public IPs in the
/// store. Pure function — no I/O. Easy to unit-test and to preview
/// in the UI before applying.
pub fn render_ifupdown(store: &VlanStore) -> String {
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — do not edit by hand.\n");
    out.push_str("# Source of truth: /etc/wolfstack/vlan-attachments.json\n");
    out.push_str("# Manage via the WolfStack UI: WolfRouter to Networking to VLANs\n\n");

    for v in &store.vlans {
        let prefix = cidr_prefix(&v.subnet).unwrap_or(24);
        let netmask = cidr_to_netmask_v4(prefix);
        let vlan_iface = format!("{}.{}", v.parent_iface, v.vlan_id);
        out.push_str(&format!("# VLAN: {} (provider: {:?})\n", v.name, v.provider));
        if !v.notes.is_empty() {
            for line in v.notes.lines() {
                out.push_str(&format!("# note: {}\n", line));
            }
        }
        // Tagged sub-interface on the parent NIC.
        out.push_str(&format!("auto {}\n", vlan_iface));
        out.push_str(&format!("iface {} inet manual\n", vlan_iface));
        out.push_str(&format!("    vlan-raw-device {}\n", v.parent_iface));
        out.push_str(&format!("    mtu {}\n", v.mtu));
        out.push('\n');
        // Bridge on top — containers/VMs attach here.
        out.push_str(&format!("auto {}\n", v.bridge_name));
        if v.self_ip.is_empty() {
            // L2-only bridge — no host address (a vSwitch whose IPs
            // live only on the guests attached to it).
            out.push_str(&format!("iface {} inet manual\n", v.bridge_name));
        } else {
            out.push_str(&format!("iface {} inet static\n", v.bridge_name));
            out.push_str(&format!("    address {}\n", v.self_ip));
            out.push_str(&format!("    netmask {}\n", netmask));
        }
        out.push_str(&format!("    bridge-ports {}\n", vlan_iface));
        out.push_str("    bridge-stp off\n");
        out.push_str("    bridge-fd 0\n");
        out.push_str(&format!("    mtu {}\n", v.mtu));
        for r in &v.routes {
            out.push_str(&format!(
                "    up ip route add {} via {} dev {}\n",
                r.destination, r.via, v.bridge_name
            ));
            out.push_str(&format!(
                "    down ip route del {} via {} dev {} || true\n",
                r.destination, r.via, v.bridge_name
            ));
        }
        out.push('\n');
    }

    for p in &store.public_ips {
        out.push_str(&format!("# Public IP: {} to {} (egress {})\n",
            p.ip, p.container_internal_ip, p.egress_iface));
        // Claim the IP on lo so the host responds to ARP for it via
        // proxy_arp on the egress interface. Combined with the iptables
        // DNAT (managed separately by `apply_public_ip_iptables`), this
        // is the routed-mode pattern Hetzner / OVH document.
        out.push_str(&format!("auto lo:{}\n", short_ip_label(&p.ip)));
        out.push_str(&format!("iface lo:{} inet static\n", short_ip_label(&p.ip)));
        out.push_str(&format!("    address {}\n", p.ip));
        out.push_str("    netmask 255.255.255.255\n");
        out.push_str(&format!(
            "    up sysctl -w net.ipv4.conf.{}.proxy_arp=1\n",
            p.egress_iface
        ));
        out.push_str("    up sysctl -w net.ipv4.ip_forward=1\n");
        // Loose rp_filter so asymmetric DNAT/SNAT return paths aren't
        // dropped by the kernel's reverse-path check. See comment in
        // apply_public_ip_iptables() for the full reasoning.
        out.push_str("    up sysctl -w net.ipv4.conf.all.rp_filter=2\n");
        out.push_str("    up sysctl -w net.ipv4.conf.lo.rp_filter=2\n");
        out.push_str(&format!(
            "    up sysctl -w net.ipv4.conf.{}.rp_filter=2\n",
            p.egress_iface
        ));
        out.push('\n');
    }

    out
}

fn short_ip_label(ip: &str) -> String {
    // Linux interface aliases (lo:LABEL) cap at 15 chars. Replace dots
    // with nothing to fit longer IPs.
    let stripped: String = ip.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if stripped.len() > 12 { stripped[..12].to_string() } else { stripped }
}

fn cidr_prefix(s: &str) -> Option<u8> {
    s.rsplit_once('/').and_then(|(_, p)| p.parse().ok())
}

fn cidr_to_netmask_v4(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let octets = mask.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

// ────────────────────────────────────────────────────────────────────
// Preflight — does this look likely to break the operator's network?
// ────────────────────────────────────────────────────────────────────
//
// Applying a VLAN config touches the live network stack. On a remote
// host that's how the operator is connected to WolfStack, a wrong
// MTU, a typo'd parent NIC, or a renderer (netplan/NM) that briefly
// drops the link can lock the operator out. Preflight is a cheap
// "look before you leap" pass that surfaces likely problems in plain
// English BEFORE we touch anything.
//
// Output is consumed by the API layer (which blocks save unless the
// operator explicitly acknowledges critical findings) and by the
// frontend (which renders the findings inline).

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreflightSeverity {
    /// Will most likely break the operator's network connection.
    /// Apply requires explicit acknowledgement.
    Critical,
    /// Might disrupt traffic briefly or won't survive a reboot.
    /// Apply proceeds, but the operator should know.
    Warn,
    /// FYI only — what file we'll write, which manager we detected.
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightFinding {
    pub severity: PreflightSeverity,
    /// Plain-English summary (one short sentence).
    pub title: String,
    /// Why this is a concern, in operator-facing language.
    pub why: String,
    /// What to do about it (or "click Apply anyway if you accept the risk").
    pub fix: String,
}

/// Inspect the host + the proposed (or current) store and return a list
/// of findings the operator should see before applying. Pure-ish: shells
/// out to `ip` to inspect the live state; never modifies anything.
///
/// `proposed` is the VLAN being added or edited (None = check current
/// store as-is). When supplied, it's checked against the live host
/// state for problems that only appear at apply time.
pub fn preflight(
    store: &VlanStore,
    manager: NetManager,
    proposed: Option<&VlanAttachment>,
) -> Vec<PreflightFinding> {
    let mut findings: Vec<PreflightFinding> = Vec::new();

    // -- Always emit the manager FYI so the operator sees what'll run.
    findings.push(PreflightFinding {
        severity: PreflightSeverity::Info,
        title: format!("Network manager detected: {}", manager.label()),
        why: if manager.auto_persist_supported() {
            "WolfStack will write the persistent config and reload it.".into()
        } else {
            "WolfStack will only update the running kernel state — config will not survive a reboot.".into()
        },
        fix: String::new(),
    });

    // -- Manager-specific disruption warnings.
    match manager {
        NetManager::Netplan => {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Warn,
                title: "netplan apply briefly cycles the network".into(),
                why: "Running `netplan apply` regenerates and reloads the underlying renderer (NetworkManager or systemd-networkd). \
                      Active connections including SSH and the WolfStack admin session can drop for 1-3 seconds. \
                      If you only have one network path to this server, you may need to wait a moment for it to come back.".into(),
                fix: "Have console access (Hetzner Robot recovery / KVM-over-IP) ready in case the new VLAN config is wrong and you can't reconnect.".into(),
            });
        }
        NetManager::NetworkManager => {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Warn,
                title: "NetworkManager will recycle our connections".into(),
                why: "WolfStack creates the bridge and slave VLAN as `wolfstack-*` connections and brings them up. NetworkManager doesn't \
                      touch unrelated connections, but if your management IP happens to be on the same physical NIC, the link can flap briefly.".into(),
                fix: "Ensure your management/SSH IP is not on the same parent NIC, or have console access ready.".into(),
            });
        }
        NetManager::SystemdNetworkd => {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Warn,
                title: "networkctl reload may rebuild interfaces".into(),
                why: "The reload re-evaluates every .network unit. systemd-networkd usually leaves running interfaces alone, but in some cases it tears down and recreates them.".into(),
                fix: "Have console access ready before applying.".into(),
            });
        }
        NetManager::Ifupdown => {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Info,
                title: "ifupdown only affects newly-created interfaces".into(),
                why: "WolfStack writes /etc/network/interfaces.d/wolfstack-vlan.conf and runs `ip` directly. Existing interfaces are not touched.".into(),
                fix: String::new(),
            });
        }
        NetManager::Wicked | NetManager::Unknown => {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Warn,
                title: "No persistence writer for this network manager".into(),
                why: "Kernel state will be applied but won't survive a reboot. After applying, copy /var/lib/wolfstack/suggested-vlan-config.txt into your distro's network config format.".into(),
                fix: String::new(),
            });
        }
    }

    // -- Per-VLAN checks: combine the existing store with the proposed
    //    addition so we catch cross-vlan conflicts (duplicate bridge,
    //    overlapping subnets) even before the save lands.
    let mut all_vlans: Vec<&VlanAttachment> = store.vlans.iter().collect();
    if let Some(p) = proposed {
        // Replace any existing entry with the same id so we're checking
        // the proposed shape, not the saved one.
        if let Some(idx) = all_vlans.iter().position(|v| v.id == p.id && !p.id.is_empty()) {
            all_vlans[idx] = p;
        } else {
            all_vlans.push(p);
        }
    }

    for v in &all_vlans {
        // Parent NIC must exist on the host.
        if !iface_exists(&v.parent_iface) {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Critical,
                title: format!("Parent NIC '{}' doesn't exist on this host", v.parent_iface),
                why: format!(
                    "Your setup is currently probably not right — there is no `{}` interface on this server. \
                     `ip link show {}` returns nothing. The VLAN device can't be created on a non-existent parent.",
                    v.parent_iface, v.parent_iface,
                ),
                fix: "Run `ip -br link` to see the actual interface names on this host. Edit the VLAN to use the right one (commonly `eno1`, `enp1s0`, `eth0`, etc).".into(),
            });
            continue;
        }
        // Parent NIC must be UP. A VLAN sub-interface on a DOWN parent
        // gets created but no traffic flows.
        match iface_oper_state(&v.parent_iface) {
            Some(state) if state == "UP" => {}
            Some(other) => {
                findings.push(PreflightFinding {
                    severity: PreflightSeverity::Critical,
                    title: format!("Parent NIC '{}' is currently {}", v.parent_iface, other),
                    why: "A VLAN sub-interface on a non-UP parent gets created but no traffic flows. \
                         The kernel will accept the `ip link add` but nothing will ride on it until the parent comes up.".into(),
                    fix: format!("Bring the parent up first: `ip link set {} up`. If it won't come up, check the cable / switch port / driver.", v.parent_iface),
                });
                continue;
            }
            None => {} // couldn't read state — ignore rather than block
        }
        // Parent NIC MTU must be >= the VLAN MTU. The kernel doesn't
        // auto-raise the parent MTU; if it's lower, our VLAN MTU is
        // silently capped and packets bigger than the cap get dropped
        // or fragmented depending on PMTU discovery state.
        if let Some(parent_mtu) = iface_mtu(&v.parent_iface) {
            if parent_mtu < v.mtu {
                findings.push(PreflightFinding {
                    severity: PreflightSeverity::Critical,
                    title: format!(
                        "Parent NIC '{}' has MTU {} but the VLAN needs {}",
                        v.parent_iface, parent_mtu, v.mtu,
                    ),
                    why: "Your setup is currently probably not right — VLAN frames carry a 4-byte 802.1Q tag on top of the inner payload. \
                         If the parent NIC's MTU is smaller than the VLAN's intended MTU, the kernel won't grow the parent automatically; \
                         packets above the parent MTU get dropped or fragmented. For Hetzner this matters because Hetzner mandates MTU 1400 \
                         AND the parent NIC must be at least that high (their default is 1500, which is fine).".into(),
                    fix: format!(
                        "Raise the parent NIC's MTU first: `ip link set {} mtu {}` (and persist it in your network config).",
                        v.parent_iface, v.mtu,
                    ),
                });
            }
        }
        // Bridge name conflict — does it already exist as something else?
        if bridge_exists_unrelated(&v.bridge_name, &v.parent_iface, v.vlan_id) {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Critical,
                title: format!("Bridge name '{}' already in use", v.bridge_name),
                why: format!(
                    "An interface called `{}` already exists on this host that wasn't created by WolfStack for this VLAN. Applying would either fail outright or hijack an existing bridge — both are bad outcomes.",
                    v.bridge_name,
                ),
                fix: "Pick a different bridge name (the dialog defaults to `vmbr<vlan_id>` which is unique per VLAN).".into(),
            });
        }
        // Self-IP collision against another local IP on a different NIC.
        if let Some(other_iface) = address_exists_elsewhere(&v.self_ip, &v.bridge_name) {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Critical,
                title: format!("Self IP {} is already assigned to {}", v.self_ip, other_iface),
                why: format!(
                    "Your setup is currently probably not right — adding `{}` to the new bridge would create a duplicate-address situation with `{}`. The kernel will accept it but routing becomes ambiguous, and packets may go to the wrong interface.",
                    v.self_ip, other_iface,
                ),
                fix: "Pick a different self IP for the VLAN, or remove the existing assignment first.".into(),
            });
        }
        // Default-route NIC warning: applying on the same NIC as the
        // default gateway is the most common way to lose the operator.
        if Some(v.parent_iface.as_str()) == default_route_iface().as_deref() {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Warn,
                title: format!("Parent NIC '{}' carries this server's default route", v.parent_iface),
                why: format!(
                    "Your management connection to this server probably arrives via `{}`. Adding a VLAN tag on top of it shouldn't break the parent IP, but if the MTU is wrong (Hetzner needs 1400) or the parent goes down even briefly, you could be locked out.",
                    v.parent_iface,
                ),
                fix: "Have console access (Hetzner Robot, KVM-over-IP, OOB) ready before applying.".into(),
            });
        }
    }

    // -- Hetzner-specific: vSwitch port enforces a MAC allowlist by
    //    default. Containers/VMs attached to a bridge expose their own
    //    MACs upstream, which the vSwitch silently drops unless those
    //    MACs are registered in Hetzner Robot. Docker on Hetzner is fine
    //    because we use ipvlan L2 (single shared MAC), but LXC, Proxmox
    //    CT/VM, and libvirt all bridge unique MACs. The operator must
    //    know this before debugging "container has IP, no traffic".
    if all_vlans.iter().any(|v| matches!(v.provider, VlanProvider::Hetzner)) {
        findings.push(PreflightFinding {
            severity: PreflightSeverity::Warn,
            title: "Hetzner vSwitch may drop traffic from container/VM MACs".into(),
            why: "Hetzner vSwitch ports allow ONE MAC by default (the server's primary NIC MAC). \
                  Containers / VMs attached via a bridge expose their own MAC addresses upstream, \
                  and the vSwitch silently drops frames sourced from un-registered MACs. \
                  Symptoms: the guest gets the right IP, ARP works locally on the bridge, but no traffic \
                  reaches the rest of the vSwitch. WolfStack already uses ipvlan L2 for Docker on Hetzner \
                  (single shared MAC) — this warning applies to LXC, Proxmox CT, Proxmox VM, and libvirt VMs.".into(),
            fix: "Either: (a) register each guest's MAC in Hetzner Robot under your vSwitch settings, \
                  (b) put guests on a private subnet behind NAT instead of a bridged VLAN, \
                  or (c) use Docker (which we attach via ipvlan and is unaffected). \
                  This warning won't block apply — Hetzner does sometimes accept multi-MAC traffic — \
                  but if your guests can't reach other vSwitch members, this is the cause.".into(),
        });
    }

    // -- Cross-vlan sanity: same parent NIC + same VLAN ID is a duplicate.
    let mut seen: std::collections::HashMap<(String, u32), usize> = Default::default();
    for v in &all_vlans {
        let key = (v.parent_iface.clone(), v.vlan_id);
        *seen.entry(key).or_insert(0) += 1;
    }
    for ((parent, vid), count) in seen {
        if count > 1 {
            findings.push(PreflightFinding {
                severity: PreflightSeverity::Critical,
                title: format!("VLAN {} is configured twice on parent NIC {}", vid, parent),
                why: "The same (parent, VLAN ID) pair is defined twice. The kernel will reject the second `ip link add`, leaving you with one half-configured VLAN.".into(),
                fix: "Remove the duplicate definition.".into(),
            });
        }
    }

    findings
}

/// True if the named interface exists on this host. Cheap — uses
/// `ip link show <name>` and inspects the exit code (0 = exists,
/// non-zero = missing).
fn iface_exists(name: &str) -> bool {
    Command::new("ip").args(["link", "show", name]).status()
        .map(|s| s.success()).unwrap_or(false)
}

/// Return the operational state of an interface ("UP", "DOWN",
/// "UNKNOWN", "LOWERLAYERDOWN") or None if we can't tell. Read from
/// `ip -br link show <name>`. The third whitespace-separated column
/// is the operstate.
fn iface_oper_state(name: &str) -> Option<String> {
    let out = Command::new("ip").args(["-br", "link", "show", name]).output().ok()?;
    if !out.status.success() { return None; }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next()?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    cols.get(1).map(|s| s.to_string())
}

/// Return the MTU of an interface or None if we can't tell. Reads
/// `/sys/class/net/<name>/mtu` directly — faster than spawning `ip`
/// and unambiguous.
fn iface_mtu(name: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{}/mtu", name);
    std::fs::read_to_string(&path).ok()?.trim().parse().ok()
}

/// True if a bridge / interface called `name` exists AND it isn't
/// safe for us to take over.
///
/// "Safe to take over" means: a bridge previously created by WolfStack
/// for this exact (parent, vlan_id) pair. Any other existing interface
/// — Docker's docker0, libvirt's virbr0, k8s's cni0, an operator's hand-
/// rolled bridge, a bond, a tap, anything — counts as a conflict.
///
/// Detection: WolfStack always attaches the matching VLAN sub-interface
/// (e.g. `eno1.4000`) as a bridge member. If the existing bridge has
/// our expected sub-interface as a member, it's ours. If it has DIFFERENT
/// members (Docker/libvirt-style), it's not ours and reusing it would
/// hijack their workload.
fn bridge_exists_unrelated(name: &str, parent: &str, vlan_id: u32) -> bool {
    let out = Command::new("ip").args(["-d", "link", "show", name]).output();
    let info = match out {
        Ok(o) if o.status.success() => o,
        _ => return false, // doesn't exist → not a conflict
    };
    let stdout = String::from_utf8_lossy(&info.stdout);
    // Not a bridge at all (bond, team, tap, ethernet, tun, etc.) — hard conflict.
    if !stdout.contains("bridge") {
        return true;
    }
    // It IS a bridge. Check who's a member. If our expected VLAN sub-
    // interface is already a port on it, this is a previous WolfStack
    // bridge we can safely reuse. Otherwise it's somebody else's
    // (docker0, virbr0, cni0, hand-rolled, etc.).
    let expected_port = format!("{}.{}", parent, vlan_id);
    let members = bridge_members(name);
    if members.iter().any(|m| m == &expected_port) {
        return false;  // our bridge — safe to reuse
    }
    // No matching member. If the bridge has NO members at all, it's a
    // freshly-created empty bridge that's probably ours from a prior
    // half-completed apply — also safe to reuse.
    if members.is_empty() {
        return false;
    }
    true  // has members, none of them are ours — somebody else's bridge
}

/// List the slave interfaces (bridge ports) of a bridge by parsing
/// `ip link show master <bridge>`. Returns an empty vec on error or
/// when the bridge has no members.
fn bridge_members(bridge: &str) -> Vec<String> {
    let out = Command::new("ip").args(["-o", "link", "show", "master", bridge]).output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&stdout);
    let mut names = Vec::new();
    for line in s.lines() {
        // Format: "12: eth0@if13: <FLAGS> ..."
        if let Some(colon) = line.find(':') {
            let after = &line[colon + 1..];
            if let Some(next_colon) = after.find(':') {
                let name = after[..next_colon].trim();
                // Strip "@ifN" suffix (veth peer marker) and any whitespace.
                let name = name.split('@').next().unwrap_or(name).trim();
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

/// Check whether `ip` is already assigned to some interface that isn't
/// the bridge we're about to create. Returns the conflicting interface
/// name if one exists.
fn address_exists_elsewhere(ip: &str, our_bridge: &str) -> Option<String> {
    let out = Command::new("ip").args(["-o", "-4", "addr", "show"]).output().ok()?;
    if !out.status.success() { return None; }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        // Format: "2: eno1    inet 1.2.3.4/24 scope global ..."
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let iface = parts[1];
        let addr = parts[3];
        let plain = addr.split('/').next().unwrap_or(addr);
        if plain == ip && iface != our_bridge {
            return Some(iface.to_string());
        }
    }
    None
}

/// Best-effort "which interface is the default route on?" — used for
/// the "you might lock yourself out" warning. Returns None if we
/// can't tell.
fn default_route_iface() -> Option<String> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    if !out.status.success() { return None; }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // First line: "default via 1.2.3.4 dev eno1 proto static ..."
    for line in stdout.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev" {
                return it.next().map(|s| s.to_string());
            }
        }
    }
    None
}

// ────────────────────────────────────────────────────────────────────
// Apply
// ────────────────────────────────────────────────────────────────────

/// Apply the store's state to the running system. On supported distros
/// (ifupdown today) this writes the config snippet AND nudges the
/// running kernel state to match. On unsupported distros we write a
/// snippet to `/var/lib/wolfstack/suggested-vlan-config.txt` and
/// return a message telling the operator how to apply it manually.
///
/// Idempotent — calling apply twice in a row is a no-op the second
/// time. The kernel-side ops (`ip link add`, `ip addr add`, iptables)
/// all check for existing state and skip if already configured.
pub fn apply(store: &VlanStore) -> Result<ApplyReport, String> {
    let manager = detect_net_manager();
    let mut report = ApplyReport {
        manager,
        actions: Vec::new(),
        warnings: Vec::new(),
        manual_snippet: None,
    };

    // 1. Live kernel state (works on every distro — we use `ip` not
    //    distro-specific tooling). This makes the new VLANs usable
    //    NOW even before the persistence side is in place.
    apply_kernel_state(store, &mut report);

    // 2. Persistence — distro-specific.
    match manager {
        NetManager::Ifupdown => {
            persist_ifupdown(store, &mut report)?;
        }
        NetManager::Netplan => {
            persist_netplan(store, &mut report)?;
        }
        NetManager::NetworkManager => {
            persist_network_manager(store, &mut report);
        }
        NetManager::SystemdNetworkd => {
            persist_systemd_networkd(store, &mut report)?;
        }
        NetManager::Wicked | NetManager::Unknown => {
            // Wicked is rare (openSUSE only) and Unknown means no
            // detection signal fired. Fall back to a written snippet
            // the operator can adapt manually.
            let snippet = render_ifupdown(store);
            let path = "/var/lib/wolfstack/suggested-vlan-config.txt";
            if let Some(dir) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(path, &snippet);
            report.manual_snippet = Some(snippet);
            report.warnings.push(format!(
                "Network manager '{}' has no auto-persist writer in this \
                 WolfStack version — kernel state has been applied but \
                 will not survive a reboot. An ifupdown-equivalent \
                 snippet has been written to {} for manual translation.",
                manager.label(), path
            ));
        }
    }

    // 3. iptables for routed public IPs. Same on every distro.
    apply_public_ip_iptables(store, &mut report);

    Ok(report)
}

#[derive(Debug, Serialize)]
pub struct ApplyReport {
    pub manager: NetManager,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
    /// Populated only on unsupported managers; contains the config the
    /// operator should adapt to their distro.
    pub manual_snippet: Option<String>,
}

fn apply_kernel_state(store: &VlanStore, report: &mut ApplyReport) {
    for v in &store.vlans {
        let vlan_iface = format!("{}.{}", v.parent_iface, v.vlan_id);
        // Roll-back tracking: only undo what THIS apply created. Pre-
        // existing devices stay put.
        let mut created_vlan = false;
        let mut created_bridge = false;

        // VLAN sub-interface — distinguish "we created it" from
        // "already existed" so rollback knows what to undo.
        match try_run_ip(&["link", "add", "link", &v.parent_iface, "name", &vlan_iface,
                            "type", "vlan", "id", &v.vlan_id.to_string()]) {
            IpResult::Created => {
                created_vlan = true;
                report.actions.push(format!("created vlan {}", vlan_iface));
            }
            IpResult::AlreadyExists => {
                report.actions.push(format!("vlan {} already exists", vlan_iface));
            }
            IpResult::Failed(err) => {
                report.warnings.push(format!("create vlan {} failed: {}", vlan_iface, err));
                continue;
            }
        }
        // MTU + up are critical — without them the VLAN is unusable.
        // On failure, roll back the device we just created so the
        // operator gets a clean state to retry from. Hetzner's mandatory
        // MTU 1400 makes a failed mtu-set the single most common reason
        // packets drop on a vSwitch.
        if let Err(e) = run_ip_strict(&["link", "set", &vlan_iface, "mtu", &v.mtu.to_string()]) {
            report.warnings.push(format!("set vlan {} mtu failed: {} — rolling back", vlan_iface, e));
            if created_vlan {
                let _ = Command::new("ip").args(["link", "del", &vlan_iface]).status();
            }
            continue;
        }
        if let Err(e) = run_ip_strict(&["link", "set", &vlan_iface, "up"]) {
            report.warnings.push(format!("bring vlan {} up failed: {} — rolling back", vlan_iface, e));
            if created_vlan {
                let _ = Command::new("ip").args(["link", "del", &vlan_iface]).status();
            }
            continue;
        }

        // Bridge — created with explicit forward_delay=0 and stp_state=0.
        // Default forward_delay is 1500 centiseconds (15 SECONDS) regardless
        // of stp_state — verified live on this machine: `lxcbr0` shows
        // `forward_delay 1500` with `stp_state 0`. Without zeroing fd
        // explicitly, every guest attached to this bridge waits 15 seconds
        // before traffic flows.
        match try_run_ip(&["link", "add", "name", &v.bridge_name, "type", "bridge",
                            "forward_delay", "0", "stp_state", "0"]) {
            IpResult::Created => {
                created_bridge = true;
                report.actions.push(format!("created bridge {}", v.bridge_name));
            }
            IpResult::AlreadyExists => {
                report.actions.push(format!("bridge {} already exists", v.bridge_name));
            }
            IpResult::Failed(err) => {
                report.warnings.push(format!(
                    "create bridge {} failed: {} — rolling back vlan", v.bridge_name, err,
                ));
                if created_vlan {
                    let _ = Command::new("ip").args(["link", "del", &vlan_iface]).status();
                }
                continue;
            }
        }
        // Force fd=0/stp=off even on existing bridges — older WolfStack
        // installs may have created them with default fd=1500.
        let _ = Command::new("ip").args([
            "link", "set", &v.bridge_name, "type", "bridge",
            "forward_delay", "0", "stp_state", "0",
        ]).status();
        if let Err(e) = run_ip_strict(&["link", "set", &v.bridge_name, "mtu", &v.mtu.to_string()]) {
            report.warnings.push(format!(
                "set bridge {} mtu failed: {} — rolling back", v.bridge_name, e,
            ));
            if created_bridge { let _ = Command::new("ip").args(["link", "del", &v.bridge_name]).status(); }
            if created_vlan   { let _ = Command::new("ip").args(["link", "del", &vlan_iface]).status(); }
            continue;
        }
        if let Err(e) = run_ip_strict(&["link", "set", &vlan_iface, "master", &v.bridge_name]) {
            report.warnings.push(format!(
                "attach {} to {} failed: {} — rolling back", vlan_iface, v.bridge_name, e,
            ));
            if created_bridge { let _ = Command::new("ip").args(["link", "del", &v.bridge_name]).status(); }
            if created_vlan   { let _ = Command::new("ip").args(["link", "del", &vlan_iface]).status(); }
            continue;
        }
        // Bringing the bridge up shouldn't fail unless something is
        // very wrong with the kernel. Capture rather than rollback —
        // a bridge that's down still allows the operator to debug.
        run_ip_capture(&["link", "set", &v.bridge_name, "up"], report, "bring bridge up");

        // Address + routes — soft-failable, and skipped entirely for an
        // L2-only attachment (empty self_ip = pure bridge, no host
        // address; the bridge still works as a vSwitch for its guests).
        if !v.self_ip.is_empty() {
            let prefix = cidr_prefix(&v.subnet).unwrap_or(24);
            let cidr_self = format!("{}/{}", v.self_ip, prefix);
            run_ip_idempotent(
                &["addr", "add", &cidr_self, "dev", &v.bridge_name],
                report, "add address",
            );
            for r in &v.routes {
                run_ip_idempotent(
                    &["route", "add", &r.destination, "via", &r.via, "dev", &v.bridge_name],
                    report, "add route",
                );
            }
        }
    }
}

#[derive(Debug)]
enum IpResult {
    Created,
    AlreadyExists,
    Failed(String),
}

/// Attempt an `ip` command and classify the result so the caller can
/// distinguish "we just created it" (rollback responsibility on later
/// failure) from "already there" (no rollback needed) from "failed".
fn try_run_ip(args: &[&str]) -> IpResult {
    match Command::new("ip").args(args).output() {
        Ok(o) if o.status.success() => IpResult::Created,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if stderr.contains("File exists") || stderr.contains("already") {
                IpResult::AlreadyExists
            } else {
                IpResult::Failed(stderr.trim().to_string())
            }
        }
        Err(e) => IpResult::Failed(format!("spawn ip: {}", e)),
    }
}

/// Run an `ip` command that has no idempotent semantics — every non-zero
/// exit is a real failure the caller must handle (typically by rolling
/// back the partial state).
fn run_ip_strict(args: &[&str]) -> Result<(), String> {
    match Command::new("ip").args(args).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(format!("spawn ip: {}", e)),
    }
}

fn run_sysctl_capture(setting: &str, report: &mut ApplyReport, action: &str) {
    match Command::new("sysctl").args(["-w", setting]).output() {
        Ok(o) if o.status.success() => {
            report.actions.push(format!("sysctl -w {} ok", setting));
        }
        Ok(o) => {
            report.warnings.push(format!(
                "{} (sysctl -w {}) failed: {}",
                action, setting, String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            report.warnings.push(format!("{} could not spawn sysctl: {}", action, e));
        }
    }
}

/// Like `run_ip_idempotent` but without the "File exists" forgiveness.
/// Used for operations (mtu set, link up, master assignment) where the
/// kernel doesn't return a "harmless re-apply" error code — every
/// failure is a real failure that the operator should see.
fn run_ip_capture(args: &[&str], report: &mut ApplyReport, action: &str) {
    match Command::new("ip").args(args).output() {
        Ok(o) if o.status.success() => {
            report.actions.push(format!("ip {} ok", args.join(" ")));
        }
        Ok(o) => {
            report.warnings.push(format!(
                "{} ({}) failed: {}",
                action, args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            report.warnings.push(format!("{} could not spawn ip: {}", action, e));
        }
    }
}

fn run_ip_idempotent(args: &[&str], report: &mut ApplyReport, action: &str) {
    let out = Command::new("ip").args(args).output();
    match out {
        Ok(o) if o.status.success() => {
            report.actions.push(format!("ip {} to ok", args.join(" ")));
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // RTNETLINK answers File exists / Address already assigned
            // are the idempotent cases — not an error.
            if stderr.contains("File exists") || stderr.contains("already") {
                report.actions.push(format!("ip {} to already configured", args.join(" ")));
            } else {
                report.warnings.push(format!("{} ({}) failed: {}", action, args.join(" "), stderr.trim()));
            }
        }
        Err(e) => {
            report.warnings.push(format!("{} could not spawn ip: {}", action, e));
        }
    }
}

fn persist_ifupdown(store: &VlanStore, report: &mut ApplyReport) -> Result<(), String> {
    let snippet = render_ifupdown(store);
    if let Some(dir) = std::path::Path::new(IFUPDOWN_SNIPPET).parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            format!("create {}: {}", dir.display(), e)
        })?;
    }
    std::fs::write(IFUPDOWN_SNIPPET, &snippet).map_err(|e| {
        format!("write {}: {}", IFUPDOWN_SNIPPET, e)
    })?;
    report.actions.push(format!("wrote {}", IFUPDOWN_SNIPPET));

    // Most distros ship /etc/network/interfaces with a
    // `source /etc/network/interfaces.d/*` line at the top — that's what
    // pulls our snippet into the boot-time config. Minimal images
    // (some Hetzner installimage variants, custom rescue installs)
    // sometimes lack this line. The kernel state we just applied works
    // for THIS boot, but the next reboot would silently lose it.
    // Detect and warn rather than silently editing the operator's main
    // config file.
    if let Ok(main) = std::fs::read_to_string("/etc/network/interfaces") {
        let has_source = main.lines().any(|l| {
            let t = l.trim();
            !t.starts_with('#') && (
                t.starts_with("source /etc/network/interfaces.d")
                    || t.starts_with("source-directory /etc/network/interfaces.d")
            )
        });
        if !has_source {
            report.warnings.push(format!(
                "/etc/network/interfaces does not source /etc/network/interfaces.d/* — \
                 the snippet at {} will NOT be loaded at next reboot. Add this line near the top:\n  \
                 source /etc/network/interfaces.d/*",
                IFUPDOWN_SNIPPET
            ));
        }
    } else {
        report.warnings.push(
            "Could not read /etc/network/interfaces to verify it sources interfaces.d/. \
             If this server doesn't use ifupdown, the snippet won't apply at boot."
            .to_string()
        );
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Persistence — netplan
// ────────────────────────────────────────────────────────────────────

const NETPLAN_FILE: &str = "/etc/netplan/99-wolfstack-vlan.yaml";

/// Generate the netplan YAML for all VLANs in the store. Pure function
/// so it's unit-testable. Public IPs are NOT emitted here — netplan
/// can't express the proxy_arp + DNAT pattern natively, so iptables
/// state remains the source of truth for public IPs.
pub fn render_netplan(store: &VlanStore) -> String {
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — do not edit by hand.\n");
    out.push_str("# Source of truth: /etc/wolfstack/vlan-attachments.json\n");
    out.push_str("# Manage via the WolfStack UI: WolfRouter to Networking to VLANs\n");
    out.push_str("network:\n");
    out.push_str("  version: 2\n");
    if store.vlans.is_empty() {
        // netplan rejects empty top-level objects; emit a placeholder
        // ethernets entry that doesn't match anything.
        out.push_str("  ethernets: {}\n");
        return out;
    }
    out.push_str("  vlans:\n");
    for v in &store.vlans {
        let vlan_iface = format!("{}.{}", v.parent_iface, v.vlan_id);
        out.push_str(&format!("    {}:\n", vlan_iface));
        out.push_str(&format!("      id: {}\n", v.vlan_id));
        out.push_str(&format!("      link: {}\n", v.parent_iface));
        out.push_str(&format!("      mtu: {}\n", v.mtu));
        // No DHCP on the VLAN sub-interface — addresses live on the
        // bridge above. Without these explicitly false, some netplan
        // versions probe DHCP and add a transient default route.
        out.push_str("      dhcp4: false\n");
        out.push_str("      dhcp6: false\n");
        // Don't auto-assign IPv6 link-local on the VLAN — it would
        // pull in router advertisements from anything on the VLAN
        // claiming to be a router.
        out.push_str("      link-local: []\n");
        out.push_str("      accept-ra: false\n");
    }
    out.push_str("  bridges:\n");
    for v in &store.vlans {
        let vlan_iface = format!("{}.{}", v.parent_iface, v.vlan_id);
        let prefix = cidr_prefix(&v.subnet).unwrap_or(24);
        out.push_str(&format!("    {}:\n", v.bridge_name));
        out.push_str(&format!("      interfaces: [{}]\n", vlan_iface));
        out.push_str(&format!("      mtu: {}\n", v.mtu));
        if !v.self_ip.is_empty() {
            out.push_str(&format!("      addresses: [\"{}/{}\"]\n", v.self_ip, prefix));
        }
        // dhcp/v6 hygiene matching the VLAN above. Bridges without
        // these are a common source of "I added a static address but
        // there's also a DHCP one" confusion.
        out.push_str("      dhcp4: false\n");
        out.push_str("      dhcp6: false\n");
        out.push_str("      link-local: []\n");
        out.push_str("      accept-ra: false\n");
        out.push_str("      parameters:\n");
        out.push_str("        stp: false\n");
        // forward-delay 0 is the same kernel-default-15s footgun every
        // other renderer hits. Without it, guests wait 15s on attach.
        out.push_str("        forward-delay: 0\n");
        if !v.routes.is_empty() {
            out.push_str("      routes:\n");
            for r in &v.routes {
                out.push_str(&format!("        - to: {}\n", r.destination));
                out.push_str(&format!("          via: {}\n", r.via));
            }
        }
    }
    out
}

fn persist_netplan(store: &VlanStore, report: &mut ApplyReport) -> Result<(), String> {
    let yaml = render_netplan(store);
    if let Some(dir) = std::path::Path::new(NETPLAN_FILE).parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            format!("create {}: {}", dir.display(), e)
        })?;
    }
    // netplan complains about world-readable YAML in 0.106+; lock the
    // file down at write time.
    std::fs::write(NETPLAN_FILE, &yaml).map_err(|e| {
        format!("write {}: {}", NETPLAN_FILE, e)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(NETPLAN_FILE, std::fs::Permissions::from_mode(0o600));
    }
    report.actions.push(format!("wrote {}", NETPLAN_FILE));

    // Apply via netplan apply — this regenerates the renderer (NM or
    // networkd) config and reloads the live state. We `try` not the
    // hot path because a netplan parse error here would otherwise
    // leave the operator with valid kernel state but stale persistence.
    match Command::new("netplan").arg("apply").output() {
        Ok(o) if o.status.success() => {
            report.actions.push("netplan apply ok".into());
        }
        Ok(o) => {
            report.warnings.push(format!(
                "netplan apply failed (exit {}): {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            report.warnings.push(format!(
                "could not spawn netplan: {} — config written but not applied", e
            ));
        }
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Persistence — NetworkManager (nmcli)
// ────────────────────────────────────────────────────────────────────

/// Connection-name prefix for everything we create. Lets us find and
/// clean up our own connections without touching operator-created ones.
const NM_PREFIX: &str = "wolfstack-";

/// Render the equivalent nmcli command sequence as a /bin/sh script.
/// Pure function — used by tests + future preview UI integration so the
/// operator can see the exact commands before they run. Kept as the
/// source-of-truth for what `persist_network_manager` does.
#[allow(dead_code)]
pub fn render_nm_script(store: &VlanStore) -> String {
    let mut out = String::new();
    out.push_str("#!/bin/sh\n");
    out.push_str("# Auto-generated by WolfStack — do not edit by hand.\n");
    out.push_str("# Source of truth: /etc/wolfstack/vlan-attachments.json\n");
    out.push_str("set -e\n\n");
    out.push_str("# Tear down stale WolfStack connections so the script is idempotent.\n");
    out.push_str("for c in $(nmcli -t -f NAME connection show 2>/dev/null | grep '^wolfstack-'); do\n");
    out.push_str("  nmcli connection delete \"$c\" || true\n");
    out.push_str("done\n\n");
    for v in &store.vlans {
        let prefix = cidr_prefix(&v.subnet).unwrap_or(24);
        let bridge_con = format!("{}br-{}", NM_PREFIX, v.bridge_name);
        let vlan_con = format!("{}vlan-{}-{}", NM_PREFIX, v.parent_iface, v.vlan_id);
        out.push_str(&format!("# VLAN {} (provider: {:?})\n", v.name, v.provider));
        // bridge.forward-delay 0 — same kernel-default-1500 footgun as
        // every other renderer. Without this, NM creates the bridge with
        // fd=15s and guests wait that long for traffic.
        let ipv4_cfg = if v.self_ip.is_empty() {
            "ipv4.method disabled".to_string()  // L2-only — no host IPv4
        } else {
            format!("ipv4.method manual ipv4.addresses '{}/{}'", v.self_ip, prefix)
        };
        out.push_str(&format!(
            "nmcli connection add type bridge con-name '{}' ifname '{}' \
             {} ipv6.method ignore stp no bridge.forward-delay 0 802-3-ethernet.mtu {}\n",
            bridge_con, v.bridge_name, ipv4_cfg, v.mtu,
        ));
        out.push_str(&format!(
            "nmcli connection add type vlan con-name '{}' ifname '{}.{}' \
             dev '{}' id {} master '{}' slave-type bridge 802-3-ethernet.mtu {}\n",
            vlan_con, v.parent_iface, v.vlan_id, v.parent_iface, v.vlan_id,
            v.bridge_name, v.mtu,
        ));
        for r in &v.routes {
            out.push_str(&format!(
                "nmcli connection modify '{}' +ipv4.routes '{} {}'\n",
                bridge_con, r.destination, r.via,
            ));
        }
        out.push_str(&format!("nmcli connection up '{}'\n", bridge_con));
        out.push_str(&format!("nmcli connection up '{}'\n", vlan_con));
        out.push('\n');
    }
    out
}

fn persist_network_manager(store: &VlanStore, report: &mut ApplyReport) {
    // Diff-then-apply rather than wipe-and-recreate. Editing one VLAN
    // must NOT flap every other VLAN — that's an outage on production
    // workloads attached to those bridges. We compute the desired set
    // of connection names from the store, list the existing wolfstack-
    // prefixed connections, delete only the ones we no longer want,
    // and skip recreation when an existing connection already matches.

    // Desired connection names (bridge + slave VLAN per VLAN).
    let mut desired: std::collections::HashSet<String> = Default::default();
    for v in &store.vlans {
        desired.insert(format!("{}br-{}", NM_PREFIX, v.bridge_name));
        desired.insert(format!("{}vlan-{}-{}", NM_PREFIX, v.parent_iface, v.vlan_id));
    }

    // Existing wolfstack-prefixed connections.
    let listed = Command::new("nmcli")
        .args(["-t", "-f", "NAME", "connection", "show"])
        .output();
    let existing: std::collections::HashSet<String> = match listed {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|n| n.starts_with(NM_PREFIX))
                .map(|n| n.to_string())
                .collect()
        }
        Ok(out) => {
            report.warnings.push(format!(
                "nmcli connection show failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
            return;
        }
        Err(_) => {
            report.warnings.push(
                "could not spawn nmcli — NetworkManager persistence skipped".into(),
            );
            return;
        }
    };

    // Delete existing connections that aren't in the desired set
    // (vlans that the operator removed). Existing+desired connections
    // we leave alone — touching them would flap the bridge.
    for stale in existing.difference(&desired) {
        let r = Command::new("nmcli")
            .args(["connection", "delete", stale])
            .output();
        match r {
            Ok(o) if o.status.success() => {
                report.actions.push(format!("deleted stale nmcli connection {}", stale));
            }
            Ok(o) => report.warnings.push(format!(
                "delete stale {} failed: {}", stale,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => report.warnings.push(format!(
                "spawn nmcli delete failed: {}", e
            )),
        }
    }

    // Create only the connections that don't already exist. Operators
    // editing an existing VLAN's parameters (e.g. adding a route) need
    // explicit re-creation — that's a separate endpoint we'd add for
    // "force-reconcile a VLAN". For the steady-state case (add/remove
    // VLANs without editing existing ones), this is the right call.
    for v in &store.vlans {
        let prefix = cidr_prefix(&v.subnet).unwrap_or(24);
        let bridge_con = format!("{}br-{}", NM_PREFIX, v.bridge_name);
        let vlan_con = format!("{}vlan-{}-{}", NM_PREFIX, v.parent_iface, v.vlan_id);
        let addr = format!("{}/{}", v.self_ip, prefix);
        let mtu = v.mtu.to_string();
        let vlan_id = v.vlan_id.to_string();
        let vlan_ifname = format!("{}.{}", v.parent_iface, v.vlan_id);

        // Skip creation if the connection already exists. This is the
        // "diff-then-apply" half: we only mutate connections that
        // weren't there before, so unrelated bridges keep their
        // running state.
        let bridge_already = existing.contains(&bridge_con);
        let vlan_already = existing.contains(&vlan_con);
        if bridge_already && vlan_already {
            report.actions.push(format!(
                "nmcli {} and {} already present — left untouched", bridge_con, vlan_con
            ));
            continue;
        }

        // Create the bridge connection. bridge.forward-delay 0 is
        // critical — NM otherwise inherits kernel default fd=15s.
        if bridge_already {
            report.actions.push(format!("nmcli {} already present", bridge_con));
        } else {
        let mut bridge_args: Vec<&str> = vec![
            "connection", "add",
            "type", "bridge",
            "con-name", bridge_con.as_str(),
            "ifname", v.bridge_name.as_str(),
        ];
        if v.self_ip.is_empty() {
            // L2-only bridge — no IPv4 on the host side.
            bridge_args.extend_from_slice(&["ipv4.method", "disabled"]);
        } else {
            bridge_args.extend_from_slice(&[
                "ipv4.method", "manual", "ipv4.addresses", addr.as_str(),
            ]);
        }
        bridge_args.extend_from_slice(&[
            "ipv6.method", "ignore",
            "stp", "no",
            "bridge.forward-delay", "0",
            "802-3-ethernet.mtu", mtu.as_str(),
        ]);
        run_nmcli_capture(&bridge_args, report, &format!("create bridge {}", bridge_con));
        }

        // Slave VLAN connection.
        if vlan_already {
            report.actions.push(format!("nmcli {} already present", vlan_con));
        } else {
        let vlan_args = vec![
            "connection", "add",
            "type", "vlan",
            "con-name", vlan_con.as_str(),
            "ifname", vlan_ifname.as_str(),
            "dev", v.parent_iface.as_str(),
            "id", vlan_id.as_str(),
            "master", v.bridge_name.as_str(),
            "slave-type", "bridge",
            "802-3-ethernet.mtu", mtu.as_str(),
        ];
        run_nmcli_capture(&vlan_args, report, &format!("create vlan {}", vlan_con));
        }

        // Routes — only added when we created the bridge (otherwise
        // we'd accumulate duplicate +ipv4.routes entries on re-apply).
        if !bridge_already {
        for r in &v.routes {
            let route_spec = format!("{} {}", r.destination, r.via);
            let route_args = vec![
                "connection", "modify", bridge_con.as_str(),
                "+ipv4.routes", route_spec.as_str(),
            ];
            run_nmcli_capture(&route_args, report, &format!("add route {}", r.destination));
        }
        }

        // Bring up only what we just created. Existing connections
        // stay up — flapping them would knock attached guests offline.
        if !bridge_already {
            run_nmcli_capture(
                &["connection", "up", bridge_con.as_str()],
                report, &format!("up {}", bridge_con),
            );
        }
        if !vlan_already {
            run_nmcli_capture(
                &["connection", "up", vlan_con.as_str()],
                report, &format!("up {}", vlan_con),
            );
        }
    }
}

fn run_nmcli_capture(args: &[&str], report: &mut ApplyReport, action: &str) {
    match Command::new("nmcli").args(args).output() {
        Ok(o) if o.status.success() => {
            report.actions.push(format!("nmcli {} ok", args.join(" ")));
        }
        Ok(o) => {
            report.warnings.push(format!(
                "{} failed: {}",
                action,
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            report.warnings.push(format!("{} could not spawn nmcli: {}", action, e));
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Persistence — systemd-networkd
// ────────────────────────────────────────────────────────────────────

const SD_NETWORKD_DIR: &str = "/etc/systemd/network";
const SD_NETWORKD_PREFIX: &str = "10-wolfstack-";

/// Generate the per-file content map for systemd-networkd. Returns
/// (filename, content) pairs so `persist_systemd_networkd` can write
/// them and so tests can assert against the rendered output.
///
/// The naming scheme uses our prefix so cleanup is a glob match; we
/// also emit a drop-in for the parent NIC's `.network` (under
/// `<parent>.network.d/wolfstack-vlan.conf`) declaring `VLAN=...` so
/// the operator's existing config is composed-with rather than
/// overwritten. This drop-in is necessary because systemd-networkd
/// only creates VLAN devices when a parent .network file lists them.
pub fn render_systemd_networkd_files(store: &VlanStore) -> Vec<(String, String)> {
    let mut files = Vec::new();
    // Group by parent for the drop-in step.
    let mut parents: std::collections::BTreeMap<&str, Vec<&VlanAttachment>> = Default::default();
    for v in &store.vlans {
        parents.entry(v.parent_iface.as_str()).or_default().push(v);
    }
    for (parent, vlans) in &parents {
        let mut dropin = String::new();
        dropin.push_str("# Auto-generated by WolfStack — drop-in to declare VLAN devices.\n");
        dropin.push_str("[Network]\n");
        for v in vlans {
            dropin.push_str(&format!("VLAN={}.{}\n", v.parent_iface, v.vlan_id));
        }
        // Drop-in path: <parent>.network.d/wolfstack-vlan.conf — applies
        // to whichever .network file matches the parent. If none exists
        // it has no effect; we warn separately.
        files.push((
            format!("{}.network.d/wolfstack-vlan.conf", parent),
            dropin,
        ));
    }

    for v in &store.vlans {
        let vlan_iface = format!("{}.{}", v.parent_iface, v.vlan_id);
        let prefix = cidr_prefix(&v.subnet).unwrap_or(24);

        // VLAN netdev.
        let mut netdev = String::new();
        netdev.push_str("# Auto-generated by WolfStack — VLAN device.\n");
        netdev.push_str("[NetDev]\n");
        netdev.push_str(&format!("Name={}\n", vlan_iface));
        netdev.push_str("Kind=vlan\n");
        netdev.push_str(&format!("MTUBytes={}\n", v.mtu));
        netdev.push_str("\n[VLAN]\n");
        netdev.push_str(&format!("Id={}\n", v.vlan_id));
        files.push((format!("{}vlan-{}.netdev", SD_NETWORKD_PREFIX, vlan_iface), netdev));

        // VLAN .network — binds the vlan iface to the bridge.
        let mut vlan_net = String::new();
        vlan_net.push_str("# Auto-generated by WolfStack — VLAN-to-bridge binding.\n");
        vlan_net.push_str("[Match]\n");
        vlan_net.push_str(&format!("Name={}\n", vlan_iface));
        vlan_net.push_str("\n[Network]\n");
        vlan_net.push_str(&format!("Bridge={}\n", v.bridge_name));
        files.push((format!("{}vlan-{}.network", SD_NETWORKD_PREFIX, vlan_iface), vlan_net));

        // Bridge netdev. The [Bridge] section here (not in .network!) is
        // where forward-delay / STP for the bridge ITSELF belong. The
        // [Bridge] section in a .network file configures bridge-PORT
        // settings, not the bridge device. Easy to confuse; systemd
        // accepts both placements but only the netdev one takes effect
        // for the bridge device.
        let mut br_dev = String::new();
        br_dev.push_str("# Auto-generated by WolfStack — bridge device.\n");
        br_dev.push_str("[NetDev]\n");
        br_dev.push_str(&format!("Name={}\n", v.bridge_name));
        br_dev.push_str("Kind=bridge\n");
        br_dev.push_str(&format!("MTUBytes={}\n", v.mtu));
        br_dev.push_str("\n[Bridge]\n");
        br_dev.push_str("STP=no\n");
        // ForwardDelaySec=0 — without this, kernel default is 15 SECONDS
        // even when STP is off. Guests would wait 15s for traffic to flow.
        br_dev.push_str("ForwardDelaySec=0\n");
        // Disable IGMP snooping — generally fine for small bridges, but
        // can drop multicast (e.g. mDNS) for guests until snooping
        // entries learn. Leaving on by default; operators who need it
        // off can edit. (Documented as default-on, no override here.)
        files.push((format!("{}bridge-{}.netdev", SD_NETWORKD_PREFIX, v.bridge_name), br_dev));

        // Bridge .network — IP, routes, no v6 surprises.
        let mut br_net = String::new();
        br_net.push_str("# Auto-generated by WolfStack — bridge IP/routes.\n");
        br_net.push_str("[Match]\n");
        br_net.push_str(&format!("Name={}\n", v.bridge_name));
        br_net.push_str("\n[Network]\n");
        if !v.self_ip.is_empty() {
            br_net.push_str(&format!("Address={}/{}\n", v.self_ip, prefix));
        }
        // Explicit IPv6 hygiene: don't accept RA on the bridge (could
        // pull in an unwanted default route from a router on the VLAN);
        // don't auto-assign link-local v6 addresses on the bridge.
        // Operators wanting v6 on the bridge can edit and add it.
        br_net.push_str("IPv6AcceptRA=no\n");
        br_net.push_str("LinkLocalAddressing=no\n");
        // Configure the bridge even when no port has carrier yet —
        // otherwise systemd-networkd waits for a port up at boot,
        // delaying the address assignment and any guest startup.
        br_net.push_str("ConfigureWithoutCarrier=yes\n");
        for r in &v.routes {
            br_net.push_str("\n[Route]\n");
            br_net.push_str(&format!("Destination={}\n", r.destination));
            br_net.push_str(&format!("Gateway={}\n", r.via));
        }
        files.push((format!("{}bridge-{}.network", SD_NETWORKD_PREFIX, v.bridge_name), br_net));
    }
    files
}

fn persist_systemd_networkd(store: &VlanStore, report: &mut ApplyReport) -> Result<(), String> {
    // Clean up stale wolfstack-prefixed files so re-runs converge.
    if let Ok(entries) = std::fs::read_dir(SD_NETWORKD_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if name_s.starts_with(SD_NETWORKD_PREFIX) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let files = render_systemd_networkd_files(store);
    let mut parents_with_dropin: std::collections::HashSet<String> = Default::default();
    for (rel, content) in &files {
        let full = format!("{}/{}", SD_NETWORKD_DIR, rel);
        if let Some(dir) = std::path::Path::new(&full).parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                format!("create {}: {}", dir.display(), e)
            })?;
        }
        std::fs::write(&full, content).map_err(|e| format!("write {}: {}", full, e))?;
        report.actions.push(format!("wrote {}", full));
        // Track which parent .network drop-ins we wrote so we can warn
        // if the parent .network doesn't exist.
        if let Some(stem) = rel.strip_suffix(".network.d/wolfstack-vlan.conf") {
            parents_with_dropin.insert(stem.to_string());
        }
    }

    // Warn if no parent .network exists — the drop-in will be inert.
    for parent in &parents_with_dropin {
        let parent_network_exists = std::fs::read_dir(SD_NETWORKD_DIR)
            .map(|rd| rd.flatten().any(|e| {
                let n = e.file_name();
                let s = n.to_string_lossy();
                s.ends_with(".network") && !s.starts_with(SD_NETWORKD_PREFIX) && {
                    // Look for [Match] Name=parent inside.
                    std::fs::read_to_string(e.path())
                        .map(|c| c.contains(&format!("Name={}", parent)))
                        .unwrap_or(false)
                }
            }))
            .unwrap_or(false);
        if !parent_network_exists {
            report.warnings.push(format!(
                "No existing systemd-networkd .network unit was found for parent NIC '{}'. \
                 The VLAN drop-in needs the parent's .network to exist, otherwise the \
                 VLAN device will not be created at boot. Create a minimal \
                 /etc/systemd/network/10-{}.network with `[Match]\\nName={}\\n[Network]\\nDHCP=yes` \
                 (or your preferred config) and re-apply.",
                parent, parent, parent
            ));
        }
    }

    // Reload + reconfigure.
    match Command::new("networkctl").arg("reload").output() {
        Ok(o) if o.status.success() => {
            report.actions.push("networkctl reload ok".into());
        }
        Ok(o) => {
            report.warnings.push(format!(
                "networkctl reload failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            report.warnings.push(format!(
                "could not spawn networkctl: {} — config written but not applied", e
            ));
        }
    }
    Ok(())
}

fn apply_public_ip_iptables(store: &VlanStore, report: &mut ApplyReport) {
    if store.public_ips.is_empty() { return; }

    // Make sure ip_forward is on — needed for both VLAN bridges acting
    // as gateways AND for routed public IPs.
    run_sysctl_capture("net.ipv4.ip_forward=1", report, "enable ip_forward");

    // Loose-mode reverse path filter on `all` and `lo`. The DNAT/SNAT
    // pattern is asymmetric: an inbound packet destined to the public
    // IP arrives on the egress NIC, gets DNAT'd to the container's
    // internal IP, and is forwarded to the bridge. The reply packet
    // sources from the public IP (after SNAT) but exits via the egress
    // NIC — the kernel's strict rp_filter (mode 1) checks "is the
    // route to source-IP via this interface?" and finds it isn't (the
    // public IP lives on lo), so it drops the reply. Setting rp_filter
    // to loose (2) tells the kernel to accept any path back. This is
    // the documented Linux pattern for routed-mode public IPs.
    run_sysctl_capture("net.ipv4.conf.all.rp_filter=2", report, "loose rp_filter on all");
    run_sysctl_capture("net.ipv4.conf.lo.rp_filter=2", report, "loose rp_filter on lo");

    for p in &store.public_ips {
        // Add the IP to lo so the host claims it (proxy_arp answers
        // ARP requests for any local IP).
        let cidr_self = format!("{}/32", p.ip);
        run_ip_idempotent(&["addr", "add", &cidr_self, "dev", "lo"], report, "claim public ip");
        // Enable proxy_arp on the egress interface.
        run_sysctl_capture(
            &format!("net.ipv4.conf.{}.proxy_arp=1", p.egress_iface),
            report,
            &format!("enable proxy_arp on {}", p.egress_iface),
        );
        // Per-interface rp_filter loose on the egress NIC too — strict
        // mode there would also drop our asymmetric returns.
        run_sysctl_capture(
            &format!("net.ipv4.conf.{}.rp_filter=2", p.egress_iface),
            report,
            &format!("loose rp_filter on {}", p.egress_iface),
        );

        // DNAT inbound + SNAT outbound. We don't `iptables -D` first
        // because that would race with -A — instead we check via -C
        // (check) before adding, so reapplying is idempotent.
        let dnat_args = vec![
            "-t", "nat", "-C", "PREROUTING",
            "-d", &p.ip, "-j", "DNAT",
            "--to-destination", &p.container_internal_ip,
        ];
        let need_dnat = !Command::new("iptables").args(&dnat_args).status()
            .map(|s| s.success()).unwrap_or(false);
        if need_dnat {
            let dnat_add: Vec<&str> = dnat_args.iter().enumerate()
                .map(|(i, a)| if i == 2 { &"-A" } else { a }).copied().collect();
            let r = Command::new("iptables").args(&dnat_add).status();
            match r {
                Ok(s) if s.success() => report.actions.push(format!("DNAT {} to {} added", p.ip, p.container_internal_ip)),
                Ok(s) => report.warnings.push(format!("iptables DNAT for {} failed (exit {})", p.ip, s.code().unwrap_or(-1))),
                Err(e) => report.warnings.push(format!("iptables DNAT spawn failed for {}: {}", p.ip, e)),
            }
        }

        let snat_args = vec![
            "-t", "nat", "-C", "POSTROUTING",
            "-s", &p.container_internal_ip, "-o", &p.egress_iface,
            "-j", "SNAT", "--to-source", &p.ip,
        ];
        let need_snat = !Command::new("iptables").args(&snat_args).status()
            .map(|s| s.success()).unwrap_or(false);
        if need_snat {
            let snat_add: Vec<&str> = snat_args.iter().enumerate()
                .map(|(i, a)| if i == 2 { &"-A" } else { a }).copied().collect();
            let r = Command::new("iptables").args(&snat_add).status();
            match r {
                Ok(s) if s.success() => report.actions.push(format!("SNAT {} ← {} added", p.ip, p.container_internal_ip)),
                Ok(s) => report.warnings.push(format!("iptables SNAT for {} failed (exit {})", p.ip, s.code().unwrap_or(-1))),
                Err(e) => report.warnings.push(format!("iptables SNAT spawn failed for {}: {}", p.ip, e)),
            }
        }
    }
}

/// Tear down a single VLAN's runtime state without removing other
/// VLANs. Best-effort — failures here just mean the operator cleans up
/// manually with `ip link del`. Used after `remove_vlan` + `apply`.
pub fn teardown_vlan_kernel_state(parent: &str, vlan_id: u32, bridge: &str) {
    let _ = Command::new("ip").args(["link", "set", bridge, "down"]).status();
    let _ = Command::new("ip").args(["link", "del", bridge]).status();
    let vlan_iface = format!("{}.{}", parent, vlan_id);
    let _ = Command::new("ip").args(["link", "del", &vlan_iface]).status();
}

/// Tear down a single public IP's runtime state.
pub fn teardown_public_ip_kernel_state(ip: &str, internal_ip: &str, egress: &str) {
    let cidr_self = format!("{}/32", ip);
    let _ = Command::new("ip").args(["addr", "del", &cidr_self, "dev", "lo"]).status();
    let _ = Command::new("iptables").args([
        "-t", "nat", "-D", "PREROUTING", "-d", ip, "-j", "DNAT", "--to-destination", internal_ip,
    ]).status();
    let _ = Command::new("iptables").args([
        "-t", "nat", "-D", "POSTROUTING",
        "-s", internal_ip, "-o", egress, "-j", "SNAT", "--to-source", ip,
    ]).status();
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hetzner_vlan_id_must_be_in_range() {
        assert!(VlanProvider::Hetzner.validate_vlan_id(4000).is_ok());
        assert!(VlanProvider::Hetzner.validate_vlan_id(4091).is_ok());
        assert!(VlanProvider::Hetzner.validate_vlan_id(3999).is_err());
        assert!(VlanProvider::Hetzner.validate_vlan_id(4092).is_err());
    }

    #[test]
    fn ovh_and_custom_accept_any_802_1q_vlan() {
        for p in [VlanProvider::Ovh, VlanProvider::Equinix, VlanProvider::Custom] {
            assert!(p.validate_vlan_id(1).is_ok());
            assert!(p.validate_vlan_id(4094).is_ok());
            assert!(p.validate_vlan_id(0).is_err(), "VLAN 0 is reserved");
            assert!(p.validate_vlan_id(4095).is_err(), "VLAN 4095 is reserved");
        }
    }

    #[test]
    fn provider_default_mtu_matches_carrier_rules() {
        assert_eq!(VlanProvider::Hetzner.default_mtu(), 1400);
        assert_eq!(VlanProvider::Ovh.default_mtu(), 1500);
        assert_eq!(VlanProvider::Custom.default_mtu(), 1500);
    }

    #[test]
    fn ip_in_cidr_v4_basic_cases() {
        assert!(ip_in_cidr("10.0.1.5", "10.0.1.0/24").unwrap());
        assert!(!ip_in_cidr("10.0.2.5", "10.0.1.0/24").unwrap());
        assert!(ip_in_cidr("10.0.1.255", "10.0.1.0/24").unwrap());
        assert!(ip_in_cidr("192.168.1.1", "192.168.0.0/16").unwrap());
        assert!(!ip_in_cidr("192.169.0.1", "192.168.0.0/16").unwrap());
    }

    #[test]
    fn ip_in_cidr_rejects_mismatched_families() {
        assert!(ip_in_cidr("10.0.0.1", "fe80::/10").is_err());
    }

    #[test]
    fn cidr_to_netmask_known_values() {
        assert_eq!(cidr_to_netmask_v4(24), "255.255.255.0");
        assert_eq!(cidr_to_netmask_v4(16), "255.255.0.0");
        assert_eq!(cidr_to_netmask_v4(32), "255.255.255.255");
        assert_eq!(cidr_to_netmask_v4(0), "0.0.0.0");
        assert_eq!(cidr_to_netmask_v4(28), "255.255.255.240");
    }

    #[test]
    fn validate_vlan_attachment_full() {
        let v = VlanAttachment {
            id: String::new(),
            name: "test".into(),
            provider: VlanProvider::Hetzner,
            parent_iface: "eno1".into(),
            vlan_id: 4000,
            mtu: 1400,
            bridge_name: "vmbr4000".into(),
            subnet: "10.0.1.0/24".into(),
            self_ip: "10.0.1.5".into(),
            routes: vec![RouteEntry { destination: "10.0.0.0/16".into(), via: "10.0.1.1".into() }], allocations: vec![], external_reservations: vec![],
            notes: String::new(),
        };
        validate_vlan_attachment(&v).expect("valid attachment must pass");
    }

    #[test]
    fn validate_vlan_attachment_l2_only() {
        // Empty subnet AND self_ip = L2-only bridge — valid (no host IP).
        let mut v = VlanAttachment {
            id: String::new(),
            name: "l2only".into(),
            provider: VlanProvider::Hetzner,
            parent_iface: "eno1".into(),
            vlan_id: 4000,
            mtu: 1400,
            bridge_name: "vmbr4000".into(),
            subnet: String::new(),
            self_ip: String::new(),
            routes: vec![], allocations: vec![], external_reservations: vec![],
            notes: String::new(),
        };
        validate_vlan_attachment(&v).expect("L2-only attachment must pass");
        // Exactly one of subnet/self_ip empty = inconsistent → rejected.
        v.subnet = "10.0.1.0/24".into();
        assert!(validate_vlan_attachment(&v).is_err(), "subnet without self_ip must fail");
        // L2-only cannot carry routes (routes need a subnet).
        v.subnet = String::new();
        v.routes = vec![RouteEntry { destination: "10.0.0.0/16".into(), via: "10.0.1.1".into() }];
        assert!(validate_vlan_attachment(&v).is_err(), "L2-only with routes must fail");
    }

    #[test]
    fn validate_vlan_attachment_rejects_self_ip_outside_subnet() {
        let mut v = VlanAttachment {
            id: String::new(), name: "x".into(), provider: VlanProvider::Custom,
            parent_iface: "eno1".into(), vlan_id: 100, mtu: 1500,
            bridge_name: "br100".into(), subnet: "10.0.1.0/24".into(),
            self_ip: "10.0.2.5".into(), routes: vec![],
            allocations: vec![], external_reservations: vec![], notes: String::new(),
        };
        assert!(validate_vlan_attachment(&v).is_err());
        // and a fixed version passes
        v.self_ip = "10.0.1.5".into();
        assert!(validate_vlan_attachment(&v).is_ok());
    }

    #[test]
    fn validate_rejects_route_via_outside_subnet() {
        let v = VlanAttachment {
            id: String::new(), name: "x".into(), provider: VlanProvider::Custom,
            parent_iface: "eno1".into(), vlan_id: 100, mtu: 1500,
            bridge_name: "br100".into(), subnet: "10.0.1.0/24".into(),
            self_ip: "10.0.1.5".into(),
            routes: vec![RouteEntry {
                destination: "10.0.0.0/16".into(),
                via: "10.0.99.1".into(), // not in 10.0.1.0/24
            }],
            allocations: vec![], external_reservations: vec![], notes: String::new(),
        };
        let err = validate_vlan_attachment(&v).unwrap_err();
        assert!(err.contains("route gateway"), "expected route-gateway error, got: {}", err);
    }

    #[test]
    fn validate_rejects_overlong_bridge_name() {
        let v = VlanAttachment {
            id: String::new(), name: "x".into(), provider: VlanProvider::Custom,
            parent_iface: "eno1".into(), vlan_id: 100, mtu: 1500,
            bridge_name: "this_name_is_far_too_long".into(),
            subnet: "10.0.1.0/24".into(), self_ip: "10.0.1.5".into(),
            routes: vec![], allocations: vec![], external_reservations: vec![], notes: String::new(),
        };
        assert!(validate_vlan_attachment(&v).is_err());
    }

    #[test]
    fn store_upsert_rejects_duplicate_vlan_on_same_parent() {
        let mut s = VlanStore::default();
        let mk = |vlan: u32| VlanAttachment {
            id: String::new(), name: format!("v{}", vlan), provider: VlanProvider::Hetzner,
            parent_iface: "eno1".into(), vlan_id: vlan, mtu: 1400,
            bridge_name: format!("vmbr{}", vlan), subnet: "10.0.1.0/24".into(),
            self_ip: "10.0.1.5".into(), routes: vec![],
            allocations: vec![], external_reservations: vec![], notes: String::new(),
        };
        assert!(s.upsert_vlan(mk(4000)).is_ok());
        // Same VLAN on same parent to reject.
        assert!(s.upsert_vlan(mk(4000)).is_err());
        // Same VLAN on different parent to ok (different physical port).
        let mut other = mk(4000);
        other.parent_iface = "eno2".into();
        other.bridge_name = "vmbr4000b".into();
        assert!(s.upsert_vlan(other).is_ok());
    }

    #[test]
    fn store_upsert_rejects_duplicate_public_ip() {
        let mut s = VlanStore::default();
        let mk = |ip: &str| PublicIpAttachment {
            id: String::new(), name: ip.into(), provider: VlanProvider::Hetzner,
            ip: ip.into(), container_internal_ip: "10.0.3.100".into(),
            egress_iface: "eno1".into(),
        };
        assert!(s.upsert_public_ip(mk("159.69.169.116")).is_ok());
        assert!(s.upsert_public_ip(mk("159.69.169.116")).is_err());
        assert!(s.upsert_public_ip(mk("159.69.169.117")).is_ok());
    }

    #[test]
    fn render_ifupdown_emits_expected_block() {
        let mut s = VlanStore::default();
        s.vlans.push(VlanAttachment {
            id: "vlan-test".into(), name: "prod".into(), provider: VlanProvider::Hetzner,
            parent_iface: "eno1".into(), vlan_id: 4000, mtu: 1400,
            bridge_name: "vmbr4000".into(), subnet: "10.0.1.0/24".into(),
            self_ip: "10.0.1.5".into(),
            routes: vec![RouteEntry { destination: "10.0.0.0/16".into(), via: "10.0.1.1".into() }], allocations: vec![], external_reservations: vec![],
            notes: "for production use".into(),
        });
        let out = render_ifupdown(&s);
        // Critical bits: VLAN sub-interface, MTU 1400, bridge with the VLAN as port,
        // address with the right netmask, route with up/down hooks.
        assert!(out.contains("auto eno1.4000"));
        assert!(out.contains("vlan-raw-device eno1"));
        assert!(out.contains("mtu 1400"));
        assert!(out.contains("auto vmbr4000"));
        assert!(out.contains("address 10.0.1.5"));
        assert!(out.contains("netmask 255.255.255.0"));
        assert!(out.contains("bridge-ports eno1.4000"));
        assert!(out.contains("up ip route add 10.0.0.0/16 via 10.0.1.1 dev vmbr4000"));
        assert!(out.contains("down ip route del 10.0.0.0/16 via 10.0.1.1 dev vmbr4000"));
        assert!(out.contains("# note: for production use"));
    }

    fn mk_attach(self_ip: &str) -> VlanAttachment {
        VlanAttachment {
            id: "v1".into(), name: "test".into(), provider: VlanProvider::Hetzner,
            parent_iface: "eno1".into(), vlan_id: 4000, mtu: 1400,
            bridge_name: "vmbr4000".into(), subnet: "10.0.1.0/24".into(),
            self_ip: self_ip.into(), routes: vec![],
            allocations: vec![], external_reservations: vec![], notes: String::new(),
        }
    }

    #[test]
    fn next_available_ip_skips_network_broadcast_self_and_gateway() {
        // Self is .5, conventional gateway .1 should be skipped, .0 and .255
        // are network/broadcast. First usable should be .2.
        let v = mk_attach("10.0.1.5");
        let ip = next_available_ip(&v, &[]).expect("should find an IP");
        assert_eq!(ip, "10.0.1.2");
    }

    #[test]
    fn next_available_ip_treats_self_as_gateway_when_self_is_dot_one() {
        // If operator deliberately put themselves on .1, that means
        // this server IS the gateway and the conventional-gw skip
        // shouldn't double-block.
        let v = mk_attach("10.0.1.1");
        let ip = next_available_ip(&v, &[]).expect("should find an IP");
        assert_eq!(ip, "10.0.1.2");  // .0 net, .1 self, next is .2
    }

    #[test]
    fn next_available_ip_skips_local_allocations() {
        let mut v = mk_attach("10.0.1.5");
        v.allocations = vec![
            IpAllocation { ip: "10.0.1.2".into(), target_kind: TargetKind::LxcNative,
                target_id: "a".into(), label: String::new(), created_at: String::new() },
            IpAllocation { ip: "10.0.1.3".into(), target_kind: TargetKind::Docker,
                target_id: "b".into(), label: String::new(), created_at: String::new() },
        ];
        let ip = next_available_ip(&v, &[]).unwrap();
        assert_eq!(ip, "10.0.1.4");
    }

    #[test]
    fn next_available_ip_skips_external_reservations_single_and_range() {
        let mut v = mk_attach("10.0.1.50");
        v.external_reservations = vec![
            ExternalReservation { spec: "10.0.1.2".into(), note: "manual host".into() },
            ExternalReservation { spec: "10.0.1.3-10.0.1.10".into(), note: "external cluster".into() },
        ];
        let ip = next_available_ip(&v, &[]).unwrap();
        assert_eq!(ip, "10.0.1.11");
    }

    #[test]
    fn next_available_ip_unions_cluster_used() {
        // Local has nothing, external has nothing, but a peer is using
        // .2 .3 .4 — picker should jump to .5 (since self is .50, and
        // .1 is conventional gw skipped).
        let v = mk_attach("10.0.1.50");
        let cluster = vec!["10.0.1.2".to_string(), "10.0.1.3".into(), "10.0.1.4".into()];
        let ip = next_available_ip(&v, &cluster).unwrap();
        assert_eq!(ip, "10.0.1.5");
    }

    #[test]
    fn next_available_ip_returns_none_when_subnet_full() {
        // /30 = 4 addresses: .0 net, .1 conv-gw, .2 usable, .3 broadcast.
        // Self is .2, which makes .2 also taken. So 0 free.
        let mut v = mk_attach("10.0.0.2");
        v.subnet = "10.0.0.0/30".into();
        assert!(next_available_ip(&v, &[]).is_none());
    }

    #[test]
    fn next_available_ip_handles_31_and_32_subnets() {
        // /31 and /32 have <2 host bits — refuse rather than guess.
        let mut v = mk_attach("10.0.0.2");
        v.subnet = "10.0.0.0/31".into();
        assert!(next_available_ip(&v, &[]).is_none());
        v.subnet = "10.0.0.2/32".into();
        v.self_ip = "10.0.0.2".into();
        assert!(next_available_ip(&v, &[]).is_none());
    }

    #[test]
    fn expand_reservation_handles_single_ip() {
        let ips = expand_reservation("10.0.1.5").unwrap();
        assert_eq!(ips, vec!["10.0.1.5".parse::<std::net::Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn expand_reservation_handles_inclusive_range() {
        let ips = expand_reservation("10.0.1.5-10.0.1.7").unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "10.0.1.5".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(ips[2], "10.0.1.7".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[test]
    fn expand_reservation_rejects_reversed_range() {
        let err = expand_reservation("10.0.1.10-10.0.1.5").unwrap_err();
        assert!(err.contains("reversed"), "expected reversed-range error, got: {}", err);
    }

    #[test]
    fn expand_reservation_rejects_oversized_range() {
        // More than /16 worth of addresses - refuse to materialise.
        let err = expand_reservation("10.0.0.0-10.2.0.0").unwrap_err();
        assert!(err.contains("/16"), "expected /16 cap error, got: {}", err);
    }

    #[test]
    fn expand_reservation_rejects_garbage() {
        assert!(expand_reservation("not an ip").is_err());
        assert!(expand_reservation("10.0.0.1-").is_err());
        assert!(expand_reservation("-10.0.0.1").is_err());
    }

    #[test]
    fn render_ifupdown_includes_public_ip_lo_alias() {
        let mut s = VlanStore::default();
        s.public_ips.push(PublicIpAttachment {
            id: "pip-test".into(), name: "regions80".into(), provider: VlanProvider::Hetzner,
            ip: "159.69.169.116".into(), container_internal_ip: "10.0.3.100".into(),
            egress_iface: "eno1".into(),
        });
        let out = render_ifupdown(&s);
        assert!(out.contains("address 159.69.169.116"));
        assert!(out.contains("netmask 255.255.255.255"));
        assert!(out.contains("net.ipv4.conf.eno1.proxy_arp=1"));
        assert!(out.contains("net.ipv4.ip_forward=1"));
        // rp_filter loose mode — without these, asymmetric DNAT/SNAT
        // return paths get silently dropped on systems with strict mode.
        assert!(out.contains("net.ipv4.conf.all.rp_filter=2"));
        assert!(out.contains("net.ipv4.conf.lo.rp_filter=2"));
        assert!(out.contains("net.ipv4.conf.eno1.rp_filter=2"));
    }

    fn sample_hetzner_vlan() -> VlanAttachment {
        VlanAttachment {
            id: "vlan-test".into(), name: "prod".into(), provider: VlanProvider::Hetzner,
            parent_iface: "eno1".into(), vlan_id: 4000, mtu: 1400,
            bridge_name: "vmbr4000".into(), subnet: "10.0.1.0/24".into(),
            self_ip: "10.0.1.5".into(),
            routes: vec![RouteEntry { destination: "10.0.0.0/16".into(), via: "10.0.1.1".into() }],
            allocations: vec![], external_reservations: vec![],
            notes: String::new(),
        }
    }

    #[test]
    fn render_netplan_emits_vlan_and_bridge() {
        let mut s = VlanStore::default();
        s.vlans.push(sample_hetzner_vlan());
        let out = render_netplan(&s);
        assert!(out.contains("network:"));
        assert!(out.contains("version: 2"));
        // VLAN block
        assert!(out.contains("eno1.4000:"));
        assert!(out.contains("id: 4000"));
        assert!(out.contains("link: eno1"));
        assert!(out.contains("mtu: 1400"));
        // Bridge block
        assert!(out.contains("vmbr4000:"));
        assert!(out.contains("interfaces: [eno1.4000]"));
        assert!(out.contains("addresses: [\"10.0.1.5/24\"]"));
        assert!(out.contains("stp: false"));
        // forward-delay 0 — same kernel-default-15s footgun every other
        // renderer hits. Without it, attached guests wait 15s for traffic.
        assert!(out.contains("forward-delay: 0"));
        // dhcp/v6 hygiene
        assert!(out.contains("dhcp4: false"));
        assert!(out.contains("dhcp6: false"));
        assert!(out.contains("link-local: []"));
        assert!(out.contains("accept-ra: false"));
        // Routes
        assert!(out.contains("to: 10.0.0.0/16"));
        assert!(out.contains("via: 10.0.1.1"));
    }

    #[test]
    fn render_netplan_handles_empty_store() {
        let s = VlanStore::default();
        let out = render_netplan(&s);
        // Must be valid YAML — netplan rejects naked `vlans:` with no
        // content, so we emit `ethernets: {}` as a placeholder.
        assert!(out.contains("ethernets: {}"));
    }

    #[test]
    fn render_nm_script_creates_bridge_and_slave_vlan() {
        let mut s = VlanStore::default();
        s.vlans.push(sample_hetzner_vlan());
        let out = render_nm_script(&s);
        // Bridge connection
        assert!(out.contains("nmcli connection add type bridge con-name 'wolfstack-br-vmbr4000'"));
        assert!(out.contains("ipv4.addresses '10.0.1.5/24'"));
        assert!(out.contains("802-3-ethernet.mtu 1400"));
        // bridge.forward-delay 0 — without this, NM inherits the kernel
        // default 15s and guests wait that long before traffic flows.
        assert!(out.contains("bridge.forward-delay 0"));
        // Slave VLAN connection
        assert!(out.contains("type vlan con-name 'wolfstack-vlan-eno1-4000'"));
        assert!(out.contains("master 'vmbr4000' slave-type bridge"));
        // Route via +ipv4.routes
        assert!(out.contains("+ipv4.routes '10.0.0.0/16 10.0.1.1'"));
        // Cleanup loop at the top so re-runs converge
        assert!(out.contains("grep '^wolfstack-'"));
        assert!(out.contains("nmcli connection delete"));
    }

    #[test]
    fn render_systemd_networkd_emits_all_required_files() {
        let mut s = VlanStore::default();
        s.vlans.push(sample_hetzner_vlan());
        let files = render_systemd_networkd_files(&s);
        let names: Vec<&String> = files.iter().map(|(n, _)| n).collect();
        // The drop-in for the parent NIC's .network so the VLAN device gets created.
        assert!(names.iter().any(|n| n.contains("eno1.network.d/wolfstack-vlan.conf")),
            "missing parent drop-in; got {:?}", names);
        // The VLAN .netdev + .network
        assert!(names.iter().any(|n| n.ends_with("vlan-eno1.4000.netdev")));
        assert!(names.iter().any(|n| n.ends_with("vlan-eno1.4000.network")));
        // The bridge .netdev + .network
        assert!(names.iter().any(|n| n.ends_with("bridge-vmbr4000.netdev")));
        assert!(names.iter().any(|n| n.ends_with("bridge-vmbr4000.network")));

        // Spot-check content shape
        let by_name = |suffix: &str| files.iter().find(|(n, _)| n.ends_with(suffix)).map(|(_, c)| c.as_str());
        let netdev = by_name("vlan-eno1.4000.netdev").unwrap();
        assert!(netdev.contains("Kind=vlan"));
        assert!(netdev.contains("Id=4000"));
        assert!(netdev.contains("MTUBytes=1400"));

        let bridge_net = by_name("bridge-vmbr4000.network").unwrap();
        assert!(bridge_net.contains("Address=10.0.1.5/24"));
        assert!(bridge_net.contains("IPv6AcceptRA=no"));
        assert!(bridge_net.contains("LinkLocalAddressing=no"));
        assert!(bridge_net.contains("ConfigureWithoutCarrier=yes"));
        assert!(bridge_net.contains("Destination=10.0.0.0/16"));
        assert!(bridge_net.contains("Gateway=10.0.1.1"));

        // Bridge .netdev must contain STP=no and ForwardDelaySec=0 —
        // [Bridge] section in the .netdev configures the bridge device
        // itself. Without ForwardDelaySec=0, kernel defaults to 15s
        // and every attached guest waits 15s before traffic flows.
        let bridge_dev = by_name("bridge-vmbr4000.netdev").unwrap();
        assert!(bridge_dev.contains("Kind=bridge"));
        assert!(bridge_dev.contains("STP=no"));
        assert!(bridge_dev.contains("ForwardDelaySec=0"));

        let dropin = by_name("eno1.network.d/wolfstack-vlan.conf").unwrap();
        assert!(dropin.contains("VLAN=eno1.4000"));
    }

    #[test]
    fn auto_persist_supported_covers_four_managers() {
        assert!(NetManager::Ifupdown.auto_persist_supported());
        assert!(NetManager::Netplan.auto_persist_supported());
        assert!(NetManager::NetworkManager.auto_persist_supported());
        assert!(NetManager::SystemdNetworkd.auto_persist_supported());
        assert!(!NetManager::Wicked.auto_persist_supported());
        assert!(!NetManager::Unknown.auto_persist_supported());
    }

    #[test]
    fn preflight_emits_manager_info() {
        let s = VlanStore::default();
        let findings = preflight(&s, NetManager::Ifupdown, None);
        assert!(findings.iter().any(|f|
            matches!(f.severity, PreflightSeverity::Info)
            && f.title.contains("Network manager")
        ));
    }

    #[test]
    fn preflight_warns_about_disruptive_managers() {
        let s = VlanStore::default();
        for mgr in [NetManager::Netplan, NetManager::NetworkManager, NetManager::SystemdNetworkd] {
            let findings = preflight(&s, mgr, None);
            assert!(
                findings.iter().any(|f| matches!(f.severity, PreflightSeverity::Warn)),
                "expected at least one Warn finding for {:?}", mgr,
            );
        }
    }

    #[test]
    fn parse_ifupdown_handles_real_proxmox_vlan_aware_bridge_config() {
        // Real config from a user's working Proxmox-on-Hetzner box.
        // Topology: vlan-aware bridge vmbr0 with eno1 as port, vlan4000
        // sub-interface using vmbr0 as raw device for IP termination.
        let cfg = r#"
auto lo
iface lo inet loopback

iface lo inet6 loopback

iface eno1 inet manual

auto vmbr0
iface vmbr0 inet static
        address 162.55.15.215/28
        gateway 162.55.15.209
        bridge-ports eno1
        bridge-stp off
        bridge-fd 1
        bridge-vlan-aware yes
        bridge-vids 2-4094

auto vlan4000
iface vlan4000 inet static
        address 10.0.1.5/24
        mtu 1400
        vlan-raw-device vmbr0
        up ip route add 10.0.0.0/16 via 10.0.1.1 dev vlan4000
        down ip route del 10.0.0.0/16 via 10.0.1.1 dev vlan4000
"#;
        let parsed = parse_ifupdown_text(cfg);
        assert_eq!(parsed.len(), 1, "expected exactly one VLAN block, got {:?}", parsed);
        let v = &parsed[0];
        assert_eq!(v.vlan_id, 4000);
        assert_eq!(v.raw_device, "vmbr0");
        assert_eq!(v.mtu, Some(1400));
        assert_eq!(v.self_ip.as_deref(), Some("10.0.1.5"));
        assert_eq!(v.subnet.as_deref(), Some("10.0.1.0/24"));
        assert_eq!(v.routes.len(), 1);
        assert_eq!(v.routes[0].destination, "10.0.0.0/16");
        assert_eq!(v.routes[0].via, "10.0.1.1");
        // Topology detected as vlan-aware-bridge because raw_device starts with vmbr.
        assert_eq!(v.source_topology, SourceTopology::VlanAwareBridge);
        assert!(v.recommendation.contains("vlan-aware bridge"));
        assert!(v.recommendation.contains("DIFFERENT self IP"));
    }

    #[test]
    fn parse_ifupdown_handles_wolfstack_shape() {
        // The other valid topology — vlan-raw-device pointed at a
        // physical NIC (what WolfStack itself generates).
        let cfg = r#"
auto eno1.4000
iface eno1.4000 inet manual
        vlan-raw-device eno1
        mtu 1400

auto vmbr4000
iface vmbr4000 inet static
        address 10.0.1.5
        netmask 255.255.255.0
        bridge-ports eno1.4000
        bridge-stp off
        bridge-fd 0
        mtu 1400
"#;
        let parsed = parse_ifupdown_text(cfg);
        // The eno1.4000 block has vlan-raw-device → it's a VLAN.
        let v = parsed.iter().find(|p| p.vlan_id == 4000).expect("must find VID 4000");
        assert_eq!(v.raw_device, "eno1");
        assert_eq!(v.source_topology, SourceTopology::PhysicalParent);
        assert_eq!(v.mtu, Some(1400));
    }

    #[test]
    fn parse_ifupdown_ignores_non_vlan_blocks() {
        // The user's actual full /etc/network/interfaces — lo, eno1,
        // vmbr0 (the management bridge), then vlan4000. We must extract
        // ONLY vlan4000 and silently drop everything else.
        let cfg = r#"
auto lo
iface lo inet loopback

iface lo inet6 loopback

iface eno1 inet manual

auto vmbr0
iface vmbr0 inet static
        address 162.55.15.215/28
        gateway 162.55.15.209
        bridge-ports eno1
        bridge-stp off
        bridge-fd 1
        bridge-vlan-aware yes
        bridge-vids 2-4094
        hwaddress 08:bf:b8:a6:98:8a
        pointopoint 162.55.15.209
        up sysctl -p
        up route add -net 162.55.15.20 netmask 255.255.255.240 gw 162.55.15.209 dev eno1
#For VLAN

auto vlan4000
iface vlan4000 inet static
        address 10.0.1.5/24
        mtu 1400
        vlan-raw-device vmbr0
        up ip route add 10.0.0.0/16 via 10.0.1.1 dev vlan4000
        down ip route del 10.0.0.0/16 via 10.0.1.1 dev vlan4000
#USE ONLY THIS FOR VM
source /etc/network/interfaces.d/*
"#;
        let parsed = parse_ifupdown_text(cfg);
        // Exactly ONE candidate — vlan4000. lo, eno1, vmbr0 must be skipped.
        assert_eq!(parsed.len(), 1, "expected 1 VLAN, got {}: {:?}",
            parsed.len(),
            parsed.iter().map(|p| (p.vlan_id, p.raw_device.clone())).collect::<Vec<_>>(),
        );
        assert_eq!(parsed[0].vlan_id, 4000);
        assert_eq!(parsed[0].raw_device, "vmbr0");
    }

    #[test]
    fn parse_ifupdown_skips_ipv6_blocks() {
        // An inet6 VLAN block would otherwise produce a v6 address that
        // can't be represented in WolfStack's v4-only store.
        let cfg = r#"
iface vlan100 inet6 static
        address fe80::5/64
        vlan-raw-device eno1

iface vlan200 inet static
        address 10.0.2.5/24
        vlan-raw-device eno1
"#;
        let parsed = parse_ifupdown_text(cfg);
        // Only the v4 vlan200 should appear.
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].vlan_id, 200);
    }

    #[test]
    fn parse_ifupdown_dedupes_repeated_blocks() {
        // Two `iface vlan100` blocks (operator pasted half a config
        // twice, or two near-identical defs). Output should collapse.
        let cfg = r#"
iface vlan100 inet static
        address 10.0.1.5/24
        vlan-raw-device eno1

iface vlan100 inet static
        address 10.0.1.5/24
        vlan-raw-device eno1
"#;
        let parsed = parse_ifupdown_text(cfg);
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn parse_ifupdown_handles_crlf_and_extra_whitespace() {
        // Windows clipboard / SSH-paste through PuTTY can introduce CRLF.
        // Extra trailing whitespace and tabs vs spaces shouldn't matter.
        let cfg = "iface vlan300 inet static\r\n\taddress 10.0.3.5/24\r\n   \tvlan-raw-device eno1\t\r\n\tmtu 1500\r\n";
        let parsed = parse_ifupdown_text(cfg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].vlan_id, 300);
        assert_eq!(parsed[0].raw_device, "eno1");
        assert_eq!(parsed[0].mtu, Some(1500));
    }

    #[test]
    fn parse_ifupdown_accepts_post_up_routes() {
        // Routes are sometimes in `post-up` instead of `up`. Both must work.
        let cfg = r#"
iface vlan400 inet static
        address 10.0.4.5/24
        vlan-raw-device eno1
        post-up ip route add 10.0.0.0/16 via 10.0.4.1 dev vlan400
        pre-up ip route add 192.168.0.0/16 via 10.0.4.2
"#;
        let parsed = parse_ifupdown_text(cfg);
        assert_eq!(parsed.len(), 1);
        let routes = &parsed[0].routes;
        assert_eq!(routes.len(), 2, "expected 2 routes, got {:?}", routes);
        assert!(routes.iter().any(|r| r.destination == "10.0.0.0/16" && r.via == "10.0.4.1"));
        assert!(routes.iter().any(|r| r.destination == "192.168.0.0/16" && r.via == "10.0.4.2"));
    }

    #[test]
    fn parse_ifupdown_rejects_out_of_range_vids() {
        // `eth0.0` and `vlan99999` are syntactically valid iface names
        // but invalid as 802.1Q VIDs. Reject silently.
        let cfg = r#"
iface eth0.0 inet static
        address 10.0.0.1/24
        vlan-raw-device eth0

iface vlan9999 inet static
        address 10.0.1.1/24
        vlan-raw-device eth0
"#;
        let parsed = parse_ifupdown_text(cfg);
        assert!(parsed.is_empty(), "expected no candidates, got {:?}", parsed);
    }

    #[test]
    fn parse_ifupdown_ignores_garbage_around_vlan_block() {
        // Operator pasted a VLAN block with random unrelated text
        // before and after. Parser must find the VLAN regardless.
        let cfg = r#"
# random notes from my email
HOST: giant.example.com
LAST_BACKUP: 2026-05-14
IPV4: 162.55.15.215

# the actual config bit:
iface vlan500 inet static
        address 10.0.5.5/24
        vlan-raw-device eno1
        mtu 1400

# a snippet from /etc/wireguard/wg0.conf:
[Interface]
Address = 10.7.0.1/24
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=

[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
AllowedIPs = 10.7.0.2/32
"#;
        let parsed = parse_ifupdown_text(cfg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].vlan_id, 500);
        assert_eq!(parsed[0].raw_device, "eno1");
        assert_eq!(parsed[0].mtu, Some(1400));
    }

    #[test]
    fn parse_ifupdown_strips_comments_and_handles_old_netmask() {
        // Old-style with netmask + comments.
        let cfg = r#"
# operator notes here
iface vlan100 inet static  # production VLAN
        address 192.168.50.10
        netmask 255.255.255.0
        vlan-raw-device eth0
        mtu 1500
"#;
        let parsed = parse_ifupdown_text(cfg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].vlan_id, 100);
        assert_eq!(parsed[0].self_ip.as_deref(), Some("192.168.50.10"));
        assert_eq!(parsed[0].subnet.as_deref(), Some("192.168.50.0/24"));
    }

    #[test]
    fn discovered_kind_serializes_as_snake_case() {
        // The frontend keys off the JSON value strings, so a rename
        // here would silently break the UI matching. Pin the format.
        let imp = serde_json::to_string(&DiscoveredKind::Importable).unwrap();
        let vab = serde_json::to_string(&DiscoveredKind::VlanAwareBridge).unwrap();
        let sub = serde_json::to_string(&DiscoveredKind::SubInterfaceOnly).unwrap();
        assert_eq!(imp, "\"importable\"");
        assert_eq!(vab, "\"vlan_aware_bridge\"");
        assert_eq!(sub, "\"sub_interface_only\"");
    }

    #[test]
    fn preflight_flags_duplicate_vlan_on_same_parent() {
        let mut s = VlanStore::default();
        s.vlans.push(sample_hetzner_vlan());
        // Propose another vlan with same (parent, vlan_id) but different id
        // to simulate the operator about to add a duplicate.
        let mut dup = sample_hetzner_vlan();
        dup.id = "vlan-dup".into();
        dup.bridge_name = "vmbr-dup".into();
        let findings = preflight(&s, NetManager::Ifupdown, Some(&dup));
        assert!(
            findings.iter().any(|f|
                matches!(f.severity, PreflightSeverity::Critical)
                && f.title.contains("configured twice")
            ),
            "expected critical 'configured twice' finding, got {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>(),
        );
    }
}
