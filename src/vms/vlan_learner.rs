// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Passive VLAN-VID learner for passthrough NICs with a stuck-on hardware
//! VLAN filter.
//!
//! ## The problem
//!
//! Some NIC drivers (seen on Realtek r8169 and some Intel chips) report
//! `rx-vlan-filter: on [fixed]` in `ethtool -k`. The `[fixed]` means the
//! driver refuses to let us change it via `ethtool -K`. The NIC will drop
//! any incoming VLAN-tagged frame whose VID isn't registered in its
//! hardware filter table. The table gets populated by the kernel's
//! `vlan_vid_add()` call, which fires when an 802.1Q subinterface (e.g.
//! `enp2s0.100`) is created on the interface.
//!
//! For an OPNsense VM doing VLAN trunking through a passthrough NIC, the
//! symptom is: a few DHCP handshakes succeed (VIDs happened to already be
//! registered from some earlier operation), then nothing — every subsequent
//! tagged frame gets silently dropped at hardware.
//!
//! ## The fix
//!
//! Watch the passthrough NIC's traffic. Outbound frames from the guest
//! don't hit the filter (filter is RX-side only), so we always see the
//! VID the guest is using. First time we see a VID, create a DOWN 802.1Q
//! subinterface for it — that registers the VID in the hardware filter
//! table via the kernel's normal path. The subinterface stays DOWN so it
//! doesn't interfere with traffic routing; its only purpose is the
//! registration side-effect.
//!
//! Learned VIDs persist to `/etc/wolfstack/vlan-learner/<iface>.json` so
//! they survive reboots. On daemon restart we re-register everything from
//! the state file before starting to listen, so the first packet on a
//! known VID goes through without the drop-then-retry.
//!
//! ## Safety
//!
//! - No-op for NICs without `rx-vlan-filter: on [fixed]` — existing
//!   `ethtool -K rxvlan off` path already handles those.
//! - Subinterfaces are created DOWN — never carry traffic, never
//!   deliver VID-matched frames up the stack alongside the bridge.
//! - Only inspects Ethernet frames with 802.1Q (0x8100) or QinQ
//!   (0x88a8) ethertype; everything else is ignored.
//! - Learner runs in a single thread per NIC, deduplicated by iface name.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use tracing::{debug, info, warn};

const STATE_DIR: &str = "/etc/wolfstack/vlan-learner";

fn state_file(iface: &str) -> PathBuf {
    PathBuf::from(format!("{}/{}.json", STATE_DIR, iface))
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct LearnerState {
    vids: Vec<u16>,
}

/// Returns true if the NIC has `rx-vlan-filter: on [fixed]` — meaning
/// `ethtool -K … rx-vlan-filter off` will fail silently and we need to
/// register VIDs manually.
pub fn rx_vlan_filter_fixed_on(iface: &str) -> bool {
    let out = match Command::new("ethtool").args(["-k", iface]).output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("rx-vlan-filter:") {
            // Format: "rx-vlan-filter: on [fixed]" or "off" etc.
            return rest.contains(" on") && rest.contains("[fixed]");
        }
    }
    false
}

fn load_state(iface: &str) -> HashSet<u16> {
    match fs::read_to_string(state_file(iface)) {
        Ok(s) => serde_json::from_str::<LearnerState>(&s)
            .map(|st| st.vids.into_iter().collect())
            .unwrap_or_default(),
        Err(_) => HashSet::new(),
    }
}

fn save_state(iface: &str, vids: &HashSet<u16>) {
    let _ = fs::create_dir_all(STATE_DIR);
    let mut sorted: Vec<u16> = vids.iter().copied().collect();
    sorted.sort_unstable();
    let state = LearnerState { vids: sorted };
    if let Ok(s) = serde_json::to_string_pretty(&state) {
        let _ = fs::write(state_file(iface), s);
    }
}

/// Build the subinterface name within the 15-char IFNAMSIZ limit. The
/// canonical `<iface>.<vid>` is preferred (debuggable), with a truncating
/// fallback only for interfaces with unusually long names.
fn subif_name(iface: &str, vid: u16) -> String {
    let vid_str = format!(".{}", vid);
    let max_iface = 15usize.saturating_sub(vid_str.len());
    let head = if iface.len() <= max_iface { iface } else { &iface[..max_iface] };
    format!("{}{}", head, vid_str)
}

/// Register a VLAN id on the physical NIC by creating a DOWN 802.1Q
/// subinterface. Idempotent: if the subinterface already exists, the
/// "File exists" error is swallowed.
fn register_vid(iface: &str, vid: u16) {
    let name = subif_name(iface, vid);
    let out = Command::new("ip")
        .args(["link", "add", "link", iface, "name", &name, "type", "vlan", "id", &vid.to_string()])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            // Keep it DOWN — registration-only. set-down is the default for
            // newly-created VLAN subinterfaces but being explicit is cheap.
            let _ = Command::new("ip").args(["link", "set", &name, "down"]).output();
            debug!("vlan_learner: registered VID {} on {} as {}", vid, iface, name);
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.contains("File exists") {
                debug!("vlan_learner: register VID {} on {} failed: {}", vid, iface, stderr.trim());
            }
        }
        Err(e) => debug!("vlan_learner: ip link add failed for {}.{}: {}", iface, vid, e),
    }
}

// Interfaces with a learner thread already running. Guarded by a mutex so
// multiple call sites (bridge setup, periodic re-apply) can each try to
// start without duplicating.
static ACTIVE_LEARNERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Start a learner for this NIC if one isn't already running. Idempotent.
/// Safe to call repeatedly from different code paths.
pub fn start_if_needed(iface: &str) {
    if !rx_vlan_filter_fixed_on(iface) { return; }
    {
        let mut active = ACTIVE_LEARNERS.lock().unwrap();
        if active.iter().any(|a| a == iface) { return; }
        active.push(iface.to_string());
    }
    let iface_owned = iface.to_string();
    thread::spawn(move || run_learner(iface_owned));
}

fn run_learner(iface: String) {
    info!("vlan_learner: starting on {} (rx-vlan-filter is fixed-on, registering VIDs as guest uses them)", iface);

    // Restore previously-learned VIDs immediately so packets on known VIDs
    // pass the filter on the first try after a daemon restart.
    let mut known = load_state(&iface);
    for vid in &known {
        register_vid(&iface, *vid);
    }
    if !known.is_empty() {
        info!("vlan_learner: re-registered {} previously-learned VID(s) on {}", known.len(), iface);
    }

    let sock = match open_packet_socket(&iface) {
        Ok(fd) => fd,
        Err(e) => {
            warn!("vlan_learner: AF_PACKET open failed on {}: {} — learner disabled (VLAN DHCP may not work)", iface, e);
            // Drop out of ACTIVE_LEARNERS so a future retry can try again.
            ACTIVE_LEARNERS.lock().unwrap().retain(|a| a != &iface);
            return;
        }
    };

    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe {
            libc::recv(sock.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0)
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted { continue; }
            warn!("vlan_learner: recv on {} failed: {} — exiting learner", iface, err);
            break;
        }
        let n = n as usize;
        // Ethernet header (14) + 802.1Q TCI (2) = 16 min for a tagged frame.
        if n < 16 { continue; }

        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype != 0x8100 && ethertype != 0x88a8 { continue; }

        let tci = u16::from_be_bytes([buf[14], buf[15]]);
        let vid = tci & 0x0FFF;
        // 0 = priority-tagged (no VLAN), 4095 = reserved.
        if vid == 0 || vid == 0xFFF { continue; }

        if known.insert(vid) {
            info!("vlan_learner: learned VID {} on {} — registering with NIC filter", vid, iface);
            register_vid(&iface, vid);
            save_state(&iface, &known);
        }
    }

    ACTIVE_LEARNERS.lock().unwrap().retain(|a| a != &iface);
}

fn open_packet_socket(iface: &str) -> io::Result<OwnedFd> {
    // ETH_P_ALL in network byte order: the kernel wants the third arg to
    // socket() as a big-endian ethertype even on little-endian hosts.
    let eth_p_all_be = (libc::ETH_P_ALL as u16).to_be() as i32;
    let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all_be) };
    if raw < 0 { return Err(io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let ifindex = get_ifindex(iface)?;
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 { return Err(io::Error::last_os_error()); }

    Ok(fd)
}

fn get_ifindex(iface: &str) -> io::Result<i32> {
    let c = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null in iface"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 { return Err(io::Error::last_os_error()); }
    Ok(idx as i32)
}
