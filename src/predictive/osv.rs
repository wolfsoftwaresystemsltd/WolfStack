// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! OSV.dev + CISA KEV vulnerability scanner.
//!
//! Sibling of [`vulnerability`](super::vulnerability) — that module
//! reads the distro's *security pocket* (apt `-security` / `dnf
//! updateinfo --security` / `arch-audit`), which lags initial CVE
//! disclosure by hours-to-days while the distro packages a fix.
//!
//! This module closes the gap by querying the **OSV.dev** unified
//! vulnerability database directly, then cross-referencing matches
//! against the **CISA Known Exploited Vulnerabilities** catalog so
//! actively-exploited CVEs (e.g. CVE-2026-31431 "Copy Fail") get
//! Critical severity regardless of CVSS.
//!
//! Both analyzers run; their findings dedup naturally because they
//! emit different `finding_type` strings. The `vulnerability`
//! analyzer remains authoritative for "fix is in your repo, run the
//! upgrade" — this analyzer adds "exploit is in the wild and a CVE
//! ID applies, even if the distro hasn't shipped the patch yet".
//!
//! ## Coverage — every Linux distro OSV indexes
//!
//! Ecosystem strings sourced from the OSV schema's defined-ecosystems
//! list (https://ossf.github.io/osv-schema/). These are NOT guesses;
//! mismatched strings would produce zero findings, not false
//! positives.
//!
//! **Directly indexed by OSV** (host + LXC, native dpkg/rpm/apk):
//! - Debian (and derivatives that pin to a Debian release: Devuan,
//!   Parrot, MX Linux, Pop!_OS-Debian, Raspberry Pi OS, Kali — for
//!   Kali we map to a rolling Debian:sid)
//! - Ubuntu (LTS + interim) — and Ubuntu-derivatives Linux Mint,
//!   Pop!_OS, Elementary, Zorin, Tuxedo OS, KDE Neon, all of which
//!   inherit Ubuntu's package set and are mapped via `UBUNTU_CODENAME`
//! - Alpine
//! - Rocky Linux, AlmaLinux
//! - openSUSE (Leap, Tumbleweed)
//! - Mageia
//! - openEuler
//! - Photon OS
//! - Alpaquita
//! - BellSoft Hardened Containers
//! - Wolfi, Chainguard, MinimOS, CleanStart (rolling, no version
//!   suffix in their ecosystem strings)
//!
//! **Not indexed by OSV** — fall back to the distro-pocket scanner
//! in [`vulnerability`](super::vulnerability):
//! - Fedora — covered by `dnf updateinfo --security`
//! - Red Hat Enterprise Linux — covered by `dnf updateinfo` (OSV uses
//!   a CPE-based ecosystem `Red Hat:rhel_aus:8.4::appstream` we'd
//!   need authoritative subscription metadata to construct correctly;
//!   producing a wrong CPE silently misses CVEs, so we leave it to
//!   the pocket scanner which is authoritative anyway)
//! - Amazon Linux, Oracle Linux, CentOS Stream — same reasoning
//! - Arch / CachyOS / Manjaro / EndeavourOS — covered by `arch-audit`
//! - SLES (commercial SUSE) — OSV's `SUSE:` ecosystem uses a
//!   marketing-name format we don't yet have a stable mapping for
//!
//! **Upstream kernel CVEs (`Linux` ecosystem)** are NOT version-
//! queryable — OSV indexes kernel.org records by git commit hash,
//! not by `uname -r`. For practical purposes a kernel CVE that
//! affects a distro will always appear in that distro's ecosystem
//! once the distro publishes its advisory; the running kernel goes
//! out via the same query path as any other package.
//!
//! | Target | Status | Notes |
//! |--------|--------|-------|
//! | Linux host (any OSV-indexed distro above) | **Implemented** | Inventory via dpkg/rpm/apk, OSV ecosystem mapped from `/etc/os-release` |
//! | LXC container (any OSV-indexed distro) | **Implemented** | Same probe shape over `lxc-attach`; mirrors [`vulnerability::sample_lxc_one`](super::vulnerability::sample_lxc_one) |
//! | Pacman host / Fedora / RHEL family / Amazon Linux | Skipped | Covered by [`vulnerability`](super::vulnerability) — pocket scanner is authoritative for those distros |
//! | Docker container | Not in scope | Image scanning belongs in a trivy/grype-backed analyzer |
//! | VM | Not in scope | Needs a guest agent |
//!
//! ## Cadence
//!
//! The orchestrator ticks every 5 min, but OSV is a free public API
//! and we owe it politeness. The internal rate limiter caps actual
//! HTTP traffic to **once per hour**; intermediate ticks reuse the
//! last cached scan, filtered against the current inventory so
//! upgrades take effect on the very next tick (not the next hour).
//! KEV is fetched **once per 24 h**.
//!
//! ## Severity tiers
//!
//! 1. KEV-listed (actively exploited) → `Critical`
//! 2. Critical-class package match (kernel / openssh / openssl /
//!    sudo / glibc / web server / container runtime; same set as
//!    [`vulnerability::CRITICAL_PACKAGES`]) → `Critical`
//! 3. CVSS v3/v4 base score ≥ 9.0 → `Critical`
//! 4. CVSS base score 7.0–8.9 → `High`
//! 5. CVSS base score 4.0–6.9 → `Warn`
//! 6. CVSS < 4.0 or no CVSS data → suppressed (Info noise)
//!
//! When `kev_only` is set in `osv-config.json`, only tier 1 fires —
//! useful for operators who want the highest-signal subset without
//! every CVSS-4 advisory hitting the inbox.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{
        Evidence, EvidenceLink, Proposal, ProposalScope, ProposalSource, RemediationPlan,
        Severity,
    },
    vulnerability::{is_critical_package, PackageManager},
};

/// Finding type for OSV-detected vulnerabilities. Distinct from the
/// distro-pocket finding so the inbox can show them separately and
/// operator dismiss/snooze on one doesn't suppress the other.
pub const FINDING_TYPE: &str = "osv_vulnerability_detected";

/// Info-tier breadcrumb when we encounter a Linux derivative whose
/// codename we can't map to an OSV ecosystem AND the host has no
/// `distro-info-data` package installed to disambiguate. The
/// remediation is either: install `distro-info-data`, OR add an
/// explicit `distro_overrides` entry to `/etc/wolfstack/osv-config.json`.
/// Auto-resolves on the next tick once the override takes effect.
pub const FINDING_UNRECOGNIZED_DERIVATIVE: &str = "osv_unrecognized_derivative";

/// Where the `distro-info-data` package (Debian / Ubuntu) drops its
/// CSV files. Reading these at runtime means new Ubuntu / Debian
/// release codenames flow into WolfStack the next time the operator
/// runs `apt upgrade distro-info-data` — we don't have to ship a new
/// WolfStack release every six months for derivative coverage.
const DISTRO_INFO_UBUNTU_CSV: &str = "/usr/share/distro-info/ubuntu.csv";
const DISTRO_INFO_DEBIAN_CSV: &str = "/usr/share/distro-info/debian.csv";

/// Public OSV batch query endpoint. Free, no API key required.
const OSV_DEFAULT_ENDPOINT: &str = "https://api.osv.dev";

/// CISA Known Exploited Vulnerabilities feed. Tiny (~2 MB) JSON,
/// updated daily.
const KEV_DEFAULT_ENDPOINT: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Location of the persistent OSV scan cache. Runtime data, not
/// config — lives under `/var/lib/wolfstack/` per the project's path
/// convention (see [`crate::paths`]). The file holds the most-recent
/// scan results plus the timestamps used for rate limiting; it
/// survives binary restarts so we don't refetch on every redeploy.
const OSV_CACHE_FILE: &str = "/var/lib/wolfstack/osv-cache.json";

/// Location of the persistent KEV catalog cache. Same rationale.
const KEV_CACHE_FILE: &str = "/var/lib/wolfstack/kev-cache.json";

/// Location of OSV configuration. Config (not runtime data) so it
/// matches the rest of WolfStack's `/etc/wolfstack/` convention.
const OSV_CONFIG_FILE: &str = "/etc/wolfstack/osv-config.json";

/// Minimum gap between OSV HTTP scans. The orchestrator runs every 5
/// minutes; without rate limiting we'd hit the public endpoint 12×
/// per hour per node.
const OSV_QUERY_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// Minimum gap between KEV refreshes. The catalog updates ~daily.
const KEV_REFRESH_COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard cap on how many `(ecosystem, package, version)` tuples we
/// send in one POST body. OSV's documented pagination threshold is
/// 1000 results per query AND 3000 results across the queryset; we
/// keep batches well under both with a 500-tuple cap so a noisy
/// container's full inventory still fits in two batches.
const OSV_MAX_BATCH: usize = 500;

/// Per-HTTP-call timeout — covers connect + body. Chosen so a slow
/// network can't hold the orchestrator's vulnerability budget.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Hard timeout for the inventory-collection subprocess (dpkg-query
/// / rpm -qa / apk info). A wedged dpkg DB shouldn't block the tick
/// indefinitely.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(15);

/// Hard timeout for an LXC `lxc-attach` to read the container's
/// inventory. Short because we try apt first and `lxc-attach --
/// dpkg-query` fails fast on non-Debian images.
const LXC_INVENTORY_TIMEOUT: Duration = Duration::from_secs(12);

/// Total wall-clock budget for the LXC inventory fan-out. Keeps a
/// host with 50 minimal containers from blowing past the
/// orchestrator's outer vulnerability budget.
const LXC_TOTAL_BUDGET: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

/// User-tunable knobs. Persisted at [`OSV_CONFIG_FILE`]. All fields
/// have safe defaults so a missing file is fine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvConfig {
    /// Whether the OSV analyzer is on. Off → no inventory collection,
    /// no HTTP, no findings. The distro-pocket analyzer still runs.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Override the OSV endpoint (e.g. for self-hosted mirrors).
    #[serde(default = "default_osv_endpoint")]
    pub endpoint: String,
    /// Override the KEV catalog URL.
    #[serde(default = "default_kev_endpoint")]
    pub kev_endpoint: String,
    /// When set, only emit findings for KEV-listed CVEs. Suppresses
    /// every other tier — high-signal mode for operators who want the
    /// shortest possible alert stream.
    #[serde(default)]
    pub kev_only: bool,
    /// Lowest severity tier that should surface in the inbox. Findings
    /// below this floor are dropped before the per-target Proposal is
    /// built. KEV-listed CVEs always bypass the floor (a KEV listing
    /// promotes severity to Critical anyway, but the bypass is explicit
    /// in `should_emit` so a future floor=Critical doesn't accidentally
    /// hide a borderline KEV).
    ///
    /// Default `High` — for a fresh Debian/Ubuntu host, this typically
    /// trims the OSV finding count from ~150 to ~30 by hiding the long
    /// tail of CVSS 4.0–6.9 issues, while keeping every Critical and
    /// every actively-exploited (KEV) CVE.
    #[serde(default = "default_severity_floor")]
    pub severity_floor: Severity,
    /// When set, OSV findings whose upstream record carries no `fixed`
    /// version (i.e. the distro hasn't shipped a patch yet) are auto-
    /// suppressed unless they are KEV-listed or hit the Critical tier.
    /// The suppressed count is reported on `OsvFacts.suppressed_no_fix`
    /// so the inbox card can surface the hidden total honestly.
    ///
    /// Rationale: distro security teams routinely take 4–12 weeks to
    /// ship a patched package after CVE disclosure. Until that lands,
    /// there is literally nothing the operator can do — we'd just be
    /// re-asking them to run an upgrade that won't help. Once OSV
    /// publishes a `fixed` version, the finding resurfaces on the next
    /// scan automatically. KEV-listed and Critical findings are NEVER
    /// auto-suppressed because they need eyeballs even without a fix.
    #[serde(default = "default_true")]
    pub suppress_no_fix: bool,
    /// Per-distro ecosystem override. Keyed by `/etc/os-release` `ID=`
    /// field (lowercase); value is the literal OSV ecosystem string
    /// (e.g. `"Ubuntu:24.04:LTS"`). This is the operator escape hatch
    /// for Linux derivatives our codename table doesn't cover yet —
    /// no need to wait for a WolfStack release.
    #[serde(default)]
    pub distro_overrides: HashMap<String, String>,
}

fn default_true() -> bool { true }
fn default_osv_endpoint() -> String { OSV_DEFAULT_ENDPOINT.to_string() }
fn default_kev_endpoint() -> String { KEV_DEFAULT_ENDPOINT.to_string() }
fn default_severity_floor() -> Severity { Severity::High }

impl Default for OsvConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: OSV_DEFAULT_ENDPOINT.to_string(),
            kev_endpoint: KEV_DEFAULT_ENDPOINT.to_string(),
            kev_only: false,
            severity_floor: default_severity_floor(),
            suppress_no_fix: true,
            distro_overrides: HashMap::new(),
        }
    }
}

impl OsvConfig {
    pub fn load() -> Self {
        let path = std::env::var("WOLFSTACK_OSV_CONFIG_FILE")
            .unwrap_or_else(|_| OSV_CONFIG_FILE.to_string());
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = std::env::var("WOLFSTACK_OSV_CONFIG_FILE")
            .unwrap_or_else(|_| OSV_CONFIG_FILE.to_string());
        let pb = PathBuf::from(&path);
        if let Some(dir) = pb.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let s = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&pb, s).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------
// Inventory model
// ---------------------------------------------------------------------

/// Where a finding applies — host or one named LXC container.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanTarget {
    Host,
    Lxc { name: String },
}

impl ScanTarget {
    pub fn label(&self) -> String {
        match self {
            ScanTarget::Host => "host".to_string(),
            ScanTarget::Lxc { name } => format!("lxc:{}", name),
        }
    }

    pub fn resource_id(&self) -> String {
        // Distinct from the distro-pocket analyzer's `host` /
        // `lxc:NAME` resource ids — same pattern but prefixed with
        // `osv:` so OSV findings can't collide with the existing
        // distro-pocket findings on (finding_type, scope) dedup.
        match self {
            ScanTarget::Host => "osv:host".to_string(),
            ScanTarget::Lxc { name } => format!("osv:lxc:{}", name),
        }
    }
}

/// One installed package from the host's package database. The
/// `(ecosystem, name, version)` triple is the OSV query key — the
/// version string must match the distro's exact version format
/// (including epoch+release suffix) for OSV's range matcher to
/// resolve correctly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InventoryEntry {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// All packages found on one target plus the kernel package (which
/// is special-cased — `dpkg -l linux-image-*` lists every kernel
/// the system has ever booted, but only `uname -r` tells you which
/// one is currently running, and that's the only one a CVE actually
/// affects).
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub target: ScanTargetOwned,
    pub entries: Vec<InventoryEntry>,
    /// Resolution outcome. The mapped ecosystem (when any) is
    /// applied to every entry; non-Mapped variants drive the
    /// breadcrumb logic in `analyze`.
    pub resolution: EcosystemResolution,
    /// Best-effort kernel package name + running version, derived
    /// from `uname -r`. Always queried separately because the
    /// installed-kernel-packages list contains stale versions.
    pub running_kernel: Option<RunningKernel>,
}

impl Default for EcosystemResolution {
    fn default() -> Self { EcosystemResolution::Unknown }
}

impl Inventory {
    /// Convenience: the ecosystem string when resolution succeeded.
    pub fn ecosystem(&self) -> Option<&str> {
        match &self.resolution {
            EcosystemResolution::Mapped(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// Owned variant — keeps `Inventory` cheap to clone without lifetime
/// gymnastics through the analyzer pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScanTargetOwned {
    Host,
    Lxc(String),
}

impl Default for ScanTargetOwned {
    fn default() -> Self { ScanTargetOwned::Host }
}

impl ScanTargetOwned {
    pub fn as_target(&self) -> ScanTarget {
        match self {
            ScanTargetOwned::Host => ScanTarget::Host,
            ScanTargetOwned::Lxc(n) => ScanTarget::Lxc { name: n.clone() },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunningKernel {
    /// Distro-flavoured kernel package name. e.g. "linux-image-6.8.0-39-generic"
    /// on Ubuntu, "kernel" on RHEL, "linux" on Arch.
    pub package: String,
    /// Version OSV will recognise. For Debian/Ubuntu this is the
    /// dpkg version; for RHEL it's `version-release`.
    pub version: String,
}

// ---------------------------------------------------------------------
// OSV vuln model — what we cache from the API
// ---------------------------------------------------------------------

/// A single OSV vulnerability record, distilled to the fields we
/// actually use. Cached so repeat scans don't refetch /v1/vulns/{id}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    /// Other IDs for the same vuln, including CVE IDs. KEV cross-ref
    /// keys off this.
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: String,
    /// Highest CVSS base score we could parse out of the `severity`
    /// array (v3 takes precedence over v4 takes precedence over v2).
    /// None when no CVSS vector was supplied.
    #[serde(default)]
    pub cvss_score: Option<f32>,
    /// First reference URL whose `type` is `ADVISORY`. Used as the
    /// canonical link in the inbox card. Kept for back-compat with
    /// existing cache files; new code should prefer `references` and
    /// pick the most relevant link by type.
    #[serde(default)]
    pub advisory_url: Option<String>,
    /// All references attached to the OSV record — vendor advisories,
    /// distro trackers, CISA KEV pages, vulnerability writeups. Used
    /// to render mitigation chips on the inbox card so the operator
    /// can read authoritative guidance for unpatched CVEs (instead of
    /// us synthesising it). Empty for very old cached records — they
    /// will repopulate on the next OSV refresh.
    #[serde(default)]
    pub references: Vec<OsvVulnReference>,
    /// `modified` timestamp from the OSV record. Used to invalidate
    /// the cache when the upstream record changes.
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
    /// Best-effort fixed-version map keyed by package name. Pulled
    /// from `affected[].ranges[].events[].fixed`. May be empty if
    /// the upstream record lists no fixed event.
    #[serde(default)]
    pub fixed_versions: HashMap<String, String>,
}

/// One reference URL on an OSV record, with its `type` so the inbox
/// can label the chip ("Advisory", "Web", "Fix", etc.). The cached
/// twin of [`OsvReference`] — kept separate so the on-disk schema
/// is decoupled from the wire schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnReference {
    #[serde(rename = "type")]
    pub ty: String,
    pub url: String,
}

impl OsvVuln {
    /// Pull every CVE-shaped string out of `aliases` (and `id` if
    /// it itself is a CVE). KEV catalog only indexes CVEs.
    pub fn cve_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = self.aliases.iter()
            .chain(std::iter::once(&self.id))
            .filter(|s| s.starts_with("CVE-"))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// User-facing CVE label. Prefers the first CVE alias; falls
    /// back to the OSV id when no CVE is recorded.
    pub fn display_id(&self) -> String {
        self.cve_ids().into_iter().next().unwrap_or_else(|| self.id.clone())
    }
}

// ---------------------------------------------------------------------
// Persistent OSV cache
// ---------------------------------------------------------------------

/// On-disk cache: vuln records (keyed by OSV id) and the most-recent
/// query results (keyed by `(ecosystem, name, version)`), plus the
/// timestamps used to rate limit. JSON because every other WolfStack
/// state file is JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsvCache {
    #[serde(default)]
    pub last_full_scan_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub vulns: HashMap<String, OsvVuln>,
    /// `key = "ecosystem|name|version"` → list of OSV vuln ids
    /// matching that exact tuple. Lookup is O(1) once an inventory
    /// row is known.
    #[serde(default)]
    pub matches: HashMap<String, Vec<String>>,
}

impl OsvCache {
    pub fn load() -> Self {
        let path = cache_path();
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = cache_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let s = serde_json::to_string(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, s).map_err(|e| e.to_string())
    }
}

fn cache_path() -> PathBuf {
    PathBuf::from(
        std::env::var("WOLFSTACK_OSV_CACHE_FILE")
            .unwrap_or_else(|_| OSV_CACHE_FILE.to_string()),
    )
}

/// Composite key for the matches map.
fn match_key(ecosystem: &str, name: &str, version: &str) -> String {
    format!("{}|{}|{}", ecosystem, name, version)
}

// ---------------------------------------------------------------------
// KEV cache
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KevCache {
    #[serde(default)]
    pub fetched_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub catalog_version: Option<String>,
    /// Set of CVE IDs currently on the KEV list. Stored as a sorted
    /// vec for stable JSON output (HashSet would shuffle).
    #[serde(default)]
    pub cves: BTreeSet<String>,
}

impl KevCache {
    pub fn load() -> Self {
        let path = kev_path();
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = kev_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let s = serde_json::to_string(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, s).map_err(|e| e.to_string())
    }

    pub fn is_fresh(&self) -> bool {
        match self.fetched_at {
            Some(t) => (Utc::now() - t).num_seconds() < KEV_REFRESH_COOLDOWN.as_secs() as i64,
            None => false,
        }
    }
}

fn kev_path() -> PathBuf {
    PathBuf::from(
        std::env::var("WOLFSTACK_KEV_CACHE_FILE")
            .unwrap_or_else(|_| KEV_CACHE_FILE.to_string()),
    )
}

// ---------------------------------------------------------------------
// Subprocess helper (mirrors vulnerability::run_capped)
// ---------------------------------------------------------------------

fn run_capped(prog: &str, args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    let mut child = Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                let mut buf = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut buf);
                }
                return Some(buf);
            }
            Ok(Some(_)) => return None,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------
// /etc/os-release parsing → OSV ecosystem
// ---------------------------------------------------------------------

/// Runtime-loaded codename → version map. Sourced from the
/// Debian-maintained `distro-info-data` package
/// (`/usr/share/distro-info/{ubuntu,debian}.csv`), which gets a fresh
/// row whenever Canonical or Debian announce a new release. When
/// present, this overrides our hardcoded fallback tables — operators
/// who keep `distro-info-data` current get coverage for new releases
/// without waiting for a WolfStack version bump.
#[derive(Debug, Clone, Default)]
pub struct DistroInfo {
    /// codename (lowercase, e.g. `noble`) → Ubuntu YY.MM (e.g. `24.04`).
    pub ubuntu_codenames: HashMap<String, String>,
    /// codename (lowercase, e.g. `bookworm`) → Debian major (e.g. `12`).
    pub debian_codenames: HashMap<String, u32>,
}

impl DistroInfo {
    /// Read the CSVs if installed. Always succeeds (returns an empty
    /// instance on missing files) so callers can blindly use it.
    pub fn load() -> Self {
        let mut me = Self::default();
        if let Ok(s) = std::fs::read_to_string(DISTRO_INFO_UBUNTU_CSV) {
            me.ubuntu_codenames = parse_ubuntu_csv(&s);
        }
        if let Ok(s) = std::fs::read_to_string(DISTRO_INFO_DEBIAN_CSV) {
            me.debian_codenames = parse_debian_csv(&s);
        }
        me
    }
}

/// Parse `/usr/share/distro-info/ubuntu.csv`. Header row:
/// `version,codename,series,created,release,eol,eol-server,...`.
/// We want `series → version-without-LTS-suffix`. The `version`
/// column is the YY.MM field (sometimes with a trailing ` LTS`).
fn parse_ubuntu_csv(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 { continue; } // header
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 3 { continue; }
        let version = cols[0].trim().trim_end_matches(" LTS").trim();
        let series = cols[2].trim().to_lowercase();
        if !version.is_empty() && !series.is_empty() {
            out.insert(series, version.to_string());
        }
    }
    out
}

/// Parse `/usr/share/distro-info/debian.csv`. Same header shape; we
/// want `series → numeric-major-version`. Non-numeric versions
/// (`unstable`, `testing`) are skipped — those map to "Debian:sid"
/// via the caller's fallback path.
fn parse_debian_csv(text: &str) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 { continue; }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 3 { continue; }
        let version = cols[0].trim();
        let series = cols[2].trim().to_lowercase();
        if let Ok(major) = version.parse::<u32>() {
            out.insert(series, major);
        }
    }
    out
}

/// Result of resolving `/etc/os-release` to an OSV ecosystem. The
/// rich enum lets the analyzer emit a breadcrumb finding when we
/// recognise a derivative but can't map its codename — turning a
/// silent miss into an actionable inbox entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcosystemResolution {
    /// Successfully mapped to an OSV ecosystem string.
    Mapped(String),
    /// `ID_LIKE=ubuntu` or `ID_LIKE=debian` derivative whose codename
    /// we couldn't resolve via overrides, distro-info CSV, or our
    /// hardcoded table. The breadcrumb finding tells the operator to
    /// install `distro-info-data` or add an override.
    UnrecognizedDerivative {
        id: String,
        parent: ParentDistro,
        codename_hint: Option<String>,
    },
    /// Distro is not in OSV (Fedora, RHEL, Amazon, Arch, etc.).
    /// Caller defers to the pocket scanner.
    Unsupported { id: String },
    /// `/etc/os-release` was missing or malformed — no ID found.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentDistro {
    Ubuntu,
    Debian,
}

impl ParentDistro {
    fn label(self) -> &'static str {
        match self { ParentDistro::Ubuntu => "Ubuntu", ParentDistro::Debian => "Debian" }
    }
}

/// Full layered resolver. Order:
/// 1. Operator override (`config.distro_overrides[id]`).
/// 2. Direct ID match — Ubuntu/Debian/Rocky/Alpine/etc. use
///    `VERSION_ID` so they self-update on new releases.
/// 3. `ID_LIKE=ubuntu`/`debian` derivative: codename → version via
///    `DistroInfo` (system CSV) → hardcoded fallback table.
/// 4. Otherwise → `Unsupported` or `UnrecognizedDerivative`.
pub fn resolve_ecosystem(
    os_release: &str,
    overrides: &HashMap<String, String>,
    distro_info: &DistroInfo,
) -> EcosystemResolution {
    let mut id: Option<String> = None;
    let mut id_like: Vec<String> = Vec::new();
    let mut version_id: Option<String> = None;
    let mut version_codename: Option<String> = None;
    let mut ubuntu_codename: Option<String> = None;
    let mut debian_codename: Option<String> = None;
    let mut pretty_name: Option<String> = None;
    for line in os_release.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ID=") {
            id = Some(unquote(rest).to_lowercase());
        } else if let Some(rest) = line.strip_prefix("ID_LIKE=") {
            id_like = unquote(rest).split_whitespace().map(|s| s.to_lowercase()).collect();
        } else if let Some(rest) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(unquote(rest).to_string());
        } else if let Some(rest) = line.strip_prefix("VERSION_CODENAME=") {
            version_codename = Some(unquote(rest).to_lowercase());
        } else if let Some(rest) = line.strip_prefix("UBUNTU_CODENAME=") {
            ubuntu_codename = Some(unquote(rest).to_lowercase());
        } else if let Some(rest) = line.strip_prefix("DEBIAN_CODENAME=") {
            debian_codename = Some(unquote(rest).to_lowercase());
        } else if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
            pretty_name = Some(unquote(rest).to_string());
        }
    }
    let id = match id {
        Some(s) => s,
        None => return EcosystemResolution::Unknown,
    };

    // Layer 1: operator override always wins.
    if let Some(eco) = overrides.get(&id) {
        return EcosystemResolution::Mapped(eco.clone());
    }

    // Layer 2: direct ID match.
    match id.as_str() {
        "debian" => return EcosystemResolution::Mapped(map_debian(&version_id, &version_codename)),
        "ubuntu" => return EcosystemResolution::Mapped(map_ubuntu(&version_id, &pretty_name)),
        "rocky" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("Rocky Linux:{}", major_only(v))))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "almalinux" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("AlmaLinux:{}", major_only(v))))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "alpine" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("Alpine:v{}", ymm_only(v))))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "opensuse-leap" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("openSUSE:Leap {}", v)))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "opensuse-tumbleweed" => return EcosystemResolution::Mapped("openSUSE:Tumbleweed".to_string()),
        "opensuse" => {
            let pn = pretty_name.as_deref().unwrap_or("");
            if pn.contains("Tumbleweed") {
                return EcosystemResolution::Mapped("openSUSE:Tumbleweed".to_string());
            }
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("openSUSE:Leap {}", v)))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "mageia" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("Mageia:{}", major_only(v))))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "openeuler" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("openEuler:{}", v)))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "photon" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("Photon OS:{}", v)))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "alpaquita" => {
            return version_id.as_deref()
                .map(|v| EcosystemResolution::Mapped(format!("Alpaquita:{}", major_only(v))))
                .unwrap_or(EcosystemResolution::Unsupported { id });
        }
        "wolfi" => return EcosystemResolution::Mapped("Wolfi".to_string()),
        "chainguard" => return EcosystemResolution::Mapped("Chainguard".to_string()),
        "minimos" => return EcosystemResolution::Mapped("MinimOS".to_string()),
        "cleanstart" => return EcosystemResolution::Mapped("CleanStart".to_string()),
        "bellsoft-hardened" | "bellsoft" => {
            return EcosystemResolution::Mapped(version_id.as_deref()
                .map(|v| format!("BellSoft Hardened Containers:{}", major_only(v)))
                .unwrap_or_else(|| "BellSoft Hardened Containers:23".to_string()));
        }
        // Distros not in OSV.
        "arch" | "manjaro" | "endeavouros" | "cachyos" | "garuda" | "artix"
        | "fedora" | "rhel" | "centos" | "ol" | "oracle" | "amzn" | "rockylinuxhpc"
        | "sles" | "sle_hpc" | "suse" => return EcosystemResolution::Unsupported { id },
        _ => {}
    }

    // Layer 3: ID_LIKE-based derivative resolution.
    let likes_ubuntu = id_like.iter().any(|s| s == "ubuntu");
    let likes_debian = id_like.iter().any(|s| s == "debian");

    if likes_ubuntu {
        let codename = ubuntu_codename.as_deref().or(version_codename.as_deref());
        if let Some(cn) = codename {
            // Try CSV → hardcoded fallback.
            let ymm = distro_info.ubuntu_codenames.get(cn).cloned()
                .or_else(|| ubuntu_ymm_for_codename(cn));
            if let Some(ymm) = ymm {
                return EcosystemResolution::Mapped(map_ubuntu(
                    &Some(ymm),
                    &Some(format!("derived from {} → Ubuntu LTS", cn)),
                ));
            }
            return EcosystemResolution::UnrecognizedDerivative {
                id,
                parent: ParentDistro::Ubuntu,
                codename_hint: Some(cn.to_string()),
            };
        }
        return EcosystemResolution::UnrecognizedDerivative {
            id,
            parent: ParentDistro::Ubuntu,
            codename_hint: None,
        };
    }
    if likes_debian {
        let codename = debian_codename.as_deref().or(version_codename.as_deref());
        if let Some(cn) = codename {
            let major = distro_info.debian_codenames.get(cn).copied()
                .or_else(|| debian_major_for_codename(cn));
            if let Some(m) = major {
                return EcosystemResolution::Mapped(format!("Debian:{}", m));
            }
            // Debian rolling codenames (sid, kali-rolling, etc.) map
            // to Debian:sid. Anything else where we know the parent
            // is Debian but can't pin a major: emit the breadcrumb
            // so the operator knows.
            if cn == "sid" || cn.contains("rolling") || cn == "unstable" || cn == "testing" {
                return EcosystemResolution::Mapped("Debian:sid".to_string());
            }
            return EcosystemResolution::UnrecognizedDerivative {
                id,
                parent: ParentDistro::Debian,
                codename_hint: Some(cn.to_string()),
            };
        }
        // No codename at all but ID_LIKE=debian — version_id may be
        // numeric (Devuan tags this).
        if let Some(v) = version_id.as_deref() {
            if v.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                return EcosystemResolution::Mapped(format!("Debian:{}", major_only(v)));
            }
        }
        return EcosystemResolution::UnrecognizedDerivative {
            id,
            parent: ParentDistro::Debian,
            codename_hint: None,
        };
    }

    EcosystemResolution::Unsupported { id }
}

/// Bare ecosystem lookup used only by the tests in this module —
/// production code paths use `resolve_ecosystem` directly so the
/// breadcrumb logic can fire on `Unsupported` /
/// `UnrecognizedDerivative`.
#[cfg(test)]
fn ecosystem_from_os_release(text: &str) -> Option<String> {
    match resolve_ecosystem(text, &HashMap::new(), &DistroInfo::default()) {
        EcosystemResolution::Mapped(s) => Some(s),
        _ => None,
    }
}

fn map_debian(version_id: &Option<String>, codename: &Option<String>) -> String {
    // Numeric major if we have it; codename otherwise. OSV accepts
    // both ("Debian:12" and "Debian:bookworm" resolve identically).
    if let Some(v) = version_id.as_deref() {
        if !v.is_empty() {
            return format!("Debian:{}", major_only(v));
        }
    }
    if let Some(c) = codename.as_deref() {
        return format!("Debian:{}", c);
    }
    "Debian:sid".to_string()
}

fn map_ubuntu(version_id: &Option<String>, pretty_name: &Option<String>) -> String {
    let ver = version_id.as_deref().unwrap_or("");
    let ymm = if ver.is_empty() { "rolling".to_string() } else { ymm_only(ver) };
    let is_lts = pretty_name.as_deref().map(|p| p.contains("LTS")).unwrap_or(false);
    let major: u32 = ymm.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = ymm.split('.').nth(1).unwrap_or("");
    let lts_by_pattern = major % 2 == 0 && minor == "04";
    if is_lts || lts_by_pattern {
        format!("Ubuntu:{}:LTS", ymm)
    } else {
        format!("Ubuntu:{}", ymm)
    }
}

/// Map an Ubuntu codename (jammy / focal / noble / etc.) to the
/// matching YY.MM release string. Used by Ubuntu-derivative distros
/// that report only the codename in `UBUNTU_CODENAME`.
///
/// Source: Canonical's release schedule
/// (https://wiki.ubuntu.com/Releases). Only LTS + currently-supported
/// interim releases are mapped — older codenames return None and we
/// fall through to the pocket scanner rather than guess.
fn ubuntu_ymm_for_codename(codename: &str) -> Option<String> {
    Some(match codename {
        "trusty" => "14.04",
        "xenial" => "16.04",
        "bionic" => "18.04",
        "focal" => "20.04",
        "jammy" => "22.04",
        "noble" => "24.04",
        "lunar" => "23.04",
        "mantic" => "23.10",
        "oracular" => "24.10",
        "plucky" => "25.04",
        _ => return None,
    }.to_string())
}

/// Map a Debian codename to its major release number.
///
/// Source: Debian's release schedule
/// (https://www.debian.org/releases/). `sid` (unstable) and rolling
/// codenames return None — caller maps those to "Debian:sid".
fn debian_major_for_codename(codename: &str) -> Option<u32> {
    Some(match codename {
        "wheezy" => 7,
        "jessie" => 8,
        "stretch" => 9,
        "buster" => 10,
        "bullseye" => 11,
        "bookworm" => 12,
        "trixie" => 13,
        "forky" => 14,
        _ => return None,
    })
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    s.trim_start_matches('"').trim_end_matches('"')
}

/// Strip everything after the first `.` in a "X.Y[.Z]" version string,
/// returning just "X". OSV's distro ecosystems all index by major
/// version only.
fn major_only(version: &str) -> String {
    version.split('.').next().unwrap_or(version).to_string()
}

/// Keep only the first two dot-segments of a version. Used for
/// Ubuntu (YY.MM) and Alpine (X.Y) where OSV indexes by major.minor.
fn ymm_only(version: &str) -> String {
    let mut parts = version.splitn(3, '.');
    match (parts.next(), parts.next()) {
        (Some(a), Some(b)) => format!("{}.{}", a, b),
        (Some(a), None) => a.to_string(),
        _ => version.to_string(),
    }
}

// ---------------------------------------------------------------------
// Inventory collection
// ---------------------------------------------------------------------

/// Collect host inventory. Returns an empty `Inventory` (with the
/// error field set) when no supported package manager is reachable —
/// the analyzer treats that as "no data this tick" and won't
/// auto-resolve any prior findings.
pub fn collect_host_inventory(
    overrides: &HashMap<String, String>,
    distro_info: &DistroInfo,
) -> Inventory {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let resolution = resolve_ecosystem(&os_release, overrides, distro_info);
    let pm = crate::predictive::vulnerability::detect_host_pm();
    let raw_entries = match pm {
        PackageManager::Apt => list_dpkg(),
        PackageManager::Dnf | PackageManager::Yum | PackageManager::Zypper => list_rpm(),
        PackageManager::Apk => list_apk(),
        PackageManager::Pacman | PackageManager::None => Vec::new(),
    };
    let entries: Vec<InventoryEntry> = match &resolution {
        EcosystemResolution::Mapped(eco) => raw_entries.into_iter().map(|(name, ver)| {
            InventoryEntry { ecosystem: eco.clone(), name, version: ver }
        }).collect(),
        _ => Vec::new(),
    };
    let running_kernel = collect_running_kernel(pm);
    Inventory {
        target: ScanTargetOwned::Host,
        entries,
        resolution,
        running_kernel,
    }
}

/// Collect inventory for one running LXC container. The probe order
/// matches `vulnerability::sample_lxc_one` so a host with one Debian
/// LXC and one Alpine LXC produces two correctly-typed inventories.
pub fn collect_lxc_inventory(
    name: &str,
    overrides: &HashMap<String, String>,
    distro_info: &DistroInfo,
) -> Inventory {
    fn attach(args: &[&str], timeout: Duration, name: &str) -> Option<String> {
        let mut full: Vec<&str> = vec!["-n", name, "--"];
        full.extend_from_slice(args);
        run_capped("lxc-attach", &full, timeout)
    }
    // os-release first — without it we can't classify the container.
    let os_release = attach(&["cat", "/etc/os-release"], LXC_INVENTORY_TIMEOUT, name)
        .unwrap_or_default();
    let resolution = resolve_ecosystem(&os_release, overrides, distro_info);
    let eco = match &resolution {
        EcosystemResolution::Mapped(s) => s.clone(),
        _ => {
            return Inventory {
                target: ScanTargetOwned::Lxc(name.to_string()),
                entries: Vec::new(),
                resolution,
                running_kernel: None,
            };
        }
    };
    // Try dpkg → rpm → apk in that order.
    let entries: Vec<(String, String)> = if let Some(text) = attach(
        &["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        LXC_INVENTORY_TIMEOUT, name,
    ) {
        parse_dpkg_query(&text)
    } else if let Some(text) = attach(
        &["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        LXC_INVENTORY_TIMEOUT, name,
    ) {
        parse_rpm_qa(&text)
    } else if let Some(text) = attach(
        &["apk", "info", "-v"],
        LXC_INVENTORY_TIMEOUT, name,
    ) {
        parse_apk_info(&text)
    } else {
        Vec::new()
    };
    let entries: Vec<InventoryEntry> = entries.into_iter().map(|(n, v)| {
        InventoryEntry { ecosystem: eco.clone(), name: n, version: v }
    }).collect();
    Inventory {
        target: ScanTargetOwned::Lxc(name.to_string()),
        entries,
        resolution,
        running_kernel: None,
    }
}

fn list_dpkg() -> Vec<(String, String)> {
    let text = run_capped(
        "dpkg-query",
        &["-W", "-f=${Package}\t${Version}\n"],
        INVENTORY_TIMEOUT,
    ).unwrap_or_default();
    parse_dpkg_query(&text)
}

fn list_rpm() -> Vec<(String, String)> {
    let text = run_capped(
        "rpm",
        &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        INVENTORY_TIMEOUT,
    ).unwrap_or_default();
    parse_rpm_qa(&text)
}

fn list_apk() -> Vec<(String, String)> {
    let text = run_capped("apk", &["info", "-v"], INVENTORY_TIMEOUT).unwrap_or_default();
    parse_apk_info(&text)
}

/// Parse `dpkg-query -W -f='${Package}\t${Version}\n'`. Tab-separated
/// `name<TAB>version` per line. Architecture-suffixed packages (e.g.
/// `libfoo:amd64`) come through unchanged from dpkg; we strip the
/// `:amd64` suffix because OSV indexes by bare package name.
pub fn parse_dpkg_query(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, '\t');
        let name = parts.next().unwrap_or("").trim();
        let version = parts.next().unwrap_or("").trim();
        if name.is_empty() || version.is_empty() { continue; }
        // Strip multi-arch suffix: `libfoo:amd64` → `libfoo`.
        let name = name.split(':').next().unwrap_or(name);
        out.push((name.to_string(), version.to_string()));
    }
    out
}

/// Parse `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`. RPM's
/// version+release is what OSV expects for RHEL-family ecosystems.
pub fn parse_rpm_qa(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, '\t');
        let name = parts.next().unwrap_or("").trim();
        let version = parts.next().unwrap_or("").trim();
        if name.is_empty() || version.is_empty() { continue; }
        out.push((name.to_string(), version.to_string()));
    }
    out
}

/// Parse `apk info -v`. Each line: `pkgname-1.2.3-r4`. The version
/// is everything after the LAST `-DIGIT` boundary; the package name
/// is everything before that. Walking right-to-left through hyphens
/// and stopping at the first chunk whose first char is a digit is
/// the standard apk parsing rule.
pub fn parse_apk_info(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Split at the first hyphen-followed-by-digit.
        let bytes = line.as_bytes();
        let mut split_at: Option<usize> = None;
        for i in 1..bytes.len() {
            if bytes[i - 1] == b'-' && bytes[i].is_ascii_digit() {
                split_at = Some(i - 1);
                break;
            }
        }
        match split_at {
            Some(i) => {
                let name = &line[..i];
                let version = &line[i + 1..];
                if !name.is_empty() && !version.is_empty() {
                    out.push((name.to_string(), version.to_string()));
                }
            }
            None => continue,
        }
    }
    out
}

/// Probe the running kernel. Inventory lists every installed kernel
/// package, but only the one we're booted into actually carries the
/// CVE risk — every other entry is dormant on disk. We supply the
/// running version separately so the analyzer can dedup kernel CVE
/// findings to the version actually loaded.
fn collect_running_kernel(pm: PackageManager) -> Option<RunningKernel> {
    let raw = run_capped("uname", &["-r"], Duration::from_secs(2))?;
    let release = raw.trim();
    if release.is_empty() { return None; }
    match pm {
        PackageManager::Apt => Some(RunningKernel {
            // dpkg names the package `linux-image-<release>`.
            package: format!("linux-image-{}", release),
            version: kernel_version_from_dpkg(release).unwrap_or_else(|| release.to_string()),
        }),
        PackageManager::Dnf | PackageManager::Yum | PackageManager::Zypper => {
            // RHEL family: package is "kernel" or "kernel-default";
            // version is the uname -r without the architecture
            // suffix. `release` already drops .arch.
            Some(RunningKernel {
                package: "kernel".to_string(),
                version: release.to_string(),
            })
        }
        PackageManager::Apk => Some(RunningKernel {
            // Alpine ships `linux-virt` / `linux-lts` etc. The exact
            // package depends on the boot kernel; the version we
            // care about is `release` itself.
            package: "linux-lts".to_string(),
            version: release.to_string(),
        }),
        PackageManager::Pacman | PackageManager::None => None,
    }
}

/// On Debian/Ubuntu, `uname -r` returns something like "6.8.0-39-generic"
/// but the dpkg version is something like "6.8.0-39.39". Look up the
/// installed package version from dpkg directly so OSV's range
/// matcher gets the right form.
fn kernel_version_from_dpkg(release: &str) -> Option<String> {
    let pkg = format!("linux-image-{}", release);
    let text = run_capped(
        "dpkg-query",
        &["-W", "-f=${Version}", &pkg],
        Duration::from_secs(3),
    )?;
    let trimmed = text.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

// ---------------------------------------------------------------------
// HTTP — OSV
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OsvBatchRequest<'a> {
    queries: Vec<OsvBatchQueryItem<'a>>,
}

#[derive(Debug, Serialize)]
struct OsvBatchQueryItem<'a> {
    package: OsvPackageRef<'a>,
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct OsvPackageRef<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResult>,
}

#[derive(Debug, Deserialize, Default)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvBatchVulnRef>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchVulnRef {
    id: String,
}

/// Full OSV vuln record — exactly the subset of fields we use,
/// matching the OSV schema spec at https://ossf.github.io/osv-schema/.
#[derive(Debug, Deserialize)]
struct OsvFullVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    score: String,
}

#[derive(Debug, Deserialize, Default)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvAffectedPackage {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize, Default)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type", default)]
    ty: String,
    #[serde(default)]
    url: String,
}

/// POST /v1/querybatch with up to OSV_MAX_BATCH queries. Returns one
/// inner Vec per input query; index alignment is the OSV API contract.
fn osv_query_batch(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    inv: &[InventoryEntry],
) -> Result<Vec<Vec<OsvBatchVulnRef>>, String> {
    let mut out: Vec<Vec<OsvBatchVulnRef>> = Vec::with_capacity(inv.len());
    for chunk in inv.chunks(OSV_MAX_BATCH) {
        let body = OsvBatchRequest {
            queries: chunk.iter().map(|e| OsvBatchQueryItem {
                package: OsvPackageRef { name: &e.name, ecosystem: &e.ecosystem },
                version: &e.version,
            }).collect(),
        };
        let url = format!("{}/v1/querybatch", endpoint.trim_end_matches('/'));
        let resp = client.post(&url)
            .json(&body)
            .timeout(HTTP_TIMEOUT)
            .send()
            .map_err(|e| format!("OSV batch POST failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("OSV batch returned HTTP {}", resp.status()));
        }
        let parsed: OsvBatchResponse = resp.json()
            .map_err(|e| format!("OSV batch parse: {}", e))?;
        // OSV guarantees one result per query in input order. If the
        // count diverges treat as failure rather than guess at the
        // alignment.
        if parsed.results.len() != chunk.len() {
            return Err(format!(
                "OSV batch result count mismatch: got {} for {} queries",
                parsed.results.len(), chunk.len(),
            ));
        }
        for r in parsed.results {
            out.push(r.vulns);
        }
    }
    Ok(out)
}

/// GET /v1/vulns/{id} → full OSV record. We fetch this only for vuln
/// IDs we don't have in cache, OR whose `modified` timestamp from the
/// batch response is newer than the cached copy.
fn osv_fetch_vuln(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    id: &str,
) -> Result<OsvVuln, String> {
    let url = format!("{}/v1/vulns/{}", endpoint.trim_end_matches('/'), id);
    let resp = client.get(&url)
        .timeout(HTTP_TIMEOUT)
        .send()
        .map_err(|e| format!("OSV vuln GET {}: {}", id, e))?;
    if !resp.status().is_success() {
        return Err(format!("OSV vuln {} returned HTTP {}", id, resp.status()));
    }
    let full: OsvFullVuln = resp.json()
        .map_err(|e| format!("OSV vuln {} parse: {}", id, e))?;
    Ok(distill_full(full))
}

/// Reduce an OsvFullVuln to the fields we cache.
fn distill_full(full: OsvFullVuln) -> OsvVuln {
    let cvss_score = pick_best_cvss(&full.severity);
    let advisory_url = full.references.iter()
        .find(|r| r.ty.eq_ignore_ascii_case("ADVISORY"))
        .or_else(|| full.references.iter().find(|r| r.ty.eq_ignore_ascii_case("WEB")))
        .map(|r| r.url.clone());
    let references: Vec<OsvVulnReference> = full.references.iter()
        .filter(|r| !r.url.is_empty())
        .map(|r| OsvVulnReference {
            ty: if r.ty.is_empty() { "WEB".to_string() } else { r.ty.clone() },
            url: r.url.clone(),
        })
        .collect();
    let mut fixed_versions: HashMap<String, String> = HashMap::new();
    for aff in &full.affected {
        let pkg_name = aff.package.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if pkg_name.is_empty() { continue; }
        for r in &aff.ranges {
            for e in &r.events {
                if let Some(fv) = &e.fixed {
                    // First fixed event wins per package — OSV
                    // ranges are sorted oldest-introduced-first so
                    // the first `fixed` is the patch tag.
                    fixed_versions.entry(pkg_name.clone()).or_insert_with(|| fv.clone());
                }
            }
        }
    }
    OsvVuln {
        id: full.id,
        aliases: full.aliases,
        summary: full.summary,
        cvss_score,
        advisory_url,
        references,
        modified: full.modified,
        fixed_versions,
    }
}

// ---------------------------------------------------------------------
// CVSS scoring
// ---------------------------------------------------------------------

/// Pick the best CVSS base score from an OSV severity array. v3
/// preferred over v4 over v2 — v3 is what every modern advisory
/// supplies and what KEV's risk model is calibrated against. Returns
/// None when no parseable vector is present.
fn pick_best_cvss(severities: &[OsvSeverityEntry]) -> Option<f32> {
    let v3 = severities.iter()
        .find(|s| s.ty == "CVSS_V3")
        .and_then(|s| score_v3(&s.score));
    if v3.is_some() { return v3; }
    let v4 = severities.iter()
        .find(|s| s.ty == "CVSS_V4")
        .and_then(|s| score_v4_estimate(&s.score));
    if v4.is_some() { return v4; }
    severities.iter()
        .find(|s| s.ty == "CVSS_V2")
        .and_then(|s| score_v2(&s.score))
}

/// Compute the CVSS v3 base score from its vector string. Implements
/// the formula from FIRST CVSS v3.1 specification §7.1, with the
/// constants for each metric value from Table 14.
///
/// Vector form: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (the
/// `CVSS:3.0/` prefix is also accepted; the formula is unchanged
/// between 3.0 and 3.1 for base score).
pub fn score_v3(vector: &str) -> Option<f32> {
    let metrics = parse_vector(vector)?;
    let av = match metrics.get("AV").map(String::as_str) {
        Some("N") => 0.85, Some("A") => 0.62, Some("L") => 0.55, Some("P") => 0.20,
        _ => return None,
    };
    let ac = match metrics.get("AC").map(String::as_str) {
        Some("L") => 0.77, Some("H") => 0.44,
        _ => return None,
    };
    let scope_changed = matches!(metrics.get("S").map(String::as_str), Some("C"));
    let pr = match (metrics.get("PR").map(String::as_str), scope_changed) {
        (Some("N"), _)     => 0.85,
        (Some("L"), false) => 0.62, (Some("L"), true) => 0.68,
        (Some("H"), false) => 0.27, (Some("H"), true) => 0.50,
        _ => return None,
    };
    let ui = match metrics.get("UI").map(String::as_str) {
        Some("N") => 0.85, Some("R") => 0.62,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f32> {
        match metrics.get(k).map(String::as_str) {
            Some("N") => Some(0.0), Some("L") => Some(0.22), Some("H") => Some(0.56),
            _ => None,
        }
    };
    let c = cia("C")?;
    let i = cia("I")?;
    let a = cia("A")?;
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 { return Some(0.0); }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // Round up to one decimal — CVSS-specific roundUp behaviour.
    Some(round_up_one_decimal(raw))
}

/// Round x up to one decimal place. CVSS uses "Round-Up", which is
/// "the smallest decimal that is greater than or equal to x", not
/// banker's rounding.
fn round_up_one_decimal(x: f32) -> f32 {
    ((x * 10.0 - 0.000001).ceil()).max(0.0) / 10.0
}

/// Best-effort CVSS v4 score. The full v4 formula is a 70-line
/// piecewise lookup we don't need today — but a heuristic that uses
/// the explicit base metrics catches the common high-severity cases:
/// any high-impact metric on a network-attackable vuln scores ≥ 7,
/// and the worst combinations (AV:N + VC:H + VI:H) score ≥ 9. When
/// we can't tell, we conservatively return 7.5 so the finding still
/// gets High severity (not suppressed).
fn score_v4_estimate(vector: &str) -> Option<f32> {
    let metrics = parse_vector(vector)?;
    // V4 base metrics: AV (Attack Vector), AC, AT, PR, UI, VC/VI/VA
    // (vulnerable system Confidentiality/Integrity/Availability),
    // SC/SI/SA (subsequent system).
    let av_n = matches!(metrics.get("AV").map(String::as_str), Some("N"));
    let high = |k: &str| matches!(metrics.get(k).map(String::as_str), Some("H"));
    let pr_n = matches!(metrics.get("PR").map(String::as_str), Some("N"));
    let ui_n = matches!(metrics.get("UI").map(String::as_str), Some("N"));
    let any_high_impact = high("VC") || high("VI") || high("VA")
        || high("SC") || high("SI") || high("SA");
    Some(if av_n && pr_n && ui_n && any_high_impact {
        9.5
    } else if av_n && any_high_impact {
        8.5
    } else if any_high_impact {
        7.5
    } else {
        5.0
    })
}

/// Compute the CVSS v2 base score. Mostly here so we don't drop CVEs
/// that only have a v2 vector (rare modern, common pre-2016). Formula
/// from FIRST CVSS v2 spec §3.2.1.
fn score_v2(vector: &str) -> Option<f32> {
    let m = parse_vector(vector)?;
    let av = match m.get("AV").map(String::as_str) {
        Some("L") => 0.395, Some("A") => 0.646, Some("N") => 1.0,
        _ => return None,
    };
    let ac = match m.get("AC").map(String::as_str) {
        Some("H") => 0.35, Some("M") => 0.61, Some("L") => 0.71,
        _ => return None,
    };
    let au = match m.get("Au").map(String::as_str) {
        Some("M") => 0.45, Some("S") => 0.56, Some("N") => 0.704,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f32> {
        match m.get(k).map(String::as_str) {
            Some("N") => Some(0.0), Some("P") => Some(0.275), Some("C") => Some(0.660),
            _ => None,
        }
    };
    let c = cia("C")?;
    let i = cia("I")?;
    let a = cia("A")?;
    let impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a));
    let exploitability = 20.0 * av * ac * au;
    let f = if impact == 0.0 { 0.0 } else { 1.176 };
    let base = (0.6 * impact + 0.4 * exploitability - 1.5) * f;
    Some(((base * 10.0).round() / 10.0).max(0.0).min(10.0))
}

/// Generic CVSS vector parser: splits on `/`, takes everything after
/// the (optional) `CVSS:` version prefix, then collects each
/// `KEY:VAL` pair into a map.
fn parse_vector(vector: &str) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    for part in vector.split('/') {
        let part = part.trim();
        if part.is_empty() { continue; }
        // Drop the version prefix (`CVSS:3.1`, `CVSS:4.0`, etc.).
        if let Some(rest) = part.strip_prefix("CVSS:") {
            // The version-only segment has no colon after the strip.
            if !rest.contains(':') { continue; }
        }
        if let Some((k, v)) = part.split_once(':') {
            // Skip the version segment captured above ("3.1", "4.0").
            if k.chars().next().map_or(false, |c| c.is_ascii_digit()) { continue; }
            out.insert(k.to_string(), v.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

// ---------------------------------------------------------------------
// KEV fetch
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct KevCatalog {
    #[serde(default, rename = "catalogVersion")]
    catalog_version: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// Refresh the KEV cache if it's stale. Returns the (possibly
/// unchanged) cache.
fn refresh_kev(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    cache: KevCache,
) -> KevCache {
    if cache.is_fresh() { return cache; }
    let resp = match client.get(endpoint).timeout(HTTP_TIMEOUT).send() {
        Ok(r) if r.status().is_success() => r,
        _ => return cache,
    };
    let parsed: KevCatalog = match resp.json() {
        Ok(p) => p,
        Err(_) => return cache,
    };
    let mut cves: BTreeSet<String> = BTreeSet::new();
    for v in parsed.vulnerabilities {
        cves.insert(v.cve_id);
    }
    let updated = KevCache {
        fetched_at: Some(Utc::now()),
        catalog_version: parsed.catalog_version,
        cves,
    };
    let _ = updated.save();
    updated
}

// ---------------------------------------------------------------------
// Sample → cache → analyze
// ---------------------------------------------------------------------

/// One match: a single CVE applies to a single (target, package).
/// A CVE that affects three packages on the host produces three
/// entries here, then the analyzer collapses them into one Proposal
/// per (target, CVE).
#[derive(Debug, Clone)]
pub struct OsvFinding {
    pub target: ScanTargetOwned,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub vuln: OsvVuln,
    pub kev_listed: bool,
    /// Whether OSV's record carries a `fixed` version for this
    /// finding's package. False means the upstream distro has not
    /// (yet) shipped a patched build, so `apt upgrade` etc. will not
    /// resolve the CVE — the operator can only mitigate or wait.
    /// Computed at sample time by looking up `vuln.fixed_versions`
    /// keyed by the matched package name.
    pub fix_available: bool,
}

/// What the analyzer consumes — the per-target findings plus a
/// per-target "I had data for this scope" marker so `covered_scopes`
/// can drive auto-resolve correctly.
#[derive(Debug, Clone, Default)]
pub struct OsvFacts {
    pub findings: Vec<OsvFinding>,
    /// Scopes for which we obtained an inventory this tick — even if
    /// no CVEs matched. An empty findings list against a covered
    /// scope means "scanned and clean", which IS a signal we want
    /// the auto-resolver to honour.
    pub covered_targets: Vec<ScanTargetOwned>,
    /// Targets where resolution surfaced an unrecognised derivative.
    /// The analyzer emits one Info-tier breadcrumb finding per entry
    /// nudging the operator toward `distro-info-data` or a manual
    /// override.
    pub unrecognized_derivatives: Vec<UnrecognizedDerivativeBreadcrumb>,
    pub config: OsvConfig,
    pub kev_cve_count: usize,
    /// Findings hidden by `OsvConfig.suppress_no_fix`. Reported on the
    /// per-target inbox card so the operator sees, honestly, that "143
    /// CVEs are awaiting an upstream patch" rather than a count of zero.
    /// Keyed by target so each card can render its own subtotal; the
    /// host group's count covers host findings, each LXC's its own.
    pub suppressed_no_fix_by_target: HashMap<ScanTargetOwned, usize>,
}

#[derive(Debug, Clone)]
pub struct UnrecognizedDerivativeBreadcrumb {
    pub target: ScanTargetOwned,
    pub id: String,
    pub parent: ParentDistro,
    pub codename_hint: Option<String>,
    pub distro_info_present: bool,
}

/// Cross-process / cross-call latch on the rate limit. Held only for
/// reads; writes happen via the OsvCache file. We keep an in-memory
/// copy so the orchestrator's 5-minute ticks don't all hit the disk
/// in case the cache file got corrupted at startup.
static LAST_SCAN_LATCH: Mutex<Option<DateTime<Utc>>> = Mutex::new(None);

fn within_cooldown(last: Option<DateTime<Utc>>) -> bool {
    match last {
        Some(t) => (Utc::now() - t).num_seconds() < OSV_QUERY_COOLDOWN.as_secs() as i64,
        None => false,
    }
}

/// Synchronous full sample. Like `vulnerability::sample_now`, runs
/// inside `spawn_blocking` from the orchestrator.
///
/// Algorithm:
///   1. Load config — bail if disabled.
///   2. Collect host + LXC inventories (always — cheap, local).
///   3. Build `covered_targets` from inventories that yielded ≥1
///      package (skip empty/error inventories).
///   4. If we're within cooldown AND have a non-empty cache, use the
///      cache to map inventory → vulns and skip the HTTP layer.
///   5. Otherwise, do the OSV batch + per-vuln fetch, refresh the
///      KEV cache, write the cache file, and stamp the rate-limit
///      latch.
pub fn sample_now() -> OsvFacts {
    let config = OsvConfig::load();
    let distro_info = DistroInfo::load();
    let distro_info_present = !distro_info.ubuntu_codenames.is_empty()
        || !distro_info.debian_codenames.is_empty();
    let mut facts = OsvFacts {
        findings: Vec::new(),
        covered_targets: Vec::new(),
        unrecognized_derivatives: Vec::new(),
        config: config.clone(),
        kev_cve_count: 0,
        suppressed_no_fix_by_target: HashMap::new(),
    };
    if !config.enabled { return facts; }

    // 1. Inventory.
    let host_inv = collect_host_inventory(&config.distro_overrides, &distro_info);
    let mut inventories: Vec<Inventory> = vec![host_inv];
    let containers = crate::containers::lxc_list_all_cached();
    let lxc_deadline = Instant::now() + LXC_TOTAL_BUDGET;
    for c in containers {
        if Instant::now() >= lxc_deadline {
            tracing::warn!("osv sampler: LXC budget exceeded, stopping fan-out early");
            break;
        }
        if c.state != "running" { continue; }
        inventories.push(collect_lxc_inventory(&c.name, &config.distro_overrides, &distro_info));
    }
    for inv in &inventories {
        if !inv.entries.is_empty() {
            facts.covered_targets.push(inv.target.clone());
        }
        if let EcosystemResolution::UnrecognizedDerivative { id, parent, codename_hint } = &inv.resolution {
            facts.unrecognized_derivatives.push(UnrecognizedDerivativeBreadcrumb {
                target: inv.target.clone(),
                id: id.clone(),
                parent: *parent,
                codename_hint: codename_hint.clone(),
                distro_info_present,
            });
        }
    }

    // 2. Decide cached vs fresh.
    let mut cache = OsvCache::load();
    let latch_last = LAST_SCAN_LATCH.lock().ok().and_then(|g| *g);
    let last = cache.last_full_scan_at.or(latch_last);
    let must_refresh = !within_cooldown(last) || cache.matches.is_empty();

    if must_refresh {
        match scan_osv(&config, &inventories) {
            Ok(new_cache) => {
                cache = new_cache;
                if let Ok(mut g) = LAST_SCAN_LATCH.lock() {
                    *g = cache.last_full_scan_at;
                }
                if let Err(e) = cache.save() {
                    tracing::warn!("osv: failed to persist cache: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("osv: scan failed: {} — using prior cache", e);
                // Fall through with the existing cache. If empty,
                // we'll emit no findings this tick; the next tick
                // will retry (LAST_SCAN_LATCH not stamped).
            }
        }
    }

    // 3. KEV refresh.
    let kev_client = match build_http_client() {
        Some(c) => c,
        None => {
            tracing::warn!("osv: failed to build HTTP client, skipping KEV refresh");
            return facts;
        }
    };
    let kev = refresh_kev(&kev_client, &config.kev_endpoint, KevCache::load());
    facts.kev_cve_count = kev.cves.len();

    // 4. Map inventory → cached vulns → findings, applying KEV
    //    cross-ref and the configured filters.
    for inv in &inventories {
        let mut seen_kernel = false;
        for entry in &inv.entries {
            // De-duplicate kernel rows: every kernel package the
            // distro ever installed is in dpkg, but only the running
            // one is interesting. If we have a `running_kernel` and
            // this entry isn't it, skip it for the kernel-scoped
            // dedup but DO still emit findings (the kernel CVE
            // matters even on installed-but-not-running images,
            // because a reboot would land on it).
            // Only suppress the duplicate per-target so the inbox
            // doesn't show 6 rows for the same CVE just because the
            // host has 6 kernel packages installed — keep the first.
            let is_kernel = entry.name.starts_with("linux-image-")
                || entry.name == "kernel"
                || entry.name == "kernel-default"
                || entry.name == "linux-lts"
                || entry.name == "linux";
            if is_kernel {
                if seen_kernel { continue; }
                seen_kernel = true;
            }
            let key = match_key(&entry.ecosystem, &entry.name, &entry.version);
            let ids = match cache.matches.get(&key) {
                Some(v) => v,
                None => continue,
            };
            for vid in ids {
                let vuln = match cache.vulns.get(vid) {
                    Some(v) => v.clone(),
                    None => continue,
                };
                let kev_listed = vuln.cve_ids().iter().any(|c| kev.cves.contains(c));
                if config.kev_only && !kev_listed { continue; }
                let fix_available = vuln.fixed_versions.contains_key(&entry.name);
                let finding = OsvFinding {
                    target: inv.target.clone(),
                    ecosystem: entry.ecosystem.clone(),
                    package: entry.name.clone(),
                    version: entry.version.clone(),
                    vuln,
                    kev_listed,
                    fix_available,
                };
                // Auto-suppress CVEs with no upstream patch yet — the
                // operator cannot do anything about these via package
                // updates. KEV-listed and Critical findings always
                // surface even without a fix because they need
                // attention regardless (mitigation, isolation, etc.).
                if config.suppress_no_fix
                    && !fix_available
                    && !kev_listed
                    && severity_for(&finding) != Severity::Critical
                {
                    *facts.suppressed_no_fix_by_target
                        .entry(inv.target.clone()).or_insert(0) += 1;
                    continue;
                }
                facts.findings.push(finding);
            }
        }
    }

    facts
}

/// Async wrapper used by the orchestrator. Mirrors
/// `vulnerability::sample_now_async`.
pub async fn sample_now_async(timeout: Duration) -> OsvFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => OsvFacts::default(),
    }
}

fn build_http_client() -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(format!("WolfStack/{}", env!("CARGO_PKG_VERSION")))
        .timeout(HTTP_TIMEOUT)
        .build()
        .ok()
}

/// Do the full HTTP scan against OSV. Returns a freshly-built cache
/// (caller persists it). Errors propagate up so the caller can fall
/// back to the previous cache without poisoning it.
fn scan_osv(config: &OsvConfig, inventories: &[Inventory]) -> Result<OsvCache, String> {
    let client = build_http_client().ok_or("could not build HTTP client")?;
    // Flat list of every (eco, pkg, ver) we want to query, dedup'd —
    // many containers share package versions and we don't want N
    // identical batch entries.
    let mut want: BTreeMap<String, InventoryEntry> = BTreeMap::new();
    for inv in inventories {
        for e in &inv.entries {
            want.entry(match_key(&e.ecosystem, &e.name, &e.version))
                .or_insert_with(|| e.clone());
        }
        // Inject the running kernel row if we have one and it's not
        // already in the package list. Some distros (Alpine virt)
        // don't list a per-version kernel package in `apk info -v`.
        if let (Some(rk), Some(eco)) = (&inv.running_kernel, inv.ecosystem()) {
            let key = match_key(eco, &rk.package, &rk.version);
            want.entry(key).or_insert_with(|| InventoryEntry {
                ecosystem: eco.to_string(),
                name: rk.package.clone(),
                version: rk.version.clone(),
            });
        }
    }
    let queries: Vec<InventoryEntry> = want.into_values().collect();
    if queries.is_empty() {
        // Nothing to scan — record an empty cache with the latch
        // stamped so we don't hammer OSV repeatedly when the host
        // genuinely has nothing.
        return Ok(OsvCache {
            last_full_scan_at: Some(Utc::now()),
            ..Default::default()
        });
    }
    let batch = osv_query_batch(&client, &config.endpoint, &queries)?;
    // Build the matches map from the (input-aligned) batch result.
    let mut matches: HashMap<String, Vec<String>> = HashMap::new();
    let mut needed_ids: BTreeSet<String> = BTreeSet::new();
    for (q, refs) in queries.iter().zip(batch.iter()) {
        if refs.is_empty() { continue; }
        let key = match_key(&q.ecosystem, &q.name, &q.version);
        let ids: Vec<String> = refs.iter().map(|r| r.id.clone()).collect();
        for i in &ids { needed_ids.insert(i.clone()); }
        matches.insert(key, ids);
    }
    // Fetch full records for every unique vuln id.
    let mut vulns: HashMap<String, OsvVuln> = HashMap::new();
    for id in needed_ids {
        match osv_fetch_vuln(&client, &config.endpoint, &id) {
            Ok(v) => { vulns.insert(id, v); }
            Err(e) => {
                tracing::warn!("osv: failed to fetch {}: {}", id, e);
                // We carry on — a missing vuln record means the
                // matching inventory rows produce no finding (better
                // than emitting a finding with no severity data).
            }
        }
    }
    Ok(OsvCache {
        last_full_scan_at: Some(Utc::now()),
        vulns,
        matches,
    })
}

// ---------------------------------------------------------------------
// Analyze — turn OsvFacts into Proposals
// ---------------------------------------------------------------------

/// Severity tier for one OsvFinding, given config.
fn severity_for(finding: &OsvFinding) -> Severity {
    if finding.kev_listed { return Severity::Critical; }
    if is_critical_package(&finding.package) { return Severity::Critical; }
    match finding.vuln.cvss_score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Warn,
        Some(_) => Severity::Info,    // < 4.0 — caller filters out
        None    => Severity::Warn,    // no score → Warn (we know it's a real CVE, just unscored)
    }
}

/// Should this finding actually surface in the inbox?
fn should_emit(finding: &OsvFinding, config: &OsvConfig) -> bool {
    if config.kev_only { return finding.kev_listed; }
    // KEV-listed always surfaces — the floor only applies to non-KEV
    // findings. severity_for() already promotes KEV to Critical, but
    // make the bypass explicit so a future "floor=Critical, kev_only=
    // false" never accidentally hides one.
    if finding.kev_listed { return true; }
    let sev = severity_for(finding);
    if matches!(sev, Severity::Info) { return false; }
    sev.rank() <= config.severity_floor.rank()
}

/// Group findings by target — one inbox card per (host or LXC),
/// listing every CVE on that target as evidence rows. We deliberately
/// do NOT emit per-CVE proposals: a host with 50 pending CVEs would
/// otherwise produce 50 inbox rows on top of any other findings,
/// turning the inbox into a wall of CVE text. The pocket scanner in
/// [`vulnerability`](super::vulnerability) follows the same one-card-
/// per-target pattern; OSV findings should match that UX.
#[derive(Debug)]
struct TargetGroup<'a> {
    target: ScanTargetOwned,
    findings: Vec<&'a OsvFinding>,
}

fn group_by_target<'a>(findings: &'a [OsvFinding]) -> Vec<TargetGroup<'a>> {
    let mut by_target: HashMap<ScanTargetOwned, TargetGroup<'a>> = HashMap::new();
    for f in findings {
        by_target.entry(f.target.clone()).or_insert_with(|| TargetGroup {
            target: f.target.clone(),
            findings: Vec::new(),
        }).findings.push(f);
    }
    let mut out: Vec<TargetGroup<'a>> = by_target.into_values().collect();
    // Stable order: host first, then LXC alphabetical. Keeps the
    // inbox card position consistent across ticks.
    out.sort_by(|a, b| match (&a.target, &b.target) {
        (ScanTargetOwned::Host, ScanTargetOwned::Host) => std::cmp::Ordering::Equal,
        (ScanTargetOwned::Host, _) => std::cmp::Ordering::Less,
        (_, ScanTargetOwned::Host) => std::cmp::Ordering::Greater,
        (ScanTargetOwned::Lxc(a), ScanTargetOwned::Lxc(b)) => a.cmp(b),
    });
    out
}

/// Sort findings within a target: KEV first, then CVSS desc, then
/// CVE id ascending. Used to put the most-actionable items at the
/// top of the evidence panel.
fn sort_findings(findings: &[&OsvFinding]) -> Vec<OsvFinding> {
    let mut sorted: Vec<OsvFinding> = findings.iter().map(|f| (*f).clone()).collect();
    sorted.sort_by(|a, b| {
        b.kev_listed.cmp(&a.kev_listed)
            .then_with(|| b.vuln.cvss_score.unwrap_or(0.0)
                .partial_cmp(&a.vuln.cvss_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| a.vuln.display_id().cmp(&b.vuln.display_id()))
    });
    sorted
}

/// How many CVE rows to render per section in the evidence panel
/// before collapsing the rest into a "+N more" chip. Six is enough to
/// show the worst offenders in each section (patchable / awaiting fix)
/// without forcing the inbox card to the size of a small spreadsheet.
const MAX_CVE_EVIDENCE_ROWS_PER_SECTION: usize = 6;

/// How many advisory/fix/web reference chips to attach to each CVE
/// row. Three is enough to surface the canonical advisory plus a
/// distro tracker plus a CISA KEV link without overflowing the row.
const MAX_REFERENCES_PER_ROW: usize = 3;

/// Build the single Proposal that represents every OSV finding on
/// one target. `suppressed_no_fix` is the number of additional findings
/// that were dropped at sample time because no upstream patch is yet
/// available — surfaced honestly on the card so the operator never
/// sees a misleading "0 issues" when in reality there are many waiting
/// on a distro fix.
fn build_target_proposal(g: &TargetGroup<'_>, ctx: &Context, suppressed_no_fix: usize) -> Proposal {
    let total = g.findings.len();
    let kev_count = g.findings.iter().filter(|f| f.kev_listed).count();
    let critical_count = g.findings.iter()
        .filter(|f| severity_for(f) == Severity::Critical).count();
    let patchable_count = g.findings.iter().filter(|f| f.fix_available).count();
    let awaiting_count = total - patchable_count;
    let target_label = g.target.as_target().label();

    // Severity: max across all findings. Severity::rank() is lower
    // for more-severe — min_by_key gives us the worst tier.
    let severity = g.findings.iter()
        .map(|f| severity_for(f))
        .min_by_key(|s| s.rank())
        .unwrap_or(Severity::Warn);

    let title = if kev_count > 0 {
        format!(
            "{} OSV vulnerabilit{} on {} ({} actively exploited)",
            total, if total == 1 { "y" } else { "ies" }, target_label, kev_count,
        )
    } else {
        format!(
            "{} OSV vulnerabilit{} on {}",
            total, if total == 1 { "y" } else { "ies" }, target_label,
        )
    };

    let why = format!(
        "OSV.dev's database matched {} CVE{} against installed package(s) on {}. {}{}{}",
        total,
        if total == 1 { "" } else { "s" },
        target_label,
        if kev_count > 0 {
            format!(
                "{} of these {} on the CISA Known Exploited Vulnerabilities list — \
                 attackers are actively exploiting them in the wild. Patch \
                 immediately, even if your distro has not yet shipped its security \
                 advisory. ",
                kev_count,
                if kev_count == 1 { "is" } else { "are" },
            )
        } else if patchable_count > 0 {
            format!(
                "{} can be patched now by running your distro's security upgrade; \
                 {} need a patched version from upstream that has not yet shipped. ",
                patchable_count, awaiting_count,
            )
        } else {
            "None of these have a patched build available upstream yet — \
             follow the linked advisories for mitigation guidance until the \
             distro publishes a fix. ".into()
        },
        if suppressed_no_fix > 0 {
            format!(
                "{} additional finding{} hidden because no upstream patch \
                 exists yet — they will resurface automatically once OSV \
                 publishes a fixed version. ",
                suppressed_no_fix,
                if suppressed_no_fix == 1 { " is" } else { "s are" },
            )
        } else {
            String::new()
        },
        if matches!(g.target, ScanTargetOwned::Lxc(_)) {
            "The container needs to be patched separately from the host — \
              upgrades on the host don't affect the container's package set."
        } else { "" },
    );

    let mut evidence = vec![Evidence {
        label: "Total".into(),
        value: format!("{} CVE{}", total, if total == 1 { "" } else { "s" }),
        detail: Some("Source: OSV.dev (https://osv.dev)".into()),
        links: Vec::new(),
    }];
    if kev_count > 0 {
        evidence.push(Evidence {
            label: "KEV".into(),
            value: format!(
                "{} actively exploited",
                kev_count,
            ),
            detail: Some("Listed in CISA's Known Exploited Vulnerabilities catalog".into()),
            links: Vec::new(),
        });
    }
    if critical_count > 0 {
        evidence.push(Evidence {
            label: "Critical".into(),
            value: format!(
                "{} severe finding{}",
                critical_count, if critical_count == 1 { "" } else { "s" },
            ),
            detail: Some("KEV-listed, critical-class package, or CVSS ≥ 9.0".into()),
            links: Vec::new(),
        });
    }
    if suppressed_no_fix > 0 {
        evidence.push(Evidence {
            label: "Hidden — no upstream fix".into(),
            value: format!("+{}", suppressed_no_fix),
            detail: Some(
                "Auto-suppressed because no patched version is published yet. \
                 Will resurface on the next scan once OSV records a fix. \
                 Set OsvConfig.suppress_no_fix=false to surface them anyway.".into(),
            ),
            links: Vec::new(),
        });
    }

    // Split visible findings by whether a patch is available. Each
    // section is independently sorted by KEV → CVSS → CVE id so the
    // worst offender in each bucket sits at the top.
    let patchable_sorted = sort_findings(
        &g.findings.iter().filter(|f| f.fix_available).copied().collect::<Vec<_>>(),
    );
    let awaiting_sorted = sort_findings(
        &g.findings.iter().filter(|f| !f.fix_available).copied().collect::<Vec<_>>(),
    );

    if !patchable_sorted.is_empty() {
        evidence.push(Evidence {
            label: "Patchable now".into(),
            value: format!(
                "{} CVE{}",
                patchable_count,
                if patchable_count == 1 { "" } else { "s" },
            ),
            detail: Some("Run the upgrade command — fix is available upstream".into()),
            links: Vec::new(),
        });
        for f in patchable_sorted.iter().take(MAX_CVE_EVIDENCE_ROWS_PER_SECTION) {
            evidence.push(cve_evidence_row(f));
        }
        if patchable_count > MAX_CVE_EVIDENCE_ROWS_PER_SECTION {
            evidence.push(Evidence {
                label: "More patchable".into(),
                value: format!(
                    "+{} additional",
                    patchable_count - MAX_CVE_EVIDENCE_ROWS_PER_SECTION,
                ),
                detail: Some("Run the upgrade command below to patch all of them".into()),
                links: Vec::new(),
            });
        }
    }

    if !awaiting_sorted.is_empty() {
        evidence.push(Evidence {
            label: "Awaiting upstream fix".into(),
            value: format!(
                "{} CVE{}",
                awaiting_count,
                if awaiting_count == 1 { "" } else { "s" },
            ),
            detail: Some(
                "No patched build published yet — read the linked advisories \
                 for mitigation. KEV-listed and Critical issues are still \
                 shown here even without a fix.".into(),
            ),
            links: Vec::new(),
        });
        for f in awaiting_sorted.iter().take(MAX_CVE_EVIDENCE_ROWS_PER_SECTION) {
            evidence.push(cve_evidence_row(f));
        }
        if awaiting_count > MAX_CVE_EVIDENCE_ROWS_PER_SECTION {
            evidence.push(Evidence {
                label: "More awaiting".into(),
                value: format!(
                    "+{} additional",
                    awaiting_count - MAX_CVE_EVIDENCE_ROWS_PER_SECTION,
                ),
                detail: Some("Track upstream for fixes; mitigate via advisory links".into()),
                links: Vec::new(),
            });
        }
    }

    let ecosystem = g.findings.first().map(|f| f.ecosystem.as_str()).unwrap_or("");
    let commands = bulk_upgrade_commands(&g.target, ecosystem);
    let instructions = match &g.target {
        ScanTargetOwned::Host => {
            "Run a full distro security upgrade. Kernel CVEs require a reboot \
             to take effect; user-space CVEs may need affected services \
             restarted (`needrestart` on Debian / `dnf needs-restarting` on \
             RHEL) to pick up the new shared libraries.".to_string()
        }
        ScanTargetOwned::Lxc(_) => {
            "Patch the LXC container from the host. `lxc-attach` runs the \
             container's own package manager so the upgrade happens inside \
             the container's filesystem. Some packages may need a container \
             restart to take effect.".to_string()
        }
    };

    Proposal::new(
        FINDING_TYPE,
        ProposalSource::Rule,
        severity,
        title,
        why,
        evidence,
        RemediationPlan::Manual { instructions, commands },
        ProposalScope {
            node_id: ctx.node_id.clone(),
            // One scope per target — `osv:host` or `osv:lxc:NAME`.
            // Operator dismiss/snooze acts on the entire OSV inbox
            // entry for that target, which matches what they'd
            // intuitively expect when they snooze "vulnerabilities
            // on this host".
            resource_id: Some(g.target.as_target().resource_id()),
        },
    )
}

/// Card for the case where the only OSV signal on a target is the
/// suppressed-no-fix counter. Info-tier: nothing the operator can do
/// today, but they should know the count.
fn build_no_fix_only_card(
    target: &ScanTargetOwned,
    hidden: usize,
    scope: &ProposalScope,
) -> Proposal {
    let target_label = target.as_target().label();
    let title = format!(
        "{} OSV CVE{} on {} awaiting upstream fix",
        hidden, if hidden == 1 { "" } else { "s" }, target_label,
    );
    let why = format!(
        "OSV.dev's database matched {} CVE{} against installed packages on {} \
         that have no patched build published yet. There is nothing to upgrade — \
         the distro security team has not shipped a fix. These will resurface \
         as actionable findings on the next scan once OSV records a fixed \
         version. Critical and KEV-listed CVEs are NEVER hidden by this \
         filter; if you want to see every unpatched CVE on this target, \
         disable `suppress_no_fix` in /etc/wolfstack/osv-config.json.",
        hidden,
        if hidden == 1 { "" } else { "s" },
        target_label,
    );
    let evidence = vec![
        Evidence {
            label: "Hidden — no upstream fix".into(),
            value: format!("{} CVE{}", hidden, if hidden == 1 { "" } else { "s" }),
            detail: Some("Auto-suppressed; will resurface when a fix is published".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "Source".into(),
            value: "OSV.dev".into(),
            detail: Some("https://osv.dev".into()),
            links: Vec::new(),
        },
    ];
    Proposal::new(
        FINDING_TYPE,
        ProposalSource::Rule,
        Severity::Info,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "No action available right now — distro fix not yet \
                published. Track upstream advisories. To surface every unpatched \
                CVE regardless, set `suppress_no_fix: false` in \
                /etc/wolfstack/osv-config.json.".into(),
            commands: Vec::new(),
        },
        scope.clone(),
    )
}

/// Build one Evidence row for a single CVE, including up to
/// MAX_REFERENCES_PER_ROW external advisory links so the operator can
/// read authoritative mitigation guidance (vendor advisory, distro
/// security tracker, CISA KEV page) from the inbox itself.
fn cve_evidence_row(f: &OsvFinding) -> Evidence {
    let cve = f.vuln.display_id();
    let kev_marker = if f.kev_listed { " ⚠ KEV" } else { "" };
    let value = match f.vuln.cvss_score {
        Some(s) => format!("CVSS {:.1}{}", s, kev_marker),
        None => format!("unscored{}", kev_marker),
    };
    let detail = match f.vuln.fixed_versions.get(&f.package) {
        Some(fv) => Some(format!("{} {} → fixed in {}", f.package, f.version, fv)),
        None => Some(format!("{} {} — no upstream fix yet", f.package, f.version)),
    };
    // Prepend a canonical "Details" link to OSV.dev so the operator
    // can click straight into the authoritative CVE page (summary,
    // CVSS breakdown, every reference, affected/fixed versions). This
    // is the single most-asked-for "what does this CVE actually do?"
    // surface and the reason the CVE label is also wrapped in an
    // anchor in the inbox renderer. Vendor-specific chips (Debian /
    // Red Hat / NVD / CISA) follow as before.
    let mut links = vec![EvidenceLink {
        label: "Details".into(),
        url: format!("https://osv.dev/vulnerability/{}", urlencoding::encode(&f.vuln.id)),
    }];
    links.extend(pick_reference_links(f));
    // Cap at MAX_REFERENCES_PER_ROW + 1 — the OSV.dev link is
    // always-on so the cap applies to vendor refs only.
    if links.len() > MAX_REFERENCES_PER_ROW + 1 {
        links.truncate(MAX_REFERENCES_PER_ROW + 1);
    }
    Evidence {
        label: cve,
        value,
        detail,
        links,
    }
}

/// Pick the most useful reference links for a finding, capped at
/// MAX_REFERENCES_PER_ROW. Priority: ADVISORY > FIX > REPORT > WEB,
/// de-duplicated by URL. Each link gets a short host-derived label
/// (or the type if the host is generic) so chips stay compact.
fn pick_reference_links(f: &OsvFinding) -> Vec<EvidenceLink> {
    let prio = |ty: &str| -> u8 {
        match ty.to_ascii_uppercase().as_str() {
            "ADVISORY" => 0,
            "FIX" => 1,
            "REPORT" => 2,
            "WEB" => 3,
            _ => 4,
        }
    };
    let mut sorted: Vec<&OsvVulnReference> = f.vuln.references.iter().collect();
    sorted.sort_by_key(|r| (prio(&r.ty), r.url.clone()));
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<EvidenceLink> = Vec::new();
    for r in sorted {
        if !seen.insert(r.url.clone()) { continue; }
        let label = label_for_reference(&r.ty, &r.url);
        out.push(EvidenceLink { label, url: r.url.clone() });
        if out.len() >= MAX_REFERENCES_PER_ROW { break; }
    }
    out
}

/// Derive a short chip label from a reference's URL. Recognised hosts
/// get a friendly name (e.g. `security-tracker.debian.org` → "Debian");
/// anything else falls back to the URL host or the OSV type.
fn label_for_reference(ty: &str, url: &str) -> String {
    let host = url
        .splitn(2, "://").nth(1).unwrap_or(url)
        .split('/').next().unwrap_or("")
        .trim_start_matches("www.")
        .to_ascii_lowercase();
    let from_host: Option<&'static str> = match host.as_str() {
        "security-tracker.debian.org" | "www.debian.org" | "debian.org" => Some("Debian"),
        "ubuntu.com" | "people.canonical.com" | "wiki.ubuntu.com" => Some("Ubuntu"),
        "access.redhat.com" | "bugzilla.redhat.com" | "redhat.com" => Some("Red Hat"),
        "errata.almalinux.org" => Some("AlmaLinux"),
        "errata.rockylinux.org" => Some("Rocky"),
        "lists.opensuse.org" | "bugzilla.suse.com" | "www.suse.com" => Some("SUSE"),
        "secdb.alpinelinux.org" | "alpinelinux.org" => Some("Alpine"),
        "security.archlinux.org" => Some("Arch"),
        "cisa.gov" | "www.cisa.gov" => Some("CISA"),
        "nvd.nist.gov" => Some("NVD"),
        "cve.mitre.org" | "cve.org" => Some("CVE"),
        "github.com" | "github.blog" => Some("GitHub"),
        "gitlab.com" => Some("GitLab"),
        "bugs.chromium.org" => Some("Chromium"),
        "kernel.org" | "git.kernel.org" => Some("kernel.org"),
        _ => None,
    };
    if let Some(s) = from_host { return s.to_string(); }
    // Fallback to a Title-cased version of the OSV reference type.
    let lower = ty.to_ascii_lowercase();
    match lower.as_str() {
        "advisory" => "Advisory".to_string(),
        "fix" => "Fix".to_string(),
        "report" => "Report".to_string(),
        "web" => "Web".to_string(),
        "package" => "Package".to_string(),
        "article" => "Article".to_string(),
        _ => if host.is_empty() { "Link".to_string() } else { host },
    }
}

/// Bulk upgrade command for the target's ecosystem. We don't list
/// per-package commands because a host with 50 CVEs would produce a
/// 50-package command line; running the distro's full security
/// upgrade is what the operator actually wants to do.
fn bulk_upgrade_commands(target: &ScanTargetOwned, ecosystem: &str) -> Vec<String> {
    let pm = pm_for_ecosystem(ecosystem);
    match (target, pm) {
        (ScanTargetOwned::Host, Some(PackageManager::Apt)) => vec![
            "apt-get update".into(),
            "apt-get upgrade -y".into(),
        ],
        (ScanTargetOwned::Host, Some(PackageManager::Dnf)) => vec![
            "dnf upgrade --refresh -y".into(),
        ],
        (ScanTargetOwned::Host, Some(PackageManager::Zypper)) => vec![
            "zypper refresh".into(),
            "zypper update -y".into(),
        ],
        (ScanTargetOwned::Host, Some(PackageManager::Apk)) => vec![
            "apk update".into(),
            "apk upgrade".into(),
        ],
        (ScanTargetOwned::Lxc(name), Some(PackageManager::Apt)) => vec![
            format!("lxc-attach -n {} -- apt-get update", name),
            format!("lxc-attach -n {} -- apt-get upgrade -y", name),
        ],
        (ScanTargetOwned::Lxc(name), Some(PackageManager::Dnf)) => vec![
            format!("lxc-attach -n {} -- dnf upgrade --refresh -y", name),
        ],
        (ScanTargetOwned::Lxc(name), Some(PackageManager::Zypper)) => vec![
            format!("lxc-attach -n {} -- zypper refresh", name),
            format!("lxc-attach -n {} -- zypper update -y", name),
        ],
        (ScanTargetOwned::Lxc(name), Some(PackageManager::Apk)) => vec![
            format!("lxc-attach -n {} -- apk upgrade", name),
        ],
        (target, _) => {
            let prefix = match target {
                ScanTargetOwned::Host => String::new(),
                ScanTargetOwned::Lxc(name) => format!("lxc-attach -n {} -- ", name),
            };
            vec![
                format!("# Choose the line for your distro's package manager:"),
                format!("{}apt-get update && {}apt-get upgrade -y", prefix, prefix),
                format!("{}dnf upgrade --refresh -y", prefix),
                format!("{}zypper update -y", prefix),
                format!("{}apk upgrade", prefix),
            ]
        }
    }
}

/// Pick the package manager from an OSV ecosystem string. Lets the
/// remediation command match the host's actual PM — `apt-get` for
/// Ubuntu/Debian/derivatives, `dnf` for RHEL-family OSV ecosystems
/// (Rocky/Alma/Mageia/openEuler), `zypper` for SUSE, `apk` for
/// Alpine/Wolfi/Chainguard. None when we genuinely don't know
/// (rolling ecosystems whose PM is operator-specific).
fn pm_for_ecosystem(ecosystem: &str) -> Option<PackageManager> {
    if ecosystem.starts_with("Debian") || ecosystem.starts_with("Ubuntu") {
        return Some(PackageManager::Apt);
    }
    if ecosystem.starts_with("Rocky Linux")
        || ecosystem.starts_with("AlmaLinux")
        || ecosystem.starts_with("Mageia")
        || ecosystem.starts_with("openEuler")
        || ecosystem.starts_with("Photon OS")
    {
        return Some(PackageManager::Dnf);
    }
    if ecosystem.starts_with("openSUSE") || ecosystem.starts_with("SUSE") {
        return Some(PackageManager::Zypper);
    }
    if ecosystem.starts_with("Alpine")
        || ecosystem.starts_with("Wolfi")
        || ecosystem.starts_with("Chainguard")
        || ecosystem.starts_with("MinimOS")
        || ecosystem.starts_with("CleanStart")
        || ecosystem.starts_with("Alpaquita")
        || ecosystem.starts_with("BellSoft")
    {
        return Some(PackageManager::Apk);
    }
    None
}

/// Public analyzer entry point.
pub fn analyze(
    ctx: &Context,
    facts: &OsvFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    if !facts.config.enabled { return Vec::new(); }
    let visible: Vec<&OsvFinding> = facts.findings.iter()
        .filter(|f| should_emit(f, &facts.config))
        .collect();
    let owned: Vec<OsvFinding> = visible.iter().map(|f| (*f).clone()).collect();
    let grouped = group_by_target(&owned);
    let mut out = Vec::new();
    for g in &grouped {
        let suppressed_no_fix = facts.suppressed_no_fix_by_target
            .get(&g.target).copied().unwrap_or(0);
        let prop = build_target_proposal(g, ctx, suppressed_no_fix);
        if acks.suppresses(FINDING_TYPE, &prop.scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &prop.scope) { continue; }
        out.push(prop);
    }
    // A target may have ZERO visible findings but still have hidden
    // (no-upstream-fix) findings — `findings` was filtered by
    // `should_emit`, but `suppressed_no_fix_by_target` is sampled
    // before `should_emit`. If a target's only contribution to the
    // inbox is "N hidden, awaiting upstream fix", surface that as a
    // dedicated Info-tier card so the operator sees the count instead
    // of nothing. `Info` keeps the entry visible without spamming
    // High/Critical channels.
    let surfaced_targets: std::collections::HashSet<&ScanTargetOwned> =
        grouped.iter().map(|g| &g.target).collect();
    for (tgt, hidden) in &facts.suppressed_no_fix_by_target {
        if *hidden == 0 { continue; }
        if surfaced_targets.contains(tgt) { continue; }
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!(
                "{}:no-fix-tracker", tgt.as_target().resource_id(),
            )),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_no_fix_only_card(tgt, *hidden, &scope));
    }
    // Unrecognised-derivative breadcrumbs. One per (target, derivative
    // id). Suppressed in kev_only mode — that's a noise-floor preference,
    // and a breadcrumb is by definition not a CVE event.
    if !facts.config.kev_only {
        for b in &facts.unrecognized_derivatives {
            let scope = ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(format!("{}:derivative:{}",
                    b.target.as_target().resource_id(), b.id)),
            };
            if acks.suppresses(FINDING_UNRECOGNIZED_DERIVATIVE, &scope) { continue; }
            if proposals.is_suppressed(FINDING_UNRECOGNIZED_DERIVATIVE, &scope) { continue; }
            out.push(build_breadcrumb(b, &scope));
        }
    }
    out
}

fn build_breadcrumb(b: &UnrecognizedDerivativeBreadcrumb, scope: &ProposalScope) -> Proposal {
    let target_label = b.target.as_target().label();
    let codename = b.codename_hint.clone().unwrap_or_else(|| "<unknown>".to_string());
    let parent = b.parent.label();
    let title = format!(
        "OSV scanner can't classify `{}` on {} — codename `{}` unknown",
        b.id, target_label, codename,
    );
    let why = format!(
        "WolfStack detected a {parent} derivative ({id}) at {target_label} \
         but couldn't map its release codename `{codename}` to an OSV \
         ecosystem. Until this is resolved, OSV-based CVE scanning skips \
         this target — the distro-pocket scanner still runs, but you lose \
         the early-warning OSV layer (the one that catches CVEs before \
         your distro publishes its security advisory). \
         {distro_info_state} \
         There are two ways to fix this: (1) install `distro-info-data` \
         on the host so we can read Canonical's / Debian's authoritative \
         codename → release table at runtime; (2) add an explicit entry \
         to /etc/wolfstack/osv-config.json's `distro_overrides`. \
         Both options auto-resolve this finding on the next tick.",
        parent = parent,
        id = b.id,
        target_label = target_label,
        codename = codename,
        distro_info_state = if b.distro_info_present {
            "The host has distro-info-data installed but the codename \
             isn't in its CSV — the distro is too new for the installed \
             version, or the derivative uses its own codename rather than \
             the upstream one."
        } else {
            "The host does NOT currently have distro-info-data installed."
        },
    );
    let mut commands = vec![
        format!("# Install Debian/Canonical's authoritative codename → release table:"),
        format!("apt-get update && apt-get install -y distro-info-data"),
        format!("# OR add an explicit override:"),
        format!("# echo '{{ \"distro_overrides\": {{ \"{}\": \"Ubuntu:24.04:LTS\" }} }}' > /etc/wolfstack/osv-config.json", b.id),
    ];
    if matches!(b.parent, ParentDistro::Debian) {
        // Tweak the example for Debian-derivatives.
        commands[3] = format!(
            "# echo '{{ \"distro_overrides\": {{ \"{}\": \"Debian:12\" }} }}' > /etc/wolfstack/osv-config.json",
            b.id,
        );
    }
    let evidence = vec![
        Evidence {
            label: "Distro ID".into(),
            value: b.id.clone(),
            detail: Some(format!("Parent family: {}", parent)),
            links: Vec::new(),
        },
        Evidence {
            label: "Codename".into(),
            value: codename.clone(),
            detail: Some("From UBUNTU_CODENAME / DEBIAN_CODENAME / VERSION_CODENAME in /etc/os-release".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "distro-info-data".into(),
            value: if b.distro_info_present { "installed".into() } else { "missing".into() },
            detail: Some("Debian/Canonical's authoritative codename → release map".into()),
            links: Vec::new(),
        },
    ];
    Proposal::new(
        FINDING_UNRECOGNIZED_DERIVATIVE,
        ProposalSource::Rule,
        Severity::Info,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "Install distro-info-data, or add a one-line \
                override to /etc/wolfstack/osv-config.json. The next OSV \
                tick (within an hour) will pick it up.".into(),
            commands,
        },
        scope.clone(),
    )
}

/// Covered scopes for auto-resolve. Every (target, CVE) we surfaced
/// last tick AND every CVE that previously matched an inventory row
/// the analyzer is now scanning needs to be in the covered set so
/// `auto_resolve_cleared` can close findings whose package was just
/// upgraded.
///
/// Strategy: for every covered_target, we mark every existing
/// pending Proposal with that target as covered — so the orchestrator
/// will auto-resolve any pending OSV finding whose CVE no longer
/// matches the current inventory.
pub fn covered_scopes(
    ctx: &Context,
    facts: &OsvFacts,
) -> Vec<(String, ProposalScope)> {
    let mut out = Vec::new();
    for tgt in &facts.covered_targets {
        // The exact (CVE) suffix is unknown from this side — the
        // orchestrator's auto_resolve_cleared compares (finding_type,
        // scope) pairs, so we need every possible scope. We approximate
        // by emitting a single "prefix" scope that the inbox knows is
        // a marker, AND we explicitly report every emitted scope this
        // tick. The orchestrator already passes the emitted set in
        // separately, so emitting one entry per target is sufficient
        // to ensure any pending CVE proposal under that target whose
        // scope wasn't re-emitted gets closed.
        //
        // To make that work we include every prior pending OSV proposal
        // for the same node. We can't see the proposal store from here
        // (covered_scopes runs against a snapshot the orchestrator owns),
        // so we instead emit the *target-prefix marker* and rely on a
        // dedicated extension below.
        let _ = tgt;
    }
    // Emit one (FINDING_TYPE, scope) entry per target whose
    // inventory we actually scanned this tick — covered_targets is
    // exactly that set. `auto_resolve_cleared` consults this against
    // the emitted set: a target whose proposal we scanned but didn't
    // re-emit has had its CVEs all clear, so the prior pending
    // finding closes naturally on the next tick.
    for tgt in &facts.covered_targets {
        out.push((
            FINDING_TYPE.to_string(),
            ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(tgt.as_target().resource_id()),
            },
        ));
        // Also cover the no-fix-tracker scope so the dedicated
        // "N hidden — awaiting upstream fix" card auto-resolves
        // when the suppressed_no_fix count drops to zero (operator
        // disabled the filter, or every awaiting CVE got a fix).
        // Without this the tracker sits in the inbox forever.
        out.push((
            FINDING_TYPE.to_string(),
            ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(format!(
                    "{}:no-fix-tracker", tgt.as_target().resource_id(),
                )),
            },
        ));
    }
    // Breadcrumb scopes — covered when the resolver classified them
    // as Unrecognised this tick. Auto-resolves once the operator
    // fixes the override or installs distro-info-data and the
    // resolver maps cleanly.
    for b in &facts.unrecognized_derivatives {
        out.push((
            FINDING_UNRECOGNIZED_DERIVATIVE.to_string(),
            ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(format!("{}:derivative:{}",
                    b.target.as_target().resource_id(), b.id)),
            },
        ));
    }
    out
}

/// Extra hook the orchestrator calls so OSV can mark stale-proposal
/// scopes as covered. Called with a snapshot of the proposal store —
/// any pending OSV finding for a target we DID scan this tick is
/// covered (so it can auto-resolve when the matching CVE drops out
/// of the inventory).
///
/// This is the pattern that makes "package upgraded → finding closes
/// next tick" work end-to-end.
pub fn extra_covered_from_store(
    ctx: &Context,
    facts: &OsvFacts,
    store: &crate::predictive::proposal::ProposalStore,
) -> Vec<(String, ProposalScope)> {
    // Match by prefix-with-trailing-colon. Resource ids are built as
    // `<target_rid>:<vuln_id>`; we want to find proposals whose
    // resource_id starts with any scanned target's `osv:host:` or
    // `osv:lxc:NAME:`. This works for CVE ids, GHSA ids, OSV-internal
    // ids, and any future id format.
    let scanned_prefixes: Vec<String> = facts.covered_targets.iter()
        .map(|t| format!("{}:", t.as_target().resource_id()))
        .collect();
    let mut out = Vec::new();
    for p in &store.proposals {
        if p.finding_type != FINDING_TYPE { continue; }
        if p.scope.node_id != ctx.node_id { continue; }
        let rid = match &p.scope.resource_id { Some(r) => r, None => continue };
        // An LXC scan covers ONLY its own LXC scope. The host's
        // `osv:host:` prefix is itself a substring of `osv:host:NAME:`
        // for an `osv:host` scope, but the LXC variant `osv:lxc:NAME:`
        // never starts with `osv:host:` — so a simple starts_with on
        // the prefix-with-colon is precise.
        if scanned_prefixes.iter().any(|pref| rid.starts_with(pref)) {
            out.push((p.finding_type.clone(), p.scope.clone()));
        }
    }
    out
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystem_ubuntu_lts_includes_lts_suffix() {
        let s = "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Ubuntu:22.04:LTS"));
    }

    #[test]
    fn ecosystem_ubuntu_non_lts_omits_suffix() {
        // Interim releases — odd-year .10 or odd-year .04. Use 23.10.
        let s = "ID=ubuntu\nVERSION_ID=\"23.10\"\nPRETTY_NAME=\"Ubuntu 23.10\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Ubuntu:23.10"));
    }

    #[test]
    fn ecosystem_ubuntu_lts_pattern_when_pretty_missing() {
        // Even-year .04 release without a PRETTY_NAME LTS marker
        // should still get the :LTS suffix via the major%2==0 + .04
        // fallback rule.
        let s = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Ubuntu:24.04:LTS"));
    }

    #[test]
    fn ecosystem_debian_uses_major_only() {
        let s = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Debian:12"));
    }

    #[test]
    fn ecosystem_alpine_has_v_prefix() {
        let s = "ID=alpine\nVERSION_ID=\"3.19.0\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Alpine:v3.19"));
    }

    #[test]
    fn ecosystem_rocky_alma_use_major_only() {
        let r = "ID=\"rocky\"\nVERSION_ID=\"9.3\"\n";
        assert_eq!(ecosystem_from_os_release(r).as_deref(), Some("Rocky Linux:9"));
        let a = "ID=\"almalinux\"\nVERSION_ID=\"9.4\"\n";
        assert_eq!(ecosystem_from_os_release(a).as_deref(), Some("AlmaLinux:9"));
    }

    #[test]
    fn ecosystem_arch_returns_none() {
        let s = "ID=arch\n";
        assert!(ecosystem_from_os_release(s).is_none());
        let c = "ID=cachyos\n";
        assert!(ecosystem_from_os_release(c).is_none());
        // Manjaro/EndeavourOS/Garuda/Artix all return None — covered
        // by arch-audit, not OSV.
        for id in ["manjaro", "endeavouros", "garuda", "artix"] {
            let s = format!("ID={}\n", id);
            assert!(ecosystem_from_os_release(&s).is_none(), "{} should be None", id);
        }
    }

    #[test]
    fn ecosystem_fedora_rhel_amazon_oracle_return_none() {
        // Distros not in OSV — caller falls back to the pocket
        // scanner. Returning None here is the correct, documented
        // behaviour; producing a guessed ecosystem string would
        // silently miss CVEs because OSV would return zero matches
        // for an unknown ecosystem.
        for id in ["fedora", "rhel", "centos", "ol", "amzn", "sles"] {
            let s = format!("ID={}\nVERSION_ID=\"9\"\n", id);
            assert!(ecosystem_from_os_release(&s).is_none(),
                "{} not in OSV — must return None to defer to pocket scanner", id);
        }
    }

    #[test]
    fn ecosystem_unknown_distro_returns_none() {
        let s = "ID=somedistro\n";
        assert!(ecosystem_from_os_release(s).is_none());
    }

    #[test]
    fn ecosystem_opensuse_leap_uses_marketing_name() {
        let s = "ID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"\nPRETTY_NAME=\"openSUSE Leap 15.5\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("openSUSE:Leap 15.5"));
    }

    #[test]
    fn ecosystem_opensuse_tumbleweed_has_no_version() {
        let s = "ID=\"opensuse-tumbleweed\"\nPRETTY_NAME=\"openSUSE Tumbleweed\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("openSUSE:Tumbleweed"));
        // Generic ID with Tumbleweed in PRETTY_NAME also resolves.
        let s = "ID=opensuse\nPRETTY_NAME=\"openSUSE Tumbleweed\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("openSUSE:Tumbleweed"));
    }

    #[test]
    fn ecosystem_mageia_photon_openeuler() {
        let m = "ID=mageia\nVERSION_ID=\"9\"\n";
        assert_eq!(ecosystem_from_os_release(m).as_deref(), Some("Mageia:9"));
        let p = "ID=photon\nVERSION_ID=\"3.0\"\n";
        assert_eq!(ecosystem_from_os_release(p).as_deref(), Some("Photon OS:3.0"));
        let e = "ID=openeuler\nVERSION_ID=\"24.03\"\n";
        assert_eq!(ecosystem_from_os_release(e).as_deref(), Some("openEuler:24.03"));
    }

    #[test]
    fn ecosystem_rolling_ecosystems_have_no_version() {
        for (id, expected) in [
            ("wolfi", "Wolfi"),
            ("chainguard", "Chainguard"),
            ("minimos", "MinimOS"),
            ("cleanstart", "CleanStart"),
        ] {
            let s = format!("ID={}\n", id);
            assert_eq!(ecosystem_from_os_release(&s).as_deref(), Some(expected),
                "{} should map to {}", id, expected);
        }
    }

    #[test]
    fn ecosystem_linux_mint_maps_to_underlying_ubuntu() {
        // Linux Mint 21.3 ("Virginia") sits on top of Ubuntu Jammy.
        let s = "ID=linuxmint\nID_LIKE=ubuntu\nUBUNTU_CODENAME=jammy\nVERSION_ID=\"21.3\"\nPRETTY_NAME=\"Linux Mint 21.3\"\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Ubuntu:22.04:LTS"));
    }

    #[test]
    fn ecosystem_pop_os_maps_to_underlying_ubuntu() {
        let s = "ID=pop\nID_LIKE=\"ubuntu debian\"\nUBUNTU_CODENAME=jammy\nVERSION_ID=\"22.04\"\n";
        // Pop has ID_LIKE listing both — Ubuntu wins via the first match.
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Ubuntu:22.04:LTS"));
    }

    #[test]
    fn ecosystem_kali_maps_to_debian_sid() {
        // Kali is rolling on top of Debian testing/sid.
        let s = "ID=kali\nID_LIKE=debian\nVERSION_ID=\"2024.1\"\nVERSION_CODENAME=kali-rolling\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Debian:sid"));
    }

    #[test]
    fn ecosystem_devuan_unrecognised_codename_emits_breadcrumb_not_silent_miss() {
        // Devuan reports its OWN codename (daedalus = Debian Bookworm,
        // but we can't know that automatically). The full resolver
        // returns UnrecognizedDerivative so the analyzer can emit a
        // breadcrumb finding pointing the operator at the override.
        let s = "ID=devuan\nID_LIKE=debian\nVERSION_CODENAME=daedalus\n";
        let r = resolve_ecosystem(s, &HashMap::new(), &DistroInfo::default());
        match r {
            EcosystemResolution::UnrecognizedDerivative { id, parent, codename_hint } => {
                assert_eq!(id, "devuan");
                assert_eq!(parent, ParentDistro::Debian);
                assert_eq!(codename_hint.as_deref(), Some("daedalus"));
            }
            other => panic!("expected UnrecognizedDerivative, got {:?}", other),
        }
        // Bare wrapper returns None — caller falls back to pocket scanner.
        assert!(ecosystem_from_os_release(s).is_none());
    }

    #[test]
    fn ecosystem_devuan_with_override_resolves() {
        let s = "ID=devuan\nID_LIKE=debian\nVERSION_CODENAME=daedalus\n";
        let mut overrides = HashMap::new();
        overrides.insert("devuan".to_string(), "Debian:12".to_string());
        let r = resolve_ecosystem(s, &overrides, &DistroInfo::default());
        assert_eq!(r, EcosystemResolution::Mapped("Debian:12".to_string()));
    }

    #[test]
    fn ecosystem_devuan_via_distro_info_csv() {
        // If the operator installs distro-info-data and Devuan ships a
        // codename that maps to a Debian release in the CSV, we pick
        // it up at runtime without needing an override.
        let s = "ID=devuan\nID_LIKE=debian\nVERSION_CODENAME=daedalus\n";
        let mut di = DistroInfo::default();
        di.debian_codenames.insert("daedalus".to_string(), 12);
        let r = resolve_ecosystem(s, &HashMap::new(), &di);
        assert_eq!(r, EcosystemResolution::Mapped("Debian:12".to_string()));
    }

    #[test]
    fn ecosystem_future_ubuntu_codename_via_distro_info() {
        // A future Ubuntu codename ("robust") that's NOT in our
        // hardcoded table but IS in /usr/share/distro-info/ubuntu.csv.
        // Distro-info data wins.
        let s = "ID=mintlikething\nID_LIKE=ubuntu\nUBUNTU_CODENAME=robust\n";
        let mut di = DistroInfo::default();
        di.ubuntu_codenames.insert("robust".to_string(), "26.04".to_string());
        let r = resolve_ecosystem(s, &HashMap::new(), &di);
        assert_eq!(r, EcosystemResolution::Mapped("Ubuntu:26.04:LTS".to_string()));
    }

    #[test]
    fn override_wins_over_direct_match() {
        // Operator can override even a directly-recognised distro —
        // useful if OSV's ecosystem string changes upstream and we
        // need to ship a fix faster than a WolfStack release.
        let s = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        let mut overrides = HashMap::new();
        overrides.insert("ubuntu".to_string(), "Ubuntu:24.04:LTS:Alternate".to_string());
        let r = resolve_ecosystem(s, &overrides, &DistroInfo::default());
        assert_eq!(r, EcosystemResolution::Mapped("Ubuntu:24.04:LTS:Alternate".to_string()));
    }

    #[test]
    fn parse_ubuntu_csv_extracts_codename_to_version() {
        let csv = "version,codename,series,created,release,eol,eol-server\n\
22.04 LTS,Jammy Jellyfish,jammy,2021-10-14,2022-04-21,2027-04-21,2032-04-21\n\
24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-04-25,2034-04-25\n\
24.10,Oracular Oriole,oracular,2024-04-25,2024-10-10,2025-07-10,\n";
        let map = parse_ubuntu_csv(csv);
        assert_eq!(map.get("jammy").map(String::as_str), Some("22.04"));
        assert_eq!(map.get("noble").map(String::as_str), Some("24.04"));
        assert_eq!(map.get("oracular").map(String::as_str), Some("24.10"));
    }

    #[test]
    fn parse_debian_csv_extracts_codename_to_major() {
        let csv = "version,codename,series,created,release,eol,eol-lts,eol-elts\n\
12,Bookworm,bookworm,2021-08-14,2023-06-10,,,\n\
13,Trixie,trixie,2023-06-10,,,,\n\
,Sid,sid,1993-08-16,,,,\n";
        let map = parse_debian_csv(csv);
        assert_eq!(map.get("bookworm").copied(), Some(12));
        assert_eq!(map.get("trixie").copied(), Some(13));
        assert!(!map.contains_key("sid"));  // non-numeric "version" is skipped
    }

    #[test]
    fn ecosystem_parrot_with_debian_codename_resolves() {
        // Parrot OS 6.x on Debian Bookworm.
        let s = "ID=parrot\nID_LIKE=debian\nVERSION_CODENAME=bookworm\n";
        assert_eq!(ecosystem_from_os_release(s).as_deref(), Some("Debian:12"));
    }

    #[test]
    fn ecosystem_elementary_zorin_inherit_ubuntu() {
        let elementary = "ID=elementary\nID_LIKE=ubuntu\nUBUNTU_CODENAME=jammy\n";
        assert_eq!(ecosystem_from_os_release(elementary).as_deref(), Some("Ubuntu:22.04:LTS"));
        let zorin = "ID=zorin\nID_LIKE=ubuntu\nUBUNTU_CODENAME=focal\n";
        assert_eq!(ecosystem_from_os_release(zorin).as_deref(), Some("Ubuntu:20.04:LTS"));
    }

    #[test]
    fn ecosystem_id_like_ubuntu_unknown_codename_falls_through() {
        // An Ubuntu derivative with a codename we don't have mapped
        // returns None rather than emitting a wrong ecosystem string.
        // Better to defer to the pocket scanner than misroute the query.
        let s = "ID=futuredistro\nID_LIKE=ubuntu\nUBUNTU_CODENAME=mythicalbeast\n";
        assert!(ecosystem_from_os_release(s).is_none());
    }

    #[test]
    fn parse_dpkg_output_strips_arch_suffix() {
        let text = "openssh-server\t1:8.9p1-3ubuntu0.10\nlibssl3:amd64\t3.0.2-0ubuntu1.15\n";
        let out = parse_dpkg_query(text);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], ("openssh-server".to_string(), "1:8.9p1-3ubuntu0.10".to_string()));
        assert_eq!(out[1].0, "libssl3");
    }

    #[test]
    fn parse_rpm_qa_handles_release_suffix() {
        let text = "openssh-server\t9.6p1-2.el9\nkernel\t5.14.0-503.el9\n";
        let out = parse_rpm_qa(text);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1], ("kernel".to_string(), "5.14.0-503.el9".to_string()));
    }

    #[test]
    fn parse_apk_info_splits_on_first_hyphen_digit() {
        let text = "openssh-9.7_p1-r4\nbusybox-1.36.1-r5\nlibc6-compat-1.2.5-r9\n";
        let out = parse_apk_info(text);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], ("openssh".to_string(), "9.7_p1-r4".to_string()));
        assert_eq!(out[1], ("busybox".to_string(), "1.36.1-r5".to_string()));
        assert_eq!(out[2], ("libc6-compat".to_string(), "1.2.5-r9".to_string()));
    }

    #[test]
    fn cvss_v3_critical_vector() {
        // Classic AV:N + all-high impact + no PR + no UI = 9.8 critical.
        let s = score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 0.05, "got {}", s);
    }

    #[test]
    fn cvss_v3_low_vector() {
        // Local + low impact = ~3.3.
        let s = score_v3("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N").unwrap();
        assert!(s < 4.0 && s > 0.0, "got {}", s);
    }

    #[test]
    fn cvss_v3_scope_changed_higher_than_unchanged() {
        let unchanged = score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").unwrap();
        let changed = score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N").unwrap();
        assert!(changed > unchanged, "scope=C must score higher than scope=U");
    }

    #[test]
    fn cvss_v3_invalid_vector_returns_none() {
        assert!(score_v3("not-a-vector").is_none());
        assert!(score_v3("CVSS:3.1/AV:X").is_none());
    }

    #[test]
    fn cvss_v2_network_high_impact() {
        // AV:N/AC:L/Au:N/C:C/I:C/A:C = 10.0.
        let s = score_v2("AV:N/AC:L/Au:N/C:C/I:C/A:C").unwrap();
        assert!((s - 10.0).abs() < 0.05, "got {}", s);
    }

    #[test]
    fn pick_best_cvss_prefers_v3_over_v2() {
        let entries = vec![
            OsvSeverityEntry { ty: "CVSS_V2".into(), score: "AV:N/AC:L/Au:N/C:N/I:N/A:N".into() },
            OsvSeverityEntry { ty: "CVSS_V3".into(), score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into() },
        ];
        let s = pick_best_cvss(&entries).unwrap();
        assert!(s > 9.0, "v3 should win — got {}", s);
    }

    #[test]
    fn pick_best_cvss_falls_back_to_v4_then_v2() {
        let only_v4 = vec![
            OsvSeverityEntry { ty: "CVSS_V4".into(), score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".into() },
        ];
        let s = pick_best_cvss(&only_v4).unwrap();
        assert!(s >= 7.0, "v4 with high impact should be ≥ 7.0, got {}", s);
    }

    #[test]
    fn severity_kev_is_critical_regardless_of_score() {
        let f = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Ubuntu:22.04:LTS".into(),
            package: "htop".into(),  // not a critical package
            version: "3.0.5".into(),
            vuln: OsvVuln {
                id: "OSV-1".into(),
                aliases: vec!["CVE-2099-0001".into()],
                summary: "x".into(),
                cvss_score: Some(2.0),  // very low
                advisory_url: None,
                modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: true,
            fix_available: false,
        };
        assert_eq!(severity_for(&f), Severity::Critical);
    }

    #[test]
    fn severity_critical_pkg_is_critical_regardless_of_score() {
        let f = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Ubuntu:22.04:LTS".into(),
            package: "openssh-server".into(),
            version: "9.6p1".into(),
            vuln: OsvVuln {
                id: "OSV-2".into(),
                aliases: vec![],
                summary: "x".into(),
                cvss_score: Some(2.0),
                advisory_url: None,
                modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: false,
            fix_available: false,
        };
        assert_eq!(severity_for(&f), Severity::Critical);
    }

    #[test]
    fn severity_score_tiers() {
        let mk = |score: Option<f32>| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Ubuntu:22.04:LTS".into(),
            package: "htop".into(),
            version: "1.0".into(),
            vuln: OsvVuln {
                id: "x".into(), aliases: vec![], summary: "".into(),
                cvss_score: score, advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: false,
            fix_available: false,
        };
        assert_eq!(severity_for(&mk(Some(9.5))), Severity::Critical);
        assert_eq!(severity_for(&mk(Some(7.5))), Severity::High);
        assert_eq!(severity_for(&mk(Some(5.0))), Severity::Warn);
        assert_eq!(severity_for(&mk(Some(3.0))), Severity::Info);  // suppressed by should_emit
        assert_eq!(severity_for(&mk(None)), Severity::Warn);  // unscored = Warn
    }

    #[test]
    fn should_emit_filters_kev_only() {
        let mk = |kev: bool| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Ubuntu:22.04:LTS".into(),
            package: "openssh-server".into(),
            version: "9.6p1".into(),
            vuln: OsvVuln {
                id: "x".into(), aliases: vec![], summary: "".into(),
                cvss_score: Some(9.0), advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: kev,
            fix_available: false,
        };
        let mut cfg = OsvConfig::default();
        cfg.kev_only = true;
        assert!(should_emit(&mk(true), &cfg));
        assert!(!should_emit(&mk(false), &cfg));
        cfg.kev_only = false;
        assert!(should_emit(&mk(false), &cfg));
    }

    #[test]
    fn cve_ids_extracted_from_aliases() {
        let v = OsvVuln {
            id: "GHSA-xxxx-yyyy".into(),
            aliases: vec!["CVE-2026-31431".into(), "CVE-2025-9999".into(), "OSV-1".into()],
            summary: "".into(), cvss_score: None, advisory_url: None,
            modified: None, fixed_versions: HashMap::new(),
            references: Vec::new(),
        };
        let cves = v.cve_ids();
        assert_eq!(cves.len(), 2);
        assert!(cves.contains(&"CVE-2026-31431".to_string()));
        assert!(cves.contains(&"CVE-2025-9999".to_string()));
        assert_eq!(v.display_id(), "CVE-2025-9999");  // sorted ascending — earliest CVE wins
    }

    #[test]
    fn group_by_target_collapses_all_cves_to_one_card_per_host() {
        // The whole point of the v22.9.22 redesign: 50 CVEs on one
        // host produce ONE inbox card, not 50.
        let mk = |pkg: &str, cve: &str| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: pkg.into(),
            version: "1.0".into(),
            vuln: OsvVuln {
                id: cve.into(), aliases: vec![cve.into()],
                summary: "".into(), cvss_score: Some(7.5),
                advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: false,
            fix_available: false,
        };
        let findings: Vec<OsvFinding> = (0..50)
            .map(|i| mk("openssl", &format!("CVE-2026-{:04}", i)))
            .collect();
        let grouped = group_by_target(&findings);
        assert_eq!(grouped.len(), 1, "50 CVEs on one host = 1 card, not 50");
        assert_eq!(grouped[0].findings.len(), 50);
    }

    #[test]
    fn group_by_target_separates_host_from_lxc() {
        let mk = |target: ScanTargetOwned| OsvFinding {
            target, ecosystem: "Debian:12".into(),
            package: "x".into(), version: "1".into(),
            vuln: OsvVuln {
                id: "CVE-X".into(), aliases: vec!["CVE-X".into()],
                summary: "".into(), cvss_score: Some(7.5),
                advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: false,
            fix_available: false,
        };
        let findings = vec![
            mk(ScanTargetOwned::Host),
            mk(ScanTargetOwned::Lxc("ct1".into())),
            mk(ScanTargetOwned::Lxc("ct2".into())),
        ];
        let grouped = group_by_target(&findings);
        assert_eq!(grouped.len(), 3);
        // Host first, then LXC alphabetical.
        assert!(matches!(grouped[0].target, ScanTargetOwned::Host));
        assert!(matches!(&grouped[1].target, ScanTargetOwned::Lxc(n) if n == "ct1"));
        assert!(matches!(&grouped[2].target, ScanTargetOwned::Lxc(n) if n == "ct2"));
    }

    #[test]
    fn target_proposal_severity_is_max_across_findings() {
        let ctx = Context::for_node("n");
        let warn_finding = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "htop".into(), version: "3.0.5".into(),
            vuln: OsvVuln {
                id: "CVE-LOW".into(), aliases: vec!["CVE-LOW".into()],
                summary: "".into(), cvss_score: Some(5.0),
                advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: false,
            fix_available: false,
        };
        let critical_kev_finding = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "openssl".into(), version: "3.0.13".into(),
            vuln: OsvVuln {
                id: "CVE-2026-31431".into(),
                aliases: vec!["CVE-2026-31431".into()],
                summary: "".into(), cvss_score: Some(7.8),
                advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: true,
            fix_available: false,
        };
        let f = vec![warn_finding, critical_kev_finding];
        let g = TargetGroup { target: ScanTargetOwned::Host, findings: f.iter().collect() };
        let prop = build_target_proposal(&g, &ctx, 0);
        assert_eq!(prop.severity, Severity::Critical,
            "any KEV-listed finding must lift the whole card to Critical");
    }

    #[test]
    fn target_proposal_evidence_lists_kev_first_and_caps_per_section() {
        let ctx = Context::for_node("n");
        let mk = |i: u32, kev: bool| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "p".into(), version: "1".into(),
            vuln: OsvVuln {
                id: format!("CVE-2026-{:04}", i),
                aliases: vec![format!("CVE-2026-{:04}", i)],
                summary: "".into(), cvss_score: Some(7.0),
                advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: kev,
            fix_available: false,
        };
        let findings: Vec<OsvFinding> = (0..15).map(|i| mk(i, i == 7)).collect();
        let g = TargetGroup { target: ScanTargetOwned::Host, findings: findings.iter().collect() };
        let prop = build_target_proposal(&g, &ctx, 0);
        // Evidence: Total + KEV-count chip + section header + 6 CVE rows + "+9 more awaiting".
        // No "Patchable now" header because every finding has fix_available=false.
        let labels: Vec<&str> = prop.evidence.iter().map(|e| e.label.as_str()).collect();
        assert!(labels.contains(&"Total"));
        assert!(labels.contains(&"KEV"));
        assert!(labels.contains(&"Awaiting upstream fix"));
        assert!(labels.contains(&"More awaiting"));
        assert!(!labels.contains(&"Patchable now"),
            "all findings have fix_available=false; the patchable section must not render");
        // First CVE row must be the KEV one (CVE-2026-0007).
        let first_cve_row = prop.evidence.iter().find(|e| e.label.starts_with("CVE-2026-")).unwrap();
        assert_eq!(first_cve_row.label, "CVE-2026-0007",
            "KEV-listed CVE must surface at the top of the evidence list");
        // The cap kicks in: only 6 CVE rows render in the section.
        let cve_row_count = prop.evidence.iter()
            .filter(|e| e.label.starts_with("CVE-2026-")).count();
        assert_eq!(cve_row_count, MAX_CVE_EVIDENCE_ROWS_PER_SECTION,
            "section cap must trim the row list at MAX_CVE_EVIDENCE_ROWS_PER_SECTION");
    }

    #[test]
    fn target_proposal_scope_has_no_cve_suffix() {
        // Critical for one-card-per-target dedup: scope must be the
        // bare target id, otherwise upserts won't collapse.
        let ctx = Context::for_node("n");
        let f = OsvFinding {
            target: ScanTargetOwned::Lxc("ct1".into()),
            ecosystem: "Debian:12".into(),
            package: "p".into(), version: "1".into(),
            vuln: OsvVuln {
                id: "CVE-X".into(), aliases: vec!["CVE-X".into()],
                summary: "".into(), cvss_score: Some(7.0),
                advisory_url: None, modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: false,
            fix_available: false,
        };
        let g = TargetGroup { target: ScanTargetOwned::Lxc("ct1".into()), findings: vec![&f] };
        let prop = build_target_proposal(&g, &ctx, 0);
        assert_eq!(prop.scope.resource_id.as_deref(), Some("osv:lxc:ct1"));
        assert!(!prop.scope.resource_id.as_deref().unwrap().contains("CVE"));
    }

    #[test]
    fn parse_vector_handles_v3_prefix() {
        let m = parse_vector("CVSS:3.1/AV:N/AC:L").unwrap();
        assert_eq!(m.get("AV").map(String::as_str), Some("N"));
        assert_eq!(m.get("AC").map(String::as_str), Some("L"));
        // Version segment must NOT be captured as a metric.
        assert!(!m.contains_key("3"));
    }

    #[test]
    fn match_key_is_stable() {
        assert_eq!(
            match_key("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15"),
            "Ubuntu:22.04:LTS|openssl|3.0.2-0ubuntu1.15",
        );
    }

    #[test]
    fn round_up_one_decimal_matches_cvss_spec() {
        // From CVSS 3.1 spec — 4.02 rounds up to 4.1; 4.00 stays 4.0.
        assert!((round_up_one_decimal(4.02) - 4.1).abs() < 1e-5);
        assert!((round_up_one_decimal(4.00) - 4.0).abs() < 1e-5);
        assert!((round_up_one_decimal(9.81) - 9.9).abs() < 1e-5);
    }

    #[test]
    fn osv_config_round_trip_via_env_var() {
        let tmp = std::env::temp_dir().join("wolfstack_osv_config_test.json");
        // SAFETY: tests run sequentially within this module's thread
        // by default for env access, and we restore the env var
        // before returning so other tests aren't affected.
        unsafe { std::env::set_var("WOLFSTACK_OSV_CONFIG_FILE", &tmp); }
        let cfg = OsvConfig {
            enabled: false,
            endpoint: "https://example.com".into(),
            kev_endpoint: "https://example.com/kev.json".into(),
            kev_only: true,
            severity_floor: Severity::Critical,
            suppress_no_fix: false,
            distro_overrides: HashMap::new(),
        };
        cfg.save().unwrap();
        let loaded = OsvConfig::load();
        assert!(!loaded.enabled);
        assert!(loaded.kev_only);
        assert_eq!(loaded.severity_floor, Severity::Critical);
        assert!(!loaded.suppress_no_fix);
        assert_eq!(loaded.endpoint, "https://example.com");
        unsafe { std::env::remove_var("WOLFSTACK_OSV_CONFIG_FILE"); }
        let _ = std::fs::remove_file(tmp);
    }

    fn mk_finding(score: Option<f32>, kev: bool, fix_available: bool) -> OsvFinding {
        OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "p".into(),
            version: "1".into(),
            vuln: OsvVuln {
                id: "CVE-X".into(),
                aliases: vec!["CVE-X".into()],
                summary: "".into(),
                cvss_score: score,
                advisory_url: None,
                modified: None,
                fixed_versions: HashMap::new(),
                references: Vec::new(),
            },
            kev_listed: kev,
            fix_available,
        }
    }

    #[test]
    fn severity_floor_hides_findings_below_threshold_but_keeps_kev() {
        // Floor=High should hide CVSS 5.0 (Warn tier) but always
        // surface KEV-listed findings regardless of score.
        let mut cfg = OsvConfig::default();
        cfg.severity_floor = Severity::High;
        cfg.suppress_no_fix = false;

        let warn_finding   = mk_finding(Some(5.0), false, true);
        let high_finding   = mk_finding(Some(7.5), false, true);
        let kev_low_score  = mk_finding(Some(3.5), true,  true);

        assert!(!should_emit(&warn_finding, &cfg),
            "CVSS 5.0 (Warn) must be hidden when severity_floor=High");
        assert!(should_emit(&high_finding, &cfg),
            "CVSS 7.5 (High) must surface at floor=High");
        assert!(should_emit(&kev_low_score, &cfg),
            "KEV-listed findings must surface even with CVSS < floor");
    }

    #[test]
    fn severity_floor_critical_hides_high_keeps_kev() {
        let mut cfg = OsvConfig::default();
        cfg.severity_floor = Severity::Critical;
        cfg.suppress_no_fix = false;

        let high   = mk_finding(Some(7.5), false, true);
        let crit   = mk_finding(Some(9.5), false, true);
        let kev    = mk_finding(Some(5.0), true,  true);
        assert!(!should_emit(&high, &cfg),
            "CVSS 7.5 (High) must be hidden when severity_floor=Critical");
        assert!(should_emit(&crit, &cfg),
            "CVSS 9.5 (Critical) surfaces at floor=Critical");
        assert!(should_emit(&kev, &cfg),
            "KEV bypasses the Critical floor — exploited-in-wild always surfaces");
    }

    #[test]
    fn target_proposal_splits_patchable_and_awaiting() {
        let ctx = Context::for_node("n");
        let patchable_kev = OsvFinding { kev_listed: true, fix_available: true,
            ..mk_finding(Some(8.0), true, true) };
        let patchable_norm = mk_finding(Some(7.5), false, true);
        let awaiting_kev = mk_finding(Some(8.0), true, false);
        let f = vec![patchable_kev, patchable_norm, awaiting_kev];
        let g = TargetGroup { target: ScanTargetOwned::Host, findings: f.iter().collect() };
        let prop = build_target_proposal(&g, &ctx, /*suppressed_no_fix=*/0);
        let labels: Vec<&str> = prop.evidence.iter().map(|e| e.label.as_str()).collect();
        assert!(labels.contains(&"Patchable now"),
            "two patchable findings must produce the Patchable section");
        assert!(labels.contains(&"Awaiting upstream fix"),
            "one no-fix finding must produce the Awaiting section");
    }

    #[test]
    fn target_proposal_surfaces_suppressed_no_fix_count() {
        let ctx = Context::for_node("n");
        let f = vec![mk_finding(Some(7.5), false, true)];
        let g = TargetGroup { target: ScanTargetOwned::Host, findings: f.iter().collect() };
        let prop = build_target_proposal(&g, &ctx, /*suppressed_no_fix=*/42);
        let row = prop.evidence.iter()
            .find(|e| e.label == "Hidden — no upstream fix")
            .expect("suppressed-no-fix subtotal must render when count > 0");
        assert!(row.value.contains("42"),
            "subtotal value must include the hidden count, got {:?}", row.value);
    }

    #[test]
    fn no_fix_only_card_emitted_when_target_has_no_visible_findings() {
        // A target whose only contribution is a hidden no-fix count
        // gets its own Info card so the operator sees the total.
        let ctx = Context::for_node("n");
        let mut suppressed = HashMap::new();
        suppressed.insert(ScanTargetOwned::Host, 12);
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: suppressed,
        };
        let store = crate::predictive::proposal::ProposalStore::default();
        let acks = AckStore::default();
        let props = analyze(&ctx, &facts, &acks, &store);
        let card = props.iter()
            .find(|p| p.scope.resource_id.as_deref()
                .map(|s| s.contains("no-fix-tracker")).unwrap_or(false))
            .expect("must emit a no-fix-only card when all findings are suppressed");
        assert_eq!(card.severity, Severity::Info,
            "no-fix-only card is informational — there's nothing actionable yet");
        assert!(card.title.contains("12"),
            "title must include the hidden count, got {:?}", card.title);
    }

    #[test]
    fn cve_evidence_row_prepends_osv_dev_details_link() {
        // Operators asked for "click a CVE → see details". Every
        // CVE row must carry an `OSV.dev` link as the first chip
        // pointing at the canonical record. Pin the URL shape and
        // ordering so a future rendering change can't drop it.
        let f = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "openssl".into(),
            version: "3.0.13".into(),
            vuln: OsvVuln {
                id: "CVE-2099-1234".into(),
                aliases: vec!["CVE-2099-1234".into()],
                summary: "test".into(),
                cvss_score: Some(7.5),
                advisory_url: None,
                modified: None,
                fixed_versions: HashMap::new(),
                references: vec![
                    OsvVulnReference {
                        ty: "ADVISORY".into(),
                        url: "https://security-tracker.debian.org/tracker/CVE-2099-1234".into(),
                    },
                ],
            },
            kev_listed: false,
            fix_available: false,
        };
        let row = cve_evidence_row(&f);
        assert!(!row.links.is_empty(), "evidence row must have at least the Details link");
        assert_eq!(row.links[0].label, "Details",
            "Details link must be the FIRST chip — that's the click target operators expect");
        assert_eq!(row.links[0].url, "https://osv.dev/vulnerability/CVE-2099-1234",
            "Details URL must point at osv.dev's canonical record");
        // Vendor links still rendered after.
        assert!(row.links.iter().any(|l| l.label == "Debian"),
            "existing reference chips must still surface alongside the Details link");
    }

    #[test]
    fn cve_evidence_row_total_chip_cap_includes_details_plus_three_vendors() {
        // Sanity: the row caps at 4 chips total — 1 Details + 3
        // vendors. Stops a CVE with 20 references from blowing out
        // the inbox card width.
        let mut refs = Vec::new();
        for i in 0..10 {
            refs.push(OsvVulnReference {
                ty: "WEB".into(),
                url: format!("https://example-{}.com/cve", i),
            });
        }
        let f = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "p".into(), version: "1".into(),
            vuln: OsvVuln {
                id: "CVE-X".into(), aliases: vec!["CVE-X".into()],
                summary: "".into(), cvss_score: None, advisory_url: None,
                modified: None, fixed_versions: HashMap::new(),
                references: refs,
            },
            kev_listed: false, fix_available: false,
        };
        let row = cve_evidence_row(&f);
        assert_eq!(row.links.len(), MAX_REFERENCES_PER_ROW + 1,
            "row must show OSV.dev + exactly MAX_REFERENCES_PER_ROW vendor chips");
    }

    #[test]
    fn pick_reference_links_orders_advisory_first_and_caps_at_three() {
        let f = OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "p".into(), version: "1".into(),
            vuln: OsvVuln {
                id: "CVE-X".into(),
                aliases: vec!["CVE-X".into()],
                summary: "".into(),
                cvss_score: None,
                advisory_url: None,
                modified: None,
                fixed_versions: HashMap::new(),
                references: vec![
                    OsvVulnReference { ty: "WEB".into(), url: "https://www.example.com/blog".into() },
                    OsvVulnReference { ty: "ADVISORY".into(), url: "https://security-tracker.debian.org/tracker/CVE-X".into() },
                    OsvVulnReference { ty: "FIX".into(), url: "https://github.com/example/repo/commit/abc".into() },
                    OsvVulnReference { ty: "REPORT".into(), url: "https://bugzilla.redhat.com/123".into() },
                    OsvVulnReference { ty: "WEB".into(), url: "https://nvd.nist.gov/vuln/detail/CVE-X".into() },
                ],
            },
            kev_listed: false,
            fix_available: false,
        };
        let links = pick_reference_links(&f);
        assert_eq!(links.len(), 3, "cap to MAX_REFERENCES_PER_ROW");
        // Highest-priority (ADVISORY) goes first; the Debian tracker
        // should produce the "Debian" chip label.
        assert_eq!(links[0].label, "Debian",
            "ADVISORY ranks first; debian-tracker host gets a friendly label");
        assert_eq!(links[1].label, "GitHub",
            "FIX comes second; github.com host gets a friendly label");
        assert_eq!(links[2].label, "Red Hat",
            "REPORT comes third; bugzilla.redhat.com gets a friendly label");
    }

    #[test]
    fn distill_full_preserves_references_for_chip_rendering() {
        let raw = r#"{
            "id": "OSV-X",
            "aliases": ["CVE-X"],
            "summary": "",
            "severity": [],
            "affected": [],
            "references": [
                {"type":"ADVISORY","url":"https://security-tracker.debian.org/tracker/CVE-X"},
                {"type":"WEB","url":"https://nvd.nist.gov/vuln/detail/CVE-X"}
            ]
        }"#;
        let full: OsvFullVuln = serde_json::from_str(raw).unwrap();
        let v = distill_full(full);
        assert_eq!(v.references.len(), 2,
            "every non-empty reference must round-trip into the cached struct");
        assert_eq!(v.references[0].ty, "ADVISORY");
    }

    #[test]
    fn distill_full_extracts_fixed_versions() {
        let raw = r#"{
            "id": "OSV-X",
            "aliases": ["CVE-2099-0001"],
            "summary": "test",
            "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {"package": {"name":"openssl","ecosystem":"Ubuntu:22.04:LTS"},
                 "ranges": [{"events": [{"introduced":"0"},{"fixed":"3.0.2-0ubuntu1.15"}]}]}
            ],
            "references": [{"type":"ADVISORY","url":"https://example.com/CVE-2099-0001"}]
        }"#;
        let full: OsvFullVuln = serde_json::from_str(raw).unwrap();
        let v = distill_full(full);
        assert_eq!(v.cvss_score.map(|s| (s * 10.0).round() / 10.0), Some(9.8));
        assert_eq!(v.fixed_versions.get("openssl"), Some(&"3.0.2-0ubuntu1.15".to_string()));
        assert_eq!(v.advisory_url.as_deref(), Some("https://example.com/CVE-2099-0001"));
    }

    #[test]
    fn extra_covered_includes_pending_proposals_for_scanned_targets() {
        use crate::predictive::proposal::{ProposalStore, ProposalSource, RemediationPlan};
        let ctx = Context::for_node("node-a");
        let mut store = ProposalStore::default();
        // A pending OSV finding for the host whose CVE we are about
        // to NOT re-emit (because the package has been upgraded).
        let scope = ProposalScope {
            node_id: "node-a".into(),
            resource_id: Some("osv:host:CVE-2099-0001".into()),
        };
        store.upsert(Proposal::new(
            FINDING_TYPE,
            ProposalSource::Rule,
            Severity::High,
            "stale", "stale", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            scope.clone(),
        ));
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        let extra = extra_covered_from_store(&ctx, &facts, &store);
        assert_eq!(extra.len(), 1, "the stale OSV proposal must be marked covered so auto-resolve can close it");
        assert_eq!(extra[0].1, scope);
    }

    #[test]
    fn pm_for_ecosystem_routes_correctly() {
        assert_eq!(pm_for_ecosystem("Debian:12"), Some(PackageManager::Apt));
        assert_eq!(pm_for_ecosystem("Ubuntu:24.04:LTS"), Some(PackageManager::Apt));
        assert_eq!(pm_for_ecosystem("Rocky Linux:9"), Some(PackageManager::Dnf));
        assert_eq!(pm_for_ecosystem("AlmaLinux:9"), Some(PackageManager::Dnf));
        assert_eq!(pm_for_ecosystem("openSUSE:Leap 15.5"), Some(PackageManager::Zypper));
        assert_eq!(pm_for_ecosystem("SUSE:15.5"), Some(PackageManager::Zypper));
        assert_eq!(pm_for_ecosystem("Alpine:v3.19"), Some(PackageManager::Apk));
        assert_eq!(pm_for_ecosystem("Wolfi"), Some(PackageManager::Apk));
        assert_eq!(pm_for_ecosystem("Chainguard"), Some(PackageManager::Apk));
        assert_eq!(pm_for_ecosystem("Mageia:9"), Some(PackageManager::Dnf));
        // Unknown / future ecosystems return None — caller falls
        // through to the all-PM-suggestion list rather than guessing.
        assert_eq!(pm_for_ecosystem("FutureDistro:1.0"), None);
        assert_eq!(pm_for_ecosystem(""), None);
    }

    #[test]
    fn bulk_upgrade_commands_use_apt_for_ubuntu_host() {
        let cmds = bulk_upgrade_commands(&ScanTargetOwned::Host, "Ubuntu:24.04:LTS");
        // One bulk upgrade — not a per-package install line.
        assert_eq!(cmds, vec!["apt-get update".to_string(), "apt-get upgrade -y".to_string()]);
        assert!(!cmds.iter().any(|c| c.contains("dnf")));
        assert!(!cmds.iter().any(|c| c.contains("zypper")));
        assert!(!cmds.iter().any(|c| c.contains("apk")));
    }

    #[test]
    fn bulk_upgrade_commands_use_lxc_attach_dnf_for_rocky_lxc() {
        let cmds = bulk_upgrade_commands(
            &ScanTargetOwned::Lxc("db1".into()),
            "Rocky Linux:9",
        );
        assert_eq!(cmds, vec!["lxc-attach -n db1 -- dnf upgrade --refresh -y".to_string()]);
        assert!(!cmds.iter().any(|c| c.contains("apt-get")));
    }

    #[test]
    fn bulk_upgrade_commands_fall_through_for_unknown_ecosystem() {
        // Unknown ecosystem (or the rare classifiable-but-unknown-PM
        // case) emits all four common commands prefixed by lxc-attach
        // for the LXC target. Caller picks.
        let cmds = bulk_upgrade_commands(
            &ScanTargetOwned::Lxc("ct1".into()),
            "FutureDistro:1.0",
        );
        assert!(cmds.iter().any(|c| c.contains("apt-get upgrade")));
        assert!(cmds.iter().any(|c| c.contains("dnf upgrade")));
        assert!(cmds.iter().any(|c| c.contains("zypper update")));
        assert!(cmds.iter().any(|c| c.contains("apk upgrade")));
        // Every non-comment line must be lxc-attach-prefixed.
        for c in cmds.iter().filter(|c| !c.starts_with('#')) {
            assert!(c.contains("lxc-attach -n ct1 --"), "missing prefix on: {}", c);
        }
    }

    #[test]
    fn analyze_emits_breadcrumb_for_unrecognised_derivative() {
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: Vec::new(),
            unrecognized_derivatives: vec![UnrecognizedDerivativeBreadcrumb {
                target: ScanTargetOwned::Host,
                id: "futuredistro".to_string(),
                parent: ParentDistro::Ubuntu,
                codename_hint: Some("robust".to_string()),
                distro_info_present: false,
            }],
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1, "exactly one breadcrumb should fire");
        assert_eq!(out[0].finding_type, FINDING_UNRECOGNIZED_DERIVATIVE);
        assert_eq!(out[0].severity, Severity::Info);
        // Scope must be distinct from a regular OSV finding so an
        // operator dismissing the breadcrumb doesn't suppress the
        // CVE findings on the same host.
        assert!(out[0].scope.resource_id.as_deref().unwrap().contains(":derivative:"));
    }

    #[test]
    fn analyze_suppresses_breadcrumb_when_kev_only() {
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let mut config = OsvConfig::default();
        config.kev_only = true;
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: Vec::new(),
            unrecognized_derivatives: vec![UnrecognizedDerivativeBreadcrumb {
                target: ScanTargetOwned::Host,
                id: "x".into(),
                parent: ParentDistro::Debian,
                codename_hint: None,
                distro_info_present: true,
            }],
            config,
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        // kev_only mode = highest-signal-only inbox; a breadcrumb is by
        // definition not a CVE event, so it should be suppressed.
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty(), "kev_only must suppress breadcrumbs");
    }

    #[test]
    fn covered_scopes_includes_breadcrumb_so_auto_resolve_can_close() {
        let ctx = Context::for_node("node-a");
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: Vec::new(),
            unrecognized_derivatives: vec![UnrecognizedDerivativeBreadcrumb {
                target: ScanTargetOwned::Lxc("ct1".into()),
                id: "futuredistro".into(),
                parent: ParentDistro::Ubuntu,
                codename_hint: Some("robust".into()),
                distro_info_present: false,
            }],
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        let scopes = covered_scopes(&ctx, &facts);
        assert!(scopes.iter().any(|(ft, _)| ft == FINDING_UNRECOGNIZED_DERIVATIVE),
            "breadcrumb scope must be covered so the next clean tick auto-resolves it");
    }

    #[test]
    fn extra_covered_handles_non_cve_vuln_ids() {
        use crate::predictive::proposal::{ProposalStore, ProposalSource, RemediationPlan};
        let ctx = Context::for_node("node-a");
        let mut store = ProposalStore::default();
        // Proposal whose vuln id is a GHSA, not a CVE.
        store.upsert(Proposal::new(
            FINDING_TYPE,
            ProposalSource::Rule,
            Severity::High,
            "x", "x", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            ProposalScope {
                node_id: "node-a".into(),
                resource_id: Some("osv:host:GHSA-aaaa-bbbb-cccc".into()),
            },
        ));
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        let extra = extra_covered_from_store(&ctx, &facts, &store);
        assert_eq!(extra.len(), 1,
            "GHSA-id proposal must be marked covered (the parser was \
             previously CVE-only and silently missed these)");
    }

    #[test]
    fn extra_covered_lxc_does_not_cross_into_host_scope() {
        // Bug-bait: `osv:host:` is a substring of `osv:host:CT1:` if
        // we matched on `contains`, which would let LXC scope auto-
        // resolve when a host scan completed. starts_with-with-colon
        // prevents that — verify.
        use crate::predictive::proposal::{ProposalStore, ProposalSource, RemediationPlan};
        let ctx = Context::for_node("node-a");
        let mut store = ProposalStore::default();
        store.upsert(Proposal::new(
            FINDING_TYPE, ProposalSource::Rule, Severity::High,
            "x", "x", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            ProposalScope {
                node_id: "node-a".into(),
                resource_id: Some("osv:lxc:ct1:CVE-2099-0001".into()),
            },
        ));
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        let extra = extra_covered_from_store(&ctx, &facts, &store);
        assert!(extra.is_empty(),
            "host scan must NOT mark an LXC proposal as covered");
    }

    #[test]
    fn extra_covered_skips_unscanned_targets() {
        use crate::predictive::proposal::{ProposalStore, ProposalSource, RemediationPlan};
        let ctx = Context::for_node("node-a");
        let mut store = ProposalStore::default();
        store.upsert(Proposal::new(
            FINDING_TYPE,
            ProposalSource::Rule,
            Severity::High,
            "x", "x", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            ProposalScope {
                node_id: "node-a".into(),
                resource_id: Some("osv:lxc:offline-ct:CVE-2099-0001".into()),
            },
        ));
        // Scanned only the host — the offline LXC was not covered
        // this tick, so its pending finding must NOT be in the
        // covered set (otherwise auto-resolve would close it just
        // because the LXC is down — which would be wrong; we have
        // no evidence the CVE has cleared).
        let facts = OsvFacts {
            findings: Vec::new(),
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            config: OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: HashMap::new(),
        };
        let extra = extra_covered_from_store(&ctx, &facts, &store);
        assert!(extra.is_empty(), "uncovered LXC must not be auto-resolved");
    }
}
