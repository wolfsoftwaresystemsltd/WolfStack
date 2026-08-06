// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Build-time enforcement of the resource rules WolfStack must never break.
//!
//! WHY THIS FILE EXISTS
//!
//! On 2026-08-05 a production fleet of twelve nodes melted down. Every node
//! climbed to 60-80% system CPU, descriptors grew ~700/min until the table was
//! exhausted at 65,535, and restarting bought only minutes. Workloads survived
//! only because systemd's `KillMode=process` kept guests out of the blast.
//!
//! Two defects, both invisible in review and both trivially preventable:
//!
//!   1. `POLL_CLIENT` — the client that dials EVERY cluster peer every 10
//!      seconds — set a total `.timeout()` but no `.connect_timeout()`. A total
//!      timeout does nothing for a connection that never establishes: a SYN to
//!      a black-holed address holds a descriptor for the kernel's full retry
//!      window (~130s at tcp_syn_retries=6). Measured: 2,422 sockets in
//!      SYN-SENT and 2,868 in CLOSE-WAIT on one node.
//!
//!   2. `SystemMonitor` refreshed ALL processes on a timer and at construction.
//!      sysinfo caches an open `/proc/<pid>/stat` handle per process and grants
//!      itself HALF of RLIMIT_NOFILE to do it — 32,767 descriptors claimed
//!      before a single metric was read.
//!
//! A management plane must not be capable of taking down the estate it
//! manages. These are not style preferences; they are the difference between a
//! bug and an outage.
//!
//! HOW THIS IS ACTUALLY ENFORCED
//!
//! By the "Resource-safety gate + test suite" step in
//! `.github/workflows/release.yml`, which runs `cargo test --locked` on the
//! x86_64 leg before the cross builds. That step was added at the same time as
//! this file — and had to be, because the release workflow previously ran only
//! `cargo check`, which compiles without executing a single test. Every rule
//! in here would have been advisory.
//!
//! If that step is ever removed, this file stops enforcing anything and
//! silently becomes documentation. The two must live or die together.
//!
//! ADDING AN EXCEPTION
//!
//! Put the file in the relevant allowlist below WITH a reason. An allowlist
//! entry is a deliberate, reviewable decision. Deleting the check is not.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under src/.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("src"), &mut out);
    assert!(!out.is_empty(), "found no source files — is the test running from the crate root?");
    out
}

/// Strip `//` line comments so a builder mentioned in prose doesn't register
/// as a real call site. Block comments are rare here and deliberately not
/// handled — a false positive is a nudge to look, which is the safe direction.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            // Don't cut inside a string literal containing "//" (e.g. a URL).
            Some(i) if l[..i].matches('"').count() % 2 == 0 => &l[..i],
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// EVERY outbound HTTP client must bound its CONNECT, not just the request.
///
/// This is the rule that would have prevented the 2026-08-05 outage outright.
#[test]
fn every_http_client_bounds_its_connect() {
    // Reason required for each entry. These build a client from operator-
    // supplied per-request settings and are constructed per call rather than
    // held on a timer, so they cannot accumulate across poll cycles.
    const ALLOWED: &[(&str, &str)] = &[
        // (path fragment, why)
    ];

    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let src = strip_line_comments(&raw);
        let display = path.display().to_string();

        if ALLOWED.iter().any(|(frag, _)| display.contains(frag)) {
            continue;
        }

        // Find each builder chain and inspect it up to its .build().
        let mut idx = 0;
        while let Some(rel) = src[idx..].find("Client::builder()")
            .or_else(|| src[idx..].find("ClientBuilder::new()"))
        {
            let start = idx + rel;
            // A chain always terminates in .build(); cap the window so a
            // missing .build() can't swallow the rest of the file.
            let window_end = src[start..]
                .find(".build()")
                .map(|e| start + e + ".build()".len())
                .unwrap_or_else(|| (start + 2000).min(src.len()));
            let chain = &src[start..window_end];

            if !chain.contains(".connect_timeout(") {
                let line = src[..start].matches('\n').count() + 1;
                violations.push(format!("{}:{}", display, line));
            }
            idx = window_end.max(start + 1);
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: HTTP client without .connect_timeout() ═══\n\n\
         {} client builder(s) can hang on connect:\n  {}\n\n\
         A total `.timeout()` does NOT bound a connection that never establishes.\n\
         A SYN to an unroutable address holds a file descriptor for the kernel's\n\
         full retry window (~130s at tcp_syn_retries=6). Any client called on a\n\
         timer then stacks those until the descriptor table is exhausted — that\n\
         is exactly how the 2026-08-05 fleet meltdown happened (2,422 SYN-SENT,\n\
         2,868 CLOSE-WAIT, ~700 sockets/min, twelve nodes).\n\n\
         FIX: add `.connect_timeout(Duration::from_secs(3..5))` to the builder.\n\
         A connect timeout is never wrong — a peer that cannot answer a SYN in\n\
         five seconds is not going to serve the request either.\n\n\
         If an exception is genuinely justified, add the file to ALLOWED in\n\
         tests/resource_safety.rs WITH a reason.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// sysinfo's process refresh claims HALF of RLIMIT_NOFILE as a permanent
/// `/proc/<pid>/stat` handle cache. It must never run on a timer or at
/// construction — only on demand, for the one endpoint that wants a process
/// list.
#[test]
fn sysinfo_never_refreshes_processes_off_demand() {
    // `top_processes()` is the ONLY legitimate caller: it backs
    // GET /api/metrics/processes, refreshes when asked, and is not on a timer.
    const ALLOWED_FN: &str = "pub fn top_processes";

    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let src = strip_line_comments(&raw);
        let display = path.display().to_string();

        for pattern in ["System::new_all(", "refresh_all(", "refresh_processes("] {
            let mut idx = 0;
            while let Some(rel) = src[idx..].find(pattern) {
                let at = idx + rel;
                // Allowed only inside top_processes().
                let inside_allowed = src[..at]
                    .rfind(ALLOWED_FN)
                    .map(|f| !src[f..at].contains("\n    pub fn ") && !src[f..at].contains("\n    fn "))
                    .unwrap_or(false);
                if !inside_allowed {
                    let line = src[..at].matches('\n').count() + 1;
                    violations.push(format!("{}:{} — {}", display, line, pattern));
                }
                idx = at + pattern.len();
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: sysinfo process refresh off the demand path ═══\n\n\
         {} occurrence(s):\n  {}\n\n\
         sysinfo's Linux backend keeps an OPEN /proc/<pid>/stat handle per\n\
         process (`stat_file: Option<FileCounter>`) and budgets itself HALF of\n\
         RLIMIT_NOFILE for that cache — it raises our soft limit to the hard\n\
         limit first to get it. At LimitNOFILE=65535 that is 32,767 descriptors\n\
         claimed before a single metric is read, and on a host with 50,766\n\
         threads the scan alone cost ~390% CPU every 30 seconds.\n\n\
         `System::new_all()` and `refresh_all()` both mean RefreshKind::everything(),\n\
         which INCLUDES processes — they are not safe alternatives.\n\n\
         FIX: refresh only what you read (`refresh_cpu_all`, `refresh_memory`).\n\
         For a process COUNT use monitoring::count_processes(), which reads\n\
         /proc directly and opens nothing. Only top_processes() may refresh the\n\
         full list, on demand.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// A full process scan must be RATE-LIMITED, not merely "on demand".
///
/// v25.10.4 moved `refresh_processes` off the metrics loop and left
/// `top_processes()` as the sole caller, reasoning that an on-demand endpoint
/// is safe. It is not. `startProcessPolling()` in web/js/app.js polls
/// GET /api/metrics/processes every 15 SECONDS while the dashboard is open —
/// a FASTER timer than the 30s loop that was removed. Anyone parked on the
/// dashboard reinstated the whole fault, four scans a minute, once per viewer
/// (reported by JJ, 2026-08-06: nodes at 100% CPU on a version that was
/// supposed to have fixed exactly this).
///
/// The lesson generalises: "on demand" means nothing when a UI timer is the
/// demand. Any path that can walk every process must carry its own cache, so
/// the cost is bounded by the clock rather than by client behaviour.
#[test]
fn process_scans_are_rate_limited() {
    let src = fs::read_to_string("src/monitoring/mod.rs")
        .expect("monitoring/mod.rs must exist");

    assert!(
        src.contains("TOP_PROC_CACHE") && src.contains("TOP_PROC_TTL"),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: unbounded process scan ═══\n\n\
         top_processes() has lost its cache (TOP_PROC_CACHE / TOP_PROC_TTL).\n\n\
         The dashboard polls /api/metrics/processes every 15 seconds PER VIEWER.\n\
         Without a server-side cache, every poll walks every process on the box\n\
         and re-claims sysinfo's /proc/<pid>/stat handle cache (half of\n\
         RLIMIT_NOFILE). That is how v25.10.4 still pegged user nodes at 100%\n\
         CPU after the metrics-loop scan had been removed.\n\n\
         FIX: keep the TTL cache. Do not make the scan cheaper-looking by\n\
         removing it.\n",
    );

    // The scan must run on a throwaway System so its descriptors are freed.
    let scan_fn = src
        .split("pub fn top_processes")
        .nth(1)
        .expect("top_processes must exist");
    let body = &scan_fn[..scan_fn.find("\n    }").unwrap_or(scan_fn.len())];
    assert!(
        body.contains("System::new()") && !body.contains("self.sys.refresh_processes"),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: process scan on the long-lived System ═══\n\n\
         top_processes() must scan a THROWAWAY `System::new()`, never\n\
         `self.sys`. sysinfo holds an open /proc/<pid>/stat handle per process\n\
         for the lifetime of the System it scanned with — on the shared monitor\n\
         those descriptors are permanent (32,767 on a busy host). Scoped to a\n\
         temporary System they are released when it drops.\n",
    );
}
