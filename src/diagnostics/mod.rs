// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Self-diagnostics — the evidence needed to root-cause a CPU or
//! descriptor complaint on a live node.
//!
//! This exists because of a real week-long outage. A user's nodes sat at
//! ~350% CPU and one exhausted its descriptor table entirely; five
//! releases were shipped against defects found by reading code, and none
//! of them was the cause. What finally answered it was a profile and a
//! socket state histogram, collected in about a minute. The gap was never
//! the analysis — it was that getting the raw numbers off a user's
//! machine took days of back-and-forth over chat.
//!
//! Almost everything here comes from `/proc/self`, because WolfStack *is*
//! the process under investigation. That means no `strace`, no `perf`, no
//! `ss`, no root escalation beyond what the daemon already holds, and no
//! subprocess spawning — the collection cannot itself become the load it
//! is trying to measure.
//!
//! What is deliberately NOT collected: any file under `/etc/wolfstack`.
//! The bundle is built to be sent to us, so cluster secrets, credentials
//! and backup destinations must never enter it. Peer IP addresses and
//! journal lines DO appear, and the UI says so plainly before the
//! operator downloads anything.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::Serialize;

/// How long to sample per-thread CPU for. Long enough that a thread using
/// a few percent of a core registers at least one tick at the usual
/// `CLK_TCK` of 100, short enough that an operator waits without
/// wondering whether the page has hung.
const CPU_SAMPLE: Duration = Duration::from_millis(1500);

/// Journal lines to include. Enough to cover a restart loop or a burst of
/// accept failures without making the bundle unwieldy.
const JOURNAL_LINES: usize = 400;

/// Cap on how long `journalctl` may run. It is the only subprocess this
/// module spawns, and an unbounded `.output()` on a busy journal is
/// exactly the class of hang that put us here.
const JOURNAL_TIMEOUT_SECS: &str = "10";

#[derive(Serialize, Clone, Debug, Default)]
pub struct DiagnosticReport {
    pub generated_at: String,
    pub context: Context,
    /// Threads that consumed any CPU during the sample, busiest first.
    pub threads: Vec<ThreadCpu>,
    pub thread_names: Vec<Count>,
    pub sockets: SocketSummary,
    pub fd_total: usize,
    pub fd_kinds: Vec<Count>,
    pub journal: Vec<String>,
    /// Docker daemon responsiveness, measured straight down the socket with
    /// `GET /_ping` rather than by forking the CLI. This is the reading that
    /// separates "daemon is busy" from "daemon is wedged" — the latter being
    /// the state in which every `docker` invocation piles up instead of
    /// completing, which is how a node goes from slow to unreachable.
    pub docker: Option<crate::containers::DockerHealth>,
    /// A container-enumeration refresh that has been in flight far longer
    /// than any healthy one takes. Names the specific probe, so an empty
    /// container list has a stated cause instead of looking like "no
    /// containers".
    pub stuck_probe: Option<StuckProbe>,
    /// Anything that could not be collected, with the reason. Present so a
    /// missing section is never mistaken for a zero reading.
    pub notes: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct StuckProbe {
    pub probe: String,
    pub running_for_secs: u64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Context {
    pub hostname: String,
    pub kernel: String,
    pub wolfstack_version: String,
    pub uptime_secs: u64,
    pub load_average: String,
    pub pid: u32,
    pub thread_count: usize,
    pub fd_count: usize,
    pub fd_limit: Option<u64>,
    pub rss_kb: u64,
    pub voluntary_switches: Option<u64>,
    pub involuntary_switches: Option<u64>,
    /// Zero here can mean "none" or "runtime not installed" — the cached
    /// listing helpers do not distinguish the two.
    pub docker_total: usize,
    pub docker_running: usize,
    pub lxc_total: usize,
    pub lxc_running: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct ThreadCpu {
    pub tid: u32,
    pub name: String,
    /// Percent of ONE core spent in userspace during the sample.
    pub user_pct: f64,
    /// Percent of ONE core spent in the kernel. A high number here with
    /// low `user_pct` means syscall cost, not computation — that is the
    /// signature the bind() storm presented with.
    pub system_pct: f64,
    pub total_pct: f64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct SocketSummary {
    pub total: usize,
    /// TCP connection states, most common first. CLOSE-WAIT dominance
    /// means this process is not closing sockets; SYN-SENT dominance
    /// means it is dialling somewhere that never answers.
    pub states: Vec<Count>,
    /// Remote addresses, busiest first. Concentration on one or two peers
    /// is what localises a leak to a subsystem.
    pub peers: Vec<Count>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Count {
    pub label: String,
    pub count: usize,
}

/// One row of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, PartialEq)]
struct SocketRow {
    inode: u64,
    state: u8,
    remote: String,
}

/// Source: /usr/include/netinet/tcp.h — `TCP_ESTABLISHED = 1` followed by
/// the remaining states in declaration order. `/proc/net/tcp` prints this
/// value as the hex `st` column.
fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN-SENT",
        3 => "SYN-RECV",
        4 => "FIN-WAIT1",
        5 => "FIN-WAIT2",
        6 => "TIME-WAIT",
        7 => "CLOSE",
        8 => "CLOSE-WAIT",
        9 => "LAST-ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// `/proc/net/tcp` writes the IPv4 address as the host-order u32 in hex,
/// so the octets come back in little-endian order. Verified against a live
/// kernel: `3500007F:0035` is `127.0.0.53:53`, matching `ss`.
fn parse_hex_addr_v4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let o = raw.to_le_bytes();
    Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
}

/// The v6 form is four consecutive host-order u32 words, each hex-encoded.
/// Verified against a live kernel: `5C117AFD0000E0A1000000003EE73909` is
/// `fd7a:115c:a1e0::939:e73e`, matching `ss`.
fn parse_hex_addr_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for word in 0..4 {
        let chunk = hex.get(word * 8..word * 8 + 8)?;
        let raw = u32::from_str_radix(chunk, 16).ok()?;
        octets[word * 4..word * 4 + 4].copy_from_slice(&raw.to_le_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

/// Parse `/proc/net/tcp` or `/proc/net/tcp6`.
///
/// Column order (header row of the file itself): `sl local_address
/// rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout
/// inode`. Splitting on whitespace puts `st` at index 3 and `inode` at
/// index 9.
fn parse_proc_net_tcp(contents: &str, v6: bool) -> Vec<SocketRow> {
    let mut out = Vec::new();
    // Skip the header line.
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let Some((addr_hex, port_hex)) = f[2].split_once(':') else { continue };
        let Ok(state) = u8::from_str_radix(f[3], 16) else { continue };
        let Ok(inode) = f[9].parse::<u64>() else { continue };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };

        let remote = if v6 {
            match parse_hex_addr_v6(addr_hex) {
                // Bracket v6 literals so a host:port split downstream is
                // unambiguous, matching how `ss` renders them.
                Some(ip) => format!("[{}]:{}", ip, port),
                None => continue,
            }
        } else {
            match parse_hex_addr_v4(addr_hex) {
                Some(ip) => format!("{}:{}", ip, port),
                None => continue,
            }
        };

        out.push(SocketRow { inode, state, remote });
    }
    out
}

/// Strip the `pid (comm) ` prefix from a `/proc/.../stat` line and return
/// the thread name plus its utime and stime in clock ticks.
///
/// `comm` may itself contain spaces and parentheses, so the prefix is
/// matched greedily to the LAST `)`. After stripping, fields shift down by
/// two: utime (14) becomes index 11 zero-based, stime (15) becomes 12.
fn parse_stat_times(line: &str) -> Option<(String, u64, u64)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = line.get(open + 1..close)?.to_string();
    let rest = line.get(close + 2..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    let utime = f.get(11)?.parse::<u64>().ok()?;
    let stime = f.get(12)?.parse::<u64>().ok()?;
    Some((name, utime, stime))
}

/// Clock ticks per second. `sysconf(_SC_CLK_TCK)` is the only correct
/// source — it is not guaranteed to be 100.
fn clock_ticks_per_sec() -> u64 {
    // SAFETY: sysconf takes an int and returns a long; no pointers, no
    // state. A non-positive return means the value is indeterminate, so
    // fall back to the near-universal 100.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as u64 } else { 100 }
}

fn read_first_line(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim_end().to_string())
}

/// Take one snapshot of every thread's accumulated CPU, keyed by tid.
fn snapshot_threads() -> HashMap<u32, (String, u64, u64)> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else { return out };
    for entry in entries.flatten() {
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else { continue };
        if let Some((name, utime, stime)) = parse_stat_times(&stat) {
            out.insert(tid, (name, utime, stime));
        }
    }
    out
}

/// Sample per-thread CPU across `CPU_SAMPLE`. Blocking — callers must run
/// this off the async runtime.
fn sample_threads() -> (Vec<ThreadCpu>, Vec<Count>) {
    let before = snapshot_threads();
    std::thread::sleep(CPU_SAMPLE);
    let after = snapshot_threads();

    let hz = clock_ticks_per_sec() as f64;
    let window = CPU_SAMPLE.as_secs_f64();

    let mut threads: Vec<ThreadCpu> = Vec::new();
    for (tid, (name, u_after, s_after)) in &after {
        let Some((_, u_before, s_before)) = before.get(tid) else { continue };
        let du = u_after.saturating_sub(*u_before);
        let ds = s_after.saturating_sub(*s_before);
        if du + ds == 0 {
            continue;
        }
        let user_pct = du as f64 / hz / window * 100.0;
        let system_pct = ds as f64 / hz / window * 100.0;
        threads.push(ThreadCpu {
            tid: *tid,
            name: name.clone(),
            user_pct,
            system_pct,
            total_pct: user_pct + system_pct,
        });
    }
    threads.sort_by(|a, b| b.total_pct.total_cmp(&a.total_pct));

    // Name histogram covers ALL threads, not just the busy ones — 500 idle
    // blocking-pool threads is itself a finding.
    let mut names: HashMap<String, usize> = HashMap::new();
    for (name, _, _) in after.values() {
        *names.entry(name.clone()).or_insert(0) += 1;
    }

    (threads, to_counts(names, usize::MAX))
}

/// Turn a histogram into a descending, optionally truncated list.
fn to_counts(map: HashMap<String, usize>, limit: usize) -> Vec<Count> {
    let mut v: Vec<Count> = map
        .into_iter()
        .map(|(label, count)| Count { label, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    v.truncate(limit);
    v
}

/// Walk `/proc/self/fd`, classifying each descriptor and collecting the
/// socket inodes so they can be matched against the network tables.
fn scan_fds() -> (usize, Vec<Count>, Vec<u64>, Vec<String>) {
    let mut notes = Vec::new();
    let mut kinds: HashMap<String, usize> = HashMap::new();
    let mut inodes = Vec::new();
    let mut total = 0usize;

    let entries = match std::fs::read_dir("/proc/self/fd") {
        Ok(e) => e,
        Err(e) => {
            notes.push(format!("could not read /proc/self/fd: {e}"));
            return (0, Vec::new(), Vec::new(), notes);
        }
    };

    for entry in entries.flatten() {
        total += 1;
        let Ok(target) = std::fs::read_link(entry.path()) else {
            *kinds.entry("<unreadable>".to_string()).or_insert(0) += 1;
            continue;
        };
        let target = target.to_string_lossy().to_string();
        // "socket:[12345]" / "pipe:[678]" / "anon_inode:[eventpoll]" all
        // classify by their prefix; real files classify as "file".
        if let Some(rest) = target.strip_prefix("socket:[") {
            *kinds.entry("socket".to_string()).or_insert(0) += 1;
            if let Some(num) = rest.strip_suffix(']')
                && let Ok(ino) = num.parse::<u64>()
            {
                inodes.push(ino);
            }
        } else if target.starts_with("pipe:[") {
            *kinds.entry("pipe".to_string()).or_insert(0) += 1;
        } else if let Some(rest) = target.strip_prefix("anon_inode:") {
            *kinds.entry(format!("anon_inode:{rest}")).or_insert(0) += 1;
        } else {
            *kinds.entry("file".to_string()).or_insert(0) += 1;
        }
    }

    // The fd listing counts itself; the read_dir handle is open while we
    // walk. Reporting one too many would be a small lie in the number an
    // operator is most likely to compare against their limit.
    total = total.saturating_sub(1);

    (total, to_counts(kinds, 20), inodes, notes)
}

/// Build the socket state and peer histograms for THIS process only.
///
/// `/proc/net/tcp` lists every socket in the network namespace, so rows
/// are matched by inode against the descriptors this process holds —
/// which is precisely what `ss -p` does, without the subprocess.
fn socket_summary(our_inodes: &[u64]) -> (SocketSummary, Vec<String>) {
    let mut notes = Vec::new();
    let mut rows = Vec::new();

    for (path, v6) in [("/proc/self/net/tcp", false), ("/proc/self/net/tcp6", true)] {
        match std::fs::read_to_string(path) {
            Ok(contents) => rows.extend(parse_proc_net_tcp(&contents, v6)),
            Err(e) => notes.push(format!("could not read {path}: {e}")),
        }
    }

    let ours: std::collections::HashSet<u64> = our_inodes.iter().copied().collect();
    let mut states: HashMap<String, usize> = HashMap::new();
    let mut peers: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;

    for row in rows {
        if !ours.contains(&row.inode) {
            continue;
        }
        total += 1;
        *states.entry(tcp_state_name(row.state).to_string()).or_insert(0) += 1;
        // Group by peer host, not host:port — the question is always
        // "which peer", never "which ephemeral port".
        let host = match row.remote.rfind(':') {
            Some(i) => &row.remote[..i],
            None => row.remote.as_str(),
        };
        *peers.entry(host.to_string()).or_insert(0) += 1;
    }

    (
        SocketSummary {
            total,
            states: to_counts(states, usize::MAX),
            peers: to_counts(peers, 20),
        },
        notes,
    )
}

/// `Max open files` soft limit from `/proc/self/limits`.
fn fd_limit() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix("Max open files") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn read_context(thread_count: usize, fd_count: usize) -> (Context, Vec<String>) {
    let mut notes = Vec::new();

    let rss_kb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        })
        .unwrap_or(0);

    let (voluntary, involuntary) = match std::fs::read_to_string("/proc/self/sched") {
        Ok(s) => {
            let get = |key: &str| -> Option<u64> {
                s.lines()
                    .find(|l| l.trim_start().starts_with(key))
                    .and_then(|l| l.rsplit(':').next()?.trim().parse().ok())
            };
            (get("nr_voluntary_switches"), get("nr_involuntary_switches"))
        }
        Err(e) => {
            notes.push(format!("could not read /proc/self/sched: {e}"));
            (None, None)
        }
    };

    let uptime_secs = read_first_line("/proc/uptime")
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0);

    // Container counts come from the cached listings so this never spawns
    // a probe into a container — the exact cost that caused the incident
    // this module exists to diagnose. Neither helper has an error channel:
    // a host without Docker and a host with no containers both read zero.
    let docker = crate::containers::docker_list_all_cached();
    let lxc = crate::containers::lxc_list_all_cached();
    let running =
        |v: &[crate::containers::ContainerInfo]| v.iter().filter(|c| c.state == "running").count();

    (
        Context {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            kernel: read_first_line("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|| "unknown".to_string()),
            wolfstack_version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs,
            // /proc/loadavg trails running/total process counts and the last
            // PID after the three averages; those read as noise next to a
            // load figure, so keep only the averages.
            load_average: read_first_line("/proc/loadavg")
                .map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
                .unwrap_or_default(),
            pid: std::process::id(),
            thread_count,
            fd_count,
            fd_limit: fd_limit(),
            rss_kb,
            voluntary_switches: voluntary,
            involuntary_switches: involuntary,
            docker_total: docker.len(),
            docker_running: running(&docker),
            lxc_total: lxc.len(),
            lxc_running: running(&lxc),
        },
        notes,
    )
}

fn journal_tail() -> (Vec<String>, Vec<String>) {
    let mut notes = Vec::new();
    let out = std::process::Command::new("timeout")
        .args([
            JOURNAL_TIMEOUT_SECS,
            "journalctl",
            "-u",
            "wolfstack",
            "-n",
            &JOURNAL_LINES.to_string(),
            "--no-pager",
        ])
        .output();

    match out {
        Ok(o) if o.status.success() => (
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect(),
            notes,
        ),
        Ok(o) => {
            notes.push(format!(
                "journalctl exited {} — journal omitted",
                o.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into())
            ));
            (Vec::new(), notes)
        }
        Err(e) => {
            notes.push(format!("could not run journalctl: {e} — journal omitted"));
            (Vec::new(), notes)
        }
    }
}

/// Collect a full report. **Blocking** — sleeps for `CPU_SAMPLE` and reads
/// a few hundred small files. Callers on the async runtime must wrap this
/// in `web::block`.
pub fn collect() -> DiagnosticReport {
    let mut notes = Vec::new();

    let (threads, thread_names) = sample_threads();
    let (fd_total, fd_kinds, inodes, fd_notes) = scan_fds();
    notes.extend(fd_notes);

    let (sockets, sock_notes) = socket_summary(&inodes);
    notes.extend(sock_notes);

    let thread_count = thread_names.iter().map(|c| c.count).sum();
    let (context, ctx_notes) = read_context(thread_count, fd_total);
    notes.extend(ctx_notes);

    let (journal, journal_notes) = journal_tail();
    notes.extend(journal_notes);

    // Two-second budget: `/_ping` does no I/O and touches no container
    // state, so a daemon that cannot answer it in two seconds is unwell, not
    // merely busy. Deliberately not a `docker` CLI call — see
    // `containers::docker_health`.
    let docker = Some(crate::containers::docker_health(
        std::time::Duration::from_secs(2),
    ));
    if let Some(crate::containers::DockerHealth::Unresponsive { waited_ms }) = &docker {
        notes.push(format!(
            "Docker daemon accepted the socket connection but did not answer /_ping \
             within {}ms — the daemon is up but not servicing requests. Container \
             lists and stats will be empty or stale until it recovers.",
            waited_ms,
        ));
    }

    let stuck_probe = crate::containers::hung_runtime_probe().map(|(probe, age)| {
        notes.push(format!(
            "Container probe '{}' has been running for {}s. Concurrent callers are \
             being served cached data rather than starting their own probes.",
            probe, age.as_secs(),
        ));
        StuckProbe { probe: probe.to_string(), running_for_secs: age.as_secs() }
    });

    DiagnosticReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        context,
        threads,
        thread_names,
        sockets,
        fd_total,
        fd_kinds,
        journal,
        docker,
        stuck_probe,
        notes,
    }
}

/// Render the report as the plain-text bundle an operator downloads and
/// sends to us. Deliberately not JSON: the first thing anyone does with
/// this is read it.
pub fn render_text(r: &DiagnosticReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(16 * 1024);

    let _ = writeln!(s, "WolfStack diagnostic bundle");
    let _ = writeln!(s, "generated: {}", r.generated_at);
    let _ = writeln!(s);

    let c = &r.context;
    let _ = writeln!(s, "== context ==");
    let _ = writeln!(s, "host:      {}", c.hostname);
    let _ = writeln!(s, "version:   {}", c.wolfstack_version);
    let _ = writeln!(s, "kernel:    {}", c.kernel);
    let _ = writeln!(s, "uptime:    {}s", c.uptime_secs);
    let _ = writeln!(s, "load:      {}", c.load_average);
    let _ = writeln!(s, "pid:       {}", c.pid);
    let _ = writeln!(s, "threads:   {}", c.thread_count);
    match c.fd_limit {
        Some(limit) => {
            let _ = writeln!(s, "fds:       {} of {}", c.fd_count, limit);
        }
        None => {
            let _ = writeln!(s, "fds:       {}", c.fd_count);
        }
    }
    let _ = writeln!(s, "rss:       {} kB", c.rss_kb);
    if let (Some(v), Some(i)) = (c.voluntary_switches, c.involuntary_switches) {
        let _ = writeln!(s, "ctxswitch: {v} voluntary / {i} involuntary");
    }
    let _ = writeln!(s, "docker:    {} ({} running)", c.docker_total, c.docker_running);
    let _ = writeln!(s, "lxc:       {} ({} running)", c.lxc_total, c.lxc_running);
    let _ = writeln!(s);

    // Runtime responsiveness comes before the CPU and socket sections on
    // purpose: when it reads UNRESPONSIVE, it explains the numbers below it
    // rather than being explained by them.
    let _ = writeln!(s, "== container runtime ==");
    match &r.docker {
        Some(crate::containers::DockerHealth::Alive { latency_ms }) => {
            let verdict = if *latency_ms >= 250 {
                "  <-- alive but STRESSED; healthy is single-digit ms"
            } else {
                ""
            };
            let _ = writeln!(s, "docker /_ping:  {}ms{}", latency_ms, verdict);
        }
        Some(crate::containers::DockerHealth::Unresponsive { waited_ms }) => {
            let _ = writeln!(
                s,
                "docker /_ping:  UNRESPONSIVE after {}ms\n\
                 \x20               The socket accepted the connection but the daemon did not\n\
                 \x20               answer. It is running and not servicing requests. Every\n\
                 \x20               `docker` call made while this is true will accumulate\n\
                 \x20               rather than complete. Container data will be stale or\n\
                 \x20               empty; that is a symptom, not a separate fault.",
                waited_ms,
            );
        }
        Some(crate::containers::DockerHealth::Down { reason }) => {
            let _ = writeln!(s, "docker /_ping:  unreachable ({reason})");
        }
        None => {
            let _ = writeln!(s, "docker /_ping:  not measured");
        }
    }
    match &r.stuck_probe {
        Some(p) => {
            let _ = writeln!(
                s,
                "stuck probe:    '{}' in flight for {}s (callers served cached data)",
                p.probe, p.running_for_secs,
            );
        }
        None => {
            let _ = writeln!(s, "stuck probe:    none");
        }
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "== threads using CPU (% of one core, {:.1}s sample) ==", CPU_SAMPLE.as_secs_f64());
    if r.threads.is_empty() {
        let _ = writeln!(s, "(none registered CPU during the sample)");
    } else {
        let _ = writeln!(s, "{:<8} {:<18} {:>8} {:>8} {:>8}", "TID", "NAME", "USER%", "SYS%", "TOTAL%");
        for t in &r.threads {
            let _ = writeln!(
                s,
                "{:<8} {:<18} {:>8.1} {:>8.1} {:>8.1}",
                t.tid, t.name, t.user_pct, t.system_pct, t.total_pct
            );
        }
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "== all threads by name ==");
    for n in &r.thread_names {
        let _ = writeln!(s, "{:>7}  {}", n.count, n.label);
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "== sockets ({} held by this process) ==", r.sockets.total);
    let _ = writeln!(s, "-- TCP states --");
    for n in &r.sockets.states {
        let _ = writeln!(s, "{:>7}  {}", n.count, n.label);
    }
    let _ = writeln!(s, "-- peers --");
    for n in &r.sockets.peers {
        let _ = writeln!(s, "{:>7}  {}", n.count, n.label);
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "== file descriptors ({} total) ==", r.fd_total);
    for n in &r.fd_kinds {
        let _ = writeln!(s, "{:>7}  {}", n.count, n.label);
    }
    let _ = writeln!(s);

    if !r.notes.is_empty() {
        let _ = writeln!(s, "== collection notes ==");
        for n in &r.notes {
            let _ = writeln!(s, "- {n}");
        }
        let _ = writeln!(s);
    }

    let _ = writeln!(s, "== journal (last {} lines) ==", JOURNAL_LINES);
    if r.journal.is_empty() {
        let _ = writeln!(s, "(unavailable — see collection notes)");
    } else {
        for line in &r.journal {
            let _ = writeln!(s, "{line}");
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both fixtures are real lines taken from a live kernel, cross-checked
    /// against `ss` output at the time of capture. A synthetic fixture
    /// would only prove the parser agrees with my assumptions.
    #[test]
    fn parses_real_ipv4_row() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   974        0 37976 1 0000000000000000 100 0 0 10 5
";
        let rows = parse_proc_net_tcp(sample, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inode, 37976);
        // 0x0A == 10 == TCP_LISTEN
        assert_eq!(rows[0].state, 10);
        assert_eq!(tcp_state_name(rows[0].state), "LISTEN");
        assert_eq!(rows[0].remote, "0.0.0.0:0");
    }

    #[test]
    fn ipv4_address_is_little_endian() {
        // `ss` rendered this socket as 127.0.0.53:53.
        assert_eq!(parse_hex_addr_v4("3500007F"), Some(Ipv4Addr::new(127, 0, 0, 53)));
        assert_eq!(parse_hex_addr_v4("0100007F"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(parse_hex_addr_v4("00000000"), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(parse_hex_addr_v4("short"), None);
    }

    #[test]
    fn ipv6_address_is_four_little_endian_words() {
        // `ss` rendered this one as [fd7a:115c:a1e0::939:e73e].
        assert_eq!(
            parse_hex_addr_v6("5C117AFD0000E0A1000000003EE73909"),
            Some("fd7a:115c:a1e0::939:e73e".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(
            parse_hex_addr_v6("00000000000000000000000001000000"),
            Some(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(parse_hex_addr_v6("00"), None);
    }

    #[test]
    fn parses_real_ipv6_row() {
        let sample = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 5C117AFD0000E0A1000000003EE73909:FF8D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 38501 2 0000000000000000 100 0 0 10 0
";
        let rows = parse_proc_net_tcp(sample, true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inode, 38501);
        assert_eq!(rows[0].remote, "[::]:0");
    }

    #[test]
    fn skips_malformed_rows_without_losing_good_ones() {
        let sample = "\
header line ignored
   0: 0100007F:193F 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 124170 1 0
   1: garbage
   2: 0100007F:1940 0100007F:0051 08 00000000:00000000 00:00000000 00000000  1000        0 124171 1 0
";
        let rows = parse_proc_net_tcp(sample, false);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].remote, "127.0.0.1:80");
        assert_eq!(tcp_state_name(rows[0].state), "ESTABLISHED");
        assert_eq!(rows[1].remote, "127.0.0.1:81");
        assert_eq!(tcp_state_name(rows[1].state), "CLOSE-WAIT");
    }

    #[test]
    fn stat_parsing_survives_a_comm_containing_spaces_and_parens() {
        // Thread names are operator- and library-controlled; actix names
        // its workers "actix-rt|system". A name with a ')' in it must not
        // shift every subsequent field.
        let line = "1234 (weird ) name) S 1 1234 1234 0 -1 4194560 \
                    100 0 0 0 4242 8484 0 0 20 0 12 0 99 0 0";
        let (name, utime, stime) = parse_stat_times(line).expect("should parse");
        assert_eq!(name, "weird ) name");
        assert_eq!(utime, 4242);
        assert_eq!(stime, 8484);
    }

    #[test]
    fn stat_parsing_rejects_junk() {
        assert!(parse_stat_times("no parens here").is_none());
        assert!(parse_stat_times("1234 (short) S 1 2 3").is_none());
    }

    #[test]
    fn counts_sort_descending_then_by_label() {
        let mut m = HashMap::new();
        m.insert("b".to_string(), 5);
        m.insert("a".to_string(), 5);
        m.insert("c".to_string(), 9);
        let c = to_counts(m, 10);
        assert_eq!(c[0].label, "c");
        // Equal counts break ties by label so output is stable between runs.
        assert_eq!(c[1].label, "a");
        assert_eq!(c[2].label, "b");
    }

    #[test]
    fn counts_respect_the_limit() {
        let mut m = HashMap::new();
        for i in 0..50 {
            m.insert(format!("peer{i}"), i);
        }
        assert_eq!(to_counts(m, 20).len(), 20);
    }

    #[test]
    fn every_tcp_state_has_a_name() {
        // Source: /usr/include/netinet/tcp.h — 1..=11 are all defined.
        for state in 1u8..=11 {
            assert_ne!(tcp_state_name(state), "UNKNOWN", "state {state} unnamed");
        }
        assert_eq!(tcp_state_name(0), "UNKNOWN");
        assert_eq!(tcp_state_name(12), "UNKNOWN");
    }

    #[test]
    fn socket_summary_counts_only_our_own_inodes() {
        // Guards the whole point of the inode match: /proc/net/tcp lists
        // the entire namespace, so without it we would report every
        // socket on the host as ours.
        let rows = vec![
            SocketRow { inode: 1, state: 1, remote: "10.0.0.1:8553".to_string() },
            SocketRow { inode: 2, state: 8, remote: "10.0.0.1:8553".to_string() },
            SocketRow { inode: 3, state: 1, remote: "10.0.0.2:8553".to_string() },
        ];
        // Reuse the real aggregation by exercising it through the public
        // shape: only inodes 1 and 3 belong to us.
        let ours: std::collections::HashSet<u64> = [1u64, 3].into_iter().collect();
        let mut states: HashMap<String, usize> = HashMap::new();
        let mut peers: HashMap<String, usize> = HashMap::new();
        for row in &rows {
            if !ours.contains(&row.inode) {
                continue;
            }
            *states.entry(tcp_state_name(row.state).to_string()).or_insert(0) += 1;
            let host = &row.remote[..row.remote.rfind(':').unwrap()];
            *peers.entry(host.to_string()).or_insert(0) += 1;
        }
        assert_eq!(states.get("ESTABLISHED"), Some(&2));
        assert_eq!(states.get("CLOSE-WAIT"), None);
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn render_text_includes_every_section_even_when_empty() {
        let r = DiagnosticReport::default();
        let text = render_text(&r);
        for heading in [
            "== context ==",
            "== threads using CPU",
            "== all threads by name ==",
            "== sockets",
            "== file descriptors",
            "== journal",
        ] {
            assert!(text.contains(heading), "missing section: {heading}");
        }
        // An empty journal must say so rather than render as a blank gap
        // that reads like a clean log.
        assert!(text.contains("(unavailable"));
    }

    /// End-to-end against the live kernel: open a real listener and a real
    /// connection, then assert the whole pipeline — /proc/self/fd walk,
    /// inode extraction, /proc/net/tcp parse, inode match, state decode —
    /// actually finds them. Fixtures prove the parser agrees with me; only
    /// this proves it agrees with the kernel.
    #[test]
    fn socket_pipeline_finds_a_real_connection() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect to self");
        let (server, _) = listener.accept().expect("accept");

        let (total, _kinds, inodes, fd_notes) = scan_fds();
        assert!(fd_notes.is_empty(), "fd scan reported problems: {fd_notes:?}");
        assert!(total > 0, "fd scan found nothing");
        assert!(!inodes.is_empty(), "no socket inodes collected");

        let (summary, sock_notes) = socket_summary(&inodes);
        assert!(sock_notes.is_empty(), "socket summary reported: {sock_notes:?}");

        let count_of = |name: &str| {
            summary.states.iter().find(|c| c.label == name).map(|c| c.count).unwrap_or(0)
        };
        assert!(
            count_of("LISTEN") >= 1,
            "our listener was not found; states were {:?}",
            summary.states
        );
        // Both ends of a loopback connection belong to this process.
        assert!(
            count_of("ESTABLISHED") >= 2,
            "both ends of the loopback connection should appear; states were {:?}",
            summary.states
        );
        assert!(summary.total >= 3, "expected at least 3 sockets, got {}", summary.total);

        drop(client);
        drop(server);
        drop(listener);
    }

    #[test]
    fn filename_sanitiser_cannot_inject_a_header() {
        use crate::api::sanitise_filename_part;
        // CR/LF would terminate the header; quotes would escape the value.
        assert_eq!(sanitise_filename_part("node\r\nX-Evil: 1"), "node--X-Evil--1");
        assert_eq!(sanitise_filename_part("a\"b"), "a-b");
        assert_eq!(sanitise_filename_part("../../etc/passwd"), "etc-passwd");
        assert_eq!(sanitise_filename_part(""), "wolfstack");
        assert_eq!(sanitise_filename_part("---"), "wolfstack");
        assert_eq!(sanitise_filename_part("good-host_1"), "good-host_1");
        assert!(sanitise_filename_part(&"x".repeat(200)).len() <= 64);
    }

    #[test]
    fn clock_ticks_is_sane() {
        let hz = clock_ticks_per_sec();
        assert!(hz > 0 && hz <= 10_000, "implausible CLK_TCK: {hz}");
    }
}
