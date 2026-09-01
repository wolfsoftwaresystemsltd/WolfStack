// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Fleet Logs on-disk store: date-segmented JSONL, zstd-compacted once a day
//! is closed, with a tiny `.idx` sidecar per cold segment so searches can skip
//! whole segments without decompressing them. Plus the retention janitor.
//!
//! Layout (`paths::loghub_dir`):
//! ```text
//! <root>/<node>/<YYYY-MM-DD>/<source>.jsonl       (hot — today, appended to)
//! <root>/<node>/<YYYY-MM-DD>/<source>.jsonl.zst   (cold — closed day)
//! <root>/<node>/<YYYY-MM-DD>/<source>.idx         (cold sidecar, JSON)
//! ```

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{date_str, now_millis, LogEvent, LogHubState, LogHubStats};

/// How often the janitor runs (retention + disk circuit-breaker check).
const JANITOR_INTERVAL_SECS: u64 = 300;
/// zstd compression level for closed segments — 3 is a good ratio/speed balance.
const ZSTD_LEVEL: i32 = 3;
/// Cap on distinct units recorded in a segment index (keeps the sidecar small).
const MAX_IDX_UNITS: usize = 256;

/// Per-cold-segment index. Lets the query layer prune by time window and unit
/// without decompressing the segment body.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SegmentIndex {
    pub min_ts: i64,
    pub max_ts: i64,
    pub lines: u64,
    #[serde(default)]
    pub units: Vec<String>,
    #[serde(default)]
    pub levels: BTreeMap<String, u64>,
}

/// Restrict a node id (or any untrusted path component) to a safe filename.
/// Defence in depth — a node id arrives over the wire on ingest, so we never
/// let it introduce path separators or `..` traversal.
pub fn safe_component(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let cleaned = cleaned.trim_matches('.').to_string();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// Append a batch of events to the appropriate hot segments. Groups by
/// (node, date, source) so a mixed batch fans out to the right files in one
/// pass. Blocking I/O — call inside `web::block` from async contexts.
pub fn append_events(root: &str, events: &[LogEvent]) -> std::io::Result<usize> {
    if events.is_empty() {
        return Ok(0);
    }
    // Buffer per target file so we do one write() per segment.
    let mut groups: BTreeMap<(String, String, &'static str), String> = BTreeMap::new();
    for ev in events {
        let node = safe_component(&ev.node);
        let date = date_str(ev.ts);
        let line = match serde_json::to_string(ev) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let buf = groups.entry((node, date, ev.source.stem())).or_default();
        buf.push_str(&line);
        buf.push('\n');
    }
    let mut written = 0usize;
    for ((node, date, stem), buf) in groups {
        let dir = format!("{root}/{node}/{date}");
        std::fs::create_dir_all(&dir)?;
        let path = format!("{dir}/{stem}.jsonl");
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        f.write_all(buf.as_bytes())?;
        written += buf.lines().count();
    }
    Ok(written)
}

/// List immediate subdirectory names of `dir` (non-recursive). Returns names
/// only, never full paths. Empty on any error.
pub fn list_subdirs(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && let Some(name) = e.file_name().to_str()
            {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out
}

/// Read a cold segment's `.idx` sidecar, if present and parseable.
pub fn read_idx(date_dir: &str, stem: &str) -> Option<SegmentIndex> {
    let p = format!("{date_dir}/{stem}.idx");
    let s = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&s).ok()
}

/// Open a streaming line reader for a segment — the cold `.jsonl.zst`
/// (transparently decompressed) if present, else the hot `.jsonl`. Returns
/// `None` if neither exists. The reader decompresses lazily, so even a
/// multi-gigabyte segment is scanned with bounded memory.
pub fn open_segment_reader(date_dir: &str, stem: &str) -> Option<Box<dyn BufRead>> {
    let cold = format!("{date_dir}/{stem}.jsonl.zst");
    let hot = format!("{date_dir}/{stem}.jsonl");
    if std::path::Path::new(&cold).exists() {
        let f = std::fs::File::open(&cold).ok()?;
        let dec = zstd::stream::read::Decoder::new(BufReader::new(f)).ok()?;
        Some(Box::new(BufReader::new(dec)))
    } else if std::path::Path::new(&hot).exists() {
        let f = std::fs::File::open(&hot).ok()?;
        Some(Box::new(BufReader::new(f)))
    } else {
        None
    }
}

/// Build a `SegmentIndex` by streaming a segment's lines (bounded memory).
fn build_index<R: BufRead>(reader: R) -> SegmentIndex {
    let mut idx = SegmentIndex {
        min_ts: i64::MAX,
        max_ts: i64::MIN,
        ..Default::default()
    };
    let mut units: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<LogEvent>(&line) {
            idx.lines += 1;
            idx.min_ts = idx.min_ts.min(ev.ts);
            idx.max_ts = idx.max_ts.max(ev.ts);
            if units.len() < MAX_IDX_UNITS {
                units.insert(ev.unit.clone());
            }
            let lvl = serde_json::to_value(ev.level)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".into());
            *idx.levels.entry(lvl).or_insert(0) += 1;
        }
    }
    if idx.lines == 0 {
        idx.min_ts = 0;
        idx.max_ts = 0;
    }
    idx.units = units.into_iter().collect();
    idx
}

/// Compress every closed-day hot segment (`<source>.jsonl` for any date before
/// `today`) into `<source>.jsonl.zst` + `<source>.idx`, then remove the hot
/// file. Idempotent — already-compacted segments are skipped. Returns the
/// number of segments compacted.
fn compress_closed_segments(root: &str, today: &str) -> u64 {
    let mut compacted = 0u64;
    for node in list_subdirs(root) {
        let node_dir = format!("{root}/{node}");
        for date in list_subdirs(&node_dir) {
            // Never touch today's (or a future-dated, clock-skewed) segment —
            // it's the active append target.
            if date.as_str() >= today {
                continue;
            }
            let date_dir = format!("{node_dir}/{date}");
            let entries = match std::fs::read_dir(&date_dir) {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let stem = match name.strip_suffix(".jsonl") {
                    Some(s) => s.to_string(),
                    None => continue, // skip .zst / .idx / anything else
                };
                let hot = format!("{date_dir}/{name}");
                // 1. Build the index by streaming the hot file (bounded memory).
                let idx = match std::fs::File::open(&hot) {
                    Ok(f) => build_index(BufReader::new(f)),
                    Err(_) => continue,
                };
                // 2. Compress hot -> cold.tmp by streaming (never loads the
                //    whole file — a busy day's segment can be multi-GB).
                let cold_tmp = format!("{date_dir}/{stem}.jsonl.zst.tmp");
                let cold = format!("{date_dir}/{stem}.jsonl.zst");
                let src = match std::fs::File::open(&hot) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let dst = match std::fs::File::create(&cold_tmp) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                if zstd::stream::copy_encode(src, dst, ZSTD_LEVEL).is_err() {
                    let _ = std::fs::remove_file(&cold_tmp);
                    continue;
                }
                if std::fs::rename(&cold_tmp, &cold).is_err() {
                    let _ = std::fs::remove_file(&cold_tmp);
                    continue;
                }
                // 3. Write the index sidecar; non-fatal if it fails (search
                //    falls back to scanning the segment without pruning).
                if let Ok(j) = serde_json::to_string(&idx) {
                    let _ = std::fs::write(format!("{date_dir}/{stem}.idx"), j);
                }
                // 4. Hot file is now redundant.
                let _ = std::fs::remove_file(&hot);
                compacted += 1;
            }
        }
    }
    compacted
}

/// Recursive byte size of a directory tree. Best-effort (skips unreadable
/// entries).
pub fn dir_size(path: &str) -> u64 {
    let mut total = 0u64;
    let rd = match std::fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => {
                total += dir_size(&p.to_string_lossy());
            }
            Ok(t) if t.is_file() => {
                if let Ok(m) = e.metadata() {
                    total += m.len();
                }
            }
            _ => {}
        }
    }
    total
}

/// Free-space percentage of the filesystem holding `path`, via the disk whose
/// mount point is the longest prefix of `path`. `None` if it can't be resolved.
pub fn disk_free_pct(path: &str) -> Option<f64> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    let mut best: Option<(usize, f64)> = None;
    for d in disks.list() {
        let mp = d.mount_point().to_string_lossy().to_string();
        if path.starts_with(&mp) && d.total_space() > 0 {
            let pct = d.available_space() as f64 / d.total_space() as f64 * 100.0;
            if best.map(|(len, _)| mp.len() > len).unwrap_or(true) {
                best = Some((mp.len(), pct));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Find the globally-oldest closed (not `today`) date directory across all
/// nodes. Returns its full path. Used to shed under the byte cap.
fn oldest_closed_date_dir(root: &str, today: &str) -> Option<String> {
    let mut best: Option<(String, String)> = None; // (date, path)
    for node in list_subdirs(root) {
        let node_dir = format!("{root}/{node}");
        for date in list_subdirs(&node_dir) {
            if date.as_str() >= today {
                continue;
            }
            let path = format!("{node_dir}/{date}");
            if best.as_ref().map(|(d, _)| &date < d).unwrap_or(true) {
                best = Some((date, path));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// One janitor pass: compact closed segments, enforce age + byte retention,
/// and run the disk circuit-breaker. Sets `loghub.ingest_blocked` and returns
/// the current blocked state so the loop can log/alert on transitions.
pub fn run_janitor(root: &str, cfg: &super::LogHubConfig, loghub: &Arc<LogHubState>) -> bool {
    let _ = std::fs::create_dir_all(root);
    let today = date_str(now_millis());

    compress_closed_segments(root, &today);

    // ── Age retention ──────────────────────────────────────────────
    // YYYY-MM-DD sorts chronologically as a string, so a lexical compare is
    // a date compare. retention_days == 0 means "keep nothing older than
    // today" — guard against an accidental wipe of today by comparing < today.
    let cutoff = date_str(now_millis() - (cfg.retention_days as i64) * 86_400_000);
    for node in list_subdirs(root) {
        let node_dir = format!("{root}/{node}");
        for date in list_subdirs(&node_dir) {
            if date.as_str() < cutoff.as_str() && date.as_str() < today.as_str() {
                let _ = std::fs::remove_dir_all(format!("{node_dir}/{date}"));
            }
        }
        // Drop an emptied node directory.
        if list_subdirs(&node_dir).is_empty() {
            let _ = std::fs::remove_dir(&node_dir);
        }
    }

    // ── Byte-cap retention (bounds OUR footprint) ──────────────────
    let mut total = dir_size(root);
    let mut guard = 0;
    while total > cfg.max_bytes && guard < 100_000 {
        match oldest_closed_date_dir(root, &today) {
            Some(p) => {
                let sz = dir_size(&p);
                let _ = std::fs::remove_dir_all(&p);
                total = total.saturating_sub(sz);
            }
            None => break, // only today's segments remain — can't shed further
        }
        guard += 1;
    }

    // ── Disk circuit-breaker ───────────────────────────────────────
    // If the *filesystem* (possibly filled by something other than us) drops
    // below the floor, stop ingesting rather than risk filling the disk and
    // taking the host down. We deliberately do NOT mass-delete here — the
    // byte cap already bounds our own usage, and nuking history because a
    // neighbour filled the disk would be a worse failure than pausing.
    let blocked = match disk_free_pct(root) {
        Some(free) => free < cfg.min_free_pct,
        None => false, // can't determine — fail open (keep ingesting)
    };
    loghub.ingest_blocked.store(blocked, Ordering::SeqCst);
    blocked
}

/// Compute store statistics for `/api/logs/stats`. Oldest/newest are derived
/// from date-directory names (cheap) rather than scanning bodies.
pub fn compute_stats(root: &str) -> LogHubStats {
    let mut stats = LogHubStats::default();
    let nodes = list_subdirs(root);
    stats.node_count = nodes.len() as u64;
    let mut oldest_date: Option<String> = None;
    let mut newest_date: Option<String> = None;
    for node in &nodes {
        let node_dir = format!("{root}/{node}");
        for date in list_subdirs(&node_dir) {
            if oldest_date.as_ref().map(|d| &date < d).unwrap_or(true) {
                oldest_date = Some(date.clone());
            }
            if newest_date.as_ref().map(|d| &date > d).unwrap_or(true) {
                newest_date = Some(date.clone());
            }
            let date_dir = format!("{node_dir}/{date}");
            if let Ok(rd) = std::fs::read_dir(&date_dir) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.ends_with(".jsonl") || name.ends_with(".jsonl.zst") {
                        stats.segment_count += 1;
                    }
                }
            }
        }
    }
    // Convert date strings to a representative millisecond timestamp (UTC
    // midnight) so the UI can render a range without us scanning bodies.
    let to_ts = |d: &str| -> Option<i64> {
        chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
            .ok()
            .and_then(|nd| nd.and_hms_opt(0, 0, 0))
            .map(|ndt| ndt.and_utc().timestamp_millis())
    };
    stats.oldest_ts = oldest_date.as_deref().and_then(to_ts);
    stats.newest_ts = newest_date.as_deref().and_then(to_ts);
    stats.store_bytes = dir_size(root);
    stats.free_pct = disk_free_pct(root);
    stats
}

/// Janitor thread entry point. Idles while disabled or when this node isn't
/// the hub; only the hub owns the store.
pub fn janitor_loop(loghub: Arc<LogHubState>) {
    let mut was_blocked = false;
    loop {
        let run = {
            let cfg = loghub.config.read().unwrap();
            cfg.enabled
        } && loghub.is_hub();

        if run {
            let cfg = loghub.config.read().unwrap().clone();
            let root = loghub.store_root();
            let blocked = run_janitor(&root, &cfg, &loghub);
            // Log/alert on state transitions only (never on steady state).
            if blocked && !was_blocked {
                tracing::error!(
                    "loghub: disk below {:.0}% free on {} — INGEST PAUSED to protect the host",
                    cfg.min_free_pct,
                    root
                );
                fire_disk_alert(&root, cfg.min_free_pct);
            } else if !blocked && was_blocked {
                tracing::info!("loghub: disk headroom recovered on {} — ingest resumed", root);
            }
            was_blocked = blocked;
        }

        std::thread::sleep(Duration::from_secs(JANITOR_INTERVAL_SECS));
    }
}

/// Fire a one-shot local alert when ingest is paused for low disk. The janitor
/// is a plain `std::thread` with no ambient tokio runtime, so we spin up a
/// throwaway current-thread runtime just for this rare event.
fn fire_disk_alert(root: &str, floor: f64) {
    let title = "Fleet Logs: ingest paused (low disk)";
    let body = format!(
        "The log hub stopped ingesting because free space on {root} fell below the {floor:.0}% floor. \
         Existing logs are retained; new logs are spooling on each node and will resume automatically \
         once disk headroom recovers. Free space or lower the retention/size limits in Fleet Logs settings."
    );
    if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
        rt.block_on(crate::alerting::send_local_alert(
            crate::alerting::AlertCategory::Threshold,
            title,
            &body,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loghub::{LogEvent, LogLevel, LogSource};
    use std::collections::BTreeMap;
    use std::io::BufRead;

    fn ev(node: &str, ts: i64, msg: &str) -> LogEvent {
        LogEvent {
            ts,
            node: node.into(),
            source: LogSource::Journald,
            unit: "test.service".into(),
            level: LogLevel::Info,
            msg: msg.into(),
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn safe_component_blocks_traversal() {
        // The contract is safety, not an exact string: never a path separator,
        // never a leading dot (so no `.`/`..` traversal), never empty.
        for bad in ["../etc/passwd", "a/b/c", "..", "....//", "x/../y", "/abs"] {
            let s = safe_component(bad);
            assert!(!s.contains('/'), "no separator in {s:?}");
            assert!(!s.starts_with('.'), "no leading dot in {s:?}");
            assert!(!s.is_empty(), "never empty for {bad:?}");
        }
        assert_eq!(safe_component(""), "unknown");
        assert_eq!(safe_component("node-01.local"), "node-01.local");
    }

    #[test]
    fn append_then_compact_then_read() {
        let dir = std::env::temp_dir().join(format!("loghub-test-{}", std::process::id()));
        let root = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&root);

        // Yesterday so the janitor will compact it.
        let yest = now_millis() - 86_400_000;
        let events = vec![ev("n1", yest, "hello world"), ev("n1", yest + 1, "second line")];
        let n = append_events(&root, &events).unwrap();
        assert_eq!(n, 2);

        let today = date_str(now_millis());
        let compacted = compress_closed_segments(&root, &today);
        assert_eq!(compacted, 1, "one segment compacted");

        let date_dir = format!("{root}/n1/{}", date_str(yest));
        let idx = read_idx(&date_dir, "journald").expect("idx written");
        assert_eq!(idx.lines, 2);
        assert!(idx.min_ts <= idx.max_ts);

        // Stream the compacted cold segment back and confirm content survived.
        let reader = open_segment_reader(&date_dir, "journald").expect("cold segment opens");
        let text: String = reader.lines().map_while(Result::ok).collect::<Vec<_>>().join("\n");
        assert!(text.contains("hello world"));
        // Hot file should be gone after compaction.
        assert!(!std::path::Path::new(&format!("{date_dir}/journald.jsonl")).exists());

        let _ = std::fs::remove_dir_all(&root);
    }
}
