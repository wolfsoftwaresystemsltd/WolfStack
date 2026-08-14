// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Consistent point-in-time views of a container rootfs: ZFS, btrfs, LVM.
//!
//! A file-level sync reads the rootfs while the container is writing to
//! it, so a replica can hold a half-written database — it looks healthy
//! right up until you fail over onto it. Taking a filesystem snapshot
//! first and reading from THAT makes everything in the round belong to one
//! instant, so the replica is **crash-consistent**: exactly the state a
//! machine would be in after a power cut, which every real database is
//! built to recover from.
//!
//! ## Why a snapshot source, and not `zfs send` as the transport
//!
//! `zfs send` is the obvious idea and the wrong one here. It requires the
//! *replica* to run ZFS too, with a common snapshot — storage we do not
//! control and cannot demand across a fleet. Reading from a snapshot
//! instead demands nothing of the replica: it receives the same tar or
//! block deltas it always did, and never knows the difference. The
//! transport stays negotiated ([`super::DriverKind`]); this axis is purely
//! local. That is why there is no send/receive code here — it would have
//! coupled both ends' storage for a benefit this design already gets.
//!
//! ## Flags, from the primary sources
//!
//! - btrfs: *"All snapshots involved in one send command must be
//!   read-only"* (btrfs-send.rst, btrfs-progs 6.10) — and a read-only
//!   snapshot is what we want anyway, so `subvolume snapshot -r`.
//! - LVM thin snapshots are taken with `lvcreate -s`, and unlike ZFS and
//!   btrfs the result is a block device that must be mounted before it can
//!   be walked.

use std::process::Command;

/// Prefix for every snapshot this module creates. Anything not carrying
/// it is left strictly alone — an operator's own snapshots must never be
/// pruned by us.
pub const SNAP_PREFIX: &str = "wolfha";

/// Snapshot name for a subject at a point in time. The timestamp makes
/// ordering obvious to a human reading `zfs list`, which matters when
/// someone is debugging a replication problem at 3am.
pub fn snapshot_name(subject: &str, unix_secs: u64) -> String {
    format!("{}-{}-{}", SNAP_PREFIX, subject, unix_secs)
}

/// True when `name` is one of ours for `subject`.
pub fn is_ours(name: &str, subject: &str) -> bool {
    name.starts_with(&format!("{}-{}-", SNAP_PREFIX, subject))
}

/// Remove any snapshots of `subject` left behind by an earlier round.
///
/// Best-effort by design: this runs on the way into a sync, and a failure
/// to clean up an old snapshot must not stop a new round from happening.
pub fn cleanup_stale(source: &super::ConsistencySource, subject: &str) -> usize {
    let mut removed = 0;
    match source {
        super::ConsistencySource::Live => {}
        super::ConsistencySource::Zfs { dataset } => {
            for s in zfs_list_ours(dataset, subject).unwrap_or_default() {
                if run("zfs", &["destroy", &format!("{}@{}", dataset, s)]).is_ok() {
                    removed += 1;
                }
            }
        }
        super::ConsistencySource::Btrfs { subvol } => {
            let dir = btrfs_snap_dir(subvol);
            for s in btrfs_list_ours(subvol, subject).unwrap_or_default() {
                if run("btrfs", &["subvolume", "delete", &format!("{}/{}", dir, s)]).is_ok() {
                    removed += 1;
                }
            }
        }
        super::ConsistencySource::LvmThin { lv } => {
            for s in lvm_list_ours(lv, subject).unwrap_or_default() {
                // The snapshot may still be mounted from the crashed round.
                let mnt = format!("/var/lib/wolfstack/wolfha/snap-{}", s);
                let _ = Command::new("umount").arg(&mnt).output();
                let _ = std::fs::remove_dir(&mnt);
                if lvm_remove(lv, &s).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

/// Run a command, returning stderr on failure. Keeps the error text the
/// operator sees identical in shape across all three backends.
fn run(bin: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("{}: {}", bin, e))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} failed: {}",
            bin,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// ─── ZFS ─────────────────────────────────────────────────────────────

/// Take `dataset@<name>`.
pub fn zfs_snapshot(dataset: &str, snap: &str) -> Result<(), String> {
    run("zfs", &["snapshot", &format!("{}@{}", dataset, snap)]).map(|_| ())
}

/// Snapshots of `dataset` that belong to `subject`, oldest first.
pub fn zfs_list_ours(dataset: &str, subject: &str) -> Result<Vec<String>, String> {
    // -d 1 keeps this to the dataset's own snapshots; -S creation would
    // sort newest first, so ask for oldest-first explicitly via -s.
    let out = run(
        "zfs",
        &["list", "-H", "-o", "name", "-t", "snapshot", "-s", "creation", "-d", "1", dataset],
    )?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_once('@').map(|(_, s)| s.to_string()))
        .filter(|s| is_ours(s, subject))
        .collect())
}

// ─── btrfs ───────────────────────────────────────────────────────────

/// Where our read-only snapshots of a subvolume live.
///
/// A sibling directory rather than inside the subvolume: a snapshot
/// nested within the subvolume it snapshots would be captured by the next
/// snapshot, compounding every round.
pub fn btrfs_snap_dir(subvol: &str) -> String {
    // Resolve the parent properly rather than appending "..": a path
    // containing ".." is resolved against symlinks by the kernel, so on a
    // rootfs reached through one it can land somewhere else entirely.
    let trimmed = subvol.trim_end_matches('/');
    let parent = std::path::Path::new(trimmed)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".to_string());
    format!("{}/.wolfha-snapshots", parent)
}

/// Take a read-only snapshot — read-only is mandatory for `btrfs send`.
pub fn btrfs_snapshot(subvol: &str, snap: &str) -> Result<String, String> {
    let dir = btrfs_snap_dir(subvol);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir, e))?;
    let dest = format!("{}/{}", dir, snap);
    run("btrfs", &["subvolume", "snapshot", "-r", subvol, &dest])?;
    Ok(dest)
}

/// Our snapshots of `subject`, oldest first (names only).
pub fn btrfs_list_ours(subvol: &str, subject: &str) -> Result<Vec<String>, String> {
    let dir = btrfs_snap_dir(subvol);
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()), // nothing taken yet
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_ours(n, subject))
        .collect();
    // Names end in a unix timestamp, so lexical order is not chronological
    // once the digit count changes. Sort on the parsed number.
    names.sort_by_key(|n| n.rsplit('-').next().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0));
    Ok(names)
}

/// Take a thin snapshot of `lv` (given as `vg/lv`).
///
/// `-s` snapshot, `-n` name, and `-p r` for read-only: a snapshot we are
/// about to read as a consistent point in time must not be writable, or
/// something else on the host could modify it mid-read.
pub fn lvm_snapshot(lv: &str, snap: &str) -> Result<(), String> {
    run("lvcreate", &["-s", "-n", snap, "-p", "r", lv]).map(|_| ())
}

/// Device path for a snapshot of `vg/lv`.
pub fn lvm_snap_device(lv: &str, snap: &str) -> String {
    let vg = lv.split('/').next().unwrap_or("");
    format!("/dev/{}/{}", vg, snap)
}

pub fn lvm_list_ours(lv: &str, subject: &str) -> Result<Vec<String>, String> {
    let vg = lv.split('/').next().unwrap_or("");
    let out = run("lvs", &["--noheadings", "-o", "lv_name", vg])?;
    let mut names: Vec<String> = out
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|n| is_ours(n, subject))
        .collect();
    names.sort_by_key(|n| n.rsplit('-').next().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0));
    Ok(names)
}

pub fn lvm_remove(lv: &str, snap: &str) -> Result<(), String> {
    let vg = lv.split('/').next().unwrap_or("");
    run("lvremove", &["-f", &format!("{}/{}", vg, snap)]).map(|_| ())
}

/// A point-in-time view of a container rootfs, to be read instead of the
/// live files, then torn down.
///
/// Closed explicitly rather than in `Drop`: tearing a snapshot down runs
/// commands that can fail, and a `Drop` impl has nowhere to report that.
pub struct SnapshotSession {
    source: super::ConsistencySource,
    /// Snapshot name — empty for a live read.
    name: String,
    /// Directory the sync should read from.
    read_path: String,
    /// Mount point we created and must unmount (LVM only).
    mounted: Option<String>,
}

impl SnapshotSession {
    /// Path the sync should walk. For [`super::ConsistencySource::Live`]
    /// this is the rootfs itself, so callers need no special case.
    pub fn read_path(&self) -> &str {
        &self.read_path
    }

    pub fn is_snapshot(&self) -> bool {
        !self.name.is_empty()
    }

    /// Open a consistent view, falling back to a live read if the snapshot
    /// cannot be taken.
    ///
    /// Falling back rather than failing is deliberate: a snapshot that
    /// cannot be created (pool full, tool missing, permission) must degrade
    /// the *quality* of the round, not abandon it. A replica that stops
    /// updating is far worse than one that is merely not crash-consistent.
    pub fn open(
        source: &super::ConsistencySource,
        rootfs: &str,
        subject: &str,
        now_unix: u64,
    ) -> Self {
        // A round that crashed between open and close leaves its snapshot
        // behind, and a leaked snapshot pins the blocks it references —
        // enough of them and the pool fills. Clear ours for this subject
        // before taking a new one. Only names carrying our prefix AND this
        // subject are touched; an operator's own snapshots are never ours.
        cleanup_stale(source, subject);

        let live = || SnapshotSession {
            source: super::ConsistencySource::Live,
            name: String::new(),
            read_path: rootfs.to_string(),
            mounted: None,
        };
        let name = snapshot_name(subject, now_unix);
        match source {
            super::ConsistencySource::Live => live(),
            super::ConsistencySource::Zfs { dataset } => {
                if zfs_snapshot(dataset, &name).is_err() {
                    return live();
                }
                // ZFS exposes snapshots under the dataset's own mount as
                // `.zfs/snapshot/<name>`; no mount call is needed.
                SnapshotSession {
                    source: source.clone(),
                    read_path: format!("{}/.zfs/snapshot/{}", rootfs.trim_end_matches('/'), name),
                    name,
                    mounted: None,
                }
            }
            super::ConsistencySource::Btrfs { subvol } => match btrfs_snapshot(subvol, &name) {
                Ok(path) => SnapshotSession {
                    source: source.clone(),
                    name,
                    read_path: path,
                    mounted: None,
                },
                Err(_) => live(),
            },
            super::ConsistencySource::LvmThin { lv } => {
                if lvm_snapshot(lv, &name).is_err() {
                    return live();
                }
                // Unlike ZFS and btrfs, an LVM snapshot is a block device
                // and has to be mounted before it can be walked.
                let mnt = format!("/var/lib/wolfstack/wolfha/snap-{}", name);
                if std::fs::create_dir_all(&mnt).is_err() {
                    let _ = lvm_remove(lv, &name);
                    return live();
                }
                let dev = lvm_snap_device(lv, &name);
                // ro because we must not modify the snapshot, and nouuid
                // because XFS refuses to mount a second filesystem carrying
                // the same UUID as the original — which every snapshot does
                // by definition.
                let ok = Command::new("mount")
                    .args(["-o", "ro,nouuid", &dev, &mnt])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    let _ = std::fs::remove_dir(&mnt);
                    let _ = lvm_remove(lv, &name);
                    return live();
                }
                SnapshotSession {
                    source: source.clone(),
                    name,
                    read_path: mnt.clone(),
                    mounted: Some(mnt),
                }
            }
        }
    }

    /// Tear the snapshot down. Errors are returned so the caller can log
    /// them; a leaked snapshot grows until the pool fills.
    pub fn close(self) -> Result<(), String> {
        if self.name.is_empty() {
            return Ok(());
        }
        if let Some(mnt) = &self.mounted {
            let _ = Command::new("umount").arg(mnt).output();
            let _ = std::fs::remove_dir(mnt);
        }
        match &self.source {
            super::ConsistencySource::Live => Ok(()),
            super::ConsistencySource::Zfs { dataset } => {
                run("zfs", &["destroy", &format!("{}@{}", dataset, self.name)]).map(|_| ())
            }
            super::ConsistencySource::Btrfs { subvol } => {
                let dir = btrfs_snap_dir(subvol);
                run("btrfs", &["subvolume", "delete", &format!("{}/{}", dir, self.name)])
                    .map(|_| ())
            }
            super::ConsistencySource::LvmThin { lv } => lvm_remove(lv, &self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_names_are_namespaced_and_recognised() {
        let n = snapshot_name("web01", 1_700_000_000);
        assert!(is_ours(&n, "web01"));
        assert!(!is_ours(&n, "web02"));
        // An operator's own snapshot must never look like ours.
        assert!(!is_ours("nightly-backup", "web01"));
        assert!(!is_ours("wolfha-web01x-1", "web01"));
    }

    /// A subject whose name contains the prefix must not be confused with
    /// another — the separator is what makes the match unambiguous.
    #[test]
    fn subject_prefixes_do_not_collide() {
        let a = snapshot_name("db", 1);
        assert!(!is_ours(&a, "d"));
        assert!(is_ours(&a, "db"));
    }

    /// Snapshot names end in a unix timestamp whose digit count changes
    /// over time, so ordering must be numeric. A lexical sort would put
    /// "…-9" after "…-10" and prune the wrong snapshot.
    #[test]
    fn ordering_is_numeric_not_lexical() {
        let mut names = vec![
            "wolfha-a-10".to_string(),
            "wolfha-a-9".to_string(),
            "wolfha-a-100".to_string(),
        ];
        names.sort_by_key(|n| {
            n.rsplit('-').next().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0)
        });
        assert_eq!(names, vec!["wolfha-a-9", "wolfha-a-10", "wolfha-a-100"]);
    }

    #[test]
    fn btrfs_snapshots_live_outside_the_subvolume_they_snapshot() {
        // Nesting them inside would make each snapshot capture the
        // previous ones, growing without bound.
        let dir = btrfs_snap_dir("/srv/lxc/web01/rootfs");
        assert!(dir.contains(".wolfha-snapshots"));
        assert!(!dir.starts_with("/srv/lxc/web01/rootfs/"));
    }

    /// A live session must be a transparent no-op: same read path, no
    /// snapshot, and closing it does nothing.
    #[test]
    fn a_live_session_reads_the_rootfs_directly() {
        let sess = SnapshotSession::open(
            &super::super::ConsistencySource::Live,
            "/srv/lxc/web01/rootfs",
            "web01",
            123,
        );
        assert_eq!(sess.read_path(), "/srv/lxc/web01/rootfs");
        assert!(!sess.is_snapshot());
        assert!(sess.close().is_ok());
    }

    /// A snapshot that cannot be created must degrade to a live read, not
    /// abandon the sync — a replica that stops updating is worse than one
    /// that is merely not crash-consistent.
    #[test]
    fn an_impossible_snapshot_falls_back_to_live() {
        let sess = SnapshotSession::open(
            &super::super::ConsistencySource::Zfs { dataset: "no/such/dataset/here".into() },
            "/srv/lxc/web01/rootfs",
            "web01",
            123,
        );
        assert!(!sess.is_snapshot(), "must not claim a snapshot it failed to take");
        assert_eq!(sess.read_path(), "/srv/lxc/web01/rootfs");
        assert!(sess.close().is_ok());
    }

    #[test]
    fn lvm_snapshot_device_path_is_derived_from_the_vg() {
        assert_eq!(lvm_snap_device("vg0/lxc-web01", "wolfha-web01-7"), "/dev/vg0/wolfha-web01-7");
    }
}
