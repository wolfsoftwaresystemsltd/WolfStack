// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Read-only file browser backend.
//!
//! Powers the "Browse…" picker used wherever the UI would otherwise make
//! the operator type an exact path (VM ISO, backup destinations, storage,
//! …). It ONLY reads directory listings — never file contents, never any
//! mutation.
//!
//! SECURITY: this exposes the host filesystem, so every listing is jailed
//! to an allow-list of roots (the WolfStack storage mounts — i.e. the
//! mounted NFS/SMB/S3 shares — plus the local ISO/VM stores that exist).
//! A requested path is `canonicalize`d (which resolves `..` AND symlinks)
//! and must land inside one of the canonicalized roots, so neither
//! `../../etc` nor a symlink pointing out of a share can escape the jail.

use std::path::{Path, PathBuf};
use serde::Serialize;

/// A directory the operator is allowed to start browsing from.
#[derive(Debug, Clone, Serialize)]
pub struct BrowseRoot {
    pub label: String,
    pub path: String,
    /// Human hint for the UI icon/grouping: "share" | "local".
    pub kind: String,
}

/// One entry in a directory listing (metadata only — no contents).
#[derive(Debug, Clone, Serialize)]
pub struct BrowseEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Unix mtime seconds (0 if unavailable).
    pub mtime: u64,
}

/// The full listing of a directory plus its (still-in-jail) parent.
#[derive(Debug, Clone, Serialize)]
pub struct BrowseListing {
    pub path: String,
    /// Parent directory, or None when `path` is a root (or the parent
    /// would leave the jail) so the UI knows whether "up" is allowed.
    pub parent: Option<String>,
    pub entries: Vec<BrowseEntry>,
}

/// Local directories that commonly hold ISOs / VM disks. Included as roots
/// only when they actually exist on this host.
const LOCAL_ROOTS: &[(&str, &str)] = &[
    ("VM storage", "/var/lib/wolfstack/vms"),
    ("Proxmox ISOs", "/var/lib/vz/template/iso"),
    ("Proxmox backups", "/var/lib/vz/dump"),
    ("libvirt images", "/var/lib/libvirt/images"),
];

/// The directories the operator may browse: every live WolfStack storage
/// mount (the mounted shares) plus the local stores above that exist.
pub fn allowed_roots() -> Vec<BrowseRoot> {
    let mut roots = Vec::new();
    for m in crate::storage::list_mounts() {
        // Only offer mounts that are actually mounted right now — a stale
        // config entry for an unmounted share would just error on browse.
        if crate::storage::check_mounted(&m.mount_point) {
            roots.push(BrowseRoot {
                label: if m.name.is_empty() { m.mount_point.clone() } else { m.name.clone() },
                path: m.mount_point.clone(),
                kind: "share".to_string(),
            });
        }
    }
    for (label, p) in LOCAL_ROOTS {
        if Path::new(p).is_dir() {
            roots.push(BrowseRoot { label: (*label).to_string(), path: (*p).to_string(), kind: "local".to_string() });
        }
    }
    roots
}

/// Canonicalized root prefixes for the jail check. Recomputed per request
/// so a newly-mounted share is browsable immediately (and an unmounted one
/// drops out). Canonicalization resolves symlinks so the roots themselves
/// can't be spoofed.
fn root_prefixes() -> Vec<PathBuf> {
    allowed_roots()
        .into_iter()
        .filter_map(|r| std::fs::canonicalize(&r.path).ok())
        .collect()
}

/// Whether an already-canonicalized path sits inside one of the allowed
/// (also-canonicalized) roots. `starts_with` is component-wise, so
/// `/mnt/a` does NOT match `/mnt/abc`.
fn within(canon: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| canon == *root || canon.starts_with(root))
}

/// Convenience wrapper (test-only): canonicalize `path` then check the
/// jail. Production callers canonicalize once and reuse the result via
/// [`within`]; the tests exercise the resolve-then-check in one step.
#[cfg(test)]
fn is_within(path: &str, roots: &[PathBuf]) -> bool {
    match std::fs::canonicalize(path) {
        Ok(canon) => within(&canon, roots),
        Err(_) => false,
    }
}

/// List a directory. Errors if the path is outside the jail or unreadable.
/// Hard-capped so a pathological directory can't return an unbounded body.
///
/// SECURITY: every returned entry is re-resolved through symlinks and
/// re-jailed, and its `path` is the CANONICAL (fully-resolved) location —
/// so a symlink inside a share that points at `/etc/shadow` (or a raw
/// device) is never listed, and the path a caller selects can never
/// resolve outside the allowed roots. The directory itself is read from
/// its canonical form to close any check→read symlink-swap race.
pub fn list_dir(path: &str) -> Result<BrowseListing, String> {
    let roots = root_prefixes();
    let outside = || "That location is outside the storage areas WolfStack can browse.".to_string();

    // Canonicalize the requested directory ONCE and both validate and read
    // that resolved path — no gap for a symlink swap between the two.
    let canon_dir = std::fs::canonicalize(path).map_err(|_| outside())?;
    if !within(&canon_dir, &roots) {
        return Err(outside());
    }
    let rd = std::fs::read_dir(&canon_dir).map_err(|e| format!("Can't read directory: {}", e))?;

    let mut entries: Vec<BrowseEntry> = Vec::new();
    for e in rd.flatten() {
        // Resolve the entry through any symlinks and RE-JAIL it. A symlink
        // escaping the roots (or a broken/unreadable one) is silently
        // dropped, never surfaced — so it can't become an out-of-jail path
        // once selected.
        let canon = match std::fs::canonicalize(e.path()) { Ok(c) => c, Err(_) => continue };
        if !within(&canon, &roots) { continue; }
        // `metadata()` FOLLOWS symlinks (unlike DirEntry::metadata), so a
        // symlinked directory reads as a directory and sizes are the real
        // target's.
        let md = match std::fs::metadata(&canon) { Ok(m) => m, Err(_) => continue };
        let mtime = md.modified().ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(BrowseEntry {
            name: e.file_name().to_string_lossy().to_string(),
            path: canon.to_string_lossy().to_string(),
            is_dir: md.is_dir(),
            size: md.len(),
            mtime,
        });
        if entries.len() >= 5000 { break; }
    }
    // Directories first, then case-insensitive by name.
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir)
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));

    // Offer a parent only if it too stays inside the jail (so the UI's
    // "up" never walks the operator out of an allowed root).
    let parent = canon_dir.parent()
        .filter(|p| within(p, &roots))
        .map(|p| p.to_string_lossy().to_string());

    Ok(BrowseListing { path: canon_dir.to_string_lossy().to_string(), parent, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn jail_rejects_traversal_and_symlink_escape() {
        // Use the OS temp dir as a fake root, then prove nothing outside it
        // passes the gate.
        let root = std::env::temp_dir();
        let canon_root = std::fs::canonicalize(&root).expect("temp dir canonicalizes");
        let roots = vec![canon_root.clone()];

        // The root itself is allowed.
        assert!(is_within(canon_root.to_str().unwrap(), &roots));

        // A path clearly outside the root is rejected.
        assert!(!is_within("/etc", &roots));
        assert!(!is_within("/etc/shadow", &roots));

        // Traversal that resolves outside the root is rejected (canonicalize
        // collapses the `..` before the prefix check).
        let escape = format!("{}/../../../../etc", canon_root.display());
        assert!(!is_within(&escape, &roots));

        // A non-existent path can't be canonicalized → rejected, never
        // silently allowed.
        assert!(!is_within("/no/such/path/anywhere-xyz", &roots));
    }

    #[test]
    fn empty_roots_allow_nothing() {
        let roots: Vec<PathBuf> = Vec::new();
        assert!(!is_within("/", &roots));
        assert!(!is_within(std::env::temp_dir().to_str().unwrap(), &roots));
    }

    // The security crux: a REAL symlink inside a root that points OUT of it
    // must resolve outside the jail (→ list_dir drops it), while a symlink
    // to a file inside the root stays in the jail.
    #[cfg(unix)]
    #[test]
    fn real_symlink_escaping_root_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("wsbrowse-{}-{}", std::process::id(), "sym"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mk root");
        let canon_root = std::fs::canonicalize(&root).expect("canon root");
        let roots = vec![canon_root.clone()];

        // Symlink inside the root → /etc (outside): resolved target is
        // outside the jail, so `within` rejects it.
        let escape = root.join("escape");
        symlink("/etc", &escape).expect("mk escape link");
        let canon_escape = std::fs::canonicalize(&escape).expect("canon escape");
        assert!(!within(&canon_escape, &roots), "symlink to /etc must be outside the jail");

        // Symlink inside the root → a file inside the root: stays in the jail.
        let real = root.join("real.iso");
        std::fs::write(&real, b"x").expect("write real");
        let good = root.join("good.iso");
        symlink(&real, &good).expect("mk good link");
        let canon_good = std::fs::canonicalize(&good).expect("canon good");
        assert!(within(&canon_good, &roots), "symlink to an in-jail file is allowed");

        let _ = std::fs::remove_dir_all(&root);
    }
}
