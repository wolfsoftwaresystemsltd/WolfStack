// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Build-time enforcement: no outbound request sets `X-WolfStack-Secret`
//! by hand. Every sender goes through `node_identity` (`peer_auth`,
//! `peer_auth_to`, `curl_headers*`, `raw_headers`) so it also carries
//! this node's signature. A hand-written header is a request that will
//! be refused the day an operator turns on "Require node signatures".

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() { rust_files(&p, out); }
        else if p.extension().map(|x| x == "rs").unwrap_or(false) { out.push(p); }
    }
}

#[test]
fn every_secret_sender_uses_node_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut offenders = Vec::new();
    for f in files {
        let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
        if rel == "src/node_identity.rs" { continue; }
        let src = fs::read_to_string(&f).unwrap();
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") { continue; }
            // Receivers read the header; only writers are in scope.
            let sends = t.contains(".header(\"X-WolfStack-Secret\"")
                || t.contains("insert(\"X-WolfStack-Secret\"")
                || t.contains("X-WolfStack-Secret: {}");
            if sends {
                offenders.push(format!("{}:{}: {}", rel, i + 1, t));
            }
        }
    }
    assert!(offenders.is_empty(),
        "hand-written cluster-secret headers (use node_identity::PeerAuth / curl_headers):\n{}",
        offenders.join("\n"));
}
