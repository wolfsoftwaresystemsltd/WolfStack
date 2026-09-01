// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Build-time KB generator. Scrapes `.route("/api/…", web::method()…)`
//! lines from the API source files plus doc comments above the matching
//! handlers, and writes a markdown file that the AI system prompt
//! includes at runtime. Re-runs only when the scraped files change.
//!
//! Design constraint: must add **zero** runtime dependencies and stay
//! fast. String scanning over the source is enough — we don't need a
//! real Rust parser for the route shapes we emit. Imperfect matches
//! on cursed edge cases are fine because the hand-written KB covers
//! the "why" that the code alone doesn't explain.

use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Sources we scrape. Each file is `rerun-if-changed` tracked so
    // the build system knows when to regenerate. Anything else under
    // src/ can change without triggering a KB rebuild — keeps cargo
    // incremental builds fast.
    let sources: &[&str] = &[
        "src/api/mod.rs",
        "src/networking/router/api.rs",
        "src/vms/api.rs",
        "src/tui.rs",
    ];
    for s in sources {
        println!("cargo:rerun-if-changed={}", s);
    }
    // Git HEAD changing means version/log changes — rebuild.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/master");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let mut out = String::new();
    out.push_str("# WolfStack Auto-Generated Knowledge\n\n");
    out.push_str("This section is regenerated from source on every build — never edit by hand.\n");
    out.push_str("The hand-written KB covers architecture and principles; this one covers the exact API surface.\n\n");

    // ── Version / git ────────────────────────────────────────────
    out.push_str("## Version & build\n\n");
    if let Ok(s) = fs::read_to_string("Cargo.toml") {
        for line in s.lines() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("version = \"")
                && let Some(end) = v.find('"') {
                    out.push_str(&format!("- **WolfStack version**: {}\n", &v[..end]));
                }
        }
    }
    if let Some(branch) = git_out(&["rev-parse", "--abbrev-ref", "HEAD"]) {
        out.push_str(&format!("- **Built from branch**: {}\n", branch.trim()));
    }
    if let Some(sha) = git_out(&["rev-parse", "--short", "HEAD"]) {
        out.push_str(&format!("- **Git HEAD**: {}\n", sha.trim()));
    }
    out.push('\n');
    if let Some(log) = git_out(&["log", "--pretty=format:- %h %s", "-n", "25"]) {
        out.push_str("## Recent commits (most recent first)\n\n");
        out.push_str(&log);
        out.push_str("\n\n");
    }

    // ── API endpoints ────────────────────────────────────────────
    out.push_str("## REST endpoints\n\n");
    out.push_str("Paths are extracted from `.route(…)` calls. The handler's doc comment is included where present.\n\n");
    let mut all_routes: Vec<(String, String, String, String)> = Vec::new(); // (method, path, handler, doc)
    for src in sources {
        let Ok(text) = fs::read_to_string(src) else { continue; };
        let routes = extract_routes(&text);
        for (method, path, handler) in routes {
            let doc = find_handler_doc(&text, &handler).unwrap_or_default();
            all_routes.push((method, path, handler, doc));
        }
    }
    // Sort for deterministic output — keeps the generated KB reproducible
    // across builds on the same SHA.
    all_routes.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let mut last_prefix = String::new();
    for (method, path, handler, doc) in &all_routes {
        // Group by first two path segments to make the list skimmable
        // ("/api/router/...", "/api/containers/...", etc.).
        let prefix: String = path.split('/').take(3).collect::<Vec<_>>().join("/");
        if prefix != last_prefix {
            out.push_str(&format!("\n### `{}`\n\n", prefix));
            last_prefix = prefix;
        }
        let method_u = method.to_uppercase();
        if doc.is_empty() {
            out.push_str(&format!("- `{} {}` → `{}()`\n", method_u, path, handler));
        } else {
            out.push_str(&format!("- `{} {}` → `{}()` — {}\n", method_u, path, handler, doc));
        }
    }
    out.push_str(&format!("\n*{} endpoints registered.*\n", all_routes.len()));

    // ── Sibling product docs ────────────────────────────────────
    // WolfStack is one tool in the IntelligentWolf suite;
    // operators regularly ask the AI about WolfNet (private mesh),
    // WolfScale (DB replication + load-balancer), and WolfDisk
    // (distributed filesystem) because they run alongside each
    // other. Embedding each product's canonical doc in the KB
    // stops the model hallucinating feature lists. Paths are
    // resolved relative to CARGO_MANIFEST_DIR (= wolfstack/) so
    // they work for any developer layout that matches the
    // monorepo. Missing files are silently skipped so the KB
    // still builds in standalone checkouts.
    //
    // We cap each doc at 60 KB — enough for every product's
    // README / CLAUDE / DOCUMENTATION while keeping the full KB
    // well inside Claude/Gemini/GPT context windows.
    out.push_str("\n# Sibling products (IntelligentWolf suite)\n\n");
    out.push_str("WolfStack is one of several IntelligentWolf products operators commonly run side-by-side. Use the content below when answering questions about these tools — do not guess feature lists or commands.\n\n");
    // CLAUDE.md files are intentionally NOT included — they're
    // instructions for the Claude Code assistant, not user-facing
    // product documentation; feeding them to the runtime AI is
    // off-topic and noise.
    let siblings: &[(&str, &[&str])] = &[
        ("WolfNet (private mesh / WireGuard overlay)", &[
            "../wolfnet/README.md",
        ]),
        ("WolfScale (MySQL/MariaDB replication + load balancer — the monorepo this workspace lives in)", &[
            "../README.md",
            "../docs/DOCUMENTATION.md",
        ]),
        ("WolfDisk (distributed filesystem / object store)", &[
            "../../wolfdisk/README.md",
        ]),
    ];
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    for (title, paths) in siblings {
        out.push_str(&format!("## {}\n\n", title));
        let mut appended = false;
        for rel in *paths {
            let full = Path::new(&manifest_dir).join(rel);
            // Tell cargo to rebuild when the sibling doc changes.
            println!("cargo:rerun-if-changed={}", full.display());
            let Ok(text) = fs::read_to_string(&full) else { continue; };
            out.push_str(&format!("### `{}`\n\n", rel));
            // Size cap so one huge doc can't swamp the context.
            if text.len() > 60 * 1024 {
                out.push_str(&text[..60 * 1024]);
                out.push_str("\n\n[…truncated at 60 KB…]\n\n");
            } else {
                out.push_str(&text);
                if !text.ends_with('\n') { out.push('\n'); }
                out.push('\n');
            }
            appended = true;
        }
        if !appended {
            out.push_str("*(doc not present in this checkout)*\n\n");
        }
    }

    // ── Write ───────────────────────────────────────────────────
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("wolfstack-kb-generated.md");
    fs::write(&dest, out).expect("failed to write generated KB");
    println!("cargo:rustc-env=WOLFSTACK_KB_GENERATED={}", dest.display());
}

fn git_out(args: &[&str]) -> Option<String> {
    Command::new("git").args(args).output().ok().and_then(|o| {
        if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).to_string())
        } else {
            None
        }
    })
}

/// Scan a source file for `.route("/api/…", web::method()…<handler>…)`
/// patterns. Returns (method, path, handler). Handles both the
/// `.to(fn_name)` and `.to(module::fn_name)` forms.
fn extract_routes(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if !t.starts_with(".route(") { continue; }
        // Extract the quoted path.
        let after_route = &t[".route(".len()..];
        let Some(path_open) = after_route.find('"') else { continue; };
        let after_open = &after_route[path_open + 1..];
        let Some(path_close) = after_open.find('"') else { continue; };
        let path = &after_open[..path_close];
        if !path.starts_with("/api/") { continue; }
        // Extract web::METHOD() — the token after `web::` up to `(`.
        let Some(web_at) = t.find("web::") else { continue; };
        let after_web = &t[web_at + 5..];
        let Some(paren) = after_web.find('(') else { continue; };
        let method = after_web[..paren].trim();
        if method.is_empty() { continue; }
        // Extract handler from .to(FN) or .to(MODULE::FN).
        let Some(to_at) = t.find(".to(") else { continue; };
        let after_to = &t[to_at + 4..];
        let Some(close) = after_to.find(')') else { continue; };
        let handler_full = after_to[..close].trim();
        // Drop any module path prefix for the display name — the AI
        // doesn't care that a handler lives in `router::api::foo`,
        // it cares that a route exists.
        let handler = handler_full.rsplit("::").next().unwrap_or(handler_full);
        out.push((method.to_string(), path.to_string(), handler.to_string()));
    }
    out
}

/// Find the doc comment above a handler definition. Handles both
/// `/// one-liner` and the common multi-line form. Returns the
/// first line (the summary) or None when no doc comment is present.
fn find_handler_doc(text: &str, handler: &str) -> Option<String> {
    // Look for `fn <handler>` or `async fn <handler>` — either form
    // is valid. Grab the doc comment block immediately above.
    let needles = [
        format!("fn {}(", handler),
        format!("fn {}<", handler),
    ];
    for needle in &needles {
        if let Some(pos) = text.find(needle) {
            // Walk backward over whitespace and attribute lines, then
            // collect consecutive `///` lines. Skipping `#[...]` is
            // the whole point — many handlers have `#[allow(...)]` or
            // `#[tracing::instrument]` between the doc and the fn,
            // and a naive break on any non-doc line would discard the
            // doc entirely.
            let prefix = &text[..pos];
            let lines: Vec<&str> = prefix.lines().collect();
            let mut i = lines.len();
            // Walk past blank lines and attributes in either order.
            loop {
                if i == 0 { break; }
                let l = lines[i - 1].trim();
                if l.is_empty()
                    || l.starts_with("#[")
                    || l.starts_with("#![")
                    || l.starts_with("pub ")   // e.g. `pub async` on prev line (multi-line signature)
                {
                    i -= 1;
                    continue;
                }
                break;
            }
            let mut doc_lines: Vec<String> = Vec::new();
            while i > 0 {
                let l = lines[i - 1].trim_start();
                if let Some(rest) = l.strip_prefix("/// ") {
                    doc_lines.push(rest.to_string());
                    i -= 1;
                } else if l == "///" {
                    doc_lines.push(String::new());
                    i -= 1;
                } else {
                    break;
                }
            }
            doc_lines.reverse();
            if let Some(first) = doc_lines.iter().find(|l| !l.is_empty()) {
                return Some(first.clone());
            }
        }
    }
    None
}
