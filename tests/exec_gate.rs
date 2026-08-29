// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Build-time enforcement: every handler that runs commands, opens a
//! shell or console, or reads/writes host or container files takes the
//! operator gate (`require_operator_auth`), never the plain one.
//!
//! WHY THIS FILE EXISTS
//!
//! GHSA-r3mw-2wmq-j6jg was fixed in 25.9.3 by adding
//! `require_operator_auth` and applying it to five surfaces *by name*.
//! On 2026-08-29 @baeseungwon1010 showed that a bare cluster secret still
//! reached `bash -c` on the host through `/api/wolfflow/exec`, and that a
//! dozen more exec/console/file endpoints had the same gap — the fix
//! patched endpoints, not the capability. This test pins the capability:
//! add a handler to the list below when you add a new shell-class sink,
//! and the build fails if any listed handler is ever moved back onto
//! `require_auth`.

use std::fs;
use std::path::Path;

/// (source file, handler name). A handler is "gated" when the first auth
/// call inside its body is `require_operator_auth`.
const SHELL_CLASS_HANDLERS: &[(&str, &str)] = &[
    // 25.9.3 originals
    ("src/api/mod.rs", "container_exec"),
    ("src/vr_terminal.rs", "vr_term_create"),
    // 2026-08-29 report
    ("src/api/mod.rs", "wolfflow_trigger"),
    ("src/api/mod.rs", "wolfflow_exec"),
    ("src/api/mod.rs", "wolfflow_container_exec"),
    ("src/api/mod.rs", "wolfflow_all_containers_exec"),
    ("src/api/mod.rs", "k8s_pod_exec"),
    ("src/api/mod.rs", "ai_action_exec"),
    ("src/api/mod.rs", "files_browse"),
    ("src/api/mod.rs", "files_mkdir"),
    ("src/api/mod.rs", "files_delete"),
    ("src/api/mod.rs", "files_rename"),
    ("src/api/mod.rs", "files_upload"),
    ("src/api/mod.rs", "files_download"),
    ("src/api/mod.rs", "files_search"),
    ("src/api/mod.rs", "files_chmod"),
    ("src/api/mod.rs", "files_read"),
    ("src/api/mod.rs", "files_write"),
    ("src/api/mod.rs", "files_docker_browse"),
    ("src/api/mod.rs", "files_docker_mkdir"),
    ("src/api/mod.rs", "files_docker_delete"),
    ("src/api/mod.rs", "files_docker_rename"),
    ("src/api/mod.rs", "files_docker_download"),
    ("src/api/mod.rs", "files_docker_upload"),
    ("src/api/mod.rs", "files_docker_read"),
    ("src/api/mod.rs", "files_docker_write"),
    ("src/api/mod.rs", "files_lxc_browse"),
    ("src/api/mod.rs", "files_lxc_mkdir"),
    ("src/api/mod.rs", "files_lxc_delete"),
    ("src/api/mod.rs", "files_lxc_rename"),
    ("src/api/mod.rs", "files_lxc_download"),
    ("src/api/mod.rs", "files_lxc_upload"),
    ("src/api/mod.rs", "files_lxc_read"),
    ("src/api/mod.rs", "files_lxc_write"),
    ("src/api/pve_console.rs", "pve_vnc_ticket"),
    ("src/api/pve_console.rs", "pve_vnc_ws"),
    ("src/api/pve_console.rs", "vm_vnc_ws"),
    ("src/api/pve_console.rs", "pve_console_ws"),
    ("src/api/container_vnc.rs", "container_vnc_ws"),
    ("src/api/container_vnc.rs", "vnc_prepare_install"),
    ("src/api/container_vnc.rs", "vnc_uninstall"),
];

fn handler_body<'a>(src: &'a str, name: &str) -> &'a str {
    let needle = format!("pub async fn {}(", name);
    let start = src.find(&needle)
        .unwrap_or_else(|| panic!("handler `{}` not found — renamed? update SHELL_CLASS_HANDLERS", name));
    let end = src[start..].find("\n}\n").map(|i| start + i).unwrap_or(src.len());
    &src[start..end]
}

#[test]
fn every_shell_class_handler_takes_the_operator_gate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut failures = Vec::new();
    for (file, name) in SHELL_CLASS_HANDLERS {
        let src = fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("{}: {}", file, e));
        let body = handler_body(&src, name);
        let op = body.find("require_operator_auth(");
        let plain = body.find("require_auth(");
        let ok = match (op, plain) {
            (Some(o), Some(p)) => o < p,
            (Some(_), None) => true,
            _ => false,
        };
        if !ok {
            failures.push(format!("{}::{} is not gated by require_operator_auth", file, name));
        }
        if body.contains("validate_inter_node_secret_from(") && op.is_none() {
            failures.push(format!("{}::{} open-codes a cluster-secret check", file, name));
        }
    }
    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

/// The three cross-node WolfFlow senders, the AI approved-action sender
/// and the WolfHost portal's loopback file calls must carry the operator
/// attribution the gate demands, or every remote step breaks.
#[test]
fn every_internal_caller_of_a_shell_class_endpoint_stamps_attribution() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let checks: &[(&str, &str, usize)] = &[
        ("src/wolfflow/mod.rs", "X-WolfStack-Actor", 3),
        ("src/ai/mod.rs", "\"X-WolfStack-Actor\", approved_by", 1),
        ("src/wolfhost/api/servers.rs", "X-WolfStack-Actor", 2),
        ("src/wolfhost/portal/files.rs", "X-WolfStack-Actor", 2),
    ];
    for (file, needle, want) in checks {
        let src = fs::read_to_string(root.join(file)).unwrap();
        let got = src.matches(needle).count();
        assert!(got >= *want, "{}: expected at least {} `{}` stamps, found {}", file, want, needle, got);
    }
}
