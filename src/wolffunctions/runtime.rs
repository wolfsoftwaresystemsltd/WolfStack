// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfFunctions execution layer — gVisor sandboxes with a Docker fallback.
//!
//! Every mechanism in this file was verified by execution against
//! runsc release-20260622.0 (spec 1.2.1) before being written:
//!
//! - Download: https://storage.googleapis.com/gvisor/releases/release/latest/
//!   {x86_64|aarch64}/runsc (+ runsc.sha512), per gvisor.dev/docs/user_guide/install/.
//! - Bundle: `runsc spec -- <argv>` generates config.json in the bundle dir
//!   (gvisor.dev OCI quick start); rootfs comes from `docker export` of the
//!   runtime image, shared READ-ONLY by all sandboxes of that runtime.
//! - Spec patches (OCI runtime-spec config.md): process.env += WOLFFN_PORT,
//!   root.readonly=true, bind /function ro, tmpfs /tmp, bind host
//!   /etc/resolv.conf + /etc/hosts ro (without these, outbound DNS fails —
//!   Errno -3 observed), linux.resources.memory.limit, and REMOVE the
//!   `network` namespace entry — with it present the sandbox gets an empty
//!   netstack and `--network=host` never applies (Errno 101 observed).
//! - Lifecycle: `runsc --network=host --root <state> run -bundle <dir>
//!   -detach <id>`, `runsc kill <id> KILL`, `runsc delete -force <id>`
//!   (flags read from `runsc help <cmd>` of the pinned release).
//!
//! `--network=host` (hostinet) trades network-namespace isolation for
//! host-reachable loopback + outbound access; syscall isolation — gVisor's
//! core value — is unaffected. This is a documented gVisor mode, not a hack.

use super::*;
use serde_json::Value;
use std::cell::Cell;
use std::path::Path;
use std::process::Command as StdCommand;
use tracing::{error, info, warn};

/// RAII release for a claimed instance. Rust drops a mid-`.await` future
/// WITHOUT running any match-arm cleanup — an inbound-socket RST while the
/// shim call is pending would otherwise strand the instance at `busy: true`
/// forever (reconcile protects busy instances), leaking a sandbox per
/// reset. This guard runs on EVERY exit path, including cancellation: it
/// flips busy off and sets Warm (success) or Failed (poison → reconcile
/// reaps + replaces). `disarm()` is called once the instance has already
/// been removed from the registry so the guard doesn't touch a stale entry.
struct ClaimGuard<'a> {
    state: &'a Arc<WolfFunctionsState>,
    function_id: String,
    sandbox_id: String,
    /// None until the call completes — a None at drop time means the future
    /// was cancelled, which we treat as poison (recycle the instance).
    outcome: Cell<Option<bool>>,
    armed: Cell<bool>,
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        if !self.armed.get() { return; }
        let poison = !matches!(self.outcome.get(), Some(true));
        let mut reg = self.state.instances.lock().unwrap();
        if let Some(list) = reg.get_mut(&self.function_id)
            && let Some(inst) = list.iter_mut().find(|i| i.sandbox_id == self.sandbox_id)
        {
            inst.busy = false;
            inst.last_used = now_secs();
            inst.status = if poison { InstanceStatus::Failed } else { InstanceStatus::Warm };
        }
    }
}

fn runtime_dir() -> String { crate::paths::get().wolffunctions_runtime_dir }
fn runsc_bin() -> String { format!("{}/bin/runsc", runtime_dir()) }
fn runsc_root() -> String { format!("{}/runsc-state", runtime_dir()) }
fn rootfs_dir(rt: FunctionRuntime) -> String {
    format!("{}/rootfs/{}", runtime_dir(), match rt {
        FunctionRuntime::Python312 => "python312",
        FunctionRuntime::Node22 => "node22",
    })
}
fn fn_dir(function_id: &str) -> String { format!("{}/fn/{}", runtime_dir(), function_id) }
fn bundle_dir(sandbox_id: &str) -> String { format!("{}/bundles/{}", runtime_dir(), sandbox_id) }
fn local_config_file() -> String { format!("{}/local.json", functions_dir()) }

// ═══════════════════════════════════════════════
// ─── Shims (run INSIDE the sandbox) ───
// ═══════════════════════════════════════════════

/// Python shim: loads /function/handler.py once (warm state persists across
/// invocations — Lambda semantics), serves invocations on
/// $WOLFFN_BIND:$WOLFFN_PORT, captures handler stdout/stderr per call.
/// Exercised end-to-end inside a runsc sandbox before landing here.
const PYTHON_SHIM: &str = r#"import contextlib
import http.server
import importlib.util
import io
import json
import os
import socketserver
import traceback

BIND = os.environ.get("WOLFFN_BIND", "127.0.0.1")
PORT = int(os.environ.get("WOLFFN_PORT", "0"))
MAX_LOG = 8192

spec = importlib.util.spec_from_file_location("handler", "/function/handler.py")
handler_mod = importlib.util.module_from_spec(spec)
load_error = None
try:
    spec.loader.exec_module(handler_mod)
except Exception:
    load_error = traceback.format_exc()


class Invoke(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            req = {}
        event = req.get("event")
        context = req.get("context", {})
        if load_error:
            self._reply(200, {"ok": False, "error": load_error[-MAX_LOG:], "logs": ""})
            return
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                result = handler_mod.handler(event, context)
            self._reply(200, {"ok": True, "result": result,
                              "logs": buf.getvalue()[-MAX_LOG:]})
        except Exception:
            self._reply(200, {"ok": False, "error": traceback.format_exc()[-MAX_LOG:],
                              "logs": buf.getvalue()[-MAX_LOG:]})

    def _reply(self, code, obj):
        try:
            body = json.dumps(obj, default=str).encode()
        except Exception:
            body = b'{"ok": false, "error": "unserializable result"}'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


# Bind (PORT=0 → kernel assigns a free port atomically, no host-side race)
# then publish the actual port so the host can reach us.
srv = Server((BIND, PORT), Invoke)
actual_port = srv.server_address[1]
portfile = os.environ.get("WOLFFN_PORTFILE")
if portfile:
    try:
        tmp = portfile + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(actual_port))
        os.replace(tmp, portfile)
    except Exception:
        pass
srv.serve_forever()
"#;

/// Node shim — same contract: exports.handler = async (event, context).
const NODE_SHIM: &str = r#"'use strict';
const http = require('http');
const MAX_LOG = 8192;

let handler = null;
let loadError = null;
try {
    handler = require('/function/handler.js').handler;
    if (typeof handler !== 'function') {
        loadError = 'handler.js does not export a `handler` function';
    }
} catch (e) {
    loadError = (e && e.stack) || String(e);
}

function capture() {
    const buf = [];
    const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
    const push = (...a) => {
        buf.push(a.map(x => {
            if (typeof x === 'string') return x;
            try { return JSON.stringify(x); } catch (e) { return String(x); }
        }).join(' '));
    };
    console.log = push; console.error = push; console.warn = push; console.info = push;
    return { buf, restore: () => Object.assign(console, orig) };
}

function reply(res, obj) {
    let body;
    try { body = JSON.stringify(obj); }
    catch (e) { body = '{"ok": false, "error": "unserializable result"}'; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(body);
}

const server = http.createServer((req, res) => {
    if (req.method === 'GET') {
        if (req.url === '/healthz') { reply(res, { ok: true }); }
        else { reply(res, { ok: false, error: 'not found' }); }
        return;
    }
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', async () => {
        let parsed = {};
        try { parsed = JSON.parse(raw || '{}'); } catch (e) { /* empty event */ }
        if (loadError) { reply(res, { ok: false, error: loadError, logs: '' }); return; }
        const cap = capture();
        try {
            const result = await handler(parsed.event, parsed.context || {});
            cap.restore();
            reply(res, { ok: true, result: result === undefined ? null : result,
                         logs: cap.buf.join('\n').slice(-MAX_LOG) });
        } catch (e) {
            cap.restore();
            reply(res, { ok: false, error: (((e && e.stack) || String(e))).slice(-MAX_LOG),
                         logs: cap.buf.join('\n').slice(-MAX_LOG) });
        }
    });
});
// PORT 0 → OS assigns a free port atomically (no host-side race); publish it.
server.listen(parseInt(process.env.WOLFFN_PORT || '0', 10),
              process.env.WOLFFN_BIND || '127.0.0.1', () => {
    const actual = server.address().port;
    const pf = process.env.WOLFFN_PORTFILE;
    if (pf) {
        try {
            const fs = require('fs');
            fs.writeFileSync(pf + '.tmp', String(actual));
            fs.renameSync(pf + '.tmp', pf);
        } catch (e) { /* best effort */ }
    }
});
"#;

// ═══════════════════════════════════════════════
// ─── Local (per-node) execution config ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Prefer gVisor; fall back to Docker if runsc can't run here.
    Auto,
    Gvisor,
    Docker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    #[serde(default = "default_mode")]
    pub execution_mode: ExecutionMode,
}
fn default_mode() -> ExecutionMode { ExecutionMode::Auto }

impl LocalConfig {
    pub fn load() -> Self {
        std::fs::read_to_string(local_config_file()).ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or(LocalConfig { execution_mode: ExecutionMode::Auto })
    }
    pub fn save(&self) {
        let _ = std::fs::create_dir_all(functions_dir());
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(local_config_file(), json);
        }
    }
}

/// What this node can execute. `mode` None = ineligible; the UI shows
/// `detail` so the operator always sees WHY (visible feedback, never silent).
#[derive(Debug, Clone, Serialize)]
pub struct NodeEligibility {
    pub docker: bool,
    pub runsc_ok: bool,
    pub mode: Option<ExecutionMode>,
    pub detail: String,
}

async fn docker_available() -> bool {
    tokio::task::spawn_blocking(|| {
        StdCommand::new("docker").arg("--version").output()
            .map(|o| o.status.success()).unwrap_or(false)
    }).await.unwrap_or(false)
}

async fn runsc_runnable() -> bool {
    let bin = runsc_bin();
    tokio::task::spawn_blocking(move || {
        StdCommand::new(bin).arg("--version").output()
            .map(|o| o.status.success()).unwrap_or(false)
    }).await.unwrap_or(false)
}

/// Single-flight guard for the runsc download. Without it, concurrent
/// `probe_eligibility` callers (the node-local endpoint, the reconcile
/// loop, and the first invoke) each kick off their own ~50MB download —
/// observed racing 4× on a fresh node, contending for bandwidth and
/// stretching a ~20s fetch to ~80s (which then blew past invoke timeouts).
static RUNSC_INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Download runsc from Google's official release bucket, sha512-verified
/// (URL scheme from gvisor.dev/docs/user_guide/install/). Idempotent and
/// single-flighted.
async fn ensure_runsc() -> Result<(), String> {
    let bin = runsc_bin();
    if Path::new(&bin).exists() {
        return Ok(());
    }
    let _guard = RUNSC_INSTALL.lock().await;
    // Re-check under the lock — a concurrent caller may have finished the
    // install while we were queued.
    if Path::new(&bin).exists() {
        return Ok(());
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => return Err(format!("unsupported architecture for runsc: {}", other)),
    };
    let base = format!("https://storage.googleapis.com/gvisor/releases/release/latest/{}", arch);
    info!("WolfFunctions: downloading runsc from {}", base);

    let client = &*FN_RPC_CLIENT;
    let dl_timeout = std::time::Duration::from_secs(180);
    let binary = client.get(format!("{}/runsc", base)).timeout(dl_timeout).send().await
        .map_err(|e| format!("runsc download failed: {}", e))?
        .bytes().await.map_err(|e| format!("runsc download read failed: {}", e))?;
    let sha_file = client.get(format!("{}/runsc.sha512", base)).timeout(dl_timeout).send().await
        .map_err(|e| format!("runsc.sha512 download failed: {}", e))?
        .text().await.map_err(|e| format!("runsc.sha512 read failed: {}", e))?;

    // sha512 file format: "<hex>  runsc" (verified against the live file).
    let expected = sha_file.split_whitespace().next().unwrap_or("").to_lowercase();
    use sha2::Digest;
    let actual = hex::encode(sha2::Sha512::digest(&binary));
    if expected.is_empty() || actual != expected {
        return Err(format!(
            "runsc checksum mismatch (expected {}, got {}) — refusing to install",
            &expected[..expected.len().min(16)], &actual[..16]
        ));
    }

    let dir = format!("{}/bin", runtime_dir());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let tmp = format!("{}.tmp", bin);
        std::fs::write(&tmp, &binary).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &bin).map_err(|e| e.to_string())?;
        Ok(())
    }).await.map_err(|e| e.to_string())??;
    info!("WolfFunctions: runsc installed (sha512 verified)");
    Ok(())
}

/// Probe (and cache) what this node can run. Called by the reconciler and
/// the status endpoint.
pub async fn probe_eligibility(state: &Arc<WolfFunctionsState>) -> NodeEligibility {
    if let Some(e) = state.eligibility.lock().unwrap().clone() {
        return e;
    }
    let docker = docker_available().await;
    let cfg_mode = LocalConfig::load().execution_mode;

    let runsc_ok = if cfg_mode == ExecutionMode::Docker {
        false // not needed, don't download
    } else {
        match ensure_runsc().await {
            Ok(()) => runsc_runnable().await,
            Err(e) => {
                warn!("WolfFunctions: runsc unavailable: {}", e);
                false
            }
        }
    };

    let (mode, detail) = if !docker {
        (None, "Docker is required to prepare runtime images — install Docker to make this node function-capable".to_string())
    } else {
        match cfg_mode {
            ExecutionMode::Docker => (Some(ExecutionMode::Docker),
                "Docker execution (configured) — reduced isolation vs gVisor".to_string()),
            ExecutionMode::Gvisor if runsc_ok => (Some(ExecutionMode::Gvisor),
                "gVisor sandbox execution".to_string()),
            ExecutionMode::Gvisor => (None,
                "gVisor mode configured but runsc is not runnable on this node".to_string()),
            ExecutionMode::Auto if runsc_ok => (Some(ExecutionMode::Gvisor),
                "gVisor sandbox execution".to_string()),
            ExecutionMode::Auto => (Some(ExecutionMode::Docker),
                "Docker execution (runsc unavailable) — reduced isolation vs gVisor".to_string()),
        }
    };

    let elig = NodeEligibility { docker, runsc_ok, mode, detail };
    *state.eligibility.lock().unwrap() = Some(elig.clone());
    elig
}

/// Drop the cached probe (e.g. after the operator changes execution_mode).
pub fn reset_eligibility(state: &Arc<WolfFunctionsState>) {
    *state.eligibility.lock().unwrap() = None;
}

// ═══════════════════════════════════════════════
// ─── Rootfs preparation ───
// ═══════════════════════════════════════════════

/// One rootfs per runtime, shared read-only by every sandbox of that
/// runtime. Built exactly like the gVisor OCI quick start: docker
/// create + docker export + tar extract.
static ROOTFS_PREP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ensure_rootfs(rt: FunctionRuntime) -> Result<(), String> {
    let dir = rootfs_dir(rt);
    let marker = format!("{}/.wolffn-ready", dir);
    if Path::new(&marker).exists() {
        // Retrofit the /run/wolffn mountpoint for rootfs prepared by an
        // older build that predates it — cheap, idempotent, and avoids a
        // full re-extract. Without this, an UPGRADED node with a cached
        // rootfs would silently fail every cold start (the golden rule:
        // never break an existing install on upgrade).
        let d = dir.clone();
        tokio::task::spawn_blocking(move || {
            let _ = std::fs::create_dir_all(format!("{}/run/wolffn", d));
        }).await.map_err(|e| e.to_string())?;
        return Ok(());
    }
    let _guard = ROOTFS_PREP.lock().await;
    if Path::new(&marker).exists() {
        let d = dir.clone();
        tokio::task::spawn_blocking(move || {
            let _ = std::fs::create_dir_all(format!("{}/run/wolffn", d));
        }).await.map_err(|e| e.to_string())?;
        return Ok(()); // another task finished it while we waited
    }
    let image = rt.image().to_string();
    info!("WolfFunctions: preparing {} rootfs from {}", rt.display(), image);

    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let pull = StdCommand::new("docker").args(["pull", &image]).output()
            .map_err(|e| format!("docker pull: {}", e))?;
        if !pull.status.success() {
            return Err(format!("docker pull {} failed: {}", image,
                String::from_utf8_lossy(&pull.stderr)));
        }
        let create = StdCommand::new("docker").args(["create", &image]).output()
            .map_err(|e| format!("docker create: {}", e))?;
        if !create.status.success() {
            return Err(format!("docker create failed: {}", String::from_utf8_lossy(&create.stderr)));
        }
        let cid = String::from_utf8_lossy(&create.stdout).trim().to_string();

        // Extract into a temp dir then rename — a half-extracted rootfs
        // must never look ready.
        let tmp_dir = format!("{}.tmp", dir);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
        let export = StdCommand::new("sh")
            .args(["-c", &format!("docker export {} | tar -xf - -C '{}'", cid, tmp_dir)])
            .output().map_err(|e| format!("docker export: {}", e))?;
        let _ = StdCommand::new("docker").args(["rm", &cid]).output();
        if !export.status.success() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("rootfs extract failed: {}", String::from_utf8_lossy(&export.stderr)));
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::rename(&tmp_dir, &dir).map_err(|e| e.to_string())?;
        // Pre-create the /run/wolffn mountpoint. The rootfs is mounted
        // read-only at runtime, so gVisor can't reliably create the bind
        // target itself — without this the rw rendezvous mount silently
        // fails on fresh nodes and the shim can't publish its port.
        std::fs::create_dir_all(format!("{}/run/wolffn", dir)).map_err(|e| e.to_string())?;
        std::fs::write(format!("{}/.wolffn-ready", dir), b"ok").map_err(|e| e.to_string())?;
        Ok(())
    }).await.map_err(|e| e.to_string())??;
    info!("WolfFunctions: {} rootfs ready", rt.display());
    Ok(())
}

// ═══════════════════════════════════════════════
// ─── Function dir (handler + shim, bind-mounted ro) ───
// ═══════════════════════════════════════════════

fn write_function_dir(func: &WolfFunction) -> Result<(), String> {
    let dir = fn_dir(&func.id);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let shim = match func.runtime {
        FunctionRuntime::Python312 => PYTHON_SHIM,
        FunctionRuntime::Node22 => NODE_SHIM,
    };
    std::fs::write(format!("{}/{}", dir, func.runtime.handler_file()), &func.code)
        .map_err(|e| e.to_string())?;
    std::fs::write(format!("{}/{}", dir, func.runtime.shim_file()), shim)
        .map_err(|e| e.to_string())?;
    std::fs::write(format!("{}/.version", dir), func.version.to_string())
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ═══════════════════════════════════════════════
// ─── Sandbox lifecycle ───
// ═══════════════════════════════════════════════

fn runsc_base_cmd() -> StdCommand {
    let mut c = StdCommand::new(runsc_bin());
    c.arg("--network=host").arg(format!("--root={}", runsc_root()));
    c
}

/// Generate + patch the OCI bundle for a gVisor instance. Every patch here
/// was validated live (see module docs). `run_dir` is a host dir bind-
/// mounted rw at /run/wolffn so the shim can publish the port it bound.
fn write_bundle(func: &WolfFunction, sandbox_id: &str, run_dir: &str) -> Result<String, String> {
    let bdir = bundle_dir(sandbox_id);
    std::fs::create_dir_all(&bdir).map_err(|e| e.to_string())?;

    let mut spec_cmd = runsc_base_cmd();
    spec_cmd.current_dir(&bdir).arg("spec").arg("--");
    for a in func.runtime.shim_argv() { spec_cmd.arg(a); }
    let out = spec_cmd.output().map_err(|e| format!("runsc spec: {}", e))?;
    if !out.status.success() {
        return Err(format!("runsc spec failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    let cfg_path = format!("{}/config.json", bdir);
    let raw = std::fs::read_to_string(&cfg_path).map_err(|e| e.to_string())?;
    let mut cfg: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;

    apply_spec_patches(&mut cfg, func, run_dir, include_dns_mounts());

    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(bdir)
}

/// Which of resolv.conf/hosts actually exist on this host (bind targets
/// must exist). Split out so the patch fn is pure and unit-testable.
fn include_dns_mounts() -> Vec<&'static str> {
    ["/etc/resolv.conf", "/etc/hosts"].into_iter()
        .filter(|p| Path::new(p).exists()).collect()
}

/// Pure OCI-spec patcher — every mutation here was validated live against
/// runsc release-20260622.0 (see module docs). Kept pure (no filesystem)
/// so the auto-vivification of `linux.resources` and the network-namespace
/// removal are unit-tested rather than trusted.
fn apply_spec_patches(cfg: &mut Value, func: &WolfFunction, run_dir: &str, dns_mounts: Vec<&str>) {
    // Shared read-only rootfs for this runtime.
    cfg["root"]["path"] = Value::String(rootfs_dir(func.runtime));
    cfg["root"]["readonly"] = Value::Bool(true);

    // Environment: append — the spec's defaults include PATH. WOLFFN_PORT=0
    // makes the shim bind an OS-assigned port atomically (no host-side port
    // race — the pre-allocate-then-rebind approach lost the port to the
    // host's ephemeral churn on busy nodes) and publish it to WOLFFN_PORTFILE.
    if let Some(env) = cfg["process"]["env"].as_array_mut() {
        env.push(Value::String("WOLFFN_PORT=0".to_string()));
        env.push(Value::String("WOLFFN_BIND=127.0.0.1".to_string()));
        env.push(Value::String("WOLFFN_PORTFILE=/run/wolffn/port".to_string()));
        for kv in &func.env {
            env.push(Value::String(kv.clone()));
        }
    }

    // Mounts: function code ro, writable /tmp, a rw rendezvous dir at
    // /run/wolffn (the shim writes its bound port there), host DNS config
    // (without resolv.conf/hosts, outbound name resolution fails — verified
    // live).
    if let Some(mounts) = cfg["mounts"].as_array_mut() {
        mounts.push(serde_json::json!({
            "destination": "/function", "type": "none",
            "source": fn_dir(&func.id), "options": ["bind", "ro"]
        }));
        mounts.push(serde_json::json!({
            "destination": "/run/wolffn", "type": "none",
            "source": run_dir, "options": ["bind", "rw"]
        }));
        mounts.push(serde_json::json!({
            "destination": "/tmp", "type": "tmpfs", "source": "tmpfs"
        }));
        for host_file in dns_mounts {
            mounts.push(serde_json::json!({
                "destination": host_file, "type": "none",
                "source": host_file, "options": ["bind", "ro"]
            }));
        }
    }

    // Memory limit (OCI linux.resources.memory.limit, bytes). serde_json
    // auto-vivifies the intermediate `resources` object when absent (the
    // node:22 spec omits it) — asserted in tests.
    cfg["linux"]["resources"]["memory"] =
        serde_json::json!({ "limit": (func.memory_mb as u64) * 1024 * 1024 });

    // Remove the network namespace so --network=host (hostinet) applies —
    // with it present the sandbox gets an empty netstack (verified live).
    if let Some(ns) = cfg["linux"]["namespaces"].as_array_mut() {
        ns.retain(|n| n["type"].as_str() != Some("network"));
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    fn sample_func() -> WolfFunction {
        WolfFunction {
            id: "abc123".into(), name: "t".into(), cluster: "WolfStack".into(),
            runtime: FunctionRuntime::Node22, code: String::new(), description: String::new(),
            memory_mb: 128, timeout_secs: 30, replicas: 2, max_per_node: 4,
            env: vec!["FOO=bar".into()], placed_nodes: vec![], public_slug: None,
            schedules: vec![], events: vec![], enabled: true, version: 1,
            created_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn patches_vivify_resources_when_absent() {
        // node:22 runsc spec has linux but no linux.resources.
        let mut cfg = serde_json::json!({
            "process": { "env": ["PATH=/usr/bin"] },
            "root": { "path": "rootfs" },
            "mounts": [],
            "linux": { "namespaces": [ {"type": "pid"}, {"type": "network"} ] }
        });
        apply_spec_patches(&mut cfg, &sample_func(), "/var/lib/wolfstack/wolffunctions/run/x", vec!["/etc/hosts"]);
        assert_eq!(cfg["linux"]["resources"]["memory"]["limit"], 128 * 1024 * 1024);
        // network namespace stripped, pid kept
        let ns = cfg["linux"]["namespaces"].as_array().unwrap();
        assert!(ns.iter().all(|n| n["type"] != "network"));
        assert!(ns.iter().any(|n| n["type"] == "pid"));
        // env appended, not replaced; shim self-picks port (0) + portfile
        let env = cfg["process"]["env"].as_array().unwrap();
        assert!(env.iter().any(|e| e == "PATH=/usr/bin"));
        assert!(env.iter().any(|e| e == "WOLFFN_PORT=0"));
        assert!(env.iter().any(|e| e == "WOLFFN_PORTFILE=/run/wolffn/port"));
        assert!(env.iter().any(|e| e == "FOO=bar"));
        // rootfs forced read-only
        assert_eq!(cfg["root"]["readonly"], true);
        // /function + /run/wolffn + /tmp + one dns mount = 4
        assert_eq!(cfg["mounts"].as_array().unwrap().len(), 4);
        // the rw rendezvous mount is present
        let mounts = cfg["mounts"].as_array().unwrap();
        assert!(mounts.iter().any(|m| m["destination"] == "/run/wolffn"
            && m["options"].as_array().unwrap().iter().any(|o| o == "rw")));
    }

    #[test]
    fn valid_name_rules() {
        assert!(super::super::valid_name("my-fn-1"));
        assert!(!super::super::valid_name("My_Fn"));
        assert!(!super::super::valid_name("-lead"));
        assert!(!super::super::valid_name("trail-"));
        assert!(!super::super::valid_name(""));
    }
}

/// Start one warm instance of `func` on this node. Blocks until the shim
/// answers /healthz (or errors out).
pub async fn start_instance(
    state: &Arc<WolfFunctionsState>,
    func: &WolfFunction,
) -> Result<Instance, String> {
    let elig = probe_eligibility(state).await;
    let mode = elig.mode.ok_or_else(|| format!("node not function-capable: {}", elig.detail))?;

    ensure_rootfs(func.runtime).await?;
    let f = func.clone();
    tokio::task::spawn_blocking(move || write_function_dir(&f))
        .await.map_err(|e| e.to_string())??;

    // Unique sandbox id — no longer derived from a pre-allocated port
    // (that raced with the host's ephemeral churn). The shim picks its own
    // port and reports it back.
    let short = uuid::Uuid::new_v4().to_string();
    let sandbox_id = format!("wolffn-{}-{}", &func.id[..func.id.len().min(8)], &short[..8]);
    let run_dir = format!("{}/run/{}", runtime_dir(), sandbox_id);

    // Register the real sandbox id as Starting BEFORE launch. cleanup_orphans
    // reaps any wolffn-* sandbox NOT in the live registry; without this, a
    // startup cleanup could race-kill a sandbox between `runsc run` making it
    // visible to `runsc list` and this function reaching the (post-poll)
    // registry insert. Registering up front also makes every failure path a
    // single deregister. Removed by `fail` on error, promoted to Warm on
    // success.
    state.instances.lock().unwrap()
        .entry(func.id.clone()).or_default().push(Instance {
            sandbox_id: sandbox_id.clone(),
            function_id: func.id.clone(),
            function_version: func.version,
            port: 0,
            status: InstanceStatus::Starting,
            started_at: now_secs(),
            last_used: now_secs(),
            busy: true,
        });
    // Cleanup for any failure after this point: drop the registry entry,
    // destroy the sandbox, remove the run dir.
    let fail = |state: &Arc<WolfFunctionsState>, fid: &str, sid: &str, rd: &str, mode: ExecutionMode| {
        let (state, fid, sid, rd) = (state.clone(), fid.to_string(), sid.to_string(), rd.to_string());
        async move {
            {
                let mut reg = state.instances.lock().unwrap();
                if let Some(list) = reg.get_mut(&fid) { list.retain(|i| i.sandbox_id != sid); }
                reg.retain(|_, v| !v.is_empty());
            }
            destroy_sandbox(mode, &sid).await;
            let _ = tokio::fs::remove_dir_all(&rd).await;
        }
    };

    let launch: Result<(), String> = match mode {
        ExecutionMode::Gvisor | ExecutionMode::Auto => {
            let f = func.clone();
            let sid = sandbox_id.clone();
            let rd = run_dir.clone();
            tokio::task::spawn_blocking(move || -> Result<(), String> {
                std::fs::create_dir_all(&rd).map_err(|e| format!("run dir: {}", e))?;
                let bdir = write_bundle(&f, &sid, &rd)?;
                // CRITICAL: `-detach` double-forks the sandbox, but the
                // detached boot/gofer processes inherit whatever stdio we
                // give the `runsc run` child. If that's a pipe (which
                // Command::output() sets up), `.output()` blocks reading it
                // to EOF forever because the sandbox keeps the write end
                // open — start_instance would hang indefinitely. Redirect
                // all stdio to /dev/null and use .status() so the command
                // returns as soon as the direct child exits.
                let status = runsc_base_cmd()
                    .args(["run", "-bundle", &bdir, "-detach", &sid])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status().map_err(|e| format!("runsc run: {}", e))?;
                if !status.success() {
                    return Err(format!("runsc run exited with {}", status));
                }
                Ok(())
            }).await.map_err(|e| e.to_string()).and_then(|r| r)
        }
        ExecutionMode::Docker => {
            // Docker publishes an OS-assigned host port (127.0.0.1:0) mapped
            // to the shim's fixed in-container 8080 — same "let the OS pick"
            // approach as gVisor, discovered afterwards via `docker port`.
            let mut args: Vec<String> = vec![
                "run".into(), "-d".into(),
                "--name".into(), sandbox_id.clone(),
                "-p".into(), "127.0.0.1:0:8080".into(),
                "-v".into(), format!("{}:/function:ro", fn_dir(&func.id)),
                "--memory".into(), format!("{}m", func.memory_mb),
                "--tmpfs".into(), "/tmp".into(),
                "-e".into(), "WOLFFN_PORT=8080".into(),
                "-e".into(), "WOLFFN_BIND=0.0.0.0".into(),
                "--restart".into(), "no".into(),
                "--label".into(), "wolffn=1".into(),
            ];
            for kv in &func.env {
                args.push("-e".into());
                args.push(kv.clone());
            }
            args.push(func.runtime.image().to_string());
            args.extend(func.runtime.shim_argv());
            match tokio::task::spawn_blocking(move || {
                StdCommand::new("docker").args(&args).output()
            }).await.map_err(|e| e.to_string()) {
                Ok(Ok(out)) if out.status.success() => Ok(()),
                Ok(Ok(out)) => Err(format!("docker run failed: {}", String::from_utf8_lossy(&out.stderr))),
                Ok(Err(e)) => Err(format!("docker run: {}", e)),
                Err(e) => Err(e),
            }
        }
    };
    if let Err(e) = launch {
        fail(state, &func.id, &sandbox_id, &run_dir, mode).await;
        return Err(e);
    }

    // Discover the port the shim/engine actually bound (gVisor: the shim
    // writes it to the rw rendezvous file; Docker: `docker port` reports
    // the published host port). Poll up to ~30s for it to appear.
    let mut port: u16 = 0;
    for _ in 0..150 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let discovered = match mode {
            ExecutionMode::Docker => {
                let name = sandbox_id.clone();
                tokio::task::spawn_blocking(move || {
                    StdCommand::new("docker").args(["port", &name, "8080/tcp"]).output().ok()
                        .filter(|o| o.status.success())
                        .and_then(|o| String::from_utf8_lossy(&o.stdout)
                            .rsplit(':').next().map(|s| s.trim().to_string()))
                        .and_then(|s| s.parse::<u16>().ok())
                }).await.ok().flatten()
            }
            _ => {
                let pf = format!("{}/port", run_dir);
                tokio::task::spawn_blocking(move || {
                    std::fs::read_to_string(&pf).ok()
                        .and_then(|s| s.trim().parse::<u16>().ok())
                }).await.ok().flatten()
            }
        };
        if let Some(p) = discovered.filter(|p| *p != 0) { port = p; break; }
    }
    if port == 0 {
        fail(state, &func.id, &sandbox_id, &run_dir, mode).await;
        return Err(format!("instance {} never reported a port (shim crash on load?)", sandbox_id));
    }

    // Confirm the shim answers /healthz on the discovered port.
    let url = format!("http://127.0.0.1:{}/healthz", port);
    let client = &*FN_RPC_CLIENT;
    let mut healthy = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).timeout(std::time::Duration::from_secs(2)).send().await {
            let ok = resp.status().is_success();
            drain_response(resp).await;
            if ok { healthy = true; break; }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    if !healthy {
        fail(state, &func.id, &sandbox_id, &run_dir, mode).await;
        return Err(format!("instance {} bound port {} but never answered /healthz", sandbox_id, port));
    }

    // Promote the pre-registered Starting instance to Warm with its port.
    // Compute the decision while holding the lock, then release it BEFORE any
    // await (the std MutexGuard is not Send — it must not cross .await).
    let promoted = {
        let mut reg = state.instances.lock().unwrap();
        let list = reg.entry(func.id.clone()).or_default();
        list.iter_mut().find(|i| i.sandbox_id == sandbox_id).map(|existing| {
            existing.port = port;
            existing.status = InstanceStatus::Warm;
            existing.busy = false;
            existing.last_used = now_secs();
            existing.clone()
        })
    };
    let inst = match promoted {
        Some(i) => i,
        None => {
            // Placeholder was reaped from under us (e.g. function deleted
            // mid-start) — tear the sandbox back down rather than orphan it.
            fail(state, &func.id, &sandbox_id, &run_dir, mode).await;
            return Err(format!("instance {} vanished from registry during start", sandbox_id));
        }
    };
    info!("WolfFunctions: started {} for {} v{} on port {}",
        inst.sandbox_id, func.name, func.version, port);
    Ok(inst)
}

/// Tear down one sandbox (gVisor or Docker) and its bundle dir.
pub async fn destroy_sandbox(mode: ExecutionMode, sandbox_id: &str) {
    let sid = sandbox_id.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        match mode {
            ExecutionMode::Docker => {
                let _ = StdCommand::new("docker").args(["rm", "-f", &sid]).output();
            }
            _ => {
                let _ = runsc_base_cmd().args(["kill", &sid, "KILL"]).output();
                std::thread::sleep(std::time::Duration::from_millis(300));
                let _ = runsc_base_cmd().args(["delete", "-force", &sid]).output();
                let _ = std::fs::remove_dir_all(bundle_dir(&sid));
                let _ = std::fs::remove_dir_all(format!("{}/run/{}", runtime_dir(), sid));
            }
        }
    }).await;
}

/// Remove an instance from the registry (by sandbox id) and destroy it.
async fn remove_instance(state: &Arc<WolfFunctionsState>, mode: ExecutionMode, sandbox_id: &str) {
    {
        let mut reg = state.instances.lock().unwrap();
        for list in reg.values_mut() {
            list.retain(|i| i.sandbox_id != sandbox_id);
        }
        reg.retain(|_, v| !v.is_empty());
    }
    destroy_sandbox(mode, sandbox_id).await;
}

/// On process start: kill sandboxes left over from a PREVIOUS WolfStack run.
/// Reaps from `runsc list` + the bundles/ + run/ dirs + docker's wolffn=1
/// label. CRITICAL: skips any sandbox_id present in the live instance
/// registry, so it can never destroy a sandbox this process just started —
/// an invocation can race in as soon as the API is up (well before this
/// runs), and blindly reaping every `wolffn-*` would kill the live sandbox
/// and delete its rendezvous dir out from under the port poll.
pub async fn cleanup_orphans(state: &Arc<WolfFunctionsState>) {
    let state = state.clone();
    let _ = tokio::task::spawn_blocking(move || {
        // Snapshot the live registry INSIDE the blocking task, right before
        // scanning — not seconds earlier on the async side. start_instance
        // registers a sandbox_id BEFORE `runsc run` makes it visible to
        // `runsc list`, so any sandbox this scan can see is already in the
        // registry by the time we look, closing the startup race where a
        // concurrent first-invoke sandbox could be mistaken for an orphan.
        let live: std::collections::HashSet<String> = state.instances.lock().unwrap()
            .values().flatten().map(|i| i.sandbox_id.clone()).collect();
        // 1. Everything runsc still tracks in our state dir.
        if let Ok(out) = runsc_base_cmd().arg("list").output() {
            for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
                let sid = line.split_whitespace().next().unwrap_or("");
                if !sid.starts_with("wolffn-") || live.contains(sid) { continue; }
                let _ = runsc_base_cmd().args(["kill", sid, "KILL"]).output();
                let _ = runsc_base_cmd().args(["delete", "-force", sid]).output();
                let _ = std::fs::remove_dir_all(format!("{}/run/{}", runtime_dir(), sid));
                info!("WolfFunctions: cleaned up orphan sandbox {} (runsc list)", sid);
            }
        }
        // 2. Any bundle dirs left behind (sandbox may already be gone).
        if let Ok(entries) = std::fs::read_dir(format!("{}/bundles", runtime_dir())) {
            for entry in entries.flatten() {
                let sid = entry.file_name().to_string_lossy().to_string();
                if !sid.starts_with("wolffn-") || live.contains(&sid) { continue; }
                let _ = runsc_base_cmd().args(["kill", &sid, "KILL"]).output();
                let _ = runsc_base_cmd().args(["delete", "-force", &sid]).output();
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        // 3. Stale rendezvous dirs (skip live ones).
        if let Ok(entries) = std::fs::read_dir(format!("{}/run", runtime_dir())) {
            for entry in entries.flatten() {
                let sid = entry.file_name().to_string_lossy().to_string();
                if !sid.starts_with("wolffn-") || live.contains(&sid) { continue; }
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        if let Ok(out) = StdCommand::new("docker")
            .args(["ps", "-a", "--filter", "label=wolffn=1", "--format", "{{.Names}}"]).output()
        {
            for name in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                if live.contains(name) { continue; }
                let _ = StdCommand::new("docker").args(["rm", "-f", name]).output();
                info!("WolfFunctions: cleaned up orphan docker instance {}", name);
            }
        }
    }).await;
}

// ═══════════════════════════════════════════════
// ─── Invocation ───
// ═══════════════════════════════════════════════

/// Invoke on THIS node: claim a warm instance (or cold-start one), POST the
/// event to its shim, record the outcome. One request per instance at a
/// time — Lambda semantics; concurrent invokes burst extra instances up to
/// `max_per_node`.
pub async fn invoke_local(
    state: &Arc<WolfFunctionsState>,
    func: &WolfFunction,
    event: Value,
    trigger: &str,
    node_name: &str,
) -> Result<Value, String> {
    let started = std::time::Instant::now();
    // The claim deadline bounds how long we'll wait to GET an instance —
    // it must be generous enough to cover a cold start (port-discovery poll
    // ~30s + health poll ~10s), which is independent of the handler's own
    // `timeout_secs` (that bounds the shim HTTP call below). Using the bare
    // handler timeout here would abort legitimate cold starts on functions
    // configured with a short timeout.
    const COLD_START_BUDGET_SECS: u64 = 90;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs((func.timeout_secs as u64).max(COLD_START_BUDGET_SECS));

    // Claim or create an instance. std Mutex is never held across an await
    // (claim happens inside the scope; cold start happens outside it).
    // A `reserving-*` placeholder is inserted under the lock BEFORE the
    // await so concurrent claimers count the in-flight start against
    // `max_per_node` — otherwise a burst all read the same pre-start count
    // and each spins up an instance, overshooting the cap.
    let claimed: Instance = loop {
        enum Step { Claimed(Instance), Reserve(String), Wait }
        let step = {
            let mut reg = state.instances.lock().unwrap();
            let list = reg.entry(func.id.clone()).or_default();
            if let Some(inst) = list.iter_mut()
                .find(|i| !i.busy && i.status == InstanceStatus::Warm
                    && i.function_version == func.version)
            {
                inst.busy = true;
                inst.status = InstanceStatus::Busy;
                Step::Claimed(inst.clone())
            } else {
                // Count real instances + outstanding reservations of the
                // current version against the cap.
                let current = list.iter()
                    .filter(|i| i.function_version == func.version).count();
                if current < func.max_per_node.max(1) as usize {
                    let rid = format!("reserving-{}", uuid::Uuid::new_v4());
                    list.push(Instance {
                        sandbox_id: rid.clone(),
                        function_id: func.id.clone(),
                        function_version: func.version,
                        port: 0,
                        status: InstanceStatus::Starting,
                        started_at: now_secs(),
                        last_used: now_secs(),
                        busy: true,
                    });
                    Step::Reserve(rid)
                } else {
                    Step::Wait
                }
            }
        };
        match step {
            Step::Claimed(inst) => break inst,
            Step::Reserve(rid) => {
                let res = start_instance(state, func).await;
                // Drop the reservation placeholder regardless of outcome;
                // on success start_instance has pushed the real instance.
                {
                    let mut reg = state.instances.lock().unwrap();
                    if let Some(list) = reg.get_mut(&func.id) {
                        list.retain(|i| i.sandbox_id != rid);
                    }
                }
                res?;
                if std::time::Instant::now() > deadline {
                    return Err("timed out acquiring an instance".to_string());
                }
                continue; // claim the freshly-started instance (or retry)
            }
            Step::Wait => {
                if std::time::Instant::now() > deadline {
                    return Err("all instances busy — concurrency limit reached".to_string());
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    };

    let elig_mode = state.eligibility.lock().unwrap().clone()
        .and_then(|e| e.mode).unwrap_or(ExecutionMode::Gvisor);

    // Arm the release guard immediately — from here to return, any exit
    // (including a cancelled future) releases the claimed instance.
    let guard = ClaimGuard {
        state,
        function_id: func.id.clone(),
        sandbox_id: claimed.sandbox_id.clone(),
        outcome: Cell::new(None),
        armed: Cell::new(true),
    };

    let context = serde_json::json!({
        "function": func.name,
        "version": func.version,
        "memory_mb": func.memory_mb,
        "node": node_name,
        "trigger": trigger,
    });
    let client = &*FN_RPC_CLIENT;
    let resp = client.post(format!("http://127.0.0.1:{}/", claimed.port))
        .timeout(std::time::Duration::from_secs(func.timeout_secs.max(1) as u64))
        .json(&serde_json::json!({ "event": event, "context": context }))
        .send().await;

    let duration_ms = started.elapsed().as_millis() as u64;

    match resp {
        Ok(r) => {
            let body: Value = r.json().await.unwrap_or_else(|_| serde_json::json!({
                "ok": false, "error": "shim returned unparseable response"
            }));
            // Release the instance back to Warm for reuse.
            guard.outcome.set(Some(true));
            drop(guard);
            let ok = body["ok"].as_bool().unwrap_or(false);
            state.record_invocation(&func.id, InvocationRecord {
                ts: now_secs(),
                node: node_name.to_string(),
                trigger: trigger.to_string(),
                duration_ms,
                ok,
                error: body["error"].as_str().map(|s| s.to_string()),
                logs: body["logs"].as_str().unwrap_or("").to_string(),
            });
            if ok {
                Ok(body["result"].clone())
            } else {
                Err(body["error"].as_str().unwrap_or("handler error").to_string())
            }
        }
        Err(e) => {
            // Timeout or transport failure — the instance may be wedged.
            // Disarm the guard and remove+destroy the instance immediately
            // (the guard would only mark it Failed for the reconciler; we
            // reap it now for a faster turnaround).
            guard.armed.set(false);
            drop(guard);
            remove_instance(state, elig_mode, &claimed.sandbox_id).await;
            let msg = if e.is_timeout() {
                format!("function timed out after {}s (instance recycled)", func.timeout_secs)
            } else {
                format!("instance unreachable: {} (instance recycled)", e)
            };
            state.record_invocation(&func.id, InvocationRecord {
                ts: now_secs(),
                node: node_name.to_string(),
                trigger: trigger.to_string(),
                duration_ms,
                ok: false,
                error: Some(msg.clone()),
                logs: String::new(),
            });
            Err(msg)
        }
    }
}

/// Cluster-routed invoke: serve locally when this node is placed (or
/// nothing is placed yet), otherwise forward to a placed node; if every
/// placed node is unreachable (mid-failover), cold-start locally so the
/// invocation still succeeds.
pub async fn invoke_routed(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
    func: &WolfFunction,
    event: Value,
    trigger: &str,
) -> Result<Value, String> {
    if !func.enabled {
        return Err("function is disabled".to_string());
    }
    let nodes = cluster.get_all_nodes();
    let self_node = nodes.iter().find(|n| n.is_self);
    let self_id = self_node.map(|n| n.id.clone()).unwrap_or_default();
    let node_name = self_node.map(|n| n.hostname.clone()).unwrap_or_else(|| "local".to_string());

    if func.placed_nodes.is_empty() || func.placed_nodes.contains(&self_id) {
        return invoke_local(state, func, event, trigger, &node_name).await;
    }

    let client = &*FN_RPC_CLIENT;
    let payload = serde_json::json!({ "event": event, "trigger": trigger });
    for placed in &func.placed_nodes {
        let Some(node) = nodes.iter().find(|n| &n.id == placed && n.online) else { continue; };
        let path = format!("/api/wolffunctions/{}/invoke-local", func.id);
        for url in crate::api::build_node_urls(&node.address, node.port, &path) {
            match client.post(&url)
                .header("X-WolfStack-Secret", cluster_secret)
                .timeout(std::time::Duration::from_secs(func.timeout_secs.max(1) as u64 + 5))
                .json(&payload)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    let body: Value = resp.json().await
                        .map_err(|e| format!("bad response from {}: {}", node.hostname, e))?;
                    if body["ok"].as_bool().unwrap_or(false) {
                        return Ok(body["result"].clone());
                    }
                    return Err(body["error"].as_str().unwrap_or("handler error").to_string());
                }
                Ok(resp) => { drain_response(resp).await; continue; }
                Err(_) => continue,
            }
        }
    }

    // Every placed node unreachable — last-resort local cold start keeps
    // the invocation alive during failover.
    warn!("WolfFunctions: no placed node reachable for {} — cold-starting locally", func.name);
    invoke_local(state, func, event, trigger, &node_name).await
}

// ═══════════════════════════════════════════════
// ─── Reconcile (every node) + placement (leader) ───
// ═══════════════════════════════════════════════

const BURST_IDLE_REAP_SECS: u64 = 300;

/// Per-node reconcile: make local instances match the replicated desired
/// state. Runs on EVERY node (each owns its own sandboxes).
pub async fn local_reconcile(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
) {
    let elig = probe_eligibility(state).await;
    let Some(mode) = elig.mode else { return; };

    let self_id = cluster.get_all_nodes().iter()
        .find(|n| n.is_self).map(|n| n.id.clone()).unwrap_or_default();
    let self_cluster = self_cluster_name(cluster);
    let functions: Vec<WolfFunction> = state.config.read().unwrap().functions.iter()
        .filter(|f| f.cluster == self_cluster).cloned().collect();
    let known_ids: std::collections::HashSet<String> =
        functions.iter().map(|f| f.id.clone()).collect();

    // 1. Destroy instances that shouldn't exist: deleted functions,
    //    stale versions, unplaced/disabled functions, failed, idle bursts.
    let doomed: Vec<String> = {
        let reg = state.instances.lock().unwrap();
        let mut doomed = Vec::new();
        for (fid, list) in reg.iter() {
            let func = functions.iter().find(|f| &f.id == fid);
            let keep_any = known_ids.contains(fid)
                && func.map(|f| f.enabled && (f.placed_nodes.contains(&self_id) || f.placed_nodes.is_empty()))
                    .unwrap_or(false);
            // Whether this node is *supposed* to hold a warm instance. When
            // false (replicas:0 scale-from-zero, or simply not a placement
            // target) we keep no permanent warm baseline — every idle
            // instance is reapable, so a scale-to-zero function actually
            // returns to zero after the idle window instead of pinning one
            // sandbox forever.
            let wants_warm_here = func.map(|f| f.placed_nodes.contains(&self_id)).unwrap_or(false);
            let current_version = func.map(|f| f.version).unwrap_or(0);
            let mut kept_warm = 0usize;
            for inst in list {
                let stale = inst.function_version != current_version;
                let failed = inst.status == InstanceStatus::Failed;
                let idle = !inst.busy
                    && now_secs().saturating_sub(inst.last_used) > BURST_IDLE_REAP_SECS;
                // Reap idle instances beyond the warm baseline; when the node
                // wants no warm baseline, reap the first idle one too.
                let idle_reap = idle && (kept_warm >= 1 || !wants_warm_here);
                let unwanted = !keep_any || (stale && !inst.busy) || failed || idle_reap;
                if unwanted && !inst.busy {
                    doomed.push(inst.sandbox_id.clone());
                    continue;
                }
                if !stale && !failed { kept_warm += 1; }
            }
        }
        doomed
    };
    for sid in doomed {
        remove_instance(state, mode, &sid).await;
    }

    // 2. Ensure a warm instance for every function placed here.
    for func in &functions {
        if !func.enabled || !func.placed_nodes.contains(&self_id) { continue; }
        let have_warm = {
            let reg = state.instances.lock().unwrap();
            // A real serving instance — not a transient `reserving-*`
            // placeholder (Starting), which would otherwise mask a needed
            // warm start until the next reconcile tick.
            reg.get(&func.id).map(|l| l.iter()
                .any(|i| i.function_version == func.version
                    && matches!(i.status, InstanceStatus::Warm | InstanceStatus::Busy)))
                .unwrap_or(false)
        };
        if !have_warm
            && let Err(e) = start_instance(state, func).await
        {
            warn!("WolfFunctions: failed to warm {} on this node: {}", func.name, e);
        }
    }

    // 3. Prune code dirs for functions that no longer exist here (deleted,
    //    or moved to another cluster). Bounded by the 512KB code cap × the
    //    count of stale dirs; without this they leak on every delete.
    let live_ids: std::collections::HashSet<String> = {
        let reg = state.instances.lock().unwrap();
        known_ids.iter().cloned().chain(reg.keys().cloned()).collect()
    };
    let base = format!("{}/fn", runtime_dir());
    tokio::task::spawn_blocking(move || {
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().to_string();
                if !live_ids.contains(&id) {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }).await.ok();
}

/// Leader-only: compute `placed_nodes` for every function, stable-first so
/// placements don't churn, and detect node online/offline transitions for
/// event triggers. Returns true if placements changed (caller broadcasts).
pub fn leader_place(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
) -> bool {
    let ranked = rank_nodes_for_placement(cluster);
    if ranked.is_empty() { return false; }
    let self_cluster = self_cluster_name(cluster);
    let online: std::collections::HashSet<&String> = ranked.iter().collect();

    let mut changed = false;
    {
        let mut cfg = state.config.write().unwrap();
        for func in cfg.functions.iter_mut() {
            if func.cluster != self_cluster { continue; }
            let want = if func.enabled { func.replicas as usize } else { 0 };
            // Keep currently-placed nodes that are still online (stability),
            // then fill from the load-ranked list.
            let mut new_placed: Vec<String> = func.placed_nodes.iter()
                .filter(|n| online.contains(n)).take(want).cloned().collect();
            for candidate in &ranked {
                if new_placed.len() >= want { break; }
                if !new_placed.contains(candidate) {
                    new_placed.push(candidate.clone());
                }
            }
            if new_placed != func.placed_nodes {
                info!("WolfFunctions: re-placing {} → {:?}", func.name, new_placed);
                func.placed_nodes = new_placed;
                changed = true;
            }
        }
    }
    if changed { state.save(); }
    changed
}

/// Leader-only schedule tick (backup-scheduler model: due-check inside a
/// periodic tick). Returns true if any `last_fired` advanced (broadcast so
/// a leader change doesn't refire).
pub async fn schedule_tick(
    state: &Arc<WolfFunctionsState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) -> bool {
    let self_cluster = self_cluster_name(cluster);
    let now = now_secs();
    // Collect due (function, schedule index) pairs without holding the lock.
    let due: Vec<(WolfFunction, usize)> = {
        let cfg = state.config.read().unwrap();
        cfg.functions.iter()
            .filter(|f| f.enabled && f.cluster == self_cluster)
            .flat_map(|f| f.schedules.iter().enumerate()
                .filter(|(_, s)| s.interval_secs >= 60
                    && now.saturating_sub(s.last_fired) >= s.interval_secs)
                .map(|(i, _)| (f.clone(), i))
                .collect::<Vec<_>>())
            .collect()
    };
    if due.is_empty() { return false; }

    for (func, idx) in &due {
        {
            let mut cfg = state.config.write().unwrap();
            if let Some(f) = cfg.functions.iter_mut().find(|f| f.id == func.id)
                && let Some(s) = f.schedules.get_mut(*idx)
            {
                s.last_fired = now;
            }
        }
        let event = serde_json::json!({ "trigger": "schedule", "scheduled_at": now });
        if let Err(e) = invoke_routed(state, cluster, cluster_secret, func, event, "schedule").await {
            error!("WolfFunctions: schedule fire for {} failed: {}", func.name, e);
        }
    }
    state.save();
    true
}
