# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
cargo build                  # Dev build
cargo build --release        # Release build
cargo test                   # Run all unit tests
cargo test statuspage::      # Run tests in a specific module
```

Single binary output: `target/debug/wolfstack` or `target/release/wolfstack`

The binary requires root privileges (reads /etc/shadow for auth). Default port: 8553.

## Architecture

WolfStack is a Proxmox-like server management platform built as a single Rust binary (actix-web 4) with an embedded SPA frontend. It manages clusters of Linux servers, Docker/LXC containers, VMs, networking, storage, backups, and more.

### Backend (Rust)

**Entry point**: `src/main.rs` — CLI args (clap), TLS setup, HTTP server, background task spawning.

**Shared state**: `api::AppState` (defined in `src/api/mod.rs` ~line 51) holds all runtime state behind `Arc<Mutex<T>>` or `Arc<RwLock<T>>`. Every module's state is a field here.

**Module structure** — each module is self-contained with its own data types, business logic, and persistence:

| Module | Purpose |
|---|---|
| `api/mod.rs` | All REST endpoints, route registration (`configure()`), auth helpers |
| `agent/mod.rs` | Cluster node discovery, inter-node polling, `ClusterState` |
| `containers/mod.rs` | Docker (socket API) and LXC (CLI) management |
| `wolfrun/mod.rs` | Container orchestration across cluster nodes |
| `statuspage/mod.rs` | Uptime monitoring, public status pages, incident tracking |
| `console.rs` | WebSocket terminal sessions via `portable-pty` |
| `storage/mod.rs` | S3/NFS/SSHFS/WolfDisk mount management |
| `backup/mod.rs` | Backup scheduling with multiple destination types |
| `networking/mod.rs` | Interface, VLAN, DNS, WolfNet overlay |
| `vms/` | Proxmox VE integration (manager.rs + api.rs) |
| `ai/mod.rs` | LLM assistant (Claude/Gemini) with health monitoring |
| `alerting.rs` | Threshold alerting with email notifications |
| `auth/mod.rs` | Linux crypt() auth against /etc/shadow, session management |
| `mysql_editor.rs` | MySQL/MariaDB browser and query execution |
| `appstore/mod.rs` | Application store for Docker/LXC/bare-metal deployment |

### Frontend (JavaScript SPA)

All frontend code lives in `web/`:
- `web/js/app.js` — Single ~15K-line JavaScript file, the entire application
- `web/index.html` — Main dashboard SPA
- `web/css/style.css` — Dark/light theme with CSS variables
- `web/login.html`, `web/console.html`, `web/vnc.html` — Separate pages

**Authentication**: Cookie-based (`wolfstack_session`). API calls use NO Authorization headers — the browser sends the session cookie automatically. Inter-node calls use `X-WolfStack-Secret` header instead.

**Navigation**: `selectView(page)` for datacenter views, `selectServerView(nodeId, view)` for per-node views. Status pages use `showStatusPagesForCluster(clusterName)`.

### Key Patterns

**Config persistence**: JSON files in `/etc/wolfstack/` — each module loads on startup, writes on change. No database for config.

**Cluster communication**: Nodes poll each other every 10 seconds via HTTP. Auth between nodes uses a shared cluster secret. Node proxy routes (`/api/nodes/{id}/proxy/{path}`) forward API calls to remote nodes.

**Background tasks**: Spawned as `tokio::spawn` loops in `main.rs` (lines ~230-825). Key intervals: self-monitoring (2s), node polling (10s), status page checks (30s), session cleanup (300s), backup scheduling (60s).

**Serde conventions**: All structs use `#[serde(rename_all = "snake_case")]` for enums. Fields that may be absent from older JSON configs need `#[serde(default)]`. The frontend sends/receives snake_case JSON matching Rust field names.

## Quality Bar — The Anthropic Test

**Every change must meet the bar Anthropic PBC themselves would hold this code to if they were shipping it.** Before declaring any work done, ask: *"If Anthropic engineers had to ship this exact diff under their name, would they?"* If the honest answer is "no" or "not quite", the work is not done.

Concretely, this means:
- **No half-measures.** All branches implemented, all error paths handled, all edge cases addressed. If three platforms exist (Proxmox/libvirt/native), all three work — not two-and-a-stub.
- **No guessed values.** Every constant, ID, format, and protocol detail comes from reading the source — never from memory or "this looks right".
- **No dead code, no TODOs, no "follow-up later".** Finish the work or raise the scope question explicitly *before* writing the partial version.
- **Re-read the diff before declaring done.** Closure bugs, async-without-await, dead variables, unused branches — catch them yourself, don't ship them for Codex/review to find.
- **Be honest about what was tested.** Compile-passes ≠ feature-works. Don't claim "production-ready" without exercising the actual code path. Surface known untested paths in the closing summary.
- **The user-facing surface matters as much as the code.** Visible feedback for user actions, accessible interactions, no silent failures. A correct backend with a broken UX is not shipped quality.
- **Defaults must be safe.** Public surfaces (status pages, logs, error messages) never leak internals, credentials, AI output, or host data unless explicitly intended.

This rule overrides "ship it fast" instincts. If the bar isn't met, say so plainly and either finish the work or stop and ask.

## Important Conventions

- All Rust source files start with the copyright header (`// Written by Paul Clevett` / `// (C)Copyright IntelligentWolf Ltd`)
- The `api/mod.rs` file contains ALL REST endpoints and the route table in `configure()` — new endpoints go here
- When adding fields to serialized structs, always add `#[serde(default)]` for backward compatibility with existing config files
- The frontend has no build step — edit `web/js/app.js` directly
- Status page code is cluster-scoped: monitors, pages, and incidents all have a `cluster: String` field
