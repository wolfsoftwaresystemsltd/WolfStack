# S3 Storage Setup, Monitoring & Bucket Sync — Implementation Plan

## Executive Summary

Four pillars, building on subsystems that already exist:

1. **Remote S3 connections** — connecting WolfStack to external S3 storage (AWS, IDrive E2, Backblaze B2, Wasabi, Cloudflare R2, a customer's own Garage/MinIO, …) **already exists** as the saved-remotes store (add/list/delete + rclone.conf import + s3fs mounts). This plan finishes it: provider presets, a test-connection step, credential editing, and health monitoring of configured remote endpoints with alerting — the 2026-08-14 IDrive FRA2 outage is the motivating incident (a dead remote endpoint should be a WolfStack alert, not a mystery).
2. **S3 server providers** — Garage and MinIO become first-class storage providers (like NFS/s3fs/WolfDisk today): detect, install, service-control, and health-monitor them, whether they run native (systemd) or as Docker containers deployed from the App Store.
3. **Bucket management** — list/create/delete buckets on any saved S3 remote (local server or external cloud) from the Storage view. Listing already exists (`storage::list_remote_buckets`); create/delete are new.
4. **Bucket sync jobs** — "keep bucket A on remote X in sync with bucket B on remote Y" via rclone `copy` (default) or `sync` (gated — it deletes), scheduled back-to-back with run history, lag tracking, and alerting. Local↔cloud, cloud↔cloud, and local↔local pairs are all just two remote ids — the engine doesn't care where either side lives. This encodes the hard-won lessons from the wtgrid asset-mirror deployment (2026-08-14→17).

No code in this document — plan only.

---

## What already exists (grounded in source)

| Thing | Where | Reuse |
|---|---|---|
| Saved S3 remotes store (endpoint+region+keys, masked API view, rclone.conf read-only import) | `src/storage/mod.rs:2099` `S3Remote` / `S3RemoteInfo` | **The credential store for everything below.** Sync jobs reference remotes by id, never copy credentials. |
| Remote CRUD API (add via `SaveS3RemoteRequest`, list, delete) + bucket list | `src/api/mod.rs:24889-24967`, routes `:45905-45908`; UI `web/js/app.js:10714+` | Pillar 1 extends this exact surface — no parallel store, no second credentials path. |
| S3 mounts on remote storage (s3fs primary, rust-s3 read-only fallback) with region/endpoint signing handled | `src/storage/mod.rs:889-973` | Untouched — mounts keep working; the new health monitor watches the same endpoints those mounts depend on. |
| Bucket listing per remote | `src/api/mod.rs:24967` `storage_s3_remote_buckets` → `storage::list_remote_buckets` | Extend alongside with create/delete. |
| Storage providers card (NFS/SSHFS/s3fs/WolfDisk: installed?, service status, install button) | `src/storage/mod.rs:2715` `list_providers()`, `:3074` `install_provider()`; UI `web/js/app.js:55032` `loadStorageProviders()` | Add `garage` + `minio` entries — same card, same UI. |
| MinIO + Garage Docker manifests | `src/appstore/mod.rs:4229` (MinIO), `:9896` (Garage) | Provider detection must also see these (docker ps), not just systemd units. |
| Recurring-job scheduler pattern | `src/main.rs:2897` 60s loop → `spawn_blocking(backup::check_schedules)` | Same pattern for the sync scheduler loop. |
| Run-history / outcome pattern | `src/backup/mod.rs:7390` `ScheduleRunSummary`; hook runner with `timeout --kill-after` `:7409` | Same shape for per-run sync records; same coreutils-timeout guard for rclone. |
| Cron matcher | `src/wolfflow/…:778` `cron_matches()` | Optional cron schedules reuse it — no new cron parser. |
| Alerting | `src/alerting.rs:455` `AlertCategory` (Threshold→"info", Posture/BruteForce→"warning", Compromise→"critical"), `send_node_alert`/`send_local_alert` | Sync failure / lag alerts. |
| Config persistence | JSON in `/etc/wolfstack/` via `crate::paths` | New `s3_sync.json` (+ garage admin tokens into the existing storage config, 0600). |
| Node proxy | `/api/nodes/{id}/proxy/{path}` | Datacenter view reads per-node sync/server state through it. |
| Native S3 client | `rust-s3 0.35` (Cargo.toml:82), already used for bind mounts | Bucket create/delete without shelling out. |

Nothing in the tree does bucket-to-bucket sync today (verified by grep) — the engine is genuinely new.

---

## Phase 1 — Remote S3 connections: finish what exists

**Current state (verified in source):** operators can already connect remote S3 storage — `POST /api/storage/s3-remotes` saves name/provider/endpoint/region/keys (`api/mod.rs:24913`), remotes from rclone.conf are imported read-only, an rclone.conf pasted into the s3fs editor is rescued into saved remotes, and mounts + bucket listing consume the store. What's missing is everything around the connection: nothing validates credentials at save time, there are no provider presets, and a remote whose endpoint dies (IDrive FRA2, 2026-08-14 — took the whole grid down for ~2h) is invisible until something downstream breaks.

### 1.1 Provider presets

The add-remote form gains a provider dropdown that pre-fills endpoint/region grammar: AWS (region-only, no endpoint), IDrive E2, Backblaze B2, Wasabi, Cloudflare R2, Scaleway, Hetzner Object Storage, DigitalOcean Spaces, plus "Garage (self-hosted)", "MinIO (self-hosted)", and "Other S3-compatible". Presets fill defaults only — every field stays editable. Exact endpoint URL patterns per provider are taken from each provider's published docs at implementation time (no guessed URLs); where an endpoint embeds an account-specific subdomain (IDrive E2's per-account host, R2's account id) the preset shows a placeholder explaining what to substitute, not a fake-valid default.

### 1.2 Test connection

A "Test" button on the add/edit form and on each saved-remote row: performs a ListBuckets (or, when the account is bucket-scoped and ListBuckets is denied — common on key-per-bucket setups — falls back to HEAD on a named bucket the operator supplies) via rust-s3 under `web::block`. Result reported inline: reachable / auth-failed / endpoint-unreachable / TLS error, with latency. Save does **not** hard-require a passing test (offline setup and firewall-pending cases are legitimate) but an untested/failing save is visibly badged.

### 1.3 Edit + upsert semantics

`save_s3_remote` derives the id from the name — the plan step here is to confirm and formalise the upsert behaviour (same name = update in place, keeping the id stable so mounts/sync jobs referencing it survive a key rotation), add an explicit edit flow in the UI (form pre-filled from the secret-free `S3RemoteInfo`, secret field blank = keep existing secret), and block deletion of a remote that is referenced by an enabled mount or sync job (report *what* references it instead — the same dependency-check courtesy the rest of WolfStack gives).

### 1.4 Remote endpoint health monitoring

A slow background probe (per saved remote, default every 5 minutes, jittered) does the cheapest authenticated call available (HEAD bucket if one is associated, else ListBuckets) and records reachable/latency/consecutive-failures. Surfaced three ways:
- status dot + last-checked on each remote row in the Storage view;
- `AlertCategory::Threshold` alert after N consecutive failures (default 3), clear-on-recovery, standard cooldown map — "IDrive E2 endpoint unreachable from node ws-1" arrives *before* the grid notices;
- the sync engine consults the same freshness data to annotate a job failure with "source remote was already unreachable" so the operator isn't debugging rclone when the problem is the provider.

Probes are per-node (a remote can be reachable from one node and not another — that's routing information, not noise). Opt-out per remote for metered/egress-billed endpoints; the probe is a metadata call, not a data transfer, but the operator decides.

---

## Phase 2 — Garage & MinIO as storage providers

New submodule `src/storage/s3_servers.rs` (storage/mod.rs is already 4,282 lines; keep it from becoming another api/mod.rs).

### 2.1 Detection (three forms per product)

- **Native systemd**: binary on PATH (`garage` / `minio`) + `systemctl is-active garage|minio` via the existing `service_status()` helper.
- **Docker**: container whose image matches `dxflrs/garage` / `minio/minio` (the App Store manifests) — via the existing Docker socket client in `containers/`.
- **Not installed**: show the install button.

Provider card gains a `detail` block (like `WolfDiskInfo`) showing: version, endpoint(s), bucket count, total objects/bytes, node/cluster health.

### 2.2 Install paths (`install_provider` extensions)

- **garage (native)**: download the static binary from the garagehq release URL, write a minimal single-node `/etc/garage/garage.toml` (rpc_secret + admin token generated, data dir under `/var/lib/garage`), systemd unit, `garage layout assign/apply` for single-node. Exact garage.toml keys and CLI sequence to be read from the garage docs/source at implementation time — **no guessed config keys** (the asset-mirror-1 box is a live reference install of v2.3.0).
- **minio (native)**: official server binary + systemd unit + `MINIO_ROOT_USER/PASSWORD` env file (0600), single-disk mode.
- **Docker**: the install button simply deep-links to the existing App Store manifests rather than duplicating them.

Install must end by registering the new server as a **saved S3 remote** (S3Remote with the generated key) so buckets/sync work on it immediately — that's the glue that makes Phases 3–4 usable with zero manual credential copying.

### 2.3 Health & stats collection

- **Garage**: admin API (`:3903`) — `GET /health` for liveness/cluster state; bucket list + per-bucket objects/bytes come from the admin API (cheap, unlike S3 LIST). Admin token stored root-0600. Exact endpoint paths read from the garage admin API spec at implementation time.
- **MinIO**: `GET /minio/health/live` + `/minio/health/cluster` (unauthenticated liveness probes); richer stats via `mc admin info --json` only if `mc` is present — degrade gracefully to the health probes when it isn't. Exact JSON fields read from mc source/docs at implementation time.
- Collected on the storage view load (on-demand) plus a slow background refresh feeding the provider card — **not** an every-10s poll; the icon-pack API stall (v25.12.7) is the cautionary tale about hammering per-view endpoints.
- Down/failed server raises `AlertCategory::Threshold` once (with cooldown via the existing `record_alert` map), clears on recovery.

### 2.4 Operational gotcha to encode

Deep-prefix LIST on garage (sqlite metadata, busy disk) can hang for minutes while point-GETs stay instant — observed live on asset-mirror-1 2026-08-17. Therefore: **never block a UI render on a full bucket LIST**; per-bucket object counts come from the admin API on garage, and on generic S3 remotes bucket stats are a lazy, explicitly-clicked "compute size" action with a visible spinner and timeout, never automatic.

---

## Phase 3 — Bucket management on saved remotes

Extend the existing S3 Remotes card in the Storage view:

- **List buckets** (exists) → becomes a table: name, created (where the API returns it), lazy size/objects (see 2.4).
- **Create bucket**: name validation per S3 rules (3–63 chars, lowercase/digits/hyphens/dots, no leading/trailing hyphen — cite the AWS spec in the code comment); path-style vs virtual-host handled the same way the mount path already does per provider. Implementation via rust-s3 — the exact create API (`Bucket::create` vs `create_with_path_style`) to be read from the rust-s3 0.35 source at implementation time.
- **Delete bucket**: only offered when the bucket is empty (a HEAD/LIST-1 check); typed-name confirmation dialog (matches the existing danger-action pattern). No force-delete-with-contents in v1.
- Remotes discovered read-only from rclone.conf (`editable: false`) get create/delete too — creating a bucket doesn't modify the remote's config, so read-only-ness of the *remote definition* is preserved (`storage/mod.rs:2406` already draws this line).

API: `POST /api/storage/s3-remotes/buckets` + `DELETE /api/storage/s3-remotes/buckets/{name}?id=…`, both `require_auth`, both `web::block` (list_remote_buckets already documents the runtime-in-runtime panic; same constraint).

---

## Phase 4 — Bucket sync jobs (the core ask)

### 4.1 Model — `/etc/wolfstack/s3_sync.json`

```
SyncJob {
  id, name, enabled,
  src:  { remote_id, bucket, prefix },     // remote_id → S3Remote store, resolved at RUN time
  dst:  { remote_id, bucket, prefix },
  mode: Copy | Sync,                        // Sync = rclone sync (DELETES at dst)
  schedule: BackToBack { gap_minutes } | Cron { expr },   // cron via wolfflow::cron_matches
  window: Auto | MaxAgeHours(n) | Full,     // --max-age; Auto = 4x last pass duration, min 24h
  tuning: { transfers, checkers, bwlimit }, // defaults 32/16/none (proven on asset-mirror-1)
  last_runs: [SyncRunRecord; keep 20],      // start, end, objects, bytes, errors, exit, log tail
  last_success_epoch,                       // = the lag clock
}
```

Credentials are **never** stored in the job — `remote_id` resolves against the S3Remote store when the run starts, so key rotation in one place fixes every job (and `s3_sync.json` stays secret-free).

### 4.2 Engine — how rclone is invoked

- rclone becomes an installable provider entry (it is not currently executed anywhere in the tree — verified; `allow-rclone.sh` only opens firewall egress). Install via distro package or the official install script — decided at implementation from what setup.sh already does for similar tools.
- **No credentials on disk**: remotes are materialised as rclone *connection-string / env-var* remotes on the child process (`RCLONE_CONFIG_<NAME>_TYPE=s3`, `…_ACCESS_KEY_ID`, etc. — exact variable grammar read from rclone docs at implementation time, not guessed). Nothing written to rclone.conf; nothing for a crashed run to leave behind.
- Run under coreutils `timeout --kill-after` (same as backup hooks, `backup/mod.rs:7409`) with a generous cap; `spawn_blocking` off the actix runtime; one in-flight run per job enforced by an in-process per-job mutex (the wtgrid flock lesson, moved in-process).
- **Stats are mandatory**: `--stats 30m --stats-one-line --stats-log-level NOTICE --log-level NOTICE` — plain NOTICE writes literally nothing, so a run would otherwise leave a 0-byte log (observed on asset-mirror-1). Final stats block parsed into `SyncRunRecord`; per-job log at `/var/log/wolfstack/s3-sync/<job>.log` with copytruncate-style rotation handled by WolfStack itself (rclone holds the log fd for the whole pass — logrotate `create` would orphan it).

### 4.3 Scheduling — the asset-mirror-1 lessons, encoded

These came from live operation of the wtgrid mirror and go straight into the design:

1. **`--max-age N` must be ≫ one pass, never equal to the interval.** A "new objects only" pass still LISTs the entire source (`--no-traverse` only skips the destination), so a pass over an 18.7M-object bucket took 6–7h and back-to-back 6h windows left a non-overlapping hole. Hence `window: Auto = max(24h, 4 × last pass duration)`.
2. **Back-to-back is the honest default, not cron.** `OnCalendar=hourly` against a 6h pass silently suppressed every elapse but one. Default schedule: next run starts `gap_minutes` (default 15) after the previous finishes. Cron remains available for genuinely short jobs.
3. **Copy is the default; Sync is dangerous.** For append-only/content-addressed stores, `copy` is simultaneously backup and failover feed, and deletions/corruption can never propagate. `mode: Sync` requires a typed confirmation in the UI ("sync deletes destination objects that vanish from the source") and shows a permanent red badge on the job row.
4. **A "still running" job looks identical to a broken one** unless the UI says otherwise — the job row must show `running (started HH:MM, 40m elapsed)` distinctly from `idle, next ≈ HH:MM`.

### 4.4 Monitoring & alerting

- **Lag** = now − `last_success_epoch`, shown on every job row.
- Alert when a run **fails** (exit ≠ 0 or errors > 0 in the stats): `AlertCategory::Threshold`, with the standard cooldown map so a flapping job doesn't spam.
- Alert when **lag exceeds threshold** (default `3 × (typical pass + gap)`, overridable per job) — this catches "runs are succeeding but the scheduler died" and "pass duration crept past the window".
- Scheduler loop: one new 60s `tokio::spawn` in main.rs beside the backup checker (`main.rs:2897` pattern, including the JoinError logging).
- Dashboard: sync-jobs summary joins the existing `DASH_SCOPED_TYPES` storage card data (`app.js:4719`) so failures surface at datacenter level.

### 4.5 Cluster scope — v1 decision

Jobs are **node-local**: created on and run by one node (the Storage view is per-node already, `selectServerView(node, 'storage')`). The datacenter view reads every node's jobs through the existing node-proxy routes for a combined read-only table. Cluster-global jobs with failover-follow-the-leader are explicitly out of v1 — that's WolfHA territory and needs the placement question answered properly, not sneaked in.

---

## Phase 5 — UI (theme adherence is a requirement, not a nicety)

New content lives in the existing per-node **Storage** view (`app.js:2492` loader chain gains `loadS3Servers()` and `loadSyncJobs()`):

- **S3 Servers card** — Garage/MinIO instances: status pill, version, endpoint, bucket count, capacity; install buttons for absent providers (existing providers-grid, new entries).
- **Buckets panel** — inside the existing S3 Remotes card: remote picker → bucket table → create/delete.
- **Bucket Sync card** — job rows: `src → dst`, mode badge, state (running/idle/disabled), last result, lag, next run; actions: run now, pause, edit, view log (tail served by API, not the whole file).

**Customer-theme rules (hard requirements):**
- Every colour comes from the theme tokens in `web/css/style.css` — `--bg-card`, `--bg-tertiary` (the aliased one — the Gary KO4BSR dark-box lesson), `--text-primary/-secondary/-muted`, `--border`, `--accent`. No hard-coded surface or text colours; the existing semantic status colours (`#10b981`/`#ef4444` pills) follow the established provider-card convention.
- Verified against the full `data-theme` set — light, midnight, datacenter, forest, punk, fruit, amber, blueprint, glass, trek, arctic, bat, obe1 — with special attention to the light themes, where every historic contrast bug has landed.
- Inline `var(--x, fallback)` fallbacks must be theme-safe (the `--text`/`--bg-tertiary` alias lessons at `style.css:35-56`).
- Feedback: every action produces a visible DOM result; error toasts `role="alert"`, non-auto-dismissing; destructive confirmations use the typed-name dialog pattern.
- Icons: emoji glyphs as the base (matching `list_providers` convention) so the icon-theme system (`applyIconTheme`) can substitute packs.
- `DOCS_PAGE_MAP` (`app.js:66534`) gains the new view mapping + a wolfstack.org doc page, per the "?" help-button convention.
- `node --check` on app.js + the no-undef lint gate before any commit (existing hooks enforce this).

---

## Security checklist (OWASP-mapped)

- **A01**: all new endpoints behind `require_auth`; node-proxied calls keep the existing `X-WolfStack-Secret` inter-node auth. No per-endpoint gaps.
- **A02**: garage admin token + minio root env files 0600 root-owned; `s3_sync.json` contains no secrets at all (remote-id indirection). The backup-credentials-0644 defect is the anti-pattern; do not repeat it.
- **A05/A10**: bucket names validated at the boundary (S3 naming spec); rclone args passed as argv array, never through a shell string — bucket/prefix values can't inject flags; error responses return the rclone stderr tail, never credentials or env.
- **Logs**: sync logs contain object keys, not credentials (env-var injection keeps keys out of argv → out of `ps` too).

---

## Delivery order & test plan

| Step | Deliverable | Runtime verification |
|---|---|---|
| 1 | Remote-connection polish: presets, test-connection, edit flow, delete-dependency check | Dev: add a scratch IDrive E2 remote via preset, test-connection against it (good key, bad key, dead endpoint), edit-with-blank-secret keeps the old key, delete blocked while a mount references it |
| 2 | Remote endpoint health probes + alert | Dev remote pointed at a stopped garage → alert after 3 misses; restart → clear-on-recovery; opt-out flag suppresses the probe |
| 3 | rclone + garage + minio provider entries (detect/status/install) | Dev box + asset-mirror-1 (existing native garage v2.3.0 = live detection fixture); MinIO via App Store docker deploy on dev |
| 4 | Bucket list/create/delete on saved remotes | Against dev garage + a scratch IDrive E2 bucket — **never** the production wtgrid remotes ([[never-test-on-production]]) |
| 5 | Sync engine + one manual "run now" job | Dev: garage→garage two-bucket copy, then copy with prefix, then cloud↔local (scratch E2 bucket → dev garage), then a deliberate failure (bad key) to prove the run-record + alert path |
| 6 | Scheduler + lag alerting | Short-gap job on dev, kill mid-run, verify single-flight + lag alert + recovery |
| 7 | UI card polish across all themes + docs page | Manual pass on every `data-theme`; screenshots light + dark |

Unit tests follow the module's existing style: window-auto arithmetic, stats-block parsing (fixture from a real asset-mirror-1 log), S3 bucket-name validation, schedule gap logic, upsert-keeps-id + blank-secret-keeps-secret on remote save, and serde round-trip of `s3_sync.json` with `#[serde(default)]` back-compat.

## Decision points for Paul (recommendations embedded)

1. **Native install scope**: plan says single-node garage/minio only; multi-node garage cluster layout from the UI is out of v1. OK?
2. **Sync mode `sync`** (deleting) included but typed-confirmation-gated — or omit entirely in v1 and ship copy-only?
3. **Node-local jobs** with datacenter read-only rollup (recommended) vs cluster-global jobs in v1?
4. **Backup-destination convergence**: `backup/mod.rs` has its own `StorageType::S3` with inline credentials. Migrating backups to the shared S3Remote store is deliberately out of scope here but is the obvious follow-on — flag it now so it's a decision, not drift.
