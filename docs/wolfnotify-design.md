# WolfNotify — event notification & automation, design

**Status:** proposal, nothing built.
**Asked for:** "report when dockers/VMs go down or error … program any combination
of things to send you a notification via your preferred system" (Paul, 2026-08-06).
**Steer given:** the *user* decides both axes — simple vs advanced rules, and
per-node vs cluster-wide scope. Neither is a global setting; both are properties
of a rule.

---

## 1. What already exists (verified in-tree, 2026-08-06)

The delivery half is done. This is the single most important fact about this
feature, because it means **we should not build a second notification subsystem.**

| Piece | Where | State |
|---|---|---|
| Channel dispatch — Discord, Slack, Telegram, ntfy, email | `alerting.rs:920 dispatch_to_channels` | Working, secrets masked in the API |
| Alert categories — Compromise / BruteForce / Posture / Threshold / Lifecycle | `alerting.rs:460 AlertCategory` | Working |
| Verbosity — Simple (compromise only) vs Verbose | `alerting.rs:446 AlertVerbosity` | Working, but **global** |
| Node offline / restored alerts | `alerting.rs` `alert_node_offline`, `alert_node_restored` | Working |
| Multi-step actions across nodes, cron-scheduled | `wolfflow/mod.rs` | Working, **cron-triggered only** |
| Config replication across the cluster (last-write-wins on a `version` field) | `auth/users.rs:24`, threat-intel allowlists | Proven pattern to copy |

A second `wolfnotify` with its own channel config would mean two secret stores,
two retry paths, and two places to look when something failed to page you. So:
reuse `dispatch_to_channels`, add what is genuinely missing in front of it.

## 2. The three real gaps

1. **Nothing observes container or VM state.** `alert_containers` reads as though
   it does, but it only gates per-container *memory* findings
   (`predictive/container_memory.rs:137`); the threshold dispatch beside it in
   `main.rs` is explicitly marked RETIRED. Nothing consumes `docker events`,
   libvirt lifecycle, or `pct` state. A container that exits non-zero, is
   OOM-killed, fails its healthcheck, or restart-loops is **completely silent
   today.** This is the bulk of the work.

2. **Routing is global.** One verbosity switch, every enabled channel gets
   everything. You cannot say "compromise → ntfy on my phone, container restarts
   → a Discord channel, disk warnings → email only".

3. **WolfFlow cannot react.** It already has the actions, targeting and cluster
   execution — it just has no event trigger, so "when X happens, do Y" is
   inexpressible.

## 3. Architecture

Three components, each small, in front of the dispatcher that already works.

```
  docker events ─┐
  libvirt/virsh ─┼─→  event source  ─→  rule engine  ─→  dispatch_to_channels()  (exists)
  pct / lxc     ─┘    (typed events)     (match+route)  └→  WolfFlow run (new trigger)
```

### 3a. Event source

A supervised task per backend, translating native state changes into one typed
`NotifyEvent`. Backends are independent so a host without libvirt simply runs
fewer sources.

- **Docker** — `docker events --format '{{json .}}'` as a long-lived child.
  Must be supervised: the stream dies whenever the daemon restarts, and a dead
  source that silently stops reporting is worse than no feature at all. Restart
  with backoff, and treat "source down" as itself an alertable condition.
- **libvirt** — `virsh event --loop`, same supervision.
- **LXC / Proxmox** — no event stream; poll `lxc-ls -f` / `pct list` on the
  existing cluster-poll cadence and diff against the last observed state.

### 3b. Event taxonomy

Deliberately small and stable. Everything else is an attribute, not a new type.

| Event | Fires when |
|---|---|
| `object_stopped` | Clean stop (exit 0, or an operator action) |
| `object_failed` | Exit non-zero, crash, VM entered a failed state |
| `object_oom_killed` | Kernel OOM-killed the workload |
| `object_health_failed` | Healthcheck transitioned to unhealthy |
| `object_restart_looping` | N restarts within a window — the single most useful signal, and invisible today |
| `object_started` | Recovery, so a rule can close its own incident |
| `source_degraded` | The event source itself died or is not reporting |

Each event carries: `node`, `backend` (docker/libvirt/lxc/pve), `object` (name),
`labels`/tags, `exit_code`, `restart_count`, `timestamp`, `message`.

### 3b-ii. Probe events — the silent-failure case

Lifecycle events only catch a workload that *stops*. The nastier failure is the
one that keeps running: a container that is `Up 3 days`, healthy by every state
check, and has quietly lost outbound connectivity. Nothing in WolfStack notices,
`docker ps` looks perfect, and the operator burns an afternoon on it (Paul,
2026-08-06 — "took a long time to figure out").

This is not a niche extra; it is the case that most justifies the subsystem,
because it is the one where state monitoring is structurally blind.

| Event | Fires when |
|---|---|
| `object_egress_failed` | The probe target became unreachable *from inside the object's network* |
| `object_egress_restored` | It came back |

Probe config lives on the rule, so the user defines what "reachable" means for
their workload:

```jsonc
"probe": {
  "kind": "egress",
  "method": "dns",              // dns | tcp | http | icmp
  "target": "1.1.1.1:53",       // or a URL for http, a host for icmp
  "interval": "60s",
  "failures_before_firing": 3   // don't page on one dropped packet
}
```

**Implementation note — probe from the host, inside the container's netns.**
Run the *host's* binary inside the container's network namespace
(`nsenter --net -t <pid> -- …`), rather than requiring curl/ping to exist in the
image. Minimal images have neither, and installing tools into a customer's
container to monitor it is not acceptable. This is the same trick
`auth::kernel_block_ip` already uses to mirror a block into a macvlan container's
namespace — precedent in-tree, and it works on a `FROM scratch` image.

Note this is a different direction of travel from the existing status-page
monitors, which check *inward* (can the world reach this service). Egress probes
check *outward* (can this workload reach the world). Both are needed; neither
substitutes for the other.

### 3c. Rule model — the user defines both axes

```jsonc
{
  "id": "…",
  "name": "Databases going down",
  "enabled": true,

  // AXIS 1 — scope. The user's choice, per rule.
  //   "node"    → evaluated and stored on this node only
  //   "cluster" → replicated to every node (version field, last-write-wins,
  //               exactly like AuthConfig / threat-intel allowlists)
  "scope": "cluster",

  // AXIS 2 — complexity. The user's choice, per rule.
  //   "simple"   → match + notify. The 90% path, must stay one screen.
  //   "advanced" → conditions combined, windows, counts, suppression.
  "mode": "simple",

  // simple mode
  "match": {
    "events": ["object_failed", "object_oom_killed"],
    "backends": ["docker"],
    "objects": ["*-db", "postgres"],        // glob on name
    "labels": { "tier": "prod" },           // all must match
    "nodes": ["*"]
  },

  // advanced mode — ignored unless mode == "advanced"
  "conditions": {
    "all": [
      { "event": "object_restart_looping", "within": "10m", "count": 3 },
      { "not": { "maintenance_window": true } }
    ],
    "any": []
  },

  // ROUTING — per rule, replacing the global verbosity for these events
  "channels": ["ntfy", "discord"],
  "cooldown": "15m",                        // per (rule, object)

  // ACTION — optional; this is the WolfFlow bridge
  "run_flow": "restart-and-capture-logs"
}
```

Design notes that matter:

- **Simple is not a lesser mode.** It is the default and must be completable
  without reading documentation. Advanced is an explicit toggle that reveals the
  condition builder — the user opted in to the complexity.
- **Cooldown is per (rule, object)**, not per rule. One flapping container must
  not silence alerts for its twenty healthy neighbours. This is the mistake that
  makes notification systems get switched off.
- **Recovery closes the alert.** `object_started` after a fired rule sends a
  resolution, or the operator learns to ignore the channel.
- **`scope: "cluster"` reuses the existing replication pattern** — a `version`
  field stamped on save, last-write-wins across peers. Not a new mechanism.

### 3d. Storage & code touchpoints

| Concern | Location |
|---|---|
| Rules | `/etc/wolfstack/notify-rules.json`, 0600, `version` for replication |
| Event source | new `src/notify/source_docker.rs`, `source_libvirt.rs`, `source_poll.rs` |
| Rule engine | new `src/notify/mod.rs` — pure `evaluate(event, rules) -> Vec<Match>`, unit-testable with no I/O |
| Dispatch | **existing** `alerting::dispatch_to_channels` — extended to take an explicit channel list rather than reading the global config |
| Action bridge | `wolfflow` gains an event trigger alongside cron |
| API | `/api/notify/rules` CRUD, `/api/notify/test` (fire a synthetic event), `/api/notify/events` (recent, for debugging) |
| UI | Alerting page gains a Rules tab; simple/advanced toggle per rule |

The rule engine being pure is the point: `evaluate()` takes an event and a rule
set and returns matches, with no clock, no filesystem and no network. Windows and
counts take the timestamp as a parameter. That makes the hard part — "3 failures
in 10 minutes, but not during maintenance" — testable without spinning up
containers.

## 4. Phasing

1. **Docker event source + simple rules + per-rule routing.** Delivers the actual
   ask ("tell me when a docker goes down") and is independently useful.
1b. **Egress probes.** Small, self-contained, and catches the failure class that
   state monitoring cannot see at all. Arguably higher value per line of code
   than anything else here — ship it early, not last.
2. **libvirt + LXC/PVE sources.** Same rule model, more backends.
3. **Advanced conditions** — windows, counts, suppression, maintenance windows.
4. **WolfFlow event trigger** — rules can act, not just tell.
5. **Cluster-scope replication** for rules marked `scope: "cluster"`.

Phases 1 and 2 are worth shipping before 3 exists; a simple rule that works beats
a condition builder that nearly does.

## 5. Risks, honestly

- **A dead event source is silent failure.** The whole feature's value is that it
  speaks up; a source that quietly stopped is worse than not having it, because
  the operator now trusts it. `source_degraded` must itself alert, and the UI must
  show each source's last-seen time.
- **Alert fatigue kills it.** Per-object cooldowns, recovery notifications and a
  conservative default rule set are not polish — they decide whether the feature
  survives contact with a flapping container.
- **`docker events` is a child process on every node.** It must be supervised,
  bounded, and must not leak descriptors — see `tests/resource_safety.rs` and the
  2026-08-05 fd-exhaustion outage. The connect-timeout/fd rules apply.
- **Restart-loop detection needs state** across events, which is the first thing
  in this design that isn't stateless. Keep that state small, in memory, and
  reconstructable — never a source of truth worth persisting.
- **Cluster-scoped rules can double-notify** if two nodes both evaluate an event
  for a third. Decide early: the node that *owns* the object evaluates, peers do
  not.

## 5b. Survey probes — documentation as a probe type (Paul, 2026-08-06)

> "a documentation probe you can use to document things … with settings like
> infrastructure etc and produce a PDF report"

The probe metaphor extends past monitoring. A **survey probe** is launched at a
target, collects, and returns a report rather than a stream of events.

This is not speculative — the pipeline exists and was exercised on 2026-08-06:
a read-only collector run over 12 hosts + 6 containers, rendered to HTML and
printed to PDF with headless chromium (`chromium --headless --print-to-pdf`,
already a dependency of the container-browser feature). That produced a 12-page
estate document. The work is turning that from an ad-hoc script into a probe.

**What differs from a monitoring probe** — and why it may want its own bay:

| | Monitoring probe | Survey probe |
|---|---|---|
| Runs | Continuously | On demand, or on a schedule |
| Emits | Events → notifications | An artefact (PDF/HTML/Markdown) |
| Succeeds by | Staying quiet | Producing a document |
| Failure mode | Missed alert | Stale or wrong document |

They share the useful half: target selection (which nodes, which objects, which
globs), scoping, and scheduling. That argues for one "probe" concept with a
`kind` (`monitor` | `survey`), not two subsystems — the same argument that kept
this out of a separate `wolfnotify` from the delivery channels.

**Sketch:**

```jsonc
{
  "kind": "survey",
  "name": "Estate documentation",
  "targets": { "nodes": ["*"] },
  "sections": ["hosts", "networking", "storage", "containers", "databases"],
  "format": "pdf",
  "schedule": "0 6 * * 1",          // optional; on-demand if absent
  "deliver": { "channels": ["email"], "path": "/var/lib/wolfstack/reports" }
}
```

**Worth deciding early:** a survey probe reads far more of the estate than a
monitoring probe, and its output is a single document containing topology,
addressing and versions. That is genuinely useful and genuinely sensitive — it
must never be written somewhere world-readable by default, and "email it to me"
needs to be a deliberate choice rather than a default. Credentials must never be
collected at all, which the 2026-08-06 collector already enforced by never
reading secret files.

## 6. Open decisions

1. Does a cluster-scoped rule notify once per cluster, or once per node that
   matches? (Recommend: once, by the owning node — see risk above.)
2. Should rules be tier-gated like Fleet Logs, or core?
3. Do we need a maintenance-window primitive in phase 1, or is a global "mute
   until" enough to start?
