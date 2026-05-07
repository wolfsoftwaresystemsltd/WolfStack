# XCP-ng / Xen Orchestra integration

WolfStack drives XCP-ng pools through Xen Orchestra's REST API, the
same way it drives Proxmox VE through `pveproxy`. This document
covers the architecture, the surface we wrap, the rationale for
specific choices, and the WolfNet considerations that come up when
WolfStack itself runs *inside* XCP-ng VMs.

## Why XCP-ng / Xen Orchestra at all

A common service-provider deployment is:

- SP runs **WolfStack** as their internal/admin platform
- SP rents **VMs** to customers, provisioned via Xen Orchestra 6 on top of XCP-ng
- Each customer wants their **own WolfStack cluster** running on the rented VMs
- SP wants **one pane of glass** across every customer cluster

The XO integration is the bottom half of that stack — it lets the
SP's WolfStack discover, inspect, and (P2+) drive the actual VMs.
The tenant federation (separate doc, P4) is the top half.

## Architecture

Two layers, each running real WolfStack — no fake "lite" customer
mode:

```
┌─ SP WolfStack (master) ──────────────────────────────────────┐
│   XO Pools page (this integration):                          │
│     • register XO instances by URL + bearer token            │
│     • read pools / hosts / VMs / templates                   │
│     • lifecycle actions on VMs (P2)                          │
│     • provision-VM-from-template + cloud-init bootstrap (P3) │
│                                                              │
│   Tenants page (separate, federation):                       │
│     • per-customer WolfStack cluster of those VMs            │
│     • aggregator dashboard, SSO drill-in                     │
└──┬─────────────────────────────────────────────────────────┬─┘
   │ XO REST + bearer token                                  │ tenant token
   ▼                                                         ▼
┌─ XCP-ng pool (1..N hosts) ──────┐         ┌─ Customer cluster ─┐
│   bare metal, Xen kernel        │ creates │   3 WolfStack VMs  │
│   stores VMs                    │ via XO  │   with full LXC    │
└─────────────────────────────────┘         └────────────────────┘
```

## Why XO REST and not raw XAPI

XCP-ng hosts speak XAPI (XML-RPC) natively — that's the underlying
control plane. Talking XAPI directly avoids depending on XO running
at all. We chose XO REST because:

- **Object model is friendlier**: XO normalises pools / hosts / VMs
  / templates / SRs into a coherent REST resource tree. XAPI
  exposes the raw OCaml objects with hundreds of fields per type.
- **Auth is simpler**: XO mints user tokens through its UI; XAPI
  needs a session login per request.
- **Live websocket option**: when we want push updates instead of
  polling, XO has a websocket subscription channel; XAPI doesn't.
- **Same path the operator already uses**: most XCP-ng installs
  already have XO running for the UI, so requiring it isn't
  imposing a dependency the operator doesn't already have.

The trade-off is one extra moving part (XO daemon) in the chain.
If a customer runs XCP-ng without XO, they'd need to install
`xen-orchestra` from sources or use the Vates appliance.

## What changes vs the Proxmox integration

XCP-ng is a **Type-1 hypervisor**. There is no host-level LXC.
With Proxmox we get LXC for free at the hypervisor level (PVE
hosts CTs natively); here the LXC layer lives one VM down, inside
guest VMs running WolfStack.

So the "takeover" pattern works at two layers, not one:

| Layer | Proxmox path | XCP-ng path |
|---|---|---|
| Hypervisor | WolfStack drives PVE; PVE hosts CTs and VMs | WolfStack drives XO; XO drives XCP-ng pools; pools host VMs only |
| Containers | LXC at hypervisor level | LXC inside WolfStack VMs (one VM deeper) |

## XO REST surface we wrap

`src/xo/mod.rs` mirrors `src/proxmox/mod.rs` shape:

| WolfStack-side | XO endpoint |
|---|---|
| `XoClient::new(url, token)` | n/a — token from XO Settings → Tokens |
| `test_connection()` | `GET /rest/v0` |
| `list_pools()` | `GET /rest/v0/pools?fields=…` |
| `list_hosts()` | `GET /rest/v0/hosts?fields=…` |
| `list_vms()` | `GET /rest/v0/vms?fields=…` |
| `vm_action(uuid, action)` | `POST /rest/v0/vms/{uuid}/actions/{action}` |
| `full_inventory()` | parallel fan-out of the above |

Reference: <https://docs.xen-orchestra.com/restapi>

## Token storage

Tokens are XOR'd with a fixed prefix and base64'd before going to
disk in `/etc/wolfstack/xo_pools.json`. This is the same scheme
WolfStack uses for the rest of its at-rest secrets — it's *not*
encryption (the key is hard-coded in the binary), it's a
"`cat` won't spill it" safeguard. The actual access control is
filesystem permissions on `/etc/wolfstack/`.

Token is never sent back to the frontend. After registration it
stays server-side until the operator unregisters the instance.

## WolfNet considerations when WolfStack runs inside VMs

When the SP provisions 3 WolfStack VMs for a customer, the
customer's cluster runs WolfNet inside those VMs. Three things
matter:

### 1. Topology — do they actually need WolfNet?

| Case | Recommendation |
|---|---|
| All 3 VMs on the same XCP-ng pool / same L2 network | WolfNet works but is over-engineered. The VMs already see each other on the bridge. Recommend: skip WolfNet, point the cluster at native LAN IPs. |
| VMs spread across pools / sites / WAN | WolfNet is exactly what it's for. Each VM gets a `10.10.10.x` address, traffic encrypted, NAT-traversal handled by wireguard's keepalive. |

The provisioning template (P3) defaults to **WolfNet on** so the
customer gets a stable cluster address space even if they later
split VMs across pools.

### 2. MTU

XCP-ng's default VM MTU is 1500. Wireguard adds ~80 bytes overhead
→ effective payload 1420. If those VMs then run LXC containers
with their own WolfNet (nested cluster), the inner overlay drops
to 1340. Default cluster WolfNet MTU is set to **1380** in the
provisioning template to leave headroom for the nested case.

### 3. Tenant isolation

Each customer cluster has its own WolfNet — different wireguard
keys, no peer relationships across customers. Customer A's
`10.10.10.0/24` and Customer B's `10.10.10.0/24` don't conflict
because they're separate wireguard networks.

The SP's WolfStack does **not** join either WolfNet. It talks to
each customer cluster via federation REST tokens over the
management network. Customer data never leaves the customer's
WolfNet.

## Phased delivery

| Phase | Ships | Status |
|---|---|---|
| **P1: Read-only inventory** | XO instance registration, pools / hosts / VMs read, status pills | **shipped** |
| **P2: VM lifecycle** | Start / stop / reboot / hard-halt / suspend / resume buttons in the VM table. Confirmations on destructive ops. VNC console proxy intentionally deferred — needs websocket forwarding which is its own engineering problem. | **shipped** |
| **P3: Provision + cloud-init** | "+ Provision VM" button on each pool card opens a wizard: template select, name, CPUs, memory, optional auto-install of WolfStack via cloud-init. The cloud-init payload sets the hostname and runs `setup.sh` (proxied through the SP — Path B — with a GitHub fallback). The new VM is a single-node cluster after first boot. Multi-VM cluster formation is an explicit operator step using the existing dashboard "Add Node" flow. | **shipped** |
| **P4: Tenant federation** | New `🏢 Tenants` tile in the Apps & Tools drawer. SP-side: register / list / refresh / delete tenant clusters. Customer-side: `/api/federation/status` endpoint and `/api/federation/tokens` CRUD. Roll-up dashboard showing tenant count, host count, VM count, container count, aggregate memory across every customer cluster. | **shipped** |
| **Future**: VNC console proxy | Forward XO's noVNC websocket through wolfstack so the operator can console into a VM without leaving the WolfStack UI. | not started |
| **Future**: SP→tenant SSO drill-in | One-click into a tenant's WolfStack UI as an operator role rather than just opening the URL in a tab. | not started |

## Storage, files, and routes

- **State**: `/etc/wolfstack/xo_pools.json` — list of registered
  XO instances. Path overridable via `paths.xo_pools_config`.
- **Backend**: `src/xo/mod.rs` — XoClient + XoPool + XoStore.
- **Routes** in `src/api/mod.rs`:
  - **XO inventory + lifecycle** — all require operator session auth, all SSRF-gate operator-supplied URLs through `validate_outbound_url`:
    - `GET /api/xo/pools` — list registered pools (token never returned)
    - `POST /api/xo/pools` — register; runs Test Connection before persist
    - `DELETE /api/xo/pools/{id}` — unregister
    - `POST /api/xo/pools/{id}/test` — re-probe + status update
    - `GET /api/xo/pools/{id}/inventory` — pools + hosts + VMs
    - `POST /api/xo/pools/{id}/vms/{vm_uuid}/action` — start/clean_reboot/clean_shutdown/hard_shutdown/suspend/resume (action whitelisted in `XoClient::vm_action`)
    - `GET /api/xo/pools/{id}/templates` — list VM templates
    - `POST /api/xo/pools/{id}/vms` — create from template; vm_name validated as RFC 1123 hostname
  - **Tenant federation (SP side)** — operator session auth, SSRF-gate on tenant URLs, file ops protected by `TENANTS_LOCK`:
    - `GET /api/tenants` — list (token never returned)
    - `POST /api/tenants` — register; probes federation status before persist
    - `DELETE /api/tenants/{id}` — unregister
    - `POST /api/tenants/{id}/refresh` — re-poll
  - **Federation status (tenant side)** — bearer-token auth via constant-time comparison against `/etc/wolfstack/federation_tokens.json`:
    - `GET /api/federation/status` — snapshot of host / VM / container counts + memory + cpu
    - `GET /api/federation/tokens` — list, masked to 8-char head + ellipsis
    - `POST /api/federation/tokens` — mint via `OsRng` (CSPRNG); 48-char alphanumeric; full token returned ONCE
    - `DELETE /api/federation/tokens/{prefix}` — revoke; prefix must be exactly 8 chars to prevent over-broad revoke
  - **Path B install proxy** — public (no auth, upstream is public):
    - `GET /api/install/setup.sh` — proxies upstream with 5-min cache
- **Frontend**: drawer tile `🦊 XO Pools` → `selectView('xopools')`
  → `renderXoPools()` in `web/js/app.js`. Page mount point is
  `#page-xopools` in `web/index.html`.

## Tenant federation (P4) — the customer-side surface

Each customer cluster ships the same WolfStack binary as the SP.
The federation endpoint is one of the routes that binary exposes:

```
GET /api/federation/status       Authorization: Bearer <token>
```

Returns this JSON:

```json
{
  "host_count": 3,
  "vm_count": 0,
  "container_count": 12,
  "mem_total_mb": 16384,
  "mem_used_mb": 4892,
  "cpu_pct": 12.4,
  "wolfstack_version": "22.9.38",
  "timestamp": "2026-..."
}
```

Tokens live in `/etc/wolfstack/federation_tokens.json` — a flat
JSON array of strings. The customer's admin manages them via:

```
GET    /api/federation/tokens          → list (first 8 chars only)
POST   /api/federation/tokens          → mint a new one
DELETE /api/federation/tokens/{prefix} → revoke by 8-char prefix
```

When a token is created, the full string is returned **once** and
never again. The customer copies it and gives it to the SP.

The SP-side flow:

1. SP enters customer URL + token in the Tenants tab "Register"
   modal.
2. SP-side WolfStack probes `GET /api/federation/status` with the
   bearer token. If anything but a 200 with parseable JSON comes
   back, the registration is rejected and nothing is saved.
3. On every refresh (manual or future auto-poll), the SP re-hits
   the status endpoint and updates the tenant row.

## Cloud-init payload (P3 detail)

The auto-install payload generated by `xo::cloud_init::build_wolfstack_user_data`
is plain cloud-config YAML. Honest scope: it installs WolfStack
on the new VM and brings up the daemon. Multi-VM cluster
formation is **not** in this payload — it's an operator step
documented below.

Verbatim shape (when `sp_url` is set, i.e. Path B):

```yaml
#cloud-config
hostname: <provided>
package_update: false
package_upgrade: false
runcmd:
  - bash -lc 'hostnamectl set-hostname '"'"'<hostname>'"'"''
  - bash -lc 'curl -fsSL --max-time 30 "<sp_url>/api/install/setup.sh" -o /tmp/wolfstack-setup.sh
              || curl -fsSL --max-time 60 "<github_raw>" -o /tmp/wolfstack-setup.sh;
              sudo bash /tmp/wolfstack-setup.sh --yes [--agent]'
  - bash -lc 'systemctl enable wolfstack || true'
  - bash -lc 'systemctl restart wolfstack || true'
final_message: "WolfStack first-boot finished after $UPTIME seconds. ..."
```

Three things to know:
- **`package_update: false`** — apt's preseed can take 10+ minutes;
  we skip it on first boot. `setup.sh` handles its own deps.
- **No cluster join in cloud-init.** The earlier draft had
  `wolfstack cluster join`/`init` lines but those CLI subcommands
  don't exist — wolfstack is a server, not a management CLI.
  Cluster formation goes through `POST /api/nodes` on the master
  with the new VM's `/etc/wolfstack/join-token`. Operator does
  this from the existing dashboard "Add Node" flow.
- **No WolfNet MTU 1380 line.** WolfNet config is owned by
  `setup.sh` — writing a partial `/etc/wolfnet/config.toml`
  would break the schema (which requires `[network] address =
  "10.x.x.x"` etc.). MTU tuning is a post-install operator
  adjustment if you need it for nested-wireguard scenarios.

### Path B install proxy

The SP's WolfStack exposes `GET /api/install/setup.sh` as a 5-min
cached proxy of the canonical
`raw.githubusercontent.com/.../master/setup.sh`. When the
operator provisions through the wizard, `sp_url` defaults to the
SP's own origin → cloud-init prefers the SP-hosted copy →
falls back to GitHub if the SP is unreachable. This pins the
install version to what the SP is running and lets the customer
VM install even when GitHub is blipped or behind corporate
egress rules. The endpoint is intentionally public (no
`require_auth`) — cloud-init has no session cookie, and the
upstream artefact is public anyway.

### Multi-VM cluster formation (operator step)

After the wizard provisions N VMs, the operator forms the
cluster manually:

1. Pick one VM to be the master (typically the first).
2. From the master's WolfStack dashboard → **Servers tree** →
   **Add Node** (or `POST /api/nodes`).
3. Supply the new node's IP and the contents of
   `/etc/wolfstack/join-token` from that node (read it via SSH
   or via `wolfstack --show-token` on that VM).

A future "Provision N-VM cluster" wizard will orchestrate this
end-to-end (provision VM1 → wait for reachability → discover IP
+ join-token → provision VM2/3 with that info pre-baked → loop
add-node calls). It's not in this release because doing it
properly requires a new bootstrap-auth pattern that lets the SP
talk to a fresh VM before the operator has logged into it; that
needs careful security thinking and isn't a one-day job.

### Template requirements

The XO VM template the operator picks must have cloud-init guest
tools installed. The Vates and upstream XO templates include
them; if a customer rolls their own template, they need
`apt install cloud-init` (or distro equivalent) baked in.

## What's intentionally NOT in P1-P4

- **VNC console proxy**. XO's noVNC websocket needs a proxy on our
  side (websocket → websocket forwarding with bearer-token auth).
  Listed under Future.
- **SP→tenant SSO drill-in**. Right now "Open" on a tenant card
  opens the customer's WolfStack URL in a new tab — the operator
  has to know the customer's admin login. A signed one-time URL
  that auto-logs the SP in as an operator role is Future.
- **Pool-scoped XO registration**. Right now one XO instance
  exposes all of its pools. Future refinement: register a single
  pool when the SP has many customers sharing one XO.
- **Auto-poll of tenant status**. P4 ships with manual refresh per
  tenant. A 30s background poll is a small follow-up — the
  scheduler exists, just need to wire it in.
