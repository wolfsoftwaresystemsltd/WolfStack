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
| **P2: VM lifecycle + console** | Start / stop / reboot / halt buttons. VNC websocket proxy. | wired in `xo::vm_action`, frontend not yet |
| **P3: Provision + cloud-init** | "Provision tenant" wizard — pick template, N VMs, cloud-init payload installs WolfStack and joins them to the customer cluster. WolfNet defaults baked in. | not started |
| **P4: Tenant federation** | Aggregator dashboard, SP drill-in, federation tokens. See `tenant-federation.md` (TBD). | not started |

## Storage, files, and routes

- **State**: `/etc/wolfstack/xo_pools.json` — list of registered
  XO instances. Path overridable via `paths.xo_pools_config`.
- **Backend**: `src/xo/mod.rs` — XoClient + XoPool + XoStore.
- **Routes** in `src/api/mod.rs`:
  - `GET /api/xo/pools`
  - `POST /api/xo/pools`
  - `DELETE /api/xo/pools/{id}`
  - `POST /api/xo/pools/{id}/test`
  - `GET /api/xo/pools/{id}/inventory`
- **Frontend**: drawer tile `🦊 XO Pools` → `selectView('xopools')`
  → `renderXoPools()` in `web/js/app.js`. Page mount point is
  `#page-xopools` in `web/index.html`.

## What's intentionally NOT in P1

- **Lifecycle action buttons** (start/stop/reboot). Backend method
  exists (`XoClient::vm_action`) but no UI yet — comes in P2 once
  we've shaken bugs out of the inventory parsing.
- **Console access**. XO's VNC websocket needs a proxy on our side.
- **Template provisioning**. The whole cloud-init / cluster-join
  pipeline. Comes with the tenants feature in P3.
- **Pool selection per registration**. Right now one XO instance
  exposes all of its pools. If a customer has multiple pools in a
  single XO and the SP only wants to see one, that's a future
  refinement.
