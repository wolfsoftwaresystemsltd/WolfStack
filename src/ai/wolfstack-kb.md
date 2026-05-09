# WolfStack Expert Knowledge Base

## Behavioural rules for the AI (READ THIS FIRST)
**Never hallucinate. If you don't know something, say so.**
- If the user asks about a feature, command, file path, port, config field, API endpoint, or version, and you can't verify it from this knowledge base, the running cluster, an [EXEC] tool result, or a file you've actually read — **say "I don't know"** or "I'm not sure — let me check" and then check, instead of inventing an answer.
- Never invent file paths, port numbers, environment variables, CLI flags, API routes, or config keys. If a user asks "is there a flag for X?" and this KB doesn't list one, the answer is "I don't see one — there may not be" not a guess.
- Never make up commit hashes, version numbers, dates, names, or quotes.
- Distinguish "I read this in the KB" from "I'm inferring this is probably true". Inferences are fine when labelled as such ("this is probably how it works, but I haven't verified").
- When the user asks "what's the latest version?" or similar live-state question, run an [EXEC] tool or fetch the running cluster's state — don't recite a version from training data or memory.
- If a user reports a bug or behaviour that contradicts what this KB says, trust the user, ask for the exact error message, and run a diagnostic — don't insist the KB is right.
- For diagnosing problems, prefer reading actual logs (`journalctl -u wolfstack -n 100`), config files, or live API responses over recalling general patterns. Cite what you read.

## Architecture
- Single Rust binary (actix-web 4), no database, no containers needed
- Config persisted as JSON files in /etc/wolfstack/
- Default ports: 8553 (HTTPS / dashboard), 8554 (HTTP inter-node, TLS-only installs), 8550 (public status pages)
- Requires root (reads /etc/shadow for auth)
- Background tasks: self-monitoring (2s), node polling (10s), status page checks (30s), session cleanup (300s), backup scheduling (60s)

## Ports Configuration
- Per-node ports persisted to /etc/wolfstack/ports.json as `{ api, inter_node, status }`
- UI: sidebar → gear icon on a node → Node Ports panel (local node only)
- CLI `--port N` still overrides the API port and pulls inter_node = N+1 with it
- Status port auto-fallback: if the configured status port is taken on boot, WolfStack scans 8550-8599 for a free one, binds there, persists the new port to ports.json, warns in logs
- API and inter_node ports hard-fail if taken (silent move would break peer polling)
- Common status-port collision: WolfDisk also defaults to 8550; auto-fallback moves WolfStack's status page aside

## VM Management (Native QEMU, Proxmox, Libvirt)
- Three backends: native QEMU (builds command line directly), Proxmox (qm commands), libvirt (virsh)
- Auto-detected: `is_proxmox()` checks for `pct`, `is_libvirt()` checks `virsh uri`
- VM configs stored in /var/lib/wolfstack/vms/{name}.json
- Disk images in /var/lib/wolfstack/vms/{name}.qcow2
- VmConfig carries `host_id: Option<String>` — the node that owns the VM. Stamped on create, rewritten by import_vm on migration target. Lets the cluster view render VMs as first-class members without a manual Scan.

### Serial Terminal
- Click the 💻 Terminal button on any running VM to open a WebSocket serial console
- Backend dispatches per platform: PVE runs `qm terminal <vmid>`, libvirt runs `virsh console <name> --force`, standalone QEMU uses socat to /var/lib/wolfstack/vms/{name}.serial.sock
- Standalone QEMU spawn wires `-chardev socket,id=serial0,path=<sock>,server=on,wait=off -serial chardev:serial0` automatically so the socket exists for socat to attach to
- Frontend pre-flights via GET /api/vms/{name}/serial-status — three outcomes:
  1. Not running → toast "start it first"
  2. Running but no serial device → Add-serial modal pops, POSTs /add-serial to wire one up
  3. Running + configured → opens terminal
- POST /api/vms/{name}/add-serial handles the fix:
  - PVE: `qm set <vmid> --serial0 socket` (reboot needed if running)
  - libvirt: dumpxml, attach only missing `<serial>` / `<console>` fragments via `virsh attach-device --config`, treats "already exists" as success
  - standalone: error message — restart the VM to pick up the new -chardev args
- Guest-side requirement (cannot be fixed from host): `console=ttyS0` on kernel cmdline + a getty on ttyS0. Terminal prints this hint at the top on every open.

### Stop vs Force Stop
- Running VMs have two stop buttons with distinct semantics
- Stop (`action: "stop"`, `force=false`): graceful ACPI — `qm shutdown --timeout 30`, `virsh shutdown`, or SIGTERM
- Force Stop (`action: "force-stop"`, `force=true`): immediate — `qm stop`, `virsh destroy`, or SIGKILL. Confirm dialog warns about unsaved data loss.
- Internal callers that need a guaranteed halt (migration export, VM delete) still pass force=true

### Import Disk Image
- When creating a VM, the "Import Disk Image" field accepts a path to an existing QCOW2, IMG, VMDK, VDI, or VHD file
- The image is converted to QCOW2 via qemu-img convert and used as the OS disk
- Supports importing from Proxmox, VMware, VirtualBox, and raw images like Home Assistant OS

### USB/PCI Passthrough
- Passthrough tab in VM settings shows host USB and PCI devices
- USB: matched by vendor:product ID (e.g. 046d:c52b)
- PCI: matched by BDF address (e.g. 0000:01:00.0), requires IOMMU/VFIO
- IOMMU group awareness — devices in the same group shown together
- Conflict guard: prevents two running VMs from claiming the same device
- Works across all three backends (native QEMU args, Proxmox qm set, libvirt hostdev XML)

### OVMF/UEFI Boot Issue
- When network config changes on a UEFI VM (WolfNet IP added, NIC added/removed, NIC model changed), OVMF boot entries reference old device paths
- WolfStack automatically resets EFI vars when network topology changes (v16.16.9+)
- Manual fix: delete /var/lib/wolfstack/vms/{name}_VARS.fd and restart VM
- Or switch to SeaBIOS temporarily — it doesn't have this issue

### Networking
- User-mode (default): VM gets NAT internet access, no incoming connections
- WolfNet IP: creates TAP interface with DHCP (requires dnsmasq installed on host)
- Bridge/Physical NIC: creates dedicated bridge for the physical interface, VM gets LAN IP via DHCP from router
- Extra NICs: add additional NICs for multi-homed VMs (e.g. OPNsense WAN+LAN)
- If VM has WolfNet IP but no DHCP response: check `ps aux | grep dnsmasq | grep tap` and install dnsmasq if missing

## Docker Container Management
- Lists containers via Docker socket API
- Start, stop, restart, remove, create
- Log viewing, exec into container
- WolfNet IP assignment for containers
- Auto-restart policy management

## LXC Container Management
- Full lifecycle: create from templates, start, stop, destroy
- File manager: browse, read, write, delete files inside LXC containers
- Exec commands inside containers
- Resource limits (CPU, memory)

## WolfNet (Encrypted Mesh VPN)
- Userspace VPN: X25519 key exchange + ChaCha20-Poly1305 encryption
- Does NOT use WireGuard kernel modules — only needs /dev/net/tun
- LAN auto-discovery on port 9601, tunnel traffic on port 9600
- Join flow: `wolfnet invite` on existing node → token → `wolfnet join <token>` on new node
- Docker image published to `ghcr.io/wolfsoftwaresystemsltd/wolfnet:latest` (multi-arch: linux/amd64 + linux/arm64)
- For NAS platforms (Unraid, Synology, TrueNAS), use the satellite compose file at docker/docker-compose.satellite.yml in the WolfStack repo — bundles WolfNet + WolfDisk
- Gateway mode: NAT traffic through a WolfNet peer

## WolfDisk (Distributed Filesystem)
- Rust FUSE-based replicated/shared storage across nodes
- Docker image published to `ghcr.io/wolfsoftwaresystemsltd/wolfdisk:latest` (multi-arch)
- Runs as native systemd service on Linux hosts (compile-from-source via setup.sh) or as a Docker container on NAS boxes
- Default bind port 8550 — conflicts with WolfStack's status page when both are on the same host; WolfStack's status-port auto-fallback resolves this
- Satellite compose pairs WolfDisk with WolfNet for NAS deployments

## WolfFlow (Workflow Automation)
- Visual drag-and-drop editor with 16 action types
- Actions sorted alphabetically: Check Disk Space, Clean Journal Logs, Condition (If/Else), Docker Container Update, Docker Prune, Docker Update Check, HTTP Request, Integration Action, NetBird API, Restart Container, Restart Systemd Service, Run Shell Command, TrueNAS API, Unifi Controller, Update System Packages, Update WolfStack
- Structured outputs: each action returns key-value data that downstream steps can reference via {{step_name.key}}
- Conditional branching: If/Else nodes evaluate expressions and jump to different steps
- Output reference picker: when editing a Condition, click to insert {{step.key}} references
- Retry logic: per-step retry count and delay
- Workflow timeout: max_runtime_secs
- 5 failure policies: Abort, Continue, Alert, Notify & Abort, Notify & Continue
- Cron scheduling with quick presets (Daily 3am, Hourly, Weekly, etc.)
- Parallel execution across cluster nodes
- Email results with HTML reports

### Check Disk Space Outputs
- available_gb, total_gb, usage_pct, mount_point, over_threshold
- Example: if {{Check Disk.available_gb}} lt 500 then run cleanup

### HTTP Request Outputs
- status_code, response_body, json (parsed response)

## Status Pages
- Public uptime monitoring at /status/{slug}
- HTTP/HTTPS/TCP/ICMP/DNS monitors
- Incident tracking with updates
- Cluster-scoped: monitors, pages, incidents all have a cluster field
- Served on BOTH the main API port (auth not required for /status/*) AND a dedicated no-auth listener on port 8550 — the main-port route is what makes reverse-proxy deployments work
- Admin UI "public URL" link uses `window.location.origin` for the local cluster, so it automatically matches whatever domain the admin is on (Cloudflare tunnel, nginx, direct IP — all work without config)

## GitHub Backup (v19.2.0+)
- Settings → 📤 **GitHub Backup** — commit WolfStack configuration to a private GitHub repo as an audit log / rollback story
- Tracked files: every `/etc/wolfstack/*.json` **except** `github-backup.json` (the token lives there — never pushed), plus every `docker-compose.yml` under `/etc/wolfstack/compose/`
- Config at `/etc/wolfstack/github-backup.json` (0600). Fields: `enabled`, `token`, `owner`, `repo`, `branch` (default `main`), `commit_name`, `commit_email`, plus last-push metadata
- Push uses the GitHub Git Data API so every push is **one atomic commit** even across many files (blobs → tree → commit → fast-forward ref). Tree is NOT based on the previous tree, so deletions (e.g. uninstalled appstore stacks) propagate to history
- Restore pulls the latest tree from the configured branch, recursively walks it, writes each known path back to `/etc/wolfstack/`. Paths outside the `config/` and `compose/` prefixes are ignored so arbitrary files committed to the repo can't be written elsewhere on the host
- Destructive actions (restore) gated by `confirmTypedYes` typed-YES modal in the frontend
- Token classic scope: `repo`. Fine-grained: `Contents: Read and write` on the single target repo. **Private repo required** — contents include API keys and passwords
- Empty repos aren't auto-initialised — the configured branch must already have at least one commit. UI Test-connection surfaces whether the branch exists
- Endpoints: `GET/POST /api/github-backup/config`, `POST /api/github-backup/push`, `POST /api/github-backup/restore`, `GET /api/github-backup/test`
- Token never reaches the browser — GET config returns `••••••••XXXX` mask; POST config with blank-or-masked token keeps the stored value untouched

## Running behind a reverse proxy (Cloudflare Tunnel, nginx, Traefik, etc.)
- Point the proxy at the main API port (default 8553, or whatever `--port` sets). Status pages, cluster browser sessions, consoles and the SPA all ride that one port.
- Required proxy headers: `Host` (preserve original), `X-Forwarded-Proto`, `X-Forwarded-For`. actix-web's `connection_info()` reads these for URL generation (cluster browser `connect_url`, etc.).
- Passkey login also reads `X-Forwarded-Proto` and `X-Forwarded-Host` (v22.6.9+). If you see "host header is incorrect for passkeys", the proxy is missing one of those — see the Authentication section.
- Enable WebSocket upgrades — consoles, VNC, k8s provisioning, and cluster browser all use WS on the same port.
- Status pages work out of the box at `https://your-domain/status/{slug}` with no extra routing.
- Port 8550 (dedicated status listener) is NOT needed behind a proxy and can be left un-forwarded; it's only there for admins who want no-auth public pages on a separate port without a proxy.

## Backups
- Scheduled backups with multiple destination types
- Docker: commit + save + volume backup
- LXC: full container backup
- VM: disk image backup
- Seven destination types: Local, S3, Remote (WolfStack node), WolfDisk, PBS (Proxmox Backup Server), NFS, SMB/CIFS
- NFS/SMB backups mount the share idempotently at /mnt/wolfstack-backup/<kind>-<sanitised-source>/ and write through like Local
- SMB fields on BackupStorage: smb_source (//server/share or \\server\share — normalised), smb_subpath, smb_username, smb_password, smb_domain, smb_options. Defaults to SMB 3.0.
- NFS fields: nfs_source (server:/export), nfs_options (defaults to rw,soft,timeo=50)
- Pre-flight at save time: `POST /api/backups/test-storage` exercises the mount path without doing a real backup, so missing-package errors surface at schedule save instead of silently failing later
- The backup runs hidden in a background task, so the UI wouldn't otherwise see MISSING_PACKAGE errors until the first run

## Storage
- Mount types: S3, NFS, SMB/CIFS, SSHFS, Directory (bind mount), WolfDisk
- SMB/CIFS: guest or username/password/domain auth. Defaults to SMB 3.0 (matches Synology/QNAP defaults). `smb_options` can override e.g. `vers=2.1` for older NAS firmware.
- Source normalisation: `\\server\share` gets converted to `//server/share` automatically
- Auto-mount on boot
- Global mounts replicate across cluster nodes

## Auto-install for Mount Helpers
- When a mount needs `mount.cifs` (cifs-utils) or `mount.nfs` (nfs-common/nfs-utils/nfs-client) and it's missing, WolfStack does NOT silently apt-get
- Mount helpers return a structured error `MISSING_PACKAGE|<binary>|<debian_pkg>|<redhat_pkg>` that the frontend parses
- UI pops a confirm modal: "Install cifs-utils? Run the install in a terminal window." Nothing installs without confirmation.
- On confirm: POST /api/system/prepare-install-package returns a session_id, frontend opens /console.html?type=pkg-install&name=<id> showing the install live
- Per-distro package names + package managers: Debian apt-get nfs-common/cifs-utils, RedHat dnf nfs-utils/cifs-utils, SUSE zypper nfs-client/cifs-utils, Arch pacman nfs-utils/cifs-utils, Unknown falls back to Debian
- Detected via `/etc/arch-release`, `/etc/debian_version`, `/etc/redhat-release`, `/etc/SuSE-release`, plus `/etc/os-release` fallback

## Alerting
- Threshold alerting with email notifications
- Discord, Slack, Telegram webhook support
- Alert cooldown to prevent spam

## App Store
- 510+ one-click applications
- Four install targets: Docker, LXC, bare-metal, VM
- User input fields for configuration (passwords, domains, etc.)
- Install modal detects which targets the manifest supports and shows matching pills
- Ports/env/memory sections auto-hide for non-Docker targets

### Docker deployment modes (v19.0.6+)
- Docker-target apps can be installed two ways: **Standard (`docker run`)** or **Docker Compose**. The radio appears in the install modal only when target is Docker AND the backend advertises `compose_available: true` on the app manifest response
- **Standard** is the default and the legacy path — completely unchanged behaviour (`install_docker` → `docker_create_with_cmd`). Every existing installed app keeps working as before
- **Compose** is opt-in per install. Writes `/etc/wolfstack/compose/appstore-{install_id}/docker-compose.yml`, runs `docker compose -f … up -d`, and records `deployment_type: "docker-compose"` + `compose_stack_name` on the `InstalledApp`
- Compose-backed installs appear on the existing Compose Stacks page automatically because they live in the same directory as user-created stacks — look for the `appstore-` prefix
- Compose template resolution (`resolve_compose_template`): hand-crafted override in `handcrafted_compose_template` takes priority; otherwise synthesised from the `DockerTarget` (image, ports, env, volumes, sidecars → one compose service each; named volumes declared at the top level)
- View / edit the compose file via `GET`/`PUT /api/appstore/installed/{install_id}/compose.yaml`. Save re-runs `docker compose up -d`
- Uninstall of a compose app runs `docker compose down -v` (wipes named volumes). Frontend gates this behind the typed-YES modal (`confirmTypedYes`)
- Existing `installed.json` records without the new fields default to `deployment_type: "docker-run"` via `#[serde(default)]` — zero migration
- Legacy `prepare-install` terminal flow is bypassed for compose installs; the call goes straight to `/api/appstore/apps/{id}/install` because `docker compose up` is non-interactive
- **Installed-apps list is cluster-wide**: fetches local installs plus every online WolfStack node via `/api/nodes/{id}/proxy/appstore/installed`, annotates each row with `__node_id`, and routes View / Edit / Uninstall through the cluster proxy when the install is remote
- **YAML escaping**: `yaml_double_quoted()` handles backslashes, quotes, newlines, tabs and control chars per the YAML spec. User inputs containing any of these no longer break the synthesised compose file
- **Install failure rollback**: if `docker compose up -d` fails on a fresh install, `install_compose` runs `down -v --remove-orphans` and deletes the stack directory before returning the error — no orphaned `/etc/wolfstack/compose/appstore-*` dirs

### VM Target (ISO-Based Apps)
- For apps that want a whole OS (PBS, pfSense, OPNsense, Home Assistant OS, etc.)
- VmTarget fields: iso_url, memory_mb, cores, disk_gb, optional data_disk_gb + data_disk_label, vga
- install_vm: downloads ISO to /var/lib/wolfstack/iso/<app_id>.iso (cached, reused across installs), auto-allocates a WolfNet IP, creates the VM via VmManager::create_vm, starts it
- User overrides via user_inputs: disk_gb, data_disk_gb, memory_mb, cores. Manifest defaults kick in if missing/zero/unparseable.
- Data disk: when manifest's data_disk_gb is Some, install_vm pushes a StorageVolume onto extra_disks. Works on all three backends: qm_create adds `--scsi{N} <storage>:<size>`, virsh_create appends `--disk path=...,size=N,format=qcow2,bus=virtio`, standalone QEMU creates the volume file and attaches via -drive.
- ISO fetch: tries the manifest URL first; if wget fails (404), calls resolve_latest_iso which scrapes the parent directory's HTML index and picks the newest file matching the same stem. Handles Proxmox's no-`_latest.iso`-alias quirk.

### Proxmox Backup Server (PBS) entry
- First VM-target app in the catalogue
- Defaults: 16 GB OS disk, 200 GB data disk, 4 GB RAM, 2 cores
- User picks storage in the install modal; everything else auto
- Points user to open VNC for the PBS installer, then add PBS as a backup destination cluster-wide via its WolfNet IP

## Authentication
- Linux crypt() against /etc/shadow (default)
- WolfStack native user accounts with Argon2 password hashing
- TOTP two-factor authentication
- WebAuthn / passkey login (v22.3.0+) — additive, sits alongside PAM
- OIDC/SSO (Enterprise): Authentik, Azure AD, Okta, Keycloak, any OIDC provider
- Cookie-based sessions (wolfstack_session cookie)
- Inter-node auth: X-WolfStack-Secret header

### Passkey login behind a reverse proxy (v22.6.9+)
- `passkey_rp_origin()` reads `X-Forwarded-Proto` and `X-Forwarded-Host` first, falls back to `Host` + `state.tls_enabled`. Without these, a wolfstack running plain HTTP behind nginx/Caddy/Traefik that terminates TLS would derive `origin=http://example.com` while the browser presents `origin=https://example.com` → webauthn-rs rejects with "host header is incorrect for passkeys"
- Multi-hop proxy chains: takes the first comma-separated value from the header (the original client-facing host/scheme)
- Bogus `X-Forwarded-Proto` values fall back to local TLS state, so a misconfigured proxy doesn't break direct access
- IPv6 hosts (`[::1]:8553`) handled correctly — port stripping only fires when the suffix is all-digits

## Certificates page (v22.6.9+)
- Three input modes: Let's Encrypt (certbot, existing), Generate Self-Signed, Install / Update
- Self-signed: `openssl req -x509 -newkey rsa:2048 -nodes -sha256` with `-addext "subjectAltName=..."`. Auto-detects DNS vs IP for each SAN entry. Default validity 825 days.
- Install / Update: paste cert + key PEM; supports encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) and legacy PEM (`Proc-Type: 4,ENCRYPTED`) via a `key_passphrase` field. Passphrase passed to openssl via `WS_KEY_PASS` env var, never argv. Decrypted key is what gets stored on disk.
- Atomic write: everything goes through `<path>.new` + `verify_cert_key_pair` (modulus check for RSA, public-key comparison for EC) + `rename`. A bad upload never overwrites a working cert.
- Path whitelist: `/etc/wolfstack/`, `/etc/pve/local/`, `/etc/pve/nodes/`. Anything else (including path traversal) is rejected.
- Discovery (existing): scans certbot CLI, `/etc/letsencrypt/live/`, `/etc/wolfstack/cert.pem` + `key.pem`, and Proxmox `pveproxy-ssl` pairs across all nodes/per-node directories. Lists everything in the page.
- Diagnostics: warns if only one of `/etc/wolfstack/cert.pem` and `key.pem` exists (the manual-install footgun)
- "Update" button on existing proxmox/custom certs pre-fills the install target so the user can replace them in place
- After install: API response carries `restart_service` (`wolfstack` or `pveproxy`). Frontend opens a `confirm()` dialog — never auto-restart. User clicks OK → POST `/api/certificates/restart-service` schedules a deferred restart (1.5s for wolfstack so HTTP response flushes, 100ms for pveproxy)
- Endpoints: `POST /api/certificates/install`, `POST /api/certificates/self-signed`, `POST /api/certificates/restart-service`, `GET /api/certificates/list`, `POST /api/certificates` (Let's Encrypt)

## Installer (setup.sh)
- Curl-piped: `curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash`
- Flags: `--beta` (use beta branch), `--yes`/`-y` (skip confirmation), `--agent` (agent-only install — see Clustering), `--install-dir <path>` (redirect Cargo target dir to external mount for low-disk hosts)
- Pre-flight checks (v22.6.9+) run before any package install:
  - DNS-on-:53 conflicts: Technitium, Pi-hole, AdGuard, BIND, Unbound, dnsmasq, systemd-resolved (the last is handled automatically — left alone)
  - Port conflicts on 8553/8554/8555 with role labels; distinguishes "our previous wolfstack" vs other process
  - Reverse proxies on 80/443 (info only — WolfStack core doesn't bind these)
  - Existing `/etc/wolfstack/` content → flagged as upgrade; explicit warning when `custom-cluster-secret` is present (move-to-new-cluster footgun)
  - ufw / firewalld active without :8553 allowed → exact `ufw allow` / `firewall-cmd` command shown
  - Architecture not in {x86_64, aarch64} → warns about source-build path (~10–30 min, ~3 GB free disk)
  - Confirmation prompt with TTY detection: works under `bash setup.sh` AND `curl|bash` (reads from /dev/tty)
- Install manifest at `/var/log/wolfstack/install-<timestamp>.log`: full diff of installed packages before vs after via `dpkg-query` / `rpm -qa` / `pacman -Q`. Used by the uninstaller for rollback.
- Join token: pre-generated at `/etc/wolfstack/join-token` (mode 0600) using `openssl rand -hex 32` or `od /dev/urandom` fallback. Format matches Rust's `load_join_token()` so the binary picks it up on first start. Printed in the completion banner — paste into master server's "Add Node" form.
- Local uninstaller: fetched from same branch as setup.sh, saved to `/usr/local/bin/wolfstack-uninstall`. Falls back to inline minimal stub if offline (stops service, removes binary + unit, optional `--purge` for /etc/wolfstack). Reachable when DNS is broken.
- Disk-space check: only on source-build fallback (when prebuilt binary download fails). Requires ~3 GB at the build dir; prompts to continue if less.

## AI Agent
- Three providers: Claude (Anthropic), Gemini (Google), Local AI (self-hosted)
- Local AI supports any OpenAI-compatible server: Ollama, LM Studio, LocalAI, vLLM, text-generation-webui, llama.cpp
- Common local URLs: Ollama http://localhost:11434, LM Studio http://localhost:1234/v1, LocalAI http://localhost:8080/v1
- Auto-detects available models from the local server's /v1/models endpoint
- API key optional for most local servers
- Expert knowledge base shipped with WolfStack — AI gives deep answers about the platform
- AI can execute read-only commands on the server via [EXEC] tags
- Health monitoring: periodic scans with AI-generated recommendations

## Pricing & Tiers (v22.8.0+)
Four-tier model on Stripe — replaces the old single £79/installation price.
- **Community** (no licence) — core platform, no Pro/Enterprise gates
- **Homelab** — explicit feature flags only; entry tier for hobbyists
- **Pro** — bundles `plugins`, `api_keys`, `wolfhost`. Anything marketed as "Pro+"
- **Enterprise** — every feature, including future ones. Pre-2026-05-06 Enterprise was unlimited; self-serve Enterprise sold from 2026-05-06 onward carries `max_nodes=100`. Custom-tier quotes carry whatever sales scoped (250/500/1000)
- **Soft host cap**: over-cap nodes still join with a warning; never blocks usage. Legacy `max_nodes=0` continues to mean "unlimited" for grandfathered customers
- License propagation: install on one node, all cluster nodes pick it up automatically
- Tier resolution: `compat::resolve_tier` reads the signed `tier` field on newer licences, falls back to inferring from the `features` list for older ones
- Dashboard header badge shows tier + current/max host count, paints amber when over cap, links to the Stripe billing portal
- Endpoint: `GET /api/platform/status` returns tier, current_nodes, over_cap (no email — that used to leak before v22.8.0)
- Plugin gates use `has_feature("plugins")` not "any valid licence" so Homelab can't unlock Pro features

## Enterprise Features
- REST API keys (wsk_* tokens) with scoped permissions
- Plugin system
- OIDC/SSO
- WolfHost (web hosting platform)
- WolfCustom (white-label branding)

## Plugin System
- Plugins installed to /etc/wolfstack/plugins/{id}/
- manifest.json + web/plugin.js + optional bin/handler backend
- Plugin Store: fetches index from GitHub, one-click install
- Reinstall kills old handler process and starts new one automatically

## Clustering
- Nodes discover each other via HTTP polling every 10 seconds
- Cluster secret for inter-node authentication
- Default secret used if no custom-cluster-secret file exists
- Node proxy: /api/nodes/{id}/proxy/{path} forwards API calls to remote nodes

### Server vs agent install mode (v22.6.9+)
- Two install modes selected at `setup.sh` time: server (default) and agent (`--agent` flag)
- Server install: full management UI on :8553, cluster API, all subsystems. Run on ONE node per management domain — that's the "single pane of glass"
- Agent install: cluster API stays bound (so the master's node-proxy still works), but the SPA / login.html / static assets are NOT served. Hitting `/` on an agent returns a small HTML page explaining it's an agent and how to add it from the master
- Implemented via the `--agent` CLI flag on the wolfstack binary. In agent mode, all three `HttpServer` blocks (HTTPS, HTTP inter-node, no-TLS fallback) swap the SPA + Files service for `default_service(web::to(agent_index_handler))`. `api::configure` is registered regardless, so cluster proxy works
- setup.sh appends `--agent` to the systemd `ExecStart=` line. On a rerun with the opposite flag it sed-edits the unit file and saves a backup at `wolfstack.service.pre-agent-flip`, then daemon-reloads + restarts
- Agent mode does NOT reduce installed runtime deps — every node still needs LXC, Docker, QEMU, etc. to actually run workloads
- If the master has rotated the cluster secret (Settings → Security), agent nodes need the same `/etc/wolfstack/custom-cluster-secret` or X-WolfStack-Secret auth fails. Surfaced in the install banner and the agent index HTML.

## Common Issues

### VM won't boot after NIC change (UEFI)
OVMF boot entries reference device paths. Network config changes alter the topology. Fix: WolfStack v16.16.9+ auto-resets EFI vars. Manual: delete {name}_VARS.fd file.

### VM has no IP (WolfNet)
Check dnsmasq is installed and running: `ps aux | grep dnsmasq | grep tap`. WolfStack starts a per-VM dnsmasq on the TAP interface to offer DHCP.

### VM has no IP (Bridge/Physical NIC)
Check bridge exists: `ip link show type bridge`. Check physical NIC is a member: `bridge link show`. Router DHCP must reach through the bridge.

### systemd-networkd-wait-online.service failed
Harmless — systemd timed out waiting for all interfaces. Common with bridges/TAPs/VPNs. Does not affect networking.

### Plugin backend not starting
Check if the handler binary is compatible: `file /etc/wolfstack/plugins/{id}/bin/handler`. Must be statically linked (musl) for cross-distro compatibility.

### WolfHost "could not reach WolfStack API"
WolfHost tries HTTPS:8553 then HTTP:8554. Also tries both custom and default cluster secrets. Restart WolfHost handler after WolfStack upgrade.

### VM terminal opens but is blank
Guest OS doesn't have a serial console enabled. Fix on the guest: add `console=ttyS0` (or `console=ttyS0,115200`) to the kernel command line, enable `systemd-getty@ttyS0.service` on systemd distros. The host side is wired automatically on all three backends.

### "VM not found in qm list" when opening terminal
PVE-only. The VM exists in the WolfStack UI but not in `qm list`. Usually means the VM was created outside Proxmox or the PVE DB is out of sync. Check `qm list` from the host shell — if the name's not there, WolfStack can't resolve a vmid for `qm terminal`.

### "Add serial console?" prompt on a PVE VM created in the Proxmox web UI
PVE VMs created outside WolfStack often lack `serial0: socket`. The prompt offers `qm set <vmid> --serial0 socket` — requires a reboot to take effect if the VM is currently running. Proxmox web UI doesn't expose the flag, so this is the fastest way to enable it.

### "Standalone VM was started before serial-console support was added"
A VM running from before the v16.40 QEMU spawn change doesn't have the -chardev socket wired. Stop + start the VM (not restart — the socket is created at spawn time).

### SMB backup to Synology/QNAP hangs or fails
Most consumer NAS defaults to SMB 3.0 (WolfStack's default). Older firmware may need `vers=2.1` in the smb_options field. Guest share permissions must allow the user you configured, or mark the share as guest-accessible and leave username blank.

### "MISSING_PACKAGE|mount.cifs|..." error
cifs-utils (or nfs-common/nfs-utils/nfs-client) not installed on the host. WolfStack never auto-installs — accept the confirm prompt to run the install in a live terminal. If you dismissed the prompt, just retry the mount or save the backup destination again and click through.

### Docker container ports show strikethrough + "host ports the daemon never bound" banner
- The Predictive Inbox port-conflict detector compares `HostConfig.PortBindings` against `NetworkSettings.Ports`. If the container is in `network_mode: host` (or `container:<id>`), Docker never populates `NetworkSettings.Ports` even though the service is fully reachable on the host stack — the diff was a false positive
- Fixed in v22.9.47: `parse_port_mappings` short-circuits and returns no mappings for host / container-namespace mode. Banner and strikethroughs disappear after upgrade. Bridge / default / custom networks still get the full diff so genuine silent-publish failures are still surfaced
- If a host-mode container actually has a service problem, check the container logs and host firewall — the port-publish layer is bypassed entirely in this mode

### Home Assistant VM setup
1. Import the HAOS QCOW2 image via "Import Disk Image" when creating VM
2. Set BIOS to OVMF (UEFI)
3. Add a bridge NIC for LAN access (Physical NIC passthrough)
4. Pass through Zigbee/Z-Wave USB dongle via Passthrough tab
5. If no IP: set static IP from HA CLI: `ha network update enp0s3 --ipv4-method static --ipv4-address 192.168.1.x/24 --ipv4-gateway 192.168.1.1`

## WireGuard Bridge (VPN access INTO the cluster from outside)

This is the answer to "how do I connect from my office / phone / laptop to my WolfStack cluster or WolfNet?". WireGuard bridges bolt a standard WireGuard VPN on the side of WolfNet so external clients can join the mesh from any network.

- Each cluster gets a unique /24 in 10.20.0.0/16 (e.g. 10.20.5.0/24) for its WireGuard bridge
- Config is stored in /etc/wolfstack/wireguard-bridge.json (per-cluster entries)
- UI: Settings → WireGuard Bridge → Create bridge for cluster → add clients
- Each client gets a download button for their .conf file (import into WireGuard app on phone/laptop)
- Endpoint = cluster node's public IP + listen port (default 51820, configurable)
- Client traffic enters the bridge, is routed into WolfNet, reaches every node + container/VM on the mesh
- Requires `wireguard-tools` on the host (install via the distro-aware deps page)
- Supports multiple bridges per host (different clusters = different subnets)
- **Wolfnet is NOT WireGuard**: WolfNet is the internal mesh overlay between cluster nodes; WireGuard bridge is the external-client door into that mesh
- WireGuard private keys are written to /tmp/wg-<iface>-key with mode 0600 (locked down since v18.7.27), consumed by `wg set`, then removed

## WolfRouter (native firewall / DHCP / DNS / WAN router on any node)

Turn any WolfStack node into a full router — no pfSense/OPNsense box needed.

- **Zones**: WAN / LAN / DMZ / WolfNet / Trusted / custom, assigned per interface
- **LAN segments**: each LAN = subnet + DHCP range + DNS. dnsmasq runs per-LAN, one process per bridge, pidfiles in /run/wolfstack-router/
- **DNS modes per LAN**: "WolfRouter" (dnsmasq serves :53) or "External" (dnsmasq DHCP-only, DHCP option 6 points clients at their chosen resolver — AdGuard/Pi-hole)
- **Firewall**: iptables filter table via iptables-restore, atomic swap, pre-flight refuses rules that would lock the admin out of :8553 / :8554 (handles --dport, port ranges `8000:9000`, `-m multiport --dports`)
- **Safe-mode rollback**: firewall apply registers a deadman-switch (default 120s) — if operator doesn't click Keep in the banner, the previous ruleset is restored automatically
- **WAN types**: DHCP, static, PPPoE (writes /etc/ppp/chap-secrets with mode 0600)
- **Host DNS panel**: when a container wants :53 on a node, use the Host DNS panel to release systemd-resolved's stub listener AND/OR move WolfRouter's own dnsmasq to a different port (e.g. 5353). Both actions are deadman-switched.
- UI: WolfRouter module in the datacenter view — Topology, Zones, Rules, LANs, WANs, DNS Tools
- Replicates config across cluster nodes automatically
- /etc/wolfstack/router.json is the source of truth

## WolfRun (container orchestration across the cluster)

n8n-like service manager that spreads Docker/LXC instances across nodes.

- Services = (image, replicas, placement, restart policy). Reconciler loop every 15s makes the live state match declared state
- Placement options: any node, specific node, all nodes (DaemonSet-like), per-zone
- Restart policy: `Always` means WolfRun auto-restarts exited containers on the next tick
- Failover events logged to /etc/wolfstack/wolfrun/failover-events.json
- Only the cluster LEADER runs the reconciler (Raft-free leader election via lowest node_id heuristic)
- Config: /etc/wolfstack/wolfrun/services.json
- UI: Datacenter → WolfRun

## WolfUSB (network USB device passthrough)

Expose host-plugged USB devices to containers/VMs on any node via USB/IP.

- Each node runs a wolfusb server on :3240 (key in /etc/wolfusb/wolfusb.env, same cluster secret)
- Requires kernel modules vhci-hcd (client) + usbip-host (server) — auto-modprobed on install, auto-installed for distros that ship them in kernel-modules-extra
- Assign a USB device to a container/VM via the WolfUSB panel; WolfStack auto-attaches on container start
- Cross-node: a USB device plugged into node A can be attached to a VM on node B. Re-attach on container restart is automatic (wolfusb::on_container_started hook).
- Common use: Zigbee/Z-Wave dongles for Home Assistant VMs, license dongles, webcams

## WolfKube (Kubernetes lifecycle + management on the cluster)

- Cluster modes: self-hosted (k3s/kubeadm installed by WolfStack), or attach to an existing kubeconfig
- Kubeconfig uploaded via UI is stored at /etc/wolfstack/kubernetes/<id>.yaml with mode 0600 (since v18.7.27)
- Pod terminal: WebSocket console to any container in any pod (`kubectl exec` under the hood)
- Scale/delete workloads from the UI; see resource usage per pod
- Stores JOIN tokens for node expansion — token endpoint is cluster-secret-auth'd

## Cluster Browser (unified web UI for every cluster-internal service)

- Scans all nodes for running web services (by common ports 80/443/3000/8080/...)
- Presents them as one pane: "Jellyfin on node-A", "AdGuard on node-B", "Grafana on node-C"
- Click through to the service's UI — WolfStack reverse-proxies it so browser credentials aren't needed per-service
- Discovery runs every 60 seconds via a reconciliation loop (main.rs background task)
- Config: /etc/wolfstack/cluster-services-discovered.json

## Predictive Inbox (v22.7.0+)

Unified ops inbox that surfaces problems *before* they page someone. One queue across the cluster, with proposed remediations the operator approves with a click.

- **9 analyzers** running on a tick: backup freshness, certificate expiry, cluster health, container disk fill, container memory, container restart-loop, host disk fill, host disk verdict, OSV/CVE scanner, port-conflict detector, security posture, threshold breaches, unused-package recommender, VM disk fill, vulnerability scan, WolfNet DHCP. Source files in `src/predictive/`
- Each analyzer emits **Proposals** with severity, scope key, evidence list, and a `RemediationPlan`. Scope keys collapse duplicates across ticks so the inbox doesn't fill up
- **Embedded terminal pane** (v22.9.10+) — every proposal can open a sandboxed shell on the affected host without leaving the page. One shell per proposal; manual-shell access for ad-hoc investigation
- **AUTOFIX** (v22.9.42+) — proposals with a deterministic, reversible plan can be applied with one click. The plan runs through the deadman-switch framework so a bad fix auto-rolls back
- **OSV.dev + CISA KEV scanner** (v22.9.21+) — CVE scanning across all OSV-indexed Linux distros (Debian/Ubuntu/RHEL/Arch/Alpine/etc.) for hosts AND LXC containers. Severity floor configurable; auto-suppresses no-fix-available CVEs; clickable CVE rows; per-host/LXC findings collapse to one card (v22.9.22)
- **Port-conflict analyzer** (v22.9.25) — detects two failure modes: (1) silent publish failure where Docker accepted the start but never bound the host port, (2) host-port collision where multiple owners want the same `(host_ip, host_port, proto)` tuple. Owners include Docker containers (published / requested-but-unpublished) and host processes from `ss -tlnp/-ulnp`. Skips containers in `host` / `container:<id>` network mode where the diff is meaningless (v22.9.47)
- **Pre-flight validator** — proposals that can be checked before applying are dry-run first. Failure surfaces in the card before the operator has to commit
- **Multi-cluster** — Inbox aggregates findings from every reachable cluster; Run buttons fan out via `/api/nodes/{id}/proxy/...`. Snooze / dismiss / approve / ack actions also fan out so a clear-on-one-node propagates
- **Optimistic UI** (v22.9.18) — dismiss/approve/snooze/ack updates immediately, reconciles with backend
- **Mobile** (v22.9.24) — Inbox list fills the viewport; terminal appears on demand (vs always-visible on desktop)
- Endpoints under `/api/predictive/...`; orchestrator at `src/predictive/orchestrator.rs` runs the analyzers on a schedule

## WolfStack Gateway (v22.9.0+)

Universal SMB/NFS share head with cross-cluster federation — turn any node into a NAS frontend regardless of where the actual storage lives.

- Sources: local directory, S3, NFS upstream, SMB upstream, SSHFS, WolfDisk, RBD, mdadm/NoNRAID arrays
- Re-exports as **SMB (Samba)** and/or **NFS** under one Gateway config
- **Cross-cluster federation** — a Gateway on cluster A can proxy a share that lives on cluster B; no manual replication
- Orchestrator at `src/gateway/orchestrator.rs` reconciles `/etc/samba/` + `/etc/exports` to match the declared config
- UI: Datacenter → WolfStack Gateway

## Storage Array (v22.9.0+)

Disk-array management for vanilla **mdadm** and **NoNRAID** (Unraid-style) backends.

- Create / assemble / start / stop / monitor RAID arrays from the UI; no shell required
- Cluster-wide aggregation (v22.9.1) — Storage Array page shows arrays across every node + federation
- Sidebar discoverability fix in v22.9.42 (Klas)
- Backend lives in `src/array/`; renders as a first-class storage target alongside local / NFS / SMB / S3 / SSHFS / WolfDisk / RBD
- Endpoints under `/api/array/...` — `GET /api/array`, `POST /api/array/{name}/start`, etc.

## WolfStack Pools / XCP-ng + Xen Orchestra (v22.9.37-41)

Sell N VMs → auto-deploy as a federated tenant cluster across **Proxmox / native QEMU / XCP-ng**.

- **XCP-ng integration** drives Xen Orchestra's REST API (not raw XAPI). Mirrors `src/proxmox/` shape — read-only inventory in v22.9.37 (P1), lifecycle + provisioning + tenant federation in v22.9.38-41 (P2-P4)
- XCP-ng is Type-1, so no host-level LXC; VMs are the workload unit
- Tokens XOR-obfuscated in `/etc/wolfstack/xo_pools.json`; never returned to the frontend
- Tenant Pools: provision a multi-VM cluster as one unit, federate the tenant across the underlying hypervisors (Proxmox host A + XCP-ng pool B + native QEMU on C)
- UI: Datacenter → Tenants / Pools

## Ceph integration

- Attach an existing Ceph cluster (MON + keys) via Settings → Ceph → Add cluster
- WolfStack renders Ceph health, OSD status, pool usage; can create/delete pools and RBD volumes
- RBD volumes become a first-class storage target (alongside local, S3, NFS, SSHFS, WolfDisk)

## Discord / Telegram / WhatsApp bots (AI access from chat)

- Each bot runs as a supervised background task; credentials in /etc/wolfstack/ai-config.json (mode 0600)
- Bots relay user messages to the AI agent (same [EXEC]/[EXEC_ALL]/[WEBSEARCH]/[FETCH]/[READ]/[SECURITY_AUDIT] tool loop as the dashboard chat)
- Discord: set DISCORD_BOT_TOKEN in the AI settings; bot joins the configured channel, replies in-thread
- Telegram: paste bot token; /start to begin; long replies get chunked into 4096-char messages
- WhatsApp: relays via the Baileys gateway (Node.js subprocess) — requires pairing a phone once

## MCP server (Model Context Protocol)

- Exposes the WolfStack AI toolbox as an MCP server so Claude Desktop / Cursor / other MCP clients can reach it
- Endpoint: /api/mcp (WebSocket, session-auth)
- Same tool set as the built-in agent: run cluster commands, propose ACTIONs, read files
- Config: /etc/wolfstack/ai-config.json → mcp_enabled

## MySQL / MariaDB editor

- Attach credentials via the Database Manager panel — stored encrypted in /etc/wolfstack/
- Browse schemas/tables, run ad-hoc queries, edit rows
- Supports both MariaDB and MySQL protocol

## Deadman-switch framework (Level 2 safety)

Any operation that can brick the node's UI registers a rollback closure with a TTL. If the operator doesn't hit "Keep" in the banner before the TTL expires, the rollback fires automatically.

- Host DNS release: 120s TTL → restore systemd-resolved stub
- WolfRouter firewall apply: 120s TTL → revert to previous ruleset
- Interface down: 90s TTL → bring interface back up
- Endpoint: GET /api/danger/pending, POST /api/danger/confirm/{id}, POST /api/danger/rollback/{id}
- Frontend banner polls every 2s, survives session expiry and network blips
- See src/danger.rs for the registry internals

## Plugin system

- Plugins live in /etc/wolfstack/plugins/<plugin>/
- Each plugin has a manifest.json declaring name, icon, backend command (if any), frontend HTML
- Backend plugins run as child processes of WolfStack, expose HTTP endpoints under /api/plugins/<plugin>/...
- Frontend plugins inject their HTML + JS into a dedicated tab
- Install: drop the directory, reload WolfStack; or use the plugin install UI (fetches from a URL)
- Plugins are sandboxed only by Unix permissions — they run as root, so trust matters

## System Check (distro-aware diagnostics)

- UI: Settings → System Check
- Runs a battery of tests: kernel modules present, iptables/nftables choice, services enabled, ports open, disk space, memory, package manager health
- Each failing check is paired with a one-click "Fix" that knows the distro (apt/dnf/pacman/apk/zypper)
- Used by the installer too — `setup.sh` runs a subset on fresh install

## Services Discovery

- Background reconciler scans each node for well-known services (Docker registries, media servers, dashboards)
- Populates the Cluster Browser + drives the app-update-summary badge
- Service definitions at /etc/wolfstack/cluster-services.json
- Tombstoning prevents re-discovering deleted services

## Security posture summary (v18.7.27+)

- All sensitive files under /etc/wolfstack/ are mode 0600 (custom-cluster-secret, nodes.json with PVE tokens, join-token, license.key, users.json, oidc.json, auth-config.json, ai-config.json, s3/*.passwd, chap-secrets)
- /etc/wolfstack/ directory itself is mode 0700
- `paths::harden_existing` runs on startup to migrate pre-v18.7.27 installs
- `paths::write_secure(path, content)` is the canonical secure writer
- Cluster secret validation is constant-time including length
- Pre-flight firewall analyser refuses rules that would lock the admin out
- AI's [READ] tool has a hard-coded deny-list covering every credential file
- AI's [EXEC] pipe allowlist applies to EVERY pipe segment (no more exfil via `ls | wget`)
- AI's approved-action [ACTION] path blocks `;`, `&&`, `||`, newlines (no shell-chain injection)

## AI tool tags reference (for the agent itself)

- `[EXEC]cmd[/EXEC]` — local read-only shell, allowlist of safe commands only
- `[EXEC_ALL]cmd[/EXEC_ALL]` — same command on every cluster node, results labelled by hostname
- `[ACTION id=".." title=".." risk="low|medium|high" explain=".." target="local|all"]cmd[/ACTION]` — proposes a fix the operator approves with one click
- `[WOLFNOTE title="..."]body[/WOLFNOTE]` — save a note for the user
- `[WEBSEARCH query="..."][/WEBSEARCH]` — DuckDuckGo top 5 results
- `[FETCH url="..."][/FETCH]` — fetch a URL, strip HTML, 8 KB cap, SSRF-guarded
- `[READ path="..."][/READ]` — read a WolfStack runtime file from a sandboxed allow-list
- `[SECURITY_AUDIT][/SECURITY_AUDIT]` — run the built-in security audit (file perms, default secret, docker restart policies)

## Common user questions → where to point them

- **"Connect from outside to my cluster/containers"** → WireGuard Bridge (Settings → WireGuard Bridge → create bridge + add client → download .conf)
- **"How do I get two nodes to talk securely?"** → WolfNet (wolfnet invite on existing node → token → wolfnet join on new node)
- **"Make this node a router / firewall / DHCP server"** → WolfRouter module
- **"Plug a USB device into my Home Assistant VM on another node"** → WolfUSB panel
- **"Run a container on whichever node is free"** → WolfRun service
- **"Public status page for my apps"** → Status Pages (cluster-scoped, served on :8550)
- **"Manage Kubernetes from WolfStack"** → WolfKube (attach kubeconfig or let WolfStack install k3s)
- **"See all my web services in one place"** → Cluster Browser
- **"Use WolfStack from Claude Desktop / Cursor"** → MCP server (Settings → AI → Enable MCP)
- **"Chat with my cluster from my phone"** → Discord / Telegram / WhatsApp bots (Settings → AI → Bots)
- **"Back up my containers / VMs"** → Backups (scheduled, destinations: local / NFS / SMB / S3 / Proxmox Backup Server / SSHFS / WolfDisk)
