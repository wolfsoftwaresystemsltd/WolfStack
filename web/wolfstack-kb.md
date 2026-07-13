# WolfStack Expert Knowledge Base

## Architecture
- Single Rust binary (actix-web 4), no database, no containers needed
- Config persisted as JSON files in /etc/wolfstack/
- Default port: 8553 (HTTPS), 8554 (HTTP fallback)
- Requires root (reads /etc/shadow for auth)
- Background tasks: self-monitoring (2s), node polling (10s), status page checks (30s), session cleanup (300s), backup scheduling (60s)

## VM Management (Native QEMU, Proxmox, Libvirt)
- Three backends: native QEMU (builds command line directly), Proxmox (qm commands), libvirt (virsh)
- Auto-detected: `is_proxmox()` checks for `pct`, `is_libvirt()` checks `virsh uri`
- VM configs stored in /var/lib/wolfstack/vms/{name}.json
- Disk images in /var/lib/wolfstack/vms/{name}.qcow2

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
- Docker container available for NAS platforms (Unraid, Synology, TrueNAS)
- Gateway mode: NAT traffic through a WolfNet peer

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

## Backups
- Scheduled backups with multiple destination types
- Docker: commit + save + volume backup
- LXC: full container backup
- VM: disk image backup
- S3/NFS/local destinations

## Storage
- S3, NFS, SSHFS mount management
- Auto-mount on boot
- Global mounts replicate across cluster nodes

## Alerting
- Threshold alerting with email notifications
- Discord, Slack, Telegram webhook support
- ntfy push notifications to phone/desktop (ntfy.sh or self-hosted server; topic + optional access token; Compromise alerts sent at max priority)
- Alert cooldown to prevent spam

## App Store
- 510+ one-click applications
- Docker, LXC, and bare-metal deployment
- User input fields for configuration (passwords, domains, etc.)

## Authentication
- Linux crypt() against /etc/shadow (default)
- WolfStack native user accounts with Argon2 password hashing
- TOTP two-factor authentication
- OIDC/SSO (Enterprise): Authentik, Azure AD, Okta, Keycloak, any OIDC provider
- Cookie-based sessions (wolfstack_session cookie)
- Inter-node auth: X-WolfStack-Secret header

## AI Agent
- Three providers: Claude (Anthropic), Gemini (Google), Local AI (self-hosted)
- Local AI supports any OpenAI-compatible server: Ollama, LM Studio, LocalAI, vLLM, text-generation-webui, llama.cpp
- Common local URLs: Ollama http://localhost:11434, LM Studio http://localhost:1234/v1, LocalAI http://localhost:8080/v1
- Auto-detects available models from the local server's /v1/models endpoint
- API key optional for most local servers
- Expert knowledge base shipped with WolfStack — AI gives deep answers about the platform
- AI can execute read-only commands on the server via [EXEC] tags
- Health monitoring: periodic scans with AI-generated recommendations

## Enterprise Features
- REST API keys (wsk_* tokens) with scoped permissions
- Plugin system
- OIDC/SSO
- WolfHost (web hosting platform)
- WolfCustom (white-label branding)
- License: £79/$99 per server per month
- License propagation: install on one node, all cluster nodes pick it up automatically

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

### Home Assistant VM setup
1. Import the HAOS QCOW2 image via "Import Disk Image" when creating VM
2. Set BIOS to OVMF (UEFI)
3. Add a bridge NIC for LAN access (Physical NIC passthrough)
4. Pass through Zigbee/Z-Wave USB dongle via Passthrough tab
5. If no IP: set static IP from HA CLI: `ha network update enp0s3 --ipv4-method static --ipv4-address 192.168.1.x/24 --ipv4-gateway 192.168.1.1`
