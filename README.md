# 🐺 WolfStack — Server, VM & Container Management Platform

The flagship management dashboard for the [Wolf Software Systems](https://wolf.uk.com/) infrastructure suite. Monitor servers, manage **virtual machines (KVM/QEMU)**, Docker and LXC containers, control services, edit configurations, and view logs — all from one beautiful, Proxmox-like web interface.

![WolfStack Dashboard](screenshot.png)

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash
```

Then open `http://your-server:8553` and log in with your Linux system credentials.

## Why WolfStack?

WolfStack is the **central control plane** for your entire infrastructure. Instead of SSH-ing into every server and running commands manually, WolfStack gives you a single dashboard to:

- **Monitor** all your servers' CPU, memory, disk, and network in real time
- **Manage virtual machines** — create, start, stop, and delete KVM/QEMU VMs with in-browser noVNC console, Windows support, and multi-disk management
- **Manage Docker containers** — list, start, stop, restart, pause, remove, view logs, and see resource usage
- **Manage LXC containers** — list, start, stop, freeze, destroy, edit configs, and view logs
- **Control services** — start, stop, restart any systemd service across your fleet
- **Install software** — install Docker, LXC, and Wolf suite components with one click
- **Edit configs** — modify configuration files for any managed component directly in the browser
- **View logs** — read live journal logs for any service or container

## Features

### 🐳 Docker Container Management
- Auto-detects Docker installation and version
- Lists all containers with real-time CPU, memory, and PID stats
- Start, stop, restart, pause, unpause, and remove containers
- **Search Docker Hub** and pull images from the dashboard
- **Create containers** with ports, env vars, memory/CPU limits, and WolfNet IPs
- **Clone containers** — create a copy with one click
- **Migrate containers** to other WolfStack nodes
- **Manage images** — use existing images to create containers, or delete unused images
- View container logs with timestamps
- Browse Docker images with size and creation info
- **Web terminal** — interactive shell via xterm.js (WebSocket console)
- **Install Docker** from the dashboard if not already present

### 🖥️ Virtual Machine Management (KVM/QEMU)
- **Tabbed creation wizard** — General → Disks → Network & Boot
- Configurable CPU, memory, and disk size with multiple storage backends
- **OS disk bus selection** — VirtIO (fastest), IDE (Windows-compatible), SATA
- **Network adapter selection** — VirtIO (Linux), Intel e1000 (Windows built-in driver), Realtek RTL8139
- **VirtIO drivers ISO** — attach a secondary CD-ROM for Windows VirtIO driver installation
- **Multiple storage volumes** — add extra disks with custom size, format (qcow2/raw), bus type, and storage location
- **Volume management** — add, resize (grow-only), and remove volumes from the tabbed settings dialog
- Boot from ISO images for OS installation, boot order auto-configured for CD-first
- **In-browser VNC console** — noVNC-powered console directly in the dashboard (no external VNC client needed)
- **Tabbed settings dialog** — edit all VM settings (hardware, disks, network) without recreating the VM
- KVM hardware acceleration for near-native performance
- Automatic disk image management (qcow2 format)
- **WolfNet TAP networking** — assign WolfNet IPs to VMs for mesh network access
- Start, stop, and delete VMs from the dashboard
- QEMU/KVM installed automatically by setup.sh

#### Installing Windows in a VM
1. Set **OS Disk Bus** to `IDE` (Windows doesn't include VirtIO drivers)
2. Set **Network Adapter** to `Intel e1000` (Windows has built-in driver)
3. Point **ISO Path** to your Windows installer ISO
4. Optionally attach a **VirtIO Drivers ISO** if you want to switch to VirtIO later for better performance
5. Start the VM and open the **Console** to complete Windows installation

### 📦 LXC Container Management
- Auto-detects LXC installation and version
- Lists all LXC containers with resource stats
- **Browse LXC templates** — Debian, Ubuntu, Alpine, CentOS, Fedora, and more
- **Create containers** from any template with one click
- Start, stop, restart, freeze, unfreeze, and destroy containers
- **Clone containers** — full copy or snapshot (copy-on-write)
- View container logs via journalctl
- Read and edit LXC container configuration files
- **Web terminal** — interactive shell via xterm.js (WebSocket console)
- **Install LXC** from the dashboard if not already present

### 🚀 Container Migration
- Migrate Docker containers between WolfStack nodes with one click
- Automatically exports, transfers, and imports the container
- Works across your cluster — pair with WolfDisk for shared storage
- Option to remove the source container after migration or keep a copy

### 🌐 WolfNet Container Networking
- Assign WolfNet IPs (10.10.10.x) to Docker and LXC containers
- Containers become reachable across your entire WolfNet mesh
- IPs auto-applied on container start/restart
- Automatic IP allocation to avoid conflicts
- WolfNet IPs displayed in the dashboard even when containers are stopped

### 📊 Real-Time Dashboard
- Live CPU, memory, disk, and network monitoring with 2-second refresh
- Animated SVG gauges for CPU, memory, and load average
- Smooth bezier-curve history charts
- Storage breakdown table showing all mounted filesystems
- Network interface statistics

### 📦 Component Management
- Auto-detects installed Wolf suite components (WolfNet, WolfDisk, WolfScale, WolfProxy, WolfServe)
- Detects MariaDB and Certbot
- **Drill-down detail view** for each component:
  - Service status, memory usage, PID, restart count
  - Start / Stop / Restart controls
  - **Config file editor** with Save button
  - **Live journal logs** from systemd

### 🖥️ Multi-Server Clustering
- Add remote servers and monitor them from one dashboard
- Works over WolfNet mesh VPN or direct IP
- Polls remote WolfStack instances for metrics and component status
- **Remote container management** — start, stop, restart, remove, clone, and migrate containers on any server in your cluster
- **Container count badges** — sidebar shows how many Docker and LXC containers each server has
- **Web terminal** — open an interactive shell on any server (local or remote) directly from the sidebar
- All API calls automatically proxied through the node proxy for remote servers

### 🔒 Linux Authentication
- Authenticates against your server's Linux user accounts (PAM/crypt)
- Session-based with 8-hour token lifetime
- All API routes protected

### ⚡ Service Control
- Start, stop, restart any systemd service
- Enable/disable services
- View service status across your fleet

### 🔐 SSL Certificates
- Request Let's Encrypt certificates via Certbot
- One-click certificate provisioning

## Architecture

```
wolfstack/
├── src/
│   ├── main.rs              # HTTP server, background tasks
│   ├── api/mod.rs           # REST API endpoints (50+ routes)
│   ├── auth/mod.rs          # Linux auth via crypt(), session management
│   ├── agent/mod.rs         # Multi-server cluster state, polling
│   ├── monitoring/mod.rs    # System metrics via sysinfo
│   ├── installer/mod.rs     # Component detection, install, systemd control
│   ├── console.rs           # WebSocket PTY terminal for containers and host shells
│   ├── containers/mod.rs    # Docker & LXC management
│   └── vms/                 # Virtual machine management
│       ├── mod.rs            # Module exports
│       ├── manager.rs        # KVM/QEMU VM lifecycle (create, start, stop, delete)
│       └── api.rs            # VM REST API endpoints
├── web/
│   ├── login.html           # Login page
│   ├── index.html           # Dashboard SPA
│   ├── css/style.css        # Dark theme design system
│   └── js/app.js            # Dashboard logic, charts, polling
├── setup.sh                 # One-line installer
├── Cargo.toml
└── README.md
```

## API

All endpoints require authentication (cookie-based session) except `/api/agent/status`.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login with Linux credentials |
| POST | `/api/auth/logout` | Destroy session |
| GET | `/api/auth/check` | Check if session is valid |

### System Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/metrics` | Current system metrics (CPU, memory, disk, network) |

### Cluster Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/nodes` | List all cluster nodes |
| POST | `/api/nodes` | Add a server to cluster |
| DELETE | `/api/nodes/{id}` | Remove a server |

### Component Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/components` | Status of all managed components |
| GET | `/api/components/{name}/detail` | Component detail (config, logs, stats) |
| PUT | `/api/components/{name}/config` | Save component config file |
| POST | `/api/components/{name}/install` | Install a component |

### Services & Certificates

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/services/{name}/action` | Start / stop / restart a service |
| POST | `/api/certificates` | Request Let's Encrypt certificate |

### Container Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/containers/status` | Docker & LXC runtime detection (installed, version, counts) |
| POST | `/api/containers/install` | Install Docker or LXC |

### Docker Containers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/containers/docker` | List all Docker containers |
| GET | `/api/containers/docker/stats` | Docker container resource stats (CPU, memory, PIDs) |
| GET | `/api/containers/docker/images` | List Docker images |
| GET | `/api/containers/docker/search?q=` | Search Docker Hub for images |
| POST | `/api/containers/docker/pull` | Pull a Docker image from Docker Hub |
| POST | `/api/containers/docker/create` | Create a Docker container (name, image, ports, env, WolfNet IP) |
| GET | `/api/containers/docker/{id}/logs` | Docker container logs |
| POST | `/api/containers/docker/{id}/action` | Start/stop/restart/pause/unpause/remove container |
| POST | `/api/containers/docker/{id}/clone` | Clone a Docker container |
| POST | `/api/containers/docker/{id}/migrate` | Migrate container to another WolfStack node |
| DELETE | `/api/containers/docker/images/{id}` | Delete a Docker image |
| POST | `/api/containers/docker/import` | Receive a migrated container image (inter-node) |

### LXC Containers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/containers/lxc` | List all LXC containers |
| GET | `/api/containers/lxc/stats` | LXC container resource stats |
| GET | `/api/containers/lxc/templates` | List available LXC templates (distro, release, arch) |
| POST | `/api/containers/lxc/create` | Create LXC container from template |
| GET | `/api/containers/lxc/{name}/logs` | LXC container logs |
| GET | `/api/containers/lxc/{name}/config` | Read LXC container config file |
| PUT | `/api/containers/lxc/{name}/config` | Save LXC container config file |
| POST | `/api/containers/lxc/{name}/action` | Start/stop/restart/freeze/unfreeze/destroy container |
| POST | `/api/containers/lxc/{name}/clone` | Clone container (full copy or snapshot) |

### Virtual Machines

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vms` | List all VMs with status, resources, and VNC port |
| GET | `/api/vms/storage` | List available storage locations |
| POST | `/api/vms/create` | Create VM (name, cpus, memory, disk, iso, os_disk_bus, net_model, drivers_iso, extra_disks) |
| GET | `/api/vms/{name}` | Get details for a specific VM |
| PUT | `/api/vms/{name}` | Update VM settings (cpus, memory, disk, iso, bus, network adapter, drivers ISO, WolfNet IP) |
| DELETE | `/api/vms/{name}` | Delete a VM and its disk image |
| POST | `/api/vms/{name}/action` | Start or stop a VM |
| POST | `/api/vms/{name}/volumes` | Add a storage volume to a VM |
| DELETE | `/api/vms/{name}/volumes/{vol}` | Remove a storage volume |
| POST | `/api/vms/{name}/volumes/{vol}/resize` | Resize a storage volume (grow only) |

### WolfNet & WebSocket

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/wolfnet/status` | WolfNet network status and peers |
| GET | `/api/wolfnet/used-ips` | List all used WolfNet IPs |
| WS | `/ws/console/{type}/{name}` | Interactive web terminal (Docker, LXC, or host) |

### Node Proxy

| Method | Endpoint | Description |
|--------|----------|-------------|
| ANY | `/api/nodes/{id}/proxy/{path}` | Proxy any API call to a remote node |

### Agent (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agent/status` | Node status (for remote polling, no auth) |

## Requirements

- **Linux** (Debian/Ubuntu or RedHat/Fedora)
- **Rust 1.70+** (installed automatically by setup.sh)
- **Root access** (required for reading `/etc/shadow` and managing systemd services)
- **libcrypt** (installed automatically by setup.sh)
- **Port 8553** (default, configurable)

Optional:
- **Docker** — for Docker container management (can be installed from the dashboard)
- **LXC** — for LXC container management (can be installed from the dashboard)
- **QEMU/KVM** — for virtual machine management (installed automatically by setup.sh)

## Manual Build

```bash
cargo build --release
sudo ./target/release/wolfstack --port 8553
```

## Configuration

Config file: `/etc/wolfstack/config.toml`

```toml
[server]
port = 8553
bind = "0.0.0.0"
web_dir = "/opt/wolfstack/web"
```

## Managing the Service

```bash
# Status
sudo systemctl status wolfstack

# Logs
sudo journalctl -u wolfstack -f

# Restart
sudo systemctl restart wolfstack

# Stop
sudo systemctl stop wolfstack
```

## Part of the Wolf Suite

WolfStack is the management hub for all Wolf Software tools:

| Tool | Description |
|------|-------------|
| **WolfStack** | Server & container management dashboard (this project) |
| **WolfScale** | Database replication & load balancing |
| **WolfDisk** | Distributed filesystem replication |
| **WolfNet** | Encrypted mesh VPN networking |
| **WolfProxy** | NGINX-compatible reverse proxy with firewall |
| **WolfServe** | Apache2-compatible web server |

All tools are managed through WolfStack — install, configure, monitor, and control everything from one place.

## License

MIT — © 2026 [Wolf Software Systems Ltd](https://wolf.uk.com/)
