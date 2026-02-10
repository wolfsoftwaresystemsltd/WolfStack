# 🐺 WolfStack — Server & Container Management Platform

The flagship management dashboard for the [Wolf Software Systems](https://wolf.uk.com/) infrastructure suite. Monitor servers, manage Docker and LXC containers, control services, edit configurations, and view logs — all from one beautiful, Proxmox-like web interface.

![WolfStack Dashboard](screenshot.png)

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash
```

Then open `http://your-server:8553` and log in with your Linux system credentials.

## Why WolfStack?

WolfStack is the **central control plane** for your entire infrastructure. Instead of SSH-ing into every server and running commands manually, WolfStack gives you a single dashboard to:

- **Monitor** all your servers' CPU, memory, disk, and network in real time
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
- View container logs with timestamps
- Browse Docker images with size and creation info
- **Install Docker** from the dashboard if not already present

### 📦 LXC Container Management
- Auto-detects LXC installation and version
- Lists all LXC containers with resource stats
- Start, stop, restart, freeze, unfreeze, and destroy containers
- View container logs via journalctl
- Read and edit LXC container configuration files
- **Install LXC** from the dashboard if not already present

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
│   ├── api/mod.rs           # REST API endpoints (40+ routes)
│   ├── auth/mod.rs          # Linux auth via crypt(), session management
│   ├── agent/mod.rs         # Multi-server cluster state, polling
│   ├── monitoring/mod.rs    # System metrics via sysinfo
│   ├── installer/mod.rs     # Component detection, install, systemd control
│   └── containers/mod.rs    # Docker & LXC management
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
| GET | `/api/containers/docker` | List all Docker containers |
| GET | `/api/containers/docker/stats` | Docker container resource stats (CPU, memory, PIDs) |
| GET | `/api/containers/docker/images` | List Docker images |
| GET | `/api/containers/docker/{id}/logs` | Docker container logs |
| POST | `/api/containers/docker/{id}/action` | Start/stop/restart/pause/unpause/remove container |
| GET | `/api/containers/lxc` | List all LXC containers |
| GET | `/api/containers/lxc/stats` | LXC container resource stats |
| GET | `/api/containers/lxc/{name}/logs` | LXC container logs |
| GET | `/api/containers/lxc/{name}/config` | Read LXC container config file |
| PUT | `/api/containers/lxc/{name}/config` | Save LXC container config file |
| POST | `/api/containers/lxc/{name}/action` | Start/stop/restart/freeze/unfreeze/destroy container |

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
