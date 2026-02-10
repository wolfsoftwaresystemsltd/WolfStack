# 🐺 WolfStack — Server Management Platform

A beautiful, Proxmox-like management dashboard for the Wolf Software suite. Monitor your servers, manage components, control services, and edit configurations — all from one place.

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash
```

Then open `http://your-server:8553` and log in with your Linux system credentials.

## Features

### 🔒 Linux Authentication
- Authenticates against your server's Linux user accounts
- Session-based with 8-hour token lifetime
- All API routes protected

### 📊 Real-Time Dashboard
- Live CPU, memory, disk, and network monitoring with 2-second refresh
- Animated SVG gauges for CPU, memory, and load average
- Smooth bezier-curve history charts
- Storage breakdown table showing all mounted filesystems

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

### ⚡ Service Control
- Start, stop, restart any systemd service
- Enable/disable services
- View service status across your fleet

### 🔒 SSL Certificates
- Request Let's Encrypt certificates via Certbot
- One-click certificate provisioning

## Screenshots

| Login | Dashboard | Component Detail |
|-------|-----------|------------------|
| Glassmorphism login with Linux auth | Real-time gauges, charts, storage table | Config editor, logs, service controls |

## Architecture

```
wolfstack/
├── src/
│   ├── main.rs           # HTTP server, background tasks
│   ├── api/mod.rs        # REST API endpoints
│   ├── auth/mod.rs       # Linux auth via crypt(), session management
│   ├── agent/mod.rs      # Multi-server cluster state, polling
│   ├── monitoring/mod.rs # System metrics via sysinfo
│   └── installer/mod.rs  # Component detection, install, systemd control
├── web/
│   ├── login.html        # Login page
│   ├── index.html        # Dashboard SPA
│   ├── css/style.css     # Dark theme design system
│   └── js/app.js         # Dashboard logic, charts, polling
├── setup.sh              # One-line installer
├── Cargo.toml
└── README.md
```

## API

All endpoints require authentication (cookie-based session) except `/api/agent/status`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login with Linux credentials |
| POST | `/api/auth/logout` | Destroy session |
| GET | `/api/auth/check` | Check if session is valid |
| GET | `/api/metrics` | Current system metrics |
| GET | `/api/nodes` | List all cluster nodes |
| POST | `/api/nodes` | Add a server to cluster |
| DELETE | `/api/nodes/{id}` | Remove a server |
| GET | `/api/components` | Status of all components |
| GET | `/api/components/{name}/detail` | Component detail (config, logs, stats) |
| PUT | `/api/components/{name}/config` | Save component config file |
| POST | `/api/components/{name}/install` | Install a component |
| POST | `/api/services/{name}/action` | Start/stop/restart a service |
| POST | `/api/certificates` | Request Let's Encrypt certificate |
| GET | `/api/agent/status` | Node status (for remote polling, no auth) |

## Requirements

- **Linux** (Debian/Ubuntu or RedHat/Fedora)
- **Rust 1.70+** (installed automatically by setup.sh)
- **Root access** (required for reading `/etc/shadow` and managing systemd services)
- **libcrypt** (installed automatically by setup.sh)
- **Port 8553** (default, configurable)

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

## License

MIT — © 2026 [Wolf Software Systems Ltd](https://wolf.uk.com/)
