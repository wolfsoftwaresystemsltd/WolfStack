# WolfStack

**Server management platform for the Wolf software suite.**

WolfStack is a Proxmox-like management dashboard that lets you monitor, install, and manage all Wolf suite components across multiple servers from a single web interface.

## Features

- **Dashboard** — Real-time CPU, memory, disk, and network monitoring with animated gauges and charts
- **Component Management** — Install and manage WolfNet, WolfProxy, WolfServe, WolfDisk, WolfScale, and MariaDB
- **Multi-Server Clustering** — Add servers and monitor them all from one dashboard (communicates over WolfNet or direct IP)
- **Service Control** — Start, stop, and restart systemd services
- **SSL Certificates** — Request Let's Encrypt certificates via Certbot
- **Cross-Platform** — Supports Debian/Ubuntu and RedHat/Fedora

## Quick Start

```bash
# Build
cargo build --release

# Run (default port 8553)
./target/release/wolfstack

# Or specify port/bind
./target/release/wolfstack --port 8553 --bind 0.0.0.0
```

Then open **http://localhost:8553** in your browser.

## Architecture

```
wolfstack/
├── src/
│   ├── main.rs            # Entry point, HTTP server
│   ├── api/mod.rs         # REST API endpoints
│   ├── agent/mod.rs       # Server-to-server communication
│   ├── monitoring/mod.rs  # System metrics collection
│   └── installer/mod.rs   # Component installation & service control
└── web/
    ├── index.html         # Dashboard UI
    ├── css/style.css      # Premium dark theme
    └── js/app.js          # Dashboard logic
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/metrics` | Current system metrics |
| GET | `/api/nodes` | All cluster nodes |
| POST | `/api/nodes` | Add a server |
| DELETE | `/api/nodes/{id}` | Remove a server |
| GET | `/api/components` | Component status |
| POST | `/api/components/{name}/install` | Install a component |
| POST | `/api/services/{name}/action` | Start/stop/restart service |
| POST | `/api/certificates` | Request SSL certificate |
| GET | `/api/agent/status` | Agent status (for node polling) |

## Multi-Server Setup

1. Install WolfStack on every server
2. Open the dashboard on any server
3. Click **"+ Add Server"** and enter the IP/hostname of other servers
4. If using WolfNet, use the WolfNet IP (e.g. `10.10.10.x`) for automatic secure communication

## Requirements

- Linux (Debian/Ubuntu or RedHat/Fedora)
- Rust 1.70+ (for building)
- Root/sudo access (for service management and installation)

## License

MIT — Wolf Software Systems Ltd
