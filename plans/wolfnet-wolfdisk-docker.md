# WolfNet & WolfDisk Docker Containers — Implementation Plan

## Executive Summary

Package WolfNet (mesh VPN) and WolfDisk (distributed filesystem) as standalone Docker containers for NAS platforms (Unraid, Synology, TrueNAS) and generic Docker hosts. Both run in `--network host` mode. A lightweight satellite agent sidecar enables these nodes to appear in the WolfStack cluster.

---

## 1. WolfNet Docker Container

### 1.1 Key Insight

WolfNet does NOT use WireGuard kernel modules. It implements a fully userspace VPN:
- TUN device (`/dev/net/tun`) — standard kernel module, available everywhere
- X25519 key exchange — userspace (x25519-dalek)
- ChaCha20-Poly1305 AEAD — userspace
- UDP transport — standard sockets

Only needs: `/dev/net/tun`, `iproute2`, `iptables`

### 1.2 Dockerfile

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables procps ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/wolfnet /var/run/wolfnet
COPY wolfnet /usr/local/bin/wolfnet
COPY wolfnetctl /usr/local/bin/wolfnetctl
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/wolfnet /usr/local/bin/wolfnetctl /entrypoint.sh
EXPOSE 9600/udp 9601/udp
VOLUME ["/etc/wolfnet"]
ENTRYPOINT ["/entrypoint.sh"]
```

### 1.3 Runtime Requirements

```bash
docker run -d --name wolfnet --network host \
  --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun \
  -v wolfnet-config:/etc/wolfnet \
  -v /run/wolfnet:/var/run/wolfnet \
  -e WOLFNET_JOIN_TOKEN=<token> \
  ghcr.io/intelligentwolf/wolfnet:latest
```

- `--network host` — TUN interface must be on host namespace
- `--cap-add NET_ADMIN` — create TUN, configure IPs/routes
- `--device /dev/net/tun` — pass TUN device
- Does NOT need `--privileged`

### 1.4 Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `WOLFNET_JOIN_TOKEN` | (none) | Base64 invite token |
| `WOLFNET_ADDRESS` | (auto) | WolfNet IP |
| `WOLFNET_SUBNET` | `24` | CIDR mask |
| `WOLFNET_PORT` | `9600` | UDP listen port |
| `WOLFNET_GATEWAY` | `false` | NAT gateway mode |
| `WOLFNET_DISCOVERY` | `true` | LAN broadcast discovery |
| `WOLFNET_INTERFACE` | `wolfnet0` | TUN name |
| `WOLFNET_HOSTNAME` | (container) | Override hostname |

### 1.5 Entrypoint Script

1. Check `/dev/net/tun` exists — exit with clear error if not
2. Generate keys if `/etc/wolfnet/private.key` missing
3. Auto-generate config from env vars if no `config.toml`
4. If `WOLFNET_JOIN_TOKEN` set, run `wolfnet join <token>`
5. exec `wolfnet --config /etc/wolfnet/config.toml`

---

## 2. WolfDisk Docker Container

### 2.1 Dockerfile

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse3 libfuse3-3 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && echo "user_allow_other" >> /etc/fuse.conf
RUN mkdir -p /etc/wolfdisk /var/lib/wolfdisk /mnt/wolfdisk
COPY wolfdisk /usr/local/bin/wolfdisk
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/wolfdisk /entrypoint.sh
EXPOSE 8550/tcp
VOLUME ["/etc/wolfdisk", "/var/lib/wolfdisk", "/mnt/wolfdisk"]
ENTRYPOINT ["/entrypoint.sh"]
```

### 2.2 Runtime Requirements

```bash
docker run -d --name wolfdisk --privileged \
  --device /dev/fuse \
  -v wolfdisk-config:/etc/wolfdisk \
  -v wolfdisk-data:/var/lib/wolfdisk \
  -v /mnt/wolfdisk:/mnt/wolfdisk:rshared \
  -e WOLFDISK_ROLE=client \
  -e WOLFDISK_PEERS=10.0.10.1:8550 \
  ghcr.io/intelligentwolf/wolfdisk:latest
```

- `--privileged` — needed for reliable FUSE (SYS_ADMIN cap minimum, but NAS platforms often need full privileged)
- `rshared` mount propagation — FUSE mount visible on host
- Network: can use host mode (if accessing WolfNet overlay) or bridge with `-p 8550:8550`

### 2.3 Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `WOLFDISK_NODE_ID` | (auto) | Unique node ID |
| `WOLFDISK_ROLE` | `auto` | leader/follower/client/auto |
| `WOLFDISK_BIND` | `0.0.0.0:8550` | Cluster comm bind |
| `WOLFDISK_PEERS` | (none) | Comma-separated peer addresses |
| `WOLFDISK_MOUNT_PATH` | `/mnt/wolfdisk` | FUSE mount point |
| `WOLFDISK_S3_ENABLED` | `false` | S3-compatible API |
| `WOLFDISK_S3_BIND` | `0.0.0.0:9000` | S3 API bind |

---

## 3. Satellite Agent (Cluster Registration)

### 3.1 New Node Type: `"satellite"`

Add to `Node` struct in `src/agent/mod.rs`. Satellite nodes have limited capabilities:
- `has_docker: false`, `has_lxc: false`, `has_kvm: false`
- Reports WolfNet status + basic system metrics
- Appears in cluster sidebar with reduced UI

### 3.2 Lightweight Agent Binary

A small HTTP server (`wolfstack-agent`) that:
- Listens on port 8553 (matching WolfStack's default)
- Responds to `/api/agent/status` with hostname, uptime, CPU, RAM
- Responds to `/api/cluster/verify-token` for join auth
- Accepts `X-WolfStack-Secret` header
- Reports WolfNet/WolfDisk status from their status files

Can be built as a new crate in the wolfscale workspace or as a feature-gated build.

### 3.3 Registration Flow

1. User adds "Satellite Node" in WolfStack UI
2. WolfStack generates join token
3. Token passed to satellite agent via `WOLFSTACK_JOIN_TOKEN` env var
4. Agent validates against WolfStack cluster on boot
5. WolfStack begins polling — satellite appears in sidebar

---

## 4. Docker Compose Examples

### WolfNet Only

```yaml
services:
  wolfnet:
    image: ghcr.io/intelligentwolf/wolfnet:latest
    restart: unless-stopped
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes:
      - wolfnet-config:/etc/wolfnet
      - /run/wolfnet:/var/run/wolfnet
    environment:
      - WOLFNET_JOIN_TOKEN=${WOLFNET_JOIN_TOKEN}
volumes:
  wolfnet-config:
```

### Full Managed Satellite

```yaml
services:
  wolfnet:
    image: ghcr.io/intelligentwolf/wolfnet:latest
    restart: unless-stopped
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: [wolfnet-config:/etc/wolfnet, /run/wolfnet:/var/run/wolfnet]
    environment: [WOLFNET_JOIN_TOKEN=${WOLFNET_JOIN_TOKEN}]

  wolfdisk:
    image: ghcr.io/intelligentwolf/wolfdisk:latest
    restart: unless-stopped
    privileged: true
    network_mode: host
    devices: ["/dev/fuse:/dev/fuse"]
    volumes: [wolfdisk-config:/etc/wolfdisk, wolfdisk-data:/var/lib/wolfdisk, "/mnt/wolfdisk:/mnt/wolfdisk:rshared"]
    environment: [WOLFDISK_ROLE=client, WOLFDISK_PEERS=${WOLFDISK_LEADER}:8550]
    depends_on: [wolfnet]

  satellite-agent:
    image: ghcr.io/intelligentwolf/wolfstack-agent:latest
    restart: unless-stopped
    network_mode: host
    volumes: [/run/wolfnet:/var/run/wolfnet:ro, agent-config:/etc/wolfstack-agent]
    environment: [WOLFSTACK_JOIN_TOKEN=${WOLFSTACK_JOIN_TOKEN}]
    depends_on: [wolfnet]

volumes:
  wolfnet-config:
  wolfdisk-config:
  wolfdisk-data:
  agent-config:
```

---

## 5. CI/CD Pipeline

### Multi-stage Build

```dockerfile
FROM rust:1.82-bookworm AS builder
WORKDIR /src
COPY . .
ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") TARGET=x86_64-unknown-linux-musl ;; \
      "linux/arm64") TARGET=aarch64-unknown-linux-musl ;; \
    esac && cross build --release --target $TARGET && \
    cp target/$TARGET/release/wolfnet /wolfnet

FROM debian:bookworm-slim
# ... runtime deps + COPY --from=builder ...
```

- Trigger on pushes to `main` that change `src/**` or `docker/**`
- Multi-arch: `linux/amd64` + `linux/arm64` via QEMU
- Push to `ghcr.io/intelligentwolf/wolfnet:latest` + version tags
- Workflows: `wolfnet/.github/workflows/docker.yml`, `.github/workflows/wolfdisk-docker.yml`

---

## 6. Platform Compatibility

| Platform | TUN | FUSE | Host Network | Notes |
|----------|-----|------|--------------|-------|
| **Unraid** | Yes | Yes | Yes | Primary target. AppData at `/mnt/user/appdata/` |
| **Synology DSM** | Maybe | Varies | Yes | May need `insmod tun.ko`, restricted caps |
| **TrueNAS Scale** | Yes | Yes | Yes (k3s) | Debian-based, may need Helm chart |
| **TrueNAS Core** | No | No | No | FreeBSD — not a target |
| **Generic Linux** | Yes | Yes | Yes | Full support |

---

## 7. Unraid Community Apps Template

```xml
<Container version="2">
  <Name>WolfNet</Name>
  <Repository>ghcr.io/intelligentwolf/wolfnet:latest</Repository>
  <Network>host</Network>
  <Privileged>false</Privileged>
  <Overview>Secure mesh VPN for your WolfStack cluster</Overview>
  <Category>Network:VPN</Category>
  <ExtraParams>--cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun</ExtraParams>
  <Config Name="Join Token" Target="WOLFNET_JOIN_TOKEN" Type="Variable" Display="always" Required="true"/>
  <Config Name="Config" Target="/etc/wolfnet" Default="/mnt/user/appdata/wolfnet" Type="Path" Display="always"/>
</Container>
```

---

## 8. Security

- **WolfNet**: Encrypted end-to-end (ChaCha20-Poly1305). UDP port 9600 should be firewalled to known peers.
- **Key persistence**: Private key MUST be in persistent volume. Entrypoint sets 0600 perms.
- **Satellite agent**: Listen only on WolfNet overlay IP, not all interfaces.
- **Container images**: Pin base image tags, scan with Trivy, sign with cosign.
- **Secrets**: Join tokens are single-use identity tokens, safe as env vars. Cluster secret via Docker secrets where available.

---

## 9. Implementation Sequence

### Phase 1: WolfNet Container (1-2 weeks)
1. Docker directory structure + Dockerfile + entrypoint
2. Env var → config.toml generation
3. Join token handling
4. GitHub Actions multi-arch build
5. Test on Docker Desktop + Unraid

### Phase 2: WolfDisk Container (1-2 weeks)
1. Dockerfile with FUSE support
2. Mount lifecycle (clean mount/unmount on SIGTERM)
3. Mount propagation testing
4. CI pipeline

### Phase 3: Satellite Agent (1-2 weeks)
1. Lightweight HTTP server binary
2. `"satellite"` node type in `src/agent/mod.rs`
3. WolfStack UI updates for satellite nodes
4. Polling logic updates

### Phase 4: Templates & Docs (1 week)
1. Unraid XML templates
2. Docker-compose examples per scenario
3. Platform-specific guides
4. End-to-end testing (WolfStack + Unraid satellite)

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `wolfnet/docker/Dockerfile` | Create |
| `wolfnet/docker/entrypoint.sh` | Create |
| `wolfnet/.github/workflows/docker.yml` | Create |
| `wolfdisk/docker/Dockerfile` | Create |
| `wolfdisk/docker/entrypoint.sh` | Create |
| `.github/workflows/wolfdisk-docker.yml` | Create |
| `wolfnet/docker/unraid-template.xml` | Create |
| `docker-compose.wolfstack-satellite.yml` | Create |
| `wolfstack-agent/` (new crate) | Create |
| `wolfstack/src/agent/mod.rs` | Modify — satellite node type |
| `wolfstack/src/api/mod.rs` | Modify — satellite node UI |
